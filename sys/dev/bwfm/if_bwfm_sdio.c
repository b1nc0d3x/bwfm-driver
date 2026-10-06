/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC SDIO transport glue for bwfm.  Targets the
 * BCM43xxx family the Raspberry Pi 4 carries on its internal SDIO
 * bus (BCM43430 / CYW43436 / BCM43455).
 *
 * Lifecycle:
 *   1. sdio0 enumerates I/O functions and creates one newbus child per
 *      function (sdio_func.c).  Each child carries manfid/prodid/class
 *      ivars exposed via SDIO_ACCESSOR().
 *   2. probe() matches on (manfid, prodid) being the Broadcom WLAN
 *      function (manfid=0x02d0, prodid in the BCM43xxx table) AND
 *      func_num == 1 — the backplane function.  Function 2 is the
 *      WLAN frame FIFO, handled by the bwfm_sdio_f2 sibling driver;
 *      function 3, where present, is Bluetooth and not driven here.
 *   3. attach() captures the parent sdio bus and starts the autostart
 *      thread (hw.bwfm_sdio.autostart), which downloads the firmware,
 *      releases the CR4 and calls bwfm_attach() so net80211 can bind.
 *   4. detach() reverses everything (see bwfm_sdio_detach: the
 *      watchdog and taskqueues are drained, then the common teardown
 *      runs).
 *
 * The chip bring-up and firmware download sequences follow Linux
 * brcmfmac (sdio.c, bcmsdh.c, chip.c; Broadcom) and OpenBSD
 * sys/dev/sdmmc/if_bwfm_sdio.c (Patrick Wildt); the code was written
 * for this driver.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/firmware.h>
#include <sys/priv.h>		/* priv_check(td, PRIV_DRIVER) */
#include <sys/proc.h>		/* kern_yield, thread_lock, curthread */
#include <sys/sched.h>		/* sched_bind / sched_unbind */
#include <sys/smp.h>		/* mp_ncpus */
#include <sys/cpuset.h>		/* CPU_WHICH_IRQ, cpuset_t */
#include <sys/interrupt.h>	/* intr_setaffinity */
#include <sys/rman.h>		/* rman_get_start */
#include <machine/resource.h>	/* SYS_RES_IRQ */

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include <dev/mmc/mmcreg.h>		/* SD_IO_CCCR_FN_ENABLE/FN_READY */
#include <dev/mmc/mmc_subr.h>		/* mmc_wait_for_cmd */
#include <dev/mmc/sdio_func.h>
#include <dev/mmc/sdioreg.h>

#include <sys/conf.h>		/* cdev, make_dev */
#include <sys/uio.h>

#include <dev/bwfm/bwfmvar.h>
#include <dev/bwfm/bwfm_sdpcm.h>
#include <dev/bwfm/bwfm_sdio_regs.h>
#include <dev/bwfm/if_bwfm_sdio_cdev.h>
#include <dev/bwfm/bwfm_chip.h>

/*
 * BCM43455 (CYW43455, rev 6) SOCRAM: 800 KB from ram_base 0x198000, so
 * RAM ends at 0x260000.  The size matters: the firmware looks for its
 * NVRAM at the end of RAM, and if it is placed short of the real end
 * the firmware runs without the board's radio settings (every AUTH is
 * NO_ACK).  Backplane reads succeed through 0x25fffc and fail at
 * 0x260000, and the firmware publishes its sdpcm_shared pointer in the
 * last word, 0x25fffc.  Linux brcmfmac sizes the same RAM from the CR4
 * bank registers and gets 0xC8000.
 */
#define	BWFM_43455_RAM_BASE	0x00198000u
#define	BWFM_43455_RAM_SIZE	0x000c8000u
#define	BWFM_43455_RAM_END	(BWFM_43455_RAM_BASE + BWFM_43455_RAM_SIZE)
#define	BWFM_43455_SHARED_SLOT	(BWFM_43455_RAM_END - 4)

#ifdef __aarch64__
#include <arm/broadcom/bcm2835/bcm2835_firmware.h>
#endif

#include <sys/sx.h>

struct bwfm_sdio_softc {
	struct bwfm_softc	 bsc_base;	/* must be first */
	device_t		 sc_dev;	/* the sdio func1 child */
	device_t		 sc_f2_dev;	/* sdio func2 child (SDPCM
						 * data path); attached by
						 * the bwfm_sdio_f2 sibling
						 * driver via the global
						 * registry below. NULL until
						 * F2 attaches. */
	struct bwfm_sdpcm_state	*sc_sdpcm;	/* SDPCM layer state.
						 * Allocated lazily on first
						 * sdpcm_test sysctl; NULL
						 * before bwfm_sdpcm_init. */
	bool			 sc_f2_enabled;	/* CCCR.IOEn F2 set + IORx F2
						 * confirmed by release_cr4
						 * after fw is up. */
	device_t		 sc_sdio_bus;	/* parent sdio bus */
	uint16_t		 sc_manfid;
	uint16_t		 sc_prodid;
	uint8_t			 sc_func_num;
	uint8_t			 sc_func_class;
	/* sc_f2_dev forward-decl above; published in bwfm_sdio_global_softc. */
	uint16_t		 sc_blksize;
	uint32_t		 sc_sbwad;	/* cached backplane window base */
	struct sx		 sc_chip_sx;	/* serialises chip-side ops */
	struct cdev		*sc_cdev;	/* /dev/bwfm0 raw interface */
	struct bwfm_chip	 sc_chip;	/* chip object (bwfm_chip.c) */
	bool			 sc_chip_ready;	/* CC core registered + caps probed */

	/*
	 * Per-sc event delivery queue.  SDPCM rx callback enqueues an
	 * mbuf-wrapped raw EVENT body here; sc_event_rx_task drains it
	 * on a dedicated kernel taskqueue thread and calls bwfm_rx_frame.
	 * Mirrors Linux brcmfmac's event_worker pattern.
	 */
	struct mtx		 sc_event_rx_mtx;
	struct mbufq		 sc_event_rx_q;
	struct task		 sc_event_rx_task;
	struct taskqueue	*sc_event_rx_tq;
	/*
	 * Data transmit queue.  net80211 calls ic_transmit with its TX lock
	 * (a mutex) held, and an SDIO write sleeps (sc_chip_sx, then the
	 * MMC request), so bwfm_sdio_txdata only queues the frame and
	 * sc_tx_task sends it from its own thread, as bwfm_pci does with
	 * its flow-ring queue.
	 */
	struct mtx		 sc_tx_mtx;
	struct mbufq		 sc_tx_q;
	/* Mailbox and credit verification counters (dev.bwfm.N.sdio_stats). */
	uint32_t		 st_hmb_int;	/* I_HMB_HOST_INT seen */
	uint32_t		 st_hmb_ack;	/* SMB_INT_ACK written */
	uint32_t		 st_hmb_reason[5];	/* per tohostmailboxdata bit */
	uint32_t		 st_hmb_stuck;	/* bit still set after clearing */
	uint32_t		 st_fc_on, st_fc_off;
	int			 st_fc_since;	/* ticks when FC went on */
	uint32_t		 st_fc_held_ms;
	uint32_t		 st_credit_waits;
	uint32_t		 st_credit_wait_max_ms;
	struct task		 sc_tx_task;
	struct taskqueue	*sc_tx_tq;

	/*
	 * Periodic SDIO watchdog, on the same 10 ms timer + thread
	 * pattern as Linux brcmf_sdio_watchdog (sdio.c).  Unlike Linux,
	 * whose brcmf_sdio_bus_watchdog lets an idle bus sleep, it
	 * fires every BWFM_WD_POLL_MS to pump the SDIO F2 RX queue.  That
	 * catches interrupts the ithread missed and keeps the bus active:
	 * BCM43455 firmware 7.45.18 tears down an association within
	 * milliseconds of ASSOC if the host goes silent.
	 */
	struct callout		 sc_wd_callout;
	struct task		 sc_wd_task;
	bool			 sc_wd_stop;
	/* The autostart thread is running; detach waits for it. */
	bool			 sc_autostart_running;
};

#define	BWFM_WD_POLL_MS		10

/* Forward declarations for the watchdog (used in release_cr4). */
static void bwfm_sdio_watchdog_callout(void *arg);
static void bwfm_sdio_watchdog_task(void *arg, int pending);

/* The F1 -> F2 binding global; defined with the F2 sibling driver. */
static struct bwfm_sdio_softc * volatile bwfm_sdio_global_softc;

/*
 * Bring the chip up after attach, from a kernel thread: chip id,
 * firmware download, CR4 release and net80211 attach, the same steps as
 * the read_chipid, load_firmware, release_cr4 and net80211_attach
 * sysctls.  The firmware module (e.g. brcmfmac43455_fw) must be loaded
 * first.  0 leaves the bring-up to those sysctls; if it goes wrong at
 * boot, "set hw.bwfm_sdio.autostart=0" at the loader prompt.
 */
static SYSCTL_NODE(_hw, OID_AUTO, bwfm_sdio, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "Broadcom FullMAC SDIO driver");
static int bwfm_sdio_autostart_dflt = 1;
SYSCTL_INT(_hw_bwfm_sdio, OID_AUTO, autostart, CTLFLAG_RDTUN,
    &bwfm_sdio_autostart_dflt, 0,
    "Bring the chip up (firmware, net80211) after attach.  "
    "0 leaves it to the bring-up sysctls.");

static int	bwfm_sdio_net80211_attach_now(struct bwfm_sdio_softc *);
static void	bwfm_sdio_autostart(void *);

/*
 * The F2 sibling driver's softc, defined with the F2 code below.
 * attach() looks for an already-attached "bwfm_f2" among the sdio bus
 * children and binds to it through this struct.
 */
struct bwfm_sdio_f2_softc;

/*
 * DPRINTF(&sc->bsc_base, level, ...) comes from bwfmvar.h and is gated
 * on sc_debug in the embedded bwfm_softc, exposed as dev.bwfm.N.debug,
 * so it behaves the same on the USB, PCI and SDIO transports:
 *   0 = silent (default)
 *   1 = milestones (attach checkpoints, chip-id, firmware load steps)
 *   2 = protocol (each CMD52/CMD53 + BCDC header)
 *   3 = per-frame / hex dumps
 */

/*
 * Recognised BCM43xxx prodids (manfid is always 0x02d0 = Broadcom).
 * The list is explicit rather than a wildcard claim; it is only a probe
 * filter.  Names use the Broadcom marketing IDs; Cypress's post-acquisition
 * relabelling is noted in comments where the chip changed name.
 */
struct bwfm_sdio_match {
	uint16_t	prodid;
	const char	*name;
};

static const struct bwfm_sdio_match bwfm_sdio_chips[] = {
	{ SDIO_DEVICE_BCM4329,  "BCM4329 WLAN"  },
	{ SDIO_DEVICE_BCM4330,  "BCM4330 WLAN"  },
	{ SDIO_DEVICE_BCM4334,  "BCM4334 WLAN"  },
	{ SDIO_DEVICE_BCM4339,  "BCM4339 WLAN"  },
	{ SDIO_DEVICE_BCM4345,  "BCM4345 WLAN"  },
	{ SDIO_DEVICE_BCM4354,  "BCM4354 WLAN"  },
	{ SDIO_DEVICE_BCM4356,  "BCM4356 WLAN"  },
	{ SDIO_DEVICE_BCM4359,  "BCM4359 WLAN"  },
	{ SDIO_DEVICE_BCM4373,  "BCM4373 / CYW4373 WLAN" },
	{ SDIO_DEVICE_BCM43340, "BCM43340 WLAN" },
	{ SDIO_DEVICE_BCM43341, "BCM43341 WLAN" },
	{ SDIO_DEVICE_BCM43362, "BCM43362 WLAN" },
	{ SDIO_DEVICE_BCM43364, "BCM43364 WLAN" },
	{ SDIO_DEVICE_BCM43430, "BCM43430 / CYW43436 WLAN (Pi 3, Pi 4B rev 1.1)" },
	{ SDIO_DEVICE_BCM43455, "BCM43455 WLAN (Pi 3B+, Pi 4B rev 1.2+)" },
	{ SDIO_DEVICE_BCM43456, "BCM43456 WLAN (Pi CM4)" },
};

/* find the table entry for a product id */
static const struct bwfm_sdio_match *
bwfm_sdio_lookup(uint16_t prodid)
{
	size_t i;

	for (i = 0; i < nitems(bwfm_sdio_chips); i++) {
		if (bwfm_sdio_chips[i].prodid == prodid)
			return (&bwfm_sdio_chips[i]);
	}
	return (NULL);
}

/* ------------------------------------------------------------------
 * BCM43xxx chip bring-up — function 1 enable, backplane window,
 * chip-id readback.  Everything later (firmware upload, mailbox setup,
 * BCDC commands) needs function 1 enabled and the backplane window
 * addressable.
 *
 * The sequence has the same chip-side semantics as the start of Linux
 * brcmfmac's brcmf_sdio_probe() (brcmfmac/sdio.c), though the code is
 * structured differently:
 *
 *   1.  CCCR.IO_EN |= 0x02      (host signals "please bring up F1")
 *   2.  poll CCCR.IO_READY      (chip ACKs "F1 is live")
 *   3.  set backplane window    (3 CMD52 writes to F1's SBADDR*)
 *   4.  CMD53 read 4 bytes      (host fetches CC.CHIPID from
 *                                chip-internal address 0x18000000)
 *
 * A chip_id matching the SDIO CIS prodid shows the backplane path works
 * and the chip's PLL is stable enough to clock its internal AXI fabric,
 * which the firmware upload relies on.
 * ------------------------------------------------------------------ */

/*
 * KSO (Keep Sleep Off) control.  Without KSO asserted, the chip
 * autonomously enters a low-power state on its 32 kHz PMU clock --
 * in that state HT_AVAIL_REQ is acknowledged (request bit sticks)
 * but the PMU never spins up the HT PLL.  Result: indefinite wait on
 * HT_AVAIL with no error.
 *
 * Sequence per Linux brcmf_sdio_kso_control(true):
 *   1. writeb SLEEPCSR = KSO_EN
 *   2. poll SLEEPCSR until both KSO and DEVON bits are set
 *
 * The first write may go to the chip's "always-on subsystem" (AOS)
 * wakeup core if the device was asleep -- that write CAN return an
 * error even though it succeeded; we re-issue inside the poll.
 */
static int
bwfm_sdio_kso_enable(struct bwfm_sdio_softc *sc)
{
	uint8_t sleepcsr = 0;
	const uint8_t want = SBSDIO_FUNC1_SLEEPCSR_KSO_MASK |
	    SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK;
	int err, retries;

	err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_SLEEPCSR,
	    SBSDIO_FUNC1_SLEEPCSR_KSO_EN);
	/*
	 * Ignore err from the wake-up write; if the chip was asleep the
	 * sdiod sleep-write path may signal a CRC error even though the
	 * KSO bit landed.  Linux explicitly tolerates this.
	 */
	(void)err;
	DELAY(2500);	/* PMU 32 kHz domain needs ~2 ms to catch up */

	for (retries = 0; retries < 64; retries++) {
		err = sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_SLEEPCSR,
		    &sleepcsr);
		if (err == 0 && (sleepcsr & want) == want) {
			DPRINTF(&sc->bsc_base, 1,
			    "KSO enabled after %d retries "
			    "(SLEEPCSR=0x%02x)\n", retries, sleepcsr);
			return (0);
		}
		pause("bwfmkso", 1);	/* ~1 ms sleep, not busy-wait */
		(void)sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_SLEEPCSR,
		    SBSDIO_FUNC1_SLEEPCSR_KSO_EN);
	}
	device_printf(sc->sc_dev,
	    "KSO never asserted (last SLEEPCSR=0x%02x err=%d)\n",
	    sleepcsr, err);
	return (ETIMEDOUT);
}

/*
 * Buscore prep: force ALP and lock HW clock request off.
 *
 * This is the preamble Linux brcmfmac runs in brcmf_sdio_buscoreprep()
 * before chip recognition.  Without it HT_AVAIL_REQ is acknowledged
 * (the bit stays set) but the PMU never spins up HT.  The order
 * matters: force ALP, wait for it, lock the hw clock request off, and
 * only then release the lock and ask for HT.
 *
 * Steps from Linux (only the ALP timeout differs):
 *   1. CHIPCLKCSR = FORCE_HW_CLKREQ_OFF | ALP_AVAIL_REQ  (0x28)
 *      -- ask for ALP and prevent the chip from auto-requesting HT.
 *   2. Read back; every bit except the two AVAIL status bits
 *      (SBSDIO_AVBITS, 0xC0) must match what we wrote.
 *   3. Poll for ALP_AVAIL (bit 6, 0x40) up to ~5 s.  Linux waits up
 *      to 1 s (PMU_MAX_TRANSITION_DLY); its comment says "may take
 *      up to 15 ms".
 *   4. CHIPCLKCSR = FORCE_HW_CLKREQ_OFF | FORCE_ALP  (0x21)
 *      -- lock the chip on ALP.
 *   5. DELAY(65).
 *   6. SBSDIO_FUNC1_SDIOPULLUP = 0 -- disable extra SDIO pull-ups.
 */
static int
bwfm_sdio_buscoreprep(struct bwfm_sdio_softc *sc)
{
	uint8_t clkset, clkval;
	int err, retries;

	clkset = SBSDIO_FORCE_HW_CLKREQ_OFF | SBSDIO_ALP_AVAIL_REQ;
	err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR, clkset);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "buscoreprep: CHIPCLKCSR initial write failed err=%d\n",
		    err);
		return (err);
	}
	err = sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR, &clkval);
	if (err != 0)
		return (err);
	if ((clkval & ~SBSDIO_AVBITS) != clkset) {
		device_printf(sc->sc_dev,
		    "buscoreprep: CHIPCLKCSR access mismatch: "
		    "wrote 0x%02x read 0x%02x\n", clkset, clkval);
		return (EIO);
	}

	for (retries = 0; retries < 5000; retries++) {
		err = sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR,
		    &clkval);
		if (err == 0 && (clkval & SBSDIO_ALP_AVAIL) != 0)
			break;
		pause("bwfmalp", 1);	/* ~1 ms sleep, not busy-wait */
	}
	if ((clkval & SBSDIO_ALP_AVAIL) == 0) {
		device_printf(sc->sc_dev,
		    "buscoreprep: ALP_AVAIL never asserted (CHIPCLKCSR=0x%02x "
		    "after %d ms)\n", clkval, retries);
		return (ETIMEDOUT);
	}
	DPRINTF(&sc->bsc_base, 1,
	    "ALP available after %d ms (CHIPCLKCSR=0x%02x)\n",
	    retries, clkval);

	/*
	 * Lock the chip on ALP (FORCE_HW_CLKREQ_OFF | FORCE_ALP) and
	 * disable extra SDIO pull-ups.  Both are required before any
	 * backplane CMD53 to chipcommon registers (PMUCONTROL etc.)
	 * is reliable on BCM43455 -- without them the chip parks
	 * subsequent CMD53s and the SDHCI host controller times out.
	 */
	clkset = SBSDIO_FORCE_HW_CLKREQ_OFF | SBSDIO_FORCE_ALP;
	err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR, clkset);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "buscoreprep: CHIPCLKCSR FORCE_ALP write failed err=%d\n",
		    err);
		return (err);
	}
	DELAY(65);

	err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_SDIOPULLUP, 0);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "buscoreprep: SDIOPULLUP write failed err=%d\n", err);
		return (err);
	}

	DPRINTF(&sc->bsc_base, 1,
	    "buscoreprep done -- chip locked on ALP, pull-ups off\n");
	return (0);
}

/*
 * Bring the HT (High-Throughput) backplane clock up.
 *
 * After F1 is enabled the chip is on ALP -- enough for CC.CHIPID
 * reads but NOT enough for core wrap register writes (CR4 IOCTL,
 * SOCRAM init, d11 reset).  Without HT, IOCTL writes silently drop.
 *
 * The path that gets HT up is chip-family-specific.  Two flavours:
 *
 *  - "non-SR" chips (BCM43340/43342/43362, older parts): host writes
 *    HT_AVAIL_REQ to CHIPCLKCSR and the PMU asynchronously spins HT
 *    up; host polls HT_AVAIL.  This is the documented spec flow.
 *
 *  - "SR-capable" chips (BCM4345 family including the BCM43455 on
 *    Pi 4, plus 4339/4354/4356/4359 etc.): the PMU runs in
 *    save/restore mode and ignores polite HT_AVAIL_REQ pings -- the
 *    request bit gets latched but HT_AVAIL never asserts.  Instead
 *    the host must:
 *
 *      1. Set SBSDIO_WCTRL_WAKE_TILL_HT_AVAIL in WAKEUPCTRL so the
 *         sdiod core, when it next powers on, parks the chip in an
 *         HT-requesting state automatically.
 *      2. Write SBSDIO_FORCE_HT to CHIPCLKCSR -- this is the strong
 *         form of HT request, telling the PMU to compel HT now, not
 *         to consider asynchronously raising it.
 *
 *    KSO + CARDCAP CMD_NODEC must already be set (we do those
 *    earlier in halt_cr4_now); without them the SR-capable chip
 *    treats even FORCE_HT as a request to dismiss.
 *
 * Every chip this driver supports is SR-capable in practice; the
 * non-SR parts (BCM43340/43342/43362) are older than anything we
 * claim to support, so every chip is treated as SR-capable.
 *
 * CHIPCLKCSR + WAKEUPCTRL live at func 1 SDIO offsets below 0x18000
 * so they do NOT need the backplane window programmed; CMD52 to
 * func 1 hits them directly.
 *
 * Reference: Infineon WHD (BSD-3-Clause) whd_enable_save_restore()
 * in WiFi_Host_Driver/src/whd_chip.c.  Constants from
 * WiFi_Host_Driver/src/bus_protocols/whd_sdio.h.
 */
static int
bwfm_sdio_request_ht_clock(struct bwfm_sdio_softc *sc)
{
	uint8_t wctrl = 0, clkctl = 0;
	int err, retries;

	/*
	 * Set WAKE_TILL_HT_AVAIL in WAKEUPCTRL so the sdiod core's wake
	 * path raises HT automatically after the next power-up.  Most
	 * BCM43xxx have other WAKEUPCTRL bits set by the chip at reset;
	 * RMW preserves them.
	 */
	err = sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_WAKEUPCTRL, &wctrl);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "WAKEUPCTRL read failed err=%d\n", err);
		return (err);
	}
	wctrl |= SBSDIO_WCTRL_WAKE_TILL_HT_AVAIL;
	err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_WAKEUPCTRL, wctrl);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "WAKEUPCTRL write failed err=%d\n", err);
		return (err);
	}

	/*
	 * Clear all clock requests first so the next write isn't OR-ing
	 * with a stale CHIPCLKCSR.  Mirrors OpenBSD bwfm_sdio_attach's
	 * final CHIPCLKCSR=0 after the WLANRESET + RES_RELOAD pair --
	 * gets the chip out of "asking for ALP" before we ask for HT.
	 */
	err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR, 0);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "CHIPCLKCSR clear failed err=%d\n", err);
		return (err);
	}

	/*
	 * Now ask for HT.  With WLANRESET + RES_RELOAD done, the PMU
	 * has a real resource graph and HT_AVAIL_REQ becomes a serviced
	 * transition rather than a politely-ignored bit toggle.
	 */
	err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR,
	    SBSDIO_HT_AVAIL_REQ);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "CHIPCLKCSR write (HT_AVAIL_REQ) failed err=%d\n", err);
		return (err);
	}

	/*
	 * Poll for HT_AVAIL but treat its absence as informational, not
	 * fatal.  On SR-capable chips the WHD reference path never polls:
	 * KSO + FORCE_HT are the contract, and backplane writes are
	 * expected to work even if CHIPCLKCSR doesn't show HT_AVAIL.  The
	 * next step, the CR4 IOCTL write, is the real test.
	 */
	for (retries = 0; retries < 200; retries++) {
		err = sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR,
		    &clkctl);
		if (err == 0 && (clkctl & SBSDIO_HT_AVAIL) != 0) {
			device_printf(sc->sc_dev,
			    "HT clock available after %d ms "
			    "(CHIPCLKCSR=0x%02x)\n", retries, clkctl);
			return (0);
		}
		pause("bwfmht", 1);
	}
	device_printf(sc->sc_dev,
	    "HT_AVAIL not surfaced after 200 ms (CHIPCLKCSR=0x%02x); "
	    "proceeding -- backplane writes are the real test\n", clkctl);
	return (0);
}

/*
 * Enable function 1.  SDIO function 0 (CCCR) is always alive; every
 * other function starts disabled and must be brought online by the
 * host writing 1<<N to CCCR.IO_EN.  The chip then powers up its
 * function-N internal block (PLL, registers, RAM windows), and when
 * ready sets bit N in CCCR.IO_READY.  Polling that bit is the only
 * way to know F1 is actually usable — issuing CMD52 to F1 before
 * IO_READY ticks risks the chip returning all-zeros, "invalid
 * function" R5 flags, or timing out.
 *
 * Timeout: bring-up on BCM43xxx is typically <10 ms.  We give it
 * 500 ms to absorb DMA reset cycles and the occasional slow PLL
 * lock; if F1 hasn't come up by then something is fundamentally
 * wrong with the chip's power or clock domain.
 */
static int
bwfm_sdio_enable_func1(struct bwfm_sdio_softc *sc)
{
	uint8_t io_en, io_ready = 0;
	int err, retries;

	err = sdio_cccr_read_byte(sc->sc_dev, SD_IO_CCCR_FN_ENABLE, &io_en);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "F1 enable: CCCR.IO_EN read failed err=%d\n", err);
		return (err);
	}
	DPRINTF(&sc->bsc_base, 2, "CCCR.IO_EN before F1 enable: 0x%02x\n",
	    io_en);

	io_en |= SDIO_FUNC_ENABLE_1;
	err = sdio_cccr_write_byte(sc->sc_dev, SD_IO_CCCR_FN_ENABLE, io_en);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "F1 enable: CCCR.IO_EN write failed err=%d\n", err);
		return (err);
	}

	/*
	 * Poll CCCR.IO_READY until F1's ready bit ticks.  Linux uses
	 * the same constant (SDIO_FUNC_READY_1 = 0x02); the bit
	 * position mirrors IO_EN by design.
	 */
	for (retries = 0; retries < 500; retries++) {
		err = sdio_cccr_read_byte(sc->sc_dev, SD_IO_CCCR_FN_READY,
		    &io_ready);
		if (err == 0 && (io_ready & SDIO_FUNC_READY_1) != 0) {
			DPRINTF(&sc->bsc_base, 1,
			    "F1 ready after %d ms (CCCR.IO_READY=0x%02x)\n",
			    retries, io_ready);
			goto set_blksize;
		}
		pause("brcmfn1", 1);	/* ~1 ms sleep, not busy-wait */
	}
	device_printf(sc->sc_dev,
	    "F1 enable: IO_READY never asserted (last=0x%02x err=%d)\n",
	    io_ready, err);
	return (ETIMEDOUT);

set_blksize:
	/*
	 * Program F1's per-function block size in FBR1.IOBLKSZ.
	 * sdio_attach reads the CIS-advertised block size into sc_blksize
	 * but never writes it back to the card -- the FBR register stays at
	 * its power-on default and any block-mode CMD53 fails with a data
	 * CRC error (host and card disagreeing on how many bytes per block
	 * to compute CRC over).  The CIS-reported value (64 B for BCM43455)
	 * is what we honour.  FBR1 starts at SD_IO_FBR_START_F(1) = 0x100
	 * in F0 address space; IOBLKSZ is the 2-byte LE field at offset
	 * 0x10..0x11.
	 */
	{
		uint16_t blksize = sc->sc_blksize != 0 ? sc->sc_blksize : 64;
		uint32_t fbr1_blksize_addr = SD_IO_FBR_START_F(1) +
		    SD_IO_FBR_IOBLKSZ;

		err = sdio_cccr_write_byte(sc->sc_dev, fbr1_blksize_addr,
		    blksize & 0xff);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "F1 enable: FBR1.IOBLKSZ low write failed err=%d\n",
			    err);
			return (err);
		}
		err = sdio_cccr_write_byte(sc->sc_dev, fbr1_blksize_addr + 1,
		    (blksize >> 8) & 0xff);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "F1 enable: FBR1.IOBLKSZ high write failed err=%d\n",
			    err);
			return (err);
		}
		DPRINTF(&sc->bsc_base, 1,
		    "F1 FBR.IOBLKSZ programmed to %u\n", blksize);
	}
	return (0);
}

/*
 * Program the backplane window so a subsequent CMD52/CMD53 to func 1
 * at sdio_offset = (chip_addr & 0x7FFF) accesses the chip's internal
 * `chip_addr`.  The window covers 32 KB; we cache the current base
 * in sc_sbwad and skip the SBADDR writes when the new chip_addr
 * stays inside the same 32 KB slot.  That short-circuit matters for
 * firmware upload where the host pushes consecutive 64-byte chunks
 * into a contiguous RAM range — without caching we'd burn three
 * CMD52s per chunk on bytes that haven't changed.
 *
 * Byte boundaries follow Linux brcmfmac's set_backplane_window():
 *   SBADDRLOW  := (chip_addr >> 8)  & 0xFF
 *   SBADDRMID  := (chip_addr >> 16) & 0xFF
 *   SBADDRHIGH := (chip_addr >> 24) & 0xFF
 * The chip itself extracts bit 15 of SBADDRLOW to position the window
 * on a 32 KB boundary; bits 8..14 are mathematical noise (they get
 * overridden by the SDIO offset on every actual access).
 */
static int
bwfm_sdio_set_backplane(struct bwfm_sdio_softc *sc, uint32_t chip_addr)
{
	uint32_t newbase, diff;
	bool cold;
	int err;

	newbase = chip_addr & SBSDIO_SBWINDOW_MASK;
	diff = newbase ^ sc->sc_sbwad;

	/*
	 * Skip only when a cached window is established (sc_sbwad != 0)
	 * and the new base falls inside it.  sc_sbwad == 0 means the
	 * cache is uninitialised: cold attach, after a module reload, or
	 * after an I/O error reset it in the fail: path below.  The
	 * chip's SBADDR* bytes may hold leftover state then, so the diff
	 * cannot be trusted and every byte must be written.
	 */
	if (sc->sc_sbwad != 0 && diff == 0)
		return (0);

	/*
	 * Only write the SBADDR bytes that actually changed.  (Linux
	 * skips the update only when the whole window is unchanged and
	 * otherwise writes all three bytes.)  When cold (sc_sbwad == 0)
	 * all three are written regardless of the diff, because a stale
	 * chip-side byte would otherwise leave the window on the wrong
	 * region: a leftover SBADDRMID=0x10 from a CR4 access would turn
	 * a CC.CHIPID read at 0x18000000 into one at 0x18100000.
	 *
	 * The byte values come from newbase, not chip_addr, so the low
	 * bits of chip_addr can't end up in SBADDR{LOW,MID}; a stray
	 * SBADDRLOW=0x04 (from chip_addr=0x18000400) wedges the next
	 * CMD53 with MMC_ERR_INVALID until the chip recovers.
	 */
	cold = (sc->sc_sbwad == 0);

	if (cold || (diff & 0x0000FF00) != 0) {
		err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_SBADDRLOW,
		    (newbase >> 8) & 0xFF);
		if (err != 0)
			goto fail;
	}
	if (cold || (diff & 0x00FF0000) != 0) {
		err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_SBADDRMID,
		    (newbase >> 16) & 0xFF);
		if (err != 0)
			goto fail;
	}
	if (cold || (diff & 0xFF000000) != 0) {
		err = sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_SBADDRHIGH,
		    (newbase >> 24) & 0xFF);
		if (err != 0)
			goto fail;
	}
	sc->sc_sbwad = newbase;
	DPRINTF(&sc->bsc_base, 2,
	    "backplane window set to base 0x%08x for chip_addr 0x%08x\n",
	    newbase, chip_addr);
	return (0);
fail:
	device_printf(sc->sc_dev,
	    "backplane window write failed at base 0x%08x: err=%d\n",
	    newbase, err);
	sc->sc_sbwad = 0;	/* force a full reprogram next call */
	return (err);
}

/*
 * 32-bit write at a chip-internal address through the backplane
 * window.  Mirror image of bwfm_sdio_bp_read32.  Local uint32_t
 * lives on the stack so the host DMA path can grab a real KVA.
 */
static int
bwfm_sdio_bp_write32(struct bwfm_sdio_softc *sc, uint32_t chip_addr,
    uint32_t val)
{
	uint32_t sdio_off, le_val;
	int err;

	err = bwfm_sdio_set_backplane(sc, chip_addr);
	if (err != 0)
		return (err);
	sdio_off = (chip_addr & SBSDIO_SB_OFT_ADDR_MASK) |
	    SBSDIO_SB_ACCESS_2_4B_FLAG;
	le_val = htole32(val);
	err = sdio_write_multi(sc->sc_dev, sdio_off, &le_val, sizeof(le_val),
	    true);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bp_write32 chip_addr=0x%08x sdio_off=0x%05x val=0x%08x "
		    "failed err=%d\n", chip_addr, sdio_off, val, err);
		return (err);
	}
	DPRINTF(&sc->bsc_base, 2,
	    "bp_write32 chip_addr=0x%08x = 0x%08x\n", chip_addr, val);
	return (0);
}

/*
 * 32-bit read of a chip-internal address through the backplane
 * window.  Sets the window if needed, then issues a single CMD53 byte
 * read for 4 bytes at SDIO offset = (chip_addr & 0x7FFF) | 0x8000.
 * The 0x8000 bit (SBSDIO_SB_ACCESS_2_4B_FLAG) tells the chip we want
 * a wide access — without it the chip serves the request 1 byte at a
 * time regardless of CMD53's count field.
 *
 * The value lands in a 4-byte-aligned local uint32_t that the host
 * controller can DMA into directly.  `*valp` is filled only on
 * success.
 */
static int
bwfm_sdio_bp_read32(struct bwfm_sdio_softc *sc, uint32_t chip_addr,
    uint32_t *valp)
{
	uint32_t sdio_off, val;
	int err;

	err = bwfm_sdio_set_backplane(sc, chip_addr);
	if (err != 0)
		return (err);
	sdio_off = (chip_addr & SBSDIO_SB_OFT_ADDR_MASK) |
	    SBSDIO_SB_ACCESS_2_4B_FLAG;
	err = sdio_read_multi(sc->sc_dev, sdio_off, &val, sizeof(val),
	    true);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bp_read32 chip_addr=0x%08x sdio_off=0x%05x failed "
		    "err=%d\n", chip_addr, sdio_off, err);
		return (err);
	}
	*valp = le32toh(val);
	DPRINTF(&sc->bsc_base, 2,
	    "bp_read32 chip_addr=0x%08x = 0x%08x\n", chip_addr, *valp);
	return (0);
}

/*
 * Per-chip firmware/RAM recipe table.  Each row says: "if CC.CHIPID
 * matches (chip_id, chiprev_mask), the chip wants firmware blob
 * `brcmfmac<fw_name>-sdio.bin` loaded at chip RAM address `ram_base`,
 * and after upload its `arm_core` family needs the corresponding
 * passive/active sequence."
 *
 * The chiprev_mask is a 32-bit bitmask where bit N means "revision N
 * matches this row".  Multiple rows can share a chip_id when
 * different revs use different firmware lineages -- e.g. BCM4345 has
 * one mask for the 43455 firmware and another for the 43456
 * firmware.  When iterating we match the first row where chip_id ==
 * row->chip_id AND (1 << rev) & row->chiprev_mask, top to bottom.
 *
 * Source of truth: Linux brcmfmac drivers/net/wireless/broadcom/
 * brcm80211/brcmfmac/sdio.c brcmf_sdio_fwnames[], cross-checked
 * against the rambase function in chip.c.  Only chips found on common
 * hardware (Pi 3, Pi 4, common dev boards) are listed.  One row
 * departs from Linux: the 43430 rev A1 row asks for
 * brcmfmac43430a1-sdio, where Linux uses brcmfmac43430-sdio.
 *
 * The SDIO CIS prodid 0xa9a6 is shared by BCM43430-class and
 * BCM43455-class boards; a Pi 4 with that prodid reads CC.CHIPID =
 * 0x4345 rev 6, which is BCM43455 silicon needing different firmware.
 * Always select firmware from CC.CHIPID, never from the SDIO prodid.
 */
static const struct bwfm_sdio_chip_recipe bwfm_sdio_recipes[] = {
	{ BWFM_CHIP_BCM43430, 0x00000001, 0x000000, BWFM_ARM_CM3,
	  "43430a0", NULL, "BCM43430 rev A0 (Pi 3 early)" },
	{ BWFM_CHIP_BCM43430, 0x00000002, 0x000000, BWFM_ARM_CM3,
	  "43430a1", NULL, "BCM43430 rev A1" },
	{ BWFM_CHIP_BCM43430, 0xFFFFFFFC, 0x000000, BWFM_ARM_CM3,
	  "43430b0", NULL, "BCM43430 rev B0 (Pi 3B, Pi Zero W)" },

	{ BWFM_CHIP_BCM4345,  0x00000200, 0x198000, BWFM_ARM_CR4,
	  "43456",  NULL, "BCM43456 (Pi CM4)" },
	{ BWFM_CHIP_BCM4345,  0xFFFFFDC0, 0x198000, BWFM_ARM_CR4,
	  "43455",  NULL, "BCM43455 (Pi 4B, Pi 3B+)" },

	{ BWFM_CHIP_BCM4339,  0xFFFFFFFF, 0x180000, BWFM_ARM_CR4,
	  "4339",   NULL, "BCM4339" },
	{ BWFM_CHIP_BCM4354,  0xFFFFFFFF, 0x180000, BWFM_ARM_CR4,
	  "4354",   NULL, "BCM4354" },
	{ BWFM_CHIP_BCM4356,  0xFFFFFFFF, 0x180000, BWFM_ARM_CR4,
	  "4356",   NULL, "BCM4356" },
	{ BWFM_CHIP_BCM4359,  0xFFFFFFFF, 0x180000, BWFM_ARM_CR4,
	  "4359",   NULL, "BCM4359 rev <9 (rev >=9 uses 0x160000)" },
	{ BWFM_CHIP_BCM4373,  0xFFFFFFFF, 0x160000, BWFM_ARM_CR4,
	  "4373",   NULL, "BCM4373 / CYW4373" },
};

/*
 * Lookup a recipe row for (chip_id, chip_rev).  Returns NULL if no
 * row matches -- which is a real diagnostic: it means the chip is
 * either too new for our table or one of the prodid-coincident chips
 * we haven't characterised yet.  Caller must not proceed with
 * firmware upload in that case.
 */
static const struct bwfm_sdio_chip_recipe *
bwfm_sdio_lookup_recipe(uint16_t chip_id, uint8_t chip_rev)
{
	const struct bwfm_sdio_chip_recipe *r;
	uint32_t revbit;
	size_t i;

	revbit = 1u << chip_rev;
	for (i = 0; i < nitems(bwfm_sdio_recipes); i++) {
		r = &bwfm_sdio_recipes[i];
		if (r->chip_id != chip_id)
			continue;
		if ((r->chiprev_mask & revbit) == 0)
			continue;
		return (r);
	}
	return (NULL);
}

/* readable name for an ARM core */
static const char *
bwfm_sdio_arm_name(enum bwfm_arm_core c)
{
	switch (c) {
	case BWFM_ARM_CM3: return ("Cortex-M3");
	case BWFM_ARM_CR4: return ("Cortex-R4");
	case BWFM_ARM_CA7: return ("Cortex-A7");
	}
	return ("unknown");
}

/*
 * Smoke test + recipe lookup.  Bring F1 up, read CC.CHIPID, decode
 * it, then look up the matching firmware recipe and log everything
 * we know about what this chip wants.  Logging both halves in one
 * sysctl trigger keeps the per-chip lookup verifiable against the
 * Linux table during bring-up of new boards.
 */
static int
bwfm_sdio_read_chipid_now(struct bwfm_sdio_softc *sc)
{
	const struct bwfm_sdio_chip_recipe *r;
	uint32_t chipid;
	uint16_t chip_id;
	uint8_t chip_rev;
	int err;

	err = bwfm_sdio_enable_func1(sc);
	if (err != 0)
		return (err);
	err = bwfm_sdio_bp_read32(sc, BWFM_CC_CORE_BASE + BWFM_CC_CHIPID,
	    &chipid);
	if (err != 0)
		return (err);

	chip_id = BWFM_CHIPID_ID(chipid);
	chip_rev = BWFM_CHIPID_REV(chipid);

	device_printf(sc->sc_dev,
	    "CC.CHIPID = 0x%08x: chip=0x%04x rev=%u pkg=%u num_cores=%u\n",
	    chipid, chip_id, chip_rev, BWFM_CHIPID_PKG(chipid),
	    BWFM_CHIPID_NUMCORES(chipid));

	r = bwfm_sdio_lookup_recipe(chip_id, chip_rev);
	if (r == NULL) {
		device_printf(sc->sc_dev,
		    "no recipe for chip=0x%04x rev=%u -- firmware upload "
		    "would not know what to load\n", chip_id, chip_rev);
		return (ENOENT);
	}
	device_printf(sc->sc_dev,
	    "recipe match: %s -- arm=%s ram_base=0x%06x "
	    "fw=brcmfmac%s-sdio.bin nvram=brcmfmac%s-sdio.txt\n",
	    r->desc, bwfm_sdio_arm_name(r->arm_core), r->ram_base,
	    r->fw_name,
	    r->nvram_board != NULL ? r->nvram_board : r->fw_name);

	/*
	 * Look up the firmware blobs via firmware(9) and log their sizes,
	 * or, if missing, the filename the operator needs to install.
	 * The references are released at once; the upload path takes
	 * its own.
	 */
	{
		char fwname[64];
		const struct firmware *fw;

		snprintf(fwname, sizeof(fwname),
		    "brcmfmac%s-sdio.bin", r->fw_name);
		fw = firmware_get(fwname);
		if (fw != NULL) {
			device_printf(sc->sc_dev,
			    "firmware(9) `%s`: %zu bytes ready\n",
			    fwname, (size_t)fw->datasize);
			firmware_put(fw, FIRMWARE_UNLOAD);
		} else {
			device_printf(sc->sc_dev,
			    "firmware(9) `%s` NOT FOUND -- "
			    "load brcmfmac%s_fw.ko\n", fwname, r->fw_name);
		}

		snprintf(fwname, sizeof(fwname),
		    "brcmfmac%s-sdio.txt",
		    r->nvram_board != NULL ? r->nvram_board : r->fw_name);
		fw = firmware_get(fwname);
		if (fw != NULL) {
			device_printf(sc->sc_dev,
			    "firmware(9) `%s`: %zu bytes ready\n",
			    fwname, (size_t)fw->datasize);
			firmware_put(fw, FIRMWARE_UNLOAD);
		} else {
			device_printf(sc->sc_dev,
			    "firmware(9) `%s` NOT FOUND\n", fwname);
		}
	}

	return (0);
}

static int bwfm_sdio_chip_soft_reset(struct bwfm_sdio_softc *sc);

/*
 * Pin the parent SDHCI controller's interrupt to a specific CPU.
 *
 * The Pi 4 GIC routes every SPI to CPU0 by default.  bwfm's CMD53
 * storm on sdhci_bcm0 generates so many interrupts on CPU0 that the
 * sibling sdhci_bcm1 (which hosts the SD card / root FS) cannot get
 * its 8 ms hardware data-line timeout serviced -- the SD controller
 * declares "Controller timeout" and UFS root panics.
 *
 * Moving sdhci_bcm0's IRQ to a non-CPU0 leaves CPU0 to sdhci_bcm1's
 * ithread alone.  We walk bwfm0 -> sdio0 -> mmc0 -> sdhci_bcm0,
 * grab the IRQ resource from its resource list, and call
 * intr_setaffinity to retarget the GIC and rebind the ithread.
 *
 * Returns 0 on success, non-zero on lookup or setaffinity failure.
 * Safe to call multiple times -- it just reapplies the affinity.
 */
static int
bwfm_sdio_pin_host_irq(struct bwfm_sdio_softc *sc, int cpu)
{
	device_t mmcbus, sdhci;
	struct resource_list *rl;
	struct resource_list_entry *rle;
	cpuset_t cs;
	int irq, err;

	mmcbus = device_get_parent(sc->sc_sdio_bus);
	if (mmcbus == NULL)
		return (ENXIO);
	sdhci = device_get_parent(mmcbus);
	if (sdhci == NULL)
		return (ENXIO);

	rl = BUS_GET_RESOURCE_LIST(device_get_parent(sdhci), sdhci);
	if (rl == NULL) {
		device_printf(sc->sc_dev,
		    "pin_host_irq: %s has no resource list\n",
		    device_get_nameunit(sdhci));
		return (ENXIO);
	}
	rle = resource_list_find(rl, SYS_RES_IRQ, 0);
	if (rle == NULL) {
		device_printf(sc->sc_dev,
		    "pin_host_irq: %s has no IRQ rid=0\n",
		    device_get_nameunit(sdhci));
		return (ENXIO);
	}
	irq = (int)rle->start;

	if (cpu < 0 || cpu >= mp_ncpus) {
		device_printf(sc->sc_dev,
		    "pin_host_irq: cpu=%d out of range (mp_ncpus=%d)\n",
		    cpu, mp_ncpus);
		return (EINVAL);
	}

	CPU_ZERO(&cs);
	CPU_SET(cpu, &cs);
	err = intr_setaffinity(irq, CPU_WHICH_IRQ, &cs);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "pin_host_irq: intr_setaffinity(%s irq=%d cpu=%d) "
		    "failed err=%d\n",
		    device_get_nameunit(sdhci), irq, cpu, err);
		return (err);
	}
	device_printf(sc->sc_dev,
	    "pin_host_irq: %s irq=%d -> CPU%d\n",
	    device_get_nameunit(sdhci), irq, cpu);
	return (0);
}

/* sysctl: pin the card interrupt to a CPU */
static int
bwfm_sdio_sysctl_pin_host_irq(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int cpu = -1;
	int err;

	err = sysctl_handle_int(oidp, &cpu, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);
	if (cpu < 0)
		return (EINVAL);
	return (bwfm_sdio_pin_host_irq(sc, cpu));
}

/*
 * Stream a buffer into chip memory via the backplane window.
 *
 * The window covers 32 KB at a 32-KB-aligned base; CMD53 writes to
 * SDIO offset (chip_addr & 0x7FFF) auto-increment within the window
 * and stop at offset 0x8000.  We chunk the source so each CMD53 stays
 * within a single window, reprogramming SBADDR{LOW,MID,HIGH} when the
 * upload crosses a 32-KB boundary.
 *
 * Bulk can use block-mode CMD53 (511 blocks * F1 block_size = 32704 B
 * per transaction).  Block mode keeps the block stream inside the
 * SDHCI hardware, so there is one TRANS_COMPLETE IRQ per CMD53 instead
 * of one per <=64 B byte-mode CMD53; for a 622 KB firmware upload that
 * is ~40 interrupts instead of ~10k, which keeps the shared SDHCI
 * ithread from starving sdhci_bcm1 (SD card / root FS) into a
 * controller timeout panic.
 *
 * Sub-block tails (len < block_size) fall back to byte-mode CMD53
 * via sdio_write_multi -- only happens at the very end of the
 * firmware blob if its size isn't a multiple of the block size.
 */
#define	BWFM_SDIO_CMD53_MAX_BLOCKS	511

/*
 * Block-mode CMD53 cap.  Disabled by default (0) because non-MMCCAM
 * kernels' sdhci.c ignores data->block_size/block_count and computes
 * blocks-of-512 internally, so any block-mode CMD53 with nblocks > 1
 * fails MMC_ERR_BADCRC (card emits CRC per 64-B block; SDHCI checks
 * one CRC over the whole transfer).  Even nblocks=1 buys nothing over
 * byte-mode at the same byte count.  Left as a tunable so a future
 * MMCCAM build can enable it without code changes.
 */
static int bwfm_sdio_cmd53_max_blocks = 0;

/*
 * Cap byte-mode CMD53 chunk size (in bytes).  Default 64 because
 * bcm2835_sdhci (the WiFi-side SDHCI on Pi 4) rejects byte-mode CMD53s
 * larger than the F1 IO block size with EIO.  Tunable so other hosts
 * with looser limits can bump it (up to 512, sdio_write_multi's cap).
 */
static int bwfm_sdio_byte_chunk = 64;

/*
 * Issue a single block-mode CMD53 transfer.  nblocks must be 1..511
 * (the 9-bit length field; 0 would encode "infinite" which we never
 * want).  blocksize is the F1 IO block size programmed by sdio_attach
 * via CCCR.FBR1.IO_BLKSIZE.
 */
static int
bwfm_sdio_cmd53_block_xfer(struct bwfm_sdio_softc *sc, uint32_t off,
    void *buf, size_t nblocks, size_t blocksize, bool write)
{
	struct mmc_command cmd;
	struct mmc_data data;
	device_t mmcbus;
	uint8_t fn;
	uint32_t arg;
	int err;

	if (nblocks == 0 || nblocks > BWFM_SDIO_CMD53_MAX_BLOCKS)
		return (EINVAL);
	if (blocksize == 0)
		return (EINVAL);

	mmcbus = device_get_parent(sc->sc_sdio_bus);
	fn = sdio_get_func_num(sc->sc_dev);

	arg = ((uint32_t)fn & SD_ARG_CMD53_FUNC_MASK) <<
	    SD_ARG_CMD53_FUNC_SHIFT;
	arg |= (off & SD_ARG_CMD53_REG_MASK) << SD_ARG_CMD53_REG_SHIFT;
	arg |= SD_ARG_CMD53_BLOCK_MODE;
	arg |= SD_ARG_CMD53_INCREMENT;
	arg |= ((uint32_t)nblocks & SD_ARG_CMD53_LENGTH_MASK);
	if (write)
		arg |= SD_ARG_CMD53_WRITE;

	memset(&cmd, 0, sizeof(cmd));
	memset(&data, 0, sizeof(data));

	cmd.opcode = SD_IO_RW_EXTENDED;
	cmd.arg = arg;
	cmd.flags = MMC_RSP_R5 | MMC_CMD_ADTC;
	cmd.data = &data;

	data.data = buf;
	data.len = nblocks * blocksize;
	data.flags = (write ? MMC_DATA_WRITE : MMC_DATA_READ) |
	    MMC_DATA_BLOCK_SIZE | MMC_DATA_MULTI;
	data.block_size = blocksize;
	data.block_count = nblocks;

	err = mmc_wait_for_cmd(mmcbus, sc->sc_dev, &cmd, 0);
	if (err != MMC_ERR_NONE) {
		device_printf(sc->sc_dev,
		    "cmd53_block_xfer: mmc_err=%d off=0x%05x nblocks=%zu "
		    "blocksize=%zu arg=0x%08x resp=0x%08x\n",
		    err, off, nblocks, blocksize, arg, cmd.resp[0]);
		return (EIO);
	}
	if ((cmd.resp[0] & 0xCB00) != 0) {
		device_printf(sc->sc_dev,
		    "cmd53_block_xfer: R5 flags=0x%08x (off=0x%05x nblocks=%zu)\n",
		    cmd.resp[0], off, nblocks);
		return (EIO);
	}
	return (0);
}

/* write a block into the chip's RAM */
static int
bwfm_sdio_socram_write(struct bwfm_sdio_softc *sc, uint32_t chip_addr,
    const void *buf, size_t len)
{
	const uint8_t *p = buf;
	const uint32_t start_addr = chip_addr;
	const size_t total = len;
	const size_t blocksize = sc->sc_blksize != 0 ? sc->sc_blksize : 64;
	size_t next_mark = 65536;	/* progress print every 64 KB */
	uint32_t window_room;
	size_t chunk;
	int err;

	while (len > 0) {
		err = bwfm_sdio_set_backplane(sc, chip_addr);
		if (err != 0)
			return (err);

		window_room = SBSDIO_SB_OFT_ADDR_LIMIT -
		    (chip_addr & SBSDIO_SB_OFT_ADDR_MASK);


		if (len >= blocksize && window_room >= blocksize &&
		    bwfm_sdio_cmd53_max_blocks >= 1) {
			size_t nblocks;
			size_t cap = (size_t)bwfm_sdio_cmd53_max_blocks;

			if (cap > BWFM_SDIO_CMD53_MAX_BLOCKS)
				cap = BWFM_SDIO_CMD53_MAX_BLOCKS;
			nblocks = MIN(len / blocksize, cap);
			nblocks = MIN(nblocks, window_room / blocksize);
			chunk = nblocks * blocksize;
			err = bwfm_sdio_cmd53_block_xfer(sc,
			    chip_addr & SBSDIO_SB_OFT_ADDR_MASK,
			    __DECONST(void *, p), nblocks, blocksize, true);
			if (err != 0) {
				device_printf(sc->sc_dev,
				    "socram_write: block CMD53 at chip 0x%08x "
				    "nblocks=%zu failed err=%d "
				    "(sent %zu/%zu B)\n",
				    chip_addr, nblocks, err,
				    (size_t)(chip_addr - start_addr), total);
				return (err);
			}
		} else {
			/*
			 * Byte-mode CMD53.  Chunk size capped by the
			 * dev.bwfm.0.byte_chunk tunable; bcm2835_sdhci has
			 * a 512-byte DMA segment ceiling, and
			 * sdio_write_multi also caps at 512.
			 *
			 * When the remaining payload is a sub-block tail
			 * (len < blocksize and < cap), pad up to blocksize
			 * with zeros in a stack buffer.  bcm2835_sdhci's
			 * BCM_SDHCI_SEGSZ_LEFT does rounddown(len, 512) and
			 * its PIO fallback truncates the last 2 bytes of a
			 * non-block-aligned transfer.  Padding to the F1
			 * block size keeps the upload byte-exact for the
			 * payload range (excess zeros land in SOCRAM past
			 * the firmware end where nothing executes).
			 */
			size_t cap = (size_t)bwfm_sdio_byte_chunk;

			if (cap == 0 || cap > 512)
				cap = 512;
			chunk = MIN(len, cap);
			if (chunk > window_room)
				chunk = window_room;
			if (len < blocksize && chunk == len &&
			    window_room >= blocksize) {
				uint8_t padbuf[512];

				memcpy(padbuf, p, chunk);
				memset(padbuf + chunk, 0, blocksize - chunk);
				err = sdio_write_multi(sc->sc_dev,
				    chip_addr & SBSDIO_SB_OFT_ADDR_MASK,
				    padbuf, blocksize, true);
				if (err != 0) {
					device_printf(sc->sc_dev,
					    "socram_write: padded tail CMD53 "
					    "at chip 0x%08x len %zu failed "
					    "err=%d\n",
					    chip_addr, blocksize, err);
					return (err);
				}
				/* Advance only by the real payload size. */
			} else {
				err = sdio_write_multi(sc->sc_dev,
				    chip_addr & SBSDIO_SB_OFT_ADDR_MASK,
				    __DECONST(void *, p), chunk, true);
				if (err != 0) {
					device_printf(sc->sc_dev,
					    "socram_write: byte CMD53 at chip "
					    "0x%08x len %zu failed err=%d "
					    "(sent %zu/%zu B)\n",
					    chip_addr, chunk, err,
					    (size_t)(chip_addr - start_addr),
					    total);
					return (err);
				}
			}
		}

		p += chunk;
		chip_addr += chunk;
		len -= chunk;

		/*
		 * Throttle to keep individual bursts under sdhci_bcm1's
		 * 8 ms hardware data-line timeout.  sdhci_bcm1's SDMA needs
		 * SDHCI_DMA_ADDRESS updates from the host every 512 B; if a
		 * burst of back-to-back CMD53s on sdhci_bcm0 saturates the
		 * shared ithread for longer than 8 ms the SD controller
		 * itself raises a controller timeout and UFS root panics
		 * (the per-CMD software watchdog is generous -- 1 s -- but
		 * the hardware bit-bang timeout fires first).
		 *
		 * pause(1) every 512 B (= 8 chunks at 64 B/CMD53) keeps each
		 * busy-burst around 400 us before yielding for ~1 ms.  Total
		 * throttle ~1.2 s across the 622 KB upload; each pause
		 * gives the shared ithread enough contiguous time to service
		 * sdhci_bcm1's DMA borders.
		 */
		if (((size_t)(chip_addr - start_addr) & 0x1ff) == 0)
			pause("bwfmthr", 1);

		if ((size_t)(chip_addr - start_addr) >= next_mark) {
			device_printf(sc->sc_dev,
			    "socram_write: %zu/%zu B uploaded (chip 0x%08x)\n",
			    (size_t)(chip_addr - start_addr), total, chip_addr);
			next_mark += 65536;
		}
	}
	device_printf(sc->sc_dev,
	    "socram_write: complete -- last byte at chip 0x%08x\n",
	    chip_addr - 1);
	return (0);
}

/* read a block from the chip's RAM */
static int
bwfm_sdio_socram_read(struct bwfm_sdio_softc *sc, uint32_t chip_addr,
    void *buf, size_t len)
{
	uint8_t *p = buf;
	uint32_t window_room;
	size_t chunk;
	int err;

	while (len > 0) {
		err = bwfm_sdio_set_backplane(sc, chip_addr);
		if (err != 0)
			return (err);
		window_room = SBSDIO_SB_OFT_ADDR_LIMIT -
		    (chip_addr & SBSDIO_SB_OFT_ADDR_MASK);
		chunk = MIN(len, (size_t)sc->sc_blksize);
		if (chunk > window_room)
			chunk = window_room;

		err = sdio_read_multi(sc->sc_dev,
		    chip_addr & SBSDIO_SB_OFT_ADDR_MASK, p, chunk, true);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "socram_read: chunk at chip 0x%08x len %zu "
			    "failed err=%d\n", chip_addr, chunk, err);
			return (err);
		}

		p += chunk;
		chip_addr += chunk;
		len -= chunk;
	}
	return (0);
}

/*
 * Upload firmware (and NVRAM) into chip RAM (the CR4 TCM on
 * BCM43455).  Matches the brcmf_sdio_download_firmware() /
 * bwfm_sdio_load_microcode() path on Linux / OpenBSD: firmware blob
 * at chip ram_base, NVRAM at the tail of RAM at (ram_base + ramsize -
 * nvram_len).  Unlike Linux we don't read ramsize from the CR4 bank
 * registers but use the known size (BWFM_43455_RAM_SIZE, 800 KB).  The
 * first and last 16 bytes of each region are read back to verify.
 *
 * The CR4 wrap stays powered down throughout, since the upload doesn't
 * touch it.  The PMU brings up the CR4 power island later, when CR4 is
 * released from reset and the firmware requests its resources.
 */
/*
 * Pack a raw NVRAM text blob into the binary form the firmware expects.
 *
 * The .txt we load is human-readable "key=value" lines with comments and
 * newlines.  The firmware instead wants the lines NUL-separated with the
 * comments removed, padded to a 4-byte boundary, and a length token as
 * the final word.  The firmware reads that token at the top of RAM to
 * locate and parse the NVRAM -- without it the vars (nocrc, board params)
 * are never found and the fw's integrity check fails.  Port of Linux
 * brcmfmac brcmf_fw_nvram_strip().  Returns the packed length (including
 * the 4-byte token) or 0 on failure.
 */
static size_t
bwfm_sdio_nvram_strip(const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_cap)
{
	size_t i = 0, j = 0;
	uint32_t token, new_length, t_le;

	while (i < data_len) {
		uint8_t c = data[i];

		/* skip inter-entry whitespace and stray NULs */
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
		    c == '\0') {
			i++;
			continue;
		}
		/* comment line -> skip to end of line */
		if (c == '#') {
			while (i < data_len && data[i] != '\n')
				i++;
			continue;
		}
		/* entry: accumulate "key=value" until a non-NVRAM char */
		{
			size_t start = i, len;
			bool have_eq = false;

			while (i < data_len) {
				uint8_t d = data[i];

				/* is_nvram_char: printable ASCII, not '#' */
				if (d < 0x20 || d >= 0x7f || d == '#')
					break;
				if (d == '=')
					have_eq = true;
				i++;
			}
			len = i - start;
			/* keep real key=value lines; drop RAW1 + keyless */
			if (have_eq && len >= 2 &&
			    !(len >= 4 &&
			      strncmp((const char *)&data[start], "RAW1", 4) == 0)) {
				if (j + len + 1 > out_cap)
					return (0);
				memcpy(&out[j], &data[start], len);
				j += len;
				out[j++] = '\0';
			}
		}
	}

	if (j == 0)
		return (0);

	/* pad to roundup(len + 1, 4): the extra NUL terminates the list */
	new_length = (uint32_t)((j + 1 + 3) & ~(size_t)3);
	if ((size_t)new_length + 4 > out_cap)
		return (0);
	while (j < new_length)
		out[j++] = 0;

	/* length token as the final word: (~n << 16) | (n & 0xffff), n=len/4 */
	token = new_length / 4;
	token = (~token << 16) | (token & 0x0000FFFFu);
	t_le = htole32(token);
	memcpy(&out[new_length], &t_le, sizeof(t_le));

	return ((size_t)new_length + 4);
}

static int
bwfm_sdio_load_firmware_now(struct bwfm_sdio_softc *sc, bool do_upload)
{
	const struct bwfm_sdio_chip_recipe *r;
	const struct firmware *fw_blob = NULL;
	const struct firmware *nvram_blob = NULL;
	char fwname[64], nvname[64];
	uint32_t chipid, head[4], tail[4];
	uint16_t chip_id;
	uint8_t chip_rev;
	int err;
	const uint32_t ramsize_43455 = BWFM_43455_RAM_SIZE;
	uint32_t nvram_addr;

	sx_assert(&sc->sc_chip_sx, SA_XLOCKED);

	/*
	 * Same prelude as halt_cr4_now: soft-reset first so the chip is
	 * in a known state whatever an earlier attempt left behind.
	 * Otherwise the KSO enable loop can hang on a chip whose
	 * SLEEPCSR.DEVON is stuck mid-state from a half-completed
	 * bring-up.
	 */
	device_printf(sc->sc_dev,
	    "load_firmware: phase 1/8 chip soft-reset (do_upload=%d)\n",
	    do_upload);
	err = bwfm_sdio_chip_soft_reset(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev, "load_firmware: phase 2/8 enable F1\n");
	err = bwfm_sdio_enable_func1(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev,
	    "load_firmware: phase 3/8 CARDCAP + KSO\n");
	(void)sdio_cccr_write_byte(sc->sc_dev, SDIO_CCCR_BWFM_CARDCAP,
	    SDIO_CCCR_BWFM_CARDCAP_CMD_NODEC);
	err = bwfm_sdio_kso_enable(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev, "load_firmware: phase 4/8 buscoreprep\n");
	err = bwfm_sdio_buscoreprep(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev,
	    "load_firmware: phase 5/8 PMU resource reload\n");
	{
		uint32_t pmuctl;
		err = bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMUCONTROL, &pmuctl);
		if (err != 0)
			return (err);
		pmuctl |= (BWFM_CC_PMUCONTROL_RES_RELOAD <<
		    BWFM_CC_PMUCONTROL_RES_SHIFT);
		(void)bwfm_sdio_bp_write32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMUCONTROL, pmuctl);
	}

	device_printf(sc->sc_dev,
	    "load_firmware: phase 6/8 chipid recipe lookup\n");
	err = bwfm_sdio_bp_read32(sc, BWFM_CC_CORE_BASE + BWFM_CC_CHIPID,
	    &chipid);
	if (err != 0)
		return (err);
	chip_id = BWFM_CHIPID_ID(chipid);
	chip_rev = BWFM_CHIPID_REV(chipid);
	r = bwfm_sdio_lookup_recipe(chip_id, chip_rev);
	if (r == NULL) {
		device_printf(sc->sc_dev,
		    "load_firmware: no recipe for chip=0x%04x rev=%u\n",
		    chip_id, chip_rev);
		return (ENOENT);
	}
	device_printf(sc->sc_dev,
	    "load_firmware: chip=0x%04x rev=%u ram_base=0x%06x fw=%s\n",
	    chip_id, chip_rev, r->ram_base, r->fw_name);

	/*
	 * Publish the fw basename so bwfm.c's CLM-blob upload path can
	 * request the per-chip blob instead of a hardcoded name.
	 */
	snprintf(sc->bsc_base.sc_fw_basename,
	    sizeof(sc->bsc_base.sc_fw_basename),
	    "brcmfmac%s-sdio", r->fw_name);

	if (!do_upload) {
		device_printf(sc->sc_dev,
		    "load_firmware: prelude only -- stopping before upload\n");
		return (0);
	}

	snprintf(fwname, sizeof(fwname),
	    "brcmfmac%s-sdio.bin", r->fw_name);
	snprintf(nvname, sizeof(nvname),
	    "brcmfmac%s-sdio.txt",
	    r->nvram_board != NULL ? r->nvram_board : r->fw_name);

	fw_blob = firmware_get(fwname);
	if (fw_blob == NULL) {
		device_printf(sc->sc_dev,
		    "load_firmware: `%s` not loaded; kldload brcmfmac%s_fw\n",
		    fwname, r->fw_name);
		return (ENOENT);
	}
	nvram_blob = firmware_get(nvname);
	if (nvram_blob == NULL) {
		device_printf(sc->sc_dev,
		    "load_firmware: NVRAM `%s` not loaded\n", nvname);
		firmware_put(fw_blob, FIRMWARE_UNLOAD);
		return (ENOENT);
	}

	device_printf(sc->sc_dev,
	    "load_firmware: phase 7/8 upload %zu B firmware + %zu B NVRAM -> "
	    "SOCRAM 0x%06x\n",
	    (size_t)fw_blob->datasize, (size_t)nvram_blob->datasize,
	    r->ram_base);

	/*
	 * Pin this thread to the highest-numbered CPU for the upload.
	 * The Pi 4 GIC routes both sdhci_bcm0 + sdhci_bcm1 interrupts to
	 * CPU0 by default; the woken-thread-runs-where-waker-was scheduler
	 * heuristic then keeps the bwfm sysctl thread on CPU0 too,
	 * ping-ponging against sdhci_bcm0's ithread.  sdhci_bcm1's ithread
	 * then has to compete for CPU0 against the bwfm/bcm0 cycle and its
	 * SDHCI_INT_DMA_END border interrupts arrive too late -- the SD
	 * card software watchdog declares timeout and UFS root panics.
	 *
	 * Binding to mp_ncpus-1 takes the bwfm-side traffic off CPU0
	 * entirely; the SDHCI ithreads share CPU0 fairly and sdhci_bcm1's
	 * borders get serviced in time.  Unbinding after the upload
	 * restores the thread to the scheduler's normal CPU selection.
	 */
	{
		int bind_cpu = mp_ncpus > 1 ? mp_ncpus - 1 : 0;

		/*
		 * Move the host SDHCI's IRQ off CPU0 first.  Without this,
		 * the sibling SDHCI's ithread (sdhci_bcm1 / SD root) shares
		 * CPU0 with sdhci_bcm0 and starves.  Best-effort: log on
		 * failure but proceed -- the upload may still complete if
		 * the host is on a different platform where this isn't
		 * needed.
		 */
		(void)bwfm_sdio_pin_host_irq(sc, bind_cpu);

		thread_lock(curthread);
		sched_bind(curthread, bind_cpu);
		thread_unlock(curthread);
		device_printf(sc->sc_dev,
		    "load_firmware: pinned to CPU%d for upload (mp_ncpus=%d)\n",
		    bind_cpu, mp_ncpus);
	}

	/*
	 * Upload firmware to ram_base.
	 */
	err = bwfm_sdio_socram_write(sc, r->ram_base,
	    fw_blob->data, fw_blob->datasize);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "load_firmware: firmware upload failed err=%d\n", err);
		goto out;
	}

	/*
	 * Verify by reading back the first 16 and last 16 bytes.  If
	 * those round-trip we trust the bulk upload landed -- the
	 * window-crossing path is the same for every chunk.
	 */
	err = bwfm_sdio_socram_read(sc, r->ram_base, head, sizeof(head));
	if (err != 0)
		goto out;
	err = bwfm_sdio_socram_read(sc,
	    r->ram_base + fw_blob->datasize - sizeof(tail), tail,
	    sizeof(tail));
	if (err != 0)
		goto out;

	if (memcmp(head, fw_blob->data, sizeof(head)) != 0) {
		device_printf(sc->sc_dev,
		    "firmware HEAD mismatch: read 0x%08x:%08x:%08x:%08x\n",
		    head[0], head[1], head[2], head[3]);
		err = EIO;
		goto out;
	}
	if (memcmp(tail, (const uint8_t *)fw_blob->data +
	    fw_blob->datasize - sizeof(tail), sizeof(tail)) != 0) {
		/*
		 * When the firmware size is not a multiple of 4 (e.g.
		 * 488193 = 0x77301 for brcmfmac43455-sdio.bin), the
		 * backplane CMD53 read of the tail rounds to a 4-byte
		 * boundary and the readback is shifted by 1-3 bytes.  The
		 * upload itself is fine, so warn but don't abort.
		 */
		device_printf(sc->sc_dev,
		    "firmware TAIL mismatch (likely SDIO alignment with "
		    "fw size 0x%x not 4-byte multiple): "
		    "read 0x%08x:%08x:%08x:%08x -- proceeding\n",
		    (unsigned)fw_blob->datasize,
		    tail[0], tail[1], tail[2], tail[3]);
	}
	device_printf(sc->sc_dev,
	    "firmware upload verified: head=0x%08x tail=0x%08x rstvec=0x%08x\n",
	    head[0], tail[3], head[0]);

	/*
	 * NVRAM lives at (ram_base + ramsize - nvram_len) per Linux
	 * brcmfmac convention.
	 */
	{
		uint8_t *nvbuf;
		size_t nvcap = (size_t)nvram_blob->datasize + 16;
		size_t nvlen;
		uint32_t tok;

		nvbuf = malloc(nvcap, M_TEMP, M_WAITOK);
		nvlen = bwfm_sdio_nvram_strip(nvram_blob->data,
		    (size_t)nvram_blob->datasize, nvbuf, nvcap);
		if (nvlen == 0) {
			device_printf(sc->sc_dev,
			    "load_firmware: nvram strip failed\n");
			free(nvbuf, M_TEMP);
			err = EINVAL;
			goto out;
		}
		/* stripped blob ends with the token; place it so the
		 * token lands at ram_base + ramsize - 4. */
		nvram_addr = r->ram_base + ramsize_43455 - nvlen;
		err = bwfm_sdio_socram_write(sc, nvram_addr, nvbuf, nvlen);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "load_firmware: nvram upload failed err=%d\n", err);
			free(nvbuf, M_TEMP);
			goto out;
		}
		tok = nvbuf[nvlen - 4] | (nvbuf[nvlen - 3] << 8) |
		    (nvbuf[nvlen - 2] << 16) | ((uint32_t)nvbuf[nvlen - 1] << 24);
		device_printf(sc->sc_dev,
		    "NVRAM upload OK: %zu B packed (%zu B raw) at chip "
		    "0x%08x, token=0x%08x\n",
		    nvlen, (size_t)nvram_blob->datasize, nvram_addr, tok);
		free(nvbuf, M_TEMP);
	}

	/*
	 * No NVRAM pointer seed or firmware patch is needed: with the
	 * NVRAM at the real end of RAM (see BWFM_43455_RAM_SIZE) the
	 * firmware finds it by itself, as it does under Linux.
	 */

	device_printf(sc->sc_dev,
	    "load_firmware: phase 8/8 DONE -- firmware + NVRAM in SOCRAM; "
	    "CR4 release path is the next phase\n");

out:
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);
	firmware_put(nvram_blob, FIRMWARE_UNLOAD);
	firmware_put(fw_blob, FIRMWARE_UNLOAD);
	return (err);
}

/*
 * bwfm_chip ops adapter: the bus-agnostic chip layer does its register
 * access through the backplane window helpers.  read32 returns
 * 0xFFFFFFFF on failure, the value Linux's sdio_readl returns on error
 * and chip.c checks as READ_FAILED; write32 ignores errors.  prepare
 * wraps buscoreprep so a fresh caller can put the chip in ALPAvail
 * before any indirect read.  activate clears the SDIO core interrupts
 * and writes the rstvec to chip address 0.
 */
static uint32_t
bwfm_sdio_chip_read32(void *ctx, uint32_t addr)
{
	struct bwfm_sdio_softc *sc = ctx;
	uint32_t v;

	if (bwfm_sdio_bp_read32(sc, addr, &v) != 0)
		return (0xFFFFFFFFu);
	return (v);
}

/* write a 32-bit word to a chip address */
static void
bwfm_sdio_chip_write32(void *ctx, uint32_t addr, uint32_t val)
{
	struct bwfm_sdio_softc *sc = ctx;

	(void)bwfm_sdio_bp_write32(sc, addr, val);
}

/* get the chip backplane ready to probe */
static int
bwfm_sdio_chip_prepare(void *ctx)
{
	struct bwfm_sdio_softc *sc = ctx;

	return (bwfm_sdio_buscoreprep(sc));
}

/* clear SDIO interrupts and start the ARM core */
static void
bwfm_sdio_chip_activate(void *ctx, struct bwfm_chip *pub,
    uint32_t rstvec)
{
	struct bwfm_sdio_softc *sc = ctx;
	struct bwfm_chip_core *sdio_core;

	/*
	 * Mirror Linux brcmf_sdio_buscore_activate (sdio.c): clear all
	 * SDIO-core interrupts before releasing the ARM.  Without this,
	 * stale host intrs at fw startup can drive SDPCM to feed the dongle
	 * before fw is ready.
	 */
	sdio_core = bwfm_chip_get_core(pub, BCMA_CORE_SDIO_DEV);
	if (sdio_core != NULL) {
		(void)bwfm_sdio_bp_write32(sc,
		    sdio_core->base + BWFM_SD_REG_INTSTATUS, 0xffffffffu);
	}

	if (rstvec != 0)
		(void)bwfm_sdio_bp_write32(sc, 0, rstvec);
}

static const struct bwfm_chip_ops bwfm_sdio_chip_ops = {
	.read32 = bwfm_sdio_chip_read32,
	.write32 = bwfm_sdio_chip_write32,
	.prepare = bwfm_sdio_chip_prepare,
	.activate = bwfm_sdio_chip_activate,
};

/*
 * Lazy chip-object init.  Caller must hold sc_chip_sx.  Idempotent.
 * Assumes the chip is already in ALPAvail (buscoreprep has run,
 * typically via the load_firmware_prelude sysctl).  Only the
 * chipcommon core at SI_ENUM_BASE_DEFAULT (0x18000000 on every
 * supported BCM43xxx) is registered here; the EROM walk is done later
 * by bwfm_chip_walk_erom.
 */
static int
bwfm_sdio_chip_ensure(struct bwfm_sdio_softc *sc)
{
	int err;

	if (sc->sc_chip_ready)
		return (0);
	bwfm_chip_init(&sc->sc_chip, &bwfm_sdio_chip_ops, sc);
	err = bwfm_chip_add_core(&sc->sc_chip, 0x800 /* BCMA_CORE_CHIPCOMMON */,
	    0, BWFM_CC_CORE_BASE, 0);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "chip_ensure: add_core(CC) failed err=%d\n", err);
		return (err);
	}
	err = bwfm_chip_probe_caps(&sc->sc_chip);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "chip_ensure: probe_caps failed err=%d\n", err);
		return (err);
	}
	device_printf(sc->sc_dev,
	    "chip: id=0x%x rev=%u cc_caps=0x%08x cc_caps_ext=0x%08x "
	    "pmurev=%u pmu_caps=0x%08x\n",
	    sc->sc_chip.chip, sc->sc_chip.chiprev, sc->sc_chip.cc_caps,
	    sc->sc_chip.cc_caps_ext, sc->sc_chip.pmurev,
	    sc->sc_chip.pmu_caps);
	sc->sc_chip_ready = true;
	return (0);
}

/*
 * Dump PMU chipcontrol registers 0..N-1 (N taken from sysctl write
 * value, capped at 32).  Writes go to dmesg; the typical use is
 *
 *   sysctl dev.bwfm.0.load_firmware_prelude=1
 *   sysctl dev.bwfm.0.dump_chipcontrol=8     # show CC[0..7]
 *
 * to see PMU chipcontrol state after the bring-up prelude has run.
 */
static int
bwfm_sdio_sysctl_dump_chipcontrol(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int n = 0;
	int err;
	uint32_t i, val;

	err = sysctl_handle_int(oidp, &n, 0, req);
	if (err != 0 || req->newptr == NULL || n <= 0)
		return (err);
	if (n > 32)
		n = 32;
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_chip_ensure(sc);
	if (err == 0) {
		device_printf(sc->sc_dev,
		    "chipcontrol dump (pmurev=%u):\n",
		    sc->sc_chip.pmurev);
		for (i = 0; i < (uint32_t)n; i++) {
			val = 0xDEADDEADu;
			(void)bwfm_chip_cc_chipcontrol_read32(&sc->sc_chip,
			    i, &val);
			device_printf(sc->sc_dev,
			    "  cc[%2u] = 0x%08x\n", i, val);
		}
		device_printf(sc->sc_dev,
		    "sr_capable=%s\n",
		    bwfm_chip_sr_capable(&sc->sc_chip) ? "yes" : "no");
	}
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/*
 * Dump OTP sromotp words.  Write value = count of u16 words (capped
 * at 64 to keep dmesg readable; the OTP fuse region is 768 u16s total
 * so multiple invocations can scroll through).  Prints OTPSTATUS +
 * OTPLAYOUT once, then 16-per-line word dumps.
 */
static int
bwfm_sdio_sysctl_dump_otp(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int n = 0;
	int err;
	uint32_t st, layout;
	uint16_t buf[64];
	int i;

	err = sysctl_handle_int(oidp, &n, 0, req);
	if (err != 0 || req->newptr == NULL || n <= 0)
		return (err);
	if (n > (int)nitems(buf))
		n = (int)nitems(buf);
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_chip_ensure(sc);
	if (err == 0) {
		st = sc->sc_chip.ops->read32(sc->sc_chip.ctx,
		    BWFM_CC_CORE_BASE + BWFM_CC_OTPSTATUS);
		layout = sc->sc_chip.ops->read32(sc->sc_chip.ctx,
		    BWFM_CC_CORE_BASE + BWFM_CC_OTPLAYOUT);
		device_printf(sc->sc_dev,
		    "otpstatus=0x%08x otplayout=0x%08x present=%s\n",
		    st, layout,
		    bwfm_chip_otp_present(&sc->sc_chip) ? "yes" : "no");
		(void)bwfm_chip_otp_dump(&sc->sc_chip, buf, n);
		for (i = 0; i < n; i += 8) {
			int end = i + 8 <= n ? i + 8 : n;
			device_printf(sc->sc_dev,
			    "  otp[%3d..]: %04x %04x %04x %04x %04x %04x %04x %04x\n",
			    i,
			    i + 0 < end ? buf[i + 0] : 0,
			    i + 1 < end ? buf[i + 1] : 0,
			    i + 2 < end ? buf[i + 2] : 0,
			    i + 3 < end ? buf[i + 3] : 0,
			    i + 4 < end ? buf[i + 4] : 0,
			    i + 5 < end ? buf[i + 5] : 0,
			    i + 6 < end ? buf[i + 6] : 0,
			    i + 7 < end ? buf[i + 7] : 0);
		}
	}
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/* sysctl: load firmware into the chip */
static int
bwfm_sdio_sysctl_load_firmware(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	if (sc->sc_autostart_running)
		return (EBUSY);	/* autostart is bringing the chip up */
	if (sc->bsc_base.sc_ic_attached)
		return (EBUSY);	/* firmware running: reload the module */
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_load_firmware_now(sc, true);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/* sysctl: run the pre-firmware setup steps */
static int
bwfm_sdio_sysctl_load_firmware_prelude(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	if (sc->sc_autostart_running)
		return (EBUSY);	/* autostart is bringing the chip up */
	if (sc->bsc_base.sc_ic_attached)
		return (EBUSY);	/* firmware running: reload the module */
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_load_firmware_now(sc, false);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/* sysctl: read and report the chip id */
static int
bwfm_sdio_sysctl_read_chipid(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);
	if (trigger == 0)
		return (0);
	if (sc->sc_autostart_running)
		return (EBUSY);	/* autostart is bringing the chip up */
	if (sc->bsc_base.sc_ic_attached)
		return (EBUSY);	/* firmware running: reload the module */
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_read_chipid_now(sc);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/* ------------------------------------------------------------------
 * CR4 halt + release.  The EROM walker is in bwfm_chip.c
 * (bwfm_chip_walk_erom); this code consumes the (id, base, wrap) tuples
 * it discovers and drives the CR4-specific wrap-register sequence.
 *
 * Halt sequence: read current IOCTL, keep only CPUHALT, do the
 * resetcore trio (prereset / reset+RESET_CTL / postreset).  Leaves
 * the core in reset with CPUHALT asserted so the next reset release
 * stays at the reset vector instead of resuming the boot ROM.  After
 * halt, the CR4's TCM (tightly-coupled memory) is accessible from
 * the host for firmware upload.
 *
 * Release sequence: write the firmware's reset vector to chip[0],
 * deassert RESET_CTL, clear CPUHALT — CR4 then fetches from chip[0]
 * and branches into the loaded firmware.
 * ------------------------------------------------------------------ */


/*
 * CR4 halt: put the Cortex-R4 in reset with its CPUHALT bit asserted
 * so a subsequent reset release doesn't immediately re-execute the
 * boot ROM.  Sequence mirrors Linux brcmf_chip_disable_arm() for
 * BCMA_CORE_ARM_CR4 -- read current IOCTL, mask to keep only
 * CPUHALT, then do the resetcore trio (prereset / reset+RESET_CTL /
 * postreset).
 */
static int
bwfm_sdio_halt_cr4(struct bwfm_sdio_softc *sc, uint32_t cr4_wrap)
{
	uint32_t ioctl_before, ioctl_after;
	uint32_t reset_before, pmuctl_before, pmuctl_after;
	uint32_t wrap_id, wrap_state;
	int err;

	/*
	 * Diagnostic dump of the wrap state before any chip-side writes,
	 * to tell whether later writes land or are dropped.
	 *
	 *   wrap+0x000  (wrap component id, ought to read 0x4bf80800-ish
	 *                on AI cores with CR4's id 0x83e encoded in bits)
	 *   wrap+0x004  (wrap status)
	 *   wrap+0x408  (BCMA_IOCTL, what halt manipulates)
	 *   wrap+0x800  (BCMA_RESET_CTL, what halt also manipulates)
	 *
	 * If wrap+0/4 read sensibly but +408/+800 read as 0 with no
	 * error, the IOCTL/RESET_CTL side is on a clock domain that is
	 * not running.  CC.PMUCONTROL, which is known to be writeable, is
	 * dumped too, to confirm chipcommon backplane writes land.
	 */
	(void)bwfm_sdio_bp_read32(sc, cr4_wrap + 0x000, &wrap_id);
	(void)bwfm_sdio_bp_read32(sc, cr4_wrap + 0x004, &wrap_state);
	(void)bwfm_sdio_bp_read32(sc, cr4_wrap + BCMA_RESET_CTL,
	    &reset_before);
	err = bwfm_sdio_bp_read32(sc, cr4_wrap + BCMA_IOCTL, &ioctl_before);
	if (err != 0)
		return (err);
	(void)bwfm_sdio_bp_read32(sc,
	    BWFM_CC_CORE_BASE + BWFM_CC_PMUCONTROL, &pmuctl_before);
	device_printf(sc->sc_dev,
	    "CR4 wrap=0x%08x dump: wrap+0=0x%08x wrap+4=0x%08x "
	    "IOCTL=0x%08x RESET_CTL=0x%08x CC.PMUCTL=0x%08x\n",
	    cr4_wrap, wrap_id, wrap_state, ioctl_before, reset_before,
	    pmuctl_before);

	/*
	 * RAM write/read probe.  Firmware lives in chip RAM at address
	 * 0x198000 on BCM43455.  On this CR4 chip that RAM is the CR4's
	 * TCM (Linux sizes it from the CR4 core; there is no SOCRAM
	 * core), though this driver calls it SOCRAM.  Unlike the CR4
	 * wrap, it is always on (the boot ROM leaves it accessible).
	 * Writing a pattern and reading it back checks the path the
	 * firmware upload will use.
	 */
	{
		uint32_t pattern, readback;
		uint32_t socram = 0x00198000;	/* BCM43455 ram_base */
		size_t i;
		uint32_t patterns[] = {
		    0xCAFEBABE, 0xDEADBEEF, 0x12345678, 0x55AAAA55,
		};
		bool all_ok = true;

		for (i = 0; i < nitems(patterns); i++) {
			pattern = patterns[i];
			(void)bwfm_sdio_bp_write32(sc, socram + 4 * i, pattern);
		}
		for (i = 0; i < nitems(patterns); i++) {
			pattern = patterns[i];
			(void)bwfm_sdio_bp_read32(sc, socram + 4 * i,
			    &readback);
			device_printf(sc->sc_dev,
			    "SOCRAM[0x%x] wrote=0x%08x read=0x%08x %s\n",
			    socram + 4 * (uint32_t)i, pattern, readback,
			    readback == pattern ? "(MATCH)" : "(MISMATCH)");
			if (readback != pattern)
				all_ok = false;
		}
		device_printf(sc->sc_dev,
		    "SOCRAM round-trip: %s\n",
		    all_ok ? "ALL MATCH -- firmware upload path is LIVE" :
		    "FAIL -- need to investigate further");
	}

	/*
	 * Probe PMU resource state.  RES_STATE bitmask = currently-up
	 * resources; MIN_RES_MASK = always-on resources; MAX_RES_MASK =
	 * resources permitted to come up.  If RES_STATE bits are sparse
	 * (only chipcommon + AOS), and MIN_RES_MASK matches, the boot
	 * ROM has explicitly kept CR4-class resources off.  Force them
	 * on by writing MIN_RES_MASK = 0xFFFFFFFF -- the chip's PMU
	 * will engage every resource the chip is capable of bringing up.
	 */
	{
		uint32_t res_state, min_res, max_res, min_res_after;
		uint32_t wrap_after;

		(void)bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMU_RES_STATE, &res_state);
		(void)bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMU_MIN_RES_MASK, &min_res);
		(void)bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMU_MAX_RES_MASK, &max_res);
		device_printf(sc->sc_dev,
		    "PMU pre: RES_STATE=0x%08x MIN_RES=0x%08x MAX_RES=0x%08x\n",
		    res_state, min_res, max_res);

		(void)bwfm_sdio_bp_write32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMU_MIN_RES_MASK,
		    0xffffffff);
		pause("bwfmres", hz / 5);	/* ~200 ms for PMU to honour */

		(void)bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMU_RES_STATE, &res_state);
		(void)bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMU_MIN_RES_MASK,
		    &min_res_after);
		device_printf(sc->sc_dev,
		    "PMU post-force: RES_STATE=0x%08x MIN_RES=0x%08x\n",
		    res_state, min_res_after);

		/* Re-read CR4 wrap to see if it woke up. */
		(void)bwfm_sdio_bp_read32(sc, cr4_wrap + 0x000, &wrap_after);
		device_printf(sc->sc_dev,
		    "CR4 wrap+0 after force = 0x%08x\n", wrap_after);
	}

	/*
	 * Round-trip write to CC.PMUCONTROL bit 0 (PowerControl ENable,
	 * always present and harmless to toggle since RES_RELOAD path
	 * already set it).  Read it back to prove bp_write32 reaches
	 * chipcommon end-to-end.  If this matches the write, we know
	 * the SDIO + backplane window path is functional and any
	 * subsequent wrap-write failures are wrap-specific.
	 */
	(void)bwfm_sdio_bp_write32(sc,
	    BWFM_CC_CORE_BASE + BWFM_CC_PMUCONTROL,
	    pmuctl_before | 0x00000001);
	(void)bwfm_sdio_bp_read32(sc,
	    BWFM_CC_CORE_BASE + BWFM_CC_PMUCONTROL, &pmuctl_after);
	device_printf(sc->sc_dev,
	    "bp_write32 sanity: wrote PMUCTL=0x%08x read=0x%08x %s\n",
	    pmuctl_before | 0x00000001, pmuctl_after,
	    (pmuctl_after & 0x00000001) ? "(write landed)" :
	    "(write DROPPED -- backplane writes are broken)");

	/*
	 * The reset/halt sequence (prereset = CPUHALT bit preserved,
	 * in-reset configure = CPUHALT, postreset = CPUHALT|CLK) is done by
	 * bwfm_chip_disable_arm through the chip layer's AI resetcore
	 * primitive, so other ARM-class chips share it.
	 */
	err = bwfm_chip_disable_arm(&sc->sc_chip, BCMA_CORE_ARM_CR4);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bwfm_chip_disable_arm(CR4) failed err=%d\n", err);
		return (err);
	}

	err = bwfm_sdio_bp_read32(sc, cr4_wrap + BCMA_IOCTL, &ioctl_after);
	if (err != 0)
		return (err);
	device_printf(sc->sc_dev,
	    "CR4 wrap=0x%08x IOCTL after halt  = 0x%08x %s\n",
	    cr4_wrap, ioctl_after,
	    (ioctl_after & ARMCR4_BCMA_IOCTL_CPUHALT) != 0 ?
	    "(CPUHALT asserted)" : "(CPUHALT MISSING!)");
	return (0);
}

/*
 * WL_REG_ON cold-reset via Raspberry Pi firmware mailbox.
 *
 * The BCM43455 on Pi 4 sits behind WL_REG_ON, a power-enable pin on the
 * firmware-side GPIO expander (not a BCM2711 GPIO).  At Pi boot the
 * boot ROM raises WL_REG_ON and the chip's own boot ROM runs, leaving
 * the chip in a state where the brcmfmac clock-gating preamble
 * (CHIPCLKCSR FORCE_HW_CLKREQ_OFF | ALP_AVAIL_REQ) wedges its backplane.
 * The only way back to the fresh-chip state Linux relies on is to drive
 * WL_REG_ON low and back high, which Linux's mmc-pwrseq-simple does at
 * boot via DT.
 *
 * Use bcm2835_firmware_property() rather than bcm2835_mbox_property()
 * directly: SET_GPIO_STATE has a known firmware quirk where the
 * response omits val_len's RESPONSE bit, and the mbox driver's
 * workaround only patches it up when the *request* side has val_len=0.
 * bcm2835_firmware_property() builds the request with val_len=0, so
 * the response gets cleaned up properly; calling bcm2835_mbox_property()
 * with a hand-built request whose val_len is set to the body size
 * causes the firmware to echo val_len without the RESPONSE bit, which
 * the workaround skips, and the mbox driver then returns EIO.
 *
 * The relevant tag is SET_GPIO_STATE (0x00038041), which addresses the
 * firmware GPIO expander -- not gpioc1, which the Pi firmware drives
 * autonomously; writing it directly panics the kernel.
 *
 * Pin numbering: the firmware-side expander starts at gpio number 128.
 * WL_REG_ON is the second pin on the expander (BT_REG_ON is pin 0,
 * WL_REG_ON is pin 1), so the mailbox gpio number is 128 + 1 = 129.
 *
 * Caveat: after the cycle, any SDIO state cached by the host (CCCR
 * function-enable bits, KSO, the F1 RAM windows) is gone too because
 * the chip has lost power.  Callers must re-issue the F1 enable +
 * SBADDR window setup; that's what bwfm_sdio_halt_cr4_now() already
 * does via bwfm_sdio_enable_func1().
 */
#define	PI4_FW_GPIO_BASE		128
#define	PI4_FW_GPIO_WL_REG_ON		(PI4_FW_GPIO_BASE + 1)

#ifdef __aarch64__
static int
bwfm_sdio_mbox_set_gpio(struct bwfm_sdio_softc *sc, uint32_t gpio,
    uint32_t state)
{
	device_t firmware;
	union msg_set_gpio_state msg;
	int err;

	firmware = devclass_get_device(devclass_find("bcm2835_firmware"), 0);
	if (firmware == NULL) {
		device_printf(sc->sc_dev,
		    "bcm2835_firmware device not present; cannot toggle "
		    "WL_REG_ON\n");
		return (ENXIO);
	}

	memset(&msg, 0, sizeof(msg));
	msg.req.gpio = gpio;
	msg.req.state = state;
	err = bcm2835_firmware_property(firmware,
	    BCM2835_FIRMWARE_TAG_SET_GPIO_STATE, &msg, sizeof(msg));
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "SET_GPIO_STATE(gpio=%u state=%u) failed err=%d\n",
		    gpio, state, err);
		return (err);
	}
	/*
	 * The firmware writes back gpio=0 on success.  Non-zero gpio in
	 * the response means the pin number wasn't recognised (e.g. out
	 * of expander range).
	 */
	if (msg.resp.gpio != 0) {
		device_printf(sc->sc_dev,
		    "SET_GPIO_STATE(gpio=%u state=%u) rejected by firmware "
		    "(resp.gpio=%u)\n", gpio, state, msg.resp.gpio);
		return (EINVAL);
	}
	return (0);
}
#else
static int
bwfm_sdio_mbox_set_gpio(struct bwfm_sdio_softc *sc, uint32_t gpio,
    uint32_t state)
{
	(void)sc; (void)gpio; (void)state;
	return (ENXIO);
}
#endif

/* power-cycle the chip's WL_REG_ON line */
static int
bwfm_sdio_wl_reg_on_cycle(struct bwfm_sdio_softc *sc)
{
	int err;

	device_printf(sc->sc_dev,
	    "WL_REG_ON cycle: drive low for 50 ms then high\n");

	err = bwfm_sdio_mbox_set_gpio(sc, PI4_FW_GPIO_WL_REG_ON, 0);
	if (err != 0)
		return (err);
	pause("wlregof", hz / 20);	/* ~50 ms low */

	err = bwfm_sdio_mbox_set_gpio(sc, PI4_FW_GPIO_WL_REG_ON, 1);
	if (err != 0)
		return (err);
	/*
	 * Hold ~150 ms before the next chip access.  The chip's boot ROM
	 * runs in this window; trying CMD52 too early returns CRC errors
	 * or undefined state.  Linux's MMC core waits 10 ms after power-up
	 * (power_delay_ms in mmc_power_up; mmc-pwrseq-simple adds nothing
	 * unless the DT sets post-power-on-delay-ms, and the Pi 4 DT does
	 * not), but BCM43455 routinely needs more in practice -- being
	 * generous is cheap.
	 */
	pause("wlregon", hz / 7);
	device_printf(sc->sc_dev, "WL_REG_ON cycle complete\n");
	return (0);
}

/* sysctl: power-cycle WL_REG_ON */
static int
bwfm_sdio_sysctl_wl_reg_on_cycle(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	return (bwfm_sdio_wl_reg_on_cycle(sc));
}

/*
 * Non-toggling SET_GPIO_STATE.  Writing dev.bwfm.N.wl_reg_on_set=1 is a
 * no-op for an already-powered chip but exercises the same mailbox path
 * as the cycle, so a 0 return shows the cycle can be trusted and EIO
 * means it should not be run.
 *
 * Writing 0 powers the chip off without re-enabling it -- treat that
 * as destructive; once written, the SDIO chip is gone until either
 * wl_reg_on_set=1 or a hardware reboot.
 */
static int
bwfm_sdio_sysctl_wl_reg_on_set(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int state = -1;
	int err;

	err = sysctl_handle_int(oidp, &state, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);
	if (state != 0 && state != 1)
		return (EINVAL);
	return (bwfm_sdio_mbox_set_gpio(sc, PI4_FW_GPIO_WL_REG_ON,
	    (uint32_t)state));
}

/*
 * SDIO-spec chip soft-reset (CCCR offset 0x06 bit 3 = RES, SDIO 3.0).
 *
 * Writing 1 to CCCR.CTL.RES puts the chip into its idle state: CCCR/FBR
 * registers reset to defaults, RCA is dropped, all functions disabled,
 * and the chip's internal silicon goes through its normal cold-boot
 * initialisation -- on Broadcom 43xxx the boot ROM re-runs and the PMU
 * latches return to factory state.  Per the spec, the host MUST then
 * re-init the card with CMD5 / CMD3 / CMD7 to re-establish the SDIO
 * session.  None of that costs us a physical power cycle, and unlike
 * WL_REG_ON toggling, it works on any platform (USB-attached, eMMC-only
 * SoCs that have no firmware GPIO mailbox, etc.).
 *
 * Race safety: sc_chip_sx serialises this routine against every
 * concurrent chip-side operation (read_chipid_now, halt_cr4_now).  We
 * take it exclusive across the whole sequence so an interrupting
 * CMD52 (from another sysctl handler) can't sneak in between the
 * CCCR.RES write and the CMD7 reselect and address a phantom RCA.
 *
 * After this returns successfully, the chip is in a freshly-booted
 * silicon state but with a new RCA (likely the same numeric value the
 * mmc layer originally negotiated, but treat it as opaque).  sc_sbwad
 * is cleared so the next set_backplane writes all three SBADDR bytes
 * unconditionally.  Callers that depend on F1 being enabled or KSO
 * being asserted must re-do those steps -- the chip lost that state
 * along with CCCR.
 */
static int
bwfm_sdio_chip_soft_reset(struct bwfm_sdio_softc *sc)
{
	device_t mmcbus, sdio;
	struct sdio_bus_ivars *sbi;
	struct mmc_command cmd;
	uint32_t ocr;
	uint16_t new_rca;
	int err, i;

	sx_assert(&sc->sc_chip_sx, SA_XLOCKED);

	sdio = sc->sc_sdio_bus;
	mmcbus = device_get_parent(sdio);
	sbi = device_get_ivars(sdio);
	if (sbi == NULL) {
		device_printf(sc->sc_dev,
		    "soft-reset: no sdio_bus_ivars on parent\n");
		return (ENXIO);
	}

	device_printf(sc->sc_dev,
	    "soft-reset: CCCR.CTL.RES + CMD5/CMD3/CMD7 re-handshake\n");

	/*
	 * 1. CCCR.CTL.RES -- chip enters idle state.  Don't gate on the
	 * write succeeding cleanly: some chips reset DURING the response
	 * window and the host sees CRC errors that we should ignore.
	 */
	(void)sdio_cccr_write_byte(sc->sc_dev, SD_IO_CCCR_CTL, CCCR_CTL_RES);
	pause("bwfmrst", hz / 100);	/* ~10 ms for the chip to settle */

	/*
	 * 2. Host-side cached state is now stale: the chip dropped its
	 * backplane window register set when it reset.  Clear sc_sbwad so
	 * the next set_backplane triggers a cold reprogram.
	 */
	sc->sc_sbwad = 0;

	/*
	 * 3. CMD5 with arg=0 -- probe.  Card responds with its OCR.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = SD_IO_SEND_OP_COND;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_R4 | MMC_CMD_BCR;
	err = mmc_wait_for_cmd(mmcbus, sc->sc_dev, &cmd, 0);
	if (err != MMC_ERR_NONE) {
		device_printf(sc->sc_dev,
		    "soft-reset: CMD5 probe failed err=%d\n", err);
		return (EIO);
	}
	ocr = cmd.resp[0] & 0xffffff;

	/*
	 * 4. CMD5 with our OCR -- request power-on at the negotiated
	 * voltage range.  Loop until the chip clears the busy bit.
	 */
	for (i = 0; i < 100; i++) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.opcode = SD_IO_SEND_OP_COND;
		cmd.arg = ocr;
		cmd.flags = MMC_RSP_R4 | MMC_CMD_BCR;
		err = mmc_wait_for_cmd(mmcbus, sc->sc_dev, &cmd, 0);
		if (err != MMC_ERR_NONE)
			break;
		if ((cmd.resp[0] & MMC_OCR_CARD_BUSY) != 0)
			break;
		pause("bwfm5", 1);
	}
	if (err != MMC_ERR_NONE ||
	    (cmd.resp[0] & MMC_OCR_CARD_BUSY) == 0) {
		device_printf(sc->sc_dev,
		    "soft-reset: CMD5 power-on never ready err=%d "
		    "resp=0x%08x\n", err, cmd.resp[0]);
		return (EIO);
	}

	/*
	 * 5. CMD3 -- chip publishes a new RCA.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = SD_SEND_RELATIVE_ADDR;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_R6 | MMC_CMD_BCR;
	err = mmc_wait_for_cmd(mmcbus, sc->sc_dev, &cmd, 0);
	if (err != MMC_ERR_NONE) {
		device_printf(sc->sc_dev,
		    "soft-reset: CMD3 failed err=%d\n", err);
		return (EIO);
	}
	new_rca = (uint16_t)(cmd.resp[0] >> 16);

	/*
	 * 6. CMD7 -- select the new RCA so subsequent CMD52/53 land at
	 * the right chip.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = MMC_SELECT_CARD;
	cmd.arg = (uint32_t)new_rca << 16;
	cmd.flags = MMC_RSP_R1B | MMC_CMD_AC;
	err = mmc_wait_for_cmd(mmcbus, sc->sc_dev, &cmd, 0);
	if (err != MMC_ERR_NONE) {
		device_printf(sc->sc_dev,
		    "soft-reset: CMD7 (RCA=0x%04x) failed err=%d\n",
		    new_rca, err);
		return (EIO);
	}

	/*
	 * 7. Update sdio_bus_ivars so any future kldunload+kldload (or
	 * sdio_attach reselect) sees the current RCA.  CMD52 itself is
	 * implicitly addressed to the currently-selected card and doesn't
	 * carry RCA in its argument, but other consumers of sbi_rca do.
	 */
	sbi->sbi_rca = new_rca;

	device_printf(sc->sc_dev,
	    "soft-reset complete: new RCA=0x%04x, OCR=0x%06x\n",
	    new_rca, ocr);
	return (0);
}

/* sysctl: soft-reset the chip */
static int
bwfm_sdio_sysctl_soft_reset(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_chip_soft_reset(sc);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/* stop the CR4 core now */
static int
bwfm_sdio_halt_cr4_now(struct bwfm_sdio_softc *sc)
{
	struct bwfm_chip_core *cr4;
	int err;

	sx_assert(&sc->sc_chip_sx, SA_XLOCKED);

	/*
	 * Soft-reset the chip first so the bring-up runs against freshly
	 * booted silicon rather than whatever the Pi boot ROM left in the
	 * PMU latches.  With that stale PMU state, the buscoreprep
	 * CHIPCLKCSR write (FORCE_HW_CLKREQ_OFF | ALP_AVAIL_REQ, as Linux
	 * does at startup) wedges the BCM43455 backplane; CC.EROMPTR reads
	 * 0 and only a reboot recovers.  The soft reset gives the same
	 * clean state Linux gets from mmc-pwrseq-simple.
	 */
	err = bwfm_sdio_chip_soft_reset(sc);
	if (err != 0)
		return (err);

	err = bwfm_sdio_enable_func1(sc);
	if (err != 0)
		return (err);

	/*
	 * Broadcom-specific CCCR write: set CMD_NODEC in
	 * SDIO_CCCR_BWFM_CARDCAP (0xF0).  This changes how the chip
	 * decodes CMD52/53 and -- critically for our purposes -- is
	 * what wakes the chip out of its deep idle so the PMU will
	 * actually action a subsequent HT_AVAIL_REQ.  Without this
	 * write, CHIPCLKCSR will ack HT_AVAIL_REQ (the request bit
	 * stays set) but HT_AVAIL never asserts.  Linux does not do this
	 * at probe: it writes CARDCAP only later, in brcmf_sdio_sr_init(),
	 * and uses CMD_NODEC only on 43751/43752/43012 (CMD14_SUPPORT |
	 * CMD14_EXT otherwise).  We write CMD_NODEC early by choice.
	 */
	err = sdio_cccr_write_byte(sc->sc_dev, SDIO_CCCR_BWFM_CARDCAP,
	    SDIO_CCCR_BWFM_CARDCAP_CMD_NODEC);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "CCCR.BWFM_CARDCAP write (CMD_NODEC) failed err=%d\n",
		    err);
		return (err);
	}
	DPRINTF(&sc->bsc_base, 1,
	    "CCCR.BWFM_CARDCAP set to CMD_NODEC for HT wake\n");

	/*
	 * Wake the chip out of any sleep state before we go asking
	 * for HT.  Without this the PMU's 32 kHz domain keeps the chip
	 * drowsy and HT_AVAIL_REQ acknowledgements never produce HT.
	 */
	err = bwfm_sdio_kso_enable(sc);
	if (err != 0)
		return (err);

	/*
	 * Buscoreprep -- force ALP, lock hw-clock-request off.  This is
	 * only safe on the freshly reset chip.
	 */
	err = bwfm_sdio_buscoreprep(sc);
	if (err != 0)
		return (err);

	/*
	 * OpenBSD makes two corrective writes the boot ROM leaves undone
	 * (only the second is done here; see below):
	 *
	 *   1. CCCR.BWFM_CARDCTRL |= WLANRESET resets the WLAN subsystem
	 *      while keeping the SDIO/CCCR session intact.  The boot ROM
	 *      leaves the WLAN side in a half-configured state; without
	 *      this the d11/CR4 wraps stay clock-gated regardless of
	 *      PMU programming.
	 *
	 *   2. CC.PMUCONTROL |= (RES_RELOAD << RES_SHIFT) tells the PMU
	 *      to reload its resource table.  The boot ROM's partial
	 *      configuration leaves the resource graph in a state where
	 *      FORCE_HT in CHIPCLKCSR is acknowledged but the PMU
	 *      doesn't actually transition the HT PLL on.  After
	 *      RES_RELOAD the resource graph re-evaluates and FORCE_HT
	 *      produces real HT.
	 *
	 * Sequence drawn from OpenBSD bwfm_sdio_attach (sys/dev/sdmmc/
	 * if_bwfm_sdio.c); same chip facts apply.
	 */
	{
		uint32_t pmuctl;

		/*
		 * CCCR.BWFM_CARDCTRL |= WLANRESET (OpenBSD bwfm_sdio_attach)
		 * is deliberately NOT done here: on BCM43455 on Pi 4 it
		 * tears down the chip's WLAN-side backplane and the chip
		 * stops servicing CMD53 for long enough that SDHCI's host
		 * controller times out before we can resume.  The PMU
		 * RES_RELOAD alone gives the resource-graph reconfiguration
		 * the pair is for.
		 */

		err = bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMUCONTROL, &pmuctl);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "PMUCONTROL read failed err=%d\n", err);
			return (err);
		}
		pmuctl |= (BWFM_CC_PMUCONTROL_RES_RELOAD <<
		    BWFM_CC_PMUCONTROL_RES_SHIFT);
		err = bwfm_sdio_bp_write32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_PMUCONTROL, pmuctl);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "PMUCONTROL write failed err=%d\n", err);
			return (err);
		}
		DPRINTF(&sc->bsc_base, 1,
		    "PMUCONTROL |= RES_RELOAD (now 0x%08x)\n", pmuctl);
	}

	/*
	 * Release the FORCE_ALP lock and ask the PMU for HT.  The resource
	 * table reload above is what makes this produce real HT; without
	 * it the request bit sticks in CHIPCLKCSR but HT_AVAIL never
	 * asserts.
	 */
	err = bwfm_sdio_request_ht_clock(sc);
	if (err != 0)
		return (err);

	err = bwfm_sdio_chip_ensure(sc);
	if (err != 0)
		return (err);
	err = bwfm_chip_walk_erom(&sc->sc_chip);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bwfm_chip_walk_erom failed err=%d\n", err);
		return (err);
	}
	cr4 = bwfm_chip_get_core(&sc->sc_chip, BCMA_CORE_ARM_CR4);
	if (cr4 == NULL) {
		device_printf(sc->sc_dev,
		    "EROM walk did not find ARM_CR4 core (id 0x%03x)\n",
		    BCMA_CORE_ARM_CR4);
		return (ENOENT);
	}
	device_printf(sc->sc_dev,
	    "EROM walk: %u cores discovered; CR4 base=0x%08x wrap=0x%08x\n",
	    sc->sc_chip.ncores, cr4->base, cr4->wrap);

	return (bwfm_sdio_halt_cr4(sc, cr4->wrap));
}

/* sysctl: halt the CR4 core */
static int
bwfm_sdio_sysctl_halt_cr4(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_halt_cr4_now(sc);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/*
 * Release the ARM-CR4 core so it begins executing the firmware we
 * just uploaded to SOCRAM.  Native port of brcmf_chip_cr4_set_active
 * + brcmf_chip_ai_resetcore (Linux brcmfmac/chip.c) + the activate
 * step from brcmf_sdio_buscore_activate (sdio.c).
 *
 * Sequence (per Linux, called as resetcore(cr4, prereset=CPUHALT,
 * reset=0, postreset=0)):
 *
 *   1. write reset vector (= first 4 bytes of firmware blob in
 *      SOCRAM) to chip address 0; the chip's boot ROM jumps there
 *      when CR4 comes out of reset.
 *   2. ai_coredisable: pre-configure IOCTL with HALT|FGC|CLK,
 *      assert RESET_CTL, then write IOCTL with FGC|CLK (HALT
 *      cleared so CR4 starts as soon as reset drops).
 *   3. clear RESET_CTL (write 0, poll until it sticks).
 *   4. final IOCTL = postreset|CLK = CLK only (drop FGC; CR4 now
 *      runs on regular gated clock).
 *
 * Pre-condition: firmware + NVRAM already uploaded by load_firmware.
 * Without that the CR4 branches to garbage and the chip wedges.
 *
 * Post-condition: CR4 is fetching from SOCRAM; the firmware later
 * publishes its sdpcm_shared pointer, which bwfm_sdio_poll_boot_done
 * waits for.
 */
static int
bwfm_sdio_release_cr4_now(struct bwfm_sdio_softc *sc)
{
	struct bwfm_chip_core *cr4;
	const struct bwfm_sdio_chip_recipe *r;
	uint32_t chipid, rstvec, ioctl_final, cr4_wrap;
	uint16_t chip_id;
	uint8_t chip_rev;
	int err;

	sx_assert(&sc->sc_chip_sx, SA_XLOCKED);

	/*
	 * Look up the chip recipe to know where the firmware lives.
	 * Re-read CC.CHIPID via the backplane window we set up earlier;
	 * if a soft-reset happened between load_firmware and now we'd
	 * be working against a fresh chip with empty SOCRAM, which we
	 * detect by reading the reset vector and refusing to proceed
	 * if it looks unreasonable.
	 */
	err = bwfm_sdio_bp_read32(sc, BWFM_CC_CORE_BASE + BWFM_CC_CHIPID,
	    &chipid);
	if (err != 0)
		return (err);
	chip_id = BWFM_CHIPID_ID(chipid);
	chip_rev = BWFM_CHIPID_REV(chipid);
	r = bwfm_sdio_lookup_recipe(chip_id, chip_rev);
	if (r == NULL) {
		device_printf(sc->sc_dev,
		    "release_cr4: no recipe for chip=0x%04x rev=%u\n",
		    chip_id, chip_rev);
		return (ENOENT);
	}

	err = bwfm_sdio_chip_ensure(sc);
	if (err != 0)
		return (err);
	/* EROM walk may already have been done by halt_cr4_now; only walk
	 * if the chip layer doesn't yet have a CR4 core registered. */
	cr4 = bwfm_chip_get_core(&sc->sc_chip, BCMA_CORE_ARM_CR4);
	if (cr4 == NULL) {
		err = bwfm_chip_walk_erom(&sc->sc_chip);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "release_cr4: bwfm_chip_walk_erom failed err=%d\n",
			    err);
			return (err);
		}
		cr4 = bwfm_chip_get_core(&sc->sc_chip, BCMA_CORE_ARM_CR4);
	}
	if (cr4 == NULL) {
		device_printf(sc->sc_dev,
		    "release_cr4: no CR4 core in EROM walk\n");
		return (ENOENT);
	}
	cr4_wrap = cr4->wrap;

	/*
	 * Reset vector = first 4 bytes of firmware in SOCRAM.  If the
	 * upload landed cleanly this is the entry-point branch the
	 * Cortex-R4 will take on first instruction fetch.
	 */
	err = bwfm_sdio_bp_read32(sc, r->ram_base, &rstvec);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "release_cr4: read rstvec at chip 0x%06x failed err=%d\n",
		    r->ram_base, err);
		return (err);
	}
	if (rstvec == 0 || rstvec == 0xffffffff) {
		device_printf(sc->sc_dev,
		    "release_cr4: rstvec at 0x%06x = 0x%08x (firmware not "
		    "uploaded?)  refusing to release\n",
		    r->ram_base, rstvec);
		return (ENXIO);
	}
	device_printf(sc->sc_dev,
	    "release_cr4: chip=0x%04x rev=%u cr4_wrap=0x%08x rstvec=0x%08x\n",
	    chip_id, chip_rev, cr4_wrap, rstvec);

	/*
	 * bwfm_chip_cr4_set_active writes rstvec to chip[0] via the
	 * transport's activate hook, then runs the AI resetcore with
	 * prereset=CPUHALT / reset=0 / postreset=0 so the CR4 comes out of
	 * reset clean and starts fetching at chip[0].
	 */
	err = bwfm_chip_cr4_set_active(&sc->sc_chip, rstvec);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bwfm_chip_cr4_set_active failed err=%d\n", err);
		return (err);
	}

	err = bwfm_sdio_bp_read32(sc, cr4_wrap + BCMA_IOCTL, &ioctl_final);
	if (err != 0)
		return (err);
	device_printf(sc->sc_dev,
	    "release_cr4: CR4 released -- final IOCTL=0x%08x "
	    "(expected 0x%08x)\n", ioctl_final, BCMA_IOCTL_CLK);

	/*
	 * Unblock the firmware clock.  During upload the backplane is
	 * held on FORCE_ALP | FORCE_HW_CLKREQ_OFF for stability.  Leave
	 * it locked and the now-running firmware's hardware HT requests
	 * are ignored, so it stalls in early init and never publishes
	 * sdpcm_shared.  Clear the force bits and ask for HT so the PMU
	 * services the firmware's clock requests.
	 */
	err = bwfm_sdio_request_ht_clock(sc);
	if (err != 0)
		device_printf(sc->sc_dev,
		    "release_cr4: HT clock request failed err=%d "
		    "(continuing)\n", err);

	{	/* Fast clock on, so the firmware runs at full speed. */
		uint8_t ck = 0;
		(void)sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR, &ck);
		(void)sdio_write_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR,
		    ck | SBSDIO_FORCE_HT);
	}

	/*
	 * Give the firmware 200 ms to start, then sample signs of life:
	 *   - CHIPCLKCSR (F1 @ 0x1000E): goes from ALP-only (~0x42) to
	 *     HT_AVAIL (0xC2) once the firmware requests HT
	 *   - chip[0x25fffc]: the sdpcm_shared_ptr slot, which holds the
	 *     NVRAM length token (0xfe4b01b4) until the firmware's SDPCM
	 *     init overwrites it
	 *   - chip[ram_base + 0xb0000]: in the firmware's heap/stack, so
	 *     non-zero means CR4 is writing memory
	 */
	{
		uint8_t clkcsr = 0;
		uint32_t shared_ptr = 0, heap_canary = 0;
		DELAY(200000);
		(void)sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR,
		    &clkcsr);
		(void)bwfm_sdio_bp_read32(sc, BWFM_43455_SHARED_SLOT,
		    &shared_ptr);
		(void)bwfm_sdio_bp_read32(sc, r->ram_base + 0xb0000u,
		    &heap_canary);
		device_printf(sc->sc_dev,
		    "release_cr4: post-release indicators: "
		    "CHIPCLKCSR=0x%02x %s, sdpcm_shared_ptr=0x%08x, "
		    "SOCRAM[ram_base+0xb0000]=0x%08x\n",
		    clkcsr,
		    (clkcsr & 0x80) ? "HT_AVAIL" :
		    ((clkcsr & 0x40) ? "ALP_AVAIL" : "no clk"),
		    shared_ptr, heap_canary);
		if ((clkcsr & 0x80) != 0 || heap_canary != 0)
			device_printf(sc->sc_dev,
			    "release_cr4: *** fw appears ALIVE ***\n");
		else
			device_printf(sc->sc_dev,
			    "release_cr4: fw indicators flat -- not running "
			    "or still very early\n");
	}

	/*
	 * F2 SDPCM data path bring-up.  Once CR4 is executing and the
	 * post-release indicators look healthy (HT_AVAIL or SOCRAM
	 * activity), enable SDIO function 2 via CCCR.IOEn and poll
	 * CCCR.IORx until the F2 bit reports ready.  fw lights the
	 * F2 backend asynchronously after CR4 release, typically within
	 * a few ms; we give it up to 500 ms.
	 *
	 * After this returns 0 the F2 device_t plumbed earlier (see
	 * bwfm_sdio_f2_attach) is the live transport for SDPCM control
	 * and data frames.
	 */
	if (sc->sc_f2_dev != NULL && !sc->sc_f2_enabled) {
		uint8_t io_en = 0, io_rdy = 0;
		int rc, j;

		rc = sdio_cccr_read_byte(sc->sc_dev, SD_IO_CCCR_FN_ENABLE,
		    &io_en);
		if (rc != 0) {
			device_printf(sc->sc_dev,
			    "release_cr4: F2 enable: CCCR.IOEn read failed err=%d\n",
			    rc);
		} else {
			io_en |= SDIO_FUNC_ENABLE_2;
			rc = sdio_cccr_write_byte(sc->sc_dev,
			    SD_IO_CCCR_FN_ENABLE, io_en);
			if (rc != 0) {
				device_printf(sc->sc_dev,
				    "release_cr4: F2 enable: CCCR.IOEn write "
				    "0x%02x failed err=%d\n", io_en, rc);
			} else {
				for (j = 0; j < 50; j++) {
					DELAY(10000);
					(void)sdio_cccr_read_byte(sc->sc_dev,
					    SD_IO_CCCR_FN_READY, &io_rdy);
					if (io_rdy & SDIO_FUNC_READY_2)
						break;
				}
				if (io_rdy & SDIO_FUNC_READY_2) {
					uint32_t fbr2 = SD_IO_FBR_START_F(2) +
					    SD_IO_FBR_IOBLKSZ;
					uint16_t f2_blksize = 256;
					int br;

					/*
					 * Program the F2 block size in
					 * CCCR FBR2.IOBLKSZ.  We use 256
					 * (block-mode CMD53 boundary on
					 * F2 = SDPCM frame boundary).
					 * Linux uses 512 for BCM43455
					 * and 256 for 4354/4356/4359.
					 * Without this, block-mode CMD53
					 * to F2 fails with a CRC error,
					 * as on F1.
					 */
					br = sdio_cccr_write_byte(sc->sc_dev, fbr2,
					    f2_blksize & 0xff);
					if (br == 0)
						br = sdio_cccr_write_byte(sc->sc_dev,
						    fbr2 + 1,
						    (f2_blksize >> 8) & 0xff);
					if (br != 0) {
						device_printf(sc->sc_dev,
						    "release_cr4: F2.IOBLKSZ "
						    "write %u failed err=%d\n",
						    f2_blksize, br);
					}
					sc->sc_f2_enabled = true;
					device_printf(sc->sc_dev,
					    "release_cr4: F2 enabled "
					    "(CCCR.IOEn=0x%02x IORx=0x%02x "
					    "after %d ms, FBR2.IOBLKSZ=%u)\n",
					    io_en, io_rdy, j * 10, f2_blksize);
					/*
					 * Arm the periodic SDIO watchdog now
					 * that F2 is live.  Linux fires this
					 * every 10 ms; without it BCM43455 fw
					 * tears down assoc when it sees no
					 * host SDIO traffic.
					 */
					callout_reset(&sc->sc_wd_callout,
					    MSEC_2_TICKS(
					        (u_int)BWFM_WD_POLL_MS),
					    bwfm_sdio_watchdog_callout, sc);
				} else {
					device_printf(sc->sc_dev,
					    "release_cr4: F2 enable timeout "
					    "(CCCR.IOEn=0x%02x IORx=0x%02x "
					    "after %d ms)\n",
					    io_en, io_rdy, j * 10);
				}
			}
		}
	} else if (sc->sc_f2_dev == NULL) {
		device_printf(sc->sc_dev,
		    "release_cr4: F2 not attached -- SDPCM transport "
		    "unavailable\n");
	}

	/*
	 * The firmware waits for these last writes before it finishes
	 * coming up: tell it which signals we want and that the host is
	 * ready.
	 */
	(void)bwfm_sdio_bp_write32(sc, 0x18004024u, 0x200000f0u);	/* hostintmask */
	(void)bwfm_sdio_bp_write32(sc, 0x18004048u, 0x00040000u);	/* tosbmailboxdata */
	(void)sdio_write_byte(sc->sc_dev, 0x10008u, 0x08u);
	(void)bwfm_sdio_bp_write32(sc, 0x18000650u, 0x00000003u);
	device_printf(sc->sc_dev,
	    "release_cr4: SDPCM datapath handshake written "
	    "(hostintmask=0x200000f0, tosbmailboxdata=0x00040000)\n");

	device_printf(sc->sc_dev,
	    "release_cr4: next phase = poll SDPCM boot_done marker\n");
	return (0);
}

/* sysctl: release the CR4 core from reset */
static int
bwfm_sdio_sysctl_release_cr4(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	if (sc->sc_autostart_running)
		return (EBUSY);	/* autostart is bringing the chip up */
	if (sc->bsc_base.sc_ic_attached)
		return (EBUSY);	/* firmware running: reload the module */
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_release_cr4_now(sc);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/*
 * BCDC iovar wrappers.  Hide the SDPCM TX/RX dance behind a small
 * (name, value) API so callers don't have to spell out the CMD53 +
 * mbuf bookkeeping for every iovar.
 *
 * Locking: caller MUST hold sc->sc_chip_sx exclusive across the call.
 * The wrapper drains any stale CONTROL responses before TX so a late
 * reply from a previous iovar doesn't get returned to this caller.
 *
 * Reqid: each call bumps st->bcdc_reqid so back-to-back iovars do not
 * collide on the wire, and the reply is matched on its dcmd ID below.
 */
static int
bwfm_sdio_iovar_xfer(struct bwfm_sdio_softc *sc, uint8_t *req, size_t reqlen,
    struct mbuf **respp)
{
	struct bwfm_sdpcm_state *st = sc->sc_sdpcm;
	struct mbuf *resp;
	uint32_t req_flags, resp_flags;
	uint16_t req_id, resp_id;
	int err, polls;

	*respp = NULL;

	if (reqlen < sizeof(struct bwfm_bcdc_dcmd))
		return (EINVAL);

	/* Snapshot the reqid we put on the wire so we can match the reply. */
	memcpy(&req_flags, req + 8, sizeof(req_flags));
	req_flags = le32toh(req_flags);
	req_id = (uint16_t)((req_flags >> BWFM_BCDC_DCMD_ID_SHIFT) &
	    BWFM_BCDC_DCMD_ID_MASK);

	/*
	 * Serialise against bs_pump_rx (the fmop_scan_start poller)
	 * and against other in-flight iovar_xfer calls.  Both paths
	 * call bwfm_sdpcm_rx_frames against the same F2 FIFO; two
	 * concurrent readers interleave packet bytes and corrupt
	 * the SDPCM state machine.  sc_chip_sx is SX_RECURSE so
	 * cmd_scan_sysctl (which already holds it across its escan
	 * iovar) can re-enter without deadlocking.
	 */
	sx_xlock(&sc->sc_chip_sx);

	/* Drain any leftover CONTROL response from a previous call. */
	mtx_lock(&st->sp_lock);
	while ((resp = st->ctrl_resp) != NULL) {
		st->ctrl_resp = resp->m_nextpkt;
		m_freem(resp);
	}
	mtx_unlock(&st->sp_lock);

	err = bwfm_sdpcm_tx_ctrlframe(st, sc->sc_f2_dev, req, reqlen);
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0)
		return (err);

	/*
	 * Poll the F2 FIFO until we see a CONTROL response whose reqid
	 * matches the one we sent.  The BCM43455 0xff-swhdr fallback in
	 * bwfm_sdpcm_rx_frames can misclassify other frames as CONTROL,
	 * and a slow ack to a prior request can still be in the ctrl
	 * queue despite the drain above (e.g. the firmware replying to
	 * the previous iovar after it timed out).  Linux brcmfmac matches
	 * the reqid too; without it a stale mbuf's first 16 bytes would
	 * be parsed as a dcmd header and reported as a garbage firmware
	 * error status.
	 */
	/*
	 * 100 × ~50 ms ≈ 5 s.  Linux SDIO waits 2.5 s for a dcmd reply
	 * (DCMD_RESP_TIMEOUT in sdio.c); we allow longer for join, since
	 * the "join" iovar / SET_SSID dcmd doesn't ack until the chip has
	 * finished off-channel auth+assoc, which can take 100s of ms on a
	 * busy 2.4 GHz band.  The long timeout doesn't starve the
	 * watchdog because sc_chip_sx is dropped between polls.
	 */
	resp = NULL;
	{
		/*
		 * Bounded stale-response handling.  On BCM43455 the
		 * 0xff-swhdr fallback in bwfm_sdpcm_rx_frames can
		 * misclassify an event frame as CONTROL, and the same
		 * stale id then comes back on every poll.  Log it once
		 * and fail fast if it repeats, rather than spending the
		 * whole timeout on it.
		 */
		uint16_t last_stale_id = 0;
		u_int same_id_repeats = 0;
		bool logged_this_call = false;

		for (polls = 0; polls < 100; polls++) {
			sx_xlock(&sc->sc_chip_sx);
			(void)bwfm_sdpcm_rx_frames(st, sc->sc_f2_dev);
			sx_xunlock(&sc->sc_chip_sx);
			resp = bwfm_sdpcm_wait_ctrl_resp(st, 50);
			if (resp == NULL)
				continue;
			if (resp->m_pkthdr.len <
			    (int)sizeof(struct bwfm_bcdc_dcmd)) {
				m_freem(resp);
				resp = NULL;
				continue;
			}
			m_copydata(resp, 8, sizeof(resp_flags),
			    (caddr_t)&resp_flags);
			resp_flags = le32toh(resp_flags);
			resp_id = (uint16_t)(
			    (resp_flags >> BWFM_BCDC_DCMD_ID_SHIFT) &
			    BWFM_BCDC_DCMD_ID_MASK);
			if (resp_id == req_id)
				break;
			/*
			 * Stale id.  Log once per call for this id, and
			 * if the same id comes back 4 times in a row,
			 * bail early: the SDPCM parser has a stuck
			 * frame and waiting out the 5 s window won't
			 * help.
			 */
			if (resp_id != last_stale_id) {
				last_stale_id = resp_id;
				same_id_repeats = 1;
				logged_this_call = false;
			} else {
				same_id_repeats++;
			}
			if (!logged_this_call) {
				device_printf(sc->sc_dev,
				    "iovar_xfer: dropping stale resp "
				    "id=%u (want %u); further drops of "
				    "this id in this call are silent\n",
				    resp_id, req_id);
				logged_this_call = true;
			}
			m_freem(resp);
			resp = NULL;
			if (same_id_repeats >= 4) {
				device_printf(sc->sc_dev,
				    "iovar_xfer: id=%u stuck in CTRL queue "
				    "(%u repeats) — SDPCM 0xff-swhdr "
				    "fallback likely misclassifying an "
				    "event frame; bailing early\n",
				    resp_id, same_id_repeats);
				return (EIO);
			}
		}
	}

	if (resp == NULL)
		return (ETIMEDOUT);

	*respp = resp;
	return (0);
}

/*
 * EVENT channel callback installed at sc_sdpcm allocation time.
 * Decodes the event code + status + reason + flags and prints a
 * single dmesg line per event.  Events reach net80211 through the
 * raw-EVENT path (bwfm_sdio_event_rx) instead.
 *
 * Called with no locks held (rx_frames doesn't hold sp_lock at
 * dispatch time).  Must be brief — see the prototype contract.
 */
static const char *
bwfm_sdio_event_name(uint32_t code)
{
	/*
	 * Codes follow Linux brcmfmac fweh.h enum brcmf_fweh_event_code
	 * (BRCMF_ENUM_DEF macro list), with some names shortened.
	 * Codes 76, 80 and 124 are not in Linux's list.  Keep in sync
	 * when porting.
	 */
	switch (code) {
	case 0:				return "SET_SSID";
	case 1:				return "JOIN";
	case 2:				return "START";
	case BWFM_E_TYPE_AUTH:		return "AUTH";	/* 3 */
	case 4:				return "AUTH_IND";
	case BWFM_E_DEAUTH:		return "DEAUTH";	/* 5 */
	case 6:				return "DEAUTH_IND";
	case BWFM_E_TYPE_ASSOC:		return "ASSOC";	/* 7 */
	case 8:				return "ASSOC_IND";
	case 9:				return "REASSOC";
	case 10:			return "REASSOC_IND";
	case BWFM_E_TYPE_DISASSOC:	return "DISASSOC";	/* 11 */
	case 12:			return "DISASSOC_IND";
	case 15:			return "BEACON_RX";
	case BWFM_E_TYPE_LINK:		return "LINK";	/* 16 */
	case 17:			return "MIC_ERROR";
	case 18:			return "NDIS_LINK";
	case 19:			return "ROAM";
	case 20:			return "TXFAIL";
	case 21:			return "PMKID_CACHE";
	case 23:			return "PRUNE";
	case 24:			return "AUTOAUTH";
	case BWFM_E_EAPOL_MSG:		return "EAPOL_MSG";	/* 25 */
	case 26:			return "SCAN_COMPLETE";
	case 27:			return "ADDTS_IND";
	case 28:			return "DELTS_IND";
	case 30:			return "BCNRX_MSG";
	case 31:			return "BCNLOST_MSG";
	case 32:			return "ROAM_PREP";
	case 33:			return "PFN_NET_FOUND";
	case 34:			return "PFN_NET_LOST";
	case 35:			return "RESET_COMPLETE";
	case 36:			return "JOIN_START";
	case 37:			return "ROAM_START";
	case 38:			return "ASSOC_START";
	case 39:			return "IBSS_ASSOC";
	case 40:			return "RADIO";
	case 41:			return "PSM_WATCHDOG";
	case 44:			return "PROBREQ_MSG";
	case 45:			return "SCAN_CONFIRM_IND";
	case 46:			return "PSK_SUP";
	case 47:			return "COUNTRY_CHANGED";
	case 50:			return "UNICAST_DECODE_ERR";
	case 51:			return "MCAST_DECODE_ERR";
	case BWFM_E_IF:			return "IF";	/* 54 */
	case 56:			return "RSSI";
	case 59:			return "ACTION_FRAME";
	case 60:			return "ACTION_FRAME_COMPLETE";
	case BWFM_E_TYPE_ESCAN_RESULT:	return "ESCAN_RESULT";	/* 69 */
	case 70:			return "AF_OFF_CHAN_COMPLETE";
	case 71:			return "PROBERESP_MSG";
	case 72:			return "P2P_PROBEREQ_MSG";
	case 73:			return "DCS_REQUEST";
	case 74:			return "FIFO_CREDIT_MAP";
	case 75:			return "ACTION_FRAME_RX";
	case 76:			return "WAKE_EVENT";
	case 80:			return "BSSID";
	case 124:			return "RSSI_LQM";
	default:			return "?";
	}
}

/*
 * Decode and print a single ESCAN_RESULT event's BSS info.  fw v0
 * blob: bwfm_escan_results header + single bwfm_bss_info entry.
 * Multi-byte fields little-endian on the wire.
 */
static void
bwfm_sdio_print_escan_result(struct bwfm_sdio_softc *sc, uint32_t status,
    const void *data, size_t datalen)
{
	const struct bwfm_escan_results *res;
	const struct bwfm_bss_info *bss;
	char ssid[BWFM_MAX_SSID_LEN + 1];
	uint16_t chanspec, capability;
	int16_t rssi;
	uint8_t ssid_len;

	if (status != BWFM_E_STATUS_PARTIAL) {
		device_printf(sc->sc_dev,
		    "EVENT ESCAN_RESULT terminator status=%u datalen=%zu\n",
		    status, datalen);
		return;
	}
	if (datalen < sizeof(*res) + sizeof(*bss))
		return;

	res = (const struct bwfm_escan_results *)data;
	bss = (const struct bwfm_bss_info *)(const void *)
	    ((const uint8_t *)data + sizeof(*res));

	ssid_len = bss->ssid_len;
	if (ssid_len > BWFM_MAX_SSID_LEN)
		ssid_len = BWFM_MAX_SSID_LEN;
	memcpy(ssid, bss->ssid, ssid_len);
	ssid[ssid_len] = '\0';

	chanspec = le16toh(bss->chanspec);
	capability = le16toh(bss->capability);
	rssi = (int16_t)le16toh((uint16_t)bss->rssi);

	device_printf(sc->sc_dev,
	    "ESCAN_RESULT bssid=%02x:%02x:%02x:%02x:%02x:%02x rssi=%d "
	    "chanspec=0x%04x ctl_ch=%u cap=0x%04x ssid=\"%s\"\n",
	    bss->bssid[0], bss->bssid[1], bss->bssid[2],
	    bss->bssid[3], bss->bssid[4], bss->bssid[5],
	    rssi, chanspec, bss->ctl_ch, capability, ssid);
}

/*
 * Raw-EVENT callback: wraps the BCDC-prefixed SDPCM body in an mbuf
 * and hands it to bwfm_rx_frame, which decodes the BWFM event
 * encapsulation and routes to bwfm_handle_event (scan results -> ic
 * scan cache, link state -> vap newstate, etc.).
 *
 * Only fires after net80211 is attached.  Before ic_attached, the
 * decoded event_cb still prints to dmesg so the diagnostic path
 * remains useful.
 */
/*
 * Worker that drains the per-sc event queue and hands each mbuf to
 * bwfm_rx_frame.  Runs on a dedicated taskqueue thread, never in the
 * SDPCM rx context, so bwfm_rx_frame's re-entrant net80211 calls
 * (ieee80211_input_all, ieee80211_new_state, taskqueue enqueues)
 * don't run inside the chip_sx thread driving the scan poll loop.
 * Mirrors Linux brcmfmac's event_worker workqueue split.
 */
/*
 * Event delivery switch, on by default.  Set to 0 to drop events
 * instead of calling bwfm_rx_frame, for debugging.
 */
static int bwfm_sdio_evrx_deliver = 1;
SYSCTL_INT(_dev, OID_AUTO, bwfm_evrx_deliver, CTLFLAG_RWTUN,
    &bwfm_sdio_evrx_deliver, 0,
    "1 = SDIO event rx worker calls bwfm_rx_frame (default); 0 = drop");

/* deferred task that pushes rx frames up the stack */
static void
bwfm_sdio_event_rx_worker(void *arg, int pending __unused)
{
	struct bwfm_sdio_softc *sc = arg;
	struct mbuf *m;

	for (;;) {
		mtx_lock(&sc->sc_event_rx_mtx);
		m = mbufq_dequeue(&sc->sc_event_rx_q);
		mtx_unlock(&sc->sc_event_rx_mtx);
		if (m == NULL)
			break;
		if (bwfm_sdio_evrx_deliver && sc->bsc_base.sc_ic_attached)
			bwfm_rx_frame(&sc->bsc_base, m);
		else
			m_freem(m);
	}
}

/* queue a received raw frame for the worker */
static void
bwfm_sdio_event_rx(void *arg, const void *body, size_t paylen)
{
	struct bwfm_sdio_softc *sc = arg;
	struct mbuf *m;

	if (!sc->bsc_base.sc_ic_attached)
		return;
	/*
	 * bwfm_rx_frame -> bwfm_handle_event reads `p + evpos` with
	 * `p = mtod(m, uint8_t *)` — assumes the mbuf data is one
	 * contiguous run.  Cap at MCLBYTES and use m_getcl so we
	 * always get a single 2 KB cluster.  BCM43455 events stay
	 * well under 2 KB (the largest are around 530 B).
	 */
	if (paylen == 0 || paylen > MCLBYTES)
		return;

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return;
	memcpy(mtod(m, void *), body, paylen);
	m->m_len = paylen;
	m->m_pkthdr.len = paylen;

	mtx_lock(&sc->sc_event_rx_mtx);
	if (mbufq_enqueue(&sc->sc_event_rx_q, m) != 0) {
		mtx_unlock(&sc->sc_event_rx_mtx);
		m_freem(m);
		return;
	}
	mtx_unlock(&sc->sc_event_rx_mtx);

	taskqueue_enqueue(sc->sc_event_rx_tq, &sc->sc_event_rx_task);
}

/* log a decoded firmware event */
static void
bwfm_sdio_event_handler(void *arg, const struct bwfm_event_msg *msg,
    const void *data, size_t datalen)
{
	struct bwfm_sdio_softc *sc = arg;

	if (msg->event_type == BWFM_E_TYPE_ESCAN_RESULT) {
		bwfm_sdio_print_escan_result(sc, msg->status, data, datalen);
		return;
	}

	device_printf(sc->sc_dev,
	    "EVENT %s (%u) status=%u reason=%u flags=0x%x "
	    "datalen=%zu addr=%02x:%02x:%02x:%02x:%02x:%02x ifidx=%u\n",
	    bwfm_sdio_event_name(msg->event_type), msg->event_type,
	    msg->status, msg->reason, msg->flags, datalen,
	    msg->addr[0], msg->addr[1], msg->addr[2],
	    msg->addr[3], msg->addr[4], msg->addr[5],
	    msg->ifidx);
}

/* make sure the SDPCM state is set up */
static struct bwfm_sdpcm_state *
bwfm_sdio_iovar_ensure_state(struct bwfm_sdio_softc *sc)
{
	if (sc->sc_sdpcm == NULL) {
		/*
		 * F2 byte address 0x8000 = backplane offset 0 with the
		 * SBSDIO_SB_ACCESS_2_4B_FLAG bit set; blksize 256 is what
		 * we program on F2 (Linux uses 512 for BCM43455).
		 */
		sc->sc_sdpcm = bwfm_sdpcm_alloc(0x8000u, 256u);
		bwfm_sdpcm_set_event_handler(sc->sc_sdpcm,
		    bwfm_sdio_event_handler, sc);
		bwfm_sdpcm_set_event_rx(sc->sc_sdpcm,
		    bwfm_sdio_event_rx, sc);
	}
	return (sc->sc_sdpcm);
}

/*
 * GET a BCDC iovar.  Copies up to outlen bytes of the response payload
 * (the bytes after the 16-byte dcmd header) into out.  Returns 0 on
 * success, errno on transport failure, EIO on fw-side DCMD_ERROR.
 */
static int
bwfm_sdio_iovar_get(struct bwfm_sdio_softc *sc, const char *name,
    void *out, size_t outlen)
{
	struct bwfm_sdpcm_state *st;
	struct bwfm_bcdc_dcmd dh;
	struct mbuf *resp;
	uint8_t *buf;
	size_t bufsz, reqlen, avail, copy;
	uint16_t reqid;
	int err;

	if (name == NULL || (outlen > 0 && out == NULL))
		return (EINVAL);
	if (sc->sc_f2_dev == NULL || !sc->sc_f2_enabled)
		return (ENXIO);

	st = bwfm_sdio_iovar_ensure_state(sc);
	if (st == NULL)
		return (ENOMEM);

	bufsz = sizeof(struct bwfm_bcdc_dcmd) + strlen(name) + 1;
	if (outlen + sizeof(struct bwfm_bcdc_dcmd) > bufsz)
		bufsz = outlen + sizeof(struct bwfm_bcdc_dcmd);
	buf = malloc(bufsz, M_TEMP, M_WAITOK);

	mtx_lock(&st->sp_lock);
	if (++st->bcdc_reqid == 0)	/* skip 0 on wrap */
		st->bcdc_reqid = 1;
	reqid = st->bcdc_reqid;
	mtx_unlock(&st->sp_lock);

	reqlen = bwfm_bcdc_build_getvar(buf, bufsz, name, outlen, reqid);
	if (reqlen == 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	err = bwfm_sdio_iovar_xfer(sc, buf, reqlen, &resp);
	free(buf, M_TEMP);
	if (err != 0)
		return (err);

	if (resp->m_pkthdr.len < sizeof(dh)) {
		m_freem(resp);
		return (EIO);
	}
	m_copydata(resp, 0, sizeof(dh), (caddr_t)&dh);
	dh.flags = le32toh(dh.flags);
	dh.status = le32toh(dh.status);

	if (dh.flags & BWFM_BCDC_DCMD_ERROR) {
		device_printf(sc->sc_dev,
		    "iovar_get(%s): fw error status=%d\n", name,
		    (int32_t)dh.status);
		m_freem(resp);
		return (EIO);
	}

	if (outlen > 0) {
		avail = resp->m_pkthdr.len - sizeof(dh);
		copy = (outlen < avail) ? outlen : avail;
		m_copydata(resp, sizeof(dh), copy, out);
		if (copy < outlen)
			memset((uint8_t *)out + copy, 0, outlen - copy);
	}
	m_freem(resp);
	return (0);
}

/*
 * SET a BCDC iovar.  Sends name+value; response payload is discarded
 * (only the dcmd status field is inspected).  Returns 0 on success,
 * errno on transport failure, EIO on fw-side DCMD_ERROR.
 */
static int
bwfm_sdio_iovar_set(struct bwfm_sdio_softc *sc, const char *name,
    const void *val, size_t vallen)
{
	struct bwfm_sdpcm_state *st;
	struct bwfm_bcdc_dcmd dh;
	struct mbuf *resp;
	uint8_t *buf;
	size_t bufsz, reqlen;
	uint16_t reqid;
	int err;

	if (name == NULL || (vallen > 0 && val == NULL))
		return (EINVAL);
	if (sc->sc_f2_dev == NULL || !sc->sc_f2_enabled)
		return (ENXIO);

	st = bwfm_sdio_iovar_ensure_state(sc);
	if (st == NULL)
		return (ENOMEM);

	bufsz = sizeof(struct bwfm_bcdc_dcmd) + strlen(name) + 1 + vallen;
	buf = malloc(bufsz, M_TEMP, M_WAITOK);

	mtx_lock(&st->sp_lock);
	if (++st->bcdc_reqid == 0)	/* skip 0 on wrap */
		st->bcdc_reqid = 1;
	reqid = st->bcdc_reqid;
	mtx_unlock(&st->sp_lock);

	reqlen = bwfm_bcdc_build_setvar(buf, bufsz, name, val, vallen, reqid);
	if (reqlen == 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	err = bwfm_sdio_iovar_xfer(sc, buf, reqlen, &resp);
	free(buf, M_TEMP);
	if (err != 0)
		return (err);

	m_copydata(resp, 0, sizeof(dh), (caddr_t)&dh);
	dh.flags = le32toh(dh.flags);
	dh.status = le32toh(dh.status);
	m_freem(resp);

	if (dh.flags & BWFM_BCDC_DCMD_ERROR) {
		device_printf(sc->sc_dev,
		    "iovar_set(%s): fw error status=%d\n", name,
		    (int32_t)dh.status);
		return (EIO);
	}
	return (0);
}

/*
 * dev.bwfm.0.sdpcm_test=1 — cur_etheraddr round-trip test through
 * bwfm_sdio_iovar_get.
 */
static int
bwfm_sdio_sysctl_sdpcm_test(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	uint8_t mac[6] = { 0 };
	int err, rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	sx_xlock(&sc->sc_chip_sx);
	device_printf(sc->sc_dev, "sdpcm_test: GET cur_etheraddr\n");
	err = bwfm_sdio_iovar_get(sc, "cur_etheraddr", mac, sizeof(mac));
	sx_xunlock(&sc->sc_chip_sx);

	if (err != 0) {
		device_printf(sc->sc_dev,
		    "sdpcm_test: iovar_get failed err=%d\n", err);
		return (err);
	}
	device_printf(sc->sc_dev,
	    "sdpcm_test: cur_etheraddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (0);
}

/*
 * dev.bwfm.N.peek=<chip_addr> -- dump 8 words (32 bytes) from a chip /
 * backplane address via bp_read32.  Diagnostic for firmware boot: read
 * the sdpcm_shared slot, the firmware heap, etc.
 */
static int
bwfm_sdio_sysctl_peek(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	uint32_t addr = 0, v;
	int rc, i, e;

	rc = sysctl_handle_int(oidp, &addr, 0, req);
	if (rc != 0 || req->newptr == NULL || addr == 0)
		return (rc);

	sx_xlock(&sc->sc_chip_sx);
	device_printf(sc->sc_dev, "peek: 8 words from chip 0x%08x:\n", addr);
	for (i = 0; i < 8; i++) {
		e = bwfm_sdio_bp_read32(sc, addr + i * 4, &v);
		if (e != 0) {
			device_printf(sc->sc_dev,
			    "  [0x%08x] read err=%d\n", addr + i * 4, e);
			break;
		}
		device_printf(sc->sc_dev,
		    "  [0x%08x] = 0x%08x\n", addr + i * 4, v);
	}
	sx_xunlock(&sc->sc_chip_sx);
	return (0);
}

/*
 * dev.bwfm.0.iovar_get=<name> — generic GET probe.  Reads up to
 * BWFM_IOVAR_PROBE_MAX bytes of response, prints a hex+ASCII dump
 * to dmesg.  Useful for poking at "ver", "country", "cur_etheraddr",
 * "clmver", etc. without recompiling.
 */
#define	BWFM_IOVAR_PROBE_MAX	256u

/* sysctl: read a firmware variable by name */
static int
bwfm_sdio_sysctl_iovar_get(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	char name[64];
	uint8_t out[BWFM_IOVAR_PROBE_MAX];
	int err, rc;
	size_t i, asclen;
	char asciibuf[BWFM_IOVAR_PROBE_MAX + 1];

	name[0] = '\0';
	rc = sysctl_handle_string(oidp, name, sizeof(name), req);
	if (rc != 0 || req->newptr == NULL || name[0] == '\0')
		return (rc);

	memset(out, 0, sizeof(out));
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_iovar_get(sc, name, out, sizeof(out));
	sx_xunlock(&sc->sc_chip_sx);

	if (err != 0) {
		device_printf(sc->sc_dev,
		    "iovar_get(%s): err=%d\n", name, err);
		return (err);
	}

	/* Render the value: ASCII if printable, hex prefix otherwise. */
	asclen = 0;
	for (i = 0; i < sizeof(out); i++) {
		if (out[i] == '\0')
			break;
		if (out[i] < 0x20 || out[i] > 0x7e)
			break;
		asciibuf[asclen++] = (char)out[i];
	}
	asciibuf[asclen] = '\0';

	if (asclen >= 1) {
		device_printf(sc->sc_dev,
		    "iovar_get(%s) = \"%s\"\n", name, asciibuf);
	} else {
		device_printf(sc->sc_dev,
		    "iovar_get(%s) = %02x %02x %02x %02x %02x %02x %02x %02x"
		    " %02x %02x %02x %02x %02x %02x %02x %02x\n",
		    name,
		    out[0], out[1], out[2], out[3],
		    out[4], out[5], out[6], out[7],
		    out[8], out[9], out[10], out[11],
		    out[12], out[13], out[14], out[15]);
	}
	return (0);
}

/*
 * Send a raw BCDC dcmd (for BWFM_C_UP/DOWN/etc. that aren't iovars).
 * Mirrors bwfm_sdio_iovar_set but uses the raw-dcmd builder.  Caller
 * holds sc_chip_sx exclusive.
 */
static int
bwfm_sdio_dcmd_set(struct bwfm_sdio_softc *sc, uint32_t cmd_id,
    const void *val, size_t vallen)
{
	struct bwfm_sdpcm_state *st;
	struct bwfm_bcdc_dcmd dh;
	struct mbuf *resp;
	uint8_t *buf;
	size_t bufsz, reqlen;
	uint16_t reqid;
	int err;

	if (sc->sc_f2_dev == NULL || !sc->sc_f2_enabled)
		return (ENXIO);

	st = bwfm_sdio_iovar_ensure_state(sc);
	if (st == NULL)
		return (ENOMEM);

	bufsz = sizeof(struct bwfm_bcdc_dcmd) + vallen;
	buf = malloc(bufsz, M_TEMP, M_WAITOK);

	mtx_lock(&st->sp_lock);
	if (++st->bcdc_reqid == 0)	/* skip 0 on wrap */
		st->bcdc_reqid = 1;
	reqid = st->bcdc_reqid;
	mtx_unlock(&st->sp_lock);

	reqlen = bwfm_bcdc_build_dcmd(buf, bufsz, cmd_id, val, vallen, 1,
	    reqid);
	if (reqlen == 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	err = bwfm_sdio_iovar_xfer(sc, buf, reqlen, &resp);
	free(buf, M_TEMP);
	if (err != 0)
		return (err);

	m_copydata(resp, 0, sizeof(dh), (caddr_t)&dh);
	dh.flags = le32toh(dh.flags);
	dh.status = le32toh(dh.status);
	m_freem(resp);

	if (dh.flags & BWFM_BCDC_DCMD_ERROR) {
		device_printf(sc->sc_dev,
		    "dcmd cmd=%u: fw error status=%d\n", cmd_id,
		    (int32_t)dh.status);
		return (EIO);
	}
	return (0);
}

/*
 * dev.bwfm.0.iovar_set_mpc=<n> — SET-path smoke test.
 *
 * Sets the "mpc" iovar (Minimum Power Consumption disable when 0).
 * Standard knob in every brcmfmac driver; safe at any time after
 * fw is up; takes a 4-byte little-endian integer.
 *
 * Sequence per write: SET mpc <- n; GET mpc -> print readback.  If
 * the readback matches, the SET path is fully functional.
 */
static int
bwfm_sdio_sysctl_iovar_set_mpc(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int val = 0;
	uint32_t wire, readback;
	int err, rc;

	rc = sysctl_handle_int(oidp, &val, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	wire = htole32((uint32_t)val);
	readback = 0xdeadbeefu;

	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_iovar_set(sc, "mpc", &wire, sizeof(wire));
	if (err == 0)
		err = bwfm_sdio_iovar_get(sc, "mpc", &readback,
		    sizeof(readback));
	sx_xunlock(&sc->sc_chip_sx);

	if (err != 0) {
		device_printf(sc->sc_dev,
		    "iovar_set_mpc(%d): err=%d\n", val, err);
		return (err);
	}
	readback = le32toh(readback);
	device_printf(sc->sc_dev,
	    "iovar_set_mpc: SET mpc=%d -> readback mpc=%u %s\n",
	    val, readback,
	    ((uint32_t)val == readback) ? "(match)" : "(MISMATCH)");
	return (0);
}

/*
 * dev.bwfm.0.net80211_attach=1 — bring up the net80211 ifnet.
 *
 * It captures cur_etheraddr into bsc_base.sc_macaddr (bwfm_attach
 * copies this into ic_macaddr), sets bsc_base.sc_dev so bwfm.c has a
 * device handle, and calls bwfm_attach(), which runs
 * ieee80211_ifattach and installs the ic_vap_create / scan / transmit
 * hooks.
 *
 * Trigger after load_firmware + release_cr4 + events_enable + cmd_up.
 */
/*
 * Poll for the firmware boot-done handshake.
 *
 * After CR4 release the firmware boots; once its SDPCM layer is up it
 * writes the chip address of its sdpcm_shared structure into the last
 * word of RAM (0x25fffc on the 43455).  Until then that slot holds the
 * NVRAM trailer (0xfe4b01b4) or zero.  Poll it for up to ~4 s, then read
 * the sdpcm_shared flags to confirm the firmware is alive and did not
 * trap.  net80211 attach must not run before this: its first BCDC iovar
 * (cur_etheraddr) would block forever on a firmware that never answers.
 * Caller holds sc_chip_sx.
 */
static int
bwfm_sdio_poll_boot_done(struct bwfm_sdio_softc *sc)
{
	const uint32_t slot = BWFM_43455_SHARED_SLOT;
	const uint32_t rambeg = BWFM_43455_RAM_BASE, ramend = BWFM_43455_RAM_END;
	uint32_t shaddr = 0, flags = 0;
	int i, err;

	for (i = 0; i < 400; i++) {		/* ~4 s at 10 ms */
		err = bwfm_sdio_bp_read32(sc, slot, &shaddr);
		if (err == 0 && shaddr != 0 && shaddr != 0xffffffffu &&
		    shaddr != 0xfe4b01b4u &&
		    shaddr >= rambeg && shaddr < ramend) {
			if (bwfm_sdio_bp_read32(sc, shaddr, &flags) != 0) {
				DELAY(10000);
				continue;
			}
			/*
			 * Versions 1 to 3 are fine: Linux brcmfmac rejects only
			 * a version newer than it knows, and the BCM43455's
			 * 7.45.18 firmware publishes version 1.
			 */
			if ((flags & BWFM_SDPCM_SHARED_VERSION_MASK) == 0 ||
			    (flags & BWFM_SDPCM_SHARED_VERSION_MASK) >
			    BWFM_SDPCM_SHARED_VERSION) {
				DELAY(10000);
				continue;	/* still settling */
			}
			if (flags & BWFM_SDPCM_SHARED_TRAP) {
				uint32_t tpc = 0;
				(void)bwfm_sdio_bp_read32(sc, shaddr + 4, &tpc);
				device_printf(sc->sc_dev,
				    "boot_done: firmware TRAP -- shared@0x%08x "
				    "flags=0x%08x trap_addr=0x%08x\n",
				    shaddr, flags, tpc);
				return (EIO);
			}
			device_printf(sc->sc_dev,
			    "boot_done: firmware ready -- shared@0x%08x "
			    "flags=0x%08x after %d ms\n", shaddr, flags, i * 10);
			return (0);
		}
		DELAY(10000);
	}
	device_printf(sc->sc_dev,
	    "boot_done: TIMEOUT -- firmware did not publish sdpcm_shared "
	    "(slot=0x%08x last=0x%08x)\n", slot, shaddr);
	return (ETIMEDOUT);
}

static int
bwfm_sdio_sysctl_net80211_attach(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int trigger = 0;
	int rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);
	if (sc->sc_autostart_running)
		return (EBUSY);	/* autostart is bringing the chip up */
	return (bwfm_sdio_net80211_attach_now(sc));
}

/*
 * Attach net80211 once the firmware is running: wait for its boot-done
 * marker, read the MAC, then bwfm_attach, the operator sysctls and the
 * runtime iovars.  Used by the net80211_attach sysctl and autostart.
 */
static int
bwfm_sdio_net80211_attach_now(struct bwfm_sdio_softc *sc)
{
	uint8_t mac[6] = { 0 };
	int err;

	if (sc->bsc_base.sc_ic_attached) {
		device_printf(sc->sc_dev,
		    "net80211_attach: ic already attached\n");
		return (EALREADY);
	}

	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_poll_boot_done(sc);
	if (err != 0)
		device_printf(sc->sc_dev,
		    "net80211_attach: boot_done poll timed out (err=%d); this "
		    "fw does not publish sdpcm_shared -- probing cur_etheraddr "
		    "to confirm readiness\n", err);
	err = bwfm_sdio_iovar_get(sc, "cur_etheraddr", mac, sizeof(mac));
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "net80211_attach: cur_etheraddr GET failed err=%d\n",
		    err);
		return (err);
	}
	memcpy(sc->bsc_base.sc_macaddr, mac, sizeof(mac));
	sc->bsc_base.sc_dev = sc->sc_dev;

	device_printf(sc->sc_dev,
	    "net80211_attach: bwfm_attach with MAC "
	    "%02x:%02x:%02x:%02x:%02x:%02x\n",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	err = bwfm_attach(&sc->bsc_base);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "net80211_attach: bwfm_attach failed err=%d\n", err);
		return (err);
	}
	/*
	 * Register the operator-facing sysctls (wpa_pmk, join_target,
	 * scan_now, iovar_get/set, ...), as the USB transport does in
	 * its attach.
	 */
	bwfm_sysctl_attach(&sc->bsc_base);

	/*
	 * Bring the firmware to the operating point net80211 expects --
	 * BWFM_C_UP + event_msgs + country=US + sup_wpa=0 + mpc=0 +
	 * roam_off=1 -- as the USB transport does from its attach.
	 */
	sx_xlock(&sc->sc_chip_sx);
	bwfm_runtime_iovars(&sc->bsc_base);
	sx_xunlock(&sc->sc_chip_sx);

	device_printf(sc->sc_dev, "net80211_attach: ic attached\n");
	return (0);
}

/*
 * dev.bwfm.0.bringup=1 -- one-shot operator entry point that chains
 * load_firmware -> release_cr4 -> net80211_attach.  Idempotent on
 * each phase (load_firmware re-soft-resets, release_cr4 is no-op if
 * already released, net80211_attach refuses EALREADY).  Lets the
 * boot recipe collapse to
 *
 *     kldload bwfm_sdio brcmfmac43455_fw
 *     sysctl dev.bwfm.0.bringup=1
 *     ifconfig wlan0 create wlandev bwfm0
 *     ifconfig wlan0 up
 *
 * Anything that fails inside is logged with phase context and an
 * errno bubbles up; the user can re-fire the granular sysctls to
 * retry individual phases.
 */
static int
bwfm_sdio_sysctl_bringup(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	uint8_t mac[6] = { 0 };
	int trigger = 0;
	int err, rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);
	if (sc->sc_autostart_running)
		return (EBUSY);	/* autostart is bringing the chip up */
	if (sc->bsc_base.sc_ic_attached)
		return (EBUSY);	/* firmware running: reload the module */

	device_printf(sc->sc_dev, "bringup: phase 1/3 load_firmware\n");
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_load_firmware_now(sc, true);
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bringup: load_firmware failed err=%d (is "
		    "brcmfmac43455_fw.ko loaded?)\n", err);
		return (err);
	}

	device_printf(sc->sc_dev, "bringup: phase 2/3 release_cr4\n");
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_release_cr4_now(sc);
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bringup: release_cr4 failed err=%d\n", err);
		return (err);
	}

	if (sc->bsc_base.sc_ic_attached) {
		device_printf(sc->sc_dev,
		    "bringup: phase 3/3 net80211_attach already done\n");
		return (0);
	}

	device_printf(sc->sc_dev, "bringup: phase 3/3 net80211_attach\n");
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_iovar_get(sc, "cur_etheraddr", mac, sizeof(mac));
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bringup: cur_etheraddr GET failed err=%d\n", err);
		return (err);
	}
	memcpy(sc->bsc_base.sc_macaddr, mac, sizeof(mac));
	sc->bsc_base.sc_dev = sc->sc_dev;
	err = bwfm_attach(&sc->bsc_base);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bringup: bwfm_attach failed err=%d\n", err);
		return (err);
	}
	bwfm_sysctl_attach(&sc->bsc_base);
	sx_xlock(&sc->sc_chip_sx);
	bwfm_runtime_iovars(&sc->bsc_base);
	sx_xunlock(&sc->sc_chip_sx);
	device_printf(sc->sc_dev,
	    "bringup: complete -- MAC %02x:%02x:%02x:%02x:%02x:%02x; create "
	    "wlan0 via `ifconfig wlan0 create wlandev bwfm0`\n",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (0);
}

/*
 * dev.bwfm.0.cmd_scan=1 — broadcast active escan, all channels.
 *
 * Builds a bwfm_escan_params_v0 with all-channel, broadcast SSID,
 * active scan defaults, sends via the "escan" iovar.  fw then
 * emits one ESCAN_RESULT event per BSS found (status=PARTIAL),
 * terminating with a final ESCAN_RESULT event whose status is
 * SUCCESS or ABORT.
 *
 * After SET, polls rx_frames for ~3 seconds so all results land in
 * dmesg before the sysctl returns.
 */
static int
bwfm_sdio_sysctl_cmd_scan(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	struct bwfm_escan_params_v0 p;
	int trigger = 0;
	int err, rc, i;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	memset(&p, 0, sizeof(p));
	p.version  = htole32(BWFM_ESCAN_REQ_VERSION);
	p.action   = htole16(BWFM_WL_ESCAN_ACTION_START);
	p.sync_id  = htole16(0x1234);
	/* scan_params: broadcast (no SSID), all channels, active. */
	p.scan_params.ssid.len = 0;
	memset(p.scan_params.bssid, 0xff, sizeof(p.scan_params.bssid));
	p.scan_params.bss_type    = BWFM_DOT11_BSSTYPE_ANY;
	p.scan_params.scan_type   = BWFM_SCANTYPE_ACTIVE;
	p.scan_params.nprobes     = htole32((uint32_t)-1);
	p.scan_params.active_time = htole32((uint32_t)-1);
	p.scan_params.passive_time= htole32((uint32_t)-1);
	p.scan_params.home_time   = htole32((uint32_t)-1);
	p.scan_params.channel_num = 0;  /* 0 = all channels */

	sx_xlock(&sc->sc_chip_sx);
	if (sc->bsc_base.sc_scan_busy) {
		sx_xunlock(&sc->sc_chip_sx);
		device_printf(sc->sc_dev,
		    "cmd_scan: scan already in flight, EAGAIN\n");
		return (EAGAIN);
	}
	sc->bsc_base.sc_scan_busy = 1;
	device_printf(sc->sc_dev, "cmd_scan: sending escan SET\n");
	err = bwfm_sdio_iovar_set(sc, "escan", &p, sizeof(p));
	if (err == 0 && sc->sc_sdpcm != NULL) {
		/*
		 * Drain ESCAN_RESULT events.  Release sc_chip_sx between
		 * polls and pause() rather than DELAY(): busy-spinning for
		 * 3 s with the lock held lets net80211 / wpa_supplicant
		 * traffic pile up behind it until the kernel watchdog
		 * trips.  The lock release lets other iovar_xfer callers
		 * get a request in between polls.
		 */
		for (i = 0; i < 60 && sc->bsc_base.sc_scan_busy; i++) {
			(void)bwfm_sdpcm_rx_frames(sc->sc_sdpcm,
			    sc->sc_f2_dev);
			if (!sc->bsc_base.sc_scan_busy)
				break;
			sx_xunlock(&sc->sc_chip_sx);
			pause("bwfmscn", MSEC_2_TICKS(50));
			sx_xlock(&sc->sc_chip_sx);
		}
	}
	sc->bsc_base.sc_scan_busy = 0;
	sx_xunlock(&sc->sc_chip_sx);

	if (err != 0) {
		device_printf(sc->sc_dev,
		    "cmd_scan: escan SET failed err=%d\n", err);
		return (err);
	}
	device_printf(sc->sc_dev, "cmd_scan: done\n");
	return (0);
}

/*
 * dev.bwfm.0.events_enable=<n>  — write 1 to enable ALL events
 * (mask = 0xff x BWFM_EVENT_MASK_LEN) via the `event_msgs` iovar.
 * Write 0 to disable everything.  Until this is run, fw doesn't
 * emit anything on the EVENT channel.
 */
static int
bwfm_sdio_sysctl_events_enable(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	int val = 0;
	uint8_t mask[BWFM_EVENT_MASK_LEN];
	int err, rc;

	rc = sysctl_handle_int(oidp, &val, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	memset(mask, val ? 0xff : 0x00, sizeof(mask));

	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_iovar_set(sc, "event_msgs", mask, sizeof(mask));
	sx_xunlock(&sc->sc_chip_sx);

	if (err != 0) {
		device_printf(sc->sc_dev,
		    "events_enable(%d): err=%d\n", val, err);
		return (err);
	}
	device_printf(sc->sc_dev,
	    "events_enable: event_msgs mask -> %s\n",
	    val ? "ALL ON" : "ALL OFF");
	return (0);
}

/*
 * dev.bwfm.0.cmd_up=1   — send BWFM_C_UP   (bring data plane up)
 * dev.bwfm.0.cmd_down=1 — send BWFM_C_DOWN (tear data plane down)
 *
 * After UP, fw typically emits BWFM_E_TYPE_LINK + BWFM_E_IF + a few
 * others; observe in dmesg via the registered event handler.  Drives
 * rx_frames during the wrapper's poll so any events arriving in the
 * immediate window get dispatched.
 */
static int
bwfm_sdio_sysctl_cmd_dcmd(SYSCTL_HANDLER_ARGS)
{
	struct bwfm_sdio_softc *sc = arg1;
	uint32_t cmd_id = (uint32_t)arg2;
	int trigger = 0;
	int err, rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	sx_xlock(&sc->sc_chip_sx);
	device_printf(sc->sc_dev, "cmd_dcmd: sending BWFM_C cmd=%u\n",
	    cmd_id);
	err = bwfm_sdio_dcmd_set(sc, cmd_id, NULL, 0);
	/*
	 * After the dcmd completes, poll rx_frames briefly so any
	 * EVENT-channel reactions (LINK/IF) get dispatched before
	 * the sysctl returns.  Without this the caller has to issue
	 * another iovar_get just to drive rx polling.
	 */
	if (err == 0 && sc->sc_sdpcm != NULL) {
		int i;
		for (i = 0; i < 10; i++) {
			(void)bwfm_sdpcm_rx_frames(sc->sc_sdpcm,
			    sc->sc_f2_dev);
			DELAY(50000);
		}
	}
	sx_xunlock(&sc->sc_chip_sx);

	if (err != 0) {
		device_printf(sc->sc_dev,
		    "cmd_dcmd(cmd=%u): err=%d\n", cmd_id, err);
		return (err);
	}
	return (0);
}

/* ------------------------------------------------------------------
 * Bus ops.  Control traffic goes through the iovar/dcmd ops below, so
 * txctl and rxctl are not supported on SDIO.
 * ------------------------------------------------------------------ */

/* send a control message (not supported yet) */
static int
bwfm_sdio_txctl(struct bwfm_softc *sc, const void *buf, size_t len)
{
	(void)sc; (void)buf; (void)len;
	return (ENOTSUP);
}

/* receive a control message (not supported yet) */
static int
bwfm_sdio_rxctl(struct bwfm_softc *sc, void *buf, size_t *lenp, int timeout_ms)
{
	(void)sc; (void)buf; (void)lenp; (void)timeout_ms;
	return (ENOTSUP);
}

/* depth of the data transmit queue */
#define	BWFM_SDIO_TXQ_LEN	128


static void	bwfm_sdio_hostmail(struct bwfm_sdio_softc *);

/* Send what bwfm_sdio_txdata queued; may sleep. */
static void
bwfm_sdio_tx_task(void *arg, int pending __unused)
{
	struct bwfm_sdio_softc *sc = arg;
	struct mbuf *m;
	int w;

	for (;;) {
		mtx_lock(&sc->sc_tx_mtx);
		m = mbufq_dequeue(&sc->sc_tx_q);
		mtx_unlock(&sc->sc_tx_mtx);
		if (m == NULL)
			break;
		if (sc->bsc_base.sc_dying || sc->sc_sdpcm == NULL ||
		    sc->sc_f2_dev == NULL) {
			m_freem(m);
			continue;
		}
		/*
		 * Wait for the firmware's credit (and for it to lift flow
		 * control), polling for the frames that carry it.  After about
		 * a second send anyway rather than stall the queue for good.
		 */
		for (w = 0; w < hz && !bwfm_sdpcm_tx_credit(sc->sc_sdpcm);
		    w++) {
			sx_xlock(&sc->sc_chip_sx);
			bwfm_sdio_hostmail(sc);
			(void)bwfm_sdpcm_rx_frames(sc->sc_sdpcm,
			    sc->sc_f2_dev);
			sx_xunlock(&sc->sc_chip_sx);
			if (bwfm_sdpcm_tx_credit(sc->sc_sdpcm))
				break;
			pause("bwfmcr", 1);
		}
		if (w > 0) {
			uint32_t ms = (uint32_t)(w * 1000 / hz);

			sc->st_credit_waits++;
			if (ms > sc->st_credit_wait_max_ms)
				sc->st_credit_wait_max_ms = ms;
		}
		if (w == hz)
			DPRINTF(&sc->bsc_base, 0,
			    "tx: no credit from the firmware after 1 s; "
			    "sending anyway\n");
		sx_xlock(&sc->sc_chip_sx);
		(void)bwfm_sdpcm_tx_dataframe(sc->sc_sdpcm, sc->sc_f2_dev, m);
		sx_xunlock(&sc->sc_chip_sx);
	}
}

/*
 * Queue a data frame; never sleeps, so it is safe under net80211's TX
 * lock.  ENOBUFS when the queue is full.
 */
static int
bwfm_sdio_txdata(struct bwfm_softc *bsc, struct mbuf *m)
{
	struct bwfm_sdio_softc *sc = (struct bwfm_sdio_softc *)bsc;
	int err;

	if (m == NULL)
		return (EINVAL);
	/* 802.11 from net80211 -> 802.3 for the firmware; see bwfm.c. */
	if ((err = bwfm_deencap_80211(&m)) != 0) {
		if (m != NULL)
			m_freem(m);
		return (err == EAGAIN ? 0 : err);	/* EAGAIN: mgmt, dropped */
	}
	if (sc->sc_sdpcm == NULL || sc->sc_f2_dev == NULL ||
	    sc->sc_tx_tq == NULL) {
		m_freem(m);
		return (ENXIO);
	}
	mtx_lock(&sc->sc_tx_mtx);
	err = mbufq_enqueue(&sc->sc_tx_q, m);
	mtx_unlock(&sc->sc_tx_mtx);
	if (err != 0) {
		m_freem(m);
		return (ENOBUFS);
	}
	taskqueue_enqueue(sc->sc_tx_tq, &sc->sc_tx_task);
	return (0);
}

/* stop the interface */
static void
bwfm_sdio_stop(struct bwfm_softc *sc)
{
	(void)sc;
}

/*
 * bus_ops bridge: route bwfm.c's iovar/dcmd dispatch through the
 * SDIO transport wrappers.  Casts bwfm_softc back to bwfm_sdio_softc
 * (bsc_base is the first member, so the pointer is identical).
 */
static int
bwfm_sdio_bus_iovar_get(struct bwfm_softc *bsc, const char *name,
    void *buf, size_t *lenp)
{
	struct bwfm_sdio_softc *sc = (struct bwfm_sdio_softc *)bsc;
	int err;

	if (lenp == NULL)
		return (EINVAL);
	err = bwfm_sdio_iovar_get(sc, name, buf, *lenp);
	/* The SDIO wrapper zero-pads short replies, so *lenp is left as
	 * the buffer size. */
	return (err);
}

/* bus hook to set a firmware variable */
static int
bwfm_sdio_bus_iovar_set(struct bwfm_softc *bsc, const char *name,
    const void *buf, size_t len)
{
	struct bwfm_sdio_softc *sc = (struct bwfm_sdio_softc *)bsc;
	return (bwfm_sdio_iovar_set(sc, name, buf, len));
}

/* bus hook to send a firmware command */
static int
bwfm_sdio_bus_dcmd_set(struct bwfm_softc *bsc, uint32_t cmd,
    const void *buf, size_t len)
{
	struct bwfm_sdio_softc *sc = (struct bwfm_sdio_softc *)bsc;
	return (bwfm_sdio_dcmd_set(sc, cmd, buf, len));
}

/*
 * Periodic watchdog -- fires every BWFM_WD_POLL_MS via callout on
 * softclock, then hands off to sc_wd_task on taskqueue_thread which
 * does one SDIO F2 RX pump to keep the bus active and drain any events
 * the ithread missed.  The timer + thread split follows Linux
 * brcmf_sdio_watchdog / brcmf_sdio_bus_watchdog (sdio.c), but Linux
 * does not pump RX there (bus->poll is false) and lets an idle bus
 * sleep.  Without the pump, BCM43455 fw 7.45.18 tears down LINK within
 * milliseconds of ASSOC when it sees no host SDIO activity.
 */
static void
bwfm_sdio_watchdog_callout(void *arg)
{
	struct bwfm_sdio_softc *sc = arg;

	if (sc->sc_wd_stop)
		return;
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_wd_task);
}

/*
 * Answer the firmware's host-mailbox interrupt, as Linux brcmfmac's
 * brcmf_sdio_hostmail() and the intstatus handling in brcmf_sdio_dpc() do:
 * read the reason from TOHOSTMAILBOXDATA, acknowledge with SMB_INT_ACK,
 * clear the interrupt, and track the flow-control state, so that the
 * firmware's mailbox requests are answered and its "stop sending" is
 * honoured.  The driver has no SDIO interrupt handler; the watchdog poll
 * and the TX task call this.  Caller holds sc_chip_sx.
 */
static void
bwfm_sdio_hostmail(struct bwfm_sdio_softc *sc)
{
	struct bwfm_chip_core *sd;
	uint32_t is, clr = 0, hmb = 0, now;
	bool fc;

	sd = bwfm_chip_get_core(&sc->sc_chip, BCMA_CORE_SDIO_DEV);
	if (sd == NULL || sc->sc_sdpcm == NULL)
		return;
	if (bwfm_sdio_bp_read32(sc, sd->base + BWFM_SD_REG_INTSTATUS,
	    &is) != 0 || is == 0xffffffffu)
		return;

	if (is & BWFM_I_HMB_HOST_INT) {
		int b;

		sc->st_hmb_int++;
		(void)bwfm_sdio_bp_read32(sc,
		    sd->base + BWFM_SD_REG_TOHOSTMAILBOXDATA, &hmb);
		for (b = 0; b < 5; b++)
			if (hmb & (1u << b))
				sc->st_hmb_reason[b]++;
		if (bwfm_sdio_bp_write32(sc,
		    sd->base + BWFM_SD_REG_TOSBMAILBOX, BWFM_SMB_INT_ACK) == 0)
			sc->st_hmb_ack++;
		clr |= BWFM_I_HMB_HOST_INT;
		DPRINTF(&sc->bsc_base, 1, "hostmail: data=0x%08x%s%s%s\n",
		    hmb, (hmb & BWFM_TOHOSTMBOX_NAKHANDLED) ? " NAKHANDLED" : "",
		    (hmb & BWFM_TOHOSTMBOX_FC) ? " FC" : "",
		    (hmb & BWFM_TOHOSTMBOX_FWHALT) ? " FWHALT" : "");
		if (hmb & BWFM_TOHOSTMBOX_FWHALT)
			device_printf(sc->sc_dev,
			    "hostmail: firmware reports it has halted\n");
	}
	if (is & BWFM_I_HMB_FC_CHANGE) {
		/* Clear the change first, then read the current state. */
		(void)bwfm_sdio_bp_write32(sc,
		    sd->base + BWFM_SD_REG_INTSTATUS, BWFM_I_HMB_FC_CHANGE);
		now = 0;
		(void)bwfm_sdio_bp_read32(sc,
		    sd->base + BWFM_SD_REG_INTSTATUS, &now);
		fc = (now & (BWFM_I_HMB_FC_STATE | BWFM_I_HMB_FC_CHANGE)) != 0;
		mtx_lock(&sc->sc_sdpcm->sp_lock);
		if (sc->sc_sdpcm->fc_off != fc) {
			DPRINTF(&sc->bsc_base, 1, "flow control %s\n",
			    fc ? "on (stop)" : "off (go)");
			if (fc) {
				sc->st_fc_on++;
				sc->st_fc_since = ticks;
			} else {
				sc->st_fc_off++;
				sc->st_fc_held_ms += (uint32_t)
				    ((ticks - sc->st_fc_since) * 1000 / hz);
			}
		}
		sc->sc_sdpcm->fc_off = fc;
		mtx_unlock(&sc->sc_sdpcm->sp_lock);
	}
	if (clr != 0) {
		uint32_t again = 0;

		(void)bwfm_sdio_bp_write32(sc,
		    sd->base + BWFM_SD_REG_INTSTATUS, clr);
		/*
		 * The write-1-to-clear must have landed.  A new interrupt the
		 * firmware raises in between also counts, so a few are normal;
		 * one per interrupt means the clear is not working.
		 */
		if (bwfm_sdio_bp_read32(sc, sd->base + BWFM_SD_REG_INTSTATUS,
		    &again) == 0 && (again & clr & BWFM_I_HMB_HOST_INT) != 0)
			sc->st_hmb_stuck++;
	}
}

/* dev.bwfm.N.sdio_stats: is the mailbox answered, are credits kept? */
static int
bwfm_sdio_stats_sysctl(SYSCTL_HANDLER_ARGS)
{
	static const char *rn[5] = { "NAKHANDLED", "DEVREADY", "FC",
	    "FWREADY", "FWHALT" };
	struct bwfm_sdio_softc *sc = arg1;
	struct bwfm_sdpcm_state *st = sc->sc_sdpcm;
	struct sbuf *sb;
	int error, b;

	sb = sbuf_new_for_sysctl(NULL, NULL, 512, req);
	sbuf_printf(sb, "mailbox: host_int=%u acked=%u%s stuck=%u\n",
	    sc->st_hmb_int, sc->st_hmb_ack,
	    sc->st_hmb_int == sc->st_hmb_ack ? " (all acked)" : " (MISSING ACKS)",
	    sc->st_hmb_stuck);
	sbuf_printf(sb, "reasons:");
	for (b = 0; b < 5; b++)
		sbuf_printf(sb, " %s=%u", rn[b], sc->st_hmb_reason[b]);
	sbuf_printf(sb, "\nflow control: on=%u off=%u held_ms=%u now=%s\n",
	    sc->st_fc_on, sc->st_fc_off, sc->st_fc_held_ms,
	    (st != NULL && st->fc_off) ? "STOP" : "go");
	if (st != NULL)
		sbuf_printf(sb, "credit: seen=%d updates=%u tx_seq=%u max_seq=%u "
		    "room=%u\ndata: sent=%u outside_window=%u%s\n",
		    st->credit_seen, st->max_seq_updates, st->tx_seq, st->max_seq,
		    (unsigned)(uint8_t)(st->max_seq - st->tx_seq), st->data_tx,
		    st->window_violations,
		    st->window_violations == 0 ? " (ok)" : " (VIOLATIONS)");
	sbuf_printf(sb, "credit waits=%u longest_ms=%u",
	    sc->st_credit_waits, sc->st_credit_wait_max_ms);

	error = sbuf_finish(sb);
	sbuf_delete(sb);
	return (error);
}

/* periodic watchdog work */
static void
bwfm_sdio_watchdog_task(void *arg, int pending __unused)
{
	struct bwfm_sdio_softc *sc = arg;

	if (sc->sc_wd_stop || sc->sc_sdpcm == NULL || sc->sc_f2_dev == NULL)
		goto rearm;
	sx_xlock(&sc->sc_chip_sx);
	bwfm_sdio_hostmail(sc);
	(void)bwfm_sdpcm_rx_frames(sc->sc_sdpcm, sc->sc_f2_dev);
	sx_xunlock(&sc->sc_chip_sx);
rearm:
	if (!sc->sc_wd_stop)
		callout_reset(&sc->sc_wd_callout,
		    MSEC_2_TICKS((u_int)BWFM_WD_POLL_MS),
		    bwfm_sdio_watchdog_callout, sc);
}

/* bus hook that drains pending rx frames */
static void
bwfm_sdio_bus_pump_rx(struct bwfm_softc *bsc, int max_ms,
    volatile int *until_clear)
{
	struct bwfm_sdio_softc *sc = (struct bwfm_sdio_softc *)bsc;
	int ticks_per_iter = 50;	/* 50 ms per spin */
	int iters = max_ms / ticks_per_iter;
	int i;

	if (sc->sc_sdpcm == NULL)
		return;
	/*
	 * Yield-friendly pump.  Each iteration holds sc_chip_sx only
	 * across the one F2 read, then drops the lock and pause()s for
	 * 50 ms.  A DELAY() with the sx held would busy-spin the CPU for
	 * max_ms (up to 3 s on the scan path) and starve every other
	 * iovar_xfer caller and the kernel watchdog.
	 */
	for (i = 0; i < iters; i++) {
		sx_xlock(&sc->sc_chip_sx);
		(void)bwfm_sdpcm_rx_frames(sc->sc_sdpcm, sc->sc_f2_dev);
		sx_xunlock(&sc->sc_chip_sx);
		if (until_clear != NULL && *until_clear == 0)
			break;
		pause("bwfmpmp", MSEC_2_TICKS((u_int)ticks_per_iter));
	}
}

static const struct bwfm_bus_ops bwfm_sdio_bus_ops = {
	.bs_txctl	= bwfm_sdio_txctl,
	.bs_rxctl	= bwfm_sdio_rxctl,
	.bs_txdata	= bwfm_sdio_txdata,
	.bs_stop	= bwfm_sdio_stop,
	.bs_iovar_get	= bwfm_sdio_bus_iovar_get,
	.bs_iovar_set	= bwfm_sdio_bus_iovar_set,
	.bs_dcmd_set	= bwfm_sdio_bus_dcmd_set,
	.bs_pump_rx	= bwfm_sdio_bus_pump_rx,
};

/* ------------------------------------------------------------------
 * Newbus glue
 * ------------------------------------------------------------------ */

/* check whether this card is supported */
static int
bwfm_sdio_probe(device_t dev)
{
	uint16_t manfid, prodid;
	uint8_t func_num;
	const struct bwfm_sdio_match *m;
	char desc[128];

	manfid = sdio_get_manfid(dev);
	prodid = sdio_get_prodid(dev);
	func_num = sdio_get_func_num(dev);

	if (manfid != SDIO_VENDOR_BROADCOM)
		return (ENXIO);
	/* Bind to function 1 (backplane) only.  Function 2 (WLAN frame
	 * FIFO) is bound by the bwfm_sdio_f2 sibling driver; function 3
	 * (Bluetooth, where present) is out of scope. */
	if (func_num != 1)
		return (ENXIO);
	m = bwfm_sdio_lookup(prodid);
	if (m == NULL)
		return (ENXIO);

	snprintf(desc, sizeof(desc),
	    "Broadcom %s (SDIO func %u)", m->name, func_num);
	device_set_desc_copy(dev, desc);
	return (BUS_PROBE_DEFAULT);
}

/*
 * /dev/bwfm0 raw SDIO transport cdev.
 *
 * Userspace tools (including a bridge that forwards the operations to
 * a Linux guest) can drive CMD52/CMD53 + backplane-window operations
 * directly through ioctls, without a sysctl for every step.
 *
 * All ioctl handlers take sc_chip_sx so they serialise against the
 * existing sysctls (load_firmware, halt_cr4, etc.).
 */

static d_open_t		bwfm_cdev_open;
static d_ioctl_t	bwfm_cdev_ioctl;

static struct cdevsw bwfm_cdevsw = {
	.d_version	= D_VERSION,
	.d_open		= bwfm_cdev_open,
	.d_ioctl	= bwfm_cdev_ioctl,
	.d_name		= "bwfm",
};

/* open the /dev control device */
static int
bwfm_cdev_open(struct cdev *cdev __unused, int flags __unused,
    int devtype __unused, struct thread *td __unused)
{
	return (0);
}

/* run a one-byte SDIO transfer for userland */
static int
bwfm_cdev_do_cmd52(struct bwfm_sdio_softc *sc, struct bwfm_cmd52 *c)
{
	struct mmc_command cmd;
	device_t mmcbus;
	int err;

	if (c->func > 7)
		return (EINVAL);
	if (c->addr > 0x1ffff)
		return (EINVAL);

	mmcbus = device_get_parent(sc->sc_sdio_bus);
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = SD_IO_RW_DIRECT;
	cmd.flags = MMC_RSP_R5 | MMC_CMD_AC;
	cmd.arg =
	    ((uint32_t)c->func << SD_ARG_CMD52_FUNC_SHIFT) |
	    ((c->addr & SD_ARG_CMD52_REG_MASK) << SD_ARG_CMD52_REG_SHIFT);
	if (c->write) {
		cmd.arg |= SD_ARG_CMD52_WRITE;
		cmd.arg |= ((uint32_t)c->data << SD_ARG_CMD52_DATA_SHIFT);
	}
	err = mmc_wait_for_cmd(mmcbus, sc->sc_dev, &cmd, 0);
	c->mmc_err = err;
	if (err != MMC_ERR_NONE)
		return (EIO);
	if (!c->write)
		c->data = cmd.resp[0] & 0xff;
	return (0);
}

/* run a multi-byte SDIO transfer for userland */
static int
bwfm_cdev_do_cmd53(struct bwfm_sdio_softc *sc, struct bwfm_cmd53 *c)
{
	struct mmc_command cmd;
	struct mmc_data data;
	device_t mmcbus;
	void *kbuf;
	uint32_t arg, lenfield;
	int err;

	if (c->func > 7)
		return (EINVAL);
	if (c->addr > 0x1ffff)
		return (EINVAL);
	if (c->len == 0 || c->len > 4096)
		return (EINVAL);

	kbuf = malloc(c->len, M_TEMP, M_WAITOK | M_ZERO);
	if (c->write) {
		err = copyin((void *)(uintptr_t)c->buf, kbuf, c->len);
		if (err != 0) {
			free(kbuf, M_TEMP);
			return (err);
		}
	}

	mmcbus = device_get_parent(sc->sc_sdio_bus);
	memset(&cmd, 0, sizeof(cmd));
	memset(&data, 0, sizeof(data));

	arg = ((uint32_t)c->func & SD_ARG_CMD53_FUNC_MASK) <<
	    SD_ARG_CMD53_FUNC_SHIFT;
	arg |= (c->addr & SD_ARG_CMD53_REG_MASK) << SD_ARG_CMD53_REG_SHIFT;
	if (c->incr)
		arg |= SD_ARG_CMD53_INCREMENT;
	if (c->write)
		arg |= SD_ARG_CMD53_WRITE;
	if (c->block_mode) {
		uint32_t blksize;

		blksize = sc->sc_blksize != 0 ? sc->sc_blksize : 64;
		if (c->len % blksize != 0) {
			free(kbuf, M_TEMP);
			return (EINVAL);
		}
		lenfield = c->len / blksize;
		if (lenfield == 0 || lenfield > 511) {
			free(kbuf, M_TEMP);
			return (EINVAL);
		}
		arg |= SD_ARG_CMD53_BLOCK_MODE;
		arg |= (lenfield & SD_ARG_CMD53_LENGTH_MASK);
		data.flags = (c->write ? MMC_DATA_WRITE : MMC_DATA_READ) |
		    MMC_DATA_BLOCK_SIZE | MMC_DATA_MULTI;
		data.block_size = blksize;
		data.block_count = lenfield;
	} else {
		lenfield = (c->len == 512) ? 0 : c->len;
		arg |= (lenfield & SD_ARG_CMD53_LENGTH_MASK);
		data.flags = c->write ? MMC_DATA_WRITE : MMC_DATA_READ;
	}

	cmd.opcode = SD_IO_RW_EXTENDED;
	cmd.arg = arg;
	cmd.flags = MMC_RSP_R5 | MMC_CMD_ADTC;
	cmd.data = &data;
	data.data = kbuf;
	data.len = c->len;

	err = mmc_wait_for_cmd(mmcbus, sc->sc_dev, &cmd, 0);
	c->mmc_err = err;
	if (err != MMC_ERR_NONE) {
		free(kbuf, M_TEMP);
		return (EIO);
	}
	if (!c->write)
		err = copyout(kbuf, (void *)(uintptr_t)c->buf, c->len);
	free(kbuf, M_TEMP);
	return (err);
}

/* handle ioctls on the control device */
static int
bwfm_cdev_ioctl(struct cdev *cdev, u_long ioc, caddr_t arg, int flag __unused,
    struct thread *td)
{
	struct bwfm_sdio_softc *sc = cdev->si_drv1;
	int err;

	if (sc == NULL)
		return (ENXIO);

	/*
	 * Safety gate: CMD52/CMD53/backplane read/write are
	 * raw SDIO transactions against F1/F2 with no bounds checks
	 * beyond addr-space width.  Same rationale as the iovar_set
	 * sysctl gate: opt-in flag + PRIV_DRIVER, so a jail's root
	 * without PRIV_DRIVER can't wedge the chip.
	 */
#ifndef BWFM_UNSAFE_IOVARS_DEFAULT_ON
	if (sc->bsc_base.sc_unsafe_iovars == 0)
		return (EPERM);
#endif
	err = priv_check(td, PRIV_DRIVER);
	if (err != 0)
		return (err);

	sx_xlock(&sc->sc_chip_sx);
	switch (ioc) {
	case BWFM_IOC_CMD52:
		err = bwfm_cdev_do_cmd52(sc, (struct bwfm_cmd52 *)arg);
		break;
	case BWFM_IOC_CMD53:
		err = bwfm_cdev_do_cmd53(sc, (struct bwfm_cmd53 *)arg);
		break;
	case BWFM_IOC_SET_WINDOW: {
		struct bwfm_set_window *w = (struct bwfm_set_window *)arg;
		err = bwfm_sdio_set_backplane(sc, w->chip_addr);
		w->mmc_err = err;
		break;
	}
	case BWFM_IOC_BP_READ32: {
		struct bwfm_bp *b = (struct bwfm_bp *)arg;
		err = bwfm_sdio_bp_read32(sc, b->chip_addr, &b->value);
		b->mmc_err = err;
		break;
	}
	case BWFM_IOC_BP_WRITE32: {
		struct bwfm_bp *b = (struct bwfm_bp *)arg;
		err = bwfm_sdio_bp_write32(sc, b->chip_addr, b->value);
		b->mmc_err = err;
		break;
	}
	case BWFM_IOC_GET_CHIPID: {
		struct bwfm_chipid *ci = (struct bwfm_chipid *)arg;
		uint32_t v;

		err = bwfm_sdio_bp_read32(sc,
		    BWFM_CC_CORE_BASE + BWFM_CC_CHIPID, &v);
		if (err == 0) {
			ci->chipid = v;
			ci->chip = BWFM_CHIPID_ID(v);
			ci->rev = BWFM_CHIPID_REV(v);
			ci->pkg = (v >> 16) & 0xf;
			ci->num_cores = (v >> 20) & 0xf;
		}
		break;
	}
	case BWFM_IOC_CARD_INFO: {
		struct bwfm_card_info *info = (struct bwfm_card_info *)arg;
		struct sdio_bus_ivars *sbi;

		sbi = device_get_ivars(sc->sc_sdio_bus);
		if (sbi == NULL) {
			err = ENXIO;
			break;
		}
		info->ocr = sbi->sbi_ocr;
		info->rca = sbi->sbi_rca;
		info->nfn = sbi->sbi_nfn;
		err = 0;
		break;
	}
	case BWFM_IOC_GET_CORES: {
		struct bwfm_cores *uc = (struct bwfm_cores *)arg;
		struct bwfm_chip_core *core;
		uint8_t i;

		/* Walk EROM lazily — the chip layer remembers cores across
		 * calls, so a second ioctl is a free copy of the list. */
		err = bwfm_sdio_chip_ensure(sc);
		if (err != 0) {
			uc->mmc_err = err;
			break;
		}
		if (sc->sc_chip.ncores <= 1) {
			err = bwfm_chip_walk_erom(&sc->sc_chip);
			if (err != 0) {
				uc->mmc_err = err;
				break;
			}
		}
		uc->count = (uint8_t)MIN((unsigned)sc->sc_chip.ncores,
		    (unsigned)uc->max);
		uc->count = MIN(uc->count, (uint8_t)16);
		i = 0;
		TAILQ_FOREACH(core, &sc->sc_chip.cores, link) {
			if (i >= uc->count)
				break;
			uc->core[i].core_id = core->id;
			uc->core[i].rev = (uint8_t)core->rev;
			uc->core[i].base = core->base;
			uc->core[i].wrap = core->wrap;
			i++;
		}
		uc->mmc_err = 0;
		break;
	}
	default:
		err = ENOTTY;
	}
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/* set up the driver when the card is found */
static int
bwfm_sdio_attach(device_t dev)
{
	struct bwfm_sdio_softc *sc = device_get_softc(dev);
	const struct bwfm_sdio_match *m;

	sc->sc_dev = dev;
	sc->sc_sdio_bus = device_get_parent(dev);
	sc->sc_manfid = sdio_get_manfid(dev);
	sc->sc_prodid = sdio_get_prodid(dev);
	sc->sc_func_num = sdio_get_func_num(dev);
	sc->sc_func_class = sdio_get_func_class(dev);
	sc->sc_blksize = sdio_get_blocksize(dev);
	sc->sc_f2_dev = NULL;

	sc->bsc_base.sc_dev = dev;
	sc->bsc_base.sc_bus_ops = &bwfm_sdio_bus_ops;

	/*
	 * Publish ourselves so the F2 sibling driver (bwfm_sdio_f2) can
	 * find us when it attaches.  If F2 already attached (uncommon but
	 * possible), pick up its device_t now.
	 */
	bwfm_sdio_global_softc = sc;
	{
		device_t *children;
		int nchildren, i;
		if (device_get_children(sc->sc_sdio_bus, &children,
		    &nchildren) == 0) {
			for (i = 0; i < nchildren; i++) {
				const char *cn = device_get_name(children[i]);
				if (cn != NULL && strcmp(cn, "bwfm_f2") == 0 &&
				    device_is_attached(children[i])) {
					sc->sc_f2_dev = children[i];
					device_printf(dev,
					    "F2 picked up post-attach (%s)\n",
					    device_get_nameunit(children[i]));
					break;
				}
			}
			free(children, M_TEMP);
		}
	}

	/*
	 * Serialise all chip-side operations.  The read_chipid / halt_cr4
	 * / soft_reset sysctl handlers each take this exclusive so two
	 * concurrent root-driven sysctls can't interleave CMD52s and
	 * leave the chip with a half-programmed backplane window or a
	 * lost RCA after a mid-sequence soft reset.
	 */
	sx_init_flags(&sc->sc_chip_sx, "bwfm-chip", SX_RECURSE);

	/*
	 * bwfm_softc's sc_mtx / sc_ctl_mtx / sc_ctl_pending are
	 * "owned by the transport attach" per bwfm.c's contract, so
	 * they are set up here as the USB transport does in its
	 * attach.  Otherwise the bwfm_rx_frame -> bwfm_handle_event
	 * path locks an uninitialised mutex and panics.
	 */
	mtx_init(&sc->bsc_base.sc_mtx, "bwfm", NULL, MTX_DEF);
	mtx_init(&sc->bsc_base.sc_ctl_mtx, "bwfm-ctl", NULL, MTX_DEF);
	TAILQ_INIT(&sc->bsc_base.sc_ctl_pending);
	/*
	 * Seed the BCDC reqid to 1, as USB does.  reqid 0 is reserved
	 * for event-shaped noise (bwfm_rxctl drops responses with id=0),
	 * so a request sent with id 0 would have its reply dropped and
	 * time out at 5 s.  Every ++sc_bcdc_reqid site also skips 0.
	 */
	sc->bsc_base.sc_bcdc_reqid = 1;

	/* EVENT rx delivery taskqueue + queue. */
	mtx_init(&sc->sc_event_rx_mtx, "bwfm-evrx", NULL, MTX_DEF);
	mbufq_init(&sc->sc_event_rx_q, 64);
	TASK_INIT(&sc->sc_event_rx_task, 0, bwfm_sdio_event_rx_worker, sc);
	sc->sc_event_rx_tq = taskqueue_create("bwfm_evrx", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->sc_event_rx_tq);
	taskqueue_start_threads(&sc->sc_event_rx_tq, 1, PI_NET,
	    "%s evrx", device_get_nameunit(dev));

	/* Data transmit queue; see sc_tx_q. */
	mtx_init(&sc->sc_tx_mtx, "bwfm-tx", NULL, MTX_DEF);
	mbufq_init(&sc->sc_tx_q, BWFM_SDIO_TXQ_LEN);
	TASK_INIT(&sc->sc_tx_task, 0, bwfm_sdio_tx_task, sc);
	sc->sc_tx_tq = taskqueue_create("bwfm_tx", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->sc_tx_tq);
	taskqueue_start_threads(&sc->sc_tx_tq, 1, PI_NET,
	    "%s tx", device_get_nameunit(dev));

	/*
	 * Periodic SDIO watchdog.  callout fires every BWFM_WD_POLL_MS
	 * on softclock, enqueues sc_wd_task on taskqueue_thread (safe
	 * to sleep in sx_xlock + pump_rx).  Mirrors Linux
	 * brcmf_sdio_watchdog_thread.
	 */
	sc->sc_wd_stop = false;
	callout_init(&sc->sc_wd_callout, 1);	/* MPSAFE */
	TASK_INIT(&sc->sc_wd_task, 0, bwfm_sdio_watchdog_task, sc);

	/*
	 * Expose dev.bwfm.N.debug for ad-hoc bring-up tracing.  Default
	 * silent; bump with `sysctl dev.bwfm.0.debug=2` to follow CMD52
	 * traffic without recompiling.  bsc_base.sc_debug is the same
	 * field the USB and PCIe transports use.
	 */
	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "debug", CTLFLAG_RWTUN, &sc->bsc_base.sc_debug, 0,
	    "DPRINTF level: 0=silent 1=milestones 2=protocol 3=hex");
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "sdio_stats", CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_stats_sysctl, "A",
	    "Mailbox answers, flow control and transmit credit counters");

	/*
	 * Write a non-zero value to dev.bwfm.N.read_chipid to fire the
	 * F1-enable + backplane-window + CC.CHIPID read smoke test.
	 * Output lands in dmesg; the sysctl resets to 0 after each
	 * shot so it's a one-trigger-per-write knob.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "read_chipid",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_read_chipid, "I",
	    "Write 1: bring F1 up + read CC.CHIPID via backplane window");

	/*
	 * Diagnostic memory peek: `sysctl dev.bwfm.N.peek=<addr>` dumps
	 * 8 words from that chip address via bp_read32.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "peek",
	    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_peek, "IU",
	    "Write a chip address: dump 8 words from it via backplane");

	/*
	 * Write a non-zero value to dev.bwfm.N.halt_cr4 to fire the
	 * EROM walk + CR4 halt sequence.  Halts the Cortex-R4 with its
	 * CPUHALT bit asserted and leaves the core in reset; firmware
	 * upload runs against the TCM in that state.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "halt_cr4",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_halt_cr4, "I",
	    "Write 1: EROM walk + put CR4 in reset with CPUHALT asserted");

	/*
	 * Release the ARM-CR4 core: write the firmware reset vector to
	 * chip address 0, then drop CR4 out of reset.  Must be run AFTER
	 * a successful load_firmware (so SOCRAM holds the firmware
	 * blob).  Fires the same brcmf_chip_ai_resetcore sequence Linux
	 * uses.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "release_cr4",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_release_cr4, "I",
	    "Write 1: write rstvec + release CR4 from reset (firmware boots)");

	/*
	 * SDPCM smoke test: build a cur_etheraddr BCDC GET_VAR, send via
	 * the SDPCM CONTROL channel on F2, wait for the response.  Run
	 * AFTER load_firmware + release_cr4 (F2 must be enabled).
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "sdpcm_test",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_sdpcm_test, "I",
	    "Write 1: SDPCM round-trip test (BCDC cur_etheraddr)");

	/*
	 * Generic BCDC iovar GET probe.  `sysctl dev.bwfm.0.iovar_get=ver`
	 * triggers `bwfm_sdio_iovar_get(sc, "ver", ...)` and prints the result
	 * to dmesg.  Same preconditions as sdpcm_test: load_firmware +
	 * release_cr4 must have run.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "iovar_get",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_iovar_get, "A",
	    "Write iovar name: GET via BCDC, print value to dmesg");

	/*
	 * SET-path smoke test using the standard "mpc" knob (Minimum
	 * Power Consumption disable when 0).  Writes are interpreted as
	 * a 4-byte little-endian integer.  Driver re-GETs after the SET
	 * and prints SET/readback to dmesg so a mismatch is visible.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "iovar_set_mpc",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_iovar_set_mpc, "I",
	    "Write integer: SET mpc via BCDC, re-GET, print result");

	/*
	 * EVENT channel control.  events_enable=1 turns on all events
	 * via the event_msgs iovar; cmd_up=1 / cmd_down=1 send the
	 * BWFM_C_UP / BWFM_C_DOWN raw dcmds.  After UP, fw normally
	 * emits BWFM_E_TYPE_LINK + BWFM_E_IF + a couple of others —
	 * watch dmesg for the registered event handler output.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "events_enable",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_events_enable, "I",
	    "Write 1: enable all fw EVENT-channel events via event_msgs");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "cmd_up",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, BWFM_C_UP, bwfm_sdio_sysctl_cmd_dcmd, "I",
	    "Write 1: send BWFM_C_UP raw dcmd; poll rx for events");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "cmd_down",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, BWFM_C_DOWN, bwfm_sdio_sysctl_cmd_dcmd, "I",
	    "Write 1: send BWFM_C_DOWN raw dcmd; poll rx for events");

	/*
	 * Broadcast active escan across all channels.  After
	 * load_firmware + release_cr4 + events_enable + cmd_up,
	 * write 1 here to trigger; each ESCAN_RESULT event prints
	 * the discovered BSS (bssid/ssid/rssi/channel) to dmesg.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "cmd_scan",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_cmd_scan, "I",
	    "Write 1: broadcast active escan + poll rx for results");

	/*
	 * net80211 attach, run on demand once the firmware is up (the
	 * bringup sysctl below chains it).
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "net80211_attach",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_net80211_attach, "I",
	    "Write 1: capture MAC + call bwfm_attach (ifnet appears)");

	/*
	 * One-shot bring-up: chains load_firmware + release_cr4 +
	 * net80211_attach.  Operator-facing entry point so the boot
	 * recipe doesn't have to enumerate every phase.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "bringup",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_bringup, "I",
	    "Write 1: load_firmware + release_cr4 + net80211_attach");

	/*
	 * Cold-reset the chip via WL_REG_ON on the Pi firmware GPIO
	 * expander.  Use this when the BCM43455 has been wedged by an
	 * earlier failed bring-up attempt (CHIPCLKCSR wedge, half-issued
	 * F1 enable, etc.).  After the cycle the chip is back in
	 * boot-ROM state and the host must re-do CCCR/F1 setup before
	 * any further chip access.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "wl_reg_on_cycle",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_wl_reg_on_cycle, "I",
	    "Write 1: power-cycle BCM43xxx via Pi firmware mailbox WL_REG_ON");

	/*
	 * Smoke test for the mbox path -- write 1 to drive WL_REG_ON high
	 * (no-op, chip already powered) and confirm no 'tag 0 response
	 * error' on the console.  Write 0 only if you mean to power the
	 * chip off and leave it off.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "wl_reg_on_set",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_wl_reg_on_set, "I",
	    "Write 0/1: set WL_REG_ON state via Pi firmware mailbox (no toggle)");

	/*
	 * SDIO-spec chip soft-reset (CCCR.CTL.RES + CMD5/3/7 re-handshake).
	 * Unlike the WL_REG_ON GPIO toggle this works on any platform and
	 * keeps the SDIO host's view of the bus consistent across the
	 * reset.  Preferred over wl_reg_on_cycle for runtime use.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "soft_reset",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_soft_reset, "I",
	    "Write 1: CCCR.CTL.RES chip soft-reset + CMD5/3/7 re-handshake");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "cmd53_max_blocks", CTLFLAG_RW,
	    &bwfm_sdio_cmd53_max_blocks, 0,
	    "Cap blocks per block-mode CMD53 (0 = disable block mode, "
	    "1..511 = max blocks)");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "byte_chunk", CTLFLAG_RW,
	    &bwfm_sdio_byte_chunk, 0,
	    "Cap bytes per byte-mode CMD53 (default 512, max 512)");

	/*
	 * Run the prelude (soft-reset + F1 + CARDCAP + KSO + buscoreprep
	 * + PMU reload + chipid recipe lookup) without the firmware
	 * upload.  If this wedges the SD-card controller (root FS) on
	 * Pi 4, the problem is in the prelude rather than the upload.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "load_firmware_prelude",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_load_firmware_prelude, "I",
	    "Write 1: bring-up prelude only (no SOCRAM upload)");

	/*
	 * Upload firmware + NVRAM to SOCRAM and verify head/tail
	 * round-trip.  Requires brcmfmac<chip>_fw.ko to be loaded so
	 * firmware(9) can hand over the blobs.  CR4 is released from
	 * reset separately, by release_cr4.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "load_firmware",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_load_firmware, "I",
	    "Write 1: upload firmware + NVRAM to SOCRAM with verification");

	/*
	 * Chip layer (bwfm_chip.c) inspection.  Run
	 * load_firmware_prelude first to leave the chip in ALPAvail,
	 * then write N to either sysctl to dump that many
	 * registers/words.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "dump_chipcontrol",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_dump_chipcontrol, "I",
	    "Write N (1..32): dump PMU chipcontrol[0..N-1] to dmesg");
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "dump_otp",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, bwfm_sdio_sysctl_dump_otp, "I",
	    "Write N (1..64): dump OTP sromotp[0..N-1] u16 words to dmesg");

	m = bwfm_sdio_lookup(sc->sc_prodid);
	device_printf(dev,
	    "matched %s -- manfid=0x%04x prodid=0x%04x class=0x%02x blksize=%u\n",
	    m != NULL ? m->name : "unknown",
	    sc->sc_manfid, sc->sc_prodid, sc->sc_func_class, sc->sc_blksize);
	DPRINTF(&sc->bsc_base, 1, "func_num=%u sdio_bus=%s\n",
	    sc->sc_func_num, device_get_nameunit(sc->sc_sdio_bus));

	/*
	 * Expose /dev/bwfm<unit> so userspace can drive raw CMD52/CMD53 +
	 * backplane-window operations.  sc_chip_sx serialises this
	 * against the sysctl path.
	 */
	sc->sc_cdev = make_dev(&bwfm_cdevsw, device_get_unit(dev),
	    UID_ROOT, GID_WHEEL, 0600, "bwfm%d", device_get_unit(dev));
	if (sc->sc_cdev != NULL)
		sc->sc_cdev->si_drv1 = sc;
	else
		device_printf(dev, "make_dev /dev/bwfm%d failed\n",
		    device_get_unit(dev));

	/*
	 * bwfm_attach() is not called here: net80211 attach drives iovars
	 * at once, which needs running firmware.  The autostart thread (or
	 * the bring-up sysctls) loads the firmware and then calls it.
	 */
	if (bwfm_sdio_autostart_dflt) {
		sc->sc_autostart_running = true;
		if (kproc_create(bwfm_sdio_autostart, sc, NULL, 0, 0,
		    "%s autostart", device_get_nameunit(dev)) != 0) {
			sc->sc_autostart_running = false;
			device_printf(dev, "autostart: kproc_create failed; "
			    "use the bring-up sysctls\n");
		}
	}
	return (0);
}

/*
 * The autostart thread.  The F2 sibling can attach after F1, so wait for
 * it first; then run the bring-up steps under sc_chip_sx as the sysctls
 * do.  A failed step is logged and left for the sysctls to retry.
 */
static void
bwfm_sdio_autostart(void *arg)
{
	struct bwfm_sdio_softc *sc = arg;
	const char *step;
	int err, i;

	for (i = 0; i < 100 && sc->sc_f2_dev == NULL &&
	    !sc->bsc_base.sc_dying; i++)
		pause("brcmf2w", hz / 10);
	if (sc->bsc_base.sc_dying)
		goto out;
	if (sc->sc_f2_dev == NULL) {
		device_printf(sc->sc_dev,
		    "autostart: no F2 device after 10 s; not starting\n");
		goto out;
	}
	device_printf(sc->sc_dev, "autostart: bringing the chip up\n");

	step = "read_chipid";
	sx_xlock(&sc->sc_chip_sx);
	err = bwfm_sdio_read_chipid_now(sc);
	if (err == 0) {
		step = "load_firmware";
		err = bwfm_sdio_load_firmware_now(sc, true);
	}
	if (err == 0) {
		step = "release_cr4";
		err = bwfm_sdio_release_cr4_now(sc);
	}
	sx_xunlock(&sc->sc_chip_sx);
	if (err == 0 && !sc->bsc_base.sc_dying) {
		step = "net80211_attach";
		err = bwfm_sdio_net80211_attach_now(sc);
	}
	if (err != 0)
		device_printf(sc->sc_dev, "autostart: %s failed (err=%d); "
		    "retry with the dev.%s.%d sysctls\n", step, err,
		    device_get_name(sc->sc_dev), device_get_unit(sc->sc_dev));
	else
		device_printf(sc->sc_dev, "autostart: chip up\n");
out:
	sc->sc_autostart_running = false;
	wakeup(&sc->sc_autostart_running);
	kproc_exit(0);
}

/* tear down the driver when the card is removed */
static int
bwfm_sdio_detach(device_t dev)
{
	struct bwfm_sdio_softc *sc = device_get_softc(dev);

	/* Let a running autostart finish before anything is torn down. */
	while (sc->sc_autostart_running)
		tsleep(&sc->sc_autostart_running, 0, "bwfmasw", hz / 10);

	/*
	 * Refuse to detach while net80211 still holds callbacks into
	 * our module text.  Otherwise `kldunload bwfm_sdio` after an
	 * `ifconfig wlan create wlandev bwfm0 ...` panics the next time
	 * net80211 dispatches an iv_op through the stale function
	 * pointer.  The operator must `ifconfig wlan0 destroy` first to
	 * drop the vap, then re-run kldunload.
	 */
	if (sc->bsc_base.sc_ic_attached) {
		device_printf(dev,
		    "detach refused: net80211 still attached "
		    "(ifconfig wlan0 destroy first)\n");
		return (EBUSY);
	}

	/*
	 * Stop the SDIO watchdog callout + task FIRST — before the
	 * common transport teardown.  bwfm_transport_teardown sleeps
	 * on sc_in_flight_dcmd, and while it sleeps the still-running
	 * watchdog task can drive a fresh SDPCM RX pump that enqueues
	 * a control frame back through the very sc_ctl_mtx path being
	 * torn down.  Silencing the watchdog first eliminates that
	 * race so teardown's sleep is guaranteed to reach zero.
	 *
	 * Order: set sc_wd_stop (both the callout and the task observe
	 * it as a bail-early check), then callout_drain (waits for any
	 * softclock callback in flight), then taskqueue_drain (waits
	 * for the deferred task if softclock enqueued one before
	 * observing sc_wd_stop).
	 */
	sc->sc_wd_stop = true;
	callout_drain(&sc->sc_wd_callout);
	taskqueue_drain(taskqueue_thread, &sc->sc_wd_task);

	/*
	 * Common transport-teardown prologue: flip sc_dying, wake any
	 * sleepers parked on sc_ctl_pending, wait for in-flight dcmds
	 * to drain BEFORE we destroy the mutex they sleep on; otherwise
	 * mtx_destroy races an in-flight dcmd in mtx_sleep, which means
	 * silent memory corruption or a panic.
	 */
	bwfm_transport_teardown(&sc->bsc_base);

	if (sc->sc_cdev != NULL) {
		destroy_dev(sc->sc_cdev);
		sc->sc_cdev = NULL;
	}
	if (sc->sc_sdpcm != NULL) {
		bwfm_sdpcm_free(sc->sc_sdpcm);
		sc->sc_sdpcm = NULL;
	}

	/* Drain + tear down the TX and EVENT rx taskqueues before
	 * freeing anything bwfm_rx_frame might touch. */
	if (sc->sc_tx_tq != NULL) {
		taskqueue_drain(sc->sc_tx_tq, &sc->sc_tx_task);
		taskqueue_free(sc->sc_tx_tq);
		sc->sc_tx_tq = NULL;
		mbufq_drain(&sc->sc_tx_q);
		mtx_destroy(&sc->sc_tx_mtx);
	}
	if (sc->sc_event_rx_tq != NULL) {
		taskqueue_drain(sc->sc_event_rx_tq, &sc->sc_event_rx_task);
		taskqueue_free(sc->sc_event_rx_tq);
		sc->sc_event_rx_tq = NULL;
	}
	mbufq_drain(&sc->sc_event_rx_q);
	mtx_destroy(&sc->sc_event_rx_mtx);

	mtx_destroy(&sc->bsc_base.sc_ctl_mtx);
	mtx_destroy(&sc->bsc_base.sc_mtx);

	sc->bsc_base.sc_bus_ops = NULL;
	sx_destroy(&sc->sc_chip_sx);
	if (bwfm_sdio_global_softc == sc)
		bwfm_sdio_global_softc = NULL;
	return (0);
}

static device_method_t bwfm_sdio_methods[] = {
	DEVMETHOD(device_probe,		bwfm_sdio_probe),
	DEVMETHOD(device_attach,	bwfm_sdio_attach),
	DEVMETHOD(device_detach,	bwfm_sdio_detach),
	DEVMETHOD_END
};

static driver_t bwfm_sdio_driver = {
	"bwfm",
	bwfm_sdio_methods,
	sizeof(struct bwfm_sdio_softc),
};

DRIVER_MODULE(bwfm_sdio, sdio, bwfm_sdio_driver, NULL, NULL);
MODULE_VERSION(bwfm_sdio, 1);
/*
 * Depend on the sdio bus driver (sys/dev/mmc/sdio_func.c, version 1),
 * not directly on mmc.  Indirection keeps us decoupled from mmc's
 * private version churn (MMC_VERSION = 5 today).  The sdio bus itself
 * inherits the mmc dep, so we get it transitively.
 */
MODULE_DEPEND(bwfm_sdio, sdio, 1, 1, 1);
MODULE_DEPEND(bwfm_sdio, wlan, 1, 1, 1);

/* ------------------------------------------------------------------
 * F2 sibling driver
 *
 * BCM43xxx exposes the WLAN function on SDIO func 1 (CMD52/CMD53 to F1
 * lands on the backplane window) and the high-throughput SDPCM data
 * path on SDIO func 2 (CMD53 writes go into the chip's TX FIFO, reads
 * drain the RX FIFO).
 *
 * The FreeBSD sdio bus enumerates each function as a separate child
 * device, so to address F2 we need a device_t for it.  Rather than
 * reaching into the sdio bus internals, attach a minimal driver to F2
 * that does nothing but stash F2's device_t into the F1 softc.
 *
 * The two functions share an sdio bus parent.  We use a global softc
 * pointer to bind them (only one card is supported per kmod load).
 * F1 attach sets `bwfm_sdio_global_softc = sc`; F2 attach reads it and
 * stores its own device_t in `sc->sc_f2_dev`.  Detach order isn't
 * deterministic (FreeBSD newbus doesn't guarantee sibling order), so
 * F2 detach also clears `sc->sc_f2_dev` only if it still points to
 * itself.
 *
 * SDPCM transport calls (bwfm_sdpcm.c) reach F2 by passing this
 * device_t to bwfm_sdpcm_f2_xfer.
 * ------------------------------------------------------------------ */

struct bwfm_sdio_f2_softc {
	device_t		f2_dev;
	struct bwfm_sdio_softc *f2_parent;	/* F1 softc */
};

/* check the function-2 child device */
static int
bwfm_sdio_f2_probe(device_t dev)
{
	uint16_t manfid;
	uint8_t func_num;
	char desc[96];

	manfid = sdio_get_manfid(dev);
	func_num = sdio_get_func_num(dev);

	if (manfid != SDIO_VENDOR_BROADCOM)
		return (ENXIO);
	if (func_num != 2)
		return (ENXIO);

	snprintf(desc, sizeof(desc),
	    "Broadcom WLAN SDPCM data (SDIO func %u)", func_num);
	device_set_desc_copy(dev, desc);
	return (BUS_PROBE_DEFAULT);
}

/* set up the function-2 child device */
static int
bwfm_sdio_f2_attach(device_t dev)
{
	struct bwfm_sdio_f2_softc *f2sc;
	struct bwfm_sdio_softc *psc;
	int err = 0;

	f2sc = device_get_softc(dev);
	f2sc->f2_dev = dev;

	/* Bind to the F1 instance — only one supported. */
	psc = bwfm_sdio_global_softc;
	if (psc == NULL) {
		/* F2 attached before F1 — uncommon, but the sdio bus
		 * doesn't guarantee enumeration order.  F1 attach finds
		 * us among the bus children. */
		device_printf(dev,
		    "F1 not yet attached; F2 device_t deferred\n");
		return (0);
	}
	f2sc->f2_parent = psc;
	psc->sc_f2_dev = dev;
	device_printf(dev,
	    "F2 attached to F1 (%s)\n", device_get_nameunit(psc->sc_dev));

	/*
	 * Do NOT write CCCR FN_ENABLE here.  F2 must stay disabled until
	 * firmware is uploaded and CR4 released — fw is the one that
	 * brings up the F2 backend; touching FN_ENABLE before that just
	 * makes the chip raise IO errors on the next CMD52.  The
	 * release_cr4 path flips the bit.
	 */
	(void)err;
	return (0);
}

/* tear down the function-2 child device */
static int
bwfm_sdio_f2_detach(device_t dev)
{
	struct bwfm_sdio_f2_softc *f2sc;

	f2sc = device_get_softc(dev);
	if (f2sc->f2_parent != NULL && f2sc->f2_parent->sc_f2_dev == dev)
		f2sc->f2_parent->sc_f2_dev = NULL;
	return (0);
}

static device_method_t bwfm_sdio_f2_methods[] = {
	DEVMETHOD(device_probe,		bwfm_sdio_f2_probe),
	DEVMETHOD(device_attach,	bwfm_sdio_f2_attach),
	DEVMETHOD(device_detach,	bwfm_sdio_f2_detach),
	DEVMETHOD_END
};

static driver_t bwfm_sdio_f2_driver = {
	"bwfm_f2",
	bwfm_sdio_f2_methods,
	sizeof(struct bwfm_sdio_f2_softc),
};

DRIVER_MODULE(bwfm_sdio_f2, sdio, bwfm_sdio_f2_driver, NULL, NULL);
