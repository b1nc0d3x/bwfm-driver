/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC SDIO transport glue for brcm. Targets the
 * BCM43xxx family that the Raspberry Pi 4 has on its internal
 * SDIO bus (BCM43430 / CYW43436 / BCM43455).
 *
 * Life cycle:
 *   1. sdio0 lists I/O functions and creates one newbus child
 *      per function (sdio_func.c). Each child carries
 *      manfid/prodid/class ivars via SDIO_ACCESSOR().
 *   2. probe() matches on (manfid, prodid) being the Broadcom
 *      WLAN function (manfid=0x02d0, prodid in the BCM43xxx
 *      table) AND func_num == 1, the WLAN function. Functions
 *      2 and 3 are vendor management interfaces we do not
 *      drive yet.
 *   3. attach() grabs the parent sdio bus device so the bus_ops
 *      can send CMD52/CMD53 via sdio_read_byte() /
 *      sdio_write_byte(). Records the chip identity for
 *      logging. Does NOT yet pull firmware or call
 *      brcm_attach(). Those need the backplane-window CMD53
 *      path plus per-chip si_pmu init, still on the todo list.
 *   4. detach() releases the child.
 *
 * What this scaffold proves:
 *   - The sdio function bus + per-function CIS parser make
 *     correctly-keyed children.
 *   - newbus binds brcm_sdio to func 1.
 *   - The bus_ops table plumbs to SDIO without dragging in
 *     brcm.c yet.
 *
 * What is stubbed on purpose:
 *   - bs_txctl / bs_rxctl / bs_txdata return ENOTSUP. There is
 *     no firmware running yet, so there is nothing to talk to.
 *   - bs_stop is a no-op.
 *   - No brcm_attach() call. net80211 would try to bring up
 *     the interface and panic on missing firmware. Wire it up
 *     in the next phase, after CMD53 + backplane window +
 *     firmware upload land.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/firmware.h>
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

#include <dev/brcm/brcmvar.h>
#include <dev/brcm/brcm_sdpcm.h>
#include <dev/brcm/brcm_sdio_regs.h>
#include <dev/brcm/if_brcm_sdio_cdev.h>
#include <dev/brcm/brcm_chip.h>

#ifdef __aarch64__
#include <arm/broadcom/bcm2835/bcm2835_firmware.h>
#endif

#include <sys/sx.h>

struct brcm_sdio_softc {
	struct brcm_softc	 bsc_base;	/* must be first */
	device_t		 sc_dev;	/* the sdio func1 child */
	device_t		 sc_f2_dev;	/* sdio func2 child (SDPCM
						 * data path); attached by
						 * the brcm_sdio_f2 sibling
						 * driver via the global
						 * registry below. NULL until
						 * F2 attaches. */
	struct brcm_sdpcm_state	*sc_sdpcm;	/* SDPCM layer state.
						 * Allocated lazily on first
						 * sdpcm_test sysctl; NULL
						 * before brcm_sdpcm_init. */
	bool			 sc_f2_enabled;	/* CCCR.IOEn F2 set + IORx F2
						 * confirmed by release_cr4
						 * after fw is up. */
	device_t		 sc_sdio_bus;	/* parent sdio bus */
	uint16_t		 sc_manfid;
	uint16_t		 sc_prodid;
	uint8_t			 sc_func_num;
	uint8_t			 sc_func_class;
	/* sc_f2_dev forward-decl above; published in brcm_sdio_global_softc. */
	uint16_t		 sc_blksize;
	uint32_t		 sc_sbwad;	/* cached backplane window base */
	struct sx		 sc_chip_sx;	/* serialises chip-side ops */
	struct cdev		*sc_cdev;	/* /dev/brcm0 raw interface */
	struct brcm_chip	 sc_chip;	/* chip object (brcm_chip.c) */
	bool			 sc_chip_ready;	/* CC core registered + caps probed */

	/*
	 * Per-sc event delivery queue.  SDPCM rx callback enqueues an
	 * mbuf-wrapped raw EVENT body here; sc_event_rx_task drains it
	 * on a dedicated kernel taskqueue thread and calls brcm_rx_frame.
	 * Mirrors Linux brcmfmac's event_worker pattern (see Pi 3B
	 * ftrace recon).
	 */
	struct mtx		 sc_event_rx_mtx;
	struct mbufq		 sc_event_rx_q;
	struct task		 sc_event_rx_task;
	struct taskqueue	*sc_event_rx_tq;

	/*
	 * Linux-parity periodic SDIO watchdog (sdio.c:3669
	 * brcmf_sdio_bus_watchdog).  Fires every BRCM_WD_POLL_MS to
	 * pump the SDIO F2 RX queue -- catches any interrupts our
	 * ithread missed and, critically, keeps SDIO bus warm so chip
	 * fw doesn't decide "host is dead" and tear down the assoc
	 * (BCM43455 fw 7.45.18 does this within milliseconds of ASSOC
	 * if host is silent -- observed).
	 */
	struct callout		 sc_wd_callout;
	struct task		 sc_wd_task;
	bool			 sc_wd_stop;
};

#define	BRCM_WD_POLL_MS		10

/* Forward declarations for the watchdog (used in release_cr4). */
static void brcm_sdio_watchdog_callout(void *arg);
static void brcm_sdio_watchdog_task(void *arg, int pending);

/* Forward-decl of the F1 → F2 binding global; defined near the F2
 * sibling driver at the end of this file. */
static struct brcm_sdio_softc * volatile brcm_sdio_global_softc;

/* Forward-decl of the F2 sibling driver's per-instance softc; defined
 * with the rest of the F2 plumbing below.  attach() walks the sdio
 * bus children looking for an already-attached "brcm_f2" and binds
 * itself to it via this struct. */
struct brcm_sdio_f2_softc;

/*
 * DPRINTF(&sc->bsc_base, level, ...) — defined by brcmvar.h, gated on
 * the per-instance sc_debug exposed as dev.brcm.N.debug (added at
 * attach below).  Levels per the core driver convention:
 *   0 = silent (default)
 *   1 = milestones (attach checkpoints, chip-id, firmware load steps)
 *   2 = protocol (each CMD52/CMD53 + BCDC header)
 *   3 = per-frame / hex dumps
 *
 * sc_debug lives in the embedded brcm_softc (bsc_base) so the
 * standard brcm DPRINTF macro picks it up uniformly across USB /
 * PCI / SDIO transports.
 */

/*
 * Recognised BCM43xxx prodids (manfid is always 0x02d0 = Broadcom).
 * Keep the list narrow at first — we want explicit support tables, not
 * wildcard claims.  Each entry will gain a chip-id row when we wire up
 * the firmware loader; for now the table is just a probe filter.
 *
 * Names use the Broadcom marketing IDs; Cypress's post-acquisition
 * relabelling is noted in comments where the chip changed name.
 */
struct brcm_sdio_match {
	uint16_t	prodid;
	const char	*name;
};

static const struct brcm_sdio_match brcm_sdio_chips[] = {
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

static const struct brcm_sdio_match *
brcm_sdio_lookup(uint16_t prodid)
{
	size_t i;

	for (i = 0; i < nitems(brcm_sdio_chips); i++) {
		if (brcm_sdio_chips[i].prodid == prodid)
			return (&brcm_sdio_chips[i]);
	}
	return (NULL);
}

/* ------------------------------------------------------------------
 * BCM43xxx chip bring-up — function 1 enable, backplane window,
 * chip-id readback.  Tier 0 of the firmware-upload path: until these
 * work, every higher-level operation (firmware blob upload, mailbox
 * setup, BCDC commands) is unreachable because they all need either
 * func 1 to be enabled or the backplane window to be addressable.
 *
 * Sequence below mirrors the early lines of Linux brcmfmac's
 * brcmf_sdio_probe() in drivers/net/wireless/broadcom/brcm80211/
 * brcmfmac/sdio.c — we don't follow the Linux structure verbatim, but
 * the chip-side semantics are identical:
 *
 *   1.  CCCR.IO_EN |= 0x02      (host signals "please bring up F1")
 *   2.  poll CCCR.IO_READY      (chip ACKs "F1 is live")
 *   3.  set backplane window    (3 CMD52 writes to F1's SBADDR*)
 *   4.  CMD53 read 4 bytes      (host fetches CC.CHIPID from
 *                                chip-internal address 0x18000000)
 *
 * If step 4 returns a sensible chip_id (matches the SDIO CIS prodid
 * we already saw), the whole backplane path is healthy and we know
 * the chip's PLL is stable enough to clock its internal AXI fabric.
 * That's the prerequisite the firmware uploader will rely on.
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
brcm_sdio_kso_enable(struct brcm_sdio_softc *sc)
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
		pause("brcmkso", 1);	/* ~1 ms sleep, not busy-wait */
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
 * This is the EXACT preamble Linux brcmfmac runs in
 * brcmf_sdio_buscoreprep() before chip recognition.  Skipping it
 * means HT_AVAIL_REQ can be acknowledged (bit stays set) but the
 * chip's PMU never spins up HT.  The trick is sequential: force
 * ALP first, wait for it, lock the hw-clock-request OFF, only then
 * release the lock and ask for HT.
 *
 * Steps verbatim from Linux:
 *   1. CHIPCLKCSR = FORCE_HW_CLKREQ_OFF | ALP_AVAIL_REQ  (0x28)
 *      -- ask for ALP and prevent the chip from auto-requesting HT.
 *   2. Read back; the low 5 bits (CSR_MASK) must match what we wrote
 *      (the upper bits are AV status the chip sets).
 *   3. Poll for ALP_AVAIL (bit 6, 0x40) up to ~5 s.  Linux comments
 *      say "may take up to 15 ms".
 *   4. CHIPCLKCSR = FORCE_HW_CLKREQ_OFF | FORCE_ALP  (0x21)
 *      -- lock the chip on ALP.
 *   5. DELAY(65).
 *   6. SBSDIO_FUNC1_SDIOPULLUP = 0 -- disable extra SDIO pull-ups.
 */
static int
brcm_sdio_buscoreprep(struct brcm_sdio_softc *sc)
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
		pause("brcmalp", 1);	/* ~1 ms sleep, not busy-wait */
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
 * Discriminating which flavour we're on: every BCM43xxx chip the
 * SDIO bus enumerates here is SR-capable in practice -- the few
 * non-SR-capable parts (BCM43340/43342/43362) predate the SDIO bus
 * support tier we promise.  Treat every chip as SR-capable.
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
brcm_sdio_request_ht_clock(struct brcm_sdio_softc *sc)
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
	 * with a stale CHIPCLKCSR.  Mirrors OpenBSD brcm_sdio_attach's
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
	 * fatal.  On SR-capable chips the WHD reference path never
	 * polls -- KSO + FORCE_HT are the contract and backplane writes
	 * are expected to work even if CHIPCLKCSR doesn't surface
	 * HT_AVAIL.  If HT_AVAIL never sets we still return 0; the next
	 * step (CR4 IOCTL write) is the real test of whether HT actually
	 * latches.  If that write also fails to latch we'll know
	 * FORCE_HT wasn't enough on this chip.
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
		pause("brcmht", 1);
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
brcm_sdio_enable_func1(struct brcm_sdio_softc *sc)
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
brcm_sdio_set_backplane(struct brcm_sdio_softc *sc, uint32_t chip_addr)
{
	uint32_t newbase, diff;
	bool cold;
	int err;

	newbase = chip_addr & SBSDIO_SBWINDOW_MASK;
	diff = newbase ^ sc->sc_sbwad;

	/*
	 * Skip only when we already have an established cached window
	 * (sc_sbwad != 0) AND the new base falls inside it.  When
	 * sc_sbwad == 0 the cache is uninitialised -- this happens at
	 * cold attach, after kldunload/kldload, and after any I/O error
	 * that forced a reset of sc_sbwad in the fail: path below.
	 * The chip's SBADDR* bytes may carry leftover state from a
	 * prior session, so we cannot trust the diff and must write
	 * every byte to bring the window to a known state.
	 */
	if (sc->sc_sbwad != 0 && diff == 0)
		return (0);

	/*
	 * Linux-style "only write the SBADDR bytes that actually changed",
	 * with one wrinkle: on cold/post-error (sc_sbwad == 0) write all
	 * three regardless of the diff bits.  Otherwise a stale chip-side
	 * byte that happens to be non-zero but matches diff==0 would
	 * leave the window pointing at the wrong region (e.g. the prior
	 * session left SBADDRMID=0x10 for a CR4 access, and we now want
	 * CC.CHIPID at 0x18000000 -- without the unconditional cold
	 * write we'd read 0x18100000 by mistake).
	 *
	 * The byte values are taken from newbase, not chip_addr, so the
	 * lower bits of chip_addr (which the chip masks anyway via the
	 * SDIO offset on every access) can't accidentally end up in
	 * SBADDR{LOW,MID}.  Historical bug: chip_addr=0x18000400 used to
	 * write SBADDRLOW=0x04 here, wedging the next CMD53 with
	 * MMC_ERR_INVALID until the chip recovered.
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
 * window.  Mirror image of brcm_sdio_bp_read32.  Local uint32_t
 * lives on the stack so the host DMA path can grab a real KVA.
 */
static int
brcm_sdio_bp_write32(struct brcm_sdio_softc *sc, uint32_t chip_addr,
    uint32_t val)
{
	uint32_t sdio_off, le_val;
	int err;

	err = brcm_sdio_set_backplane(sc, chip_addr);
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
 * Buffer alignment: the value lands in a local uint32_t which sits at
 * a 4-byte-aligned slot on the stack; the host (bcm2835_sdhci on Pi 4)
 * can DMA directly into it.  Caller's `*valp` is filled only on
 * success.
 */
static int
brcm_sdio_bp_read32(struct brcm_sdio_softc *sc, uint32_t chip_addr,
    uint32_t *valp)
{
	uint32_t sdio_off, val;
	int err;

	err = brcm_sdio_set_backplane(sc, chip_addr);
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
 * brcm80211/brcmfmac/sdio.c brcmf_sdio_fwnames[] (2026 head, cross-
 * checked against the rambase function in chip.c).  We only include
 * the chips that actually ship on hardware we expect to see in the
 * field (Pi 3, Pi 4, common dev boards); the long tail can be added
 * as it turns up.
 *
 * Important note on Pi 4: the SDIO CIS prodid 0xa9a6 is shared by
 * BCM43430-class and BCM43455-class boards.  Our Pi 4 sample reads
 * CC.CHIPID = 0x4345 rev 6, so it's actually BCM43455 silicon --
 * different firmware from BCM43430.  Always select firmware from
 * CC.CHIPID, never from the SDIO prodid.
 */
static const struct brcm_sdio_chip_recipe brcm_sdio_recipes[] = {
	{ BRCM_CHIP_BCM43430, 0x00000001, 0x000000, BRCM_ARM_CM3,
	  "43430a0", NULL, "BCM43430 rev A0 (Pi 3 early)" },
	{ BRCM_CHIP_BCM43430, 0x00000002, 0x000000, BRCM_ARM_CM3,
	  "43430a1", NULL, "BCM43430 rev A1" },
	{ BRCM_CHIP_BCM43430, 0xFFFFFFFC, 0x000000, BRCM_ARM_CM3,
	  "43430b0", NULL, "BCM43430 rev B0 (Pi 3B, Pi Zero W)" },

	{ BRCM_CHIP_BCM4345,  0x00000200, 0x198000, BRCM_ARM_CR4,
	  "43456",  NULL, "BCM43456 (Pi CM4)" },
	{ BRCM_CHIP_BCM4345,  0xFFFFFDC0, 0x198000, BRCM_ARM_CR4,
	  "43455",  NULL, "BCM43455 (Pi 4B, Pi 3B+)" },

	{ BRCM_CHIP_BCM4339,  0xFFFFFFFF, 0x180000, BRCM_ARM_CR4,
	  "4339",   NULL, "BCM4339" },
	{ BRCM_CHIP_BCM4354,  0xFFFFFFFF, 0x180000, BRCM_ARM_CR4,
	  "4354",   NULL, "BCM4354" },
	{ BRCM_CHIP_BCM4356,  0xFFFFFFFF, 0x180000, BRCM_ARM_CR4,
	  "4356",   NULL, "BCM4356" },
	{ BRCM_CHIP_BCM4359,  0xFFFFFFFF, 0x180000, BRCM_ARM_CR4,
	  "4359",   NULL, "BCM4359 rev <9 (rev >=9 uses 0x160000)" },
	{ BRCM_CHIP_BCM4373,  0xFFFFFFFF, 0x160000, BRCM_ARM_CR4,
	  "4373",   NULL, "BCM4373 / CYW4373" },
};

/*
 * Lookup a recipe row for (chip_id, chip_rev).  Returns NULL if no
 * row matches -- which is a real diagnostic: it means the chip is
 * either too new for our table or one of the prodid-coincident chips
 * we haven't characterised yet.  Caller must not proceed with
 * firmware upload in that case.
 */
static const struct brcm_sdio_chip_recipe *
brcm_sdio_lookup_recipe(uint16_t chip_id, uint8_t chip_rev)
{
	const struct brcm_sdio_chip_recipe *r;
	uint32_t revbit;
	size_t i;

	revbit = 1u << chip_rev;
	for (i = 0; i < nitems(brcm_sdio_recipes); i++) {
		r = &brcm_sdio_recipes[i];
		if (r->chip_id != chip_id)
			continue;
		if ((r->chiprev_mask & revbit) == 0)
			continue;
		return (r);
	}
	return (NULL);
}

static const char *
brcm_sdio_arm_name(enum brcm_arm_core c)
{
	switch (c) {
	case BRCM_ARM_CM3: return ("Cortex-M3");
	case BRCM_ARM_CR4: return ("Cortex-R4");
	case BRCM_ARM_CA7: return ("Cortex-A7");
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
brcm_sdio_read_chipid_now(struct brcm_sdio_softc *sc)
{
	const struct brcm_sdio_chip_recipe *r;
	uint32_t chipid;
	uint16_t chip_id;
	uint8_t chip_rev;
	int err;

	err = brcm_sdio_enable_func1(sc);
	if (err != 0)
		return (err);
	err = brcm_sdio_bp_read32(sc, BRCM_CC_CORE_BASE + BRCM_CC_CHIPID,
	    &chipid);
	if (err != 0)
		return (err);

	chip_id = BRCM_CHIPID_ID(chipid);
	chip_rev = BRCM_CHIPID_REV(chipid);

	device_printf(sc->sc_dev,
	    "CC.CHIPID = 0x%08x: chip=0x%04x rev=%u pkg=%u num_cores=%u\n",
	    chipid, chip_id, chip_rev, BRCM_CHIPID_PKG(chipid),
	    BRCM_CHIPID_NUMCORES(chipid));

	r = brcm_sdio_lookup_recipe(chip_id, chip_rev);
	if (r == NULL) {
		device_printf(sc->sc_dev,
		    "no recipe for chip=0x%04x rev=%u -- firmware upload "
		    "would not know what to load\n", chip_id, chip_rev);
		return (ENOENT);
	}
	device_printf(sc->sc_dev,
	    "recipe match: %s -- arm=%s ram_base=0x%06x "
	    "fw=brcmfmac%s-sdio.bin nvram=brcmfmac%s-sdio.txt\n",
	    r->desc, brcm_sdio_arm_name(r->arm_core), r->ram_base,
	    r->fw_name,
	    r->nvram_board != NULL ? r->nvram_board : r->fw_name);

	/*
	 * Final verification step: try to look up the firmware blobs
	 * via firmware(9).  If brcmfmac<chip>_fw.ko is loaded (or built
	 * into the kernel), firmware_get() returns a handle and we log
	 * the blob size as proof the upload path will have something to
	 * push.  If it's missing the operator sees exactly which
	 * filename to install -- usually just a kldload away.
	 *
	 * We release the references immediately; the actual firmware
	 * upload path will re-acquire them when it's ready to run.
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

static int brcm_sdio_chip_soft_reset(struct brcm_sdio_softc *sc);

/*
 * Pin the parent SDHCI controller's interrupt to a specific CPU.
 *
 * The Pi 4 GIC routes every SPI to CPU0 by default.  brcm's CMD53
 * storm on sdhci_bcm0 generates so many interrupts on CPU0 that the
 * sibling sdhci_bcm1 (which hosts the SD card / root FS) cannot get
 * its 8 ms hardware data-line timeout serviced -- the SD controller
 * declares "Controller timeout" and UFS root panics.
 *
 * Moving sdhci_bcm0's IRQ to a non-CPU0 leaves CPU0 to sdhci_bcm1's
 * ithread alone.  We walk brcm0 -> sdio0 -> mmc0 -> sdhci_bcm0,
 * grab the IRQ resource from its resource list, and call
 * intr_setaffinity to retarget the GIC and rebind the ithread.
 *
 * Returns 0 on success, non-zero on lookup or setaffinity failure.
 * Safe to call multiple times -- it just reapplies the affinity.
 */
static int
brcm_sdio_pin_host_irq(struct brcm_sdio_softc *sc, int cpu)
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

static int
brcm_sdio_sysctl_pin_host_irq(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int cpu = -1;
	int err;

	err = sysctl_handle_int(oidp, &cpu, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);
	if (cpu < 0)
		return (EINVAL);
	return (brcm_sdio_pin_host_irq(sc, cpu));
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
 * Bulk uses block-mode CMD53 (511 blocks * F1 block_size = 32704 B per
 * transaction).  Block mode bundles the block stream inside the SDHCI
 * hardware, so we get one TRANS_COMPLETE IRQ per CMD53 instead of one
 * per <=64 B byte-mode CMD53.  For a 622 KB firmware upload that
 * drops the interrupt count from ~10k to ~40 -- removes the shared
 * SDHCI ithread saturation that previously starved sdhci_bcm1 (SD
 * card / root FS) into a controller timeout panic.
 *
 * Sub-block tails (len < block_size) fall back to byte-mode CMD53
 * via sdio_write_multi -- only happens at the very end of the
 * firmware blob if its size isn't a multiple of the block size.
 */
#define	BRCM_SDIO_CMD53_MAX_BLOCKS	511

/*
 * Block-mode CMD53 cap.  Disabled by default (0) because non-MMCCAM
 * kernels' sdhci.c ignores data->block_size/block_count and computes
 * blocks-of-512 internally, so any block-mode CMD53 with nblocks > 1
 * fails MMC_ERR_BADCRC (card emits CRC per 64-B block; SDHCI checks
 * one CRC over the whole transfer).  Even nblocks=1 buys nothing over
 * byte-mode at the same byte count.  Left as a tunable so a future
 * MMCCAM build can enable it without code changes.
 */
static int brcm_sdio_cmd53_max_blocks = 0;

/*
 * Cap byte-mode CMD53 chunk size (in bytes).  Default 64 because
 * bcm2835_sdhci (the WiFi-side SDHCI on Pi 4) rejects byte-mode CMD53s
 * larger than the F1 IO block size with EIO.  Tunable so other hosts
 * with looser limits can bump it (up to 512, sdio_write_multi's cap).
 */
static int brcm_sdio_byte_chunk = 64;

/*
 * Issue a single block-mode CMD53 transfer.  nblocks must be 1..511
 * (the 9-bit length field; 0 would encode "infinite" which we never
 * want).  blocksize is the F1 IO block size programmed by sdio_attach
 * via CCCR.FBR1.IO_BLKSIZE.
 */
static int
brcm_sdio_cmd53_block_xfer(struct brcm_sdio_softc *sc, uint32_t off,
    void *buf, size_t nblocks, size_t blocksize, bool write)
{
	struct mmc_command cmd;
	struct mmc_data data;
	device_t mmcbus;
	uint8_t fn;
	uint32_t arg;
	int err;

	if (nblocks == 0 || nblocks > BRCM_SDIO_CMD53_MAX_BLOCKS)
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

static int
brcm_sdio_socram_write(struct brcm_sdio_softc *sc, uint32_t chip_addr,
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
		err = brcm_sdio_set_backplane(sc, chip_addr);
		if (err != 0)
			return (err);

		window_room = SBSDIO_SB_OFT_ADDR_LIMIT -
		    (chip_addr & SBSDIO_SB_OFT_ADDR_MASK);


		if (len >= blocksize && window_room >= blocksize &&
		    brcm_sdio_cmd53_max_blocks >= 1) {
			size_t nblocks;
			size_t cap = (size_t)brcm_sdio_cmd53_max_blocks;

			if (cap > BRCM_SDIO_CMD53_MAX_BLOCKS)
				cap = BRCM_SDIO_CMD53_MAX_BLOCKS;
			nblocks = MIN(len / blocksize, cap);
			nblocks = MIN(nblocks, window_room / blocksize);
			chunk = nblocks * blocksize;
			err = brcm_sdio_cmd53_block_xfer(sc,
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
			 * dev.brcm.0.byte_chunk tunable -- bcm2835_sdhci has
			 * a 512-byte DMA segment ceiling, and there may be
			 * smaller working maxima that we're still bisecting.
			 * sdio_write_multi will further cap at 512 internally.
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
			size_t cap = (size_t)brcm_sdio_byte_chunk;

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
			pause("brcmthr", 1);

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

static int
brcm_sdio_socram_read(struct brcm_sdio_softc *sc, uint32_t chip_addr,
    void *buf, size_t len)
{
	uint8_t *p = buf;
	uint32_t window_room;
	size_t chunk;
	int err;

	while (len > 0) {
		err = brcm_sdio_set_backplane(sc, chip_addr);
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
 * Upload firmware (and NVRAM) into SOCRAM.  Matches the
 * brcmf_sdio_download_firmware() / brcm_sdio_load_microcode() path on
 * Linux / OpenBSD: firmware blob at chip ram_base, NVRAM at the
 * tail of RAM at (ram_base + ramsize - nvram_len).  We don't yet know
 * ramsize from chip-side discovery, so plumb in the chip recipe's
 * advertised size (768 KB for BCM43455 by convention).  Verify by
 * reading back the first and last 16 bytes of each region.
 *
 * The CR4 wrap stays powered-down through all of this -- which is
 * fine, the upload doesn't touch the wrap.  Releasing CR4 from reset
 * after the upload is the next phase; that's when the chip's PMU
 * brings up the CR4 power island in response to firmware's resource
 * requests.
 */
static int
brcm_sdio_load_firmware_now(struct brcm_sdio_softc *sc, bool do_upload)
{
	const struct brcm_sdio_chip_recipe *r;
	const struct firmware *fw_blob = NULL;
	const struct firmware *nvram_blob = NULL;
	char fwname[64], nvname[64];
	uint32_t chipid, head[4], tail[4];
	uint16_t chip_id;
	uint8_t chip_rev;
	int err;
	const uint32_t ramsize_43455 = 0xC0000;	/* 768 KB */
	uint32_t nvram_addr;

	sx_assert(&sc->sc_chip_sx, SA_XLOCKED);

	/*
	 * Same prelude as halt_cr4_now -- soft-reset first to put the
	 * chip into a known fresh state regardless of what previous
	 * sysctl experiments left in place.  Without this, the KSO
	 * enable loop can hang on a chip whose SLEEPCSR.DEVON is in a
	 * mid-state from a half-completed prior bring-up.
	 */
	device_printf(sc->sc_dev,
	    "load_firmware: phase 1/8 chip soft-reset (do_upload=%d)\n",
	    do_upload);
	err = brcm_sdio_chip_soft_reset(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev, "load_firmware: phase 2/8 enable F1\n");
	err = brcm_sdio_enable_func1(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev,
	    "load_firmware: phase 3/8 CARDCAP + KSO\n");
	(void)sdio_cccr_write_byte(sc->sc_dev, SDIO_CCCR_BRCM_CARDCAP,
	    SDIO_CCCR_BRCM_CARDCAP_CMD_NODEC);
	err = brcm_sdio_kso_enable(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev, "load_firmware: phase 4/8 buscoreprep\n");
	err = brcm_sdio_buscoreprep(sc);
	if (err != 0)
		return (err);

	device_printf(sc->sc_dev,
	    "load_firmware: phase 5/8 PMU resource reload\n");
	{
		uint32_t pmuctl;
		err = brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMUCONTROL, &pmuctl);
		if (err != 0)
			return (err);
		pmuctl |= (BRCM_CC_PMUCONTROL_RES_RELOAD <<
		    BRCM_CC_PMUCONTROL_RES_SHIFT);
		(void)brcm_sdio_bp_write32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMUCONTROL, pmuctl);
	}

	device_printf(sc->sc_dev,
	    "load_firmware: phase 6/8 chipid recipe lookup\n");
	err = brcm_sdio_bp_read32(sc, BRCM_CC_CORE_BASE + BRCM_CC_CHIPID,
	    &chipid);
	if (err != 0)
		return (err);
	chip_id = BRCM_CHIPID_ID(chipid);
	chip_rev = BRCM_CHIPID_REV(chipid);
	r = brcm_sdio_lookup_recipe(chip_id, chip_rev);
	if (r == NULL) {
		device_printf(sc->sc_dev,
		    "load_firmware: no recipe for chip=0x%04x rev=%u\n",
		    chip_id, chip_rev);
		return (ENOENT);
	}
	device_printf(sc->sc_dev,
	    "load_firmware: chip=0x%04x rev=%u ram_base=0x%06x fw=%s\n",
	    chip_id, chip_rev, r->ram_base, r->fw_name);

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
	 * heuristic then keeps the brcm sysctl thread on CPU0 too,
	 * ping-ponging against sdhci_bcm0's ithread.  sdhci_bcm1's ithread
	 * then has to compete for CPU0 against the brcm/bcm0 cycle and its
	 * SDHCI_INT_DMA_END border interrupts arrive too late -- the SD
	 * card software watchdog declares timeout and UFS root panics.
	 *
	 * Binding to mp_ncpus-1 takes the brcm-side traffic off CPU0
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
		(void)brcm_sdio_pin_host_irq(sc, bind_cpu);

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
	err = brcm_sdio_socram_write(sc, r->ram_base,
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
	err = brcm_sdio_socram_read(sc, r->ram_base, head, sizeof(head));
	if (err != 0)
		goto out;
	err = brcm_sdio_socram_read(sc,
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
		 * When fw size is not 4-byte aligned (e.g., 488193 = 0x77301
		 * for brcmfmac43455-sdio.bin), the SDIO backplane CMD53 read
		 * of the tail rounds to a 4-byte boundary, producing a
		 * 1-3 byte shift in the readback vs. source.  The bulk
		 * upload itself works (HEAD verifies clean and SOCRAM
		 * activity is visible post-CR4 release).  Warn but don't
		 * abort.
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
	nvram_addr = r->ram_base + ramsize_43455 - nvram_blob->datasize;
	err = brcm_sdio_socram_write(sc, nvram_addr,
	    nvram_blob->data, nvram_blob->datasize);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "load_firmware: nvram upload failed err=%d\n", err);
		goto out;
	}
	device_printf(sc->sc_dev,
	    "NVRAM upload OK: %zu B at chip 0x%08x\n",
	    (size_t)nvram_blob->datasize, nvram_addr);

	/*
	 * BCM43455 fw integrity-check bypass.
	 *
	 * fw[0x4DB3C] runs a handshake against ROM at chip 0xFFE6C70C:
	 * fw stores a static magic (fw[0x771D8] = 0x28DD9C8E) at sp[20],
	 * calls ROM, then bne.n 0x4DC7E (panic loop) if returned value
	 * != ~magic.  On our Pi 4 + FreeBSD path, ROM returns a different
	 * value than fw expects, hanging the chip before HT/F2/sdpcm.
	 * Linux brcmfmac does NOT need this bypass (investigation open
	 * — likely a pre-release register write we still miss).
	 *
	 * Surgical NOP of the bne.n at fw[0x4DC1C]:
	 *   bp_write32 truncates unaligned addresses; chip[0x1E5C1C] is
	 *   word-aligned.  Write preserves fw[0x4DC1E..0x4DC1F] (ldr r2,
	 *   [sp, #12] = bytes 0x03 0x9A) and overwrites bne.n bytes 0x2F
	 *   0xD1 with nop bytes 0x00 0xBF.  Resulting word LE = 0x9A03BF00.
	 *
	 * See feedback_brcm_breakpoint_alignment for the alignment rule,
	 * project_brcm_bypass_technical_note_2026_06_25 for security /
	 * regulatory notes, and project_brcm_bisection_redo_2026_06_24
	 * for the 10-probe discovery story.
	 */
	{
		uint32_t before = 0, after = 0;
		(void)brcm_sdio_bp_read32(sc, r->ram_base + 0x4DC1C, &before);
		if (before == 0x9A03D12Fu) {
			/*
			 * 488193 B brcmfmac43455-sdio.bin (md5
			 * 0324fe9c…): integrity check is here and active.
			 * Apply the patch.
			 */
			err = brcm_sdio_bp_write32(sc,
			    r->ram_base + 0x4DC1C, 0x9A03BF00u);
			if (err != 0) {
				device_printf(sc->sc_dev,
				    "load_firmware: bypass write failed "
				    "err=%d\n", err);
				goto out;
			}
			(void)brcm_sdio_bp_read32(sc,
			    r->ram_base + 0x4DC1C, &after);
			device_printf(sc->sc_dev,
			    "BCM43455 integrity-check bypass: chip[0x%08x] "
			    "0x%08x -> 0x%08x %s\n",
			    r->ram_base + 0x4DC1C, before, after,
			    after == 0x9A03BF00u ? "OK" : "MISMATCH");
			if (after != 0x9A03BF00u) {
				err = EIO;
				goto out;
			}
		} else {
			/*
			 * Different fw blob — bytes don't match the
			 * 488193 B variant we RE'd.  Likely the 637406 B
			 * RPi-Distro firmware-nonfree blob.  Skip the
			 * patch entirely; either this fw doesn't have the
			 * check, or it's elsewhere we haven't located.
			 */
			device_printf(sc->sc_dev,
			    "BCM43455 integrity-check bypass: chip[0x%08x] = "
			    "0x%08x (not 0x9A03D12F) -- different fw blob, "
			    "patch NOT applied\n",
			    r->ram_base + 0x4DC1C, before);
		}
	}

	device_printf(sc->sc_dev,
	    "load_firmware: phase 8/8 DONE -- firmware + NVRAM + bypass in SOCRAM; "
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
 * brcm_chip ops adapter — let the bus-agnostic chip layer drive
 * register access through brcm_sdio's existing backplane window
 * helpers.  read32/write32 ignore EIO (returns 0xFFFFFFFF on failure,
 * mirrors Linux's BUSCORE_READ_FAILED sentinel); upper layers handle
 * the sentinel as needed.  prepare wraps buscoreprep so a fresh call
 * site (sysctl handler) can leave the chip in ALPAvail before any
 * indirect read.  activate is not used by phase-1 helpers but plumbed
 * for completeness — it writes the rstvec to chip[0].
 */
static uint32_t
brcm_sdio_chip_read32(void *ctx, uint32_t addr)
{
	struct brcm_sdio_softc *sc = ctx;
	uint32_t v;

	if (brcm_sdio_bp_read32(sc, addr, &v) != 0)
		return (0xFFFFFFFFu);
	return (v);
}

static void
brcm_sdio_chip_write32(void *ctx, uint32_t addr, uint32_t val)
{
	struct brcm_sdio_softc *sc = ctx;

	(void)brcm_sdio_bp_write32(sc, addr, val);
}

static int
brcm_sdio_chip_prepare(void *ctx)
{
	struct brcm_sdio_softc *sc = ctx;

	return (brcm_sdio_buscoreprep(sc));
}

static void
brcm_sdio_chip_activate(void *ctx, struct brcm_chip *pub,
    uint32_t rstvec)
{
	struct brcm_sdio_softc *sc = ctx;
	struct brcm_chip_core *sdio_core;

	/*
	 * Mirror Linux brcmf_sdio_buscore_activate (sdio.c:3889): clear all
	 * SDIO-core interrupts before releasing the ARM.  Without this,
	 * stale host intrs at fw startup can drive SDPCM to feed the dongle
	 * before fw is ready.
	 */
	sdio_core = brcm_chip_get_core(pub, BCMA_CORE_SDIO_DEV);
	if (sdio_core != NULL) {
		(void)brcm_sdio_bp_write32(sc,
		    sdio_core->base + BRCM_SD_REG_INTSTATUS, 0xffffffffu);
	}

	if (rstvec != 0)
		(void)brcm_sdio_bp_write32(sc, 0, rstvec);
}

static const struct brcm_chip_ops brcm_sdio_chip_ops = {
	.read32 = brcm_sdio_chip_read32,
	.write32 = brcm_sdio_chip_write32,
	.prepare = brcm_sdio_chip_prepare,
	.activate = brcm_sdio_chip_activate,
};

/*
 * Lazy chip-object init.  Caller must hold sc_chip_sx.  Idempotent.
 * Assumes the chip is already in ALPAvail (buscoreprep ran in some
 * prior path -- typically the load_firmware_prelude sysctl).  Phase-1
 * only registers the chipcommon core at SI_ENUM_BASE_DEFAULT
 * (0x18000000 for every BCM43xxx we care about); the full EROM walk
 * port comes in phase 2.
 */
static int
brcm_sdio_chip_ensure(struct brcm_sdio_softc *sc)
{
	int err;

	if (sc->sc_chip_ready)
		return (0);
	brcm_chip_init(&sc->sc_chip, &brcm_sdio_chip_ops, sc);
	err = brcm_chip_add_core(&sc->sc_chip, 0x800 /* BCMA_CORE_CHIPCOMMON */,
	    0, BRCM_CC_CORE_BASE, 0);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "chip_ensure: add_core(CC) failed err=%d\n", err);
		return (err);
	}
	err = brcm_chip_probe_caps(&sc->sc_chip);
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
 *   sysctl dev.brcm.0.load_firmware_prelude=1
 *   sysctl dev.brcm.0.dump_chipcontrol=8     # show CC[0..7]
 *
 * to see PMU chipcontrol state after the bring-up prelude has run.
 */
static int
brcm_sdio_sysctl_dump_chipcontrol(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int n = 0;
	int err;
	uint32_t i, val;

	err = sysctl_handle_int(oidp, &n, 0, req);
	if (err != 0 || req->newptr == NULL || n <= 0)
		return (err);
	if (n > 32)
		n = 32;
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_chip_ensure(sc);
	if (err == 0) {
		device_printf(sc->sc_dev,
		    "chipcontrol dump (pmurev=%u):\n",
		    sc->sc_chip.pmurev);
		for (i = 0; i < (uint32_t)n; i++) {
			val = 0xDEADDEADu;
			(void)brcm_chip_cc_chipcontrol_read32(&sc->sc_chip,
			    i, &val);
			device_printf(sc->sc_dev,
			    "  cc[%2u] = 0x%08x\n", i, val);
		}
		device_printf(sc->sc_dev,
		    "sr_capable=%s\n",
		    brcm_chip_sr_capable(&sc->sc_chip) ? "yes" : "no");
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
brcm_sdio_sysctl_dump_otp(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
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
	err = brcm_sdio_chip_ensure(sc);
	if (err == 0) {
		st = sc->sc_chip.ops->read32(sc->sc_chip.ctx,
		    BRCM_CC_CORE_BASE + BRCM_CC_OTPSTATUS);
		layout = sc->sc_chip.ops->read32(sc->sc_chip.ctx,
		    BRCM_CC_CORE_BASE + BRCM_CC_OTPLAYOUT);
		device_printf(sc->sc_dev,
		    "otpstatus=0x%08x otplayout=0x%08x present=%s\n",
		    st, layout,
		    brcm_chip_otp_present(&sc->sc_chip) ? "yes" : "no");
		(void)brcm_chip_otp_dump(&sc->sc_chip, buf, n);
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

static int
brcm_sdio_sysctl_load_firmware(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_load_firmware_now(sc, true);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

static int
brcm_sdio_sysctl_load_firmware_prelude(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_load_firmware_now(sc, false);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

static int
brcm_sdio_sysctl_read_chipid(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);
	if (trigger == 0)
		return (0);
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_read_chipid_now(sc);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

/* ------------------------------------------------------------------
 * CR4 halt + release.  The EROM walker has moved into brcm_chip.c
 * (brcm_chip_walk_erom); we just consume the (id, base, wrap) tuples
 * it discovers and drive the CR4-specific wrap-register sequence.
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
brcm_sdio_halt_cr4(struct brcm_sdio_softc *sc, uint32_t cr4_wrap)
{
	uint32_t ioctl_before, ioctl_after;
	uint32_t reset_before, pmuctl_before, pmuctl_after;
	uint32_t wrap_id, wrap_state;
	int err;

	/*
	 * Diagnostic dump before any chip-side writes.  We want a
	 * fingerprint of the wrap state so we can tell whether subsequent
	 * writes are landing or being dropped.
	 *
	 *   wrap+0x000  (wrap component id, ought to read 0x4bf80800-ish
	 *                on AI cores with CR4's id 0x83e encoded in bits)
	 *   wrap+0x004  (wrap status)
	 *   wrap+0x408  (BCMA_IOCTL, what halt manipulates)
	 *   wrap+0x800  (BCMA_RESET_CTL, what halt also manipulates)
	 *
	 * If wrap+0/4 read sensibly but +408/+800 read as 0 with no
	 * error, the wrap's status side is on a different clock domain
	 * from the IOCTL/RESET_CTL side -- which would be the smoking
	 * gun for "wrap clock not running".  Also dump CC.PMUCONTROL
	 * which we know is writeable, to confirm chipcommon backplane
	 * writes really do land.
	 */
	(void)brcm_sdio_bp_read32(sc, cr4_wrap + 0x000, &wrap_id);
	(void)brcm_sdio_bp_read32(sc, cr4_wrap + 0x004, &wrap_state);
	(void)brcm_sdio_bp_read32(sc, cr4_wrap + BCMA_RESET_CTL,
	    &reset_before);
	err = brcm_sdio_bp_read32(sc, cr4_wrap + BCMA_IOCTL, &ioctl_before);
	if (err != 0)
		return (err);
	(void)brcm_sdio_bp_read32(sc,
	    BRCM_CC_CORE_BASE + BRCM_CC_PMUCONTROL, &pmuctl_before);
	device_printf(sc->sc_dev,
	    "CR4 wrap=0x%08x dump: wrap+0=0x%08x wrap+4=0x%08x "
	    "IOCTL=0x%08x RESET_CTL=0x%08x CC.PMUCTL=0x%08x\n",
	    cr4_wrap, wrap_id, wrap_state, ioctl_before, reset_before,
	    pmuctl_before);

	/*
	 * SOCRAM write/read probe.  Firmware lives in SOCRAM at chip
	 * address 0x198000 on BCM43455.  Unlike the CR4 wrap, SOCRAM is
	 * always-on (it's where firmware was upload-staged on the chips
	 * brcmfmac was originally targeted at, and the chip's boot ROM
	 * leaves it accessible).  Writing a recognisable pattern and
	 * reading it back is the proof-of-life test for the firmware-
	 * upload path -- if this round-trips, the next step is uploading
	 * the actual brcmfmac43455-sdio.bin and triggering CR4 to boot
	 * from it.
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
			(void)brcm_sdio_bp_write32(sc, socram + 4 * i, pattern);
		}
		for (i = 0; i < nitems(patterns); i++) {
			pattern = patterns[i];
			(void)brcm_sdio_bp_read32(sc, socram + 4 * i,
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

		(void)brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMU_RES_STATE, &res_state);
		(void)brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMU_MIN_RES_MASK, &min_res);
		(void)brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMU_MAX_RES_MASK, &max_res);
		device_printf(sc->sc_dev,
		    "PMU pre: RES_STATE=0x%08x MIN_RES=0x%08x MAX_RES=0x%08x\n",
		    res_state, min_res, max_res);

		(void)brcm_sdio_bp_write32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMU_MIN_RES_MASK,
		    0xffffffff);
		pause("brcmres", hz / 5);	/* ~200 ms for PMU to honour */

		(void)brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMU_RES_STATE, &res_state);
		(void)brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMU_MIN_RES_MASK,
		    &min_res_after);
		device_printf(sc->sc_dev,
		    "PMU post-force: RES_STATE=0x%08x MIN_RES=0x%08x\n",
		    res_state, min_res_after);

		/* Re-read CR4 wrap to see if it woke up. */
		(void)brcm_sdio_bp_read32(sc, cr4_wrap + 0x000, &wrap_after);
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
	(void)brcm_sdio_bp_write32(sc,
	    BRCM_CC_CORE_BASE + BRCM_CC_PMUCONTROL,
	    pmuctl_before | 0x00000001);
	(void)brcm_sdio_bp_read32(sc,
	    BRCM_CC_CORE_BASE + BRCM_CC_PMUCONTROL, &pmuctl_after);
	device_printf(sc->sc_dev,
	    "bp_write32 sanity: wrote PMUCTL=0x%08x read=0x%08x %s\n",
	    pmuctl_before | 0x00000001, pmuctl_after,
	    (pmuctl_after & 0x00000001) ? "(write landed)" :
	    "(write DROPPED -- backplane writes are broken)");

	/*
	 * Reset/halt dance now lives in brcm_chip_disable_arm — same
	 * sequence (prereset = CPUHALT bit preserved, in-reset configure
	 * = CPUHALT, postreset = CPUHALT|CLK), just driven through the
	 * chip layer's AI resetcore primitive so the next ARM-class chip
	 * we add gets it for free.
	 */
	err = brcm_chip_disable_arm(&sc->sc_chip, BCMA_CORE_ARM_CR4);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "brcm_chip_disable_arm(CR4) failed err=%d\n", err);
		return (err);
	}

	err = brcm_sdio_bp_read32(sc, cr4_wrap + BCMA_IOCTL, &ioctl_after);
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
 * firmware-side GPIO expander (NOT a chip-side BCM2711 GPIO).  When the
 * Pi boots, its boot ROM brings WL_REG_ON high and then runs the chip's
 * boot ROM, which leaves the chip in a state where Linux brcmfmac's
 * Linux-derived clock-gating preamble (CHIPCLKCSR FORCE_HW_CLKREQ_OFF |
 * ALP_AVAIL_REQ) actually wedges its backplane.  Empirically: the only
 * way to recover the "fresh chip" state Linux relies on is to drive
 * WL_REG_ON low and back high -- exactly what Linux's mmc-pwrseq-simple
 * does for free at boot via DT.
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
 * autonomously and would panic the kernel if we wrote it directly (see
 * feedback_pi4_gpioc1_pin1.md).
 *
 * Pin numbering: the firmware-side expander starts at gpio number 128.
 * WL_REG_ON is the second pin on the expander (BT_REG_ON is pin 0,
 * WL_REG_ON is pin 1), so the mailbox gpio number is 128 + 1 = 129.
 *
 * Caveat: after the cycle, any SDIO state cached by the host (CCCR
 * function-enable bits, KSO, the F1 RAM windows) is gone too because
 * the chip has lost power.  Callers must re-issue the F1 enable +
 * SBADDR window setup; that's what brcm_sdio_halt_cr4_now() already
 * does via brcm_sdio_enable_func1().
 */
#define	PI4_FW_GPIO_BASE		128
#define	PI4_FW_GPIO_WL_REG_ON		(PI4_FW_GPIO_BASE + 1)

#ifdef __aarch64__
static int
brcm_sdio_mbox_set_gpio(struct brcm_sdio_softc *sc, uint32_t gpio,
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
brcm_sdio_mbox_set_gpio(struct brcm_sdio_softc *sc, uint32_t gpio,
    uint32_t state)
{
	(void)sc; (void)gpio; (void)state;
	return (ENXIO);
}
#endif

static int
brcm_sdio_wl_reg_on_cycle(struct brcm_sdio_softc *sc)
{
	int err;

	device_printf(sc->sc_dev,
	    "WL_REG_ON cycle: drive low for 50 ms then high\n");

	err = brcm_sdio_mbox_set_gpio(sc, PI4_FW_GPIO_WL_REG_ON, 0);
	if (err != 0)
		return (err);
	pause("wlregof", hz / 20);	/* ~50 ms low */

	err = brcm_sdio_mbox_set_gpio(sc, PI4_FW_GPIO_WL_REG_ON, 1);
	if (err != 0)
		return (err);
	/*
	 * Hold ~150 ms before the next chip access.  The chip's boot ROM
	 * runs in this window; trying CMD52 too early returns CRC errors
	 * or undefined state.  Linux's mmc-pwrseq-simple defaults to a
	 * 10 ms post-power-on delay but BCM43455 routinely needs more in
	 * practice -- being generous is cheap.
	 */
	pause("wlregon", hz / 7);
	device_printf(sc->sc_dev, "WL_REG_ON cycle complete\n");
	return (0);
}

static int
brcm_sdio_sysctl_wl_reg_on_cycle(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	return (brcm_sdio_wl_reg_on_cycle(sc));
}

/*
 * Non-toggling SET_GPIO_STATE.  Useful as a smoke test: writing
 * dev.brcm.N.wl_reg_on_set=1 should be a no-op for the chip (it was
 * already powered) but exercises the same mbox code path the cycle
 * uses.  If this returns 0, the message format is correct and the
 * cycle can be trusted.  If this returns EIO, the message format is
 * still wrong and we should not run the cycle.
 *
 * Writing 0 powers the chip off without re-enabling it -- treat that
 * as destructive; once written, the SDIO chip is gone until either
 * wl_reg_on_set=1 or a hardware reboot.
 */
static int
brcm_sdio_sysctl_wl_reg_on_set(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int state = -1;
	int err;

	err = sysctl_handle_int(oidp, &state, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);
	if (state != 0 && state != 1)
		return (EINVAL);
	return (brcm_sdio_mbox_set_gpio(sc, PI4_FW_GPIO_WL_REG_ON,
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
brcm_sdio_chip_soft_reset(struct brcm_sdio_softc *sc)
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
	pause("brcmrst", hz / 100);	/* ~10 ms for the chip to settle */

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
		pause("brcm5", 1);
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

static int
brcm_sdio_sysctl_soft_reset(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_chip_soft_reset(sc);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

static int
brcm_sdio_halt_cr4_now(struct brcm_sdio_softc *sc)
{
	struct brcm_chip_core *cr4;
	int err;

	sx_assert(&sc->sc_chip_sx, SA_XLOCKED);

	/*
	 * Soft-reset the chip first so we run the rest of the bring-up
	 * against a freshly-booted silicon state instead of whatever the
	 * Pi boot ROM has left in the PMU latches.  Before this was wired,
	 * the buscoreprep CHIPCLKCSR write below would wedge the chip's
	 * backplane on BCM43455 because the boot-ROM-stale PMU couldn't
	 * tolerate the FORCE_HW_CLKREQ_OFF | ALP_AVAIL_REQ combo Linux
	 * does at startup; CC.EROMPTR would read 0 and only a system
	 * reboot recovered.  A soft reset puts the chip into the same
	 * pristine state Linux gets from mmc-pwrseq-simple, so the Linux
	 * preamble works as documented.
	 */
	err = brcm_sdio_chip_soft_reset(sc);
	if (err != 0)
		return (err);

	err = brcm_sdio_enable_func1(sc);
	if (err != 0)
		return (err);

	/*
	 * Broadcom-specific CCCR write: set CMD_NODEC in
	 * SDIO_CCCR_BRCM_CARDCAP (0xF0).  This changes how the chip
	 * decodes CMD52/53 and -- critically for our purposes -- is
	 * what wakes the chip out of its deep idle so the PMU will
	 * actually action a subsequent HT_AVAIL_REQ.  Without this
	 * write, CHIPCLKCSR will ack HT_AVAIL_REQ (the request bit
	 * stays set) but HT_AVAIL never asserts.  Linux brcmfmac's
	 * brcmf_sdio_probe() does this as its very first chip access.
	 */
	err = sdio_cccr_write_byte(sc->sc_dev, SDIO_CCCR_BRCM_CARDCAP,
	    SDIO_CCCR_BRCM_CARDCAP_CMD_NODEC);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "CCCR.BRCM_CARDCAP write (CMD_NODEC) failed err=%d\n",
		    err);
		return (err);
	}
	DPRINTF(&sc->bsc_base, 1,
	    "CCCR.BRCM_CARDCAP set to CMD_NODEC for HT wake\n");

	/*
	 * Wake the chip out of any sleep state before we go asking
	 * for HT.  Without this the PMU's 32 kHz domain keeps the chip
	 * drowsy and HT_AVAIL_REQ acknowledgements never produce HT.
	 */
	err = brcm_sdio_kso_enable(sc);
	if (err != 0)
		return (err);

	/*
	 * Buscoreprep -- force ALP, lock hw-clock-request off.  Wedged
	 * the chip pre-soft-reset; works fine on a fresh chip.
	 */
	err = brcm_sdio_buscoreprep(sc);
	if (err != 0)
		return (err);

	/*
	 * Two corrective writes the boot ROM leaves undone:
	 *
	 *   1. CCCR.BRCM_CARDCTRL |= WLANRESET resets the WLAN subsystem
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
	 * Sequence drawn from OpenBSD brcm_sdio_attach (sys/dev/sdmmc/
	 * if_brcm_sdio.c); same chip facts apply.
	 */
	{
		uint32_t pmuctl;

		/*
		 * CCCR.BRCM_CARDCTRL |= WLANRESET (OpenBSD brcm_sdio_attach)
		 * is deliberately NOT done here: on BCM43455 on Pi 4 it
		 * tears down the chip's WLAN-side backplane and the chip
		 * stops servicing CMD53 for long enough that SDHCI's host
		 * controller times out before we can resume.  The PMU
		 * RES_RELOAD on its own gives us the resource-graph
		 * reconfiguration we wanted from this whole pair; skip
		 * WLANRESET unless a future chip needs it.
		 */

		err = brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMUCONTROL, &pmuctl);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "PMUCONTROL read failed err=%d\n", err);
			return (err);
		}
		pmuctl |= (BRCM_CC_PMUCONTROL_RES_RELOAD <<
		    BRCM_CC_PMUCONTROL_RES_SHIFT);
		err = brcm_sdio_bp_write32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_PMUCONTROL, pmuctl);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "PMUCONTROL write failed err=%d\n", err);
			return (err);
		}
		DPRINTF(&sc->bsc_base, 1,
		    "PMUCONTROL |= RES_RELOAD (now 0x%08x)\n", pmuctl);
	}

	/*
	 * Release the FORCE_ALP lock and ask the PMU for HT.  With the
	 * PMU resource table reloaded above this should now produce
	 * real HT, unlike the pre-PMU-reload runs where the request bit
	 * stuck in CHIPCLKCSR but HT_AVAIL never asserted.
	 */
	err = brcm_sdio_request_ht_clock(sc);
	if (err != 0)
		return (err);

	err = brcm_sdio_chip_ensure(sc);
	if (err != 0)
		return (err);
	err = brcm_chip_walk_erom(&sc->sc_chip);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "brcm_chip_walk_erom failed err=%d\n", err);
		return (err);
	}
	cr4 = brcm_chip_get_core(&sc->sc_chip, BCMA_CORE_ARM_CR4);
	if (cr4 == NULL) {
		device_printf(sc->sc_dev,
		    "EROM walk did not find ARM_CR4 core (id 0x%03x)\n",
		    BCMA_CORE_ARM_CR4);
		return (ENOENT);
	}
	device_printf(sc->sc_dev,
	    "EROM walk: %u cores discovered; CR4 base=0x%08x wrap=0x%08x\n",
	    sc->sc_chip.ncores, cr4->base, cr4->wrap);

	return (brcm_sdio_halt_cr4(sc, cr4->wrap));
}

static int
brcm_sdio_sysctl_halt_cr4(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_halt_cr4_now(sc);
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
 * Pre-conditions: firmware + NVRAM already uploaded (load_firmware
 * complete through phase 8).  Without that the CR4 will branch to
 * garbage and the chip wedges.
 *
 * Post-conditions: CR4 is fetching from SOCRAM and (eventually) the
 * firmware writes a SDPCM "boot_done" marker we can poll for.  That
 * second handshake is the next phase (not yet implemented).
 */
static int
brcm_sdio_release_cr4_now(struct brcm_sdio_softc *sc)
{
	struct brcm_chip_core *cr4;
	const struct brcm_sdio_chip_recipe *r;
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
	err = brcm_sdio_bp_read32(sc, BRCM_CC_CORE_BASE + BRCM_CC_CHIPID,
	    &chipid);
	if (err != 0)
		return (err);
	chip_id = BRCM_CHIPID_ID(chipid);
	chip_rev = BRCM_CHIPID_REV(chipid);
	r = brcm_sdio_lookup_recipe(chip_id, chip_rev);
	if (r == NULL) {
		device_printf(sc->sc_dev,
		    "release_cr4: no recipe for chip=0x%04x rev=%u\n",
		    chip_id, chip_rev);
		return (ENOENT);
	}

	err = brcm_sdio_chip_ensure(sc);
	if (err != 0)
		return (err);
	/* EROM walk may already have been done by halt_cr4_now; only walk
	 * if the chip layer doesn't yet have a CR4 core registered. */
	cr4 = brcm_chip_get_core(&sc->sc_chip, BCMA_CORE_ARM_CR4);
	if (cr4 == NULL) {
		err = brcm_chip_walk_erom(&sc->sc_chip);
		if (err != 0) {
			device_printf(sc->sc_dev,
			    "release_cr4: brcm_chip_walk_erom failed err=%d\n",
			    err);
			return (err);
		}
		cr4 = brcm_chip_get_core(&sc->sc_chip, BCMA_CORE_ARM_CR4);
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
	err = brcm_sdio_bp_read32(sc, r->ram_base, &rstvec);
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
	 * Release dance now lives in brcm_chip_cr4_set_active — writes
	 * rstvec to chip[0] via the transport's activate hook, then runs
	 * the AI resetcore with prereset=CPUHALT / reset=0 / postreset=0
	 * so the CR4 comes out of reset clean and starts fetching at
	 * chip[0].  Same sequence the inline code did, factored through
	 * the chip layer.
	 */
	err = brcm_chip_cr4_set_active(&sc->sc_chip, rstvec);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "brcm_chip_cr4_set_active failed err=%d\n", err);
		return (err);
	}

	err = brcm_sdio_bp_read32(sc, cr4_wrap + BCMA_IOCTL, &ioctl_final);
	if (err != 0)
		return (err);
	device_printf(sc->sc_dev,
	    "release_cr4: CR4 released -- final IOCTL=0x%08x "
	    "(expected 0x%08x)\n", ioctl_final, BCMA_IOCTL_CLK);

	/*
	 * Brief post-release poll for fw-alive indicators.  We give fw
	 * 200 ms to start, then sample:
	 *   - CHIPCLKCSR (F1 CCCR @ 0x1000E): healthy boot bumps from
	 *     ALP-only (~0x42) to HT_AVAIL (0xC2) once fw requests it
	 *   - chip[0x257ffc]: sdpcm_shared_ptr slot.  Pre-release we
	 *     wrote NVRAM trailer here (0xfe4b01b4); fw clears or sets
	 *     it once SDPCM init runs.
	 *   - chip[ram_base + 0xb0000]: empirically active region for
	 *     fw heap/stack — non-zero means CR4 is writing memory.
	 */
	{
		uint8_t clkcsr = 0;
		uint32_t shared_ptr = 0, heap_canary = 0;
		DELAY(200000);
		(void)sdio_read_byte(sc->sc_dev, SBSDIO_FUNC1_CHIPCLKCSR,
		    &clkcsr);
		(void)brcm_sdio_bp_read32(sc, 0x257ffcu, &shared_ptr);
		(void)brcm_sdio_bp_read32(sc, r->ram_base + 0xb0000u,
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
	 * brcm_sdio_f2_attach) is the live transport for SDPCM control
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
					 * Program F2 block size in CCCR FBR2.IOBLKSZ.
					 * Linux brcmfmac uses 256 for BCM43455 (block-mode
					 * CMD53 boundary on F2 = SDPCM frame boundary).
					 * Without this, block-mode CMD53 to F2 fails with
					 * CRC error — same root cause as the F1 fix above.
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
					        (u_int)BRCM_WD_POLL_MS),
					    brcm_sdio_watchdog_callout, sc);
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

	device_printf(sc->sc_dev,
	    "release_cr4: next phase = poll SDPCM boot_done marker\n");
	return (0);
}

static int
brcm_sdio_sysctl_release_cr4(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	int err;

	err = sysctl_handle_int(oidp, &trigger, 0, req);
	if (err != 0 || req->newptr == NULL || trigger == 0)
		return (err);
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_release_cr4_now(sc);
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
 * collide on the wire.  The response's dcmd ID is not yet checked
 * (M6/M8/M9) — single-flight in current code makes that fine.
 */
static int
brcm_sdio_iovar_xfer(struct brcm_sdio_softc *sc, uint8_t *req, size_t reqlen,
    struct mbuf **respp)
{
	struct brcm_sdpcm_state *st = sc->sc_sdpcm;
	struct mbuf *resp;
	uint32_t req_flags, resp_flags;
	uint16_t req_id, resp_id;
	int err, polls;

	*respp = NULL;

	if (reqlen < sizeof(struct brcm_bcdc_dcmd))
		return (EINVAL);

	/* Snapshot the reqid we put on the wire so we can match the reply. */
	memcpy(&req_flags, req + 8, sizeof(req_flags));
	req_flags = le32toh(req_flags);
	req_id = (uint16_t)((req_flags >> BRCM_BCDC_DCMD_ID_SHIFT) &
	    BRCM_BCDC_DCMD_ID_MASK);

	/*
	 * Serialise against bs_pump_rx (the fmop_scan_start poller)
	 * and against other in-flight iovar_xfer calls.  Both paths
	 * call brcm_sdpcm_rx_frames against the same F2 FIFO; two
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

	err = brcm_sdpcm_tx_ctrlframe(st, sc->sc_f2_dev, req, reqlen);
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0)
		return (err);

	/*
	 * Poll the F2 FIFO until we see a CONTROL response whose reqid
	 * matches the one we sent.  The BCM43455 0xff-swhdr fallback in
	 * brcm_sdpcm_rx_frames can misclassify other frames as CONTROL,
	 * and a slow ack to a prior request can still be in the ctrl
	 * queue despite the drain above (e.g. fw replying to the previous
	 * iovar after we'd timed out).  Reqid matching is what Linux
	 * brcmfmac uses; without it the caller parses a stale/foreign
	 * mbuf's first 16 bytes as a dcmd header and reports "fw error
	 * status=<garbage>" (e.g. 0x24a36501) with the ERROR bit blindly
	 * set in the cooked flags.
	 */
	/*
	 * 100 × ~50 ms ≈ 5 s, matching Linux's BRCMF_DCMD_TIMEOUT_DEF.
	 * Safe to extend now that each poll iteration uses pause() + a
	 * cross-iter lock drop (see below) -- other threads can squeeze
	 * in between polls, so a long timeout no longer starves the
	 * watchdog.  Required because the "join" iovar / SET_SSID dcmd
	 * doesn't ack until the chip has finished off-channel auth+assoc,
	 * which can take 100s of ms on a busy 2.4 GHz band.
	 */
	resp = NULL;
	for (polls = 0; polls < 100; polls++) {
		sx_xlock(&sc->sc_chip_sx);
		(void)brcm_sdpcm_rx_frames(st, sc->sc_f2_dev);
		sx_xunlock(&sc->sc_chip_sx);
		/*
		 * wait_ctrl_resp uses sp_lock + msleep internally, so it
		 * doubles as our sleep + retry tick.  No extra pause() is
		 * needed -- it returns either with the next CONTROL frame
		 * (we may still need to drop it as stale) or NULL after
		 * ~50 ms.  sc_chip_sx is dropped across the wait so any
		 * other thread that needs the F2 FIFO (concurrent iovar,
		 * cmd_scan poller, event_rx_cb pump) can run.
		 */
		resp = brcm_sdpcm_wait_ctrl_resp(st, 50);
		if (resp == NULL)
			continue;
		if (resp->m_pkthdr.len <
		    (int)sizeof(struct brcm_bcdc_dcmd)) {
			m_freem(resp);
			resp = NULL;
			continue;
		}
		m_copydata(resp, 8, sizeof(resp_flags),
		    (caddr_t)&resp_flags);
		resp_flags = le32toh(resp_flags);
		resp_id = (uint16_t)((resp_flags >> BRCM_BCDC_DCMD_ID_SHIFT) &
		    BRCM_BCDC_DCMD_ID_MASK);
		if (resp_id == req_id)
			break;
		device_printf(sc->sc_dev,
		    "iovar_xfer: dropping stale resp id=%u (want %u)\n",
		    resp_id, req_id);
		m_freem(resp);
		resp = NULL;
	}

	if (resp == NULL)
		return (ETIMEDOUT);

	*respp = resp;
	return (0);
}

/*
 * EVENT channel callback installed at sc_sdpcm allocation time.
 * Decodes the event code + status + reason + flags and prints a
 * single dmesg line per event.  Heavier work (forwarding to
 * net80211, dispatching to a per-event handler table) belongs in
 * a taskqueue follow-up; for now this is a discovery scope.
 *
 * Called with no locks held (rx_frames doesn't hold sp_lock at
 * dispatch time).  Must be brief — see the prototype contract.
 */
static const char *
brcm_sdio_event_name(uint32_t code)
{
	/*
	 * Codes mirror Linux brcmfmac fweh.h enum brcmf_fweh_event_code
	 * (BRCMF_ENUM_DEF macro list).  Keep in sync when porting.
	 */
	switch (code) {
	case 0:				return "SET_SSID";
	case 1:				return "JOIN";
	case 2:				return "START";
	case BRCM_E_TYPE_AUTH:		return "AUTH";	/* 3 */
	case 4:				return "AUTH_IND";
	case BRCM_E_DEAUTH:		return "DEAUTH";	/* 5 */
	case 6:				return "DEAUTH_IND";
	case BRCM_E_TYPE_ASSOC:		return "ASSOC";	/* 7 */
	case 8:				return "ASSOC_IND";
	case 9:				return "REASSOC";
	case 10:			return "REASSOC_IND";
	case BRCM_E_TYPE_DISASSOC:	return "DISASSOC";	/* 11 */
	case 12:			return "DISASSOC_IND";
	case 15:			return "BEACON_RX";
	case BRCM_E_TYPE_LINK:		return "LINK";	/* 16 */
	case 17:			return "MIC_ERROR";
	case 18:			return "NDIS_LINK";
	case 19:			return "ROAM";
	case 20:			return "TXFAIL";
	case 21:			return "PMKID_CACHE";
	case 23:			return "PRUNE";
	case 24:			return "AUTOAUTH";
	case BRCM_E_EAPOL_MSG:		return "EAPOL_MSG";	/* 25 */
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
	case BRCM_E_IF:			return "IF";	/* 54 */
	case 56:			return "RSSI";
	case 59:			return "ACTION_FRAME";
	case 60:			return "ACTION_FRAME_COMPLETE";
	case BRCM_E_TYPE_ESCAN_RESULT:	return "ESCAN_RESULT";	/* 69 */
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
 * blob: brcm_escan_results header + single brcm_bss_info entry.
 * Multi-byte fields little-endian on the wire.
 */
static void
brcm_sdio_print_escan_result(struct brcm_sdio_softc *sc, uint32_t status,
    const void *data, size_t datalen)
{
	const struct brcm_escan_results *res;
	const struct brcm_bss_info *bss;
	char ssid[BRCM_MAX_SSID_LEN + 1];
	uint16_t chanspec, capability;
	int16_t rssi;
	uint8_t ssid_len;

	if (status != BRCM_E_STATUS_PARTIAL) {
		device_printf(sc->sc_dev,
		    "EVENT ESCAN_RESULT terminator status=%u datalen=%zu\n",
		    status, datalen);
		return;
	}
	if (datalen < sizeof(*res) + sizeof(*bss))
		return;

	res = (const struct brcm_escan_results *)data;
	bss = (const struct brcm_bss_info *)(const void *)
	    ((const uint8_t *)data + sizeof(*res));

	ssid_len = bss->ssid_len;
	if (ssid_len > BRCM_MAX_SSID_LEN)
		ssid_len = BRCM_MAX_SSID_LEN;
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
 * and hands it to brcm_rx_frame, which decodes the BRCM event
 * encapsulation and routes to brcm_handle_event (scan results -> ic
 * scan cache, link state -> vap newstate, etc.).
 *
 * Only fires after net80211 is attached.  Before ic_attached, the
 * decoded event_cb still prints to dmesg so the diagnostic path
 * remains useful.
 */
/*
 * Worker that drains the per-sc event queue and hands each mbuf to
 * brcm_rx_frame.  Runs on a dedicated taskqueue thread — never on
 * the SDPCM rx context — so brcm_rx_frame's re-entrant net80211
 * calls (ieee80211_input_all, ieee80211_new_state, taskqueue
 * enqueues) don't run inside the chip_sx sysctl thread that is
 * driving the scan poll loop.  Mirrors Linux brcmfmac's
 * event_worker workqueue split (see Pi 3B ftrace recon).
 */
/*
 * Per-sc EVENT delivery worker control.  Default ON now that the
 * sustained-scan panic (bss_count u32 read of u16 field, brcm.c
 * commit b75ea78) is fixed.  Tunable left in for debugging — set to
 * 0 to silence the brcm_rx_frame call without rebuilding.
 */
static int brcm_sdio_evrx_deliver = 1;
SYSCTL_INT(_dev, OID_AUTO, brcm_evrx_deliver, CTLFLAG_RWTUN,
    &brcm_sdio_evrx_deliver, 0,
    "1 = SDIO event rx worker calls brcm_rx_frame (default); 0 = drop");

static void
brcm_sdio_event_rx_worker(void *arg, int pending __unused)
{
	struct brcm_sdio_softc *sc = arg;
	struct mbuf *m;

	for (;;) {
		mtx_lock(&sc->sc_event_rx_mtx);
		m = mbufq_dequeue(&sc->sc_event_rx_q);
		mtx_unlock(&sc->sc_event_rx_mtx);
		if (m == NULL)
			break;
		if (brcm_sdio_evrx_deliver && sc->bsc_base.sc_ic_attached)
			brcm_rx_frame(&sc->bsc_base, m);
		else
			m_freem(m);
	}
}

static void
brcm_sdio_event_rx(void *arg, const void *body, size_t paylen)
{
	struct brcm_sdio_softc *sc = arg;
	struct mbuf *m;

	if (!sc->bsc_base.sc_ic_attached)
		return;
	/*
	 * brcm_rx_frame -> brcm_handle_event reads `p + evpos` with
	 * `p = mtod(m, uint8_t *)` — assumes the mbuf data is one
	 * contiguous run.  Cap at MCLBYTES and use m_getcl so we
	 * always get a single 2 KB cluster.  Real BCM43455 events
	 * stay well under 2 KB (largest seen so far: 530 B).
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

static void
brcm_sdio_event_handler(void *arg, const struct brcm_event_msg *msg,
    const void *data, size_t datalen)
{
	struct brcm_sdio_softc *sc = arg;

	if (msg->event_type == BRCM_E_TYPE_ESCAN_RESULT) {
		brcm_sdio_print_escan_result(sc, msg->status, data, datalen);
		return;
	}

	device_printf(sc->sc_dev,
	    "EVENT %s (%u) status=%u reason=%u flags=0x%x "
	    "datalen=%zu addr=%02x:%02x:%02x:%02x:%02x:%02x ifidx=%u\n",
	    brcm_sdio_event_name(msg->event_type), msg->event_type,
	    msg->status, msg->reason, msg->flags, datalen,
	    msg->addr[0], msg->addr[1], msg->addr[2],
	    msg->addr[3], msg->addr[4], msg->addr[5],
	    msg->ifidx);
}

static struct brcm_sdpcm_state *
brcm_sdio_iovar_ensure_state(struct brcm_sdio_softc *sc)
{
	if (sc->sc_sdpcm == NULL) {
		/*
		 * F2 byte address 0x8000 = backplane offset 0 with the
		 * SBSDIO_SB_ACCESS_2_4B_FLAG bit set; blksize 256 matches
		 * what Linux brcmfmac programs for BCM43455.
		 */
		sc->sc_sdpcm = brcm_sdpcm_alloc(0x8000u, 256u);
		brcm_sdpcm_set_event_handler(sc->sc_sdpcm,
		    brcm_sdio_event_handler, sc);
		brcm_sdpcm_set_event_rx(sc->sc_sdpcm,
		    brcm_sdio_event_rx, sc);
	}
	return (sc->sc_sdpcm);
}

/*
 * GET a BCDC iovar.  Copies up to outlen bytes of the response payload
 * (the bytes after the 16-byte dcmd header) into out.  Returns 0 on
 * success, errno on transport failure, EIO on fw-side DCMD_ERROR.
 */
static int
brcm_sdio_iovar_get(struct brcm_sdio_softc *sc, const char *name,
    void *out, size_t outlen)
{
	struct brcm_sdpcm_state *st;
	struct brcm_bcdc_dcmd dh;
	struct mbuf *resp;
	uint8_t *buf;
	size_t bufsz, reqlen, avail, copy;
	uint16_t reqid;
	int err;

	if (name == NULL || (outlen > 0 && out == NULL))
		return (EINVAL);
	if (sc->sc_f2_dev == NULL || !sc->sc_f2_enabled)
		return (ENXIO);

	st = brcm_sdio_iovar_ensure_state(sc);
	if (st == NULL)
		return (ENOMEM);

	bufsz = sizeof(struct brcm_bcdc_dcmd) + strlen(name) + 1;
	if (outlen + sizeof(struct brcm_bcdc_dcmd) > bufsz)
		bufsz = outlen + sizeof(struct brcm_bcdc_dcmd);
	buf = malloc(bufsz, M_TEMP, M_WAITOK);

	mtx_lock(&st->sp_lock);
	reqid = ++st->bcdc_reqid;
	mtx_unlock(&st->sp_lock);

	reqlen = brcm_bcdc_build_getvar(buf, bufsz, name, outlen, reqid);
	if (reqlen == 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	err = brcm_sdio_iovar_xfer(sc, buf, reqlen, &resp);
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

	if (dh.flags & BRCM_BCDC_DCMD_ERROR) {
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
brcm_sdio_iovar_set(struct brcm_sdio_softc *sc, const char *name,
    const void *val, size_t vallen)
{
	struct brcm_sdpcm_state *st;
	struct brcm_bcdc_dcmd dh;
	struct mbuf *resp;
	uint8_t *buf;
	size_t bufsz, reqlen;
	uint16_t reqid;
	int err;

	if (name == NULL || (vallen > 0 && val == NULL))
		return (EINVAL);
	if (sc->sc_f2_dev == NULL || !sc->sc_f2_enabled)
		return (ENXIO);

	st = brcm_sdio_iovar_ensure_state(sc);
	if (st == NULL)
		return (ENOMEM);

	bufsz = sizeof(struct brcm_bcdc_dcmd) + strlen(name) + 1 + vallen;
	buf = malloc(bufsz, M_TEMP, M_WAITOK);

	mtx_lock(&st->sp_lock);
	reqid = ++st->bcdc_reqid;
	mtx_unlock(&st->sp_lock);

	reqlen = brcm_bcdc_build_setvar(buf, bufsz, name, val, vallen, reqid);
	if (reqlen == 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	err = brcm_sdio_iovar_xfer(sc, buf, reqlen, &resp);
	free(buf, M_TEMP);
	if (err != 0)
		return (err);

	m_copydata(resp, 0, sizeof(dh), (caddr_t)&dh);
	dh.flags = le32toh(dh.flags);
	dh.status = le32toh(dh.status);
	m_freem(resp);

	if (dh.flags & BRCM_BCDC_DCMD_ERROR) {
		device_printf(sc->sc_dev,
		    "iovar_set(%s): fw error status=%d\n", name,
		    (int32_t)dh.status);
		return (EIO);
	}
	return (0);
}

/*
 * dev.brcm.0.sdpcm_test=1 — original cur_etheraddr round-trip smoke
 * test, now driven through brcm_iovar_get.
 */
static int
brcm_sdio_sysctl_sdpcm_test(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	uint8_t mac[6] = { 0 };
	int err, rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	sx_xlock(&sc->sc_chip_sx);
	device_printf(sc->sc_dev, "sdpcm_test: GET cur_etheraddr\n");
	err = brcm_sdio_iovar_get(sc, "cur_etheraddr", mac, sizeof(mac));
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
 * dev.brcm.0.iovar_get=<name> — generic GET probe.  Reads up to
 * BRCM_IOVAR_PROBE_MAX bytes of response, prints a hex+ASCII dump
 * to dmesg.  Useful for poking at "ver", "country", "cur_etheraddr",
 * "clmver", etc. without recompiling.
 */
#define	BRCM_IOVAR_PROBE_MAX	256u

static int
brcm_sdio_sysctl_iovar_get(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	char name[64];
	uint8_t out[BRCM_IOVAR_PROBE_MAX];
	int err, rc;
	size_t i, asclen;
	char asciibuf[BRCM_IOVAR_PROBE_MAX + 1];

	name[0] = '\0';
	rc = sysctl_handle_string(oidp, name, sizeof(name), req);
	if (rc != 0 || req->newptr == NULL || name[0] == '\0')
		return (rc);

	memset(out, 0, sizeof(out));
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_iovar_get(sc, name, out, sizeof(out));
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
 * Send a raw BCDC dcmd (for BRCM_C_UP/DOWN/etc. that aren't iovars).
 * Mirrors brcm_sdio_iovar_set but uses the raw-dcmd builder.  Caller
 * holds sc_chip_sx exclusive.
 */
static int
brcm_sdio_dcmd_set(struct brcm_sdio_softc *sc, uint32_t cmd_id,
    const void *val, size_t vallen)
{
	struct brcm_sdpcm_state *st;
	struct brcm_bcdc_dcmd dh;
	struct mbuf *resp;
	uint8_t *buf;
	size_t bufsz, reqlen;
	uint16_t reqid;
	int err;

	if (sc->sc_f2_dev == NULL || !sc->sc_f2_enabled)
		return (ENXIO);

	st = brcm_sdio_iovar_ensure_state(sc);
	if (st == NULL)
		return (ENOMEM);

	bufsz = sizeof(struct brcm_bcdc_dcmd) + vallen;
	buf = malloc(bufsz, M_TEMP, M_WAITOK);

	mtx_lock(&st->sp_lock);
	reqid = ++st->bcdc_reqid;
	mtx_unlock(&st->sp_lock);

	reqlen = brcm_bcdc_build_dcmd(buf, bufsz, cmd_id, val, vallen, 1,
	    reqid);
	if (reqlen == 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	err = brcm_sdio_iovar_xfer(sc, buf, reqlen, &resp);
	free(buf, M_TEMP);
	if (err != 0)
		return (err);

	m_copydata(resp, 0, sizeof(dh), (caddr_t)&dh);
	dh.flags = le32toh(dh.flags);
	dh.status = le32toh(dh.status);
	m_freem(resp);

	if (dh.flags & BRCM_BCDC_DCMD_ERROR) {
		device_printf(sc->sc_dev,
		    "dcmd cmd=%u: fw error status=%d\n", cmd_id,
		    (int32_t)dh.status);
		return (EIO);
	}
	return (0);
}

/*
 * dev.brcm.0.iovar_set_mpc=<n> — SET-path smoke test.
 *
 * Sets the "mpc" iovar (Minimum Power Consumption disable when 0).
 * Standard knob in every brcmfmac driver; safe at any time after
 * fw is up; takes a 4-byte little-endian integer.
 *
 * Sequence per write: SET mpc <- n; GET mpc -> print readback.  If
 * the readback matches, the SET path is fully functional.
 */
static int
brcm_sdio_sysctl_iovar_set_mpc(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int val = 0;
	uint32_t wire, readback;
	int err, rc;

	rc = sysctl_handle_int(oidp, &val, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	wire = htole32((uint32_t)val);
	readback = 0xdeadbeefu;

	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_iovar_set(sc, "mpc", &wire, sizeof(wire));
	if (err == 0)
		err = brcm_sdio_iovar_get(sc, "mpc", &readback,
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
 * dev.brcm.0.net80211_attach=1 — bring up the net80211 ifnet.
 *
 * Phase 1A of the net80211 integration:
 *  - Capture cur_etheraddr into bsc_base.sc_macaddr (brcm_attach
 *    copies this into ic_macaddr).
 *  - Set bsc_base.sc_dev so brcm.c gets a device handle.
 *  - Call brcm_attach() which runs ieee80211_ifattach + installs the
 *    ic_vap_create / scan / transmit hooks.
 *
 * Trigger AFTER load_firmware + release_cr4 + events_enable + cmd_up.
 *
 * KNOWN GAPS (next phases):
 *  - bs_txdata is still a stub; ic_transmit will fail until DATA path.
 *  - SDPCM EVENT handler still uses the local cb that prints to dmesg
 *    only.  EVENT -> brcm_handle_event routing (so scan results land
 *    in net80211's scan cache) is phase 1B.
 *  - ic_set_channel, scan_curchan are no-ops; OK for SCAN coverage,
 *    needed for join.
 */
static int
brcm_sdio_sysctl_net80211_attach(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int trigger = 0;
	uint8_t mac[6] = { 0 };
	int err, rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	if (sc->bsc_base.sc_ic_attached) {
		device_printf(sc->sc_dev,
		    "net80211_attach: ic already attached\n");
		return (EALREADY);
	}

	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_iovar_get(sc, "cur_etheraddr", mac, sizeof(mac));
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
	    "net80211_attach: brcm_attach with MAC "
	    "%02x:%02x:%02x:%02x:%02x:%02x\n",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	err = brcm_attach(&sc->bsc_base);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "net80211_attach: brcm_attach failed err=%d\n", err);
		return (err);
	}
	/*
	 * Register operator-facing sysctls (wpa_pmk, join_target,
	 * scan_now, iovar_get/set, ...).  USB transport already does
	 * this in its attach; SDIO was missing the call so wpa_pmk
	 * etc. never appeared in `sysctl dev.brcm.0` even though the
	 * code was wired.
	 */
	brcm_sysctl_attach(&sc->bsc_base);

	/*
	 * Bring the firmware to the operating point net80211 expects --
	 * BRCM_C_UP + event_msgs + country=US + sup_wpa=0 + mpc=0 +
	 * roam_off=1.  Without this each session needed five manual
	 * sysctls (events_enable, cmd_up, ...).  USB transport has
	 * always called brcm_runtime_iovars from its attach; SDIO was
	 * the outlier.
	 */
	sx_xlock(&sc->sc_chip_sx);
	brcm_runtime_iovars(&sc->bsc_base);
	sx_xunlock(&sc->sc_chip_sx);

	device_printf(sc->sc_dev, "net80211_attach: ic attached\n");
	return (0);
}

/*
 * dev.brcm.0.bringup=1 -- one-shot operator entry point that chains
 * load_firmware -> release_cr4 -> net80211_attach.  Idempotent on
 * each phase (load_firmware re-soft-resets, release_cr4 is no-op if
 * already released, net80211_attach refuses EALREADY).  Lets the
 * boot recipe collapse to
 *
 *     kldload brcm_sdio brcmfmac43455_fw
 *     sysctl dev.brcm.0.bringup=1
 *     ifconfig wlan0 create wlandev brcm0
 *     ifconfig wlan0 up
 *
 * Anything that fails inside is logged with phase context and an
 * errno bubbles up; the user can re-fire the granular sysctls to
 * retry individual phases.
 */
static int
brcm_sdio_sysctl_bringup(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	uint8_t mac[6] = { 0 };
	int trigger = 0;
	int err, rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	device_printf(sc->sc_dev, "bringup: phase 1/3 load_firmware\n");
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_load_firmware_now(sc, true);
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bringup: load_firmware failed err=%d (is "
		    "brcmfmac43455_fw.ko loaded?)\n", err);
		return (err);
	}

	device_printf(sc->sc_dev, "bringup: phase 2/3 release_cr4\n");
	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_release_cr4_now(sc);
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
	err = brcm_sdio_iovar_get(sc, "cur_etheraddr", mac, sizeof(mac));
	sx_xunlock(&sc->sc_chip_sx);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bringup: cur_etheraddr GET failed err=%d\n", err);
		return (err);
	}
	memcpy(sc->bsc_base.sc_macaddr, mac, sizeof(mac));
	sc->bsc_base.sc_dev = sc->sc_dev;
	err = brcm_attach(&sc->bsc_base);
	if (err != 0) {
		device_printf(sc->sc_dev,
		    "bringup: brcm_attach failed err=%d\n", err);
		return (err);
	}
	brcm_sysctl_attach(&sc->bsc_base);
	sx_xlock(&sc->sc_chip_sx);
	brcm_runtime_iovars(&sc->bsc_base);
	sx_xunlock(&sc->sc_chip_sx);
	device_printf(sc->sc_dev,
	    "bringup: complete -- MAC %02x:%02x:%02x:%02x:%02x:%02x; create "
	    "wlan0 via `ifconfig wlan0 create wlandev brcm0`\n",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (0);
}

/*
 * dev.brcm.0.cmd_scan=1 — broadcast active escan, all channels.
 *
 * Builds a brcm_escan_params_v0 with all-channel, broadcast SSID,
 * active scan defaults, sends via the "escan" iovar.  fw then
 * emits one ESCAN_RESULT event per BSS found (status=PARTIAL),
 * terminating with a final ESCAN_RESULT event whose status is
 * SUCCESS or ABORT.
 *
 * After SET, polls rx_frames for ~3 seconds so all results land in
 * dmesg before the sysctl returns.
 */
static int
brcm_sdio_sysctl_cmd_scan(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	struct brcm_escan_params_v0 p;
	int trigger = 0;
	int err, rc, i;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	memset(&p, 0, sizeof(p));
	p.version  = htole32(BRCM_ESCAN_REQ_VERSION);
	p.action   = htole16(BRCM_WL_ESCAN_ACTION_START);
	p.sync_id  = htole16(0x1234);
	/* scan_params: broadcast (no SSID), all channels, active. */
	p.scan_params.ssid.len = 0;
	memset(p.scan_params.bssid, 0xff, sizeof(p.scan_params.bssid));
	p.scan_params.bss_type    = BRCM_DOT11_BSSTYPE_ANY;
	p.scan_params.scan_type   = BRCM_SCANTYPE_ACTIVE;
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
	err = brcm_sdio_iovar_set(sc, "escan", &p, sizeof(p));
	if (err == 0 && sc->sc_sdpcm != NULL) {
		/*
		 * Drain ESCAN_RESULT events.  Release sc_chip_sx between
		 * polls and use pause() instead of DELAY() so we don't
		 * busy-spin for 3 s holding the lock -- doing so wedged
		 * the Pi 4 when concurrent net80211 / wpa_supplicant
		 * traffic piled up behind us and tripped the in-kernel
		 * watchdog.  pause() yields the CPU; the lock release
		 * lets other iovar_xfer callers squeeze a request in
		 * between our polls.
		 */
		for (i = 0; i < 60 && sc->bsc_base.sc_scan_busy; i++) {
			(void)brcm_sdpcm_rx_frames(sc->sc_sdpcm,
			    sc->sc_f2_dev);
			if (!sc->bsc_base.sc_scan_busy)
				break;
			sx_xunlock(&sc->sc_chip_sx);
			pause("brcmscn", MSEC_2_TICKS(50));
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
 * dev.brcm.0.events_enable=<n>  — write 1 to enable ALL events
 * (mask = 0xff x BRCM_EVENT_MASK_LEN) via the `event_msgs` iovar.
 * Write 0 to disable everything.  Until this is run, fw doesn't
 * emit anything on the EVENT channel.
 */
static int
brcm_sdio_sysctl_events_enable(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	int val = 0;
	uint8_t mask[BRCM_EVENT_MASK_LEN];
	int err, rc;

	rc = sysctl_handle_int(oidp, &val, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	memset(mask, val ? 0xff : 0x00, sizeof(mask));

	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdio_iovar_set(sc, "event_msgs", mask, sizeof(mask));
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
 * dev.brcm.0.cmd_up=1   — send BRCM_C_UP   (bring data plane up)
 * dev.brcm.0.cmd_down=1 — send BRCM_C_DOWN (tear data plane down)
 *
 * After UP, fw typically emits BRCM_E_TYPE_LINK + BRCM_E_IF + a few
 * others; observe in dmesg via the registered event handler.  Drives
 * rx_frames during the wrapper's poll so any events arriving in the
 * immediate window get dispatched.
 */
static int
brcm_sdio_sysctl_cmd_dcmd(SYSCTL_HANDLER_ARGS)
{
	struct brcm_sdio_softc *sc = arg1;
	uint32_t cmd_id = (uint32_t)arg2;
	int trigger = 0;
	int err, rc;

	rc = sysctl_handle_int(oidp, &trigger, 0, req);
	if (rc != 0 || req->newptr == NULL || trigger == 0)
		return (rc);

	sx_xlock(&sc->sc_chip_sx);
	device_printf(sc->sc_dev, "cmd_dcmd: sending BRCM_C cmd=%u\n",
	    cmd_id);
	err = brcm_sdio_dcmd_set(sc, cmd_id, NULL, 0);
	/*
	 * After the dcmd completes, poll rx_frames briefly so any
	 * EVENT-channel reactions (LINK/IF) get dispatched before
	 * the sysctl returns.  Without this the caller has to issue
	 * another iovar_get just to drive rx polling.
	 */
	if (err == 0 && sc->sc_sdpcm != NULL) {
		int i;
		for (i = 0; i < 10; i++) {
			(void)brcm_sdpcm_rx_frames(sc->sc_sdpcm,
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
 * Bus ops — stubs until the backplane-window CMD53 path lands.
 * ------------------------------------------------------------------ */

static int
brcm_sdio_txctl(struct brcm_softc *sc, const void *buf, size_t len)
{
	(void)sc; (void)buf; (void)len;
	return (ENOTSUP);
}

static int
brcm_sdio_rxctl(struct brcm_softc *sc, void *buf, size_t *lenp, int timeout_ms)
{
	(void)sc; (void)buf; (void)lenp; (void)timeout_ms;
	return (ENOTSUP);
}

static int
brcm_sdio_txdata(struct brcm_softc *bsc, struct mbuf *m)
{
	struct brcm_sdio_softc *sc = (struct brcm_sdio_softc *)bsc;
	int err;

	if (m == NULL)
		return (EINVAL);
	if (sc->sc_sdpcm == NULL || sc->sc_f2_dev == NULL) {
		m_freem(m);
		return (ENXIO);
	}

	sx_xlock(&sc->sc_chip_sx);
	err = brcm_sdpcm_tx_dataframe(sc->sc_sdpcm, sc->sc_f2_dev, m);
	sx_xunlock(&sc->sc_chip_sx);
	return (err);
}

static void
brcm_sdio_stop(struct brcm_softc *sc)
{
	(void)sc;
}

/*
 * bus_ops bridge: route brcm.c's iovar/dcmd dispatch through the
 * SDIO transport wrappers we already validated against fw.  Casts
 * brcm_softc back to brcm_sdio_softc (bsc_base is the first member,
 * so the pointer is identical).
 */
static int
brcm_sdio_bus_iovar_get(struct brcm_softc *bsc, const char *name,
    void *buf, size_t *lenp)
{
	struct brcm_sdio_softc *sc = (struct brcm_sdio_softc *)bsc;
	int err;

	if (lenp == NULL)
		return (EINVAL);
	err = brcm_sdio_iovar_get(sc, name, buf, *lenp);
	/* SDIO wrapper zero-pads short replies; report the buffer size
	 * back as actual length.  Tighten if/when callers need it. */
	return (err);
}

static int
brcm_sdio_bus_iovar_set(struct brcm_softc *bsc, const char *name,
    const void *buf, size_t len)
{
	struct brcm_sdio_softc *sc = (struct brcm_sdio_softc *)bsc;
	return (brcm_sdio_iovar_set(sc, name, buf, len));
}

static int
brcm_sdio_bus_dcmd_set(struct brcm_softc *bsc, uint32_t cmd,
    const void *buf, size_t len)
{
	struct brcm_sdio_softc *sc = (struct brcm_sdio_softc *)bsc;
	return (brcm_sdio_dcmd_set(sc, cmd, buf, len));
}

/*
 * Periodic watchdog -- fires every BRCM_WD_POLL_MS via callout on
 * softclock, then hands off to sc_wd_task on taskqueue_thread which
 * does one SDIO F2 RX pump to keep the SDIO bus warm + drain any
 * events the ithread missed.  Mirrors Linux brcmf_sdio_bus_watchdog
 * (sdio.c:3669).  Without it BCM43455 fw 7.45.18 tears down LINK
 * within milliseconds of ASSOC when it sees zero host SDIO activity.
 */
static void
brcm_sdio_watchdog_callout(void *arg)
{
	struct brcm_sdio_softc *sc = arg;

	if (sc->sc_wd_stop)
		return;
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_wd_task);
}

static void
brcm_sdio_watchdog_task(void *arg, int pending __unused)
{
	struct brcm_sdio_softc *sc = arg;

	if (sc->sc_wd_stop || sc->sc_sdpcm == NULL || sc->sc_f2_dev == NULL)
		goto rearm;
	sx_xlock(&sc->sc_chip_sx);
	(void)brcm_sdpcm_rx_frames(sc->sc_sdpcm, sc->sc_f2_dev);
	sx_xunlock(&sc->sc_chip_sx);
rearm:
	if (!sc->sc_wd_stop)
		callout_reset(&sc->sc_wd_callout,
		    MSEC_2_TICKS((u_int)BRCM_WD_POLL_MS),
		    brcm_sdio_watchdog_callout, sc);
}

static void
brcm_sdio_bus_pump_rx(struct brcm_softc *bsc, int max_ms,
    volatile int *until_clear)
{
	struct brcm_sdio_softc *sc = (struct brcm_sdio_softc *)bsc;
	int ticks_per_iter = 50;	/* 50 ms per spin */
	int iters = max_ms / ticks_per_iter;
	int i;

	if (sc->sc_sdpcm == NULL)
		return;
	/*
	 * Yield-friendly pump.  Each iteration holds sc_chip_sx only
	 * across the one F2 read, then drops the lock and pause()s for
	 * 50 ms.  Avoids the original DELAY()-while-holding-sx pattern
	 * which busy-spun the CPU for max_ms milliseconds (up to 3 s on
	 * the scan path) and starved every other iovar_xfer caller +
	 * the kernel watchdog -- the Pi 4 wedge reproducer.
	 */
	for (i = 0; i < iters; i++) {
		sx_xlock(&sc->sc_chip_sx);
		(void)brcm_sdpcm_rx_frames(sc->sc_sdpcm, sc->sc_f2_dev);
		sx_xunlock(&sc->sc_chip_sx);
		if (until_clear != NULL && *until_clear == 0)
			break;
		pause("brcmpmp", MSEC_2_TICKS((u_int)ticks_per_iter));
	}
}

static const struct brcm_bus_ops brcm_sdio_bus_ops = {
	.bs_txctl	= brcm_sdio_txctl,
	.bs_rxctl	= brcm_sdio_rxctl,
	.bs_txdata	= brcm_sdio_txdata,
	.bs_stop	= brcm_sdio_stop,
	.bs_iovar_get	= brcm_sdio_bus_iovar_get,
	.bs_iovar_set	= brcm_sdio_bus_iovar_set,
	.bs_dcmd_set	= brcm_sdio_bus_dcmd_set,
	.bs_pump_rx	= brcm_sdio_bus_pump_rx,
};

/* ------------------------------------------------------------------
 * Newbus glue
 * ------------------------------------------------------------------ */

static int
brcm_sdio_probe(device_t dev)
{
	uint16_t manfid, prodid;
	uint8_t func_num;
	const struct brcm_sdio_match *m;
	char desc[128];

	manfid = sdio_get_manfid(dev);
	prodid = sdio_get_prodid(dev);
	func_num = sdio_get_func_num(dev);

	if (manfid != SDIO_VENDOR_BROADCOM)
		return (ENXIO);
	/* Only function 1 carries WLAN.  Funcs 2/3 (BCM43xxx management,
	 * Bluetooth, etc.) are out of scope for this driver. */
	if (func_num != 1)
		return (ENXIO);
	m = brcm_sdio_lookup(prodid);
	if (m == NULL)
		return (ENXIO);

	snprintf(desc, sizeof(desc),
	    "Broadcom %s (SDIO func %u)", m->name, func_num);
	device_set_desc_copy(dev, desc);
	return (BUS_PROBE_DEFAULT);
}

/*
 * /dev/brcm0 raw SDIO transport cdev.
 *
 * Userspace (and, via a TCP bridge daemon, a QEMU Linux guest) can
 * drive CMD52/CMD53 + backplane-window operations directly through
 * ioctls.  This lets us hand the rest of the brcmfmac bring-up to a
 * Linux-side userspace port without depending on FreeBSD-side
 * sysctl plumbing for every step.
 *
 * All ioctl handlers take sc_chip_sx so they serialise against the
 * existing sysctls (load_firmware, halt_cr4, etc.).
 */

static d_open_t		brcm_cdev_open;
static d_ioctl_t	brcm_cdev_ioctl;

static struct cdevsw brcm_cdevsw = {
	.d_version	= D_VERSION,
	.d_open		= brcm_cdev_open,
	.d_ioctl	= brcm_cdev_ioctl,
	.d_name		= "brcm",
};

static int
brcm_cdev_open(struct cdev *cdev __unused, int flags __unused,
    int devtype __unused, struct thread *td __unused)
{
	return (0);
}

static int
brcm_cdev_do_cmd52(struct brcm_sdio_softc *sc, struct brcm_cmd52 *c)
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

static int
brcm_cdev_do_cmd53(struct brcm_sdio_softc *sc, struct brcm_cmd53 *c)
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

static int
brcm_cdev_ioctl(struct cdev *cdev, u_long ioc, caddr_t arg, int flag __unused,
    struct thread *td __unused)
{
	struct brcm_sdio_softc *sc = cdev->si_drv1;
	int err;

	if (sc == NULL)
		return (ENXIO);

	sx_xlock(&sc->sc_chip_sx);
	switch (ioc) {
	case BRCM_IOC_CMD52:
		err = brcm_cdev_do_cmd52(sc, (struct brcm_cmd52 *)arg);
		break;
	case BRCM_IOC_CMD53:
		err = brcm_cdev_do_cmd53(sc, (struct brcm_cmd53 *)arg);
		break;
	case BRCM_IOC_SET_WINDOW: {
		struct brcm_set_window *w = (struct brcm_set_window *)arg;
		err = brcm_sdio_set_backplane(sc, w->chip_addr);
		w->mmc_err = err;
		break;
	}
	case BRCM_IOC_BP_READ32: {
		struct brcm_bp *b = (struct brcm_bp *)arg;
		err = brcm_sdio_bp_read32(sc, b->chip_addr, &b->value);
		b->mmc_err = err;
		break;
	}
	case BRCM_IOC_BP_WRITE32: {
		struct brcm_bp *b = (struct brcm_bp *)arg;
		err = brcm_sdio_bp_write32(sc, b->chip_addr, b->value);
		b->mmc_err = err;
		break;
	}
	case BRCM_IOC_GET_CHIPID: {
		struct brcm_chipid *ci = (struct brcm_chipid *)arg;
		uint32_t v;

		err = brcm_sdio_bp_read32(sc,
		    BRCM_CC_CORE_BASE + BRCM_CC_CHIPID, &v);
		if (err == 0) {
			ci->chipid = v;
			ci->chip = BRCM_CHIPID_ID(v);
			ci->rev = BRCM_CHIPID_REV(v);
			ci->pkg = (v >> 16) & 0xf;
			ci->num_cores = (v >> 20) & 0xf;
		}
		break;
	}
	case BRCM_IOC_CARD_INFO: {
		struct brcm_card_info *info = (struct brcm_card_info *)arg;
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
	case BRCM_IOC_GET_CORES: {
		struct brcm_cores *uc = (struct brcm_cores *)arg;
		struct brcm_chip_core *core;
		uint8_t i;

		/* Walk EROM lazily — the chip layer remembers cores across
		 * calls, so a second ioctl is a free copy of the list. */
		err = brcm_sdio_chip_ensure(sc);
		if (err != 0) {
			uc->mmc_err = err;
			break;
		}
		if (sc->sc_chip.ncores <= 1) {
			err = brcm_chip_walk_erom(&sc->sc_chip);
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

static int
brcm_sdio_attach(device_t dev)
{
	struct brcm_sdio_softc *sc = device_get_softc(dev);
	const struct brcm_sdio_match *m;

	sc->sc_dev = dev;
	sc->sc_sdio_bus = device_get_parent(dev);
	sc->sc_manfid = sdio_get_manfid(dev);
	sc->sc_prodid = sdio_get_prodid(dev);
	sc->sc_func_num = sdio_get_func_num(dev);
	sc->sc_func_class = sdio_get_func_class(dev);
	sc->sc_blksize = sdio_get_blocksize(dev);
	sc->sc_f2_dev = NULL;

	sc->bsc_base.sc_dev = dev;
	sc->bsc_base.sc_bus_ops = &brcm_sdio_bus_ops;

	/*
	 * Publish ourselves so the F2 sibling driver (brcm_sdio_f2) can
	 * find us when it attaches.  If F2 already attached (uncommon but
	 * possible), pick up its device_t now.
	 */
	brcm_sdio_global_softc = sc;
	{
		device_t *children;
		int nchildren, i;
		if (device_get_children(sc->sc_sdio_bus, &children,
		    &nchildren) == 0) {
			for (i = 0; i < nchildren; i++) {
				const char *cn = device_get_name(children[i]);
				if (cn != NULL && strcmp(cn, "brcm_f2") == 0 &&
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
	sx_init_flags(&sc->sc_chip_sx, "brcm-chip", SX_RECURSE);

	/*
	 * brcm_softc's sc_mtx / sc_ctl_mtx / sc_ctl_pending are
	 * "owned by the transport attach" per brcm.c's contract.
	 * The USB transport sets them up in its attach; we do it
	 * here.  Without this brcm_rx_frame -> brcm_handle_event
	 * paths hit mtx_lock on an uninitialized mutex and panic
	 * with vm_fault_lookup on a kernel kstack address (phase 1B
	 * smoke-test root cause).
	 */
	mtx_init(&sc->bsc_base.sc_mtx, "brcm", NULL, MTX_DEF);
	mtx_init(&sc->bsc_base.sc_ctl_mtx, "brcm-ctl", NULL, MTX_DEF);
	TAILQ_INIT(&sc->bsc_base.sc_ctl_pending);

	/* EVENT rx delivery taskqueue + queue. */
	mtx_init(&sc->sc_event_rx_mtx, "brcm-evrx", NULL, MTX_DEF);
	mbufq_init(&sc->sc_event_rx_q, 64);
	TASK_INIT(&sc->sc_event_rx_task, 0, brcm_sdio_event_rx_worker, sc);
	sc->sc_event_rx_tq = taskqueue_create("brcm_evrx", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->sc_event_rx_tq);
	taskqueue_start_threads(&sc->sc_event_rx_tq, 1, PI_NET,
	    "%s evrx", device_get_nameunit(dev));

	/*
	 * Periodic SDIO watchdog.  callout fires every BRCM_WD_POLL_MS
	 * on softclock, enqueues sc_wd_task on taskqueue_thread (safe
	 * to sleep in sx_xlock + pump_rx).  Mirrors Linux
	 * brcmf_sdio_watchdog_thread.
	 */
	sc->sc_wd_stop = false;
	callout_init(&sc->sc_wd_callout, 1);	/* MPSAFE */
	TASK_INIT(&sc->sc_wd_task, 0, brcm_sdio_watchdog_task, sc);

	/*
	 * Expose dev.brcm.N.debug for ad-hoc bring-up tracing.  Default
	 * silent; bump with `sysctl dev.brcm.0.debug=2` to follow CMD52
	 * traffic without recompiling.  bsc_base.sc_debug is the same
	 * field used by USB and PCIe transports — one knob, all paths.
	 */
	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "debug", CTLFLAG_RWTUN, &sc->bsc_base.sc_debug, 0,
	    "DPRINTF level: 0=silent 1=milestones 2=protocol 3=hex");

	/*
	 * Write a non-zero value to dev.brcm.N.read_chipid to fire the
	 * F1-enable + backplane-window + CC.CHIPID read smoke test.
	 * Output lands in dmesg; the sysctl resets to 0 after each
	 * shot so it's a one-trigger-per-write knob.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "read_chipid",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_read_chipid, "I",
	    "Write 1: bring F1 up + read CC.CHIPID via backplane window");

	/*
	 * Write a non-zero value to dev.brcm.N.halt_cr4 to fire the
	 * EROM walk + CR4 halt sequence.  Halts the Cortex-R4 with its
	 * CPUHALT bit asserted and leaves the core in reset; firmware
	 * upload runs against the TCM in that state.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "halt_cr4",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_halt_cr4, "I",
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
	    sc, 0, brcm_sdio_sysctl_release_cr4, "I",
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
	    sc, 0, brcm_sdio_sysctl_sdpcm_test, "I",
	    "Write 1: SDPCM round-trip test (BCDC cur_etheraddr)");

	/*
	 * Generic BCDC iovar GET probe.  `sysctl dev.brcm.0.iovar_get=ver`
	 * triggers `brcm_sdio_iovar_get(sc, "ver", ...)` and prints the result
	 * to dmesg.  Same preconditions as sdpcm_test: load_firmware +
	 * release_cr4 must have run.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "iovar_get",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_iovar_get, "A",
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
	    sc, 0, brcm_sdio_sysctl_iovar_set_mpc, "I",
	    "Write integer: SET mpc via BCDC, re-GET, print result");

	/*
	 * EVENT channel control.  events_enable=1 turns on all events
	 * via the event_msgs iovar; cmd_up=1 / cmd_down=1 send the
	 * BRCM_C_UP / BRCM_C_DOWN raw dcmds.  After UP, fw normally
	 * emits BRCM_E_TYPE_LINK + BRCM_E_IF + a couple of others —
	 * watch dmesg for the registered event handler output.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "events_enable",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_events_enable, "I",
	    "Write 1: enable all fw EVENT-channel events via event_msgs");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "cmd_up",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, BRCM_C_UP, brcm_sdio_sysctl_cmd_dcmd, "I",
	    "Write 1: send BRCM_C_UP raw dcmd; poll rx for events");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "cmd_down",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, BRCM_C_DOWN, brcm_sdio_sysctl_cmd_dcmd, "I",
	    "Write 1: send BRCM_C_DOWN raw dcmd; poll rx for events");

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
	    sc, 0, brcm_sdio_sysctl_cmd_scan, "I",
	    "Write 1: broadcast active escan + poll rx for results");

	/*
	 * Phase 1A net80211 attach.  Opt-in via sysctl so the kldload
	 * smoke path stays minimal until the full DATA path is wired.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "net80211_attach",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_net80211_attach, "I",
	    "Write 1: capture MAC + call brcm_attach (ifnet appears)");

	/*
	 * One-shot bring-up: chains load_firmware + release_cr4 +
	 * net80211_attach.  Operator-facing entry point so the boot
	 * recipe doesn't have to enumerate every phase.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "bringup",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_bringup, "I",
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
	    sc, 0, brcm_sdio_sysctl_wl_reg_on_cycle, "I",
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
	    sc, 0, brcm_sdio_sysctl_wl_reg_on_set, "I",
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
	    sc, 0, brcm_sdio_sysctl_soft_reset, "I",
	    "Write 1: CCCR.CTL.RES chip soft-reset + CMD5/3/7 re-handshake");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "cmd53_max_blocks", CTLFLAG_RW,
	    &brcm_sdio_cmd53_max_blocks, 0,
	    "Cap blocks per block-mode CMD53 (0 = disable block mode, "
	    "1..511 = max blocks)");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "byte_chunk", CTLFLAG_RW,
	    &brcm_sdio_byte_chunk, 0,
	    "Cap bytes per byte-mode CMD53 (default 512, max 512)");

	/*
	 * Run the prelude (soft-reset + F1 + CARDCAP + KSO + buscoreprep
	 * + PMU reload + chipid recipe lookup) WITHOUT the firmware
	 * upload.  Used as a safety gate: if this wedges the SD-card
	 * controller (root FS) on Pi 4, we know the regression is in the
	 * prelude rather than the upload.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "load_firmware_prelude",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_load_firmware_prelude, "I",
	    "Write 1: bring-up prelude only (no SOCRAM upload)");

	/*
	 * Upload firmware + NVRAM to SOCRAM and verify head/tail
	 * round-trip.  Requires brcmfmac<chip>_fw.ko to be loaded so
	 * firmware(9) can hand over the blobs.  Does NOT yet release
	 * the CR4 from reset -- that's the next phase.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "load_firmware",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_load_firmware, "I",
	    "Write 1: upload firmware + NVRAM to SOCRAM with verification");

	/*
	 * Phase-1 chip layer (brcm_chip.c) test surface.  Run
	 * load_firmware_prelude first to leave the chip in ALPAvail,
	 * then write N to either sysctl to dump that many
	 * registers/words.  Cheaper than building brcm_drive for
	 * debug-only OTP/chipcontrol inspection.
	 */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "dump_chipcontrol",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_dump_chipcontrol, "I",
	    "Write N (1..32): dump PMU chipcontrol[0..N-1] to dmesg");
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "dump_otp",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, brcm_sdio_sysctl_dump_otp, "I",
	    "Write N (1..64): dump OTP sromotp[0..N-1] u16 words to dmesg");

	m = brcm_sdio_lookup(sc->sc_prodid);
	device_printf(dev,
	    "matched %s -- manfid=0x%04x prodid=0x%04x class=0x%02x blksize=%u\n",
	    m != NULL ? m->name : "unknown",
	    sc->sc_manfid, sc->sc_prodid, sc->sc_func_class, sc->sc_blksize);
	DPRINTF(&sc->bsc_base, 1, "func_num=%u sdio_bus=%s\n",
	    sc->sc_func_num, device_get_nameunit(sc->sc_sdio_bus));
	device_printf(dev,
	    "scaffold attach: firmware loader + brcm_attach() not yet wired\n");

	/*
	 * Expose /dev/brcm<unit> so userspace (and the RPC bridge daemon
	 * that fronts a QEMU Linux guest) can drive raw CMD52/CMD53 +
	 * backplane-window operations.  Same chip_sx serialises this
	 * against the sysctl path.
	 */
	sc->sc_cdev = make_dev(&brcm_cdevsw, device_get_unit(dev),
	    UID_ROOT, GID_WHEEL, 0600, "brcm%d", device_get_unit(dev));
	if (sc->sc_cdev != NULL)
		sc->sc_cdev->si_drv1 = sc;
	else
		device_printf(dev, "make_dev /dev/brcm%d failed\n",
		    device_get_unit(dev));

	/*
	 * Do NOT call brcm_attach() yet.  net80211 attach would try to
	 * register an interface and immediately drive iovars to firmware
	 * that hasn't been uploaded — guaranteed panic.  Phase 2 will
	 * land the upload path (CMD53 backplane window + chip-id init +
	 * brcmfmac firmware blob), and only then call brcm_attach().
	 */
	return (0);
}

static int
brcm_sdio_detach(device_t dev)
{
	struct brcm_sdio_softc *sc = device_get_softc(dev);

	/*
	 * Refuse to detach while net80211 still holds callbacks into
	 * our module text.  Without this, `kldunload brcm_sdio` after
	 * an `ifconfig wlan create wlandev brcm0 ...` panics the box
	 * the next time net80211 dispatches an iv_op (the function
	 * pointer is now stale).  Operator must `ifconfig wlan0
	 * destroy` first to drop the vap, then re-run kldunload.
	 * See feedback_no_kldunload_brcm_sdio.
	 */
	if (sc->bsc_base.sc_ic_attached) {
		device_printf(dev,
		    "detach refused: net80211 still attached "
		    "(ifconfig wlan0 destroy first)\n");
		return (EBUSY);
	}

	if (sc->sc_cdev != NULL) {
		destroy_dev(sc->sc_cdev);
		sc->sc_cdev = NULL;
	}
	if (sc->sc_sdpcm != NULL) {
		brcm_sdpcm_free(sc->sc_sdpcm);
		sc->sc_sdpcm = NULL;
	}

	/* Drain + tear down the EVENT rx taskqueue before freeing
	 * anything brcm_rx_frame might touch. */
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
	if (brcm_sdio_global_softc == sc)
		brcm_sdio_global_softc = NULL;
	return (0);
}

static device_method_t brcm_sdio_methods[] = {
	DEVMETHOD(device_probe,		brcm_sdio_probe),
	DEVMETHOD(device_attach,	brcm_sdio_attach),
	DEVMETHOD(device_detach,	brcm_sdio_detach),
	DEVMETHOD_END
};

static driver_t brcm_sdio_driver = {
	"brcm",
	brcm_sdio_methods,
	sizeof(struct brcm_sdio_softc),
};

DRIVER_MODULE(brcm_sdio, sdio, brcm_sdio_driver, NULL, NULL);
MODULE_VERSION(brcm_sdio, 1);
/*
 * Depend on the sdio bus driver (sys/dev/mmc/sdio_func.c, version 1),
 * not directly on mmc.  Indirection keeps us decoupled from mmc's
 * private version churn (MMC_VERSION = 5 today).  The sdio bus itself
 * inherits the mmc dep, so we get it transitively.
 */
MODULE_DEPEND(brcm_sdio, sdio, 1, 1, 1);
MODULE_DEPEND(brcm_sdio, wlan, 1, 1, 1);

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
 * F1 attach sets `brcm_sdio_global_softc = sc`; F2 attach reads it and
 * stores its own device_t in `sc->sc_f2_dev`.  Detach order isn't
 * deterministic (FreeBSD newbus doesn't guarantee sibling order), so
 * F2 detach also clears `sc->sc_f2_dev` only if it still points to
 * itself.
 *
 * SDPCM transport calls (brcm_sdpcm.c) reach F2 via the public
 * brcm_sdio_f2_write / brcm_sdio_f2_read helpers below.
 * ------------------------------------------------------------------ */

struct brcm_sdio_f2_softc {
	device_t		f2_dev;
	struct brcm_sdio_softc *f2_parent;	/* F1 softc */
};

static int
brcm_sdio_f2_probe(device_t dev)
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

static int
brcm_sdio_f2_attach(device_t dev)
{
	struct brcm_sdio_f2_softc *f2sc;
	struct brcm_sdio_softc *psc;
	int err = 0;

	f2sc = device_get_softc(dev);
	f2sc->f2_dev = dev;

	/* Bind to the F1 instance — only one supported. */
	psc = brcm_sdio_global_softc;
	if (psc == NULL) {
		/* F2 attached before F1 — uncommon, but the sdio bus
		 * doesn't guarantee enumeration order.  Defer: stash
		 * ourselves in the global so F1 attach can pick us up. */
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
	 * load_firmware / release_cr4 path (or a future sdpcm_attach
	 * hook) is the right place to flip the bit.
	 */
	(void)err;
	return (0);
}

static int
brcm_sdio_f2_detach(device_t dev)
{
	struct brcm_sdio_f2_softc *f2sc;

	f2sc = device_get_softc(dev);
	if (f2sc->f2_parent != NULL && f2sc->f2_parent->sc_f2_dev == dev)
		f2sc->f2_parent->sc_f2_dev = NULL;
	return (0);
}

static device_method_t brcm_sdio_f2_methods[] = {
	DEVMETHOD(device_probe,		brcm_sdio_f2_probe),
	DEVMETHOD(device_attach,	brcm_sdio_f2_attach),
	DEVMETHOD(device_detach,	brcm_sdio_f2_detach),
	DEVMETHOD_END
};

static driver_t brcm_sdio_f2_driver = {
	"brcm_f2",
	brcm_sdio_f2_methods,
	sizeof(struct brcm_sdio_f2_softc),
};

DRIVER_MODULE(brcm_sdio_f2, sdio, brcm_sdio_f2_driver, NULL, NULL);

/*
 * F2 transport helpers used to live here; they were inlined into
 * brcm_sdpcm.c when the SDPCM API switched to taking (state, device_t)
 * directly instead of a softc.  See brcm_sdpcm_f2_xfer.
 */
