/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC PCIe transport glue for brcm.
 *
 * Matches the BCM43602 and the other BCM43xx PCIe parts by ID, maps
 * BAR0 (the register window) and BAR2 (chip RAM), walks the backplane
 * cores, downloads the firmware into chip RAM and releases the ARM,
 * then hands the shared-memory handshake and the MSGBUF rings to
 * brcm_pci_msgbuf.c.  The bring-up runs from attach in a kernel thread
 * (hw.brcm_pci.autostart).  Only the BCM43602 has the full bring-up;
 * the other IDs attach for probing only.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/kdb.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/firmware.h>

#include <machine/bus.h>
#if defined(__amd64__) || defined(__i386__)
#include <machine/cpufunc.h>	/* inb / outb */
#endif
#include <machine/resource.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_input.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>

#include "brcmvar.h"
#include "brcmreg.h"
#include "brcm_pci_msgbuf.h"
#include "ieee80211_fullmac.h"

#define	BRCM_PCI_DESC	"Broadcom FullMAC PCIe"

/* Forward declarations for sysctls defined at end-of-file. */
static int brcm_pci_sysctl_net80211_attach(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_net80211_detach(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_msgbuf_attach(SYSCTL_HANDLER_ARGS);
static void brcm_pci_preinit_dcmds(struct brcm_pci_softc *sc);
static int brcm_pci_sysctl_dump_console(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_wlc_up(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_delete_flowring(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_wlc_down(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_mac_addr(SYSCTL_HANDLER_ARGS);

/*
 * Loader tunables for attach-time behaviour.  Any attach-time chip
 * operation that could wedge the host belongs behind a tunable, so a
 * plain reboot (or "set" at the loader prompt) gets the machine back.
 */
static int brcm_pci_attach_appu_warm_dflt = 1;
SYSCTL_NODE(_hw, OID_AUTO, brcm_pci, CTLFLAG_RD, 0, "brcm_pci driver tunables");
SYSCTL_INT(_hw_brcm_pci, OID_AUTO, attach_appu_warm, CTLFLAG_RDTUN,
    &brcm_pci_attach_appu_warm_dflt, 0,
    "Run APPU warm sequence at attach.  Default 1 (safe, proven).  "
    "Set to 0 in loader.conf to disable if it ever regresses.");

/*
 * Bring the chip all the way up after attach: firmware, msgbuf, WLC_UP and
 * net80211, so the device shows up in net.wlan.devices like any other wifi
 * card and userland only has to create wlan0.  0 leaves it to the
 * bringup/msgbuf_attach/wlc_up/net80211_attach sysctls.  If it goes wrong
 * at boot, "set hw.brcm_pci.autostart=0" at the loader prompt.
 */
static int brcm_pci_autostart_dflt = 1;
SYSCTL_INT(_hw_brcm_pci, OID_AUTO, autostart, CTLFLAG_RDTUN,
    &brcm_pci_autostart_dflt, 0,
    "Bring the chip up (firmware, msgbuf, net80211) after attach.  "
    "0 leaves it to the bring-up sysctls.");
/*
 * There is deliberately no tunable that forces bring-up from attach
 * itself: a wedge there combined with a persistent loader.conf setting
 * would make every boot wedge.  Manual bring-up goes through the runtime
 * sysctl dev.brcm_pci.N.bringup=1, which does not survive a reboot.
 */

/* Vendor IDs. */
#define	BRCM_PCI_VENDOR_BROADCOM	0x14e4

/*
 * Device IDs.  Names map to the chip family; some IDs are shared
 * across multiple silicon revisions and only the chipid register
 * disambiguates.
 *
 * Linux brcm_hw_ids.h gives BCM4356 0x43ec and BCM4358 0x43e9, not
 * 0x43a3, and calls 0x4415 BCM43596; both BCM4366 revisions share
 * 0x43c3 (0x43c4/0x43c5 for the 2G/5G parts).  The names below are
 * kept as they are, but the BCM4366C label on 0x4415 does not match.
 */
#define	BRCM_PCI_DEVICE_BCM4350	0x43a3	/* BCM4350 */
#define	BRCM_PCI_DEVICE_BCM4360	0x43a0	/* BCM4360 3x3 */
#define	BRCM_PCI_DEVICE_BCM4360_2	0x43a2	/* BCM4360 2x2 */
#define	BRCM_PCI_DEVICE_BCM43602	0x43ba	/* BCM43602 */
#define	BRCM_PCI_DEVICE_BCM4366C	0x4415	/* Linux: BCM43596 */
#define	BRCM_PCI_DEVICE_BCM4366B	0x43c3	/* BCM4366b */
#define	BRCM_PCI_DEVICE_BCM4365	0x43ca	/* BCM4365 */
#define	BRCM_PCI_DEVICE_BCM4364	0x4464	/* BCM4364 */

struct brcm_pci_devmatch {
	uint16_t	devid;
	const char	*desc;
};

static const struct brcm_pci_devmatch brcm_pci_devs[] = {
	{ BRCM_PCI_DEVICE_BCM4350,   "Broadcom BCM4350 802.11ac"   },
	{ BRCM_PCI_DEVICE_BCM4360,   "Broadcom BCM4360 802.11ac"   },
	{ BRCM_PCI_DEVICE_BCM4360_2, "Broadcom BCM4360 2x2 802.11ac" },
	{ BRCM_PCI_DEVICE_BCM43602,  "Broadcom BCM43602 802.11ac"  },
	{ BRCM_PCI_DEVICE_BCM4366C,  "Broadcom BCM4366c 802.11ac"  },
	{ BRCM_PCI_DEVICE_BCM4366B,  "Broadcom BCM4366b 802.11ac"  },
	{ BRCM_PCI_DEVICE_BCM4365,   "Broadcom BCM4365 802.11ac"   },
	{ BRCM_PCI_DEVICE_BCM4364,   "Broadcom BCM4364 802.11ac"   },
};

/*
 * Per-chip parameters.  Bringup / firmware / memory-topology facts that
 * vary across the Broadcom PCIe family.
 *
 * bringup_supported=true means the full bringup chain in
 * brcm_pci_bringup_sequence() has been implemented + tested for this
 * chip.  false means probe/warmup/diagnostic sysctls work but
 * `bringup=1` will refuse (rather than wedge the host trying to run
 * 43602-specific PMU init on a chip that doesn't have those registers).
 *
 * mem_core = ID of the on-chip memory core to power up in
 * enter_download_state.  43602 has SOCRAM (0x80e).  The 4360-family
 * entries use 0x81a, called BUF_MEM here, but Linux bcma.h names
 * 0x81a BCMA_CORE_USB20_DEV (memory cores there are INTERNAL_MEM
 * 0x80e and SYS_MEM 0x849), so that ID is unverified.
 */
struct brcm_pci_chip_info {
	uint16_t	devid;
	uint32_t	rambase;	/* TCM base for fw upload */
	uint16_t	mem_core;	/* SOCRAM / BUF_MEM ID */
	const char     *fw_name;	/* firmware_get() name */
	bool		bringup_supported;
	const char     *notes;
};

static const struct brcm_pci_chip_info brcm_pci_chip_table[] = {
	/*
	 * BCM43602 - Apple A1398, MacBookPro 11,3 / 11,4 / 11,5 / 12,1.
	 * The fully-tested target.
	 */
	{ .devid		= BRCM_PCI_DEVICE_BCM43602,
	  .rambase		= 0x180000,
	  .mem_core		= 0x80e,	/* BRCM_CORE_SOCRAM */
	  .fw_name		= "brcmfmac43602_pcie",
	  .bringup_supported	= true,
	  .notes		= "43602 - fully supported"
	},

	/*
	 * BCM4360 (14e4:43a0, chip 0x4360, distinct from the BCM43602),
	 * an Apple 3x3 802.11ac part also sold as an M.2 card with Apple
	 * subvendor 106b:0117.  Only the proprietary broadcom-wl driver
	 * supports it, using D11 core ucode directly rather than an ARM-CR4
	 * firmware upload.  Probe, core walk and D-state cycling work.
	 * Bring-up steps 1-9 pass (with the pmu_init_4360 max_res guard
	 * and rambase 0 so the image fits BAR2), but wait_fw_ready times
	 * out: the 43602 firmware cannot run on 4360 silicon.
	 *
	 * The differences from the 43602 are rambase 0 rather than
	 * 0x180000, memory core 0x81a (called BUF_MEM here; bcma.h has
	 * 0x81a as USB20_DEV, so unverified) with no SOCRAM bank power-up
	 * since there is a single memory aperture, and no pmu_init_43602
	 * or pll_init_43602 (43602-specific tables and PLLCTL values).
	 *
	 * bringup_supported stays false so bringup=1 fails cleanly with
	 * EOPNOTSUPP; the entry stays populated so the diagnostics work
	 * and 4360-native firmware only needs the flag flipped.
	 */
	{ .devid		= BRCM_PCI_DEVICE_BCM4360,
	  .rambase		= 0x0,
	  .mem_core		= 0x81a,	/* "BUF_MEM"; see above */
	  .fw_name		= "brcmfmac4360_pcie",
	  .bringup_supported	= false,
	  .notes		= "4360 - probe only (needs 4360-native fw)"
	},
	{ .devid		= BRCM_PCI_DEVICE_BCM4360_2,
	  .rambase		= 0x0,
	  .mem_core		= 0x81a,
	  .fw_name		= "brcmfmac4360_pcie",
	  .bringup_supported	= false,
	  .notes		= "4360 2x2 - probe only (needs 4360-native fw)"
	},

	/*
	 * Everything else is probe only.  These entries stop the
	 * driver attempting to run 43602-specific bringup on the wrong
	 * chip and wedging the host.  Implementing bringup for any of
	 * these just means filling in the correct rambase + fw + memcore
	 * and flipping bringup_supported.
	 */
	{ BRCM_PCI_DEVICE_BCM4350,   0x0, 0x81a, "brcmfmac4350_pcie", false,
	  "4350 - probe only" },
	{ BRCM_PCI_DEVICE_BCM4366C,  0x0, 0x81a, "brcmfmac4366c_pcie", false,
	  "4366c - probe only" },
	{ BRCM_PCI_DEVICE_BCM4366B,  0x0, 0x81a, "brcmfmac4366b_pcie", false,
	  "4366b - probe only" },
	{ BRCM_PCI_DEVICE_BCM4365,   0x0, 0x81a, "brcmfmac4365_pcie", false,
	  "4365 - probe only" },
	{ BRCM_PCI_DEVICE_BCM4364,   0x0, 0x81a, "brcmfmac4364_pcie", false,
	  "4364 - probe only" },
};

/*
 * Lookup the per-chip info table by device ID.  Returns NULL if the
 * device ID isn't in the table (probe already rejected it, so this
 * only happens with a stale sc->sc_devid — treat as fatal).
 */
static const struct brcm_pci_chip_info *
brcm_pci_chip_lookup(uint16_t devid)
{
	int i;
	for (i = 0; i < (int)nitems(brcm_pci_chip_table); i++) {
		if (brcm_pci_chip_table[i].devid == devid)
			return (&brcm_pci_chip_table[i]);
	}
	return (NULL);
}

/*
 * BAR layout.  All shipping BCM4360-family parts expose two memory
 * BARs: a small control / register window and a larger chip-RAM /
 * shared-memory window.  The control window is required for any
 * register access; the RAM window is required for firmware download
 * and MSGBUF ring storage.
 */
#define	BRCM_PCI_BAR0_RID	PCIR_BAR(0)
#define	BRCM_PCI_BAR2_RID	PCIR_BAR(2)

/*
 * BAR0 windowing.  The whole 4 KB BAR0 region is a sliding window onto
 * the chip-side backplane address space.  The window register is PCI
 * config-space offset 0x80 (not a BAR0 offset): write the top 20 bits
 * of the target backplane address there, then read/write at BAR0[low
 * 12 bits] to reach the desired chip register.
 *
 * The PCIe2 core's registers (IRQ mailbox, doorbells) are reached the
 * same way, by pointing the window at the PCIe2 core, as Linux
 * brcmf_pcie_select_core() does.
 */
#define	BRCM_PCI_BAR0_WINDOW		0x80
#define	BRCM_PCI_BAR0_WINDOW_MASK	0xfffff000	/* top 20 bits */
#define	BRCM_PCI_BAR0_WINDOW_OFF_MASK	0x00000fff	/* low 12 bits */

/*
 * PCI config-space registers of the endpoint (Linux pcie.c
 * BRCMF_PCIE_REG_LINK_STATUS_CTRL 0xBC, read with
 * pci_read_config_dword).  Config space is served by the root complex,
 * so these are not subject to the BAR0 window.
 */
#define	BRCM_PCI_PCIE2_LINK_STATUS_CTRL	0xbc
#define	BRCM_PCI_PCIE2_LINK_UP		0x00000001	/* low bit of link
							   status word */

/* Backplane core base addresses (AI-style chips, BCM4360 family). */
#define	BRCM_BACKPLANE_CHIPCOMMON	0x18000000

/* ChipCommon register layout (offsets within the core). */
#define	BRCM_CC_REG_CHIPID		0x00
#define	BRCM_CC_REG_EROMPTR		0xfc
#define	BRCM_CC_CHIPID_ID_MASK		0x0000ffff
#define	BRCM_CC_CHIPID_REV_SHIFT	16
#define	BRCM_CC_CHIPID_REV_MASK		0x000f0000
#define	BRCM_CC_CHIPID_PKG_SHIFT	20
#define	BRCM_CC_CHIPID_PKG_MASK		0x00f00000
#define	BRCM_CC_CHIPID_NCORES_SHIFT	24
#define	BRCM_CC_CHIPID_NCORES_MASK	0x0f000000
#define	BRCM_CC_CHIPID_TYPE_SHIFT	28
#define	BRCM_CC_CHIPID_TYPE_MASK	0xf0000000

/*
 * EROM (Enumeration ROM) descriptor layout for AI-style chips.
 * The EROM is a chip-internal table that enumerates every backplane
 * core: the host walks it (via the SBTOPCI window) to find each
 * core's ID, revision, and register base.  We read the EROM start
 * address from ChipCommon[0xfc].
 *
 * Each descriptor is a 32-bit word; the low 4 bits identify the
 * descriptor type.  COMPONENT descriptors come in pairs (id + rev/
 * port-count); ADDRESS descriptors give a core's base address.  EOT
 * marks end-of-table.
 */
#define	BRCM_EROM_DESC_TYPE_MSK		0x0000000fU
#define	BRCM_EROM_DESC_VALID		0x00000001U
#define	BRCM_EROM_DESC_COMPONENT	0x00000001U
#define	BRCM_EROM_DESC_MASTER_PORT	0x00000003U
#define	BRCM_EROM_DESC_ADDRESS		0x00000005U
#define	BRCM_EROM_DESC_ADDRSIZE_GT32	0x00000008U
#define	BRCM_EROM_DESC_EOT		0x0000000fU
#define	BRCM_EROM_COMP_PARTNUM		0x000fff00U
#define	BRCM_EROM_COMP_PARTNUM_S	8
#define	BRCM_EROM_COMP_REVISION		0xff000000U
#define	BRCM_EROM_COMP_REVISION_S	24
#define	BRCM_EROM_SLAVE_ADDR_BASE	0xfffff000U
#define	BRCM_EROM_SLAVE_SIZE_TYPE	0x00000030U
#define	BRCM_EROM_SLAVE_SIZE_DESC	3
#define	BRCM_EROM_SLAVE_TYPE_MASK	0x000000c0U
#define	BRCM_EROM_SLAVE_TYPE_SHIFT	6
#define	BRCM_EROM_SLAVE_TYPE_SLAVE	0
#define	BRCM_EROM_SLAVE_TYPE_BRIDGE	1
#define	BRCM_EROM_SLAVE_TYPE_SWRAP	2
#define	BRCM_EROM_SLAVE_TYPE_MWRAP	3

/* BCMA core IDs we'll see on BCM43602. */
#define	BRCM_CORE_CHIPCOMMON		0x800
#define	BRCM_CORE_SOCRAM		0x80e
#define	BRCM_CORE_D11			0x812
#define	BRCM_CORE_PMU			0x827
#define	BRCM_CORE_ARM_CM3		0x82a
#define	BRCM_CORE_PHY_AC		0x83b
#define	BRCM_CORE_PCIE2			0x83c
#define	BRCM_CORE_ARM_CR4		0x83e
#define	BRCM_CORE_GCI			0x840

/*
 * Cached core info from EROM walk.  Up to 32 cores is more than any
 * shipping BCM43xx chip has (BCM43602 has ~6); the array doesn't
 * need to grow.  Populated by brcm_pci_walk_cores().
 */
#define	BRCM_PCI_MAX_CORES	32

struct brcm_pci_core {
	uint16_t	id;
	uint8_t		rev;
	uint32_t	base;
	uint32_t	wrap;
};

/*
 * Chip IDs as read from the ChipCommon chipid register.  Five-digit
 * parts store the decimal number (BCM43602 is 0xaa52, i.e. 43602),
 * four-digit parts read as the hex digits (BCM4366 is 0x4366).  A
 * BCM43602 rev 1 reads 0x1601aa52: chip 0xaa52, rev 1, 6 cores.
 */
#define	BRCM_CHIP_BCM43602		0xaa52
#define	BRCM_CHIP_BCM4360		0x4360
#define	BRCM_CHIP_BCM4350		0x4350
#define	BRCM_CHIP_BCM4356		0x4356
#define	BRCM_CHIP_BCM4358		0x4358
#define	BRCM_CHIP_BCM4365		0x4365
#define	BRCM_CHIP_BCM4366		0x4366

/*
 * Start of BAR0's PCIe2-core fixed-offset region (about 512 bytes at
 * 0x80..0x2ff on BCM43602).  Below it, 0x0..0x7f is the SBTOPCI-windowed
 * region, whose contents change as the window register moves.
 */
#define	BRCM_PCI_SNAP_BASE	0x80

struct brcm_pci_softc {
	struct brcm_softc	 bus_sc;
	device_t		 sc_dev;

	struct resource		*sc_bar0;
	bus_space_tag_t		 sc_bar0_t;
	bus_space_handle_t	 sc_bar0_h;

	struct resource		*sc_bar2;
	bus_space_tag_t		 sc_bar2_t;
	bus_space_handle_t	 sc_bar2_h;

	int			 sc_msix_count;
	bool			 sc_msi;	/* true: MSI fallback when MSI-X
						   unavailable; false + count=0
						   means INTx */
	struct resource		*sc_irq;
	int			 sc_irq_rid;
	void			*sc_irq_handle;

	uint16_t		 sc_devid;
	uint8_t			 sc_revid;
	const struct brcm_pci_chip_info *sc_chip;	/* per-chip params */

	/*
	 * Chip state.  attach() itself makes no BAR0 access: on Apple
	 * machines the BCM43602 is held gated until the EC.APWC bit and a
	 * second step are cleared, and any blind BAR0 read in that state
	 * master-aborts the host (MCE, then reboot).
	 */
	bool			 sc_chip_alive;
	/*
	 * Set when bring-up reaches wait_fw_ready, cleared by
	 * cold_reattach.  The bringup sysctl refuses while it is set:
	 * uploading over running firmware kills it, and the recovery
	 * that follows can hang the host.
	 */
	bool			 sc_fw_running;
	/* The autostart thread is running; detach waits for it. */
	bool			 sc_autostart_running;
	/* Firmware image, held from the first upload until detach. */
	const struct firmware	*sc_fw;
	/* FW-ready sentinel captured from TCM[ramsize-4] by wait_fw_ready */
	uint32_t		 sc_fw_sharedram;
	/*
	 * RAM size in bytes, captured in bring-up step 4 before firmware is
	 * loaded.  Later users must use this: brcm_pci_ramsize_query()
	 * after firmware boot halts the running CR4.
	 */
	uint32_t		 sc_fw_ramsize;
	/* dump_console read cursor into the fw log ring. */
	uint32_t		 sc_console_read_idx;

	struct brcm_pci_core	 sc_cores[BRCM_PCI_MAX_CORES];
	int			 sc_ncores;
	bool			 sc_bar2_sized;

	struct brcm_pci_msgbuf	 sc_msgbuf;

	/*
	 * Firmware crash auto-recovery.  The DCMD path bumps
	 * mb->stat_dcmd_timeout_consec on each timeout and resets it on
	 * any success.  When it hits sc_crash_recover_threshold we
	 * enqueue sc_crash_recover_task, which runs brcm_pci_cold_reattach
	 * from taskqueue_thread.  Threshold 0 (the default) disables it.
	 * Timeouts are not proof of a crash: firmware that stops answering
	 * while being taken down, or after a second upload, looks the same,
	 * and rebuilding a chip that is still running can hang the host.
	 * Opt in with the crash_recover_threshold sysctl.
	 */
	/*
	 * Transmit flow rings, made off the transmit path.  net80211 calls
	 * the transmit routine holding its TX lock, and making a ring means
	 * waiting for the firmware, so a frame with no ring yet is queued
	 * here and sc_flow_task makes the ring and sends the queue.  Index
	 * 0 is data (prio 0), 1 is EAPOL (prio 7).  Sleeping in the transmit
	 * path would panic with "sleeping thread holds brcm_pci0_tx_lock".
	 */
#define	BRCM_PCI_FLOWQ_LEN	64
	struct mtx		 sc_flowq_mtx;
	struct mbufq		 sc_flowq[2];
	bool			 sc_flowq_busy[2];
	uint8_t			 sc_flowq_sa[2][6];
	uint8_t			 sc_flowq_da[2][6];
	struct task		 sc_flow_task;

	struct task		 sc_crash_recover_task;
	uint32_t		 sc_crash_recover_threshold;
	uint32_t		 sc_crash_recover_events;   /* triggers */
	bool			 sc_crash_recover_pending;
};

#define	SC_TO_PCI(sc)	__containerof((sc), struct brcm_pci_softc, bus_sc)

/*
 * Silent-by-default trace print keyed on the shared brcm_softc's sc_debug.
 * Argument is a `struct brcm_pci_softc *` so callers don't have to spell
 * out `&sc->bus_sc` at each site.  level==0 fires when sc_debug > 0.
 */
#define	PDPRINTF(pci_sc, level, ...)	do {				\
	if ((pci_sc)->bus_sc.sc_debug > (level))			\
		device_printf((pci_sc)->sc_dev, __VA_ARGS__);		\
} while (0)

/* ------------------------------------------------------------------
 * Apple platform unlock.
 *
 * On MacBook Pros with the BCM43602 (A1398 and similar) the chip's
 * PCIe link is held in a clock-gated / disabled state at boot.  Even
 * after a move to D0 via PMCSR, BAR0 cycles return 0xffffffff because
 * the chip's PCIe controller isn't responding.  The DSDT exposes an `APPU`
 * ("AirPort Power Up") method on the parent root-port bridge that
 * performs the unlock:
 *
 *   - sets the bridge's LDIS bit to 0 (link-disable off)
 *   - flips \_SB.PCI0.LPCB.EC.APWC = 1 (Embedded Controller's
 *     AirPort power-control bit)
 *   - polls LACT == 1 && ARPT vendor-ID != 0xFFFF until link
 *     trains and the WiFi device answers config-space reads
 *
 * Method lives on the bridge's ACPI handle, not on the WiFi
 * device's.  We walk one step up the ACPI namespace from the
 * device's handle to reach it.
 *
 * Returns 0 if APPU was found and called (regardless of whether
 * it actually flipped state — its early-return cases are platform
 * policy).  Returns ENOENT if no APPU method exists, in which
 * case we're on a non-Apple platform and don't need the unlock.
 * ------------------------------------------------------------------ */

/*
 * Apple EC port write.
 *
 * On these Apple machines the BCM43602's PCIe memory decoder
 * is gated until the embedded controller's APWC bit (EC RAM byte
 * 0x03, bit 0) is set to 1.  The ACPI AML path to that write is
 * locked behind methods (APPU / _PS0) that also touch the gated
 * chip and master-abort us before completing.
 *
 * Bypass by talking to the EC directly via its standard ACPI I/O
 * ports: 0x62 (data) + 0x66 (cmd/status).  Protocol:
 *   - poll status bit IBF (bit 1) until clear
 *   - command 0x80 (RD_EC) / 0x81 (WR_EC) on port 0x66
 *   - address byte on port 0x62
 *   - data byte on port 0x62 (write) or read after OBF (output
 *     buffer full, bit 0) becomes 1
 *
 * Races with FreeBSD's acpi_ec driver are possible in principle,
 * but at our attach time (kldload of brcm_pci) no other ACPI
 * activity is reasonably in flight against the EC.
 */
#define	BRCM_EC_DATA	0x62
#define	BRCM_EC_CMD	0x66
#define	BRCM_EC_S_OBF	0x01		/* status: output buffer full */
#define	BRCM_EC_S_IBF	0x02		/* status: input buffer full */
#define	BRCM_EC_C_RD	0x80		/* command: read EC byte */
#define	BRCM_EC_C_WR	0x81		/* command: write EC byte */

#define	BRCM_EC_APWC_OFFSET	0x03	/* AirPort Power Control byte */
#define	BRCM_EC_APWC_BIT	0x01	/* bit 0 */

#if defined(__amd64__) || defined(__i386__)
static int
brcm_pci_ec_wait_ibf(void)
{
	int t;

	for (t = 0; t < 10000; t++) {	/* up to 100 ms */
		if ((inb(BRCM_EC_CMD) & BRCM_EC_S_IBF) == 0)
			return (0);
		DELAY(10);
	}
	return (ETIMEDOUT);
}

static int
brcm_pci_ec_wait_obf(void)
{
	int t;

	for (t = 0; t < 10000; t++) {	/* up to 100 ms */
		if ((inb(BRCM_EC_CMD) & BRCM_EC_S_OBF) != 0)
			return (0);
		DELAY(10);
	}
	return (ETIMEDOUT);
}

static int
brcm_pci_ec_read_byte(uint8_t off, uint8_t *out)
{
	int error;

	if ((error = brcm_pci_ec_wait_ibf()) != 0)
		return (error);
	outb(BRCM_EC_CMD, BRCM_EC_C_RD);
	if ((error = brcm_pci_ec_wait_ibf()) != 0)
		return (error);
	outb(BRCM_EC_DATA, off);
	if ((error = brcm_pci_ec_wait_obf()) != 0)
		return (error);
	*out = inb(BRCM_EC_DATA);
	return (0);
}

static int
brcm_pci_ec_write_byte(uint8_t off, uint8_t val)
{
	int error;

	if ((error = brcm_pci_ec_wait_ibf()) != 0)
		return (error);
	outb(BRCM_EC_CMD, BRCM_EC_C_WR);
	if ((error = brcm_pci_ec_wait_ibf()) != 0)
		return (error);
	outb(BRCM_EC_DATA, off);
	if ((error = brcm_pci_ec_wait_ibf()) != 0)
		return (error);
	outb(BRCM_EC_DATA, val);
	return (brcm_pci_ec_wait_ibf());
}
#else  /* non-x86: no PC EC access */
static int brcm_pci_ec_read_byte(uint8_t off __unused,
    uint8_t *out __unused) { return (ENOTSUP); }
static int brcm_pci_ec_write_byte(uint8_t off __unused,
    uint8_t val __unused) { return (ENOTSUP); }
#endif

/*
 * Apple WAPS ("Wake AirPort Subsystem").
 *
 * \_SB.PCI0.RP03.WAPS in the DSDT, called by APPU after the EC.APWC=1
 * step succeeds.  EC.APWC=1
 * alone wakes the chip's power rails but leaves its PCIe config in
 * a state where BAR cycles still master-abort the host.  WAPS pokes
 * an internal backdoor register pair to program the chip's
 * subsystem-vendor / subsystem-device IDs into a hidden config
 * shadow; once that's done the chip's PCIe controller starts
 * responding to BAR reads.
 *
 * The backdoor is two PCI config-space registers on the ARPT device:
 *   BDIR at offset 0xA0  — 32-bit indirect index
 *   BDDR at offset 0xA4  — 32-bit indirect data
 * Plus an enable (BDEN, offset 0x88) and a mapping register
 * (BDMR, offset 0x80) that together gate when the access is
 * recognized.
 *
 * The full WAPS sequence:
 *
 *   BDEN = 0x40              ; enable backdoor
 *   BDMR = 0x18003000        ; map to chip's internal config region
 *   BDIR = 0x0120 ; BDDR = 0x0438       ; backdoor write #1
 *   BDIR = 0x0124 ; BDDR = 0x0152106B   ; SS vendor 106B + dev 0152
 *   BDEN = 0x00              ; disable backdoor
 *
 * All accesses are PCI config space, so they are safe on a gated
 * chip.  Reading BDDR back as 0x0152106B afterwards means the chip
 * accepted the program; ARPT._PS0 uses the same read as its "already
 * unlocked" check.
 */
#define	BRCM_PCI_BD_MR	0x80
#define	BRCM_PCI_BD_EN	0x88
#define	BRCM_PCI_BD_IR	0xa0
#define	BRCM_PCI_BD_DR	0xa4
/*
 * The DSDT APPU method reimplemented in C.
 *
 * The macOS warm-up path is RP03._PS0 -> ALPR(0) -> APPU().  APPU's
 * inner loop:
 *   1. Write \_SB.PCI0.LPCB.EC.APWC = 0x01 (the Apple EC APWC bit).
 *   2. Sleep 0xFA = 250ms.
 *   3. Poll for 10s (10 million 100ns Timer ticks / 10ms Sleeps):
 *        (LACT == 1) && (\_SB.PCI0.RP03.ARPT.AVND != 0xFFFF)
 *      LACT = Link Active bit on parent bridge's PCIe LinkStatus.
 *      AVND = chip's PCI vendor ID via ARPT config-space.
 *   4. If poll fails, write APWC=0, sleep 0x0107=263ms, retry up to
 *      5 attempts total.
 *
 * Doing it in C keeps the 10s poll outside the ACPICA interpreter
 * mutex; evaluating APPU through AcpiEvaluateObject() holds that lock
 * long enough to panic with a spin lock held too long.
 *
 * On success the ChipID (BAR0[0x00]) goes from 0xffffffff (cold) to
 * 0xaa52 (BCM43602 warm); dev.brcm_pci.N.chip_alive=1 checks it.
 */
#define BRCM_APPU_PERST_SLEEP_US   250000    /* 250 ms after APWC=1 */
#define BRCM_APPU_POLL_INTERVAL_US 10000     /* 10 ms per iter */
#define BRCM_APPU_POLL_ITERS       1000      /* 1000 * 10ms = 10s */
#define BRCM_APPU_OFF_SLEEP_US     263000    /* 263 ms between retries */
#define BRCM_APPU_MAX_ATTEMPTS     5

static int
brcm_pci_apple_appu_warm(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint8_t b;
	uint16_t vid;
	int attempt, iter, error;
	bool link_up;

	for (attempt = 0; attempt < BRCM_APPU_MAX_ATTEMPTS; attempt++) {
		device_printf(dev, "APPU: attempt %d/%d - writing APWC=1\n",
		    attempt + 1, BRCM_APPU_MAX_ATTEMPTS);

		error = brcm_pci_ec_read_byte(BRCM_EC_APWC_OFFSET, &b);
		if (error != 0) {
			device_printf(dev, "APPU: EC read failed rc=%d\n", error);
			return (error);
		}
		error = brcm_pci_ec_write_byte(BRCM_EC_APWC_OFFSET,
		    b | BRCM_EC_APWC_BIT);
		if (error != 0) {
			device_printf(dev, "APPU: EC write APWC=1 failed rc=%d\n",
			    error);
			return (error);
		}

		/* Step 2: 250ms settle after APWC=1. */
		DELAY(BRCM_APPU_PERST_SLEEP_US);

		/*
		 * Step 3: poll chip PCI vendor ID for 10s.  When the chip
		 * finishes its ROM boot, its PCI config space starts
		 * answering with the real VID (0x14e4) instead of 0xffff.
		 * Config-space reads never wedge (they go through the root
		 * complex, not the chip's memory decoder), so this is safe.
		 */
		link_up = false;
		for (iter = 0; iter < BRCM_APPU_POLL_ITERS; iter++) {
			vid = pci_read_config(dev, PCIR_VENDOR, 2);
			if (vid != 0xffff && vid != 0x0000) {
				link_up = true;
				break;
			}
			DELAY(BRCM_APPU_POLL_INTERVAL_US);
		}

		if (link_up) {
			device_printf(dev,
			    "APPU: link up after %d ms - chip vendor=0x%04x, "
			    "chip is WARM\n",
			    (iter + 1) * (BRCM_APPU_POLL_INTERVAL_US / 1000),
			    vid);
			return (0);
		}

		device_printf(dev,
		    "APPU: attempt %d timed out after 10s - APWC=0 and retry\n",
		    attempt + 1);

		/* Step 4: retry - APWC=0, sleep 263ms, loop. */
		error = brcm_pci_ec_read_byte(BRCM_EC_APWC_OFFSET, &b);
		if (error == 0) {
			(void)brcm_pci_ec_write_byte(BRCM_EC_APWC_OFFSET,
			    b & ~BRCM_EC_APWC_BIT);
		}
		DELAY(BRCM_APPU_OFF_SLEEP_US);
	}

	device_printf(dev,
	    "APPU: chip failed to come up after %d attempts - stays cold\n",
	    BRCM_APPU_MAX_ATTEMPTS);
	return (ETIMEDOUT);
}

/* ------------------------------------------------------------------
 * BAR0 windowing helpers.
 *
 * Reads and writes of backplane-side chip registers go through the
 * sliding window register at PCI config offset 0x80.
 *
 * The window register is per-device chip state and no lock guards
 * it; the interrupt path is meant to use only the PCIe2 fixed offsets
 * at 0x90 and above, not the windowed 0x0..0x7f region.
 * ------------------------------------------------------------------ */

static void
brcm_pci_set_window(struct brcm_pci_softc *sc, uint32_t addr)
{
	uint32_t want = addr & BRCM_PCI_BAR0_WINDOW_MASK;

	/*
	 * The window register is at PCI config offset 0x80, not BAR0
	 * memory offset 0x80; a BAR0 write there does not move the
	 * window.  The DSDT's WAPS method drives the same register
	 * through config space.
	 */
	pci_write_config(sc->sc_dev, BRCM_PCI_BAR0_WINDOW, want, 4);
	(void)pci_read_config(sc->sc_dev, BRCM_PCI_BAR0_WINDOW, 4);
}

static uint32_t
brcm_pci_read_core32(struct brcm_pci_softc *sc, uint32_t backplane_addr)
{
	brcm_pci_set_window(sc, backplane_addr);
	return (bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    backplane_addr & BRCM_PCI_BAR0_WINDOW_OFF_MASK));
}

/*
 * Config-space-only chip-alive test.  It cannot wedge even with a cold
 * backplane, since config space is served by the root complex, but it
 * does not prove BAR0 MMIO is safe.  Mirrors the gating check in
 * macOS AppleBCMWLANBusInterfacePCIe attachPCIeBusGated.
 */
static bool
brcm_pci_chip_alive_cfg(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint16_t vid;
	uint32_t win_readback;

	vid = pci_read_config(dev, PCIR_VENDOR, 2);
	if (vid == 0xffff) {
		device_printf(dev,
		    "chip_alive_cfg: cfg VID=0xffff — PCIe link down or "
		    "device absent.  Refusing.\n");
		return (false);
	}

	pci_write_config(dev, BRCM_PCI_BAR0_WINDOW,
	    BRCM_BACKPLANE_CHIPCOMMON, 4);
	win_readback = pci_read_config(dev, BRCM_PCI_BAR0_WINDOW, 4);
	if (win_readback == 0xffffffffU) {
		device_printf(dev,
		    "chip_alive_cfg: cfg BAR0_WIN readback=0xffffffff — "
		    "RC completion timeout, backplane unreachable.  "
		    "Refusing.\n");
		return (false);
	}
	if (win_readback != BRCM_BACKPLANE_CHIPCOMMON) {
		device_printf(dev,
		    "chip_alive_cfg: cfg BAR0_WIN readback=0x%08x — expected "
		    "0x%x.  cfg-space write not retained; PCIe fabric "
		    "unhealthy.  Refusing.\n",
		    win_readback, BRCM_BACKPLANE_CHIPCOMMON);
		return (false);
	}

	/* Backplane data read through the config-space window at 0x1e8. */
	{
		uint32_t bp_data;

		bp_data = pci_read_config(dev, 0x1e8, 4);
		if (bp_data == 0xffffffffU) {
			device_printf(dev,
			    "chip_alive_cfg: cfg 0x1e8 backplane read = "
			    "0xffffffff — backplane clock is OFF.  cfg VID "
			    "was 0x%04x, BAR0_WIN was 0x%08x, but chip "
			    "backplane isn't responding to config-space "
			    "read-through.  Refusing to protect from CPU "
			    "wedge.\n",
			    vid, win_readback);
			return (false);
		}

		device_printf(dev,
		    "chip_alive_cfg: cfg VID=0x%04x, BAR0_WIN=0x%08x, "
		    "backplane data (ChipID via cfg 0x1e8) = 0x%08x — "
		    "backplane clock is ON.\n",
		    vid, win_readback, bp_data);
	}
	return (true);
}

/* ------------------------------------------------------------------
 * EROM (Enumeration ROM) walk.
 *
 * Every AI-style Broadcom chip publishes a table of its backplane
 * cores at the chip-side address held in ChipCommon[0xfc].  Walking
 * the table tells us where each core's registers live and which
 * cores exist on this particular silicon — needed for ARM-CR4 reset,
 * SOCRAM sizing, PCIe2 doorbell setup, and so on.  Without it, the
 * driver would have to hardcode per-chip base addresses; the EROM
 * lets one code path serve every chip.
 *
 * Walker layout:
 *
 *   Each COMPONENT descriptor pair (id + rev/port-counts) is
 *   followed by zero or more MASTER_PORT descriptors then one or
 *   more ADDRESS descriptors.  The first ADDRESS for a component
 *   gives the slave (register) base; we record (id, rev, base) per
 *   core into sc_cores[].
 *
 * Every read goes through the SBTOPCI window, which is slow but only
 * happens once per bring-up.
 * ------------------------------------------------------------------ */

static const char *
brcm_pci_core_name(uint16_t id)
{
	switch (id) {
	case BRCM_CORE_CHIPCOMMON:	return "ChipCommon";
	case BRCM_CORE_SOCRAM:		return "SOCRAM";
	case BRCM_CORE_D11:		return "D11/80211";
	case BRCM_CORE_PMU:		return "PMU";
	case BRCM_CORE_ARM_CM3:		return "ARM-CM3";
	case BRCM_CORE_PHY_AC:		return "PHY-AC";
	case BRCM_CORE_PCIE2:		return "PCIe2";
	case BRCM_CORE_ARM_CR4:		return "ARM-CR4";
	case BRCM_CORE_GCI:		return "GCI";
	default:			return "?";
	}
}

static uint32_t
brcm_pci_erom_next(struct brcm_pci_softc *sc, uint32_t *paddr)
{
	uint32_t v;

	v = brcm_pci_read_core32(sc, *paddr);
	*paddr += 4;
	return (v);
}

static int
brcm_pci_walk_cores(struct brcm_pci_softc *sc)
{
	uint32_t eromptr, addr;
	uint32_t v1, v2, vd;
	uint16_t id;
	uint8_t rev, type, sztype;
	uint32_t base;
	int i, guard;
	bool found_addr;

	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "core_walk: refusing — sc_chip_alive is false\n");
		return (ENXIO);
	}

	eromptr = brcm_pci_read_core32(sc,
	    BRCM_BACKPLANE_CHIPCOMMON + BRCM_CC_REG_EROMPTR);
	PDPRINTF(sc, 0,
	    "core_walk: ChipCommon[0xfc] EROM pointer = 0x%08x\n", eromptr);
	if (eromptr == 0 || eromptr == 0xffffffffU) {
		device_printf(sc->sc_dev,
		    "core_walk: EROM pointer looks invalid; aborting\n");
		return (EIO);
	}

	addr = eromptr;
	sc->sc_ncores = 0;
	guard = 0;
	while (guard++ < 256) {
		v1 = brcm_pci_erom_next(sc, &addr);
		type = v1 & BRCM_EROM_DESC_TYPE_MSK;
		if (type == BRCM_EROM_DESC_EOT) {
			PDPRINTF(sc, 0,
			    "core_walk: EOT at EROM offset 0x%x\n",
			    addr - 4 - eromptr);
			break;
		}
		if ((v1 & BRCM_EROM_DESC_VALID) == 0)
			continue;
		if (type != BRCM_EROM_DESC_COMPONENT)
			continue;

		id = (v1 & BRCM_EROM_COMP_PARTNUM) >>
		    BRCM_EROM_COMP_PARTNUM_S;

		/* Second COMPONENT word — required. */
		v2 = brcm_pci_erom_next(sc, &addr);
		if ((v2 & BRCM_EROM_DESC_TYPE_MSK) !=
		    BRCM_EROM_DESC_COMPONENT) {
			device_printf(sc->sc_dev,
			    "core_walk: malformed component pair "
			    "(id=0x%03x), second word 0x%08x not "
			    "COMPONENT — stopping walk\n", id, v2);
			break;
		}
		rev = (v2 & BRCM_EROM_COMP_REVISION) >>
		    BRCM_EROM_COMP_REVISION_S;

		/*
		 * Walk ADDRESS descriptors.  Each carries a slave-type
		 * field (bits 6-7) saying whether the address is the
		 * core's register window (SLAVE), its slave-side wrapper
		 * (SWRAP), or master-side wrapper (MWRAP).  We capture
		 * the first SLAVE-type address as `base` and the first
		 * SWRAP as `wrap` — wrap is what reset/clock control
		 * goes through.
		 */
		base = 0;
		uint32_t wrap = 0;
		(void)found_addr;
		for (i = 0; i < 32; i++) {	/* bounded per-component */
			uint32_t v;
			uint8_t t, stype;

			v = brcm_pci_erom_next(sc, &addr);
			t = v & BRCM_EROM_DESC_TYPE_MSK;

			if (t == BRCM_EROM_DESC_EOT) {
				addr -= 4;
				goto eot;
			}
			if (t == BRCM_EROM_DESC_COMPONENT) {
				addr -= 4;
				break;
			}
			if (t == BRCM_EROM_DESC_MASTER_PORT)
				continue;
			if ((t & ~BRCM_EROM_DESC_ADDRSIZE_GT32) ==
			    BRCM_EROM_DESC_ADDRESS) {
				stype = (v & BRCM_EROM_SLAVE_TYPE_MASK) >>
				    BRCM_EROM_SLAVE_TYPE_SHIFT;

				if (stype == BRCM_EROM_SLAVE_TYPE_SLAVE &&
				    base == 0)
					base = v & BRCM_EROM_SLAVE_ADDR_BASE;
				else if (stype == BRCM_EROM_SLAVE_TYPE_SWRAP &&
				    wrap == 0)
					wrap = v & BRCM_EROM_SLAVE_ADDR_BASE;
				else if (stype == BRCM_EROM_SLAVE_TYPE_MWRAP &&
				    wrap == 0)
					wrap = v & BRCM_EROM_SLAVE_ADDR_BASE;

				if (t & BRCM_EROM_DESC_ADDRSIZE_GT32)
					(void)brcm_pci_erom_next(sc, &addr);
				sztype = (v & BRCM_EROM_SLAVE_SIZE_TYPE) >> 4;
				if (sztype == BRCM_EROM_SLAVE_SIZE_DESC) {
					vd = brcm_pci_erom_next(sc, &addr);
					if (vd & BRCM_EROM_DESC_ADDRSIZE_GT32)
						(void)brcm_pci_erom_next(sc,
						    &addr);
				}
				continue;
			}
			addr -= 4;
			break;
		}

		if (sc->sc_ncores >= BRCM_PCI_MAX_CORES) {
			device_printf(sc->sc_dev,
			    "core_walk: hit BRCM_PCI_MAX_CORES (%d); "
			    "dropping further entries\n",
			    BRCM_PCI_MAX_CORES);
			continue;
		}
		sc->sc_cores[sc->sc_ncores].id   = id;
		sc->sc_cores[sc->sc_ncores].rev  = rev;
		sc->sc_cores[sc->sc_ncores].base = base;
		sc->sc_cores[sc->sc_ncores].wrap = wrap;
		sc->sc_ncores++;

		PDPRINTF(sc, 0,
		    "core_walk: %2d. %-12s id=0x%03x rev=%u "
		    "base=0x%08x wrap=0x%08x\n",
		    sc->sc_ncores, brcm_pci_core_name(id), id, rev,
		    base, wrap);
	}
eot:
	PDPRINTF(sc, 0,
	    "core_walk: %d core(s) recorded\n", sc->sc_ncores);
	return (0);
}

/* ------------------------------------------------------------------
 * Firmware upload.
 *
 * On BCM43602 the host loads the ARM-CR4 image directly into the
 * chip's SOCRAM via BAR2.  BAR2 is the "TCM" aperture: a flat
 * window onto chip-side memory.  The firmware destination within
 * BAR2 is `rambase`, a per-chip constant (NOT the SOCRAM core's
 * backplane address).  On BCM43602 rambase = 0x180000; per-chip
 * table lives in brcm_pci_chip_table[].
 *
 * The firmware image is wrapped as the kld brcm_pci_fw_43602.  It is
 * a raw ARM-CR4 image (no ELF or Mach-O header), about 635 KB and
 * 4-byte aligned, with no relocation table or signature: the loader
 * is expected to know the chip's rambase.  The ARM-CR4 reset vector
 * is the first le32 of the image.
 *
 * The strings at the tail of the image carry the firmware version and
 * feature list (e.g. "43602a1-roml/pcie Version: 7.35.177.61 ..."),
 * and they are logged at upload so dmesg shows which firmware ran.
 * ------------------------------------------------------------------ */

#define	BRCM_PCI_FW_43602	"brcmfmac43602_pcie"
#define	BRCM_PCI_RAMBASE_43602	0x180000	/* per-chip TCM base */
#define	BRCM_PCI_FW_VERSTRING_MAX	256

/*
 * Minimal synthetic NVRAM for the BCM43602 on Apple A1398.
 *
 * Apple's AirPortBrcmNIC kext carries per-board NVRAM tables keyed by
 * model; those are not used here.  This is the smallest set of fields
 * the firmware needs to complete its boot handshake (writing the
 * shared-memory pointer to BAR2[rambase+ramsize-4]).  Radio
 * calibration (antenna switch tables, PA cal, BT coex) is omitted, so
 * the chip falls back to its on-die fuse defaults: the link works but
 * is not tuned for the board.
 *
 * Field choices:
 *   manfid    = 0x14e4   Broadcom (chip rejects mismatched manfid)
 *   prodid    = 0xaa52   BCM43602 chip ID
 *   devid     = 0x43ba   PCI device ID (cfg space matches)
 *   boardvendor=0x106b   Apple (subv in cfg 0x2C)
 *   boardtype = 0x0152   Apple A1398 SS-device ID
 *   boardrev  = 0x1319   Apple A1398 board rev, as macOS IOKit reports
 *                        it (IO80211HardwareVersion).
 *   sromrev   = 11       SROM v11 format (43602a1 expects this; v12 is
 *                        4378+)
 *   boardflags*          Conservative Apple-style flags from a public
 *                        43602a1 reference NVRAM
 *   macaddr   = template; firmware overwrites from eFuse on boot
 *   ccode/regrev         FCC defaults; net80211 sets real cc later
 *   aa2g / aa5g = 3      Both antenna chains live
 */
static const char brcm_pci_minimal_nvram[] =
	"manfid=0x14e4\0"
	"prodid=0xaa52\0"
	"devid=0x43ba\0"
	"boardvendor=0x106b\0"
	"boardtype=0x0152\0"
	"boardrev=0x1319\0"
	"sromrev=12\0"
	"boardflags=0x82482001\0"
	"boardflags2=0x40000000\0"
	"boardflags3=0x44004404\0"
	"macaddr=00:90:4c:c5:43:60\0"
	"ccode=ALL\0"
	"regrev=0\0"
	"aa2g=3\0"
	"aa5g=3\0"
	"agbg0=2\0"
	"agbg1=2\0"
	"aga0=2\0"
	"aga1=2\0"
	"antswitch=0\0"
	"\0\0";	/* double-NUL terminator */

/* ARM-CR4 core register offsets used during enter_download_state. */
#define	BRCM_ARMCR4_BANKIDX	0x40
#define	BRCM_ARMCR4_BANKPDA	0x4c

/*
 * PCIe2 core "internal config" backdoor: CONFIGADDR is the index
 * register (which internal config word to access); CONFIGDATA is
 * read/write to it.  Live at BAR0[0x120] / BAR0[0x124] when the
 * SBTOPCI window is pointed at the PCIe2 core (chip backplane
 * 0x18003000).  Used to resize the BAR2 aperture so it maps chip
 * TCM; without it a single BAR2 write target-aborts the host.
 */
#define	BRCM_PCIE2_CONFIGADDR	0x120
#define	BRCM_PCIE2_CONFIGDATA	0x124
#define	BRCM_PCIE2_CFG_BAR2RESIZE	0x4e0	/* internal cfg index */

/*
 * ChipCommon watchdog register: writing N here triggers a chip-wide
 * reset after N ticks (use 4).
 */
#define	BRCM_CC_REG_WATCHDOG	0x80

/* ChipCommon PMU register block, relative to the ChipCommon base. */
#define	BRCM_CC_PMU_CTRL		0x600
#define	BRCM_CC_PMU_CAP			0x604
#define	BRCM_CC_PMU_STATUS		0x608
#define	BRCM_CC_PMU_RES_STATE		0x60c
#define	BRCM_CC_PMU_RES_PENDING		0x610
#define	BRCM_CC_PMU_TIMER		0x614
#define	BRCM_CC_PMU_MIN_RES_MASK	0x618
#define	BRCM_CC_PMU_MAX_RES_MASK	0x61c
#define	BRCM_CC_PMU_RES_TABLE_SEL	0x620
#define	BRCM_CC_PMU_RES_DEP_MASK	0x624
#define	BRCM_CC_PMU_RES_UPDN_TIMER	0x628
#define	BRCM_CC_PMU_RES_TIMER		0x62c
#define	BRCM_CC_PMU_CHIPCONTROL_ADDR	0x650
#define	BRCM_CC_PMU_CHIPCONTROL_DATA	0x654
#define	BRCM_CC_PMU_REGCONTROL_ADDR	0x658
#define	BRCM_CC_PMU_REGCONTROL_DATA	0x65c
#define	BRCM_CC_PMU_PLLCONTROL_ADDR	0x660
#define	BRCM_CC_PMU_PLLCONTROL_DATA	0x664

/*
 * BCMA core wrapper registers.  Live at <core->wrap> + offset.
 * IOCTL gates the core's clock + power; RESET_CTL holds it in or
 * brings it out of reset.  These are accessible whenever the
 * backplane interconnect is alive — they're how the host turns
 * cores on, so they must be reachable even when the core itself
 * is off.
 */
#define	BRCM_BCMA_IOCTL		0x408
#define	BRCM_BCMA_IOCTL_CLK	0x1
#define	BRCM_BCMA_IOCTL_FGC	0x2
#define	BRCM_BCMA_RESET_CTL	0x800
#define	BRCM_BCMA_RESET_CTL_RESET	0x1
#define	BRCM_ARMCR4_IOCTL_CPUHALT	0x20

/*
 * D11 (802.11 MAC) core IOCTL bits.  Used by chip_set_passive to put
 * D11 into "PHY clock on, PHY reset asserted" before firmware load;
 * without this the WiFi MAC core can interact with shared
 * resources in ways that prevent the ARM-CR4 firmware from
 * completing its early init handshake.
 */
#define	BRCM_D11_IOCTL_PHYCLOCKEN	0x4
#define	BRCM_D11_IOCTL_PHYRESET		0x8

/* ARM-CR4 core registers (offsets within core->base). */
#define	BRCM_ARMCR4_CAP		0x04
#define	BRCM_ARMCR4_BANKINFO	0x44	/* paired with BANKIDX at 0x40 */
#define	BRCM_ARMCR4_TCBANB_MASK	0x0000000fU
#define	BRCM_ARMCR4_TCBBNB_MASK	0x000000f0U
#define	BRCM_ARMCR4_TCBBNB_SHIFT	4
#define	BRCM_ARMCR4_BSZ_MASK	0x0000007fU
#define	BRCM_ARMCR4_BLK_1K_MASK	0x00000200U
#define	BRCM_ARMCR4_BSZ_MULT	8192

/*
 * Take a core out of reset and turn its clock on.  This is the
 * minimal "enable core" sequence for the common case where the
 * core is currently held in reset and we want it running with no
 * special IOCTL flags.
 *
 *   poll wrap+RESET_CTL writing 0 until the reset bit clears
 *   write postreset|CLK to wrap+IOCTL
 *   read wrap+IOCTL to flush
 *
 * Call only once the wrap registers are known to be readable, i.e.
 * the backplane interconnect is alive.
 */
static int
brcm_pci_core_enable(struct brcm_pci_softc *sc, uint16_t coreid,
    uint32_t postreset)
{
	uint32_t wrap = 0;
	uint32_t v;
	int i, count;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == coreid) {
			wrap = sc->sc_cores[i].wrap;
			break;
		}
	}
	if (wrap == 0) {
		device_printf(sc->sc_dev,
		    "core_enable: %s (0x%03x) has no wrap base\n",
		    brcm_pci_core_name(coreid), coreid);
		return (ENOENT);
	}

	brcm_pci_set_window(sc, wrap);

	/* Poll RESET_CTL — write 0 until bit 0 clears, up to ~2.5 ms. */
	count = 0;
	while (((v = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK)) &
	    BRCM_BCMA_RESET_CTL_RESET) != 0) {
		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0);
		count++;
		if (count > 50)
			break;
		DELAY(50);
	}
	PDPRINTF(sc, 0,
	    "core_enable: %s RESET_CTL = 0x%08x after %d poll(s)\n",
	    brcm_pci_core_name(coreid), v, count);

	/* Write IOCTL: postreset | CLK. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    postreset | BRCM_BCMA_IOCTL_CLK);
	v = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	PDPRINTF(sc, 0,
	    "core_enable: %s IOCTL after write = 0x%08x\n",
	    brcm_pci_core_name(coreid), v);

	return (0);
}

/*
 * Release ARM-CR4 from reset, which boots the firmware.
 *
 * BCM43602 path:
 *
 *   1. Reset vector at TCM[0] (BAR2 + rambase + 0).  Already the
 *      first dword of the firmware blob from our upload; we read it
 *      back for logging.
 *   2. ai_coredisable(ARM_CR4, prereset=CPUHALT, reset=0):
 *        - if not in reset: IOCTL = CPUHALT|FGC|CLK ; RESET_CTL = 1 ;
 *          poll until RESET_CTL reads back 1
 *        - in-reset configure: IOCTL = FGC|CLK (no CPUHALT)
 *   3. Poll RESET_CTL writing 0 until reset bit clears.
 *   4. Postreset: IOCTL = CLK only; the CPU starts at rstvec.
 *
 * Once the firmware is up it writes its pciedev_shared_t pointer to
 * BAR2[rambase + ramsize - 4], which the caller polls.
 */
static int
brcm_pci_armcr4_release(struct brcm_pci_softc *sc)
{
	uint32_t wrap = 0;
	uint32_t rstvec, ioctl, reset;
	int i, count;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_ARM_CR4) {
			wrap = sc->sc_cores[i].wrap;
			break;
		}
	}
	if (wrap == 0) {
		device_printf(sc->sc_dev,
		    "armcr4_release: ARM-CR4 wrap base unknown\n");
		return (ENOENT);
	}
	if (sc->sc_bar2 == NULL) {
		device_printf(sc->sc_dev,
		    "armcr4_release: BAR2 not allocated\n");
		return (ENXIO);
	}

	/*
	 * Rstvec is the first 4 bytes of the firmware image, a Thumb-2
	 * B.W instruction that branches to the real entry point.
	 * load_firmware already put it at BAR2[rambase], so read it back
	 * from there to log and validate it.
	 */
	{
	uint32_t rambase = sc->sc_chip ? sc->sc_chip->rambase :
	    BRCM_PCI_RAMBASE_43602;
	rstvec = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, rambase);
	PDPRINTF(sc, 0,
	    "armcr4_release: firmware[0] (rstvec value) = 0x%08x "
	    "(rambase=0x%x)\n", rstvec, rambase);
	}
	if (rstvec == 0 || rstvec == 0xffffffffU) {
		device_printf(sc->sc_dev,
		    "armcr4_release: reset vector looks invalid; "
		    "skip (run load_fw first)\n");
		return (ENXIO);
	}

	/*
	 * Write rstvec at BAR2[0] (chip address 0), where the CR4 fetches
	 * its first instruction on reset release.  That is a different
	 * location from BAR2[rambase], where the image was loaded; with
	 * it uninitialised the CPU fetches garbage and halts.  Linux
	 * likewise writes the image at tcm + rambase and the reset vector
	 * at tcm + 0 (brcmf_pcie_buscore_activate).
	 */
	bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h, 0, rstvec);
	(void)bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, 0);

	/*
	 * Apple's loadChipImage prologue writes cfg 0x110 = 0x31c1
	 * (SPROM ctrl retention) before touching wrapper registers.
	 */
	pci_write_config(sc->sc_dev, 0x110, 0x31c1, 4);
	PDPRINTF(sc, 0,
	    "armcr4_release: cfg[0x110] = 0x31c1 (SPROM ctrl retention)\n");

	brcm_pci_set_window(sc, wrap);

	/*
	 * Full ai_resetcore(CR4, CPUHALT, 0, 0).  Toggling CPUHALT alone
	 * is not enough: without asserting RESET_CTL the CR4 resumes
	 * from wherever it was (Apple firmware left from a warm boot, or
	 * a halted state) instead of starting the new image.
	 *
	 *   1. IOCTL = CPUHALT | FGC | CLK    (halt CPU, force clock)
	 *   2. RESET_CTL = 1                  (assert reset), short delay
	 *   3. IOCTL = FGC | CLK              (in-reset config)
	 *   4. RESET_CTL = 0                  (deassert), short delay
	 *   5. IOCTL = CLK only               (running)
	 */

	/* 1. Halt CPU + gate clock (pre-reset). */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_ARMCR4_IOCTL_CPUHALT | BRCM_BCMA_IOCTL_FGC |
	    BRCM_BCMA_IOCTL_CLK);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	/* 2. Assert reset. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_RESET_CTL_RESET);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	DELAY(20);

	/* 3. In-reset config; dropping CPUHALT clears it while in reset. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_IOCTL_FGC | BRCM_BCMA_IOCTL_CLK);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	/* 4. Deassert reset; the CR4 starts executing. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	DELAY(2);

	/* 5. Postreset: drop FGC so clock runs normally. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_IOCTL_CLK);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	(void)count;

	/* Read final state for the log. */
	ioctl = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	reset = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	PDPRINTF(sc, 0,
	    "armcr4_release: ARM-CR4 running.  IOCTL=0x%08x RESET_CTL=0x%08x "
	    "rstvec=0x%08x\n", ioctl, reset, rstvec);
	return (0);
}

/*
 * Compute total TCM (chip RAM) size from ARM-CR4 CAP + per-bank
 * BANKINFO registers.  Returns 0 on success and fills *ramsize_p.
 */
static int
brcm_pci_ramsize_query(struct brcm_pci_softc *sc, uint32_t *ramsize_p)
{
	uint32_t cr4_base = 0;
	uint32_t cap, info, blksize;
	uint32_t totb, nab, nbb;
	uint32_t memsize = 0, idx;
	int i, rc;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_ARM_CR4) {
			cr4_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cr4_base == 0)
		return (ENOENT);

	/* CAP + BANKIDX/BANKINFO reads require ARM-CR4 clock on. */
	rc = brcm_pci_core_enable(sc, BRCM_CORE_ARM_CR4,
	    BRCM_ARMCR4_IOCTL_CPUHALT);
	if (rc != 0)
		return (rc);

	brcm_pci_set_window(sc, cr4_base);
	cap = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_ARMCR4_CAP & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	nab = cap & BRCM_ARMCR4_TCBANB_MASK;
	nbb = (cap & BRCM_ARMCR4_TCBBNB_MASK) >> BRCM_ARMCR4_TCBBNB_SHIFT;
	totb = nab + nbb;
	PDPRINTF(sc, 0,
	    "ramsize_query: ARM-CR4 CAP=0x%08x A-banks=%u B-banks=%u total=%u\n",
	    cap, nab, nbb, totb);

	for (idx = 0; idx < totb; idx++) {
		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_ARMCR4_BANKIDX & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
		    idx);
		info = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_ARMCR4_BANKINFO & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		blksize = (info & BRCM_ARMCR4_BLK_1K_MASK) ?
		    1024 : BRCM_ARMCR4_BSZ_MULT;
		memsize += ((info & BRCM_ARMCR4_BSZ_MASK) + 1) * blksize;
		PDPRINTF(sc, 0,
		    "ramsize_query:   bank %u INFO=0x%08x blk=%u "
		    "size=%u running total=%u\n",
		    idx, info, blksize,
		    ((info & BRCM_ARMCR4_BSZ_MASK) + 1) * blksize, memsize);
	}
	*ramsize_p = memsize;
	PDPRINTF(sc, 0,
	    "ramsize_query: total RAM = %u bytes (0x%x)\n",
	    memsize, memsize);
	return (0);
}

/*
 * Upload the minimal synthetic NVRAM to chip TCM and append the trailer
 * firmware uses to find it:
 *
 *   TCM[rambase + ramsize - nvram_len_padded - 4] = NVRAM bytes
 *   TCM[rambase + ramsize - 4]                    = trailer dword
 *
 *   trailer = (~len_low16) << 16 | (len/4) & 0xffff
 *
 * After ARM release, firmware walks down from TCM end, reads the
 * trailer, validates the inverted-length checksum, then parses the
 * NVRAM bytes preceding it.  The trailer doubles as the handshake
 * cell: firmware overwrites it with its shared-memory structure
 * pointer once init completes, which is what wait_fw_ready polls for.
 *
 * Returns 0 on success.  Run after load_fw and before armcr4_release.
 */
/*
 * Random-seed prelude for Apple chips: 256 bytes of random data
 * followed by an 8-byte {length, magic} footer just below the NVRAM.
 * Off by default (dev.brcm_pci_nvram_seed_enable): with it on, the
 * BCM43602 firmware never writes sharedram_addr, and the right
 * condition and format for the seed are not known.
 */
#define	BRCM_PCI_RANDOM_SEED_LENGTH	0x100u
#define	BRCM_PCI_RANDOM_SEED_MAGIC	0xfeedc0deu

static int brcm_pci_nvram_seed_enable = 0;
SYSCTL_INT(_dev, OID_AUTO, brcm_pci_nvram_seed_enable, CTLFLAG_RWTUN,
    &brcm_pci_nvram_seed_enable, 0,
    "Emit random-seed prelude in nvram_inject (0=off, 1=on).");

static int
brcm_pci_nvram_inject(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint32_t ramsize, off, trailer;
	uint32_t nvram_len, nvram_len_padded;
	uint32_t seed_footer_off, seed_bytes_off;
	uint8_t randbuf[BRCM_PCI_RANDOM_SEED_LENGTH];
	size_t i;
	int error;
	bool use_seed = (brcm_pci_nvram_seed_enable != 0);

	error = brcm_pci_ramsize_query(sc, &ramsize);
	if (error != 0)
		return (error);

	/*
	 * Compute padded length.  The blob is built as a series of
	 * NUL-terminated key=value pairs followed by an extra NUL;
	 * brcmf treats the final \0\0 as the terminator.  Strip the
	 * compiler's automatic trailing \0 from sizeof to match.
	 */
	nvram_len = (uint32_t)(sizeof(brcm_pci_minimal_nvram) - 1);
	nvram_len_padded = (nvram_len + 3) & ~3U;

	{
		uint32_t need = nvram_len_padded + 4;
		if (use_seed)
			need += 8 + BRCM_PCI_RANDOM_SEED_LENGTH;
		if (need > ramsize) {
			device_printf(dev,
			    "nvram_inject: needed %u > ramsize %u\n",
			    need, ramsize);
			return (EFBIG);
		}
	}

	{
	uint32_t rambase = sc->sc_chip ? sc->sc_chip->rambase :
	    BRCM_PCI_RAMBASE_43602;
	off = rambase + ramsize - nvram_len_padded - 4;
	seed_footer_off = off - 8;
	seed_bytes_off = seed_footer_off - BRCM_PCI_RANDOM_SEED_LENGTH;

	if (use_seed) {
		PDPRINTF(sc, 0,
		    "nvram_inject: nvram=%u@BAR2+0x%x trailer@BAR2+0x%x "
		    "seed_footer@BAR2+0x%x seed_bytes(256)@BAR2+0x%x\n",
		    nvram_len, off, rambase + ramsize - 4,
		    seed_footer_off, seed_bytes_off);
	} else {
		PDPRINTF(sc, 0,
		    "nvram_inject: writing %u bytes (padded %u) at BAR2+0x%x; "
		    "trailer at BAR2+0x%x\n",
		    nvram_len, nvram_len_padded, off,
		    rambase + ramsize - 4);
	}
	}

	/* Byte-by-byte write of the NVRAM body. */
	for (i = 0; i < nvram_len; i++) {
		bus_space_write_1(sc->sc_bar2_t, sc->sc_bar2_h, off + i,
		    (uint8_t)brcm_pci_minimal_nvram[i]);
	}
	/* Zero-pad the tail to 4-byte alignment. */
	for (i = nvram_len; i < nvram_len_padded; i++) {
		bus_space_write_1(sc->sc_bar2_t, sc->sc_bar2_h, off + i, 0);
	}

	if (use_seed) {
		/*
		 * Random-seed footer + entropy layout:
		 *   [seed_bytes_off .. +0x100) 256 bytes entropy
		 *   [seed_footer_off .. +8)    {length=0x100, magic=0xfeedc0de}
		 *   [nvram_off .. +nvram)      key=value\0 pairs
		 *   [ramsize-4]                NVRAM trailer / handshake cell
		 */
		arc4random_buf(randbuf, sizeof(randbuf));
		for (i = 0; i < sizeof(randbuf); i++) {
			bus_space_write_1(sc->sc_bar2_t, sc->sc_bar2_h,
			    seed_bytes_off + i, randbuf[i]);
		}
		bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    seed_footer_off + 0,
		    htole32(BRCM_PCI_RANDOM_SEED_LENGTH));
		bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    seed_footer_off + 4,
		    htole32(BRCM_PCI_RANDOM_SEED_MAGIC));
	}

	/*
	 * Trailer dword:
	 *   low16  = dword count of the padded nvram payload
	 *   high16 = ones' complement of low16
	 * Firmware reads the trailer, validates ~low16 == high16, and
	 * trusts the low16 as the dword count to scan back through.
	 */
	{
		uint16_t dwords = (uint16_t)(nvram_len_padded / 4);
		uint16_t inv = (uint16_t)~dwords;

		uint32_t rambase = sc->sc_chip ? sc->sc_chip->rambase :
		    BRCM_PCI_RAMBASE_43602;
		trailer = ((uint32_t)inv << 16) | dwords;
		bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    rambase + ramsize - 4, trailer);
	}
	return (0);
}

/*
 * Full reset cycle on SOCRAM, specific to the BCM43602.
 *
 * The 43602's SOCRAM controller caches bus state that goes stale
 * once the firmware has been copied to TCM; without this reset the
 * ARM-CR4 fetches garbage on its first instruction load and faults
 * immediately (the ARM runs but makes no memory writes).
 *
 * Equivalent to brcmf_chip_resetcore(SOCRAM, 0, 0, 0):
 *   1. ai_coredisable: force into reset (IOCTL = FGC|CLK, RESET_CTL=1)
 *   2. in-reset configure (IOCTL = FGC|CLK with reset=0 fields)
 *   3. poll RESET_CTL writing 0 until clear
 *   4. final IOCTL = CLK only
 *
 * brcm_pci_bringup_sequence calls it as step 5, before
 * load_firmware, and skips the post-upload step 7.  That differs
 * from Linux, which runs this same resetcore on 43602 after the
 * upload, in brcmf_pcie_exit_download_state.
 */
static int
brcm_pci_exit_download_state(struct brcm_pci_softc *sc)
{
	uint32_t wrap = 0;
	uint32_t v;
	int i, count;

	if (!sc->sc_chip_alive)
		return (ENXIO);

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_SOCRAM) {
			wrap = sc->sc_cores[i].wrap;
			break;
		}
	}
	if (wrap == 0) {
		device_printf(sc->sc_dev,
		    "exit_download_state: no SOCRAM core wrap; skipping\n");
		return (ENOENT);
	}

	brcm_pci_set_window(sc, wrap);

	/* 1. Pre-reset IOCTL = 0 | FGC | CLK. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_IOCTL_FGC | BRCM_BCMA_IOCTL_CLK);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	/* 2. Put in reset. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_RESET_CTL_RESET);
	DELAY(20);

	/* 3. Spin until RESET_CTL reads back as 1. */
	count = 0;
	while ((bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK) &
	    BRCM_BCMA_RESET_CTL_RESET) == 0) {
		if (++count > 300)
			break;
		DELAY(10);
	}

	/* 4. In-reset configure: IOCTL = FGC|CLK (reset field is 0). */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_IOCTL_FGC | BRCM_BCMA_IOCTL_CLK);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	/* 5. Release reset — poll writing 0. */
	count = 0;
	while ((bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK) &
	    BRCM_BCMA_RESET_CTL_RESET) != 0) {
		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0);
		if (++count > 50)
			break;
		DELAY(50);
	}

	/* 6. Postreset: IOCTL = CLK only. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_IOCTL_CLK);
	v = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	PDPRINTF(sc, 0,
	    "exit_download_state: SOCRAM resetcore complete (IOCTL=0x%08x)\n",
	    v);
	return (0);
}

/*
 * BCM43602 PMU init tables, from Apple's AirPortBrcmNIC.kext
 * (_bcm43602_res_updown 32 B, _bcm43602_res_depend 96 B,
 * _bcm43602_res_pciewar 192 B).
 *
 * Its si_pmu_res_init walks each table backwards from table_end-8
 * to table_start, with a per-chip entry count:
 *   updown: count=3   (the last 8 B entry is a zeroed sentinel)
 *   depend: count=4
 *   pciewar: count=8
 *
 * res_updown entry layout (8 B):
 *   +0..3: u32 resnum       (only low byte used as resource index)
 *   +4..7: u32 updn_val     (written to RES_UPDN_TIMER 0x628)
 *
 * res_depend / res_pciewar entry layout (24 B each):
 *   +0..3:  u32 res_mask    (bitmap of resources to touch)
 *   +4..7:  u32 action      (1=OR add, 2=AND with ~mask, 3=SET)
 *   +8..11: u32 dep_mask    (dependency bits to apply)
 *   +12..23: padding (zeros)
 *
 * For each entry the walker does, per bit set in res_mask:
 *   RES_TABLE_SEL (0x620) = res_index
 *   read RES_DEP_MASK (0x624) -> cur
 *   apply action(cur, dep_mask) -> new
 *   RES_DEP_MASK (0x624) = new
 *
 * pciewar is applied after depend through the same code path; it
 * adds PCIe-related dependencies on top of the base graph.
 */

static const uint8_t bcm43602_res_updown[32] = {
	0x0d, 0x00, 0x00, 0x00, 0x19, 0x00, 0x19, 0x00,
	0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x00,
	0x15, 0x00, 0x00, 0x00, 0x05, 0x00, 0x43, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t bcm43602_res_depend[96] = {
	0x00, 0xf2, 0xef, 0x01, 0x01, 0x00, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x80, 0x73, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x80, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xe8, 0x01, 0xff, 0x00, 0x00, 0x00,
	0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t bcm43602_res_pciewar[192] = {
	0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x16, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static inline uint32_t
brcm_pci_pmu_read(struct brcm_pci_softc *sc, uint32_t off)
{
	return (bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    off & BRCM_PCI_BAR0_WINDOW_OFF_MASK));
}

static inline void
brcm_pci_pmu_write(struct brcm_pci_softc *sc, uint32_t off, uint32_t val)
{
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    off & BRCM_PCI_BAR0_WINDOW_OFF_MASK, val);
}

/*
 * Apply one dep-table entry: for each bit set in res_mask, select the
 * resource via RES_TABLE_SEL then RMW its RES_DEP_MASK per action.
 * Actions, as in Apple's si_pmu_res_dep_apply:
 *   1 = OR   (add deps)
 *   2 = AND-NOT (remove deps)
 *   3 = SET   (replace deps)
 */
static void
brcm_pci_pmu_dep_apply(struct brcm_pci_softc *sc, const char *tag,
    int idx, uint32_t res_mask, uint32_t action, uint32_t dep_mask)
{
	uint32_t cur, new;
	int bit;

	if (res_mask == 0)
		return;
	PDPRINTF(sc, 0,
	    "pmu_init: %s[%d] res_mask=0x%08x action=%u dep_mask=0x%08x\n",
	    tag, idx, res_mask, action, dep_mask);
	for (bit = 0; bit < 32; bit++) {
		if ((res_mask & (1u << bit)) == 0)
			continue;
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_TABLE_SEL, bit);
		cur = brcm_pci_pmu_read(sc, BRCM_CC_PMU_RES_DEP_MASK);
		switch (action) {
		case 1:  new = cur | dep_mask; break;
		case 2:  new = cur & ~dep_mask; break;
		case 3:  new = dep_mask; break;
		default: new = cur; break;
		}
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_DEP_MASK, new);
		PDPRINTF(sc, 0,
		    "pmu_init: %s[%d] res %2d: DEP 0x%08x -> 0x%08x\n",
		    tag, idx, bit, cur, new);
	}
}

/*
 * BCM43602 si_pmu_res_init, applying the tables above the way Apple's
 * AirPortBrcmNIC does.  On cold silicon this must run before firmware
 * upload so the PMU resource-dependency graph and up/down timers match
 * what the firmware's PA init assumes.
 */
static int
brcm_pci_pmu_init_43602(struct brcm_pci_softc *sc)
{
	uint32_t cc_base = 0;
	uint32_t reg, val, res_mask, action, dep_mask, updn;
	uint8_t resnum;
	const uint8_t *e;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cc_base == 0) {
		device_printf(sc->sc_dev,
		    "pmu_init: ChipCommon base unknown; run core_walk first\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, cc_base);

	reg = brcm_pci_pmu_read(sc, BRCM_CC_PMU_CAP);
	PDPRINTF(sc, 0,
	    "pmu_init: pmucap=0x%08x pmurev=%u num_res=%u\n",
	    reg, reg & 0xff, (reg >> 8) & 0xff);
	reg = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MIN_RES_MASK);
	val = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MAX_RES_MASK);
	PDPRINTF(sc, 0,
	    "pmu_init: min_res_mask=0x%08x max_res_mask=0x%08x (before)\n",
	    reg, val);

	/* res_updown: 3 entries + 1 sentinel; skip resnum == 0. */
	for (i = 0; i < 3; i++) {
		e = bcm43602_res_updown + i * 8;
		resnum = e[0];
		updn = e[4] | (e[5] << 8) | (e[6] << 16) | (e[7] << 24);
		if (resnum == 0)
			continue;
		PDPRINTF(sc, 0,
		    "pmu_init: updown[%d] res %u updn=0x%08x\n",
		    i, resnum, updn);
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_TABLE_SEL, resnum);
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_UPDN_TIMER, updn);
	}

	/* res_depend: 4 entries × 24 B. */
	for (i = 0; i < 4; i++) {
		e = bcm43602_res_depend + i * 24;
		res_mask = e[0] | (e[1] << 8) | (e[2] << 16) | (e[3] << 24);
		action   = e[4] | (e[5] << 8) | (e[6] << 16) | (e[7] << 24);
		dep_mask = e[8] | (e[9] << 8) | (e[10] << 16) | (e[11] << 24);
		brcm_pci_pmu_dep_apply(sc, "depend", i, res_mask, action,
		    dep_mask);
	}

	/* res_pciewar: 8 entries × 24 B, same walker as depend. */
	for (i = 0; i < 8; i++) {
		e = bcm43602_res_pciewar + i * 24;
		res_mask = e[0] | (e[1] << 8) | (e[2] << 16) | (e[3] << 24);
		action   = e[4] | (e[5] << 8) | (e[6] << 16) | (e[7] << 24);
		dep_mask = e[8] | (e[9] << 8) | (e[10] << 16) | (e[11] << 24);
		brcm_pci_pmu_dep_apply(sc, "pciewar", i, res_mask, action,
		    dep_mask);
	}

	DELAY(1000);

	reg = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MIN_RES_MASK);
	val = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MAX_RES_MASK);
	PDPRINTF(sc, 0,
	    "pmu_init: min_res_mask=0x%08x max_res_mask=0x%08x (after)\n",
	    reg, val);
	reg = brcm_pci_pmu_read(sc, BRCM_CC_PMU_RES_STATE);
	PDPRINTF(sc, 0,
	    "pmu_init: res_state=0x%08x (after)\n", reg);

	return (0);
}

/*
 * BCM4360 si_pmu_res_init, as in Apple's older AirPortBrcm4360.kext:
 *
 *   _bcm4360_res_updown   (rev < 4), 1 entry (8 B)
 *     { resnum=6, updn=0x00200001 }
 *   _bcm4360B1_res_updown (rev >= 4), 1 entry (8 B)
 *     { resnum=4, updn=0x00430002 }
 *
 * PCIe-war (chip 0x4360 rev < 4, byte[0x48] bit 0x20 clear):
 *   RES_TABLE_SEL = 6;     RES_DEP_MASK = 0x09048562
 *   RES_TABLE_SEL = 0xe;   RES_DEP_MASK = 0x09048562
 *
 * This is much smaller than the 43602 set (3 updown, 4 depend and
 * 8 pciewar entries).
 */
static int
brcm_pci_pmu_init_4360(struct brcm_pci_softc *sc)
{
	uint32_t cc_base = 0;
	uint32_t reg, val;
	uint8_t rev = sc->sc_revid;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cc_base == 0) {
		device_printf(sc->sc_dev,
		    "pmu_init_4360: ChipCommon base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, cc_base);

	uint32_t max_res, min_res;

	reg = brcm_pci_pmu_read(sc, BRCM_CC_PMU_CAP);
	min_res = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MIN_RES_MASK);
	max_res = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MAX_RES_MASK);
	val = brcm_pci_pmu_read(sc, BRCM_CC_PMU_RES_STATE);
	PDPRINTF(sc, 0,
	    "pmu_init_4360: CAP=0x%08x MIN_RES=0x%08x MAX_RES=0x%08x "
	    "STATE=0x%08x (chiprev=%u)\n",
	    reg, min_res, max_res, val, rev);

	/*
	 * Only touch resources that exist in MAX_RES_MASK.  Apple's 4360
	 * path writes res 0xe (14), which exists on Apple boards but not
	 * on every BCM4360: a rev 3 M.2 card has MAX_RES = 0x0000013f
	 * (res 0-5 and 8).  Writing DEP for a resource that does not
	 * exist wedges the backplane.
	 */
#define PMU_MAYBE_UPDN(resnum, updn) do {				\
	if (max_res & (1u << (resnum))) {				\
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_TABLE_SEL, (resnum)); \
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_UPDN_TIMER, (updn)); \
		PDPRINTF(sc, 0,						\
		    "pmu_init_4360: updown res %u = 0x%08x\n",		\
		    (resnum), (updn));					\
	} else {							\
		PDPRINTF(sc, 0,						\
		    "pmu_init_4360: updown res %u NOT in max_res, skip\n", \
		    (resnum));						\
	}								\
} while (0)

#define PMU_MAYBE_DEP(resnum, dep) do {					\
	if (max_res & (1u << (resnum))) {				\
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_TABLE_SEL, (resnum)); \
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_RES_DEP_MASK, (dep));	\
		PDPRINTF(sc, 0,						\
		    "pmu_init_4360: dep res %u = 0x%08x\n",		\
		    (resnum), (dep));					\
	} else {							\
		PDPRINTF(sc, 0,						\
		    "pmu_init_4360: dep res %u NOT in max_res, skip\n",	\
		    (resnum));						\
	}								\
} while (0)

	if (rev < 4) {
		PMU_MAYBE_UPDN(6, 0x00200001);
		PMU_MAYBE_DEP(6, 0x09048562);
		PMU_MAYBE_DEP(0xe, 0x09048562);
	} else {
		PMU_MAYBE_UPDN(4, 0x00430002);
	}

#undef PMU_MAYBE_UPDN
#undef PMU_MAYBE_DEP

	DELAY(1000);

	min_res = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MIN_RES_MASK);
	max_res = brcm_pci_pmu_read(sc, BRCM_CC_PMU_MAX_RES_MASK);
	val = brcm_pci_pmu_read(sc, BRCM_CC_PMU_RES_STATE);
	PDPRINTF(sc, 0,
	    "pmu_init_4360: MIN_RES=0x%08x MAX_RES=0x%08x STATE=0x%08x (after)\n",
	    min_res, max_res, val);
	return (0);
}

/*
 * BCM43602 PLL calibration, as macOS AirPortBrcmNIC programs it:
 *   ChangeVCO => vco:960, xtalF:40, frac: 98, ndivMode: 3, ndivint: 24
 *   PLL_CNTRL_ADDR2 = 0x00000c31
 *   PLL_CNTRL_ADDR3 (Fractional) = 0x0000100e
 *
 * These are per-board PLL constants Apple's driver writes before
 * firmware upload; the firmware likely stalls without the RF PLL
 * configured.
 *
 * Access pattern is standard Broadcom PMU indirect:
 *   PLLCONTROL_ADDR (cc+0x660) = plli index
 *   PLLCONTROL_DATA (cc+0x664) = value
 * A dummy read of ADDR barriers the index write.
 */
static int
brcm_pci_pll_init_43602(struct brcm_pci_softc *sc)
{
	static const struct { uint32_t idx; uint32_t val; } pll_writes[] = {
		{ 2, 0x00000c31 },   /* PLL_CNTRL_ADDR2 */
		{ 3, 0x0000100e },   /* PLL_CNTRL_ADDR3 (Fractional) */
	};
	uint32_t cc_base = 0, readback;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cc_base == 0) {
		device_printf(sc->sc_dev,
		    "pll_init: ChipCommon base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, cc_base);

	for (i = 0; i < (int)nitems(pll_writes); i++) {
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_PLLCONTROL_ADDR,
		    pll_writes[i].idx);
		(void)brcm_pci_pmu_read(sc, BRCM_CC_PMU_PLLCONTROL_ADDR);
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_PLLCONTROL_DATA,
		    pll_writes[i].val);
		/* Read back for logging: re-select, then read data. */
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_PLLCONTROL_ADDR,
		    pll_writes[i].idx);
		(void)brcm_pci_pmu_read(sc, BRCM_CC_PMU_PLLCONTROL_ADDR);
		readback = brcm_pci_pmu_read(sc, BRCM_CC_PMU_PLLCONTROL_DATA);
		PDPRINTF(sc, 0,
		    "pll_init: PLLCONTROL[%u] wrote 0x%08x, readback 0x%08x\n",
		    pll_writes[i].idx, pll_writes[i].val, readback);
	}

	/*
	 * PLL_INIT trigger: Apple's BCMWL_UNDI DXE PLL programmer sets
	 * PMU_CTL bit 0x400 (read-modify-write) after all PLLCTL writes,
	 * which makes the PLL adopt the new values.  Without it the
	 * PLLCTL registers hold the values but the running PLL keeps
	 * its previous programming.
	 */
	{
		uint32_t pmu_ctl = brcm_pci_pmu_read(sc, BRCM_CC_PMU_CTRL);
		PDPRINTF(sc, 0,
		    "pll_init: PMU_CTL before = 0x%08x\n", pmu_ctl);
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_CTRL, pmu_ctl | 0x400);
		(void)brcm_pci_pmu_read(sc, BRCM_CC_PMU_CTRL);
		DELAY(100);
		readback = brcm_pci_pmu_read(sc, BRCM_CC_PMU_CTRL);
		PDPRINTF(sc, 0,
		    "pll_init: PMU_CTL after |= 0x400 = 0x%08x (self-clears)\n",
		    readback);
	}
	return (0);
}

/*
 * Chip-wide watchdog reset.  Disable ASPM (so the chip can't
 * autonomously enter L1 mid-reset), write 4 to ChipCommon.watchdog
 * (fires after 4 ticks), sleep 100 ms for the chip to come back,
 * restore ASPM.
 *
 * After this:
 *   - PCIe link comes back up on its own (PCIe2 core handles the
 *     link layer; the chip reset only re-inits internal cores).
 *   - The WAPS shadow (chip-side subsystem-ID program) is lost, and
 *     nothing in the driver reprograms it.  Bring-up only resets a
 *     chip that is not already alive, which ordinary reboots never
 *     produce.
 *   - EC.APWC is unaffected (EC is external).
 *   - sc_chip_alive stays true because the chip's PCIe interface
 *     is still up; sc_bar2_sized is cleared because BAR2_CONFIG
 *     reverts to its post-reset default and needs to be re-sized.
 */
static int
brcm_pci_chip_reset(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	int pcie_cap;
	uint16_t lcr_saved;
	uint32_t cc_base = 0;
	int i;

	/*
	 * Cold-chip guard.  Use the config-space check, which the root
	 * complex terminates and so cannot wedge, not a BAR0 check, which
	 * would wedge before it could print.  Mirrors macOS
	 * OLYHAL::verifyPCIeDevice and the check in
	 * AppleBCMWLANBusInterfacePCIe::attachPCIeBusGated.
	 *
	 * Passing it does not prove BAR0 MMIO is safe: the watchdog write
	 * below is posted so it cannot wedge, but a later BAR0 read can if
	 * the backplane clock is off.
	 */
	if (!brcm_pci_chip_alive_cfg(sc))
		return (ENXIO);

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	/*
	 * Before core_walk has run (chip_reset needs cc_base, core_walk
	 * needs the warm chip chip_reset provides), fall back to
	 * BRCM_BACKPLANE_CHIPCOMMON (0x18000000), where every BCM43xx PCIe
	 * part places ChipCommon.
	 */
	if (cc_base == 0)
		cc_base = BRCM_BACKPLANE_CHIPCOMMON;

	if (cc_base == 0) {
		device_printf(dev,
		    "chip_reset: ChipCommon base unknown; "
		    "run core_walk first\n");
		return (ENOENT);
	}

	/* ASPM off. */
	if (pci_find_cap(dev, PCIY_EXPRESS, &pcie_cap) != 0) {
		device_printf(dev, "chip_reset: no PCIe cap\n");
		return (ENXIO);
	}
	lcr_saved = pci_read_config(dev, pcie_cap + PCIER_LINK_CTL, 2);
	pci_write_config(dev, pcie_cap + PCIER_LINK_CTL,
	    lcr_saved & ~PCIEM_LINK_CTL_ASPMC, 2);

	/* Watchdog: fire in 4 ticks. */
	PDPRINTF(sc, 0,
	    "chip_reset: writing 4 to ChipCommon.watchdog @0x%08x\n",
	    cc_base + BRCM_CC_REG_WATCHDOG);
	brcm_pci_set_window(sc, cc_base);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_CC_REG_WATCHDOG & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 4);

	/* Let the chip reset + come back. */
	DELAY(100000);	/* 100 ms */

	/* Restore ASPM. */
	pci_write_config(dev, pcie_cap + PCIER_LINK_CTL, lcr_saved, 2);

	/* BAR2 needs re-sizing; WAPS shadow needs re-asserting. */
	sc->sc_bar2_sized = false;

	PDPRINTF(sc, 0,
	    "chip_reset: watchdog issued + 100ms settle; sc_bar2_sized "
	    "cleared.  Re-run waps_redo then size_bar2.\n");
	return (0);
}

/* Defined later, called from brcm_pci_bringup_sequence(). */
static int brcm_pci_enter_download_state(struct brcm_pci_softc *sc);
static int brcm_pci_enter_download_state_generic(struct brcm_pci_softc *sc);
static int brcm_pci_load_firmware(struct brcm_pci_softc *sc);

/*
 * Poll TCM[ramsize - 4] for the FW-ready sentinel.  Firmware writes
 * the shared-RAM address there once initialized.  Poll loop is
 * 5s / 50ms.
 *
 * Returns 0 on success (and stashes sentinel in sc->sc_fw_sharedram),
 * ETIMEDOUT if the sentinel stays 0 after `timeout_ms`.
 */
static int
brcm_pci_wait_fw_ready(struct brcm_pci_softc *sc, uint32_t ramsize,
    int timeout_ms)
{
	uint32_t sharedram_addr;
	uint32_t rambase = sc->sc_chip ? sc->sc_chip->rambase :
	    BRCM_PCI_RAMBASE_43602;
	int i, iters = timeout_ms / 50;

	for (i = 0; i < iters; i++) {
		DELAY(50000);	/* 50 ms */
		sharedram_addr = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    rambase + ramsize - 4);
		/*
		 * Non-zero alone is insufficient: nvram_inject just wrote a
		 * trailer there and FW hasn't overwritten yet.  Require
		 * the value to be a TCM address inside
		 * [rambase, rambase+ramsize).  For rambase=0 chips (4360)
		 * this permits any low address as a valid sentinel.
		 */
		if (sharedram_addr >= rambase &&
		    sharedram_addr < rambase + ramsize) {
			PDPRINTF(sc, 0,
			    "wait_fw_ready: FW alive after %d ms, "
			    "sharedram_addr=0x%08x\n",
			    (i + 1) * 50, sharedram_addr);
			sc->sc_fw_sharedram = sharedram_addr;
			return (0);
		}
	}
	device_printf(sc->sc_dev,
	    "wait_fw_ready: FW failed to initialize (sentinel still 0 "
	    "after %d ms)\n",
	    timeout_ms);
	return (ETIMEDOUT);
}

/*
 * Chip bring-up, run by the autostart thread or by
 *
 *     sysctl dev.brcm_pci.0.bringup=1
 *
 * With debug output on, each step logs "STARTING" and "DONE", so if a
 * step wedges the machine the last STARTING line names it.
 *
 * Steps:
 *   1. chip_reset (watchdog + ASPM cycle); skipped, see below
 *   2. core_walk, which populates sc_cores[]
 *   3. pcie2cfg_restore; skipped along with chip_reset
 *   4. PMU and PLL init (chip specific), then ramsize_query
 *   5. enter_download_state (BANKPDA 5,7 cleared), plus the SOCRAM
 *      reset on the 43602
 *   6. load_firmware, the image to TCM
 *   7. exit_download_state; skipped, see below
 *   8. nvram_inject, NVRAM to high TCM
 *   9. armcr4_release, reset vector written and CPUHALT off
 *  10. wait_fw_ready, polling the ramsize-4 sentinel (5s)
 */
static int
brcm_pci_bringup_sequence(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint32_t ramsize = 0;
	int rc;

	/*
	 * Per-chip gate.  Bring-up is implemented only for the BCM43602;
	 * running the 43602-specific PMU init, PLL init and SOCRAM bank
	 * power-up on other chip families wedges the backplane, so refuse
	 * early.  The brcm_pci_chip_table comments say what each chip
	 * needs before bringup_supported can be set.
	 */
	if (sc->sc_chip == NULL || !sc->sc_chip->bringup_supported) {
		device_printf(dev,
		    "bringup: refusing - chip devid 0x%04x %s.  "
		    "See brcm_pci_chip_table in if_brcm_pci.c for what to "
		    "implement to enable this chip.\n",
		    sc->sc_devid,
		    sc->sc_chip ? sc->sc_chip->notes : "unknown");
		return (EOPNOTSUPP);
	}

/*
 * One bring-up step: log it, run it, stop the sequence on failure.  The
 * quarter-second pauses either side are settle time for the chip.
 */
#define BRINGUP_STEP(n, name, expr) do {                                  \
	PDPRINTF(sc, 0, "bringup: step %d " name " STARTING\n", (n));      \
	pause("bringup", hz / 4);                                         \
	rc = (expr);                                                      \
	if (rc != 0) {                                                    \
		device_printf(dev,                                        \
		    "bringup: step %d " name " FAILED rc=%d\n", (n), rc); \
		goto fail;                                                \
	}                                                                 \
	PDPRINTF(sc, 0, "bringup: step %d " name " DONE\n", (n));          \
	pause("bringup", hz / 4);                                         \
} while (0)

	/*
	 * Cold-chip pre-flight before any step.  Use the config-space
	 * test: a BAR0-based check itself wedges on a cold backplane,
	 * while config space is served by the root complex and always
	 * returns.
	 */
	if (!brcm_pci_chip_alive_cfg(sc)) {
		device_printf(dev,
		    "bringup: refusing - PCIe cfg-space says chip is absent "
		    "or link is down.\n");
		return (ENXIO);
	}

	/*
	 * Escape hatch: chip_reset's own gate refuses when sc_chip_alive
	 * is false.  Force true for the duration; on failure we clear it
	 * so later per-sysctl pokes don't blindly touch BAR0.
	 */
	sc->sc_chip_alive = true;

	/*
	 * chip_reset is skipped unconditionally once the config-space
	 * check passes.  If APPU brought the chip up at attach the PCIe
	 * link is healthy, and chip_reset's watchdog write is not
	 * deterministic on real hardware: it wedges the fabric
	 * intermittently.  If APPU was not enough and the backplane is
	 * really cold, the first BAR0 read in core_walk fails cleanly (or
	 * wedges, if AER is not configured).
	 */
	if (true) {
		PDPRINTF(sc, 0, "bringup: step 1 chip_reset SKIPPED "
		    "(cfg says alive; chip_reset watchdog write is "
		    "non-deterministic on bare metal)\n");
	} else {
		BRINGUP_STEP(1, "chip_reset (watchdog + ASPM cycle)",
		    brcm_pci_chip_reset(sc));
	}
	BRINGUP_STEP(2, "core_walk (EROM)", brcm_pci_walk_cores(sc));
	/* pcie2cfg_restore is only needed after chip_reset, also skipped. */
	PDPRINTF(sc, 0, "bringup: step 3 pcie2cfg_restore SKIPPED\n");

	if (sc->sc_devid == BRCM_PCI_DEVICE_BCM43602) {
		/*
		 * PMU init: Apple's resource-dependency and up/down timer
		 * tables for the BCM43602.  Must happen before firmware
		 * upload; the firmware's PA init assumes it.
		 */
		BRINGUP_STEP(4, "pmu_init_43602 (Apple PMU tables)",
		    brcm_pci_pmu_init_43602(sc));
		/* Apple's board-specific PLL calibration constants. */
		BRINGUP_STEP(4, "pll_init_43602 (Apple PLL calibration)",
		    brcm_pci_pll_init_43602(sc));
	} else if (sc->sc_devid == BRCM_PCI_DEVICE_BCM4360 ||
	    sc->sc_devid == BRCM_PCI_DEVICE_BCM4360_2) {
		/*
		 * BCM4360 has its own PMU init (from Apple's older
		 * AirPortBrcm4360.kext): one res_updown entry and two
		 * pciewar dep_mask writes.
		 */
		BRINGUP_STEP(4, "pmu_init_4360 (Apple 4360 PMU)",
		    brcm_pci_pmu_init_4360(sc));
		PDPRINTF(sc, 0,
		    "bringup: step 4 pll_init SKIPPED (4360 uses chip "
		    "defaults per Apple decomp)\n");
	} else {
		/*
		 * Other chip families: skip PMU + PLL init entirely.
		 * Chip defaults are expected to be usable.
		 */
		PDPRINTF(sc, 0,
		    "bringup: step 4 pmu_init + pll_init SKIPPED "
		    "(no chip-specific tables ported)\n");
	}

	BRINGUP_STEP(4, "ramsize_query", brcm_pci_ramsize_query(sc, &ramsize));
	sc->sc_fw_ramsize = ramsize;
	PDPRINTF(sc, 0, "bringup: TCM ramsize=0x%x (cached)\n", ramsize);

	if (sc->sc_devid == BRCM_PCI_DEVICE_BCM43602) {
		BRINGUP_STEP(5, "enter_download_state (BANKIDX 5,7 zero)",
		    brcm_pci_enter_download_state(sc));
		/*
		 * SOCRAM sysmemReset before firmware upload: Apple's
		 * loadChipImage runs the SYSMEM wrapper reset cycle here,
		 * not after the copy.
		 */
		BRINGUP_STEP(5, "sysmem_reset_pre (SOCRAM resetcore)",
		    brcm_pci_exit_download_state(sc));
	} else {
		/*
		 * Generic download-state entry: enable the chip's memory
		 * core (BUF_MEM 0x81a on 4360) and halt the ARM CR4.  No
		 * SOCRAM bank power-up or sysmem reset; both are 43602
		 * specific.
		 */
		BRINGUP_STEP(5, "enter_download_state_generic",
		    brcm_pci_enter_download_state_generic(sc));
	}

	BRINGUP_STEP(6, "load_firmware", brcm_pci_load_firmware(sc));
	/*
	 * Step 7 exit_download_state is omitted: SOCRAM RESET_CTL=1 after
	 * the upload can wipe TCM on some 43602 silicon revisions.
	 * armcr4_release rewrites only TCM[0] (rstvec), so the ARM
	 * branches into zeroed memory, hard-faults and spins in its
	 * exception handler (IOCTL=0x1, no TCM writes, the sentinel never
	 * changes).  sysmem_reset_pre in step 5 already does the SOCRAM
	 * resetcore Apple's loadChipImage requires before the copy.
	 */
	PDPRINTF(sc, 0, "bringup: step 7 exit_download_state SKIPPED "
	    "(post-fw SOCRAM reset destroys TCM contents)\n");
	BRINGUP_STEP(8, "nvram_inject", brcm_pci_nvram_inject(sc));
	/* cold_reattach turns bus mastering off; the firmware needs it. */
	pci_enable_busmaster(dev);
	BRINGUP_STEP(9, "armcr4_release (CPUHALT off)",
	    brcm_pci_armcr4_release(sc));
	BRINGUP_STEP(10, "wait_fw_ready (poll TCM[ramsize-4])",
	    brcm_pci_wait_fw_ready(sc, ramsize, 5000));

#undef BRINGUP_STEP

	sc->sc_fw_running = true;
	PDPRINTF(sc, 0, "bringup: SUCCESS - chip warm, FW alive\n");
	return (0);

fail:
	device_printf(dev,
	    "bringup: FAILED rc=%d.  Chip may be in partial state; "
	    "use dev.brcm_pci.%d.err_dump=1 to inspect.\n",
	    rc, device_get_unit(dev));
	sc->sc_chip_alive = false;
	return (rc);
}

static int
brcm_pci_sysctl_bringup(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (sc->sc_autostart_running)
		return (EBUSY);	/* two bring-ups at once can hang */
	if (sc->sc_fw_running) {
		device_printf(sc->sc_dev,
		    "bringup: firmware already running; not uploading again\n");
		return (EALREADY);
	}
	return (brcm_pci_bringup_sequence(sc));
}

static int
brcm_pci_sysctl_chip_alive(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	return (brcm_pci_chip_alive_cfg(sc) ? 0 : ENXIO);
}

/*
 * BCM43602 pre-upload step.  Before writing the firmware to BAR2 we
 * must clear the Power-Down-Aware bit on SOCRAM banks 5 and 7,
 * otherwise those banks stay powered off and any BAR2 write that
 * targets them generates a chip-side Target Abort which propagates
 * back to the host PCIe bridge and hangs the bus.
 *
 * The mechanism is per-bank: BANKIDX selects bank, BANKPDA = 0
 * disables PDA gating.
 */
static int
brcm_pci_enter_download_state(struct brcm_pci_softc *sc)
{
	uint32_t cr4_base = 0;
	int i, rc;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_ARM_CR4) {
			cr4_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cr4_base == 0) {
		device_printf(sc->sc_dev,
		    "enter_download: ARM-CR4 core base unknown; "
		    "run core_walk first\n");
		return (ENOENT);
	}

	/*
	 * Each core's IOCTL.CLK must be on before touching its registers,
	 * or the backplane routes the transactions nowhere.  SOCRAM for
	 * the TCM writes; ARM-CR4 halted so BANKIDX/BANKPDA are reachable.
	 */
	rc = brcm_pci_core_enable(sc, BRCM_CORE_SOCRAM, 0);
	if (rc != 0) {
		device_printf(sc->sc_dev,
		    "enter_download: SOCRAM core_enable failed rc=%d\n", rc);
		return (rc);
	}
	rc = brcm_pci_core_enable(sc, BRCM_CORE_ARM_CR4,
	    BRCM_ARMCR4_IOCTL_CPUHALT);
	if (rc != 0) {
		device_printf(sc->sc_dev,
		    "enter_download: ARM-CR4 core_enable(halted) failed rc=%d\n",
		    rc);
		return (rc);
	}

	/* Bank 5: clear PDA. */
	brcm_pci_set_window(sc, cr4_base);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_ARMCR4_BANKIDX & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 5);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_ARMCR4_BANKPDA & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0);

	/* Bank 7: clear PDA. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_ARMCR4_BANKIDX & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 7);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_ARMCR4_BANKPDA & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0);

	PDPRINTF(sc, 0,
	    "enter_download: SOCRAM+ARM-CR4 clocks on; banks 5,7 powered up "
	    "(BANKIDX/BANKPDA via ARM-CR4 @0x%08x)\n", cr4_base);
	return (0);
}

/*
 * Generic version of enter_download_state for chips that use BUF_MEM
 * (0x81a; see the chip table note, bcma.h calls it USB20_DEV) instead
 * of SOCRAM.  The BCM4360 family has a single BUF_MEM aperture, so no
 * bank power-up is needed: enable the clock and halt the CPU so the
 * upload sees stable TCM.
 *
 * Uses sc->sc_chip->mem_core for the memory core ID.
 */
static int
brcm_pci_enter_download_state_generic(struct brcm_pci_softc *sc)
{
	int rc;

	if (sc->sc_chip == NULL) {
		device_printf(sc->sc_dev,
		    "enter_download_generic: sc_chip NULL\n");
		return (ENXIO);
	}

	rc = brcm_pci_core_enable(sc, sc->sc_chip->mem_core, 0);
	if (rc != 0) {
		device_printf(sc->sc_dev,
		    "enter_download_generic: mem_core 0x%03x enable "
		    "failed rc=%d\n", sc->sc_chip->mem_core, rc);
		return (rc);
	}
	rc = brcm_pci_core_enable(sc, BRCM_CORE_ARM_CR4,
	    BRCM_ARMCR4_IOCTL_CPUHALT);
	if (rc != 0) {
		device_printf(sc->sc_dev,
		    "enter_download_generic: ARM-CR4 halted enable "
		    "failed rc=%d\n", rc);
		return (rc);
	}
	PDPRINTF(sc, 0,
	    "enter_download_generic: mem_core 0x%03x + ARM-CR4 halted OK\n",
	    sc->sc_chip->mem_core);
	return (0);
}

static int
brcm_pci_load_firmware(struct brcm_pci_softc *sc)
{
	const struct firmware *fw;
	const uint32_t *src;
	size_t nwords, i;
	uint32_t verify, resetintr;
	int mismatches;
	uint32_t dst_off;
	bus_size_t bar2_size;
	char verstr[BRCM_PCI_FW_VERSTRING_MAX];
	const uint8_t *p;
	size_t vs_off, vs_len;

	if (sc->sc_bar2 == NULL) {
		device_printf(sc->sc_dev,
		    "load_fw: BAR2 not allocated; cannot upload\n");
		return (ENXIO);
	}
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "load_fw: refusing — sc_chip_alive is false\n");
		return (ENXIO);
	}

	{
		const char *fwname = (sc->sc_chip && sc->sc_chip->fw_name) ?
		    sc->sc_chip->fw_name : BRCM_PCI_FW_43602;
		/*
		 * Keep the image from the first upload until detach, so a
		 * later re-upload never goes back to firmware(9), which may
		 * have to load the module from disk.
		 */
		if (sc->sc_fw == NULL)
			sc->sc_fw = firmware_get(fwname);
		fw = sc->sc_fw;
		if (fw == NULL) {
			device_printf(sc->sc_dev,
			    "load_fw: firmware_get(\"%s\") failed; "
			    "kldload the corresponding brcm_pci_fw_* module\n",
			    fwname);
			return (ENOENT);
		}
	}
	/*
	 * Firmware images are not always a multiple of 4 bytes (635449
	 * bytes for v7.35.177.61, one byte past the last dword).  The
	 * ARM-CR4 never fetches past the last symbol, so the tail word is
	 * zero-padded and the whole upload is done in dwords.
	 */

	bar2_size = rman_get_size(sc->sc_bar2);
	dst_off = sc->sc_chip ? sc->sc_chip->rambase : BRCM_PCI_RAMBASE_43602;
	PDPRINTF(sc, 0,
	    "load_fw: BAR2=%ju bytes, rambase=0x%x, fw datasize=%zu\n",
	    (uintmax_t)bar2_size, dst_off, fw->datasize);
	if (dst_off + fw->datasize > bar2_size) {
		device_printf(sc->sc_dev,
		    "load_fw: dst 0x%x + size %zu > BAR2 size %ju\n",
		    dst_off, fw->datasize, (uintmax_t)bar2_size);
		return (EFBIG);
	}

	/*
	 * Power up TCM before writing.  On 43602 this powers up SOCRAM
	 * banks 5+7; on generic chips (4360-family) it just enables the
	 * BUF_MEM aperture.  Skipping means BAR2 writes hit unpowered
	 * mem and the chip Target-Aborts, hanging host PCIe.
	 *
	 * Bring-up step 5 already ran the same helper, but calling it
	 * again is harmless (core_enable polls RESET_CTL until 0, then
	 * sets IOCTL).
	 */
	{
		int (*enter_fn)(struct brcm_pci_softc *) =
		    (sc->sc_devid == BRCM_PCI_DEVICE_BCM43602) ?
		    brcm_pci_enter_download_state :
		    brcm_pci_enter_download_state_generic;
		if (enter_fn(sc) != 0)
			return (EIO);
	}

	/*
	 * Log what is about to be uploaded.  The reset vector
	 * (first 4 bytes) is the Thumb-2 branch the ARM-CR4 takes on
	 * release.  Version string is at the tail.
	 */
	resetintr = le32toh(((const uint32_t *)fw->data)[0]);
	memset(verstr, 0, sizeof(verstr));
	vs_off = fw->datasize > sizeof(verstr) ?
	    fw->datasize - sizeof(verstr) : 0;
	vs_len = fw->datasize - vs_off;
	p = (const uint8_t *)fw->data + vs_off;
	for (i = 0; i < vs_len && i < sizeof(verstr) - 1; i++) {
		uint8_t c = p[i];
		verstr[i] = (c >= 0x20 && c < 0x7f) ? c : '.';
	}
	PDPRINTF(sc, 0,
	    "load_fw: blob %zu bytes, reset vector 0x%08x, dst BAR2+0x%x\n",
	    fw->datasize, resetintr, dst_off);
	PDPRINTF(sc, 0,
	    "load_fw: tail strings: %s\n", verstr);

	src = (const uint32_t *)fw->data;
	nwords = fw->datasize / 4;
	for (i = 0; i < nwords; i++) {
		bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    dst_off + i * 4, le32toh(src[i]));
	}
	/*
	 * Tail word: copy the unaligned trailing bytes into a zero-
	 * initialized stack word, write as one 32-bit BAR2 store.
	 */
	if (fw->datasize & 3) {
		uint32_t tail = 0;
		const uint8_t *tail_src = (const uint8_t *)fw->data +
		    nwords * 4;

		memcpy(&tail, tail_src, fw->datasize & 3);
		bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    dst_off + nwords * 4, le32toh(tail));
		nwords++;
	}

	/* Flush the host's posted writes before the chip reads the image. */
	bus_space_barrier(sc->sc_bar2_t, sc->sc_bar2_h,
	    dst_off, nwords * 4, BUS_SPACE_BARRIER_WRITE);

	/*
	 * Spot-check the upload: verify first, middle, and last
	 * dwords survived the write.  BAR2 is one big aperture; a
	 * silent drop usually affects the whole window, so the spot
	 * check catches the common failure mode.
	 */
	mismatches = 0;
	{
		size_t probes[3];

		probes[0] = 0;
		probes[1] = nwords / 2;
		probes[2] = nwords - 1;
		for (i = 0; i < 3; i++) {
			verify = bus_space_read_4(sc->sc_bar2_t,
			    sc->sc_bar2_h, dst_off + probes[i] * 4);
			if (verify != le32toh(src[probes[i]])) {
				device_printf(sc->sc_dev,
				    "load_fw: mismatch at word %zu: "
				    "wrote 0x%08x read 0x%08x\n",
				    probes[i], le32toh(src[probes[i]]),
				    verify);
				mismatches++;
			}
		}
	}

	PDPRINTF(sc, 0,
	    "load_fw: %s (%d spot-check mismatch(es))\n",
	    mismatches == 0 ? "upload verified" : "upload FAILED",
	    mismatches);

	return (mismatches == 0 ? 0 : EIO);
}

/* ------------------------------------------------------------------
 * Recovery and diagnostic paths.
 *
 * On Apple machines the BCM43602's PCIe memory decoder stays gated
 * until the platform unlock above completes, and any BAR0 read while
 * it is gated triggers a Master Abort and a Machine Check,
 * which on x86 is an instant reboot with no panic message.  Chip-side
 * operations are therefore explicit steps that check for a live chip
 * first, and the manual ones are sysctls.  They all log through
 * device_printf so the trail lands in dmesg.
 * ------------------------------------------------------------------ */

/*
 * PCIe D-state transition: D0 -> D3hot -> D0.
 *
 * This hangs the kernel on a cold BCM43602 backplane: the D3hot
 * transition or the D0 restore starts PCIe retraining that never
 * completes on cold silicon, blocking config-space access
 * indefinitely.  Only use it once the chip is known to be warm.
 *
 * PCIe PM spec:
 *   D3hot: main power off, aux power on.  Config-space and PCIe
 *          link only.  Chip's internal state may reset.
 *   D0:    full power, chip runs normally.
 *
 * It does not warm a cold chip.
 */
static int
brcm_pci_apple_dstate_cycle(struct brcm_pci_softc *sc)
{
	int pm_cap;
	uint16_t pmcsr;

	if (pci_find_cap(sc->sc_dev, PCIY_PMG, &pm_cap) != 0) {
		device_printf(sc->sc_dev,
		    "dstate_cycle: no PMG capability\n");
		return (ENOENT);
	}

	pmcsr = pci_read_config(sc->sc_dev, pm_cap + PCIR_POWER_STATUS, 2);
	device_printf(sc->sc_dev,
	    "dstate_cycle: PMCSR before = 0x%04x (state=D%d)\n",
	    pmcsr, pmcsr & PCIM_PSTAT_DMASK);

	/* Enter D3hot: main power off, keep aux power. */
	pci_write_config(sc->sc_dev, pm_cap + PCIR_POWER_STATUS,
	    (pmcsr & ~PCIM_PSTAT_DMASK) | 0x3, 2);
	DELAY(100000);  /* 100ms dwell in D3hot (spec min 10ms) */
	pmcsr = pci_read_config(sc->sc_dev, pm_cap + PCIR_POWER_STATUS, 2);
	device_printf(sc->sc_dev,
	    "dstate_cycle: PMCSR in D3 = 0x%04x (state=D%d)\n",
	    pmcsr, pmcsr & PCIM_PSTAT_DMASK);

	/* Return to D0. */
	pci_write_config(sc->sc_dev, pm_cap + PCIR_POWER_STATUS,
	    pmcsr & ~PCIM_PSTAT_DMASK, 2);
	DELAY(10000);  /* 10ms recovery */
	pmcsr = pci_read_config(sc->sc_dev, pm_cap + PCIR_POWER_STATUS, 2);
	device_printf(sc->sc_dev,
	    "dstate_cycle: PMCSR after = 0x%04x (state=D%d)\n",
	    pmcsr, pmcsr & PCIM_PSTAT_DMASK);
	return (0);
}

/*
 * Cold-resume path: after S3 removes power to the chip the fw is dead
 * and every DCMD hangs.  Rebuild the whole stack in-kernel:
 *   1. Tear the stale msgbuf state down (DMA rings, ISR, mbufs).
 *   2. DSDT APPU warm sequence via EC APWC (safe on cold chip).
 *   3. PCIe D0 -> D3 -> D0 nudge.
 *   4. Verify chip cfg-space liveness.
 *   5. Re-point BAR0_WIN1 at CHIPCOMMON.
 *   6. Full bring-up: core_walk, PMU, PLL, ramsize, firmware upload,
 *      NVRAM, armcr4 release and wait_fw_ready.
 *   7. msgbuf_attach: fresh DMA rings, rebind ISR, post rx buffers.
 *   8. WLC_UP.
 *   9. preinit dcmds: event_msgs, mpc, scan timers, txbf.
 *
 * net80211 is intentionally not torn down.  wlan0 stays present as an
 * ifnet, sc_ic_attached stays true; wpa_supplicant's SIOCS80211 fd
 * survives.  The VAP's next iv_op after resume will find sc_wlc_up
 * true again, the fw ready to accept SET_SSID, and re-associate
 * naturally without needing userland to re-create the interface.
 */
static int
brcm_pci_cold_reattach(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	int rc;

	device_printf(dev, "cold_reattach: starting full chip rebuild\n");

	/*
	 * The firmware may still be running: a hung dcmd does not mean a
	 * dead ARM, and D3hot does not reset this chip (PMCSR
	 * No_Soft_Reset is set).  Stop it mastering the bus before its
	 * rings are freed, or it keeps writing into memory the kernel
	 * has handed back.  bringup_sequence turns mastering back on
	 * once the ARM is halted and the new image is in place.
	 */
	pci_disable_busmaster(dev);
	brcm_pci_msgbuf_detach(sc);
	sc->bus_sc.sc_wlc_up = false;
	sc->sc_chip_alive = false;
	sc->sc_fw_running = false;

	rc = brcm_pci_apple_appu_warm(sc);
	if (rc != 0) {
		device_printf(dev,
		    "cold_reattach: APPU warm failed rc=%d\n", rc);
		return (rc);
	}

	(void)brcm_pci_apple_dstate_cycle(sc);

	if (!brcm_pci_chip_alive_cfg(sc)) {
		device_printf(dev,
		    "cold_reattach: chip still absent from cfg-space "
		    "after APPU + dstate_cycle\n");
		return (ENXIO);
	}
	sc->sc_chip_alive = true;

	pci_write_config(dev, BRCM_PCI_BAR0_WINDOW, 0x18000000, 4);
	(void)pci_read_config(dev, BRCM_PCI_BAR0_WINDOW, 4);

	rc = brcm_pci_bringup_sequence(sc);
	if (rc != 0) {
		device_printf(dev,
		    "cold_reattach: bringup_sequence rc=%d\n", rc);
		return (rc);
	}

	rc = brcm_pci_msgbuf_attach(sc);
	if (rc != 0) {
		device_printf(dev,
		    "cold_reattach: msgbuf_attach rc=%d\n", rc);
		return (rc);
	}

	rc = brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_UP, 0);
	if (rc != 0) {
		device_printf(dev,
		    "cold_reattach: WLC_UP rc=%d\n", rc);
		return (rc);
	}
	sc->bus_sc.sc_wlc_up = true;

	brcm_pci_preinit_dcmds(sc);

	/*
	 * Chip is fully back but net80211's VAP still believes it's in
	 * whatever state it was before the tear-down.  Force each vap to
	 * INIT so the next userland scan/assoc request walks the state
	 * machine cleanly against the fresh fw.  wpa_supplicant sees
	 * SIOCG80211(SSID) come back empty, treats it as a link drop, and
	 * reissues its own re-association without needing to be restarted.
	 */
	if (sc->bus_sc.sc_ic_attached) {
		struct ieee80211vap *vap;
		TAILQ_FOREACH(vap, &sc->bus_sc.sc_ic.ic_vaps, iv_next)
			(void)ieee80211_new_state(vap, IEEE80211_S_INIT, -1);
	}

	device_printf(dev, "cold_reattach: SUCCESS\n");
	return (0);
}

/*
 * Called from msgbuf.c on every DCMD timeout after it bumps
 * mb->stat_dcmd_timeout_consec.  Checks the softc-level threshold
 * and enqueues the crash-recover task at most once per burst.
 * Idempotent: task body clears sc_crash_recover_pending on exit so a
 * subsequent burst re-arms.
 */
void
brcm_pci_maybe_queue_crash_recover(struct brcm_pci_softc *sc)
{
	uint32_t thresh = sc->sc_crash_recover_threshold;
	uint32_t consec = sc->sc_msgbuf.stat_dcmd_timeout_consec;

	if (thresh == 0 || consec < thresh || sc->sc_crash_recover_pending)
		return;
	sc->sc_crash_recover_pending = true;
	sc->sc_crash_recover_events++;
	device_printf(sc->sc_dev,
	    "fw crash detected (dcmd timeout consec=%u >= %u); "
	    "queueing cold_reattach (event #%u)\n",
	    consec, thresh, sc->sc_crash_recover_events);
	taskqueue_enqueue(taskqueue_thread, &sc->sc_crash_recover_task);
}

/*
 * Firmware crash auto-recovery taskqueue callback.  Runs on
 * taskqueue_thread after the DCMD timeout path bumps
 * mb->stat_dcmd_timeout_consec past sc_crash_recover_threshold.  Body
 * mirrors what the cold_reattach sysctl does; the pending flag is
 * flipped back to false so a subsequent crash burst re-arms.
 */
static void
brcm_pci_crash_recover_task(void *ctx, int pending __unused)
{
	struct brcm_pci_softc *sc = ctx;
	int rc;

	device_printf(sc->sc_dev,
	    "crash_recover_task: running cold_reattach (event #%u)\n",
	    sc->sc_crash_recover_events);
	rc = brcm_pci_cold_reattach(sc);
	device_printf(sc->sc_dev,
	    "crash_recover_task: cold_reattach rc=%d\n", rc);
	sc->sc_crash_recover_pending = false;
}

/*
 * Diagnostic: manually trigger the crash-recover task without waiting
 * for real DCMD timeouts.  Sets the pending flag and enqueues the task;
 * task body then calls cold_reattach.  Same effect as
 * `sysctl dev.brcm_pci.N.cold_reattach=1` but exercises the async
 * taskqueue path that a real fw crash would take.
 */
static int
brcm_pci_sysctl_crash_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	if (sc->sc_crash_recover_pending) {
		device_printf(sc->sc_dev,
		    "crash_probe: already pending, ignored\n");
		return (0);
	}
	sc->sc_crash_recover_pending = true;
	sc->sc_crash_recover_events++;
	device_printf(sc->sc_dev,
	    "crash_probe: injecting event #%u, enqueueing task\n",
	    sc->sc_crash_recover_events);
	taskqueue_enqueue(taskqueue_thread, &sc->sc_crash_recover_task);
	return (0);
}

/*
 * Diagnostic: force cold_reattach without going through ACPI S3.  Tears
 * the running msgbuf state down and rebuilds — chip will drop the
 * current association and reconnect once wpa_supplicant reissues its
 * scan/assoc.  Safe to run on a working link; it exercises the cold
 * resume path without a physical suspend cycle.
 */
static int
brcm_pci_sysctl_cold_reattach(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_cold_reattach(sc));
}

/*
 * Diagnostic: run the D3 mailbox handshake (H2D_HOST_D3_INFORM, then
 * wait up to 2s for D2H_DEV_D3_ACK) and follow with H2D_HOST_D0_INFORM,
 * without touching WLC, net80211 or the PCIe bus D-state.  Exercises
 * the firmware side of suspend/resume without an actual ACPI S3; the
 * chip stays associated across the round trip.
 */
static int
brcm_pci_sysctl_d3_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error, rc_send, rc_ack;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);

	rc_send = brcm_pci_msgbuf_send_mb_data(sc, BRCM_H2D_HOST_D3_INFORM);
	if (rc_send == 0) {
		rc_ack = brcm_pci_msgbuf_wait_mb_ack(sc,
		    BRCM_D2H_DEV_D3_ACK, 2000);
		device_printf(sc->sc_dev,
		    "d3_probe: D3_INFORM sent, D3_ACK rc=%d\n", rc_ack);
	} else {
		device_printf(sc->sc_dev,
		    "d3_probe: D3_INFORM send rc=%d\n", rc_send);
	}
	(void)brcm_pci_msgbuf_send_mb_data(sc, BRCM_H2D_HOST_D0_INFORM);
	device_printf(sc->sc_dev, "d3_probe: D0_INFORM sent\n");
	return (0);
}

static void
brcm_pci_attach_sysctls(struct brcm_pci_softc *sc)
{
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(sc->sc_dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(sc->sc_dev);
	struct sysctl_oid_list *list = SYSCTL_CHILDREN(tree);

	SYSCTL_ADD_INT(ctx, list, OID_AUTO, "debug",
	    CTLFLAG_RWTUN, &sc->bus_sc.sc_debug, 0,
	    "Verbosity level for DPRINTF chatter (0=silent, 1=attach info, "
	    "2=proto trace, 3=data-path, 4=register poke).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "chip_alive",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_chip_alive, "I",
	    "Write 1 to probe PCIe cfg-space aliveness (VID + BAR0_WINDOW "
	    "readback).  Returns 0 if cfg responds, ENXIO if link is down. "
	    "This is safe on any chip state because cfg-space is served by "
	    "the root complex, not the chip -- it never wedges.  It does "
	    "NOT prove BAR0 MMIO is safe; for that use chip_probe_mmio "
	    "(which wedges if backplane is cold).");
	SYSCTL_ADD_BOOL(ctx, list, OID_AUTO, "fw_running",
	    CTLFLAG_RD, &sc->sc_fw_running, 0,
	    "1 once bring-up has started the firmware.  bringup refuses "
	    "while it is set.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "bringup",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_bringup, "I",
	    "Write 1 to run full bring-up sequence: chip_reset "
	    "-> core_walk -> ramsize_query -> enter_download_state -> "
	    "load_firmware -> nvram_inject -> armcr4_release -> "
	    "wait_fw_ready.  Each step prints STARTING/DONE markers.  "
	    "Now guarded by chip_alive_cfg pre-flight; refuses if PCIe cfg "
	    "reports link down.  Note: cfg-alive does NOT prove BAR0 MMIO "
	    "is safe -- backplane clock may still be off after APPU.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "msgbuf_attach",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_msgbuf_attach, "I",
	    "Write 1 to read fw shared struct, allocate 5 common rings + "
	    "scratch buffers via bus_dma, and publish DMA addresses to "
	    "fw.  Requires armcr4_release to have fired first.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "delete_flowring",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_delete_flowring, "I",
	    "Write local flowid (>=0) to send FLOW_RING_DELETE + wait "
	    "up to 2 s for CMPLT.  Marks the slot CLOSED on success.  "
	    "Used to verify the delete protocol standalone.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "wlc_up",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_wlc_up, "I",
	    "Write 1 to send WLC_UP DCMD (2), bringing chip WLAN up.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "wlc_down",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_wlc_down, "I",
	    "Write 1 to send WLC_DOWN DCMD (3).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "net80211_attach",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_net80211_attach, "I",
	    "Write 1 to attach the ieee80211com and expose the driver as "
	    "wlan0 via net80211.  Requires fw running + msgbuf_attach done.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "net80211_detach",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_net80211_detach, "I",
	    "Write 1 to detach the ieee80211com (undo net80211_attach).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "dump_console",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_dump_console, "I",
	    "Write 1 to drain the fw runtime console and print any new "
	    "lines to dmesg (fw: ...).  Requires msgbuf_attach first.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "mac_addr",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    brcm_pci_sysctl_mac_addr, "A",
	    "Read chip's cur_etheraddr via GET_VAR (262).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "d3_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_d3_probe, "I",
	    "Fire mbdata H2D_HOST_D3_INFORM + wait 2s for D2H_DEV_D3_ACK "
	    "+ H2D_HOST_D0_INFORM, without touching WLC/net80211/PCIe bus.  "
	    "Diagnostic for the fw side of item #4 (D3 suspend/resume).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "cold_reattach",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_cold_reattach, "I",
	    "Write 1 to force the ACPI-S3 cold-resume path: msgbuf_detach, "
	    "APPU warm, dstate cycle, full bringup (fw reupload), msgbuf "
	    "reattach, WLC_UP, preinit.  Chip drops current association "
	    "and rebuilds; wpa_supplicant re-associates once fw is back.  "
	    "For iterating on item #4b without needing physical S3 cycles.");
	SYSCTL_ADD_UINT(ctx, list, OID_AUTO, "crash_recover_threshold",
	    CTLFLAG_RW, &sc->sc_crash_recover_threshold, 0,
	    "Consecutive DCMD-timeout count that triggers automatic "
	    "cold_reattach.  Default 0 (off): a timeout does not prove "
	    "the firmware crashed, and rebuilding a running chip can "
	    "hang the host.");
	SYSCTL_ADD_UINT(ctx, list, OID_AUTO, "crash_recover_events",
	    CTLFLAG_RD, &sc->sc_crash_recover_events, 0,
	    "Number of times the fw-crash auto-recovery task has been "
	    "queued since attach (item #13).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "crash_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_crash_probe, "I",
	    "Write 1 to inject a fake crash event and exercise the "
	    "async crash_recover task queue.  Behaviour equivalent to "
	    "cold_reattach but goes through taskqueue_thread the same "
	    "way a real DCMD-timeout burst would (item #13).");
}

/* ------------------------------------------------------------------
 * Newbus glue
 * ------------------------------------------------------------------ */

static const struct brcm_pci_devmatch *
brcm_pci_lookup(device_t dev)
{
	const struct brcm_pci_devmatch *m;
	uint16_t vendor, devid;

	vendor = pci_get_vendor(dev);
	if (vendor != BRCM_PCI_VENDOR_BROADCOM)
		return (NULL);
	devid = pci_get_device(dev);
	for (m = brcm_pci_devs; m->desc != NULL; m++)
		if (m->devid == devid)
			return (m);
	return (NULL);
}

static int
brcm_pci_probe(device_t dev)
{
	const struct brcm_pci_devmatch *m;

	m = brcm_pci_lookup(dev);
	if (m == NULL)
		return (ENXIO);
	device_set_desc(dev, m->desc);
	return (BUS_PROBE_DEFAULT);
}

static int
brcm_pci_alloc_bars(struct brcm_pci_softc *sc)
{
	int rid;

	rid = BRCM_PCI_BAR0_RID;
	sc->sc_bar0 = bus_alloc_resource_any(sc->sc_dev, SYS_RES_MEMORY,
	    &rid, RF_ACTIVE);
	if (sc->sc_bar0 == NULL) {
		device_printf(sc->sc_dev, "BAR0 alloc failed\n");
		return (ENXIO);
	}
	sc->sc_bar0_t = rman_get_bustag(sc->sc_bar0);
	sc->sc_bar0_h = rman_get_bushandle(sc->sc_bar0);

	rid = BRCM_PCI_BAR2_RID;
	sc->sc_bar2 = bus_alloc_resource_any(sc->sc_dev, SYS_RES_MEMORY,
	    &rid, RF_ACTIVE);
	if (sc->sc_bar2 == NULL) {
		device_printf(sc->sc_dev,
		    "BAR2 alloc failed (chip-RAM window); firmware "
		    "download will be unavailable until this is wired\n");
		/* Not fatal here; bring-up checks for BAR2 itself. */
	} else {
		sc->sc_bar2_t = rman_get_bustag(sc->sc_bar2);
		sc->sc_bar2_h = rman_get_bushandle(sc->sc_bar2);
	}
	return (0);
}

static void
brcm_pci_free_bars(struct brcm_pci_softc *sc)
{
	if (sc->sc_bar2 != NULL) {
		bus_release_resource(sc->sc_dev, SYS_RES_MEMORY,
		    BRCM_PCI_BAR2_RID, sc->sc_bar2);
		sc->sc_bar2 = NULL;
	}
	if (sc->sc_bar0 != NULL) {
		bus_release_resource(sc->sc_dev, SYS_RES_MEMORY,
		    BRCM_PCI_BAR0_RID, sc->sc_bar0);
		sc->sc_bar0 = NULL;
	}
}

static int
brcm_pci_alloc_irq(struct brcm_pci_softc *sc)
{
	int count;

	count = 1;
	if (pci_alloc_msix(sc->sc_dev, &count) == 0 && count >= 1) {
		sc->sc_msix_count = count;
		sc->sc_msi = false;
		sc->sc_irq_rid = 1;	/* MSI-X starts at RID 1. */
	} else if (pci_alloc_msi(sc->sc_dev, &count) == 0 && count >= 1) {
		sc->sc_msix_count = 0;
		sc->sc_msi = true;
		sc->sc_irq_rid = 1;
	} else {
		/* Legacy INTx — usable; some platforms can't route MSI. */
		sc->sc_msix_count = 0;
		sc->sc_msi = false;
		sc->sc_irq_rid = 0;
	}
	sc->sc_irq = bus_alloc_resource_any(sc->sc_dev, SYS_RES_IRQ,
	    &sc->sc_irq_rid, RF_ACTIVE | RF_SHAREABLE);
	if (sc->sc_irq == NULL) {
		device_printf(sc->sc_dev, "IRQ alloc failed\n");
		return (ENXIO);
	}
	return (0);
}

static void
brcm_pci_free_irq(struct brcm_pci_softc *sc)
{
	if (sc->sc_irq_handle != NULL) {
		bus_teardown_intr(sc->sc_dev, sc->sc_irq, sc->sc_irq_handle);
		sc->sc_irq_handle = NULL;
	}
	if (sc->sc_irq != NULL) {
		bus_release_resource(sc->sc_dev, SYS_RES_IRQ,
		    sc->sc_irq_rid, sc->sc_irq);
		sc->sc_irq = NULL;
	}
	if (sc->sc_msix_count > 0 || sc->sc_msi)
		pci_release_msi(sc->sc_dev);
	sc->sc_msix_count = 0;
	sc->sc_msi = false;
}

/* -----------------------------------------------------------------
 * Bus ops for brcm.c integration.  brcm.c (the FullMAC core shared
 * with the SDIO and USB transports) calls these wrappers; PCIe uses
 * msgbuf DCMDs instead of BCDC, so txctl/rxctl are BCDC-only and
 * return ENXIO.  txdata goes out through the msgbuf flow rings.
 * ----------------------------------------------------------------- */
static int
brcm_pci_bs_txctl(struct brcm_softc *bsc __unused, const void *buf __unused,
    size_t len __unused)
{
	/* BCDC-specific control path.  Msgbuf uses DCMD ring instead. */
	return (ENXIO);
}

static int
brcm_pci_bs_rxctl(struct brcm_softc *bsc __unused, void *buf __unused,
    size_t *lenp __unused, int timeout_ms __unused)
{
	return (ENXIO);
}

/*
 * net80211 hands ic_transmit()/ic_raw_xmit() fully 802.11-encapsulated
 * frames (post ieee80211_encap(): an 802.11 header + RFC1042 LLC/SNAP).
 * The FullMAC firmware's msgbuf TX path wants plain 802.3 ethernet frames --
 * it does its own 802.11 encap and encryption -- so convert back to 802.3
 * here.  Otherwise the TX path reads the destination MAC and ethertype
 * out of the 802.11 header at 802.3 offsets, which gives a bogus flow
 * ring key and breaks the 4-way handshake and every data frame.
 *
 * Returns 0 with *mp rewritten to 802.3 on success; EAGAIN for a mgmt/ctl
 * frame the host must not put on the data path (the firmware owns MLME --
 * caller drops it); or an errno if the mbuf could not be made contiguous.
 */
static int
brcm_pci_deencap_80211(struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct ieee80211_frame *wh;
	uint8_t dst[6], src[6];
	uint8_t *eh;
	const uint8_t *snap;
	uint16_t etype;
	int hdrlen;

	if (m->m_len < sizeof(struct ieee80211_frame) &&
	    (m = m_pullup(m, sizeof(struct ieee80211_frame))) == NULL) {
		*mp = NULL;
		return (ENOMEM);
	}
	wh = mtod(m, struct ieee80211_frame *);
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_DATA) {
		/* Management/control frame: the firmware runs its own MLME. */
		*mp = m;
		return (EAGAIN);
	}
	hdrlen = ieee80211_hdrsize(wh);
	/* Need the 802.11 header + 8-byte LLC/SNAP contiguous. */
	if (m->m_len < hdrlen + 8 &&
	    (m = m_pullup(m, hdrlen + 8)) == NULL) {
		*mp = NULL;
		return (ENOMEM);
	}
	wh = mtod(m, struct ieee80211_frame *);
	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_TODS:		/* STA uplink (normal case) */
		IEEE80211_ADDR_COPY(dst, wh->i_addr3);
		IEEE80211_ADDR_COPY(src, wh->i_addr2);
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		IEEE80211_ADDR_COPY(dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(src, wh->i_addr3);
		break;
	default:				/* NODS */
		IEEE80211_ADDR_COPY(dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(src, wh->i_addr2);
		break;
	}
	/* RFC1042 SNAP: aa aa 03 00 00 00 <ethertype:2>. */
	snap = mtod(m, const uint8_t *) + hdrlen;
	etype = ((uint16_t)snap[6] << 8) | snap[7];
	/* Collapse (802.11 header + SNAP) into a 14-byte ethernet header. */
	m_adj(m, (hdrlen + 8) - ETHER_HDR_LEN);
	eh = mtod(m, uint8_t *);
	IEEE80211_ADDR_COPY(eh, dst);
	IEEE80211_ADDR_COPY(eh + 6, src);
	eh[12] = etype >> 8;
	eh[13] = etype & 0xff;
	*mp = m;
	return (0);
}

/*
 * Make the flow rings queued frames are waiting for, then send them.  Runs
 * on taskqueue_thread, where waiting for the firmware is allowed.  If a
 * ring cannot be made, its queue is dropped.
 */
static void
brcm_pci_flow_task(void *arg, int pending __unused)
{
	struct brcm_pci_softc *sc = arg;
	uint8_t sa[6], da[6];
	uint16_t flowid;
	struct mbuf *m;
	int q, error;

	for (q = 0; q < 2; q++) {
		uint8_t prio = q == 1 ? 7 : 0;

		mtx_lock(&sc->sc_flowq_mtx);
		if (!sc->sc_flowq_busy[q]) {
			mtx_unlock(&sc->sc_flowq_mtx);
			continue;
		}
		memcpy(sa, sc->sc_flowq_sa[q], 6);
		memcpy(da, sc->sc_flowq_da[q], 6);
		mtx_unlock(&sc->sc_flowq_mtx);

		error = 0;
		flowid = brcm_pci_msgbuf_flowring_lookup(sc, da, prio);
		if (flowid == (uint16_t)-1)
			error = brcm_pci_msgbuf_flowring_create(sc, sa, da, prio,
			    0, &flowid);
		if (error != 0)
			device_printf(sc->sc_dev, "flow ring for prio %u: %d; "
			    "dropping its queued frames\n", prio, error);
		for (;;) {
			mtx_lock(&sc->sc_flowq_mtx);
			if ((m = mbufq_dequeue(&sc->sc_flowq[q])) == NULL) {
				sc->sc_flowq_busy[q] = false;
				mtx_unlock(&sc->sc_flowq_mtx);
				break;
			}
			mtx_unlock(&sc->sc_flowq_mtx);
			if (error != 0 ||
			    brcm_pci_msgbuf_txmbuf(sc, flowid, m, 0) != 0)
				m_freem(m);
		}
	}
}

static int
brcm_pci_bs_txdata(struct brcm_softc *bsc, struct mbuf *m)
{
	struct brcm_pci_softc *sc = SC_TO_PCI(bsc);
	uint8_t da[6], sa[6];
	uint16_t flowid;
	uint8_t prio, ifidx;
	int error;

	if (m == NULL)
		return (EINVAL);

	/* Convert net80211's 802.11-encapsulated frame back to 802.3. */
	{
		int dr = brcm_pci_deencap_80211(&m);
		if (dr != 0) {
			if (m != NULL)
				m_freem(m);
			/* EAGAIN == host mgmt/ctl frame: drop, report sent. */
			return (dr == EAGAIN ? 0 : dr);
		}
	}
	if (m->m_pkthdr.len < ETHER_HDR_LEN) {
		m_freem(m);
		return (EINVAL);
	}
	if (m->m_len < ETHER_HDR_LEN) {
		m = m_pullup(m, ETHER_HDR_LEN);
		if (m == NULL)
			return (ENOMEM);
	}
	/* Extract dst/src MAC + ethertype. */
	memcpy(da, mtod(m, uint8_t *), 6);
	memcpy(sa, mtod(m, uint8_t *) + 6, 6);

	/*
	 * For broadcast/multicast dst, redirect the flowring key to the
	 * AP's MAC.  In STA mode every uplink frame is a unicast 802.11
	 * frame TO the AP regardless of its 802.3 dst; using the broadcast
	 * MAC as the flowring peer makes the chip skip PTK encryption
	 * (there is no SCB for ff:ff:ff:ff:ff:ff), so the frame goes out
	 * in the clear and the AP deauthenticates us with reason 6
	 * ("class 2 frame from nonauthenticated STA").
	 */
	if ((da[0] & 0x01) != 0 && bsc->sc_ic_attached) {
		struct ieee80211vap *_vap =
		    TAILQ_FIRST(&bsc->sc_ic.ic_vaps);
		if (_vap != NULL && _vap->iv_bss != NULL) {
			memcpy(da, _vap->iv_bss->ni_bssid, 6);
		}
	}
	/*
	 * In station mode every frame goes to the AP whatever its 802.3
	 * destination, so key the flow ring on the AP alone, one per
	 * priority.  Linux brcmfmac's indirect address mode also ignores
	 * the destination, but keys one ring per AC fifo (prio2fifo), not
	 * per priority.  Keying on the destination would need a ring of
	 * its own for each new peer or gateway, made on the transmit path.
	 */
	if (bsc->sc_ic_attached) {
		struct ieee80211vap *_vap =
		    TAILQ_FIRST(&bsc->sc_ic.ic_vaps);
		if (_vap != NULL && _vap->iv_opmode == IEEE80211_M_STA &&
		    _vap->iv_bss != NULL)
			memcpy(da, _vap->iv_bss->ni_bssid, 6);
	}

	/*
	 * EAPOL (ethertype 0x888e) must ride a dedicated flowring at
	 * prio 7 (voice / TID 7).  Rationale: after brcm_set_key installs
	 * the PTK, the chip starts encrypting outbound frames on the peer's
	 * data flowring.  M4 (or any EAPOL retransmit) that arrives on the
	 * same flowring gets AES-encrypted; the AP can't validate the MIC
	 * and keeps replaying M3.  The TID-7 ring is this driver's choice;
	 * Linux brcmfmac does not separate EAPOL (it classifies it as
	 * priority 0 and instead waits for pending EAPOL TX in
	 * brcmf_netdev_wait_pend8021x before installing keys).  Broadcom
	 * firmware is believed to treat the TID-7 flowring as an EAPOL
	 * bypass path, sending frames unencrypted regardless of PTK
	 * install state, which is what 802.11i requires for M2 and M4.
	 */
	prio = 0;
	if (m->m_pkthdr.len >= 14) {
		const uint8_t *p = mtod(m, const uint8_t *);
		uint16_t etype = ((uint16_t)p[12] << 8) | p[13];
		if (etype == 0x888e)
			prio = 7;
	}
	ifidx = 0;

	{
		int q = prio == 7 ? 1 : 0;
		bool kick = false;

		mtx_lock(&sc->sc_flowq_mtx);
		flowid = sc->sc_flowq_busy[q] ? (uint16_t)-1 :
		    brcm_pci_msgbuf_flowring_lookup(sc, da, prio);
		if (flowid == (uint16_t)-1) {
			/* No ring yet, or one is being made: queue. */
			if (mbufq_enqueue(&sc->sc_flowq[q], m) != 0) {
				mtx_unlock(&sc->sc_flowq_mtx);
				m_freem(m);
				return (ENOBUFS);
			}
			if (!sc->sc_flowq_busy[q]) {
				sc->sc_flowq_busy[q] = true;
				memcpy(sc->sc_flowq_sa[q], sa, 6);
				memcpy(sc->sc_flowq_da[q], da, 6);
				kick = true;
			}
			mtx_unlock(&sc->sc_flowq_mtx);
			if (kick)
				taskqueue_enqueue(taskqueue_thread,
				    &sc->sc_flow_task);
			return (0);
		}
		mtx_unlock(&sc->sc_flowq_mtx);
	}
	error = brcm_pci_msgbuf_txmbuf(sc, flowid, m, ifidx);
	if (error != 0)
		m_freem(m);
	return (error);
}

static void
brcm_pci_bs_stop(struct brcm_softc *bsc __unused)
{
}

static int
brcm_pci_bs_dcmd_get(struct brcm_softc *bsc, uint32_t cmd, void *buf,
    size_t *lenp)
{
	struct brcm_pci_softc *sc = SC_TO_PCI(bsc);
	int32_t fwerr = 0;
	int error;

	error = brcm_pci_msgbuf_dcmd(sc, cmd, false, buf, *lenp,
	    buf, lenp, &fwerr);
	if (error == 0 && fwerr != 0)
		error = EIO;
	return (error);
}

static int
brcm_pci_bs_dcmd_set(struct brcm_softc *bsc, uint32_t cmd, const void *buf,
    size_t len)
{
	struct brcm_pci_softc *sc = SC_TO_PCI(bsc);
	size_t rlen = 0;
	int32_t fwerr = 0;
	int error;

	error = brcm_pci_msgbuf_dcmd(sc, cmd, true, buf, len,
	    NULL, &rlen, &fwerr);
	if (error == 0 && fwerr != 0)
		error = EIO;
	return (error);
}

static int
brcm_pci_bs_iovar_get(struct brcm_softc *bsc, const char *name, void *buf,
    size_t *lenp)
{
	struct brcm_pci_softc *sc = SC_TO_PCI(bsc);

	return (brcm_pci_msgbuf_dcmd_get_var(sc, name, buf, lenp));
}

static int
brcm_pci_bs_iovar_set(struct brcm_softc *bsc, const char *name,
    const void *buf, size_t len)
{
	struct brcm_pci_softc *sc = SC_TO_PCI(bsc);

	return (brcm_pci_msgbuf_dcmd_set_var(sc, name, buf, len));
}

static void
brcm_pci_bs_flowring_purge(struct brcm_softc *bsc)
{
	brcm_pci_msgbuf_flowring_delete_all(SC_TO_PCI(bsc));
}

static int
brcm_pci_bs_wait_eapol_drain(struct brcm_softc *bsc, int timeout_ms)
{
	return (brcm_pci_msgbuf_wait_eapol_drain(SC_TO_PCI(bsc), timeout_ms));
}

static const struct brcm_bus_ops brcm_pci_bus_ops = {
	.bs_txctl	= brcm_pci_bs_txctl,
	.bs_rxctl	= brcm_pci_bs_rxctl,
	.bs_txdata	= brcm_pci_bs_txdata,
	.bs_stop	= brcm_pci_bs_stop,
	.bs_dcmd_get	= brcm_pci_bs_dcmd_get,
	.bs_dcmd_set	= brcm_pci_bs_dcmd_set,
	.bs_iovar_get	= brcm_pci_bs_iovar_get,
	.bs_iovar_set	= brcm_pci_bs_iovar_set,
	.bs_flowring_purge = brcm_pci_bs_flowring_purge,
	.bs_wait_eapol_drain = brcm_pci_bs_wait_eapol_drain,
	/* No bs_pump_rx: the msgbuf ISR delivers asynchronously. */
};

static void	brcm_pci_autostart(void *);

static int
brcm_pci_attach(device_t dev)
{
	struct brcm_pci_softc *sc = device_get_softc(dev);
	int error;

	sc->sc_dev = dev;
	sc->sc_devid = pci_get_device(dev);
	sc->sc_revid = pci_get_revid(dev);
	sc->sc_chip = brcm_pci_chip_lookup(sc->sc_devid);
	if (sc->sc_chip == NULL) {
		device_printf(dev,
		    "attach: no chip-info entry for devid 0x%04x — "
		    "bringup will be refused\n", sc->sc_devid);
	} else {
		device_printf(dev, "attach: chip %s (rambase=0x%x, fw=%s%s)\n",
		    sc->sc_chip->notes, sc->sc_chip->rambase,
		    sc->sc_chip->fw_name,
		    sc->sc_chip->bringup_supported ? "" :
		    ", BRINGUP NOT IMPLEMENTED — sysctl bringup=1 will refuse");
	}

	/*
	 * Prepare the shared brcm_softc so brcm_attach() can run later,
	 * once the firmware is running and msgbuf is up.  brcm.c expects
	 * the transport to initialise these mutexes; they survive attach
	 * failures and are used by any ctlrx thread brcm.c starts.
	 */
	sc->bus_sc.sc_dev = dev;
	sc->bus_sc.sc_bus_ops = &brcm_pci_bus_ops;
	mtx_init(&sc->bus_sc.sc_mtx, device_get_nameunit(dev), NULL, MTX_DEF);
	mtx_init(&sc->bus_sc.sc_ctl_mtx, "brcm_pci ctl", NULL, MTX_DEF);
	TAILQ_INIT(&sc->bus_sc.sc_ctl_pending);

	/*
	 * Transition to D0 before any device-side access.  On Apple
	 * machines the EFI handoff parks the BCM43602 in D3-cold; without
	 * this the very first BAR0 register write faults the host CPU
	 * before any error-recovery layer can catch it.
	 *
	 * pci_set_powerstate goes through config space (PMCSR), which is
	 * always reachable regardless of device state.  After the write
	 * the PCI spec mandates up to a 10ms settle window for D3hot->D0;
	 * 10ms covers both the spec-mandated path and the D3cold case.
	 */
	{
		int pstate_before = pci_get_powerstate(dev);

		if (pstate_before != PCI_POWERSTATE_D0) {
			pci_set_powerstate(dev, PCI_POWERSTATE_D0);
			DELAY(10000);
			PDPRINTF(sc, 0,
			    "power state: %s -> D0 (%s)\n",
			    pstate_before == PCI_POWERSTATE_D1 ? "D1" :
			    pstate_before == PCI_POWERSTATE_D2 ? "D2" :
			    pstate_before == PCI_POWERSTATE_D3 ? "D3" :
			    "unknown",
			    pci_get_powerstate(dev) == PCI_POWERSTATE_D0 ?
			        "ok" : "FAILED");
		}
	}

	pci_enable_busmaster(dev);
	/*
	 * Explicitly enable memory-space decoding in the PCI Command
	 * register.  bus_alloc_resource_any(SYS_RES_MEMORY) is meant
	 * to do this implicitly via the platform's resource-activation
	 * path, but behind the Apple A1398 PCH bridges it does not get
	 * set, and every BAR0 read returns 0xffffffff (the device replies
	 * "Unsupported Request" because its memory decoder is off).
	 */
	pci_enable_io(dev, SYS_RES_MEMORY);
	{
		uint16_t cmd = pci_read_config(dev, PCIR_COMMAND, 2);
		PDPRINTF(sc, 0,
		    "PCI command 0x%04x (busmaster=%d, mem=%d, io=%d)\n",
		    cmd,
		    (cmd & PCIM_CMD_BUSMASTEREN) ? 1 : 0,
		    (cmd & PCIM_CMD_MEMEN)       ? 1 : 0,
		    (cmd & PCIM_CMD_PORTEN)      ? 1 : 0);
	}

	error = brcm_pci_alloc_bars(sc);
	if (error != 0)
		goto fail;
	error = brcm_pci_alloc_irq(sc);
	if (error != 0)
		goto fail;

	/*
	 * The Apple AML methods (APPU, the bridge's _PS0, ARPT._PS0) are
	 * never evaluated: they poll a hardware bit (LACT, link active)
	 * for up to 10 seconds under the ACPICA interpreter mutex, past
	 * FreeBSD's spin-lock-held-too-long limit.  Apple's AML assumes
	 * Darwin's more permissive interpreter locking.  The APPU warm
	 * sequence below is a C reimplementation instead.
	 *
	 * Until then the BAR0 window may not reach chip registers, so log
	 * only what config space says, plus the BAR sizes.
	 */
	{
		const char *irqkind = sc->sc_msix_count > 0 ? "MSI-X" :
		    sc->sc_msi ? "MSI" : "INTx";

		device_printf(dev,
		    "PCI %04x:%04x rev=0x%02x bar0=%#jx/%ju bar2=%#jx/%ju "
		    "irq=%s(%d)\n",
		    BRCM_PCI_VENDOR_BROADCOM, sc->sc_devid, sc->sc_revid,
		    (uintmax_t)rman_get_start(sc->sc_bar0),
		    (uintmax_t)rman_get_size(sc->sc_bar0),
		    sc->sc_bar2 != NULL ?
		        (uintmax_t)rman_get_start(sc->sc_bar2) : (uintmax_t)0,
		    sc->sc_bar2 != NULL ?
		        (uintmax_t)rman_get_size(sc->sc_bar2) : (uintmax_t)0,
		    irqkind,
		    sc->sc_msix_count > 0 ? sc->sc_msix_count : 1);
	}

	/*
	 * No BAR0 register access from attach().  On Apple machines the
	 * BCM43602's PCIe memory decoder stays gated after EC.APWC=1
	 * alone, and any blind bus_space_read_4 on BAR0 master-aborts
	 * the host (MCE, then an immediate reboot with no panic message).
	 *
	 * Everything chip-side waits until the warm sequence below has
	 * run; the rest of the bring-up then happens in the autostart
	 * thread started at the end of attach (or by the bring-up sysctls,
	 * with hw.brcm_pci.autostart=0), so kldload always finishes
	 * cleanly.
	 */
	brcm_pci_attach_sysctls(sc);

	/*
	 * Firmware crash-recovery task.  Off by default (threshold 0); see
	 * sc_crash_recover_threshold.
	 */
	TASK_INIT(&sc->sc_crash_recover_task, 0,
	    brcm_pci_crash_recover_task, sc);
	mtx_init(&sc->sc_flowq_mtx, "brcm_pci flowq", NULL, MTX_DEF);
	mbufq_init(&sc->sc_flowq[0], BRCM_PCI_FLOWQ_LEN);
	mbufq_init(&sc->sc_flowq[1], BRCM_PCI_FLOWQ_LEN);
	TASK_INIT(&sc->sc_flow_task, 0, brcm_pci_flow_task, sc);
	sc->sc_crash_recover_threshold = 0;

	/*
	 * Run the APPU warm sequence now, before anything touches BAR0.
	 * After a normal EFI boot the chip is already warm and this
	 * returns on the first ~10ms poll; a cold chip (after a wedge, or
	 * a deep S5 wake) gets up to 5 attempts of 10s each.
	 *
	 * APPU is EC port I/O and a config-space poll only, with no BAR0
	 * writes, so unlike chip_reset's watchdog write it cannot wedge a
	 * cold chip.
	 *
	 * If APPU fails after all retries, attach still succeeds and the
	 * sysctls stay available for manual recovery; the chip just is not
	 * usable until something else warms it (a macOS boot, a power
	 * cycle).
	 */
	{
		int do_appu = brcm_pci_attach_appu_warm_dflt;
		int rc;

		if (!do_appu) {
			device_printf(dev,
			    "attach: hw.brcm_pci.attach_appu_warm=0 - "
			    "skipping APPU (opt-out).\n");
		} else {
			rc = brcm_pci_apple_appu_warm(sc);
			if (rc != 0) {
				device_printf(dev,
				    "attach: APPU warm failed rc=%d - chip "
				    "likely unusable this session; sysctls "
				    "still available for manual recovery.\n",
				    rc);
				goto attach_done;
			}
			device_printf(dev, "attach: APPU warm succeeded.\n");
		}

		/* Then dstate_cycle and chip_probe, both config space only. */
		rc = brcm_pci_apple_dstate_cycle(sc);
		if (rc != 0) {
			device_printf(dev,
			    "attach: dstate_cycle failed rc=%d - continuing "
			    "with sysctls available for manual recovery.\n",
			    rc);
		}

		{
			uint16_t vid, did, cmd;

			vid = pci_read_config(dev, PCIR_VENDOR, 2);
			did = pci_read_config(dev, PCIR_DEVICE, 2);
			cmd = pci_read_config(dev, PCIR_COMMAND, 2);
			device_printf(dev,
			    "attach: chip_probe vid=0x%04x did=0x%04x "
			    "cmd=0x%04x memen=%d bme=%d\n",
			    vid, did, cmd,
			    (cmd & PCIM_CMD_MEMEN) ? 1 : 0,
			    (cmd & PCIM_CMD_BUSMASTEREN) ? 1 : 0);
			sc->sc_chip_alive = (vid != 0xffff &&
			    (cmd & PCIM_CMD_MEMEN) != 0);
		}

		PDPRINTF(sc, 0,
		    "attach: warm sequence complete (APPU + dstate_cycle + "
		    "chip_probe).  Fire final bringup manually with "
		    "dev.brcm_pci.%d.bringup=1 — runtime sysctl is per-"
		    "session so a wedge doesn't persist.\n",
		    device_get_unit(dev));
	}

	/*
	 * Point BAR0_WIN1 (PCI cfg 0x80) at CHIPCOMMON (0x18000000) so
	 * BAR0[0..0x1000) MMIO reads land on ChipCommon registers (CHIPID
	 * at BAR0[0], CAPS at BAR0[4], and so on), which later code
	 * assumes.  Otherwise BAR0 shows whatever the firmware or previous
	 * OS left in WIN1, typically 0x18003000 (the PCIe2 core), whose
	 * offset 0 reads 0xffffffff and looks like a cold chip.
	 *
	 * The config-space write is safe even with BAR0 cold, since config
	 * space is served by the root complex, not the chip.
	 */
	pci_write_config(dev, BRCM_PCI_BAR0_WINDOW, 0x18000000, 4);
	(void)pci_read_config(dev, BRCM_PCI_BAR0_WINDOW, 4);
	device_printf(dev,
	    "attach: BAR0_WIN1 (cfg 0x%02x) = 0x18000000 (CHIPCOMMON)\n",
	    BRCM_PCI_BAR0_WINDOW);

attach_done:

	sc->bus_sc.sc_dev = dev;
	sc->bus_sc.sc_bus_ops = &brcm_pci_bus_ops;

	if (brcm_pci_autostart_dflt && sc->sc_chip_alive &&
	    sc->sc_chip != NULL && sc->sc_chip->bringup_supported) {
		sc->sc_autostart_running = true;
		if (kthread_add(brcm_pci_autostart, sc, NULL, NULL, 0, 0,
		    "%s start", device_get_nameunit(dev)) != 0) {
			sc->sc_autostart_running = false;
			device_printf(dev, "attach: could not start the "
			    "autostart thread; use the bring-up sysctls\n");
		}
	}
	return (0);

fail:
	brcm_pci_free_irq(sc);
	brcm_pci_free_bars(sc);
	pci_disable_busmaster(dev);
	return (error);
}

static int
brcm_pci_detach(device_t dev)
{
	struct brcm_pci_softc *sc = device_get_softc(dev);
	struct brcm_softc *bsc = &sc->bus_sc;

	/*
	 * Refuse detach while net80211 still holds callbacks into our module
	 * text.  Mirrors SDIO/USB transports: `ifconfig wlan0 destroy` must
	 * happen first, then `sysctl dev.brcm_pci.N.net80211_detach=1`, only
	 * then `kldunload brcm_pci` (or `devctl detach`).  Without this the
	 * next iv_op after our text vanishes panics the box.
	 */
	if (bsc->sc_ic_attached) {
		device_printf(dev,
		    "detach refused: net80211 still attached "
		    "(sysctl dev.brcm_pci.%d.net80211_detach=1 first, "
		    "after `ifconfig wlan0 destroy`)\n", device_get_unit(dev));
		return (EBUSY);
	}

	/*
	 * Teardown ordering (reverse of attach — LIFO):
	 *
	 *   1. Set sc_dying + wake in-flight DCMD sleepers so any sysctl
	 *      handler currently blocked in a DCMD bails through the
	 *      sc_dying check before we destroy the mutex it sleeps on.
	 *   2. If chip is up, send WLC_DOWN so fw stops autonomous DMA
	 *      (event bursts, scan results) before we tear the ISR down.
	 *   3. msgbuf_detach — masks chip interrupt, unbinds ISR, drains
	 *      event task, reclaims RX/TX/event/flow DMA rings + mbufs,
	 *      destroys msgbuf-internal mutexes/cv/sx.
	 *   4. Drain the brcm.c taskqueue tasks (scan_done, link, assoc,
	 *      disassoc, post_assoc) and our flow task.  They fire from the
	 *      msgbuf ISR path via brcm_handle_event, and the ISR is now
	 *      unbound.  Drain unconditionally: the task structs live in
	 *      the zeroed softc, so draining one never initialised or
	 *      never queued is a no-op.
	 *   5. Free IRQ and BARs (msgbuf_unbind_intr already tore down the
	 *      handler; free_irq just releases SYS_RES_IRQ and the MSI/MSI-X
	 *      vectors).
	 *   6. Destroy the sc_ctl_mtx / sc_mtx pair from attach.  Must come
	 *      after step 1 (no sleepers left).
	 *   7. pci_disable_busmaster (config space only, safe after the BARs
	 *      are released; no chip MMIO past this point).
	 */

	bsc->sc_dying = true;
	if (mtx_initialized(&bsc->sc_ctl_mtx)) {
		struct brcm_ctl_req *r;

		mtx_lock(&bsc->sc_ctl_mtx);
		TAILQ_FOREACH(r, &bsc->sc_ctl_pending, link)
			wakeup(r);
		/*
		 * Wait for any sysctl handler blocked in a dcmd to bail
		 * through the sc_dying check before we destroy the mutex
		 * they sleep on.  Each wakeup (or the 1s timeout) rechecks
		 * sc_dying, so the wait is bounded.
		 */
		while (bsc->sc_in_flight_dcmd != 0)
			(void)mtx_sleep(&bsc->sc_in_flight_dcmd,
			    &bsc->sc_ctl_mtx, 0, "brcmdcd", hz);
		mtx_unlock(&bsc->sc_ctl_mtx);
	}
	/* Let a bring-up in progress stop at its next step. */
	while (sc->sc_autostart_running)
		(void)tsleep(&sc->sc_autostart_running, 0, "brcmast", hz / 10);

	/*
	 * Best-effort chip quiesce: WLC_DOWN before killing the ISR so fw
	 * stops autonomous DMA (event bursts, scan results, per-flowring
	 * beacon delivery) that would otherwise hit a torn-down landing
	 * zone.  Skip if bringup never fired — no chip context to quiesce
	 * and the DCMD would just error.  Ignore return: chip may already
	 * be halted, and by this point the alternative is limping past.
	 *
	 * Note: sc_wlc_up mirrors fw pub->up state (set in
	 * brcm_pci_sysctl_wlc_up + brcm.c's various post-WLC_UP paths).
	 */
	if (bsc->sc_wlc_up) {
		(void)brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_DOWN, 0);
		bsc->sc_wlc_up = false;
	}

	/*
	 * msgbuf teardown.  Idempotent — safe to call even if
	 * msgbuf_attach was never fired (mb->attached is false in a
	 * freshly zeroed softc; detach short-circuits).
	 */
	brcm_pci_msgbuf_detach(sc);

	/*
	 * Drain brcm.c's task queue callbacks.  brcm_detach (called by
	 * the user via net80211_detach sysctl before us) tore down the
	 * ieee80211com but did NOT drain these tasks — that's our job on
	 * the transport side (mirrors USB's brcm_usb_teardown).  ISR is
	 * unbound at this point (msgbuf_detach did it), so no new
	 * enqueues can happen from the interrupt path.
	 */
	taskqueue_drain(taskqueue_thread, &bsc->sc_scan_done_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_link_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_assoc_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_disassoc_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_post_assoc_task);
	taskqueue_drain(taskqueue_thread, &sc->sc_flow_task);
	if (mtx_initialized(&sc->sc_flowq_mtx)) {
		mbufq_drain(&sc->sc_flowq[0]);
		mbufq_drain(&sc->sc_flowq[1]);
		mtx_destroy(&sc->sc_flowq_mtx);
	}

	brcm_pci_free_irq(sc);
	brcm_pci_free_bars(sc);

	if (sc->sc_fw != NULL) {
		firmware_put(sc->sc_fw, FIRMWARE_UNLOAD);
		sc->sc_fw = NULL;
	}

	/*
	 * Destroy the transport-owned mutexes last.  brcm.c documents
	 * that these are the transport's responsibility (see the comment
	 * on brcm_softc.sc_mtx / sc_ctl_mtx).  All in-flight sleepers
	 * bailed in step 1; no other codepath can touch these now.
	 */
	if (mtx_initialized(&bsc->sc_ctl_mtx))
		mtx_destroy(&bsc->sc_ctl_mtx);
	if (mtx_initialized(&bsc->sc_mtx))
		mtx_destroy(&bsc->sc_mtx);
	bsc->sc_bus_ops = NULL;

	pci_disable_busmaster(dev);
	return (0);
}

/* ------------------------------------------------------------------
 * MSGBUF accessors — bridge functions consumed by brcm_pci_msgbuf.c.
 * Kept here so that file needs no visibility into brcm_pci_softc.
 * ------------------------------------------------------------------ */
uint32_t
brcm_pci_msgbuf_pcie2_base(struct brcm_pci_softc *sc)
{
	int i;

	for (i = 0; i < sc->sc_ncores; i++)
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2)
			return (sc->sc_cores[i].base);
	return (0);
}

void
brcm_pci_msgbuf_set_window(struct brcm_pci_softc *sc, uint32_t addr)
{
	brcm_pci_set_window(sc, addr);
}

struct resource *
brcm_pci_msgbuf_bar0(struct brcm_pci_softc *sc)		{ return (sc->sc_bar0); }
struct resource *
brcm_pci_msgbuf_bar2(struct brcm_pci_softc *sc)		{ return (sc->sc_bar2); }
bus_space_tag_t
brcm_pci_msgbuf_bar0_tag(struct brcm_pci_softc *sc)	{ return (sc->sc_bar0_t); }
bus_space_handle_t
brcm_pci_msgbuf_bar0_handle(struct brcm_pci_softc *sc)	{ return (sc->sc_bar0_h); }
bus_space_tag_t
brcm_pci_msgbuf_bar2_tag(struct brcm_pci_softc *sc)	{ return (sc->sc_bar2_t); }
bus_space_handle_t
brcm_pci_msgbuf_bar2_handle(struct brcm_pci_softc *sc)	{ return (sc->sc_bar2_h); }
device_t
brcm_pci_msgbuf_dev(struct brcm_pci_softc *sc)		{ return (sc->sc_dev); }
int
brcm_pci_msgbuf_debug(struct brcm_pci_softc *sc)	{ return (sc->bus_sc.sc_debug); }
uint32_t
brcm_pci_msgbuf_rambase(struct brcm_pci_softc *sc __unused)
{
	return (BRCM_PCI_RAMBASE_43602);
}
uint32_t
brcm_pci_msgbuf_ramsize(struct brcm_pci_softc *sc)
{
	/*
	 * Return the cached value.  brcm_pci_ramsize_query halts the
	 * ARM CR4 (BRCM_ARMCR4_IOCTL_CPUHALT) to read the TCM BANKINFO;
	 * after bring-up that would kill the running firmware and hang
	 * the host on the next TCM access.
	 */
	if (sc->sc_fw_ramsize != 0)
		return (sc->sc_fw_ramsize);
	/* Before bring-up has cached it. */
	{
		uint32_t sz = 0;
		(void)brcm_pci_ramsize_query(sc, &sz);
		return (sz);
	}
}
struct brcm_pci_msgbuf *
brcm_pci_msgbuf_state(struct brcm_pci_softc *sc)
{
	return (&sc->sc_msgbuf);
}

int
brcm_pci_msgbuf_bind_intr(struct brcm_pci_softc *sc,
    driver_filter_t *filter, driver_intr_t *thread, void *arg)
{
	int error;

	if (sc->sc_irq == NULL)
		return (ENXIO);
	if (sc->sc_irq_handle != NULL)
		return (EBUSY);
	error = bus_setup_intr(sc->sc_dev, sc->sc_irq,
	    INTR_TYPE_NET | INTR_MPSAFE, filter, thread, arg,
	    &sc->sc_irq_handle);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "msgbuf: bus_setup_intr failed: %d\n", error);
		sc->sc_irq_handle = NULL;
	}
	return (error);
}

void
brcm_pci_msgbuf_event_up(struct brcm_pci_softc *sc, const uint8_t *payload,
    size_t len)
{
	if (!sc->bus_sc.sc_ic_attached)
		return;
	/*
	 * Msgbuf event buffer layout: 14 B Ethernet header + 10 B
	 * brcm_ethhdr + 48 B brcm_event_msg + data.  brcm_handle_event
	 * expects `evpos` = offset of the event_msg = 24.
	 */
	brcm_handle_event(&sc->bus_sc, payload, len, 24);
}

void
brcm_pci_msgbuf_rx_up(struct brcm_pci_softc *sc, struct mbuf *m, int rssi_dbm)
{
	if (!sc->bus_sc.sc_ic_attached || m == NULL) {
		if (m != NULL)
			m_freem(m);
		return;
	}
	(void)rssi_dbm;
#ifdef BRCM_PCI_PROBE_ONLY
	m_freem(m);
#else
	{
		struct ieee80211com *ic = &sc->bus_sc.sc_ic;
		struct ieee80211vap *vap;
		const uint8_t *p;
		uint16_t ethertype;

		if (m->m_pkthdr.len < 14) {
			m_freem(m);
			return;
		}
		if (m->m_len < 14) {
			m = m_pullup(m, 14);
			if (m == NULL)
				return;
		}
		vap = TAILQ_FIRST(&ic->ic_vaps);
		if (vap == NULL) {
			m_freem(m);
			return;
		}
		p = mtod(m, const uint8_t *);
		ethertype = (uint16_t)p[12] << 8 | p[13];

		/*
		 * EAPOL goes to the fmac helper, which wraps it and
		 * delivers it to wpa_supplicant via BPF on wlan0.
		 */
		if (ethertype == 0x888e) {
			uint8_t ap_mac[6];
			size_t plen = m->m_pkthdr.len - 14;

			memcpy(ap_mac, p + 6, 6);
			ieee80211_fmac_eapol_rx(ic, ap_mac, p + 14, plen);
			m_freem(m);
			return;
		}

		/* Normal data: deliver 802.3 frame straight to the vap. */
		m->m_pkthdr.rcvif = vap->iv_ifp;
		ieee80211_vap_deliver_data(vap, m);
	}
#endif
}

void
brcm_pci_msgbuf_unbind_intr(struct brcm_pci_softc *sc)
{
	if (sc->sc_irq_handle == NULL)
		return;
	bus_teardown_intr(sc->sc_dev, sc->sc_irq, sc->sc_irq_handle);
	sc->sc_irq_handle = NULL;
}

/* Sysctl: fire msgbuf_attach on a fw-live chip. */
static int
brcm_pci_sysctl_msgbuf_attach(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	if (sc->sc_autostart_running)
		return (EBUSY);
	return (brcm_pci_msgbuf_attach(sc));
}

/*
 * Read the firmware's runtime console at TCM console_addr.  Console
 * layout (from Linux brcmfmac):
 *   +0..+7  reserved
 *   +8..+11 buf_addr (u32) — TCM offset of ring buffer
 *   +12..+15 bufsize (u32)
 *   +16..+19 write_idx (u32) — fw increments as it prints
 *
 * We keep our own read index and print everything from it up to
 * write_idx, so each call prints what the firmware logged since the
 * previous one.
 */
static int
brcm_pci_sysctl_dump_console(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	struct brcm_pci_msgbuf *mb = brcm_pci_msgbuf_state(sc);
	uint32_t base, buf_addr, bufsize, write_idx;
	uint32_t idx, count;
	int trig = 0, error;
	char line[256];
	uint32_t linelen = 0;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	if (mb == NULL || !mb->attached) {
		device_printf(sc->sc_dev,
		    "dump_console: msgbuf not attached\n");
		return (ENOENT);
	}
	base = mb->console_addr;
	if (base == 0) {
		device_printf(sc->sc_dev,
		    "dump_console: console_addr not set\n");
		return (ENOENT);
	}
	buf_addr = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, base + 8);
	bufsize = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, base + 12);
	write_idx = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, base + 16);
	device_printf(sc->sc_dev,
	    "dump_console: base=0x%x buf=0x%x size=%u w_idx=%u r_idx=%u\n",
	    base, buf_addr, bufsize, write_idx, sc->sc_console_read_idx);

	if (bufsize == 0 || bufsize > 0x100000)
		return (EINVAL);
	idx = sc->sc_console_read_idx;
	if (idx >= bufsize)
		idx = 0;

	count = (write_idx >= idx) ?
	    (write_idx - idx) : (bufsize - idx + write_idx);
	if (count == 0) {
		device_printf(sc->sc_dev, "dump_console: no new data\n");
		return (0);
	}
	if (count > 8192)
		count = 8192;

	while (count-- > 0) {
		uint8_t ch = bus_space_read_1(sc->sc_bar2_t, sc->sc_bar2_h,
		    buf_addr + idx);
		idx++;
		if (idx >= bufsize)
			idx = 0;
		if (ch == '\r')
			continue;
		if (ch == '\n' || linelen >= sizeof(line) - 1) {
			line[linelen] = '\0';
			if (linelen > 0)
				device_printf(sc->sc_dev, "fw: %s\n", line);
			linelen = 0;
			continue;
		}
		if (ch >= 32 && ch < 127)
			line[linelen++] = ch;
	}
	if (linelen > 0) {
		line[linelen] = '\0';
		device_printf(sc->sc_dev, "fw: %s\n", line);
	}
	sc->sc_console_read_idx = idx;
	return (0);
}

/* WLC_GET_VAR */
#define	BRCM_DCMD_GET_VAR	262
/* Sysctl: write 1 to send WLC_UP. */
static int
brcm_pci_sysctl_wlc_up(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	if (sc->sc_autostart_running)
		return (EBUSY);
	error = brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_UP, 0);
	device_printf(sc->sc_dev, "wlc_up: %s (err=%d)\n",
	    error == 0 ? "ok" : "fail", error);
	if (error == 0)
		sc->bus_sc.sc_wlc_up = true;
	return (0);
}

/*
 * Sysctl: write a local flowid to run a synchronous FLOW_RING_DELETE
 * and wait for its completion, to exercise the delete protocol on its
 * own rather than during a live association.
 */
static int
brcm_pci_sysctl_delete_flowring(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int flowid = -1, error;

	error = sysctl_handle_int(oidp, &flowid, 0, req);
	if (error != 0 || req->newptr == NULL || flowid < 0)
		return (error);
	error = brcm_pci_msgbuf_flowring_delete(sc, (uint16_t)flowid);
	device_printf(sc->sc_dev,
	    "delete_flowring: local_id=%d rc=%d\n", flowid, error);
	return (0);
}

/* Sysctl: write 1 to send WLC_DOWN. */
static int
brcm_pci_sysctl_wlc_down(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	error = brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_DOWN, 0);
	device_printf(sc->sc_dev, "wlc_down: %s (err=%d)\n",
	    error == 0 ? "ok" : "fail", error);
	return (0);
}

/* Sysctl: read the cur_etheraddr iovar and format it as a MAC string. */
static int
brcm_pci_sysctl_mac_addr(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint8_t mac[6] = { 0 };
	char buf[32];
	size_t rlen = sizeof(mac);
	int error;

	error = brcm_pci_msgbuf_dcmd_get_var(sc, "cur_etheraddr",
	    mac, &rlen);
	if (error != 0 || rlen != sizeof(mac))
		snprintf(buf, sizeof(buf), "(err=%d rlen=%zu)", error, rlen);
	else
		snprintf(buf, sizeof(buf),
		    "%02x:%02x:%02x:%02x:%02x:%02x",
		    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (sysctl_handle_string(oidp, buf, sizeof(buf), req));
}

/* Firmware setup run before net80211 attach and after a cold reattach. */
static void
brcm_pci_preinit_dcmds(struct brcm_pci_softc *sc)
{
	uint8_t evmask[BRCM_EVENT_MASK_LEN];
	uint8_t buf[128];
	size_t rlen;
	uint32_t v;
	int error;

	/* GET revinfo (informational). */
	error = brcm_pci_msgbuf_dcmd_get_int(sc, BRCM_C_GET_REVINFO, &v);
	device_printf(sc->sc_dev,
	    "preinit: GET revinfo=0x%08x (err=%d)\n", v, error);

	/* GET ver (informational). */
	memset(buf, 0, sizeof(buf));
	rlen = sizeof(buf);
	error = brcm_pci_msgbuf_dcmd_get_var(sc, "ver", buf, &rlen);
	if (error == 0 && rlen > 0) {
		buf[sizeof(buf) - 1] = 0;
		device_printf(sc->sc_dev,
		    "preinit: GET ver=\"%s\"\n", (char *)buf);
	}

	/* SET mpc=1. */
	v = htole32(1);
	error = brcm_pci_msgbuf_dcmd_set_var(sc, "mpc", &v, sizeof(v));
	device_printf(sc->sc_dev,
	    "preinit: SET mpc=1 (err=%d)\n", error);

	/*
	 * GET current event_msgs, add the events we handle, SET back.
	 * Add the same set the SDIO path uses: the 43602 firmware's
	 * defaults do not include ESCAN_RESULT, so adding only E_IF
	 * leaves scans silent.
	 */
	memset(evmask, 0, sizeof(evmask));
	rlen = sizeof(evmask);
	error = brcm_pci_msgbuf_dcmd_get_var(sc, "event_msgs", evmask,
	    &rlen);
	device_printf(sc->sc_dev,
	    "preinit: GET event_msgs (err=%d)\n", error);
#define	SETBIT(m, b)	((m)[(b) / 8] |= 1u << ((b) % 8))
	SETBIT(evmask, BRCM_E_IF);
	SETBIT(evmask, BRCM_E_TYPE_ESCAN_RESULT);
	SETBIT(evmask, BRCM_E_TYPE_LINK);
	SETBIT(evmask, BRCM_E_TYPE_AUTH);
	SETBIT(evmask, BRCM_E_TYPE_ASSOC);
	SETBIT(evmask, BRCM_E_TYPE_DISASSOC);
	SETBIT(evmask, BRCM_E_DEAUTH);
	SETBIT(evmask, BRCM_E_TYPE_SET_SSID);
	SETBIT(evmask, BRCM_E_TYPE_JOIN);
	SETBIT(evmask, BRCM_E_EAPOL_MSG);
#undef	SETBIT
	error = brcm_pci_msgbuf_dcmd_set_var(sc, "event_msgs", evmask,
	    sizeof(evmask));
	device_printf(sc->sc_dev,
	    "preinit: SET event_msgs (err=%d)\n", error);

	/* SET SCAN_CHANNEL_TIME=40. */
	error = brcm_pci_msgbuf_dcmd_set_int(sc,
	    BRCM_C_SET_SCAN_CHANNEL_TIME, 40);
	device_printf(sc->sc_dev,
	    "preinit: SET SCAN_CHANNEL_TIME=40 (err=%d)\n", error);

	/* SET SCAN_UNASSOC_TIME=40. */
	error = brcm_pci_msgbuf_dcmd_set_int(sc,
	    BRCM_C_SET_SCAN_UNASSOC_TIME, 40);
	device_printf(sc->sc_dev,
	    "preinit: SET SCAN_UNASSOC_TIME=40 (err=%d)\n", error);

	/* SET txbf=1 (best-effort). */
	v = htole32(1);
	error = brcm_pci_msgbuf_dcmd_set_var(sc, "txbf", &v, sizeof(v));
	device_printf(sc->sc_dev,
	    "preinit: SET txbf=1 (err=%d)\n", error);
}

/*
 * Bring up the net80211 attachment.  Reads the chip's MAC via
 * GET_VAR("cur_etheraddr"), populates the shared brcm_softc, runs
 * the preinit DCMD chain, and calls brcm_attach() to expose the
 * driver as wlan0.  Idempotent — subsequent writes with sc_ic
 * already attached return 0 without side effects.
 */
static int
brcm_pci_net80211_attach(struct brcm_pci_softc *sc)
{
	struct brcm_softc *bsc = &sc->bus_sc;
	uint8_t mac[6] = { 0 };
	size_t rlen = sizeof(mac);
	int error;

	if (bsc->sc_ic_attached) {
		device_printf(sc->sc_dev,
		    "net80211_attach: already attached\n");
		return (0);
	}
	error = brcm_pci_msgbuf_dcmd_get_var(sc, "cur_etheraddr", mac, &rlen);
	if (error != 0 || rlen != sizeof(mac)) {
		device_printf(sc->sc_dev,
		    "net80211_attach: cur_etheraddr get failed (err=%d "
		    "rlen=%zu) — did you run msgbuf_attach first?\n",
		    error, rlen);
		return (error != 0 ? error : EIO);
	}
	memcpy(bsc->sc_macaddr, mac, sizeof(mac));
	device_printf(sc->sc_dev,
	    "net80211_attach: chip MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/*
	 * Run the preinit DCMDs before net80211 attach so the chip is
	 * configured by the time any scan or join request can arrive
	 * from userland.
	 */
	brcm_pci_preinit_dcmds(sc);

	error = brcm_attach(bsc);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "net80211_attach: brcm_attach failed %d\n", error);
		return (error);
	}
	/*
	 * Leave sup_wpa unset at attach — the join dispatch chooses the
	 * mode later.  brcm_join_wpa2 sets sup_wpa=1 (fw supplicant, PSK
	 * offload, Linux brcmfmac parity — needed for the fw to actually
	 * encrypt post-4-way data with the correct PTK); brcm_join_wpa2_
	 * host_eapol sets sup_wpa=0 (userspace wpa_supplicant runs 4-way,
	 * wsec_key installs the PTK we derived).  Forcing sup_wpa=0 here
	 * would break the firmware-supplicant mode: the chip would not
	 * transmit data, since the wsec_key path is not running.
	 */
	brcm_sysctl_attach(bsc);
	device_printf(sc->sc_dev,
	    "net80211_attach: OK — create wlan0 with "
	    "`ifconfig wlan0 create wlandev %s`\n",
	    device_get_nameunit(sc->sc_dev));
	return (0);
}

static int
brcm_pci_sysctl_net80211_attach(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	if (sc->sc_autostart_running)
		return (EBUSY);
	return (brcm_pci_net80211_attach(sc));
}

/*
 * The whole bring-up, with pauses between steps: firmware (unless it is
 * already running), msgbuf, WLC_UP, net80211.  Runs in its own thread so
 * kldload returns at once, and stops between steps if the device is
 * detaching.
 */
static void
brcm_pci_autostart(void *arg)
{
	struct brcm_pci_softc *sc = arg;
	struct brcm_softc *bsc = &sc->bus_sc;
	const char *step = "firmware";
	int error = 0;

	device_printf(sc->sc_dev, "autostart: bringing the chip up\n");
	if (!sc->sc_fw_running &&
	    (error = brcm_pci_bringup_sequence(sc)) != 0)
		goto out;
	if (bsc->sc_dying)
		goto out;
	step = "msgbuf";
	if ((error = brcm_pci_msgbuf_attach(sc)) != 0)
		goto out;
	pause("brcmup", 2 * hz);
	if (bsc->sc_dying)
		goto out;
	step = "WLC_UP";
	if ((error = brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_UP, 0)) != 0)
		goto out;
	bsc->sc_wlc_up = true;
	pause("brcmup", hz);
	if (bsc->sc_dying)
		goto out;
	step = "net80211";
	error = brcm_pci_net80211_attach(sc);
out:
	if (bsc->sc_dying)
		device_printf(sc->sc_dev, "autostart: stopped at %s for "
		    "detach\n", step);
	else if (error != 0)
		device_printf(sc->sc_dev, "autostart: %s failed (%d); the "
		    "bring-up sysctls are still there\n", step, error);
	else
		device_printf(sc->sc_dev, "autostart: up; %s is in "
		    "net.wlan.devices\n", device_get_nameunit(sc->sc_dev));
	sc->sc_autostart_running = false;
	wakeup(&sc->sc_autostart_running);
	kthread_exit();
}

/* Sysctl: detach net80211 (undo net80211_attach). */
static int
brcm_pci_sysctl_net80211_detach(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	struct brcm_softc *bsc = &sc->bus_sc;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);

	if (!bsc->sc_ic_attached) {
		device_printf(sc->sc_dev,
		    "net80211_detach: not attached\n");
		return (0);
	}
	brcm_detach(bsc);
	device_printf(sc->sc_dev, "net80211_detach: OK\n");
	return (0);
}

/*
 * ACPI S3 / D3 suspend/resume.  Refused by default (opt in with
 * hw.brcm_pci.pm_supported=1).  Warm resume works when the platform
 * keeps aux power to the chip; after a cold resume (chip power off)
 * resume falls back to brcm_pci_cold_reattach, and if that fails the
 * module has to be reloaded.
 *
 *   - Suspend: brings VAPs to INIT, sends WLC_DOWN, then the mbdata
 *     D3 handshake (H2D_HOST_D3_INFORM + wait for D2H_DEV_D3_ACK,
 *     2 s timeout).  If the fw acks, DMA is quiesced before ACPI
 *     removes power.
 *   - Resume: sends H2D_HOST_D0_INFORM (the firmware does not ack
 *     D0), then re-issues WLC_UP.  If WLC_UP succeeds the chip was
 *     warm and net80211 is usable again; otherwise the chip is
 *     treated as cold and rebuilt.
 */
static int brcm_pci_pm_supported = 0;
SYSCTL_INT(_hw_brcm_pci, OID_AUTO, pm_supported, CTLFLAG_RDTUN,
    &brcm_pci_pm_supported, 0,
    "Allow S3/D3 suspend/resume attempts.  Default 0 = refuse suspend "
    "(safe).  Set to 1 in loader.conf for best-effort warm-resume; "
    "cold resume still requires kldunload+kldload.");

static int
brcm_pci_suspend(device_t dev)
{
	struct brcm_pci_softc *sc = device_get_softc(dev);
	struct brcm_softc *bsc = &sc->bus_sc;
	struct ieee80211vap *vap;
	uint32_t v;

	if (!brcm_pci_pm_supported) {
		device_printf(dev,
		    "suspend refused (hw.brcm_pci.pm_supported=0); "
		    "set to 1 in loader.conf to opt into best-effort PM\n");
		return (EOPNOTSUPP);
	}

	/*
	 * Best-effort suspend: bring each vap back to INIT so net80211
	 * flushes state cleanly, then send WLC_DOWN so the fw stops
	 * autonomous DMA before the bus takes the chip's power away.
	 */
	if (bsc->sc_ic_attached) {
		vap = TAILQ_FIRST(&bsc->sc_ic.ic_vaps);
		if (vap != NULL)
			(void)ieee80211_new_state(vap, IEEE80211_S_INIT, -1);
	}
	if (bsc->sc_wlc_up) {
		v = htole32(0);
		(void)brcm_dcmd_set(bsc, BRCM_C_DOWN, &v, sizeof(v));
		bsc->sc_wlc_up = false;
	}

	/*
	 * D3 mailbox handshake: send H2D_HOST_D3_INFORM and wait up to
	 * 2 s for the fw to reply with D2H_DEV_D3_ACK.  Ack means fw has
	 * quiesced its DMA and is ready for the bus to remove power;
	 * silence past the timeout is not fatal, and resume copes with
	 * whatever state the chip is left in.
	 */
	{
		int rc = brcm_pci_msgbuf_send_mb_data(sc,
		    BRCM_H2D_HOST_D3_INFORM);
		if (rc == 0) {
			rc = brcm_pci_msgbuf_wait_mb_ack(sc,
			    BRCM_D2H_DEV_D3_ACK, 2000);
			device_printf(dev,
			    "suspend: D3_INFORM sent, D3_ACK rc=%d\n", rc);
		} else {
			device_printf(dev,
			    "suspend: D3_INFORM send rc=%d — proceeding "
			    "without ack\n", rc);
		}
	}
	device_printf(dev, "suspend: WLC_DOWN + D3, awaiting resume\n");
	return (0);
}

static int
brcm_pci_resume(device_t dev)
{
	struct brcm_pci_softc *sc = device_get_softc(dev);
	struct brcm_softc *bsc = &sc->bus_sc;
	uint32_t v;

	if (!brcm_pci_pm_supported)
		return (0);

	/*
	 * D0 mailbox notify: after ACPI has restored bus power the
	 * fw expects H2D_HOST_D0_INFORM before it will accept any
	 * DMA / DCMD traffic again.  The firmware does not ack D0 the
	 * way it acks D3.  If the D3 side never reached the firmware the
	 * message is meaningless but harmless.
	 */
	(void)brcm_pci_msgbuf_send_mb_data(sc, BRCM_H2D_HOST_D0_INFORM);

	/*
	 * Warm resume: if config space still reads the chip's vendor ID
	 * the PCIe link is up and the firmware is likely alive, so
	 * re-issuing WLC_UP is all that is needed.  Config space is
	 * served by the root complex, so the probe is safe even on a cold
	 * chip; it just returns 0xffff and we take the cold path.
	 */
	if (brcm_pci_chip_alive_cfg(sc)) {
		v = htole32(1);
		if (brcm_dcmd_set(bsc, BRCM_C_UP, &v, sizeof(v)) == 0) {
			bsc->sc_wlc_up = true;
			device_printf(dev,
			    "resume: warm ok (chip retained)\n");
			return (0);
		}
		device_printf(dev,
		    "resume: warm WLC_UP failed — falling back to cold\n");
	} else {
		device_printf(dev,
		    "resume: chip cfg absent — cold reattach\n");
	}

	/*
	 * Cold resume: the firmware is gone, so rebuild everything (see
	 * brcm_pci_cold_reattach).  net80211 stays attached and the VAP
	 * re-associates once the firmware is up.
	 */
	if (brcm_pci_cold_reattach(sc) != 0) {
		device_printf(dev,
		    "resume: cold reattach failed — kldunload+kldload "
		    "to recover\n");
	}
	return (0);
}

static device_method_t brcm_pci_methods[] = {
	DEVMETHOD(device_probe,		brcm_pci_probe),
	DEVMETHOD(device_attach,	brcm_pci_attach),
	DEVMETHOD(device_detach,	brcm_pci_detach),
	DEVMETHOD(device_suspend,	brcm_pci_suspend),
	DEVMETHOD(device_resume,	brcm_pci_resume),
	DEVMETHOD_END
};

static driver_t brcm_pci_driver = {
	"brcm_pci",
	brcm_pci_methods,
	sizeof(struct brcm_pci_softc)
};

DRIVER_MODULE(brcm_pci, pci, brcm_pci_driver, NULL, NULL);
MODULE_DEPEND(brcm_pci, pci, 1, 1, 1);
#ifndef BRCM_PCI_PROBE_ONLY
MODULE_DEPEND(brcm_pci, wlan, 1, 1, 1);
#endif
MODULE_VERSION(brcm_pci, 1);
