/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC PCIe transport glue for brcm.
 *
 * Step 1 scaffold — what's here today:
 *   1. PCI ID match for the BCM43602 / BCM4360 / BCM43xx family used
 *      in Apple, Intel, and various consumer wireless modules.
 *   2. BAR0 (chip control / register window) + BAR2 (chip RAM / shared
 *      memory window) resource allocation.
 *   3. MSI/MSI-X allocation — single vector for the skeleton, will
 *      expand to MSGBUF doorbell vectors in step 2.
 *   4. Read of the PCI config-space class / revision + a sanity-check
 *      read from BAR0 offset 0 so we know the BAR window is alive.
 *   5. bus_ops vtable wired up but mostly stubbed — bs_stop and noop
 *      placeholders so brcm_attach has something to embed against.
 *      bs_dcmd_get/set + bs_iovar_get/set arrive in step 2 with the
 *      MSGBUF protocol layer.
 *
 * Step 2 (next) will add: backplane-core walking + chip ID/rev read
 * via the chipcommon core, firmware download (BAR2-mapped chip RAM
 * + ARM reset/release), pciedev_shared_t handshake, MSGBUF SUBMIT /
 * COMPLETE ring init, doorbell IRQ handling, and the bs_dcmd_* /
 * bs_iovar_* implementations against the SUBMIT ring.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kdb.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
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
static int brcm_pci_sysctl_pmu_init(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_crwlpciegen2(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_reg_pm_clk_period(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_clkctl_init(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_LTR_war(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_pmu_slow_clk(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_slave_wrapper(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_clkctl_clk(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_pci_up(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_otp_dump(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_srom_parse_self(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_net80211_attach(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_net80211_detach(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_msgbuf_attach(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_dump_console(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_dcmd_probe(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_flow_create(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_tx_probe(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_wlc_up(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_wlc_down(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_set_infra(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_set_wsec(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_set_country(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_set_ssid(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_mac_addr(SYSCTL_HANDLER_ARGS);
static int brcm_pci_sysctl_disassoc(SYSCTL_HANDLER_ARGS);

/*
 * Loader tunables — SAFETY GATES for risky attach-time behavior.
 *
 * BOOT-WEDGE PROTECTION RULE: any attach-time chip operation that
 * COULD wedge the host must be gated behind a default-off tunable.
 * If it wedges the box during testing, a normal reboot puts the
 * tunable back to default (safe) and the box comes up without
 * requiring USB rescue.
 *
 * Set in /boot/loader.conf, e.g.:
 *   hw.brcm_pci.attach_bringup="1"    # opt-in only for testing
 *
 * Attach reads these via `resource_int_value` at each device attach
 * (so they can also be set per-instance via device.hints).
 */
static int brcm_pci_attach_appu_warm_dflt = 1;    /* PROVEN SAFE */
SYSCTL_NODE(_hw, OID_AUTO, brcm_pci, CTLFLAG_RD, 0, "brcm_pci driver tunables");
SYSCTL_INT(_hw_brcm_pci, OID_AUTO, attach_appu_warm, CTLFLAG_RDTUN,
    &brcm_pci_attach_appu_warm_dflt, 0,
    "Run APPU warm sequence at attach.  Default 1 (safe, proven).  "
    "Set to 0 in loader.conf to disable if it ever regresses.");
static int brcm_pci_debug_sysctls = 0;
SYSCTL_INT(_hw_brcm_pci, OID_AUTO, debug_sysctls,
    CTLFLAG_RDTUN, &brcm_pci_debug_sysctls, 0,
    "Register the full ~70-sysctl debug tree (0=essential only, "
    "1=all).  Set in /boot/loader.conf as "
    "hw.brcm_pci.debug_sysctls=\"1\" during kernel-driver debugging.");
/*
 * attach_bringup tunable REMOVED (was: hw.brcm_pci.attach_bringup).
 *
 * A wedge inside bringup and a persistent value in loader.conf creates
 * an infinite boot-wedge loop that only USB rescue can break.
 * Attach-time bringup is disabled entirely.  Users MUST fire bringup
 * via the runtime sysctl `dev.brcm_pci.N.bringup=1` — that path is
 * per-session, so if it wedges, next reboot is clean automatically.
 */

/* Vendor IDs. */
#define	BRCM_PCI_VENDOR_BROADCOM	0x14e4

/*
 * Device IDs.  Names map to the chip family; some IDs are shared
 * across multiple silicon revisions and only the chipid register
 * read (step 2) disambiguates.
 */
#define	BRCM_PCI_DEVICE_BCM4350	0x43a3	/* BCM4350 / BCM4356 / BCM4358 */
#define	BRCM_PCI_DEVICE_BCM4360	0x43a0	/* BCM4360 3x3 */
#define	BRCM_PCI_DEVICE_BCM4360_2	0x43a2	/* BCM4360 2x2 */
#define	BRCM_PCI_DEVICE_BCM43602	0x43ba	/* Apple A1398 + others */
#define	BRCM_PCI_DEVICE_BCM4366C	0x4415	/* BCM4366c */
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
 * enter_download_state.  43602 has SOCRAM (0x80e); 4360-family have
 * BUF_MEM (0x81a) instead, which uses different bank-power semantics.
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
	  .mem_core		= 0x80e,	/* BRCM_CORE_SOCRAM (defined below) */
	  .fw_name		= "brcmfmac43602_pcie",
	  .bringup_supported	= true,
	  .notes		= "43602 - fully supported"
	},

	/*
	 * BCM4360 (14e4:43a0) - Apple 3x3 802.11ac.  Ships on RockPro64
	 * (armbsd) as a PCIe M.2 card with Apple subvendor 106b:0117.
	 * Probe / core_walk / dstate_cycle work; bringup NOT implemented
	 * (2026-07-19 wedged armbsd running 43602-specific PMU init).
	 *
	 * When implementing bringup:
	 *   - Rambase: 0x0 (chip 4360 loads fw at rambase 0 —
	 *     different from 43602's 0x180000)
	 *   - fw name: brcmfmac4360-pcie.bin
	 *   - Memory core: BUF_MEM (0x81a), not SOCRAM.  No SOCRAM bank
	 *     powerup — 4360 has a single BUF_MEM aperture.
	 *   - Skip pmu_init_43602 (chip-specific tables).
	 *   - Skip pll_init_43602 (Apple 43602-specific PLLCTL values).
	 */
	/*
	 * BCM4360 (chip 0x4360, distinct from BCM43602 chip 0x43602).
	 * Only the proprietary broadcom-wl driver supports it, using D11
	 * core ucode directly (not ARM-CR4 fw upload).  Our bringup
	 * steps 1-9 all pass (with pmu_init_4360 max_res guard +
	 * rambase=0 for BAR2 fit) but step 10 wait_fw_ready times out
	 * -- v7.15 Apple 43602 fw can't run on 4360 silicon.
	 *
	 * Keep bringup_supported=false so bringup=1 refuses cleanly with
	 * a clear EOPNOTSUPP.  Chip-info stays populated so
	 * probe/warmup diagnostics still work and someone with a real
	 * 4360-native fw can flip the flag.
	 */
	{ .devid		= BRCM_PCI_DEVICE_BCM4360,
	  .rambase		= 0x0,
	  .mem_core		= 0x81a,	/* BUF_MEM */
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
	 * Everything else - probe only for now.  These entries stop the
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
 * BAR0 windowing.  The BAR0 region is a 4 KB sliding window onto the
 * chip-side backplane address space.  BAR0 offset 0x80 is the window
 * register: write the top 20 bits of the target backplane address
 * there, then read/write at BAR0[low 12 bits] to reach the desired
 * chip register.
 *
 * The PCIe2 core's own registers (IRQ mailbox, doorbells, link
 * status) live at fixed BAR0 offsets >= 0x90 that are not affected
 * by the window; the windowing only retargets BAR0[0x0..0x7f].
 */
#define	BRCM_PCI_BAR0_WINDOW		0x80
#define	BRCM_PCI_BAR0_WINDOW_MASK	0xfffff000	/* top 20 bits */
#define	BRCM_PCI_BAR0_WINDOW_OFF_MASK	0x00000fff	/* low 12 bits */

/*
 * PCIe2 core fixed-offset registers.  These live within BAR0 but are
 * NOT subject to the SBTOPCI windowing — they're the host-side PCIe
 * controller's own registers, accessible whenever the BAR is mapped
 * and the chip is in D0.  Used for probing whether the chip is awake
 * before any windowed backplane access.
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
 * Chip IDs we expect to see via the chipID register.  These are the
 * raw values the chip programs into ChipCommon[0]; Broadcom calls
 * them "decimal" chip IDs in their wiki even though the register
 * holds them in hex.  Examples: BCM43602 → 0xaa52 (43602 decimal),
 * BCM4366 → 0x4366 directly).  Confirmed by reading the live
 * ChipCommon[0] on the macbsd A1398 BCM43602: 0x1601aa52 →
 * chip=0xaa52, rev=1, ncores=6.
 */
#define	BRCM_CHIP_BCM43602		0xaa52
#define	BRCM_CHIP_BCM4360		0x4360
#define	BRCM_CHIP_BCM4350		0x4350
#define	BRCM_CHIP_BCM4356		0x4356
#define	BRCM_CHIP_BCM4358		0x4358
#define	BRCM_CHIP_BCM4365		0x4365
#define	BRCM_CHIP_BCM4366		0x4366

/*
 * MMIO range monitor — captures a baseline of BAR0 register space so a
 * `snapshot_save -> action -> snapshot_diff` sequence shows the user
 * exactly what an action changed.  Per the standard RE technique from
 * the Mali T-860 bring-up: cheap to scaffold, pays for itself the first
 * afternoon you don't have a working reference to consult.
 *
 * The snapshot is sized for BAR0's PCIe2-core fixed-offset region
 * (~512 bytes at offsets 0x80..0x2ff on BCM43602).  Avoid snapshotting
 * the SBTOPCI-windowed region (0x0..0x7f) — its contents shift under
 * us as the window register moves.
 */
#define	BRCM_PCI_SNAP_BASE	0x80
#define	BRCM_PCI_SNAP_LEN	0x200	/* 512 bytes / 128 dwords */

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
	 * Reverse-engineering scratch.  All of this is touched only via
	 * sysctl handlers — never from attach().  On Apple A1398 the
	 * BCM43602 chip is held in a gated state until both the EC.APWC
	 * bit and an unknown second step are cleared; any blind BAR0
	 * read in that state master-aborts the host (MCE -> reboot).
	 * Keeping the unsafe probes behind sysctls means kldload of this
	 * module always succeeds, and the user can opt in to each probe
	 * one at a time after they've established the chip is alive.
	 */
	bool			 sc_chip_alive;
	uint32_t		 sc_probe_addr;
	uint32_t		 sc_probe_last_read;
	uint32_t		 sc_probe_last_write;
	bool			 sc_chip_probe_break;
	uint32_t		 sc_pmu_init_stage;	/* 4360 bisect stage */
	uint32_t		 sc_bringup_stop_after;	/* bringup bisect */
	uint32_t		 sc_snapshot[BRCM_PCI_SNAP_LEN / 4];
	bool			 sc_snapshot_valid;
	/* FW-ready sentinel captured from TCM[ramsize-4] by wait_fw_ready */
	uint32_t		 sc_fw_sharedram;
	/* Cached RAM size in bytes; captured during bringup step 4 (safe:
	 * fw not loaded yet).  Any later ramsize call must use this — calling
	 * brcm_pci_ramsize_query after fw boot HALTS the running CR4. */
	uint32_t		 sc_fw_ramsize;
	/* dump_console read cursor into the fw log ring. */
	uint32_t		 sc_console_read_idx;
	/* TCM memory range monitor (BAR2) */
	uint32_t		 sc_tcm_range_offset;
	uint32_t		 sc_tcm_range_words;
	uint32_t		 sc_tcm_range_prev[64];
	bool			 sc_tcm_range_valid;

	struct brcm_pci_core	 sc_cores[BRCM_PCI_MAX_CORES];
	int			 sc_ncores;
	bool			 sc_bar2_sized;

	struct brcm_pci_msgbuf	 sc_msgbuf;
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
 * On A1398-class MacBook Pros the BCM43602's PCIe link is held in
 * a clock-gated / disabled state at boot.  Even with bring-up to
 * D0 via PMCSR, BAR0 cycles return 0xffffffff because the chip's
 * PCIe controller isn't responding.  The DSDT exposes an `APPU`
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
 * Apple A1398 EC port write.
 *
 * On the Apple A1398 platform the BCM43602's PCIe memory decoder
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
 * Apple A1398 WAPS — "Wake AirPort Subsystem".
 *
 * Discovered by reading the macbsd DSDT (\_SB.PCI0.RP03.WAPS, called
 * by APPU at 6630 after the EC.APWC=1 step succeeds).  EC.APWC=1
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
 * All accesses are PCI config-space — completely safe on a gated
 * chip.  Verification: read BDDR after the sequence; if it returns
 * 0x0152106B the chip has accepted the program.  (Confirmed by the
 * ARPT._PS0 method at line 6773 which uses exactly this read as
 * the "already unlocked" cache check.)
 */
#define	BRCM_PCI_BD_MR	0x80
#define	BRCM_PCI_BD_EN	0x88
#define	BRCM_PCI_BD_IR	0xa0
#define	BRCM_PCI_BD_DR	0xa4

static int
brcm_pci_apple_waps(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint32_t r;

	r = pci_read_config(dev, BRCM_PCI_BD_DR, 4);
	device_printf(dev,
	    "waps: BDDR before = 0x%08x (target 0x0152106b)\n", r);
	if (r == 0x0152106bU) {
		device_printf(dev,
		    "waps: chip already programmed, skipping\n");
		return (0);
	}

	pci_write_config(dev, BRCM_PCI_BD_EN, 0x40,       4);
	pci_write_config(dev, BRCM_PCI_BD_MR, 0x18003000, 4);
	pci_write_config(dev, BRCM_PCI_BD_IR, 0x00000120, 4);
	pci_write_config(dev, BRCM_PCI_BD_DR, 0x00000438, 4);
	pci_write_config(dev, BRCM_PCI_BD_IR, 0x00000124, 4);
	pci_write_config(dev, BRCM_PCI_BD_DR, 0x0152106b, 4);
	pci_write_config(dev, BRCM_PCI_BD_EN, 0x00000000, 4);

	r = pci_read_config(dev, BRCM_PCI_BD_DR, 4);
	device_printf(dev,
	    "waps: BDDR after  = 0x%08x %s\n", r,
	    r == 0x0152106bU ? "(UNLOCKED)" : "(still gated)");

	return (r == 0x0152106bU ? 0 : EIO);
}

static int
brcm_pci_apple_ec_unlock(struct brcm_pci_softc *sc)
{
	uint8_t b;
	int error;

	error = brcm_pci_ec_read_byte(BRCM_EC_APWC_OFFSET, &b);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "EC read APWC byte failed (errno %d)\n", error);
		return (error);
	}
	device_printf(sc->sc_dev,
	    "EC APWC byte before: 0x%02x (APWC bit = %d)\n",
	    b, (b & BRCM_EC_APWC_BIT) ? 1 : 0);
	if ((b & BRCM_EC_APWC_BIT) != 0) {
		device_printf(sc->sc_dev, "EC APWC already set, skip\n");
		return (0);
	}
	error = brcm_pci_ec_write_byte(BRCM_EC_APWC_OFFSET,
	    b | BRCM_EC_APWC_BIT);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "EC write APWC failed (errno %d)\n", error);
		return (error);
	}
	DELAY(100000);	/* 100 ms for chip wake */
	(void)brcm_pci_ec_read_byte(BRCM_EC_APWC_OFFSET, &b);
	device_printf(sc->sc_dev,
	    "EC APWC byte after:  0x%02x (APWC bit = %d)\n",
	    b, (b & BRCM_EC_APWC_BIT) ? 1 : 0);
	return (0);
}

/*
 * Force a 1→0→1 transition on APWC.  Needed when the bit persists
 * across reboots and apple_ec_unlock becomes a no-op — the EC only
 * wakes the chip on the RISING EDGE of APWC.  Clearing the bit,
 * waiting, and setting it again re-issues the wakeup pulse.
 */
static int
brcm_pci_apple_ec_cycle(struct brcm_pci_softc *sc)
{
	uint8_t b;
	int error;

	error = brcm_pci_ec_read_byte(BRCM_EC_APWC_OFFSET, &b);
	if (error != 0)
		return (error);
	device_printf(sc->sc_dev,
	    "EC APWC cycle: byte = 0x%02x (bit=%d) -- clearing\n",
	    b, (b & BRCM_EC_APWC_BIT) ? 1 : 0);
	error = brcm_pci_ec_write_byte(BRCM_EC_APWC_OFFSET,
	    b & ~BRCM_EC_APWC_BIT);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "EC APWC cycle: clear write failed (errno %d)\n", error);
		return (error);
	}
	/*
	 * Long rail-off dwell.  200ms was tried and didn't work — chip
	 * stayed cold.  3s gives EC time to fully de-power the rail and
	 * for the chip's internal state to fully decay to cold before we
	 * re-assert APWC.  Mirror what a full power-off would do.
	 */
	pause("apwcoff", hz * 3);  /* 3s */
	(void)brcm_pci_ec_read_byte(BRCM_EC_APWC_OFFSET, &b);
	device_printf(sc->sc_dev,
	    "EC APWC cycle: cleared byte = 0x%02x -- setting\n", b);
	error = brcm_pci_ec_write_byte(BRCM_EC_APWC_OFFSET,
	    b | BRCM_EC_APWC_BIT);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "EC APWC cycle: set write failed (errno %d)\n", error);
		return (error);
	}
	pause("apwcon", hz / 2);  /* 500ms rail-on dwell */
	(void)brcm_pci_ec_read_byte(BRCM_EC_APWC_OFFSET, &b);
	device_printf(sc->sc_dev,
	    "EC APWC cycle: final byte = 0x%02x (bit=%d)\n",
	    b, (b & BRCM_EC_APWC_BIT) ? 1 : 0);
	return (0);
}

/*
 * Reimplementation of the DSDT APPU method as native C.
 *
 * Decoded from the host DSDT via `iasl -da -e ssdt*.dat dsdt.dat`.
 * The macOS warm-up path on this <Mac model> is:
 *   RP03._PS0 -> ALPR(0) -> APPU()
 * APPU's inner loop:
 *   1. Write \_SB.PCI0.LPCB.EC.APWC = 0x01 (Apple EC APWC bit) -- our
 *      brcm_pci_apple_ec_write does this.
 *   2. Sleep 0xFA = 250ms.
 *   3. Poll for 10s (10 million 100ns Timer ticks / 10ms Sleeps):
 *        (LACT == 1) && (\_SB.PCI0.RP03.ARPT.AVND != 0xFFFF)
 *      LACT = Link Active bit on parent bridge's PCIe LinkStatus.
 *      AVND = chip's PCI vendor ID via ARPT config-space.
 *   4. If poll fails, write APWC=0, sleep 0x0107=263ms, retry up to
 *      5 attempts total.
 *
 * FreeBSD equivalent below - native C so the 10s poll runs OUTSIDE
 * the ACPICA interpreter mutex (avoiding the spin-lock-held-too-long
 * panic that killed all prior AcpiEvaluateObject("APPU") attempts).
 *
 * On success, chip's ChipID (BAR0[0x00]) transitions from 0xffffffff
 * (cold) to 0xaa52 (BCM43602 warm signature).  Verify with subsequent
 * dev.brcm_pci.N.chip_alive=1.
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

static int
brcm_pci_sysctl_apple_appu_warm(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	return (brcm_pci_apple_appu_warm(sc));
}

/*
 * Apple A1398 (BCM43602) unlock — pure PCI config space.
 *
 * Earlier attempts that called either APPU or _PS0 via
 * AcpiEvaluateObject crashed macbsd with what looks like a
 * "spin lock held too long" watchdog panic: those AML methods
 * spin on LACT (PCIe link-active) for up to 10 seconds under the
 * ACPICA interpreter mutex, blowing through FreeBSD's spin-lock
 * deadline.  Avoid touching ACPI here; just do the minimum that
 * APPU's happy path does after its guards clear:
 *
 *   - clear the parent bridge's PCIe Link Disable bit (bit 4 of
 *     the PCIe Express Capability's Link Control register at
 *     cap_offset + 0x10) so the link can train.
 *
 * Pure config-space read+write, milliseconds at most.  The EC bit
 * step (\_SB.PCI0.LPCB.EC.APWC = 1) is still TODO; if BAR access
 * is still blocked after this, that's the next thing.
 */
static int
brcm_pci_apple_powerup(struct brcm_pci_softc *sc)
{
	device_t bridge;
	int pcie_cap;
	uint16_t lcr;

	bridge = device_get_parent(device_get_parent(sc->sc_dev));
	if (bridge == NULL)
		return (ENOENT);

	if (pci_find_cap(bridge, PCIY_EXPRESS, &pcie_cap) != 0)
		return (ENOENT);

	lcr = pci_read_config(bridge, pcie_cap + PCIER_LINK_CTL, 2);
	device_printf(sc->sc_dev,
	    "parent bridge PCIe Link Control = 0x%04x (LDIS=%d)\n",
	    lcr, (lcr & PCIEM_LINK_CTL_LINK_DIS) ? 1 : 0);
	if ((lcr & PCIEM_LINK_CTL_LINK_DIS) != 0) {
		pci_write_config(bridge, pcie_cap + PCIER_LINK_CTL,
		    lcr & ~PCIEM_LINK_CTL_LINK_DIS, 2);
		device_printf(sc->sc_dev,
		    "cleared parent bridge LDIS\n");
	}

	/*
	 * Diagnostic dump.  Read-only, all PCI config space.  Tells us
	 * whether the bridge looks sane (link up, memory window
	 * covering the BAR0 / BAR2 range, etc.).
	 */
	{
		uint16_t bcr, lsr, dsr;
		uint32_t memb_lim, pref_lim;
		uint8_t pri, sec, sub;

		bcr = pci_read_config(bridge, PCIR_BRIDGECTL_1, 2);
		pri = pci_read_config(bridge, PCIR_PRIBUS_1, 1);
		sec = pci_read_config(bridge, PCIR_SECBUS_1, 1);
		sub = pci_read_config(bridge, PCIR_SUBBUS_1, 1);
		memb_lim = pci_read_config(bridge, PCIR_MEMBASE_1, 4);
		pref_lim = pci_read_config(bridge, PCIR_PMBASEL_1, 4);
		lsr = pci_read_config(bridge, pcie_cap + PCIER_LINK_STA, 2);
		dsr = pci_read_config(bridge, pcie_cap + PCIER_DEVICE_STA, 2);

		device_printf(sc->sc_dev,
		    "bridge: bus pri=%u sec=%u sub=%u bctl=0x%04x\n",
		    pri, sec, sub, bcr);
		device_printf(sc->sc_dev,
		    "bridge: mem window 0x%04x..0x%04x prefetch 0x%04x..0x%04x\n",
		    (memb_lim & 0xffff) << 16 >> 16,
		    (memb_lim >> 16) | 0xfffff,
		    (pref_lim & 0xffff) << 16 >> 16,
		    (pref_lim >> 16) | 0xfffff);
		device_printf(sc->sc_dev,
		    "bridge: PCIe Link Status 0x%04x "
		    "(LinkSpeed=%u, LinkWidth=%u, DLLLA=%d)\n",
		    lsr, lsr & 0xf, (lsr >> 4) & 0x3f,
		    (lsr & PCIEM_LINK_STA_DL_ACTIVE) ? 1 : 0);
		device_printf(sc->sc_dev,
		    "bridge: PCIe Device Status 0x%04x (CED=%d NFD=%d "
		    "FED=%d UR=%d TP=%d)\n",
		    dsr,
		    (dsr & PCIEM_STA_CORRECTABLE_ERROR) ? 1 : 0,
		    (dsr & PCIEM_STA_NON_FATAL_ERROR)   ? 1 : 0,
		    (dsr & PCIEM_STA_FATAL_ERROR)       ? 1 : 0,
		    (dsr & PCIEM_STA_UNSUPPORTED_REQ)   ? 1 : 0,
		    (dsr & PCIEM_STA_TRANSACTION_PND)   ? 1 : 0);
	}

	return (0);
}

/* ------------------------------------------------------------------
 * BAR0 windowing helpers.
 *
 * Reads/writes against backplane-side chip registers always go
 * through the sliding window register at BAR0[0x80].  The helpers
 * here cache the most recently programmed window so back-to-back
 * accesses to the same core don't re-touch the window register.
 *
 * Concurrency: the window register is per-device chip state.  Until
 * step 2 wires the MSGBUF doorbell IRQ handler (which will need its
 * own access to the PCIe2 fixed offsets >= 0x90, not the windowed
 * 0x0..0x7f region), the only caller is the attach thread, so no
 * lock is needed.  Once IRQs arrive, a sc_reg_mtx will guard the
 * window register and the BAR0[<0x80] access pair.
 * ------------------------------------------------------------------ */

static void
brcm_pci_set_window(struct brcm_pci_softc *sc, uint32_t addr)
{
	uint32_t want = addr & BRCM_PCI_BAR0_WINDOW_MASK;

	/*
	 * The window register lives at PCI config offset 0x80, NOT at
	 * BAR0 memory offset 0x80.  Earlier attempts to drive it via
	 * bus_space_write_4(BAR0, 0x80, addr) did not change which
	 * backplane region BAR0 mapped onto (verified on Apple A1398:
	 * ChipID came back as 0x00010192 from whatever the default
	 * chip-side mapping was, not the BCM43602's actual ChipID
	 * 0xa886).  The DSDT's WAPS method drives the same register
	 * via config space.
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
 * Cfg-space-only chip-alive test — never wedges even on cold backplane
 * (cfg is served by the RC).  Does NOT prove BAR0 MMIO is safe.
 * Mirrors macOS AppleBCMWLANBusInterfacePCIe attachPCIeBusGated.
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

	/* Backplane-data read through cfg-space window (see macOS decomp). */
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
 * Walking via SBTOPCI window for every read is slow but fine:
 *   ChipCommon stays at the same 4KB window so window writes are
 *   nearly free once we settle the cache (set_window short-circuits
 *   when the target hasn't changed — see brcm_pci_set_window).
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
 * Firmware blob is wrapped as kld brcm_pci_fw_43602.
 * ARM-CR4 reset vector sits at offset 0 of the blob (just the
 * first le32 from the file).
 * We stash it for the post-load ARM-CR4 release sequence (not yet
 * wired).
 *
 * Pre-load metadata dump: the strings at the tail of the blob
 * carry the firmware version + feature list (43602a1-roml/pcie
 * Version: 7.35.177.61 ...).  Logging them at upload time gives
 * us a clear signal in dmesg that we loaded the firmware we think
 * we loaded.
 *
 * Studied before writing: blob is raw ARM-CR4 image (no ELF/Mach-O
 * header), 635 KB, 4-byte-aligned for memcpy-style upload.  No
 * embedded relocation table or signature — Broadcom assumes the
 * loader knows the chip's rambase.
 * ------------------------------------------------------------------ */

#define	BRCM_PCI_FW_43602	"brcmfmac43602_pcie"
#define	BRCM_PCI_RAMBASE_43602	0x180000	/* per-chip TCM base */
#define	BRCM_PCI_FW_VERSTRING_MAX	256

/*
 * Minimal synthetic NVRAM for BCM43602 on Apple A1398 (<Mac model>).
 *
 * Apple's AirPortBrcmNIC kext carries per-board NVRAM tables keyed by
 * model — extracting our model's exact bytes is a few hours of Mach-O
 * walking, deferred.  This blob is the smallest viable set of fields
 * the firmware needs to complete its boot handshake (write the shared-
 * mem pointer to BAR2[rambase+ramsize-4]) so we can wire MSGBUF + bring
 * the net80211 vap up.  Radio cal coefficients (antenna switch tables,
 * PA cal, BT coex) are omitted: the chip falls back to its on-die fuse
 * defaults — link will work but suboptimal until the real NVRAM is
 * extracted from AirPortBrcmNIC.
 *
 * Field choices:
 *   manfid    = 0x14e4   Broadcom (chip rejects mismatched manfid)
 *   prodid    = 0xaa52   BCM43602 chipID (per our chip_id sysctl read)
 *   devid     = 0x43ba   PCI device ID (cfg space matches)
 *   boardvendor=0x106b   Apple (subv in cfg 0x2C)
 *   boardtype = 0x0152   Apple A1398 SS-device ID
 *   boardrev  = 0x1319   Real Apple A1398 board rev, read from live
 *                        chip via macOS IOKit (IO80211HardwareVersion).
 *                        Prior value 0x1402 was a common-43602a1
 *                        guess and was WRONG.
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
 * 0x18003000).  Used to re-size the BAR2 aperture so it actually
 * maps to chip TCM (without this step a single BAR2 write
 * Target-Aborts the host).
 */
#define	BRCM_PCIE2_CONFIGADDR	0x120
#define	BRCM_PCIE2_CONFIGDATA	0x124
#define	BRCM_PCIE2_CFG_BAR2RESIZE	0x4e0	/* internal cfg index */

/* ChipCommon watchdog register: writing N here triggers a chip-wide
 * reset after N ticks (use 4). */
#define	BRCM_CC_REG_WATCHDOG	0x80

/* ChipCommon PMU register block — offsets relative to ChipCommon
 * core base.
 */
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
 * D11 into "PHY clock on, PHY reset asserted" before firmware load
 * — without this the WiFi MAC core can interact with shared
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

/* Forward decl — err_dump lives in the sysctl section below. */
static int	brcm_pci_err_dump(struct brcm_pci_softc *sc, const char *tag);

/*
 * Helper: read the wrapper registers of a named core.  Wrapper regs
 * (IOCTL at 0x408, RESET_CTL at 0x800) live in the BACKPLANE
 * INTERCONNECT decoder, which is always alive even when the core
 * itself is off — that's how you turn a core on.  If reading the
 * wrap regs hangs, the interconnect is broken; otherwise the regs
 * tell us whether the core is in reset and whether its clock is on.
 *
 * Returns 0 on success and fills out *ioctl_p and *reset_p.
 */
static int
brcm_pci_core_wrap_dump(struct brcm_pci_softc *sc, uint16_t coreid,
    uint32_t *ioctl_p, uint32_t *reset_p)
{
	uint32_t wrap = 0;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == coreid) {
			wrap = sc->sc_cores[i].wrap;
			break;
		}
	}
	if (wrap == 0) {
		device_printf(sc->sc_dev,
		    "core_wrap_dump: core 0x%03x has no wrap base\n",
		    coreid);
		return (ENOENT);
	}

	brcm_pci_set_window(sc, wrap);
	*ioctl_p = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	*reset_p = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	PDPRINTF(sc, 0,
	    "core_wrap_dump: %s (id=0x%03x wrap=0x%08x) "
	    "IOCTL=0x%08x RESET_CTL=0x%08x %s%s\n",
	    brcm_pci_core_name(coreid), coreid, wrap, *ioctl_p, *reset_p,
	    (*reset_p & BRCM_BCMA_RESET_CTL_RESET) ? "(in reset) " : "",
	    (*ioctl_p & BRCM_BCMA_IOCTL_CLK) ? "(clk on)" : "(clk off)");
	return (0);
}

static int
brcm_pci_sysctl_wrap_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t ioctl, reset;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "wrap_dump: refusing — sc_chip_alive false\n");
		return (ENXIO);
	}
	(void)brcm_pci_err_dump(sc, "pre-wrap-dump");
	(void)brcm_pci_core_wrap_dump(sc, BRCM_CORE_SOCRAM, &ioctl, &reset);
	(void)brcm_pci_core_wrap_dump(sc, BRCM_CORE_ARM_CR4, &ioctl, &reset);
	(void)brcm_pci_core_wrap_dump(sc, BRCM_CORE_PCIE2, &ioctl, &reset);
	(void)brcm_pci_err_dump(sc, "post-wrap-dump");
	return (0);
}

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
 * Safe to call only after wrap_dump confirmed the wrap registers
 * are readable (so we know the backplane interconnect is alive).
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
 * Disable a core via the AI-style reset+IOCTL cycle:
 *   if not in reset: IOCTL = prereset|FGC|CLK; RESET_CTL = 1; poll
 *   in-reset:        IOCTL = reset|FGC|CLK
 * Leaves the core in RESET_CTL=1 with IOCTL configured for the
 * "in-reset" state, ready for FW to enable it itself.
 */
static int
brcm_pci_core_disable(struct brcm_pci_softc *sc, uint16_t coreid,
    uint32_t prereset, uint32_t reset)
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
		    "core_disable: %s (0x%03x) has no wrap base\n",
		    brcm_pci_core_name(coreid), coreid);
		return (ENOENT);
	}

	brcm_pci_set_window(sc, wrap);

	v = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	if ((v & BRCM_BCMA_RESET_CTL_RESET) == 0) {
		/* Pre-reset configure. */
		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
		    prereset | BRCM_BCMA_IOCTL_FGC | BRCM_BCMA_IOCTL_CLK);
		(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
		    BRCM_BCMA_RESET_CTL_RESET);
		DELAY(20);
		count = 0;
		while ((bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_BCMA_RESET_CTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK) &
		    BRCM_BCMA_RESET_CTL_RESET) == 0) {
			if (++count > 300)
				break;
			DELAY(10);
		}
	}
	/* In-reset configure. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    reset | BRCM_BCMA_IOCTL_FGC | BRCM_BCMA_IOCTL_CLK);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	PDPRINTF(sc, 0,
	    "core_disable: %s held in reset (IOCTL=0x%x)\n",
	    brcm_pci_core_name(coreid),
	    reset | BRCM_BCMA_IOCTL_FGC | BRCM_BCMA_IOCTL_CLK);
	return (0);
}

/*
 * Put D11 (802.11 MAC) into the passive state before firmware load:
 *   prereset = PHYRESET | PHYCLOCKEN
 *   reset    = PHYCLOCKEN
 * Net effect: D11 in reset, PHY clocks running, PHY reset deasserted
 * — firmware can take it from here.
 */
static int
brcm_pci_sysctl_d11_disable(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);
	return (brcm_pci_core_disable(sc, BRCM_CORE_D11,
	    BRCM_D11_IOCTL_PHYRESET | BRCM_D11_IOCTL_PHYCLOCKEN,
	    BRCM_D11_IOCTL_PHYCLOCKEN));
}

static int
brcm_pci_sysctl_socram_enable(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);
	(void)brcm_pci_err_dump(sc, "pre-socram-enable");
	error = brcm_pci_core_enable(sc, BRCM_CORE_SOCRAM, 0);
	(void)brcm_pci_err_dump(sc, "post-socram-enable");
	return (error);
}

/*
 * Release ARM-CR4 from reset — the actual firmware boot trigger.
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
 *   4. Postreset: IOCTL = CLK only — CPU starts at rstvec.
 *
 * After this, the chip should write its pciedev_shared_t pointer
 * to BAR2[rambase + ramsize - 4] (a known well-known location).
 * Caller can poll that to know when firmware is up.
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
	 * Rstvec is the first 4 bytes of the firmware blob — a Thumb-2
	 * B.W instruction that redirects the ARM PC to the real entry
	 * point in the firmware body.  We already wrote it at BAR2[rambase]
	 * during load_firmware (as byte 0 of the blob), so we read it back
	 * to log + validate.
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
	 * CRITICAL: Write rstvec at BAR2[0] = chip[0].  This is where
	 * the ARM CR4 fetches its first instruction on reset-release
	 * — NOT at rambase.  Previously writing at BAR2[rambase]
	 * (which is the same location we already loaded fw into) left
	 * the reset vector at chip[0] uninitialized, so ARM fetched
	 * garbage / target-aborted, HW auto-halted, sentinel never got
	 * written.
	 */
	/*
	 * NOTE: on 43602 PCIE2, BAR2[0] and BAR2[rambase] are aliased to
	 * the same chip memory location (BAR2 window is fixed at rambase
	 * for this variant).  Redundant with load_firmware's write of the
	 * blob's first word — kept for clarity that rstvec is in place
	 * before we deassert reset.
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
	 * FULL ai_resetcore(CR4, CPUHALT, 0, 0) dance.  Previous
	 * "Apple 3-write path" ONLY toggled CPUHALT — never asserted
	 * RESET_CTL, so CR4 resumed from wherever it was (Apple
	 * firmware from warm boot, or a garbage-halt state) rather
	 * than fetching from rambase.  That's why the sentinel never
	 * got written: CR4 was running the wrong code.
	 *
	 * Sequence:
	 *   1. IOCTL = CPUHALT | FGC | CLK        (halt CPU, gate clock)
	 *   2. RESET_CTL = 1                       (assert reset)
	 *   3. delay 10us
	 *   4. IOCTL = FGC | CLK                   (in-reset config)
	 *   5. RESET_CTL = 0                       (deassert — CR4 fetches from rambase!)
	 *   6. delay 1us
	 *   7. IOCTL = CLK only                    (running)
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

	/* 3. In-reset config (no CPUHALT — clears it while in reset). */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_BCMA_IOCTL_FGC | BRCM_BCMA_IOCTL_CLK);
	(void)bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_BCMA_IOCTL & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	/* 4. Deassert reset — CR4 starts fetching from rambase now. */
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

static int
brcm_pci_sysctl_armcr4_release(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);
	(void)brcm_pci_err_dump(sc, "pre-armcr4-release");
	error = brcm_pci_armcr4_release(sc);
	(void)brcm_pci_err_dump(sc, "post-armcr4-release");
	return (error);
}

/*
 * Read N dwords from BAR2 starting at rambase + offset.  Pure read,
 * useful for polling the shared-mem pointer at BAR2[rambase +
 * ramsize - 4] after armcr4_release.  Reads a few canonical
 * offsets around the handshake location.
 */
/*
 * Read PCIe2 mailbox + intstatus registers via BAR0 SBTOPCI window.
 * The chip uses these to signal completion of firmware boot, MSGBUF
 * doorbell, etc.  After armcr4_release the D2H bits should start
 * flipping as the firmware initialises.
 */
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

static int
brcm_pci_sysctl_ramsize_query(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t ramsize;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);
	return (brcm_pci_ramsize_query(sc, &ramsize));
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
 * cell — firmware overwrites it with its shared-mem-struct pointer
 * once init completes, which is what our prep_handshake / poll
 * machinery already watches for.
 *
 * Returns 0 on success.  Run after load_fw and before armcr4_release.
 */
/*
 * Random-seed prelude for Apple chips.  Writes 256 bytes of random
 * data followed by an 8-byte {length, magic} footer just below the
 * NVRAM.  Gated behind dev.brcm_pci.<n>.nvram_seed sysctl -- first
 * attempt regressed fw on BCM43602 (fw stopped writing
 * sharedram_addr entirely).  Kept off by default until we determine
 * the correct condition/format.
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
		 *     [seed_bytes_off .. +0x100)   256 bytes entropy
		 *     [seed_footer_off .. +8)     {length=0x100, magic=0xfeedc0de}
		 *     [nvram_off      .. +nvram)   key=value\0 pairs
		 *     [ramsize-4]                  NVRAM trailer / handshake cell
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
	 *   low16  = dword count of nvram payload (just the padded
	 *            payload; trailer adds +1 implicitly because len
	 *            was rounded up to dword boundary already)
	 *   high16 = ones-complement of low16
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

static int
brcm_pci_sysctl_nvram_inject(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive || sc->sc_bar2 == NULL)
		return (ENXIO);
	return (brcm_pci_nvram_inject(sc));
}

/*
 * Pre-release handshake setup: zero BAR2[rambase + ramsize - 4].
 * The firmware writes its shared-mem-struct pointer there once
 * boot completes.  Without this zero step, the host can't tell
 * a fresh write from leftover RAM contents.
 */
static int
brcm_pci_sysctl_prep_handshake(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t ramsize, off, before;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);
	if (sc->sc_bar2 == NULL)
		return (ENXIO);

	error = brcm_pci_ramsize_query(sc, &ramsize);
	if (error != 0)
		return (error);
	if (ramsize < 4 || ramsize > rman_get_size(sc->sc_bar2))
		return (ERANGE);

	off = BRCM_PCI_RAMBASE_43602 + ramsize - 4;
	before = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, off);
	bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h, off, 0);
	device_printf(sc->sc_dev,
	    "prep_handshake: BAR2[rambase + 0x%x - 4] (off 0x%x) "
	    "%08x -> 0\n",
	    ramsize, off, before);
	return (0);
}

/*
 * Diagnostic #1: dump ARM-CR4 wrapper register space.  256 bytes
 * at the wrap base — IOCTL (0x408), RESET_CTL (0x800), and any
 * other status that's accessible.  Together with #2 (TCM watch)
 * this is the closest host-side view of CPU state we can get
 * without JTAG.  If wrap regs change between snapshots while ARM
 * is "running", the chip-internal state machine is alive even if
 * the CPU itself isn't executing useful code.
 */
static int
brcm_pci_sysctl_armcr4_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t wrap = 0, v;
	int trig = 0, error, i;
	uint32_t off;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_ARM_CR4) {
			wrap = sc->sc_cores[i].wrap;
			break;
		}
	}
	if (wrap == 0)
		return (ENOENT);

	brcm_pci_set_window(sc, wrap);
	device_printf(sc->sc_dev,
	    "armcr4_dump: wrap@0x%08x — 256 bytes:\n", wrap);
	for (off = 0; off < 0x100; off += 0x10) {
		device_printf(sc->sc_dev,
		    "  %03x: %08x %08x %08x %08x\n", off,
		    bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, off),
		    bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, off + 4),
		    bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, off + 8),
		    bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, off + 12));
	}
	(void)v;
	return (0);
}

/*
 * Diagnostic #2: TCM watcher.  Poll the handshake address +
 * MAILBOXINT + a few candidate TCM dwords at 100 ms cadence for
 * 5 seconds; print only on change.  If firmware is alive but
 * stalled mid-init, we'll see writes to other TCM locations
 * (stack, heap, init counters) even before the handshake fires.
 * If nothing changes anywhere, ARM-CR4 is either in a tight loop
 * with no memory writes or wedged in an exception handler.
 */
static int
brcm_pci_sysctl_tcm_watch(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t ramsize, pcie2 = 0;
	int trig = 0, error, i, iter;
	uint32_t hs_off, mbox_off;
	uint32_t watch_offs[6];
	uint32_t last[6 + 2];
	uint32_t now[6 + 2];

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive || sc->sc_bar2 == NULL)
		return (ENXIO);

	error = brcm_pci_ramsize_query(sc, &ramsize);
	if (error != 0)
		return (error);

	for (i = 0; i < sc->sc_ncores; i++)
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2)
			pcie2 = sc->sc_cores[i].base;
	if (pcie2 == 0)
		return (ENOENT);

	/* Watch list — handshake, mailbox, then 6 TCM dwords spread across. */
	hs_off = BRCM_PCI_RAMBASE_43602 + ramsize - 4;
	mbox_off = 0x48;	/* PCIe2 MAILBOXINT (relative to pcie2 base) */
	watch_offs[0] = BRCM_PCI_RAMBASE_43602 + 0x100;
	watch_offs[1] = BRCM_PCI_RAMBASE_43602 + 0x1000;
	watch_offs[2] = BRCM_PCI_RAMBASE_43602 + 0x10000;
	watch_offs[3] = BRCM_PCI_RAMBASE_43602 + 0x40000;
	watch_offs[4] = BRCM_PCI_RAMBASE_43602 + ramsize / 2;
	watch_offs[5] = BRCM_PCI_RAMBASE_43602 + ramsize - 0x1000;

	/* Initial snapshot. */
	last[0] = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, hs_off);
	brcm_pci_set_window(sc, pcie2);
	last[1] = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, mbox_off);
	for (i = 0; i < 6; i++)
		last[2 + i] = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    watch_offs[i]);
	device_printf(sc->sc_dev,
	    "tcm_watch: t=0 hs=0x%08x mb=0x%08x\n", last[0], last[1]);

	/* 50 iterations × 100 ms = 5 sec. */
	for (iter = 1; iter <= 50; iter++) {
		DELAY(100000);
		now[0] = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h,
		    hs_off);
		brcm_pci_set_window(sc, pcie2);
		now[1] = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    mbox_off);
		for (i = 0; i < 6; i++)
			now[2 + i] = bus_space_read_4(sc->sc_bar2_t,
			    sc->sc_bar2_h, watch_offs[i]);
		for (i = 0; i < 8; i++) {
			if (now[i] != last[i]) {
				const char *name;

				switch (i) {
				case 0: name = "hs"; break;
				case 1: name = "mb"; break;
				default:
					name = "tcm";
					break;
				}
				device_printf(sc->sc_dev,
				    "tcm_watch: t=%dms %s[%d] 0x%08x -> 0x%08x\n",
				    iter * 100, name, i, last[i], now[i]);
				last[i] = now[i];
			}
		}
	}
	device_printf(sc->sc_dev, "tcm_watch: 5s elapsed\n");
	return (0);
}

/*
 * Diagnostic #3: read-only PCIe2 internal cfg dump.  Same register
 * list as pcie2cfg_restore but without the RMW — pure observation
 * so we can compare values before/after each bring-up step without
 * perturbing them.
 */
static int
brcm_pci_sysctl_pcie2cfg_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t pcie2 = 0, cfg;
	int trig = 0, error, i;
	size_t j;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);

	for (i = 0; i < sc->sc_ncores; i++)
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2)
			pcie2 = sc->sc_cores[i].base;
	if (pcie2 == 0)
		return (ENOENT);

	static const uint32_t local_list[] = {
		0x004, 0x04c, 0x058, 0x05c, 0x060, 0x064,
		0x0dc, 0x228, 0x248, 0x4e0, 0x4f4
	};

	brcm_pci_set_window(sc, pcie2);
	device_printf(sc->sc_dev, "pcie2cfg_dump (read-only):\n");
	for (j = 0; j < nitems(local_list); j++) {
		uint32_t off = local_list[j];

		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
		    off);
		cfg = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		device_printf(sc->sc_dev,
		    "  [0x%03x] = 0x%08x\n", off, cfg);
	}
	return (0);
}

static int
brcm_pci_sysctl_mailbox_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t pcie2_base = 0;
	uint32_t intmask, mailboxint;
	int trig = 0, error, i;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2) {
			pcie2_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (pcie2_base == 0)
		return (ENOENT);

	brcm_pci_set_window(sc, pcie2_base);
	intmask = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x24 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	mailboxint = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x48 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	device_printf(sc->sc_dev,
	    "mailbox: PCIe2 INTMASK[0x24]=0x%08x MAILBOXINT[0x48]=0x%08x\n",
	    intmask, mailboxint);
	return (0);
}

static int
brcm_pci_sysctl_tcm_tail_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	const uint32_t offs_from_rambase[] = {
		0x000,			/* reset vector */
		0x004,			/* second instr */
		0x0f0000 - 4,		/* ramsize=960K handshake address */
		0x040000 - 4,		/* 256K mark - 4 */
		0x080000 - 4,		/* 512K mark - 4 */
		0x0c0000 - 4,		/* 768K mark - 4 */
	};
	uint32_t off, v;
	int trig = 0, error;
	size_t i;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (sc->sc_bar2 == NULL || !sc->sc_chip_alive)
		return (ENXIO);

	for (i = 0; i < nitems(offs_from_rambase); i++) {
		off = BRCM_PCI_RAMBASE_43602 + offs_from_rambase[i];
		v = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, off);
		device_printf(sc->sc_dev,
		    "tcm_tail: BAR2[rambase+0x%06x] = 0x%08x\n",
		    offs_from_rambase[i], v);
	}
	return (0);
}

/*
 * Memory range monitor for BAR2 TCM.  Two-shot pattern:
 *   1. sysctl dev.brcm_pci.0.tcm_range_offset=<offset from rambase>
 *   2. sysctl dev.brcm_pci.0.tcm_range_words=<word count, max 64>
 *   3. sysctl dev.brcm_pci.0.tcm_range_dump=1
 *      — dumps N words, also SAVES them to sc_tcm_range_prev
 *   4. (do something that might change TCM state)
 *   5. sysctl dev.brcm_pci.0.tcm_range_dump=1 again
 *      — diffs against sc_tcm_range_prev, logs only changed words
 * That gives us fw-vs-us memory diff without spamming dmesg.
 */
static int
brcm_pci_sysctl_tcm_range_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t off, base;
	uint32_t buf[64];
	int trig = 0, error, i, changed = 0;
	uint32_t n;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (sc->sc_bar2 == NULL || !sc->sc_chip_alive)
		return (ENXIO);

	n = sc->sc_tcm_range_words;
	if (n == 0 || n > 64) n = 16;
	base = (sc->sc_chip ? sc->sc_chip->rambase : BRCM_PCI_RAMBASE_43602)
	    + sc->sc_tcm_range_offset;

	for (i = 0; i < (int)n; i++) {
		off = base + i * 4;
		buf[i] = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, off);
	}

	if (sc->sc_tcm_range_valid) {
		for (i = 0; i < (int)n; i++) {
			if (buf[i] != sc->sc_tcm_range_prev[i]) {
				device_printf(sc->sc_dev,
				    "tcm_range: DIFF BAR2[rambase+0x%06x] "
				    "0x%08x -> 0x%08x\n",
				    sc->sc_tcm_range_offset + i * 4,
				    sc->sc_tcm_range_prev[i], buf[i]);
				changed++;
			}
		}
		if (changed == 0) {
			device_printf(sc->sc_dev,
			    "tcm_range: no change across %u words at "
			    "rambase+0x%06x\n", n, sc->sc_tcm_range_offset);
		} else {
			device_printf(sc->sc_dev,
			    "tcm_range: %d/%u words changed at rambase+0x%06x\n",
			    changed, n, sc->sc_tcm_range_offset);
		}
	} else {
		device_printf(sc->sc_dev,
		    "tcm_range: SNAPSHOT %u words at rambase+0x%06x\n",
		    n, sc->sc_tcm_range_offset);
		for (i = 0; i < (int)n; i++) {
			device_printf(sc->sc_dev,
			    "tcm_range: [rambase+0x%06x] = 0x%08x\n",
			    sc->sc_tcm_range_offset + i * 4, buf[i]);
		}
	}
	memcpy(sc->sc_tcm_range_prev, buf, n * sizeof(uint32_t));
	sc->sc_tcm_range_valid = true;
	return (0);
}

/*
 * Full reset cycle on SOCRAM — a BCM43602-specific kick right
 * before ARM-CR4 release.
 *
 * The 43602's SOCRAM controller caches bus state that becomes
 * stale once we've finished memcpy-ing the firmware to TCM;
 * without this reset the ARM-CR4 fetches garbage on its first
 * instruction load and faults immediately (matches exactly the
 * tcm_watch result: ARM running, but no memory writes anywhere).
 *
 * Equivalent to brcmf_chip_resetcore(SOCRAM, 0, 0, 0):
 *   1. ai_coredisable: force into reset (IOCTL = FGC|CLK, RESET_CTL=1)
 *   2. in-reset configure (IOCTL = FGC|CLK with reset=0 fields)
 *   3. poll RESET_CTL writing 0 until clear
 *   4. final IOCTL = CLK only
 *
 * Task #24: extracted from the sysctl into this helper so
 * brcm_pci_bringup_sequence can call it as step 7 right after
 * load_firmware.
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

static int
brcm_pci_sysctl_socram_full_reset(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	return (brcm_pci_exit_download_state(sc));
}

/*
 * Bring ARM-CR4 out of reset with the CPU HALTED (BCMA IOCTL bit
 * CPUHALT set).  The clock is on so the core's register space (and
 * its embedded TCM) is alive, but the ARM doesn't start fetching
 * instructions — leaves SOCRAM safe for the host to write firmware
 * into.  The BANKIDX/BANKPDA writes need ARM-CR4 enabled+halted.
 */
static int
brcm_pci_sysctl_armcr4_halted_enable(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive)
		return (ENXIO);
	(void)brcm_pci_err_dump(sc, "pre-armcr4-enable");
	error = brcm_pci_core_enable(sc, BRCM_CORE_ARM_CR4,
	    BRCM_ARMCR4_IOCTL_CPUHALT);
	(void)brcm_pci_err_dump(sc, "post-armcr4-enable");
	return (error);
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
 *   - WAPS shadow (chip-side subsystem-ID program) is LOST.  Caller
 *     must re-run brcm_pci_apple_waps to put it back.
 *   - EC.APWC is unaffected (EC is external).
 *   - sc_chip_alive stays true because the chip's PCIe interface
 *     is still up; sc_bar2_sized is cleared because BAR2_CONFIG
 *     reverts to its post-reset default and needs to be re-sized.
 */
/*
 * BCM43602 PMU init tables — extracted from Apple
 * AirPortBrcmNIC.kext (Mach-O x86_64) via llvm-objdump -s.  Symbols:
 *   _bcm43602_res_updown   at VA 0x529e80,  32 B
 *   _bcm43602_res_depend   at VA 0x529ea0,  96 B
 *   _bcm43602_res_pciewar  at VA 0x529f00, 192 B
 *
 * Walker in si_pmu_res_init (VA 0x2cb9a2) iterates BACKWARDS from
 * table_end-8 to table_start, count taken from a per-chip const:
 *   updown: count=3   (last 8B entry is a zeroed sentinel — skipped)
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
 *   read RES_DEP_MASK (0x624) → cur
 *   apply action(cur, dep_mask) → new
 *   RES_DEP_MASK (0x624) = new
 *
 * pciewar is applied AFTER depend and is exactly the same code path —
 * it just adds PCIe-related dependencies on top of the base graph.
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
 * Actions per Apple si_pmu_res_dep_apply disasm:
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
 * BCM43602 si_pmu_res_init port — bytewise table dispatch as done by
 * Apple's AirPortBrcmNIC.  On cold silicon this is the last thing that
 * must happen before fw upload so that PMU resource-dependency graph +
 * up/down timers match what the fw's PA-init assumes.
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
 * BCM4360 si_pmu_res_init port — Ghidra decomp of Apple's older
 * AirPortBrcm4360.kext shows:
 *
 *   _bcm4360_res_updown   (rev < 4) @ VA 0x3dc218, 1 entry (8 B)
 *     { resnum=6, updn=0x00200001 }
 *   _bcm4360B1_res_updown (rev >= 4) @ VA 0x3dc220, 1 entry (8 B)
 *     { resnum=4, updn=0x00430002 }
 *
 * PCIe-war (chip 0x4360 rev < 4, byte[0x48] bit 0x20 clear):
 *   RES_TABLE_SEL = 6;     RES_DEP_MASK = 0x09048562
 *   RES_TABLE_SEL = 0xe;   RES_DEP_MASK = 0x09048562
 *
 * armbsd BCM4360 is rev 3 → matches rev<4 path.  Much smaller table
 * than 43602 (which had 3 updown + 4 depend + 8 pciewar entries).
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
	 * Only touch resources that exist in MAX_RES_MASK.  On armbsd's
	 * BCM4360 rev 3, MAX_RES = 0x0000013f (res 0-5, 8) — Apple's decomp
	 * has an unwritten res 0xe (14) in its 4360 path that IS present
	 * on Apple hardware but NOT on the M.2 card in armbsd.  Writing
	 * DEP for a non-existent resource wedged the backplane (bisected
	 * via pmu_init_stage sysctl reaching stage 6).
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
 * PLL calibration writes captured from macOS AirPortBrcmNIC boot log
 * on <Mac model> BCM43602:
 *   ChangeVCO => vco:960, xtalF:40, frac: 98, ndivMode: 3, ndivint: 24
 *   PLL_CNTRL_ADDR2 = 0x00000c31
 *   PLL_CNTRL_ADDR3 (Fractional) = 0x0000100e
 *
 * These are per-board PLL constants Apple's driver writes before fw
 * upload.  The fw likely stalls without RF PLL properly configured.
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
		/* Read-back for logging (indirect: re-select then read data). */
		brcm_pci_pmu_write(sc, BRCM_CC_PMU_PLLCONTROL_ADDR,
		    pll_writes[i].idx);
		(void)brcm_pci_pmu_read(sc, BRCM_CC_PMU_PLLCONTROL_ADDR);
		readback = brcm_pci_pmu_read(sc, BRCM_CC_PMU_PLLCONTROL_DATA);
		PDPRINTF(sc, 0,
		    "pll_init: PLLCONTROL[%u] wrote 0x%08x, readback 0x%08x\n",
		    pll_writes[i].idx, pll_writes[i].val, readback);
	}

	/*
	 * PLL_INIT trigger — Apple BCMWL_UNDI DXE PLL programmer sets
	 * PMU_CTL bit 0x400 via RMW after all PLLCTL writes.  This is
	 * what makes the PLL adopt the new calibration values.
	 * Without it PLLCTL[N] stick in registers but the running PLL
	 * still uses the previous programming.
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
 * si_pciedev_crwlpciegen2 port — Apple AirPortBrcmNIC.kext RE'd at
 * VA 0xef677 (pciedev_crwlpciegen2).
 *
 * Chip dispatch: fires for BCM43602 (0xaa52) OR BCM4350 (0x4350).
 * All other chips are a no-op.
 *
 * Sequence for 43602:
 *   1. RMW pcie2_base[0x000]  |=  0x00000010      (PCIE control, set bit 4)
 *   2. Write pcie2_base[0x120] = 0x800            (CONFIGADDR = 0x800)
 *   3. RMW pcie2_base[0x124]  &= ~0x01000000      (CONFIGDATA, clear bit 24)
 *
 * The last RMW is via the PCIe2 internal-cfg indirection window —
 * CONFIGADDR selects the internal register, CONFIGDATA is the RMW port.
 * So step 3 modifies internal cfg register 0x800 bit 24.
 *
 * Purpose: PCIe gen2 chip-warmup workaround.  What internal-cfg[0x800]
 * bit 24 gates isn't documented — just a chip-specific fixup.
 * Diagnostic printouts of before/after values.
 */
static int
brcm_pci_pciedev_crwlpciegen2(struct brcm_pci_softc *sc)
{
	uint32_t pcie2_base = 0;
	uint32_t ctrl_before, ctrl_after, cfg800_before, cfg800_after;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2) {
			pcie2_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (pcie2_base == 0) {
		device_printf(sc->sc_dev,
		    "crwlpciegen2: PCIe2 core base unknown; "
		    "run core_walk first\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, pcie2_base);

	/* Step 1: RMW pcie2_base[0x000] |= 0x10. */
	ctrl_before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x000 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	ctrl_after = ctrl_before | 0x00000010;
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x000 & BRCM_PCI_BAR0_WINDOW_OFF_MASK, ctrl_after);
	device_printf(sc->sc_dev,
	    "crwlpciegen2: PCIe2[0x000] 0x%08x -> 0x%08x (set bit 4)\n",
	    ctrl_before, ctrl_after);

	/* Step 2 + 3: internal cfg[0x800] &= ~(1u<<24) via CONFIGADDR/DATA. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0x800);
	cfg800_before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	cfg800_after = cfg800_before & ~0x01000000U;
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    cfg800_after);
	device_printf(sc->sc_dev,
	    "crwlpciegen2: PCIe2_cfg[0x800] 0x%08x -> 0x%08x (clear bit 24)\n",
	    cfg800_before, cfg800_after);

	return (0);
}

/*
 * si_pciedev_reg_pm_clk_period port — Apple RE at VA 0xef8ca.
 *
 * For chip=0xaa52 (BCM43602) or 0x4350, program PCIe2 internal cfg
 * register 0x184c with the number of ALP clock cycles per 20 μs.
 * Value = 2_000_000 (2 MHz reference) / alp_clock_khz.
 *
 * We don't have si_pmu_alp_clock ported yet — assume 40 MHz ALP for
 * BCM43602 (standard 40 MHz xtal → ALP = xtal on this chip).
 * Result: 2_000_000 / 40_000 = 50 (0x32).  Apple's disasm shows the
 * default write is `0x184c`, which is the REGISTER OFFSET, not the
 * value — the value comes from the ALP-clock division.
 */
/*
 * SROM v11 parser — reference tables extracted from
 * AirPortBrcmNIC.kext (_pci_sromvars, _perpath_pci_sromvars).
 * These describe the byte offsets and bit masks Apple's driver uses
 * to convert raw OTP fuse bytes into named NVRAM variables (boardrev,
 * pa5ga0, patoneidx5g, etc.).
 *
 * Given an OTP buffer, brcm_pci_srom_parse_v11 emits a "key=value\0"
 * concatenated string ready to feed into brcm_pci_nvram_inject.
 */
#include "brcm_srom_v11_table.h"

/* Shift a mask down to bit 0 — number of trailing zero bits. */
static uint32_t
brcm_srom_mask_shift(uint32_t mask)
{
	uint32_t s = 0;
	if (mask == 0)
		return (0);
	while ((mask & 1u) == 0) {
		mask >>= 1;
		s++;
	}
	return (s);
}

/*
 * Emit "name=0xHHHH" for one variable at offset `off` (byte-offset into
 * OTP), masked and shifted per the table entry.  Returns bytes written
 * to `dst` (excluding trailing \0), or 0 if would overflow.
 */
static size_t
brcm_srom_emit_var(char *dst, size_t space, const struct brcm_srom_var *v,
    const uint8_t *otp, size_t otp_len, int chain_idx)
{
	uint16_t word;
	uint16_t off = v->off;
	uint16_t val;
	int n;
	char namebuf[32];

	if (chain_idx >= 0) {
		off += chain_idx * BRCM_SROM_REV11_PATH_STRIDE;
		snprintf(namebuf, sizeof(namebuf), "%s%d", v->name, chain_idx);
	} else {
		snprintf(namebuf, sizeof(namebuf), "%s", v->name);
	}
	/* SROM offsets are byte-addresses; OTP is little-endian u16 array. */
	if ((size_t)off + 2 > otp_len)
		return (0);
	word = otp[off] | (otp[off + 1] << 8);
	val = (word & v->mask) >> brcm_srom_mask_shift(v->mask);
	n = snprintf(dst, space, "%s=0x%x", namebuf, val);
	if (n < 0 || (size_t)n >= space)
		return (0);
	return ((size_t)n + 1);	/* include the \0 separator */
}

/*
 * Walk both tables (main + perpath×3 chains) and emit a full NVRAM
 * string.  Terminates with a double-\0.  Returns total bytes written.
 */
static size_t
brcm_pci_srom_parse_v11(const uint8_t *otp, size_t otp_len,
    char *out, size_t out_size)
{
	size_t used = 0;
	size_t i, chain;
	size_t n;

	for (i = 0; i < BRCM_SROM_REV11_MAIN_N; i++) {
		if (used >= out_size)
			return (used);
		n = brcm_srom_emit_var(out + used, out_size - used,
		    &brcm_srom_rev11_main[i], otp, otp_len, -1);
		used += n;
	}
	for (chain = 0; chain < BRCM_43602_NPATH; chain++) {
		for (i = 0; i < BRCM_SROM_REV11_PERPATH_N; i++) {
			if (used >= out_size)
				return (used);
			n = brcm_srom_emit_var(out + used, out_size - used,
			    &brcm_srom_rev11_perpath[i], otp, otp_len,
			    (int)chain);
			used += n;
		}
	}
	/* Trailing double-NUL. */
	if (used + 2 <= out_size) {
		out[used++] = 0;
		out[used++] = 0;
	}
	return (used);
}

/*
 * OTP dump — reads the chip's 768-word SROM/OTP window via ChipCommon
 * and prints it hex to dmesg.  This is where the REAL Apple A1398
 * NVRAM lives: macOS's AirPortBrcmNIC.kext contains only format
 * strings + parsing code + the SROM v11/v12 layout table
 * (_pci_sromvars).  The actual per-device fuse values (patoneidx5g,
 * pa5ga0, maxp5ga0, boardtype, macaddr, ...) sit in the chip's OTP
 * and are read at runtime.
 *
 * BCM43602 has IPX OTP (ccrev >= 23 → _ipxotp_fn).  The old SROMOTP
 * window at CC+0x800 is UNMAPPED on this chip (returns 0xffff).
 * Reads use bit-addressable access via CC.OTPPROG (0x018):
 *
 *   ipxotp_read_bit(cc, bit_addr):
 *     write CC.OTPCONTROL (0x014) = 0        # reset
 *     read  CC.OTPLAYOUT  (0x01c) → rowsize
 *     row = bit_addr / rowsize
 *     col = bit_addr % rowsize
 *     write CC.OTPPROG (0x018) = 0x80000000 | (row<<8) | col
 *     poll  CC.OTPPROG until bit 31 clear (busy done)
 *     if (result & (1<<28))  → error (0xffff)
 *     else                   → bit value = (result >> 29) & 1
 *
 * With 768 words × 16 bits = 12288 bit-reads × ~5 register accesses
 * each = ~60000 accesses.  Slow but only runs once for extraction.
 */

/*
 * Read a single OTP bit at bit_addr via the IPX OTP interface.
 * Returns 0/1 on success, 0xffff on error.  Caller must have set
 * BAR0 window to ChipCommon.
 */
static uint16_t
brcm_pci_ipxotp_read_bit(struct brcm_pci_softc *sc, uint16_t rowsize,
    uint32_t bit_addr)
{
	uint32_t prog, val;
	int i;

	/* Reset OTPCONTROL. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x014 & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0);

	/* Compose OTPPROG value: read-bit command at (row, col). */
	prog = 0x80000000u | ((bit_addr / rowsize) << 8) |
	    (bit_addr % rowsize);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x018 & BRCM_PCI_BAR0_WINDOW_OFF_MASK, prog);

	/* Poll for READY (bit 31 clear). */
	for (i = 0; i < 10000; i++) {
		val = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    0x018 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		if ((val & 0x80000000u) == 0)
			break;
	}
	if ((val & 0x80000000u) != 0)
		return (0xffff);	/* BUSY stuck */
	if ((val & (1u << 28)) != 0)
		return (0xffff);	/* error */
	return ((val >> 29) & 1u);
}

/*
 * Read one 16-bit OTP word at word_idx.  Composes 16 bit-reads.
 */
static uint16_t
brcm_pci_ipxotp_read_word(struct brcm_pci_softc *sc, uint16_t rowsize,
    uint32_t word_idx)
{
	uint32_t bit_addr = word_idx * 16;
	uint16_t word = 0, bit;
	int i;

	for (i = 0; i < 16; i++) {
		bit = brcm_pci_ipxotp_read_bit(sc, rowsize, bit_addr + i);
		if (bit == 0xffff)
			return (0xffff);
		word |= (bit & 1u) << i;
	}
	return (word);
}

static int
brcm_pci_otp_dump(struct brcm_pci_softc *sc)
{
	uint32_t cc_base = 0;
	uint32_t status, w;
	int i, present, programmed;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cc_base == 0) {
		device_printf(sc->sc_dev,
		    "otp_dump: ChipCommon core base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, cc_base);
	{
		uint32_t chipid    = bus_space_read_4(sc->sc_bar0_t,
		    sc->sc_bar0_h, 0x000 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		uint32_t caps      = bus_space_read_4(sc->sc_bar0_t,
		    sc->sc_bar0_h, 0x004 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		uint32_t otpctl    = bus_space_read_4(sc->sc_bar0_t,
		    sc->sc_bar0_h, 0x014 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		uint32_t otplayout = bus_space_read_4(sc->sc_bar0_t,
		    sc->sc_bar0_h, 0x01c & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		uint32_t chipstat  = bus_space_read_4(sc->sc_bar0_t,
		    sc->sc_bar0_h, 0x02c & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		device_printf(sc->sc_dev,
		    "otp_dump: CC.CHIPID=0x%08x CAPS=0x%08x CHIPSTATUS=0x%08x\n",
		    chipid, caps, chipstat);
		device_printf(sc->sc_dev,
		    "otp_dump: OTPCONTROL=0x%08x OTPLAYOUT=0x%08x\n",
		    otpctl, otplayout);
	}
	status = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x010 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	present    = (status & 0x1u) ? 1 : 0;
	programmed = (status & 0x4u) ? 1 : 0;
	device_printf(sc->sc_dev,
	    "otp_dump: OTPSTATUS=0x%08x present=%d programmed=%d\n",
	    status, present, programmed);
	if (!present || !programmed) {
		device_printf(sc->sc_dev,
		    "otp_dump: OTP not present or not programmed — "
		    "may need si_pmu_otp_power first\n");
		/* fall through, dump anyway */
	}

	/*
	 * ipxotp_init dispatch on pmurev:
	 *   pmurev >= 40 (0x28): rowsize = ((OTPLAYOUT >> 4) & 0xff) - 4
	 *   pmurev 21..27      : jump-table branch, rowsize ∈ {12, 20}
	 *                        (12 if cached-value < 128, else 20)
	 *   pmurev 25          : rowsize = 20
	 *
	 * Our chip has pmurev=24 (in [21,27]) → jump-table.
	 *
	 * Common IPX OTP rowsize values across BCM43xx: 65, 96, 128, 160,
	 * 256.  Rather than guess, scan candidates and log the first 8
	 * words at each — the one where word[0]=manfid=0x14e4 or
	 * boardtype=0x0152 shows up is the right rowsize.
	 */
	{
		uint32_t layout = bus_space_read_4(sc->sc_bar0_t,
		    sc->sc_bar0_h,
		    0x01c & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		static const uint16_t candidates[] = {
			60, 65, 96, 128, 160, 256, 288, 320
		};
		uint16_t rowsize = 65;
		int c;
		int nread = 0;
		device_printf(sc->sc_dev,
		    "otp_dump: layout=0x%08x scanning candidate rowsizes\n",
		    layout);
		for (c = 0; c < (int)nitems(candidates); c++) {
			uint16_t rs = candidates[c];
			uint16_t words[8];
			for (i = 0; i < 8; i++) {
				words[i] = brcm_pci_ipxotp_read_word(sc, rs, i);
			}
			device_printf(sc->sc_dev,
			    "otp_dump: rs=%3u -> %04x %04x %04x %04x "
			    "%04x %04x %04x %04x\n",
			    rs, words[0], words[1], words[2], words[3],
			    words[4], words[5], words[6], words[7]);
		}
		(void)status; (void)w;

		/*
		 * Read up to 256 words (512 bytes = 4096 bit-reads) first.
		 * Full OTP is 768 words but the H/W region we care about
		 * for NVRAM extraction is in the first 256.
		 */
		for (i = 0; i < 256; i += 8) {
			uint16_t words[8];
			int j;
			for (j = 0; j < 8; j++) {
				words[j] = brcm_pci_ipxotp_read_word(sc,
				    rowsize, i + j);
				nread++;
			}
			device_printf(sc->sc_dev,
			    "otp[%03d]: %04x %04x %04x %04x %04x %04x %04x %04x\n",
			    i, words[0], words[1], words[2], words[3],
			    words[4], words[5], words[6], words[7]);
			/* If everything is 0xffff after 16 words, bail. */
			if (i == 16) {
				int k, allff = 1;
				for (k = 0; k < 8; k++)
					if (words[k] != 0xffff) {
						allff = 0;
						break;
					}
				if (allff) {
					device_printf(sc->sc_dev,
					    "otp_dump: all 0xffff at word 16 — "
					    "OTP read may be failing (wrong "
					    "rowsize or not unlocked); "
					    "aborting.\n");
					break;
				}
			}
		}
		device_printf(sc->sc_dev,
		    "otp_dump: %d words read via IPX bit-reads\n", nread);
	}

	return (0);
}

/*
 * si_pci_up port for BCM43602.  Apple RE at VA 0x2f2b8e.
 *
 * The full si_pci_up covers multiple chips; for BCM43602 (chip
 * 0xaa52) the specific fixup at VA 0x2f2bee is:
 *   si_pmu_chipcontrol(sc, index=1, mask=0x10000000, value=0)
 * i.e. clear bit 28 of PMU chipcontrol[1].
 *
 * Register access via ChipCommon indirection:
 *   CHIPCONTROL_ADDR (0x650) = 1
 *   read/modify/write CHIPCONTROL_DATA (0x654): clear bit 28
 *
 * Called from wlc_bmac_up_prep after wlc_clkctl_clk, just before
 * wlc_bmac_corereset (fw upload + boot).  Not covered by any of the
 * wlc_bmac_hw_up ports — this is a NEW register touch for cold-boot.
 */
static int
brcm_pci_si_pci_up(struct brcm_pci_softc *sc)
{
	uint32_t cc_base = 0;
	uint32_t before, after;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cc_base == 0) {
		device_printf(sc->sc_dev,
		    "pci_up: ChipCommon core base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, cc_base);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_CC_PMU_CHIPCONTROL_ADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 1);
	before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_CC_PMU_CHIPCONTROL_DATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	after = before & ~0x10000000U;
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_CC_PMU_CHIPCONTROL_DATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    after);
	device_printf(sc->sc_dev,
	    "pci_up: PMU chipcontrol[1] 0x%08x -> 0x%08x "
	    "(clear bit 28)\n", before, after);
	return (0);
}

/*
 * wlc_clkctl_clk port for BCM43602.  Apple RE at VA 0xf822c.
 *
 * Called from wlc_bmac_hw_up as `wlc_clkctl_clk(sc, 0)` — arg2=0
 * takes the "SET HT clock request" path.
 *
 * Gate: sih.0x1b bit 4 SET → do the CC.clk_ctl_st RMW.  Otherwise
 * falls to si_clkctl_cc which for PCIe cores is a no-op.  We assume
 * the CC path (safer to set the HT_REQ bit than to skip on cold).
 *
 * Action:
 *   read CC.clk_ctl_st (offset 0x1e0)
 *   new = old | 0x2   (set bit 1 = HT_REQ, "chip wants HT clock")
 *   write back
 *
 * This differs from si_clkctl_init's bit-18 write in PCIe2_cfg[0x30c0]:
 * that's a PCIe-side handshake, this is the ChipCommon-side handshake
 * that fw's PMU reads.  Both may be needed for cold-boot.
 */
static int
brcm_pci_wlc_clkctl_clk(struct brcm_pci_softc *sc)
{
	uint32_t cc_base = 0;
	uint32_t before, after;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cc_base == 0) {
		device_printf(sc->sc_dev,
		    "clkctl_clk: ChipCommon core base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, cc_base);
	before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x1e0 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	after = before | 0x2U;
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x1e0 & BRCM_PCI_BAR0_WINDOW_OFF_MASK, after);
	device_printf(sc->sc_dev,
	    "clkctl_clk: CC[0x1e0] 0x%08x -> 0x%08x "
	    "(set bit 1 = HT_REQ)\n", before, after);
	return (0);
}

/*
 * si_slave_wrapper_add port for BCM43602.
 *
 * Apple si_slave_wrapper_add at VA 0x2f9317 dispatches to
 * ai_update_backplane_timeouts at VA 0x2fc2cf with three calls:
 *   ai_update_backplane_timeouts(sc, 1, 0x13, 0)      // broadcast
 *   ai_update_backplane_timeouts(sc, 0, 0, 0x820)      // PCIe1 filter
 *   ai_update_backplane_timeouts(sc, 0, 0, 0x83c)      // PCIe2 filter
 *
 * ai_update_backplane_timeouts computes:
 *   value = ((arg2 & 0x7f) << 9) | ((arg3 & 0x1f) << 4)
 *   → call 1: value = (1<<9) | (0x13<<4) = 0x200 | 0x130 = 0x330
 *   → call 2: value = 0
 *   → call 3: value = 0
 *
 * Walks the AXI wrapper table and writes `value` to `wrap + 0x900`
 * — the AXI wrapper's "backplane timeout config" register.  Filter:
 * if arg4 (coreid) != 0, only touch entries whose coreid matches
 * arg4.  Broadcast (arg4=0) touches all NON-PCIe cores.
 *
 * Wrap+0x900 encoding (Broadcom AXI slave wrapper):
 *   bits 15:9 = timeout enable + prescale (0x1 = enable, prescale 1)
 *   bits 8:4  = timeout value (log2 cycles)
 *   0x330 = enable + prescale=1, timeout=0x13 (2^19 = 524288 cycles)
 *
 * Live finding: every core wrapper on our chip reads 0x00000000
 * at +0x900 — meaning NO backplane timeouts are enabled.
 * On cold silicon a hung fw backplane transaction would hang the chip
 * forever; enabling timeouts (0x330) lets it recover.  This is the
 * FIRST port where current ≠ Apple's target — the previous 6 ports
 * were all idempotent on this macOS-warmed chip.  Strong candidate
 * for the cold-boot wall.
 */
static int
brcm_pci_slave_wrapper_add(struct brcm_pci_softc *sc)
{
	uint32_t val_broadcast = (1U << 9) | ((0x13U & 0x1FU) << 4);  /* 0x330 */
	uint32_t val_pcie = 0;
	uint32_t cur, want;
	int i;

	if (!sc->sc_chip_alive)
		return (ENXIO);

	for (i = 0; i < sc->sc_ncores; i++) {
		uint32_t wrap = sc->sc_cores[i].wrap;
		uint16_t id = sc->sc_cores[i].id;

		if (wrap == 0)
			continue;
		want = (id == 0x820 || id == 0x83c) ?
		    val_pcie : val_broadcast;

		brcm_pci_set_window(sc, wrap);
		cur = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    0x900 & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    0x900 & BRCM_PCI_BAR0_WINDOW_OFF_MASK, want);
		device_printf(sc->sc_dev,
		    "slave_wrapper: %s (id=0x%03x wrap=0x%08x) "
		    "[+0x900] 0x%08x -> 0x%08x\n",
		    brcm_pci_core_name(id), id, wrap, cur, want);
	}
	return (0);
}

/*
 * si_pmu_slow_clk_reinit port for BCM43602.  Apple RE at VA 0x2eb879
 * (si_pmu_slow_clk_reinit) → 0x2dad78 (si_pmu_enb_slow_clk).
 *
 * si_pmu_slow_clk_reinit dispatch: chip 0xaa52 with xtalfreq loaded
 * from NVRAM → falls through to case where edx = 0x9c40 (40000 kHz)
 * then tail-calls si_pmu_enb_slow_clk(sc, osh, 40000).
 *
 * si_pmu_enb_slow_clk for BCM43602 (PCIe2 rev 9, xtal 40000):
 *   1. Gate: PCIe2 core (0x83c), rev ≤ 11, bit-rev clear in 0xa80
 *      (rev 9 passes: bit 9 of 0xa80 = 0)
 *   2. For xtal 40000: value = 0x00010199
 *   3. Write CC+0x6dc = 0x00010199
 *      (PMU extension register — slow-clock enable + timing constants)
 *
 * The pmurev-gated dispatch to a different core index (0x827) fires
 * only for pmurev >= 35.  Our chip has pmurev 24 → uses ChipCommon
 * core index 0 (default) for the corereg_addr computation.
 */
static int
brcm_pci_pmu_slow_clk_reinit(struct brcm_pci_softc *sc)
{
	uint32_t cc_base = 0;
	uint32_t before, after;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_CHIPCOMMON) {
			cc_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (cc_base == 0) {
		device_printf(sc->sc_dev,
		    "pmu_slow_clk: ChipCommon core base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, cc_base);
	before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x6dc & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	after = 0x00010199U;
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    0x6dc & BRCM_PCI_BAR0_WINDOW_OFF_MASK, after);
	device_printf(sc->sc_dev,
	    "pmu_slow_clk: CC[0x6dc] 0x%08x -> 0x%08x "
	    "(slow-clock enable, 40 MHz xtal, BCM43602 constant)\n",
	    before, after);
	return (0);
}

/*
 * si_pcie_hw_LTR_war port — Apple AirPortBrcmNIC.kext at VA 0x2f8e49
 * (tail-calls into pcie_hw_LTR_war at 0xeeba0, ~675 lines).
 *
 * Gate:
 *   - bus type == PCI (0x4(rdi) == 1)
 *   - current core == 0x83c (PCIe2)
 *   - core rev ≤ 13
 *   - core rev > 10 OR bit-rev clear in 0x403 (= bits {0,1,10})
 *     BCM43602 with PCIe2 rev 9: bit 9 of 0x403 = 0 → fires
 *
 * Action (from disasm):
 *   1. CONFIGADDR = 0xd4; read CONFIGDATA; test bit 10.
 *      If bit 10 clear → early exit.  Otherwise:
 *   2. Write cfg[0x844] = LTR MAX_SNOOP_LATENCY (two 16-bit slots)
 *   3. Write cfg[0x848] = LTR MAX_NOSNOOP_LATENCY
 *   4. Write cfg[0x84c] = additional LTR word
 *
 * The values Apple writes come from pciecore_priv->0x28/0x2c/0x30
 * which macOS computes from PCIe LTR-capability parsing.  We don't
 * have that infra ported, so we use the observed constants from a
 * macOS-warmed BCM43602 chip:
 *   cfg[0x844] = 0x883c883c   (MAX_SNOOP,   both slots)
 *   cfg[0x848] = 0x88648864   (MAX_NOSNOOP, both slots)
 *   cfg[0x84c] = 0x90039003
 * 16-bit slot format is PCIe LTR standard: {req[15], reserved[14:13],
 * scale[12:10], latency[9:0]}.  0x883c decodes to req=1, scale=0,
 * value=60 (LTR requirement, 60ns).  These match a 4-lane PCIe 2.x
 * link with 100 MHz refclk and are safe defaults for BCM43602.
 */
#define	BRCM_PCI_LTR_MAX_SNOOP		0x883c883cU
#define	BRCM_PCI_LTR_MAX_NOSNOOP	0x88648864U
#define	BRCM_PCI_LTR_EXTRA		0x90039003U

static int
brcm_pci_pcie_hw_LTR_war(struct brcm_pci_softc *sc)
{
	uint32_t pcie2_base = 0;
	uint32_t v_d4, v_844, v_848, v_84c;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2) {
			pcie2_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (pcie2_base == 0) {
		device_printf(sc->sc_dev,
		    "LTR_war: PCIe2 core base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, pcie2_base);

	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0xd4);
	v_d4 = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);

	if ((v_d4 & (1u << 10)) == 0) {
		device_printf(sc->sc_dev,
		    "LTR_war: cfg[0xd4]=0x%08x bit 10 clear — skip LTR "
		    "programming (Apple early-exit path)\n", v_d4);
		return (0);
	}

	/* Bit 10 set — apply LTR values. */
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0x844);
	v_844 = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_PCI_LTR_MAX_SNOOP);

	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0x848);
	v_848 = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_PCI_LTR_MAX_NOSNOOP);

	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0x84c);
	v_84c = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_PCI_LTR_EXTRA);

	device_printf(sc->sc_dev,
	    "LTR_war: cfg[0xd4]=0x%08x bit 10 set → applied LTR: "
	    "[0x844] 0x%08x -> 0x%08x, [0x848] 0x%08x -> 0x%08x, "
	    "[0x84c] 0x%08x -> 0x%08x\n",
	    v_d4,
	    v_844, BRCM_PCI_LTR_MAX_SNOOP,
	    v_848, BRCM_PCI_LTR_MAX_NOSNOOP,
	    v_84c, BRCM_PCI_LTR_EXTRA);
	return (0);
}

/*
 * si_clkctl_init port — Apple AirPortBrcmNIC.kext at VA 0x2f176e.
 *
 * Gate:
 *   - bit 2 of sc.0x1a must be set (some cap flag) — we assume set
 *   - bus type == 1 (PCI): our brcm_pci always qualifies
 *   - current core is 0x820 (PCIe1), 0x83c (PCIe2), or 0x804 rev>12
 *     BCM43602 has PCIe2 (0x83c) rev 9 — gate passes
 *
 * Action for PCIe path (from disasm at 2f17b4..2f183f):
 *   r15 = *(sc + 0xc8) + 0x3000   ← Apple stores a base pointer at
 *                                    sc+0xc8; the +0x3000 offset lands
 *                                    inside PCIe2's internal-cfg
 *                                    indirection window, NOT its own
 *                                    4K MMIO region (verified live:
 *                                    direct read at pcie2_base+0x30c0
 *                                    returns 0xffffffff, but CONFIGADDR
 *                                    /CONFIGDATA indirection at 0x30c0
 *                                    returns a real register value).
 *   RMW cfg[0x30c0]:
 *     new = (old & 0x0000ffff) | 0x00040000
 *     (preserve low 16 status bits, zero mid, force bit 18 set)
 *
 * Bit 18 is likely ForceHT / RequestHT — the "chip wants HT clock"
 * handshake bit that cold silicon needs to see before fw PA-init can
 * proceed.  Post-init slow-clock frequency-period writes at r15+0xb0
 * (Apple 2f18bf onward, via si_slowclk_src / si_slowclk_freq) are
 * DEFERRED — the bit-18 OR is the primary chip-warmup handshake.
 */
static int
brcm_pci_clkctl_init(struct brcm_pci_softc *sc)
{
	uint32_t pcie2_base = 0;
	uint32_t before, after;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2) {
			pcie2_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (pcie2_base == 0) {
		device_printf(sc->sc_dev,
		    "clkctl_init: PCIe2 core base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	brcm_pci_set_window(sc, pcie2_base);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0x30c0);
	before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	after = (before & 0x0000ffff) | 0x00040000;
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK, after);
	device_printf(sc->sc_dev,
	    "clkctl_init: PCIe2_cfg[0x30c0] 0x%08x -> 0x%08x "
	    "(force bit 18 = HT clock request)\n",
	    before, after);
	return (0);
}

static int
brcm_pci_pciedev_reg_pm_clk_period(struct brcm_pci_softc *sc)
{
	uint32_t pcie2_base = 0;
	uint32_t alp_khz, period, before, after;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2) {
			pcie2_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (pcie2_base == 0) {
		device_printf(sc->sc_dev,
		    "reg_pm_clk_period: PCIe2 core base unknown\n");
		return (ENOENT);
	}
	if (!sc->sc_chip_alive)
		return (ENXIO);

	/* BCM43602: 40 MHz xtal → ALP clock = 40 MHz = 40000 kHz. */
	alp_khz = 40000;
	period = 2000000U / alp_khz;

	brcm_pci_set_window(sc, pcie2_base);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK, 0x184c);
	before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	after = period;
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK, after);
	device_printf(sc->sc_dev,
	    "reg_pm_clk_period: PCIe2_cfg[0x184c] 0x%08x -> 0x%08x "
	    "(ALP %u kHz, period=%u)\n",
	    before, after, alp_khz, period);
	return (0);
}

static int
brcm_pci_chip_reset(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	int pcie_cap;
	uint16_t lcr_saved;
	uint32_t cc_base = 0;
	int i;

	/*
	 * Cold-chip guard.  Use the cfg-space check (RC-terminated, never
	 * wedges) not the BAR0 check (would wedge before the guard could
	 * even print).  Mirrors macOS OLYHAL::verifyPCIeDevice + the sabotage
	 * detect in AppleBCMWLANBusInterfacePCIe::attachPCIeBusGated.
	 *
	 * Note: cfg-alive passing does not prove BAR0 MMIO is safe — the
	 * watchdog write below is posted so it can't wedge, but any
	 * subsequent BAR0 READ can if backplane clock is off.  This gate
	 * just prevents wedging the box before we even try.
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
	 * If core_walk hasn't populated sc_cores yet (chicken-and-egg on
	 * first bring-up: chip_reset needs cc_base, core_walk needs a warm
	 * chip which chip_reset provides), fall back to the canonical
	 * Broadcom ChipCommon backplane address BRCM_BACKPLANE_CHIPCOMMON
	 * (0x18000000).  Every BCM43xx PCIe part places ChipCommon there.
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

/* Forward decls for functions defined later in this file, called from
 * brcm_pci_bringup_sequence(). */
static int brcm_pci_enter_download_state(struct brcm_pci_softc *sc);
static int brcm_pci_enter_download_state_generic(struct brcm_pci_softc *sc);
static int brcm_pci_load_firmware(struct brcm_pci_softc *sc);
static int brcm_pci_pcie2cfg_restore(struct brcm_pci_softc *sc);

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
 * Manual-trigger bring-up.  Attach stays passive.  Trigger:
 *
 *     sysctl dev.brcm_pci.0.bringup=1
 *
 * Typically with `dmesg -w` streaming in a second SSH session, so
 * that if step N wedges the kernel, the streamed dmesg captures
 * "step N STARTING" without a following "step N DONE" - identifying
 * the wedge point.
 *
 * Order:
 *   1. chip_reset (watchdog + ASPM cycle) - warms backplane
 *   2. core_walk - populates sc_cores[]
 *   3. ramsize_query - TCM sizing
 *   4. enter_download_state - BANKIDX 5,7 zero
 *   5. load_firmware - FW blob to TCM
 *   6. nvram_inject - NVRAM to high TCM
 *   7. armcr4_release - reset vector + CPUHALT off
 *   8. wait_fw_ready - poll ramsize-4 sentinel (5s)
 */
static int
brcm_pci_bringup_sequence(struct brcm_pci_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint32_t ramsize = 0;
	int rc;

	/*
	 * Per-chip gate.  Bringup is fully implemented only for BCM43602
	 * today; running the 43602-specific PMU init / PLL init / SOCRAM
	 * bank powerup on other chip families wedges the backplane (2026-
	 * 07-19: armbsd RockPro64 BCM4360 died running bringup).  Refuse
	 * early with a clear message rather than crash the host.  Fixing
	 * this per chip family is documented in the brcm_pci_chip_table
	 * comments — flip `bringup_supported` when the chip's params +
	 * bringup path are actually implemented.
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
 * Bisect gate: `sysctl dev.brcm_pci.0.bringup_stop_after=N` stops
 * bringup right after step N.  Default 0 = run everything.  On a
 * wedge, next reboot lets you set N-1 and see if that's still safe.
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
	if (sc->sc_bringup_stop_after != 0 &&                             \
	    (uint32_t)(n) >= sc->sc_bringup_stop_after) {                 \
		device_printf(dev,                                        \
		    "bringup: STOP requested after step %d "              \
		    "(bringup_stop_after=%u)\n", (n),                     \
		    sc->sc_bringup_stop_after);                           \
		return (0);                                               \
	}                                                                 \
} while (0)

	/*
	 * Cold-chip pre-flight before any step.  Use cfg-space test —
	 * the old BAR0-based check itself wedged the box on cold
	 * backplane.  cfg-space is served by the root complex, always
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
	 * chip_reset is OPTIONAL and SKIPPED unconditionally when
	 * cfg-alive passes.  If APPU brought the chip up at attach,
	 * cfg says the PCIe link is healthy, and chip_reset's watchdog
	 * write is non-deterministic on bare-metal (wedges the fabric
	 * intermittently even after prior
	 * "known good" test runs).
	 *
	 * Trust the APPU success and save the wedge risk.  If APPU
	 * wasn't enough and the backplane really is cold, the first
	 * BAR0 read in core_walk will fail cleanly (or wedge, if AER
	 * isn't configured).
	 *
	 * NOTE: prior version tried a BAR0-read chip-alive test here to
	 * decide whether to skip chip_reset.  That check ITSELF was a BAR0
	 * read that wedged on cold backplane — superseded by cfg-alive,
	 * which never wedges.
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
	/* pcie2cfg_restore skipped: only needed after chip_reset (skipped too). */
	PDPRINTF(sc, 0, "bringup: step 3 pcie2cfg_restore SKIPPED\n");

	if (sc->sc_devid == BRCM_PCI_DEVICE_BCM43602) {
		/*
		 * PMU init: Apple-extracted resource-dependency + up/down
		 * timer tables for BCM43602.  Apple's driver requires it —
		 * must happen before fw upload so fw's PA-init assumes.
		 */
		BRINGUP_STEP(4, "pmu_init_43602 (Apple PMU tables)",
		    brcm_pci_pmu_init_43602(sc));
		/*
		 * Apple-observed PLL calibration writes from live macOS.
		 * Board-specific PLL constants.
		 */
		BRINGUP_STEP(4, "pll_init_43602 (Apple PLL calibration)",
		    brcm_pci_pll_init_43602(sc));
	} else if (sc->sc_devid == BRCM_PCI_DEVICE_BCM4360 ||
	    sc->sc_devid == BRCM_PCI_DEVICE_BCM4360_2) {
		/*
		 * BCM4360 has its own PMU init (Ghidra decomp of Apple's
		 * older AirPortBrcm4360.kext).  Much smaller than 43602 —
		 * just 1 res_updown entry + 2 pciewar dep_mask writes.
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
		 * SOCRAM sysmemReset BEFORE firmware upload — Apple's
		 * loadChipImage runs the SYSMEM wrapper reset cycle here,
		 * not after fw copy.
		 */
		BRINGUP_STEP(5, "sysmem_reset_pre (SOCRAM resetcore)",
		    brcm_pci_exit_download_state(sc));
	} else {
		/*
		 * Generic download-state entry: enable chip's memory core
		 * (BUF_MEM 0x81a on 4360) + halt ARM CR4.  No SOCRAM bank
		 * powerup (43602-specific).  No SOCRAM sysmem reset.
		 */
		BRINGUP_STEP(5, "enter_download_state_generic",
		    brcm_pci_enter_download_state_generic(sc));
	}

	BRINGUP_STEP(6, "load_firmware", brcm_pci_load_firmware(sc));
	/*
	 * Step 7 exit_download_state omitted: SOCRAM RESET_CTL=1 after
	 * fw upload can WIPE TCM contents on some 43602 silicon
	 * revisions.  armcr4_release re-writes only TCM[0] (rstvec) —
	 * rest of firmware bytes end up as zeros, ARM branches into a
	 * zero region, HardFaults, spins silently in exception handler.
	 * Matches every observed symptom (IOCTL=0x1 running, no TCM
	 * writes ever, sentinel unchanged forever).
	 *
	 * The pre-fw sysmem_reset_pre at step 5 already does the SOCRAM
	 * resetcore Apple's loadChipImage requires before fw copy.
	 */
	PDPRINTF(sc, 0, "bringup: step 7 exit_download_state SKIPPED "
	    "(post-fw SOCRAM reset destroys TCM contents)\n");
	BRINGUP_STEP(8, "nvram_inject", brcm_pci_nvram_inject(sc));
	BRINGUP_STEP(9, "armcr4_release (CPUHALT off)",
	    brcm_pci_armcr4_release(sc));
	BRINGUP_STEP(10, "wait_fw_ready (poll TCM[ramsize-4])",
	    brcm_pci_wait_fw_ready(sc, ramsize, 5000));

#undef BRINGUP_STEP

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

static int
brcm_pci_sysctl_chip_reset(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "chip_reset: refusing — sc_chip_alive false\n");
		return (ENXIO);
	}
	return (brcm_pci_chip_reset(sc));
}

/*
 * Resize the BAR2 aperture.  Without this step BAR2 cycles target
 * something the chip doesn't accept (PCIe2-internal regs?  some
 * default mapping?) and a single 4-byte write at BAR2[rambase]
 * Target-Aborts the host.  Mirrors brcmf_pcie_attach()'s
 * "BAR1 window may not be sized properly" RMW: write 0x4e0 to PCIe2
 * CONFIGADDR, read CONFIGDATA, write it back unchanged.  The RMW
 * itself is the trigger — the chip re-evaluates BAR2 aperture
 * when CONFIGADDR=0x4e0 is touched.
 *
 * Must run AFTER core_walk (we need the PCIe2 core base) and
 * BEFORE any BAR2 access.
 */
static int
brcm_pci_size_bar2(struct brcm_pci_softc *sc)
{
	uint32_t pcie2_base = 0;
	uint32_t cfg;
	int i;

	for (i = 0; i < sc->sc_ncores; i++) {
		if (sc->sc_cores[i].id == BRCM_CORE_PCIE2) {
			pcie2_base = sc->sc_cores[i].base;
			break;
		}
	}
	if (pcie2_base == 0) {
		device_printf(sc->sc_dev,
		    "size_bar2: PCIe2 core base unknown; "
		    "run core_walk first\n");
		return (ENOENT);
	}

	brcm_pci_set_window(sc, pcie2_base);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
	    BRCM_PCIE2_CFG_BAR2RESIZE);
	cfg = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
	device_printf(sc->sc_dev,
	    "size_bar2: PCIe2[0x4e0] = 0x%08x (rewriting unchanged)\n",
	    cfg);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK, cfg);
	sc->sc_bar2_sized = true;
	return (0);
}

/*
 * Full PCIe2-internal cfg RMW loop (rev<=13 path).  For each of
 * these PCIe2 internal cfg registers, write the offset to
 * CONFIGADDR, read CONFIGDATA, write the same value back.  The
 * RMW is what "commits" the chip-side decoder state.
 *
 * One of these (most likely RBAR_CTRL — Resizable BAR control —
 * or REG_BAR2_CONFIG / REG_BAR3_CONFIG) gates whether BAR2 cycles
 * are accepted.  size_bar2 already does just 0x4e0 and that wasn't
 * enough; this runs the whole list.  Caller must be in
 * sc_chip_alive state and have core_walk populated.
 */
static const uint32_t brcm_pci_pcie2cfg_rmw_list[] = {
	0x004,	/* STATUS_CMD */
	0x04c,	/* PM_CSR */
	0x058,	/* MSI_CAP */
	0x05c,	/* MSI_ADDR_L */
	0x060,	/* MSI_ADDR_H */
	0x064,	/* MSI_DATA */
	/* 0x0dc LINK_STATUS_CTRL2 skipped: RMW triggers link retrain wedge. */
	0x228,	/* RBAR_CTRL */
	0x248,	/* PML1_SUB_CTRL1 */
	0x4e0,	/* REG_BAR2_CONFIG */
	0x4f4,	/* REG_BAR3_CONFIG */
};

static int
brcm_pci_pcie2cfg_restore(struct brcm_pci_softc *sc)
{
	uint32_t pcie2_base = 0;
	uint32_t cfg;
	size_t i;
	int j;

	for (j = 0; j < sc->sc_ncores; j++) {
		if (sc->sc_cores[j].id == BRCM_CORE_PCIE2) {
			pcie2_base = sc->sc_cores[j].base;
			break;
		}
	}
	if (pcie2_base == 0) {
		device_printf(sc->sc_dev,
		    "pcie2cfg_restore: PCIe2 base unknown\n");
		return (ENOENT);
	}

	brcm_pci_set_window(sc, pcie2_base);
	for (i = 0; i < nitems(brcm_pci_pcie2cfg_rmw_list); i++) {
		uint32_t off = brcm_pci_pcie2cfg_rmw_list[i];

		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_PCIE2_CONFIGADDR & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
		    off);
		cfg = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		device_printf(sc->sc_dev,
		    "pcie2cfg_restore: [0x%03x] = 0x%08x (RMW)\n",
		    off, cfg);
		bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_PCIE2_CONFIGDATA & BRCM_PCI_BAR0_WINDOW_OFF_MASK,
		    cfg);
	}
	sc->sc_bar2_sized = true;
	return (0);
}

static int
brcm_pci_sysctl_pcie2cfg_restore(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "pcie2cfg_restore: refusing — sc_chip_alive false\n");
		return (ENXIO);
	}
	return (brcm_pci_pcie2cfg_restore(sc));
}

static int
brcm_pci_sysctl_size_bar2(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "size_bar2: refusing — sc_chip_alive false\n");
		return (ENXIO);
	}
	return (brcm_pci_size_bar2(sc));
}

/*
 * BCM43602 pre-upload step.  Before writing the firmware to BAR2 we
 * must clear the Power-Down-Aware bit on SOCRAM banks 5 and 7,
 * otherwise those banks stay powered off and any BAR2 write that
 * targets them generates a chip-side Target Abort which propagates
 * back to the host PCIe bridge and hangs the bus (we learned this
 * the hard way — uploading without the BANKPDA clear took macbsd
 * down hard within ~half a second of the first write).
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
	 * Each core's IOCTL.CLK must be on before touching its regs, else
	 * the backplane arbitrates transactions to nowhere.  SOCRAM for
	 * TCM writes; ARM-CR4 with CPUHALT so BANKIDX/BANKPDA accessible.
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
 * (0x81a) instead of SOCRAM.  BCM4360-family uses a single BUF_MEM
 * aperture — no bank-power dance needed, just enable clock and halt
 * the CPU so fw upload has stable TCM.
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
		fw = firmware_get(fwname);
		if (fw == NULL) {
			device_printf(sc->sc_dev,
			    "load_fw: firmware_get(\"%s\") failed; "
			    "kldload the corresponding brcm_pci_fw_* module\n",
			    fwname);
			return (ENOENT);
		}
	}
	/*
	 * Firmware blobs aren't always 4-byte-aligned in size (635449
	 * bytes for v7.35.177.61 — 1 trailing byte beyond the last
	 * dword).  ARM-CR4 never fetches past the last symbol, so we
	 * zero-pad the tail word in-place and treat the whole upload
	 * as dword-sized.
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
		firmware_put(fw, FIRMWARE_UNLOAD);
		return (EFBIG);
	}

	/*
	 * Power up TCM before writing.  On 43602 this powers up SOCRAM
	 * banks 5+7; on generic chips (4360-family) it just enables the
	 * BUF_MEM aperture.  Skipping means BAR2 writes hit unpowered
	 * mem and the chip Target-Aborts, hanging host PCIe.
	 *
	 * Chose the correct helper based on chip family.  Caller already
	 * ran the same helper in bringup step 5, but calling again is
	 * idempotent (core_enable poll RESET_CTL until 0 then set IOCTL).
	 */
	{
		int (*enter_fn)(struct brcm_pci_softc *) =
		    (sc->sc_devid == BRCM_PCI_DEVICE_BCM43602) ?
		    brcm_pci_enter_download_state :
		    brcm_pci_enter_download_state_generic;
		if (enter_fn(sc) != 0) {
			firmware_put(fw, FIRMWARE_UNLOAD);
			return (EIO);
		}
	}

	/*
	 * Pre-load: log what we're about to upload.  Reset vector
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

	/*
	 * Write barrier — flush host store buffer before chip starts
	 * reading fw bytes.
	 */
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

	firmware_put(fw, 0);
	return (mismatches == 0 ? 0 : EIO);
}

/* ------------------------------------------------------------------
 * Reverse-engineering sysctls.
 *
 * Why gate everything behind sysctls instead of doing the probes
 * inline: on Apple A1398 the BCM43602's PCIe memory decoder is held
 * gated until a still-unknown unlock sequence completes (we know
 * EC.APWC=1 is one step; there's at least one more).  Any BAR0 read
 * while the chip is gated triggers a Master Abort → Machine Check on
 * the host, which on x86 is an instant reboot — no panic message,
 * nothing to learn from.
 *
 * Putting the probes behind sysctls means kldload always succeeds.
 * The user then opts in to one probe at a time and watches dmesg
 * between each one.  Standard order:
 *
 *   1. chip_probe    BAR0[0x0]+BAR0[0x4] alive check.  May still MCE
 *                    if the chip is gated, but only when the user
 *                    explicitly asks.
 *   2. chip_id       Windowed ChipCommon[0] read via SBTOPCI.  Gated
 *                    on sc_chip_alive (set by chip_probe).
 *   3. mmio_snapshot_save / mmio_snapshot_diff
 *                    Baseline + diff of the PCIe2-core fixed-offset
 *                    region (BAR0 0x80..0x27f).  Pair with poke_*
 *                    to map out write-1-to-clear bits, RO bits, and
 *                    side-effecting registers.
 *   4. poke_addr / poke_value
 *                    32-bit write at any BAR0 offset, with read-back
 *                    before and after.  Catches RO bits silently
 *                    masked by the hardware.
 *
 * All sysctls log via device_printf so the trail lands in dmesg
 * regardless of where the user invoked them from.
 * ------------------------------------------------------------------ */

static int
brcm_pci_sysctl_hello(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	device_printf(sc->sc_dev, "hello: sysctl handler alive\n");
	return (0);
}

static int
brcm_pci_sysctl_chip_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint16_t vid, did, cmd;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	/*
	 * MINIMAL config-space-only probe.  3 reads, 1 printf.  Nothing
	 * else.  Prior version wrote PCIR_STATUS to clear abort bits and
	 * observed to hang the box on this Apple platform when the child
	 * device is in an aborted state — root port may reject cfg writes.
	 */
	vid = pci_read_config(sc->sc_dev, PCIR_VENDOR, 2);
	did = pci_read_config(sc->sc_dev, PCIR_DEVICE, 2);
	cmd = pci_read_config(sc->sc_dev, PCIR_COMMAND, 2);
	device_printf(sc->sc_dev,
	    "chip_probe: vid=0x%04x did=0x%04x cmd=0x%04x memen=%d bme=%d\n",
	    vid, did, cmd,
	    (cmd & PCIM_CMD_MEMEN) ? 1 : 0,
	    (cmd & PCIM_CMD_BUSMASTEREN) ? 1 : 0);
	sc->sc_chip_alive = (vid != 0xffff && (cmd & PCIM_CMD_MEMEN) != 0);
	return (0);
}

static int
brcm_pci_sysctl_chip_probe_mmio(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t r0, r4;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	/*
	 * Optional pre-read DDB drop via chip_probe_break sysctl.
	 * No-op if kernel lacks DDB backend (safe to leave set).
	 */
#ifdef KDB
	if (sc->sc_chip_probe_break) {
		device_printf(sc->sc_dev,
		    "chip_probe_mmio: breaking to DDB before BAR0 read\n");
		kdb_enter(KDB_WHY_UNSET, "brcm_pci chip_probe_mmio pre-BAR0");
	}
#endif

	device_printf(sc->sc_dev,
	    "chip_probe_mmio: about to read BAR0[0x000] and BAR0[0x004] — "
	    "hang here = backplane clock is off; power-cycle required.\n");

	r0 = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, 0x000);
	r4 = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, 0x004);

	device_printf(sc->sc_dev,
	    "chip_probe_mmio: BAR0[0x000]=0x%08x BAR0[0x004]=0x%08x\n",
	    r0, r4);

	if (r0 == 0xffffffff && r4 == 0xffffffff) {
		device_printf(sc->sc_dev,
		    "chip_probe_mmio: chip gated (all-1s reply).\n");
		sc->sc_chip_alive = false;
	} else {
		device_printf(sc->sc_dev,
		    "chip_probe_mmio: chip talking; chip_id / mmio_snapshot_* "
		    "/ poke_* usable.\n");
		sc->sc_chip_alive = true;
	}
	return (0);
}

static int
brcm_pci_sysctl_chip_id(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t cid;
	uint16_t chip;
	uint8_t rev, pkg, ncores;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "chip_id: refusing — sc_chip_alive is false; run "
		    "chip_probe=1 first.\n");
		return (ENXIO);
	}

	cid = brcm_pci_read_core32(sc,
	    BRCM_BACKPLANE_CHIPCOMMON + BRCM_CC_REG_CHIPID);
	if (cid == 0xffffffff) {
		device_printf(sc->sc_dev,
		    "chip_id: read returned 0xffffffff via SBTOPCI window; "
		    "the windowing path may not be programmed yet.\n");
		return (0);
	}

	chip   = cid & BRCM_CC_CHIPID_ID_MASK;
	rev    = (cid & BRCM_CC_CHIPID_REV_MASK) >> BRCM_CC_CHIPID_REV_SHIFT;
	pkg    = (cid & BRCM_CC_CHIPID_PKG_MASK) >> BRCM_CC_CHIPID_PKG_SHIFT;
	ncores = (cid & BRCM_CC_CHIPID_NCORES_MASK) >>
	    BRCM_CC_CHIPID_NCORES_SHIFT;
	device_printf(sc->sc_dev,
	    "chip_id: ChipID 0x%08x: chip=0x%04x rev=%u pkg=%u ncores=%u\n",
	    cid, chip, rev, pkg, ncores);
	return (0);
}

static int
brcm_pci_sysctl_snap_save(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t i;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "mmio_snapshot_save: refusing — sc_chip_alive is "
		    "false; run chip_probe=1 first.\n");
		return (ENXIO);
	}
	for (i = 0; i < BRCM_PCI_SNAP_LEN / 4; i++) {
		sc->sc_snapshot[i] = bus_space_read_4(sc->sc_bar0_t,
		    sc->sc_bar0_h, BRCM_PCI_SNAP_BASE + i * 4);
	}
	sc->sc_snapshot_valid = true;
	device_printf(sc->sc_dev,
	    "mmio_snapshot_save: captured BAR0[0x%03x..0x%03x]\n",
	    BRCM_PCI_SNAP_BASE,
	    BRCM_PCI_SNAP_BASE + BRCM_PCI_SNAP_LEN - 4);
	return (0);
}

static int
brcm_pci_sysctl_snap_diff(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t i, now, changes;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "mmio_snapshot_diff: refusing — sc_chip_alive is "
		    "false; run chip_probe=1 first.\n");
		return (ENXIO);
	}
	if (!sc->sc_snapshot_valid) {
		device_printf(sc->sc_dev,
		    "mmio_snapshot_diff: no snapshot — run "
		    "mmio_snapshot_save=1 first.\n");
		return (ENOENT);
	}

	changes = 0;
	for (i = 0; i < BRCM_PCI_SNAP_LEN / 4; i++) {
		now = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    BRCM_PCI_SNAP_BASE + i * 4);
		if (now != sc->sc_snapshot[i]) {
			device_printf(sc->sc_dev,
			    "mmio_snapshot_diff: [0x%03x] 0x%08x -> 0x%08x "
			    "(xor 0x%08x)\n",
			    BRCM_PCI_SNAP_BASE + i * 4,
			    sc->sc_snapshot[i], now,
			    sc->sc_snapshot[i] ^ now);
			changes++;
		}
	}
	device_printf(sc->sc_dev,
	    "mmio_snapshot_diff: %u register(s) changed\n", changes);
	return (0);
}

/*
 * Read PCIe error state from device + parent bridge, log + clear.
 * Pure config-space; safe to call before and after any chip-side
 * operation to see what kind of fault that operation caused.
 *
 * Device Status (Device cap + 0x0A) bits:
 *   CED = Correctable Error Detected
 *   NFD = Non-Fatal Error Detected
 *   FED = Fatal Error Detected
 *   UR  = Unsupported Request received
 *   TP  = Transaction Pending
 *
 * Bridge Secondary Status (offset 0x1E in bridge config) bits:
 *   RTA = Received Target Abort
 *   RMA = Received Master Abort  (this is what bus-hang looks like)
 *   SSE = Signaled System Error
 *
 * All "detected/received" bits are write-1-to-clear.
 */
static int
brcm_pci_err_dump(struct brcm_pci_softc *sc, const char *tag)
{
	device_t bridge;
	int pcie_cap, br_pcie_cap;
	uint16_t dev_sta, br_dev_sta, sec_sta;

	bridge = device_get_parent(device_get_parent(sc->sc_dev));
	if (pci_find_cap(sc->sc_dev, PCIY_EXPRESS, &pcie_cap) != 0)
		return (ENOENT);
	dev_sta = pci_read_config(sc->sc_dev, pcie_cap + PCIER_DEVICE_STA, 2);

	br_dev_sta = 0;
	if (bridge != NULL &&
	    pci_find_cap(bridge, PCIY_EXPRESS, &br_pcie_cap) == 0) {
		br_dev_sta = pci_read_config(bridge,
		    br_pcie_cap + PCIER_DEVICE_STA, 2);
	}
	sec_sta = bridge != NULL ?
	    pci_read_config(bridge, PCIR_SECSTAT_1, 2) : 0;

	device_printf(sc->sc_dev,
	    "errstat[%s]: dev=0x%04x (CED=%d NFD=%d FED=%d UR=%d TP=%d) "
	    "bridge=0x%04x sec_sta=0x%04x (RTA=%d RMA=%d SSE=%d)\n",
	    tag, dev_sta,
	    (dev_sta & PCIEM_STA_CORRECTABLE_ERROR) ? 1 : 0,
	    (dev_sta & PCIEM_STA_NON_FATAL_ERROR)   ? 1 : 0,
	    (dev_sta & PCIEM_STA_FATAL_ERROR)       ? 1 : 0,
	    (dev_sta & PCIEM_STA_UNSUPPORTED_REQ)   ? 1 : 0,
	    (dev_sta & PCIEM_STA_TRANSACTION_PND)   ? 1 : 0,
	    br_dev_sta, sec_sta,
	    (sec_sta & PCIM_STATUS_RTABORT) ? 1 : 0,
	    (sec_sta & PCIM_STATUS_RMABORT) ? 1 : 0,
	    (sec_sta & PCIM_STATUS_SERR)    ? 1 : 0);

	/* Write back to clear the W1C bits. */
	pci_write_config(sc->sc_dev, pcie_cap + PCIER_DEVICE_STA, dev_sta, 2);
	if (bridge != NULL) {
		pci_write_config(bridge, PCIR_SECSTAT_1, sec_sta, 2);
	}
	return (0);
}

static int
brcm_pci_sysctl_err_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	return (brcm_pci_err_dump(sc, "manual"));
}

/*
 * BAR2 single-word READ probe at several offsets.  Reads are safer
 * than writes — a UR (Unsupported Request) on a read returns
 * 0xffffffff back to the CPU without faulting the bus, whereas a
 * write generates a posted memory write that has no return path
 * for the chip to refuse cleanly, so the chip silently drops it or
 * (worse) Target-Aborts.  Reading first lets us probe whether BAR2
 * is mapped at all without risking a hang.
 *
 * The error-state read before/after frames the experiment:
 *   error_dump -> read BAR2[0] -> error_dump
 *   error_dump -> read BAR2[0x100000] -> error_dump
 *   error_dump -> read BAR2[0x180000] -> error_dump
 * UR bit set after a read tells us the chip's TCM decoder is off
 * for that range.
 */
static int
brcm_pci_bar2_read_probe(struct brcm_pci_softc *sc)
{
	const uint32_t offs[] = { 0x0, 0x100000, 0x180000, 0x1ff000 };
	uint32_t v;
	size_t i;

	if (sc->sc_bar2 == NULL) {
		device_printf(sc->sc_dev,
		    "bar2_read_probe: BAR2 not allocated\n");
		return (ENXIO);
	}
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "bar2_read_probe: refusing — sc_chip_alive false\n");
		return (ENXIO);
	}

	(void)brcm_pci_err_dump(sc, "pre-read");
	for (i = 0; i < nitems(offs); i++) {
		v = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, offs[i]);
		device_printf(sc->sc_dev,
		    "bar2_read_probe: BAR2[0x%06x] = 0x%08x\n", offs[i], v);
		(void)brcm_pci_err_dump(sc, "post-read");
	}
	return (0);
}

/*
 * SOCRAM probe via BAR0 SBTOPCI window — alternate path to chip RAM
 * that doesn't depend on BAR2 being mapped.  If BAR2 stays dead we
 * can fall back to this for firmware upload (slower — every 4 KB
 * page needs a window re-program — but reliable).  Reads at SOCRAM
 * core base (0x18004000 from core_walk) plus several offsets.
 */
static int
brcm_pci_socram_window_probe(struct brcm_pci_softc *sc)
{
	uint32_t socram_base = 0;
	const uint32_t offs[] = { 0x000, 0x100, 0x800, 0xff0 };
	uint32_t v;
	int j;
	size_t i;

	for (j = 0; j < sc->sc_ncores; j++) {
		if (sc->sc_cores[j].id == BRCM_CORE_SOCRAM) {
			socram_base = sc->sc_cores[j].base;
			break;
		}
	}
	if (socram_base == 0) {
		device_printf(sc->sc_dev,
		    "socram_probe: SOCRAM core base unknown\n");
		return (ENOENT);
	}

	brcm_pci_set_window(sc, socram_base);
	(void)brcm_pci_err_dump(sc, "pre-socram-read");
	for (i = 0; i < nitems(offs); i++) {
		v = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
		    offs[i] & BRCM_PCI_BAR0_WINDOW_OFF_MASK);
		device_printf(sc->sc_dev,
		    "socram_probe: SOCRAM[0x%03x] (chip 0x%08x) = 0x%08x\n",
		    offs[i], socram_base + offs[i], v);
	}
	(void)brcm_pci_err_dump(sc, "post-socram-read");
	return (0);
}

static int
brcm_pci_sysctl_socram_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "socram_probe: refusing — sc_chip_alive false\n");
		return (ENXIO);
	}
	return (brcm_pci_socram_window_probe(sc));
}

static int
brcm_pci_sysctl_bar2_read_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	return (brcm_pci_bar2_read_probe(sc));
}

/*
 * BAR2 single-word write/read probe.  Before risking a 635 KB upload
 * that might Target-Abort the bus, write one dword at the same dst
 * offset (BAR2 + 0x180000 on BCM43602) and read back.  Three
 * outcomes:
 *   - readback equals what we wrote: BAR2 maps to chip RAM, full
 *     upload should be safe.
 *   - readback differs but the host is still alive: BAR2 is mapped
 *     to something else (PCIe2 internal regs?) — full upload would
 *     corrupt that region.  Treat as failure.
 *   - host hangs / reboots: BAR2 windowing into chip memory needs a
 *     prep step we haven't done yet (PCIE2REG_CONFIGADDR = 0x4e0
 *     read-modify-write to resize the aperture).
 */
static int
brcm_pci_bar2_probe(struct brcm_pci_softc *sc)
{
	uint32_t off = BRCM_PCI_RAMBASE_43602;
	uint32_t magic = 0xdeadbeefU;
	uint32_t before, after;

	if (sc->sc_bar2 == NULL) {
		device_printf(sc->sc_dev,
		    "bar2_probe: BAR2 not allocated\n");
		return (ENXIO);
	}
	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "bar2_probe: refusing — sc_chip_alive is false\n");
		return (ENXIO);
	}

	before = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, off);
	device_printf(sc->sc_dev,
	    "bar2_probe: BAR2[0x%x] before = 0x%08x (about to write 0x%08x)\n",
	    off, before, magic);

	bus_space_write_4(sc->sc_bar2_t, sc->sc_bar2_h, off, magic);
	after = bus_space_read_4(sc->sc_bar2_t, sc->sc_bar2_h, off);

	device_printf(sc->sc_dev,
	    "bar2_probe: BAR2[0x%x] after  = 0x%08x %s\n",
	    off, after, after == magic ? "(WRITE LANDED)" : "(silent drop)");
	return (after == magic ? 0 : EIO);
}

static int
brcm_pci_sysctl_bar2_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);
	return (brcm_pci_bar2_probe(sc));
}

static int
brcm_pci_sysctl_load_fw(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	return (brcm_pci_load_firmware(sc));
}

static int
brcm_pci_sysctl_core_walk(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	return (brcm_pci_walk_cores(sc));
}

static int
brcm_pci_sysctl_cfg_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	device_t dev = sc->sc_dev;
	uint32_t off;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	device_printf(dev, "cfg dump (PCI config 0x00..0xff):\n");
	for (off = 0x00; off < 0x100; off += 0x10) {
		device_printf(dev,
		    "  %02x: %08x %08x %08x %08x\n", off,
		    pci_read_config(dev, off + 0x0, 4),
		    pci_read_config(dev, off + 0x4, 4),
		    pci_read_config(dev, off + 0x8, 4),
		    pci_read_config(dev, off + 0xc, 4));
	}
	return (0);
}

static int
brcm_pci_sysctl_waps_redo(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	(void)brcm_pci_apple_waps(sc);
	return (0);
}

static int
brcm_pci_sysctl_apple_ec_unlock(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_apple_ec_unlock(sc));
}

static int
brcm_pci_sysctl_apple_ec_cycle(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_apple_ec_cycle(sc));
}

static int
brcm_pci_sysctl_apple_powerup(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_apple_powerup(sc));
}

/*
 * PCIe D-state transition: D0→D3hot→D0.
 *
 * WARNING: observed to HANG THE KERNEL on cold
 * BCM43602 backplane.  The D3hot transition and/or the D0 restore
 * triggers PCIe re-training that never completes on cold silicon,
 * blocking config-space access indefinitely.  Only safe to fire
 * once we already know chip is warm.
 *
 * PCIe PM spec:
 *   D3hot: main power off, aux power on.  Config-space and PCIe
 *          link only.  Chip's internal state may reset.
 *   D0:    full power, chip runs normally.
 *
 * DEPRECATED as a warmup mechanism — earlier belief that this
 * warmed the chip was a false positive (the actual warming came
 * from the kldunload+kldload+attach cycle done just before it).
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

static int
brcm_pci_sysctl_apple_dstate_cycle(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_apple_dstate_cycle(sc));
}

/*
 * One-shot warmup — safe path only (no dstate_cycle).
 *
 * dstate_cycle was found to HANG the kernel on cold BCM43602 (D3hot
 * transition triggers PCIe re-training that never completes).
 * Removed from the warmup sequence.
 *
 * The actual warming is done by the kldunload+kldload+attach cycle
 * that the user does BEFORE running this — that path re-runs the
 * PCI framework's config-space init on the child which nudges the
 * chip's PCIe endpoint enough to warm the backplane.
 *
 * This sysctl just verifies + reports.
 */
static int
brcm_pci_sysctl_warmup(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t r0;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);

	device_printf(sc->sc_dev, "warmup: STEP 1 apple_ec_unlock (best-effort)\n");
	(void)brcm_pci_apple_ec_unlock(sc);

	device_printf(sc->sc_dev, "warmup: STEP 2 verify BAR0\n");
	r0 = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h, 0x000);
	if (r0 == 0xffffffff) {
		device_printf(sc->sc_dev,
		    "warmup: BAR0=0xffffffff — chip is COLD. "
		    "Run this sequence to warm:\n"
		    "  sudo devctl detach pci0:3:0:0     # wait 3s\n"
		    "  sudo kldunload brcm_pci           # wait 2s\n"
		    "  sudo kldload /boot/modules/brcm_pci.ko  # wait 2s\n"
		    "  sudo devctl attach pci0:3:0:0     # wait 3s\n"
		    "  sudo sysctl dev.brcm_pci.0.warmup=1\n");
		sc->sc_chip_alive = false;
		return (0);
	}
	device_printf(sc->sc_dev,
	    "warmup: chip is WARM — BAR0=0x%08x.\n", r0);
	sc->sc_chip_alive = true;
	return (0);
}

static int
brcm_pci_sysctl_poke_value(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint32_t val = 0, before, after;
	int error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (!sc->sc_chip_alive) {
		device_printf(sc->sc_dev,
		    "poke_value: refusing — sc_chip_alive is false; run "
		    "chip_probe=1 first.\n");
		return (ENXIO);
	}
	if (sc->sc_probe_addr >= rman_get_size(sc->sc_bar0)) {
		device_printf(sc->sc_dev,
		    "poke_value: poke_addr 0x%x out of BAR0 range (size "
		    "0x%jx)\n", sc->sc_probe_addr,
		    (uintmax_t)rman_get_size(sc->sc_bar0));
		return (EINVAL);
	}

	before = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    sc->sc_probe_addr);
	bus_space_write_4(sc->sc_bar0_t, sc->sc_bar0_h, sc->sc_probe_addr,
	    val);
	after = bus_space_read_4(sc->sc_bar0_t, sc->sc_bar0_h,
	    sc->sc_probe_addr);
	device_printf(sc->sc_dev,
	    "poke: BAR0[0x%x] %08x  -- wrote %08x --> %08x  (xor %08x)\n",
	    sc->sc_probe_addr, before, val, after, before ^ after);
	sc->sc_probe_last_write = val;
	sc->sc_probe_last_read = after;
	return (0);
}

static int
brcm_pci_sysctl_bridge_sbr(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	device_t bridge;
	uint16_t bcr;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	bridge = device_get_parent(device_get_parent(sc->sc_dev));
	if (bridge == NULL) {
		device_printf(sc->sc_dev, "bridge_sbr: no parent bridge\n");
		return (ENOENT);
	}

	bcr = pci_read_config(bridge, PCIR_BRIDGECTL_1, 2);
	device_printf(sc->sc_dev,
	    "bridge_sbr: BCR before = 0x%04x; asserting SBR (0x0040)\n", bcr);
	pci_write_config(bridge, PCIR_BRIDGECTL_1, bcr | PCIB_BCR_SECBUS_RESET, 2);
	DELAY(2000);  /* 2ms — PCIe spec requires SBR held >= 1ms */
	pci_write_config(bridge, PCIR_BRIDGECTL_1, bcr, 2);
	device_printf(sc->sc_dev,
	    "bridge_sbr: SBR released; sleeping 100ms for link retrain\n");
	DELAY(100000);  /* 100ms — allow link retrain + child re-enum */

	bcr = pci_read_config(bridge, PCIR_BRIDGECTL_1, 2);
	device_printf(sc->sc_dev, "bridge_sbr: BCR after = 0x%04x\n", bcr);

	/*
	 * After SBR the child's BARs and CMD register are reset.  Instead
	 * of requiring devctl detach/reattach dance (which is unreliable
	 * — sometimes reattach never completes), just re-enable MemEn +
	 * BusMaster here.  The BAR values in the child's config space
	 * survive SBR (they're set by parent bridge routing) — only CMD
	 * gets reset.
	 */
	{
		uint16_t vid = pci_read_config(sc->sc_dev, PCIR_VENDOR, 2);
		uint16_t cmd = pci_read_config(sc->sc_dev, PCIR_COMMAND, 2);
		device_printf(sc->sc_dev,
		    "bridge_sbr: post-reset child vid=0x%04x cmd=0x%04x\n",
		    vid, cmd);
		if (vid == 0xffff) {
			device_printf(sc->sc_dev,
			    "bridge_sbr: child gone after SBR — link didn't retrain\n");
			return (0);
		}
		if ((cmd & (PCIM_CMD_MEMEN | PCIM_CMD_BUSMASTEREN)) !=
		    (PCIM_CMD_MEMEN | PCIM_CMD_BUSMASTEREN)) {
			pci_write_config(sc->sc_dev, PCIR_COMMAND,
			    cmd | PCIM_CMD_MEMEN | PCIM_CMD_BUSMASTEREN, 2);
			cmd = pci_read_config(sc->sc_dev, PCIR_COMMAND, 2);
			device_printf(sc->sc_dev,
			    "bridge_sbr: restored cmd=0x%04x (memen=%d bme=%d) "
			    "— no detach/reattach required.\n", cmd,
			    (cmd & PCIM_CMD_MEMEN) ? 1 : 0,
			    (cmd & PCIM_CMD_BUSMASTEREN) ? 1 : 0);
		}
	}
	return (0);
}

static int
brcm_pci_sysctl_bridge_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	device_t bridge;
	int pcie_cap;
	uint16_t bcr, lcr, lsr, dsr, dcr, dc2, lc2;
	uint32_t devcap;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trig == 0)
		return (0);

	bridge = device_get_parent(device_get_parent(sc->sc_dev));
	if (bridge == NULL || pci_find_cap(bridge, PCIY_EXPRESS, &pcie_cap) != 0) {
		device_printf(sc->sc_dev,
		    "bridge_probe: no PCIe capability on parent\n");
		return (ENOENT);
	}

	bcr = pci_read_config(bridge, PCIR_BRIDGECTL_1, 2);
	lcr = pci_read_config(bridge, pcie_cap + PCIER_LINK_CTL, 2);
	lsr = pci_read_config(bridge, pcie_cap + PCIER_LINK_STA, 2);
	dcr = pci_read_config(bridge, pcie_cap + PCIER_DEVICE_CTL, 2);
	dsr = pci_read_config(bridge, pcie_cap + PCIER_DEVICE_STA, 2);
	devcap = pci_read_config(bridge, pcie_cap + PCIER_DEVICE_CAP, 4);
	lc2 = pci_read_config(bridge, pcie_cap + PCIER_LINK_CTL2, 2);
	dc2 = pci_read_config(bridge, pcie_cap + PCIER_DEVICE_CTL2, 2);

	device_printf(sc->sc_dev,
	    "bridge_probe: BCR=0x%04x LinkCtl=0x%04x LinkSta=0x%04x "
	    "DevCtl=0x%04x DevSta=0x%04x DevCap=0x%08x LinkCtl2=0x%04x "
	    "DevCtl2=0x%04x\n",
	    bcr, lcr, lsr, dcr, dsr, devcap, lc2, dc2);
	device_printf(sc->sc_dev,
	    "bridge_probe: link {speed=%u width=%u DLLLA=%d}  "
	    "aspm=0x%x ldis=%d\n",
	    lsr & 0xf, (lsr >> 4) & 0x3f,
	    (lsr & PCIEM_LINK_STA_DL_ACTIVE) ? 1 : 0,
	    lcr & 0x3, (lcr & PCIEM_LINK_CTL_LINK_DIS) ? 1 : 0);
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

	if (!brcm_pci_debug_sysctls)
		return;

	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "hello",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_hello, "I",
	    "Write 1 to test that the sysctl handler path itself works. "
	    "Prints 'hello: sysctl handler alive' — nothing else.  If this "
	    "hangs, the wedge is in sysctl/dev infrastructure, not in "
	    "chip access.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "chip_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_chip_probe, "I",
	    "Write 1 for a minimal config-space-only chip health check "
	    "(3 reads, 1 printf; never touches BAR0).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "chip_probe_mmio",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_chip_probe_mmio, "I",
	    "Write 1 to read BAR0[0x000]/[0x004] to test backplane liveness "
	    "and set sc_chip_alive.  MAY HANG THE BOX if backplane clock is "
	    "off — power-cycle required to recover.  Only fire after "
	    "chip_probe reports healthy config space AND you have a reason "
	    "to believe silicon is warm (e.g. post-macOS-boot).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "bridge_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_bridge_probe, "I",
	    "Write 1 to dump parent bridge PCIe capability registers "
	    "(BCR, LinkCtl, LinkSta, DevCtl, DevSta, DevCap, LinkCtl2, "
	    "DevCtl2).  All reads, all config-space, always safe.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "bridge_sbr",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_bridge_sbr, "I",
	    "Write 1 to trigger PCIe Secondary Bus Reset on the parent "
	    "bridge.  This hot-resets the child device.  Standard PCIe "
	    "recovery for a wedged child; may also warm the chip by "
	    "re-running its ROM boot sequence.  Child BARs/CMD are reset "
	    "after this so a detach/reattach cycle is required to re-init "
	    "resources.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "chip_id",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_chip_id, "I",
	    "Write 1 to read ChipCommon[0] via the BAR0 SBTOPCI "
	    "window.  Gated on sc_chip_alive.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "core_walk",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_core_walk, "I",
	    "Write 1 to walk the EROM and dump each backplane core "
	    "(id, rev, base).  Populates sc_cores[].");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "socram_enable",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_socram_enable, "I",
	    "Write 1 to deassert SOCRAM core reset and turn on its "
	    "clock.  Required before any chip-RAM access (BAR0 "
	    "windowed at SOCRAM, BAR2 TCM aperture).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "socram_full_reset",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_socram_full_reset, "I",
	    "Write 1 to run the BCM43602-specific full SOCRAM reset "
	    "cycle right before ARM-CR4 release.  Must run AFTER "
	    "load_fw and BEFORE armcr4_release.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "armcr4_halted_enable",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_armcr4_halted_enable, "I",
	    "Write 1 to bring ARM-CR4 out of reset with CPU HALTED "
	    "(IOCTL CPUHALT bit set).  Clock on, register space alive, "
	    "CPU not executing — required state for firmware load.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "d11_disable",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_d11_disable, "I",
	    "Write 1 to put the D11 (802.11 MAC) core into the "
	    "passive pre-fw-load state: in reset with "
	    "PHYCLOCKEN | FGC | CLK, PHYRESET deasserted.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "armcr4_release",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_armcr4_release, "I",
	    "Write 1 to release ARM-CR4 from reset.  CPU starts "
	    "executing the firmware at TCM[0].  Must be called after "
	    "load_fw.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "ramsize_query",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_ramsize_query, "I",
	    "Write 1 to compute total chip TCM size by reading ARM-CR4 "
	    "CAP + per-bank BANKINFO.  Logs each bank's size.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "prep_handshake",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_prep_handshake, "I",
	    "Write 1 to determine ramsize and zero BAR2[rambase + "
	    "ramsize - 4].  Run before armcr4_release to be able to "
	    "detect when firmware writes its shared-mem pointer.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "nvram_inject",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_nvram_inject, "I",
	    "Write 1 to upload the built-in minimal synthetic NVRAM "
	    "to chip TCM (with the brcmf trailer firmware looks for).  "
	    "Run after load_fw and before armcr4_release.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "armcr4_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_armcr4_dump, "I",
	    "Write 1 to dump ARM-CR4 wrapper register space "
	    "(256 bytes) — diagnostic state visibility.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "tcm_watch",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_tcm_watch, "I",
	    "Write 1 to poll handshake + mailbox + 6 TCM dwords "
	    "at 100 ms cadence for 5 seconds; print only on change.  "
	    "Reveals firmware liveness short of completed handshake.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "pcie2cfg_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_pcie2cfg_dump, "I",
	    "Write 1 to read-only dump the 11 PCIe2 internal cfg "
	    "registers from pcie2cfg_restore's list.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "mailbox",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_mailbox_dump, "I",
	    "Write 1 to read PCIe2 INTMASK + MAILBOXINT.  After "
	    "armcr4_release the D2H bits should set as firmware "
	    "comes up.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "tcm_tail",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_tcm_tail_dump, "I",
	    "Write 1 to read several TCM offsets including the "
	    "presumed shared-mem-pointer location.  Use after "
	    "armcr4_release to detect when firmware has come up.");
	SYSCTL_ADD_U32(ctx, list, OID_AUTO, "tcm_range_offset",
	    CTLFLAG_RW, &sc->sc_tcm_range_offset, 0,
	    "Byte offset from RAMBASE for tcm_range_dump.");
	SYSCTL_ADD_U32(ctx, list, OID_AUTO, "tcm_range_words",
	    CTLFLAG_RW, &sc->sc_tcm_range_words, 0,
	    "Number of 32-bit words to read (max 64).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "tcm_range_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_tcm_range_dump, "I",
	    "Memory range monitor for BAR2 TCM. First fire logs snapshot; "
	    "subsequent fires log only changed words vs prev snapshot. "
	    "Uses tcm_range_offset/tcm_range_words parameters.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "wrap_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_wrap_dump, "I",
	    "Write 1 to read IOCTL + RESET_CTL of SOCRAM, ARM-CR4, "
	    "PCIe2 wrapper registers.  Tells us if cores are in "
	    "reset / have clocks on.  Safer than touching the cores "
	    "themselves.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "chip_reset",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_chip_reset, "I",
	    "Write 1 to issue ChipCommon watchdog reset (ASPM off "
	    "during reset, 100ms wait, ASPM restore).  Clears WAPS "
	    "shadow + BAR2 config; re-run waps_redo + size_bar2 "
	    "after this.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "err_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_err_dump, "I",
	    "Write 1 to read PCIe Device Status + bridge Secondary "
	    "Status, log, and clear.  Run before/after each chip op "
	    "to identify which step generates UR/RMA/RTA/etc.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "pmu_init",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_pmu_init, "I",
	    "Write 1 to run BCM43602 PMU res_updown + res_depend table "
	    "programming (extracted from Apple AirPortBrcmNIC.kext).  "
	    "Run after core_walk and chip_reset, before load_fw.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "crwlpciegen2",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_crwlpciegen2, "I",
	    "Write 1 to run BCM43602 pciedev_crwlpciegen2 fixup — set "
	    "PCIe2[0] bit 4 and clear PCIe2_cfg[0x800] bit 24.  Apple "
	    "AirPortBrcmNIC pciedev_crwlpciegen2 port (VA 0xef677).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "reg_pm_clk_period",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_reg_pm_clk_period, "I",
	    "Write 1 to program PCIe2_cfg[0x184c] = ALP_period.  Apple "
	    "AirPortBrcmNIC pciedev_reg_pm_clk_period port (VA 0xef8ca).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "clkctl_init",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_clkctl_init, "I",
	    "Write 1 to RMW PCIe2[0x30c0]: preserve low16, force bit 18 "
	    "set.  Apple AirPortBrcmNIC si_clkctl_init port (VA 0x2f176e), "
	    "primary handshake only — slow-clock period writes deferred.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "LTR_war",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_LTR_war, "I",
	    "Write 1 to run PCIe LTR (Latency Tolerance Reporting) workaround "
	    "— DIAGNOSTIC-only port of Apple si_pcie_hw_LTR_war (VA "
	    "0x2f8e49).  Reads PCIe2_cfg[0xd4,0x844,0x848,0x84c] and "
	    "reports whether Apple would fire the LTR writes based on "
	    "cfg[0xd4] bit 10.  No writes.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "pmu_slow_clk",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_pmu_slow_clk, "I",
	    "Write 1 to enable BCM43602 PMU slow-clock: CC[0x6dc] = "
	    "0x00010199.  Apple si_pmu_slow_clk_reinit → si_pmu_enb_slow_clk "
	    "port (VA 0x2eb879 → 0x2dad78).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "slave_wrapper",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_slave_wrapper, "I",
	    "Write 1 to program per-core AXI wrapper backplane-timeout "
	    "registers (wrap+0x900).  Apple si_slave_wrapper_add port "
	    "(VA 0x2f9317).  Non-PCIe cores get 0x330; PCIe cores get 0.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "clkctl_clk",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_clkctl_clk, "I",
	    "Write 1 to set HT_REQ bit in CC.clk_ctl_st (offset 0x1e0). "
	    "Apple wlc_clkctl_clk port (VA 0xf822c) — companion to "
	    "clkctl_init's PCIe-side bit-18 write.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "pci_up",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_pci_up, "I",
	    "Write 1 to clear bit 28 of PMU chipcontrol[1].  Apple "
	    "si_pci_up port (VA 0x2f2b8e), BCM43602-specific fixup at "
	    "0x2f2bee.  Called from wlc_bmac_up_prep just before fw boot.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "otp_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_otp_dump, "I",
	    "Write 1 to dump the chip's 768-word SROM/OTP window to "
	    "dmesg.  This is where the real Apple A1398 per-device fuse "
	    "values live — read into a file, then parse with SROM v11/v12 "
	    "layout to build proper NVRAM.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "srom_parse_self",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_srom_parse_self, "I",
	    "Write 1 to unit-test the SROM v11 parser against a synthetic "
	    "512-byte OTP buffer.  Prints emitted NVRAM keys — validates "
	    "the layout tables extracted from AirPortBrcmNIC.kext without "
	    "needing chip access.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "dcmd_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_dcmd_probe, "I",
	    "Write 1 to send DCMD 262 (WLC_GET_VAR) with iovar "
	    "\"ver\" and print the reply.  msgbuf first-light validation.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "flow_create",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_flow_create, "I",
	    "Write 1 to create test flowring 0 to peer 02:00:00:00:00:01 "
	    "prio 0 ifidx 0.  Sends FLOW_RING_CREATE_REQ and waits for "
	    "FLOW_RING_CREATE_CMPLT.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "tx_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_tx_probe, "I",
	    "Write 1 to send a 100-byte Ethernet test frame through "
	    "local flowring 0.  Requires flow_create to have succeeded.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "set_infra",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_set_infra, "I",
	    "Write integer to send WLC_SET_INFRA (20).  1 = STA infrastructure.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "set_wsec",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_set_wsec, "I",
	    "Write integer to send WLC_SET_WSEC (134).  0 = open.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "set_country",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_set_country, "A",
	    "Write 2-char country code (e.g. \"US\") — sends "
	    "WLC_SET_COUNTRY (84).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "set_ssid",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_set_ssid, "A",
	    "Write SSID string to trigger WLC_SET_SSID (26) — chip-supplicant "
	    "JOIN.  Requires wlc_up + set_infra=1 + set_wsec=0 first for OPEN.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "disassoc",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_disassoc, "I",
	    "Write 1 to send WLC_DISASSOC (52) — leave current BSS.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "bar2_read_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_bar2_read_probe, "I",
	    "Write 1 to read BAR2 at four offsets and log "
	    "post-read PCIe error status.  Pure read, safer than "
	    "bar2_probe write.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "socram_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_socram_probe, "I",
	    "Write 1 to read SOCRAM via BAR0 SBTOPCI window at several "
	    "offsets.  Bypasses BAR2 entirely; uses the known-working "
	    "BAR0 windowed path.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "size_bar2",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_size_bar2, "I",
	    "Write 1 to run PCIe2[0x4e0] read-modify-write that "
	    "configures the BAR2 aperture to map to chip TCM.  Must "
	    "run after core_walk and before bar2_probe / load_fw.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "pcie2cfg_restore",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_pcie2cfg_restore, "I",
	    "Write 1 to RMW the full PCIe2-internal cfg register list "
	    "(STATUS_CMD, PM_CSR, MSI_*, LINK_STATUS_CTRL2, RBAR_CTRL, "
	    "PML1_SUB_CTRL1, BAR2_CONFIG, BAR3_CONFIG).  Post-reset cfg "
	    "restore for chip rev<=13.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "bar2_probe",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_bar2_probe, "I",
	    "Write 1 to do a single 4-byte test write/read at "
	    "BAR2[rambase].  Gated on size_bar2 having run.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "load_fw",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_load_fw, "I",
	    "Write 1 to firmware_get(\"brcmfmac43602_pcie\") and "
	    "upload the blob into BAR2 (chip SOCRAM).  Kldload "
	    "brcm_pci_fw_43602 first.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "mmio_snapshot_save",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_snap_save, "I",
	    "Write 1 to capture BAR0[0x80..0x27f] into the kernel "
	    "snapshot buffer.  Pair with mmio_snapshot_diff.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "mmio_snapshot_diff",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_snap_diff, "I",
	    "Write 1 to diff BAR0[0x80..0x27f] against the saved "
	    "snapshot; prints (offset, before, after, xor) per change.");
	SYSCTL_ADD_UINT(ctx, list, OID_AUTO, "poke_addr",
	    CTLFLAG_RW, &sc->sc_probe_addr, 0,
	    "BAR0 offset for the next poke_value write.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "poke_value",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_poke_value, "I",
	    "Write a 32-bit value to BAR0[poke_addr] and print "
	    "before/after read-back.  Gated on sc_chip_alive.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "cfg_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_cfg_dump, "I",
	    "Write 1 to dump PCI config 0x00..0xff via "
	    "pci_read_config.  Always safe (config-space).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "dstate_cycle",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_apple_dstate_cycle, "I",
	    "PCIe D0->D3hot->D0 transition via PMCSR.  Standard PCIe "
	    "wakeup that may trigger chip ROM re-run when APWC-based "
	    "warmup fails.  100ms dwell in D3hot.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "warmup",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_warmup, "I",
	    "One-shot chip warmup: apple_ec_unlock + bridge_sbr + BAR0 "
	    "verify.  Sets sc_chip_alive on success.  Reports SUCCESS or "
	    "STILL COLD.  Use on fresh boot with APWC=0.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "apple_ec_cycle",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_apple_ec_cycle, "I",
	    "Force APWC bit 1->0->1 cycle with 200ms dwells.  EC only "
	    "wakes chip on RISING edge; if apple_ec_unlock is no-op "
	    "because APWC persists as 1, use this to re-trigger wakeup.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "apple_ec_unlock",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_apple_ec_unlock, "I",
	    "Write 1 to set EC APWC bit (opt-in — attach used to do this "
	    "automatically but direct EC port I/O could race with the "
	    "acpi_ec driver and wedge the box).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "apple_appu_warm",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_apple_appu_warm, "I",
	    "Write 1 to run the DSDT APPU warm sequence in native C: "
	    "EC APWC=1 + 250ms settle + 10s poll for chip PCI vendor ID "
	    "!= 0xffff, retry up to 5x.  This is the software-only "
	    "cold->warm path decoded from fbsdmac's own DSDT (RP03._PS0 "
	    "-> ALPR(0) -> APPU()).  Success = ChipID BAR0[0] reads 0xaa52 "
	    "on subsequent chip_alive=1.");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "apple_powerup",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_apple_powerup, "I",
	    "Write 1 to clear PCIe Link Disable on parent bridge (opt-in "
	    "companion to apple_ec_unlock).");
	SYSCTL_ADD_PROC(ctx, list, OID_AUTO, "waps_redo",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pci_sysctl_waps_redo, "I",
	    "Write 1 to re-run the WAPS config-space unlock sequence "
	    "(EC.APWC + bridge LDIS already cleared in attach).");
	SYSCTL_ADD_UINT(ctx, list, OID_AUTO, "probe_last_read",
	    CTLFLAG_RD, &sc->sc_probe_last_read, 0,
	    "Last value read by poke_value (read-back after write).");
	SYSCTL_ADD_BOOL(ctx, list, OID_AUTO, "chip_probe_break",
	    CTLFLAG_RW, &sc->sc_chip_probe_break, 0,
	    "Set to 1 to kdb_enter() before chip_probe's BAR0 reads.  "
	    "Requires kernel with options KDB + DDB.  Use to catch pre-MCE "
	    "state when the chip is still gated after apple_ec_unlock.");
	SYSCTL_ADD_UINT(ctx, list, OID_AUTO, "pmu_init_stage",
	    CTLFLAG_RW, &sc->sc_pmu_init_stage, 0,
	    "BCM4360 pmu_init bisect stage: 0 = reads only, 1..6 add one "
	    "write per stage.  Fire pmu_init=1 after setting this.");
	SYSCTL_ADD_UINT(ctx, list, OID_AUTO, "bringup_stop_after",
	    CTLFLAG_RW, &sc->sc_bringup_stop_after, 0,
	    "Stop bringup right after step N (0 = run all).  Bisect wedge "
	    "point by setting N=2 then 4 then 5 etc.");
	SYSCTL_ADD_UINT(ctx, list, OID_AUTO, "probe_last_write",
	    CTLFLAG_RD, &sc->sc_probe_last_write, 0,
	    "Last value written by poke_value.");
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
		/* Not fatal for the skeleton — step 2 makes it required. */
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
 * Bus-ops for brcm.c integration.  brcm.c (the shared FullMAC core
 * from the SDIO/USB families) calls into these wrappers when the
 * transport uses msgbuf DCMDs instead of BCDC.  Only the dcmd_*
 * and iovar_* hooks are meaningful for PCIe/msgbuf; txctl/rxctl
 * are BCDC-specific and return ENXIO.  txdata routes into
 * brcm_pci_msgbuf_txmbuf but requires flowring management that's
 * added in phase 3 — for now returns ENXIO.
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
	 * (there's no SCB for ff:ff:ff:ff:ff:ff) so the frame goes out
	 * clear and the AP DEAUTHs us reason=6 ("class 2 frame from
	 * nonauthenticated STA").  Symptom: DHCP DISCOVER TX-completes
	 * but AP never replies with OFFER and instead re-fires M1 EAPOL.
	 */
	if ((da[0] & 0x01) != 0 && bsc->sc_ic_attached) {
		struct ieee80211vap *_vap =
		    TAILQ_FIRST(&bsc->sc_ic.ic_vaps);
		if (_vap != NULL && _vap->iv_bss != NULL) {
			memcpy(da, _vap->iv_bss->ni_bssid, 6);
		}
	}

	/*
	 * EAPOL (ethertype 0x888e) must ride a dedicated flowring at
	 * prio 7 (voice / TID 7).  Rationale: after brcm_set_key installs
	 * the PTK, the chip starts encrypting outbound frames on the peer's
	 * data flowring.  M4 (or any EAPOL retransmit) that arrives on the
	 * same flowring gets AES-encrypted; the AP can't validate the MIC
	 * and keeps replaying M3.  Linux brcmfmac uses the same TID-7
	 * separation for EAPOL; Broadcom fw treats the TID-7 flowring as
	 * an EAPOL bypass path — frames go on-air unencrypted regardless
	 * of PTK install state, which is what 802.11i requires for M2 and
	 * M4.
	 */
	prio = 0;
	if (m->m_pkthdr.len >= 14) {
		const uint8_t *p = mtod(m, const uint8_t *);
		uint16_t etype = ((uint16_t)p[12] << 8) | p[13];
		if (etype == 0x888e)
			prio = 7;
	}
	ifidx = 0;

	flowid = brcm_pci_msgbuf_flowring_lookup(sc, da, prio);
	if (flowid == (uint16_t)-1) {
		error = brcm_pci_msgbuf_flowring_create(sc, sa, da, prio,
		    ifidx, &flowid);
		if (error != 0) {
			m_freem(m);
			return (error);
		}
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

static const struct brcm_bus_ops brcm_pci_bus_ops = {
	.bs_txctl	= brcm_pci_bs_txctl,
	.bs_rxctl	= brcm_pci_bs_rxctl,
	.bs_txdata	= brcm_pci_bs_txdata,
	.bs_stop	= brcm_pci_bs_stop,
	.bs_dcmd_get	= brcm_pci_bs_dcmd_get,
	.bs_dcmd_set	= brcm_pci_bs_dcmd_set,
	.bs_iovar_get	= brcm_pci_bs_iovar_get,
	.bs_iovar_set	= brcm_pci_bs_iovar_set,
	/* bs_pump_rx = NULL — msgbuf ISR delivers async without polling. */
};

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
	 * Prepare the shared brcm_softc so brcm_attach() can be invoked
	 * later (via the net80211_attach sysctl once fw is running and
	 * msgbuf is up).  These mutexes must be inited by the transport
	 * per brcm.c's contract — they survive across attach failures
	 * and are used by any ctlrx thread brcm.c may spin up.
	 */
	sc->bus_sc.sc_dev = dev;
	sc->bus_sc.sc_bus_ops = &brcm_pci_bus_ops;
	mtx_init(&sc->bus_sc.sc_mtx, device_get_nameunit(dev), NULL, MTX_DEF);
	mtx_init(&sc->bus_sc.sc_ctl_mtx, "brcm_pci ctl", NULL, MTX_DEF);
	TAILQ_INIT(&sc->bus_sc.sc_ctl_pending);

	/*
	 * Transition to D0 before any device-side access.  On Apple A1398
	 * BCM43602 the EFI/macOS handoff parks the chip in D3-cold; without
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
	 * path, but on the Apple A1398 PCH bridges it does not get
	 * set, and every subsequent BAR0 read returns 0xffffffff (the
	 * device replies "Unsupported Request" because its memory
	 * decoder is off).  Set both bits explicitly here.
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
	 * Apple-platform unlock — pure config-space only.
	 *
	 * Earlier attempts to evaluate APPU, bridge._PS0, or ARPT._PS0
	 * all crashed macbsd: those AML methods spin on a hardware bit
	 * (LACT, link-active) for up to 10 seconds under the ACPICA
	 * interpreter mutex, blowing past FreeBSD's spin-lock-held-too-
	 * long watchdog.  Apple's AML assumes Darwin's permissive
	 * interpreter locking, which we don't share.
	 *
	 * For now, clear LDIS via config-space and stop.  The chip-side
	 * EC.APWC bit that APPU's happy path also sets is the missing
	 * piece; without it the BCM43602's PCIe controller stays in
	 * reset.  The fix is either a direct EC-port write (invasive)
	 * or a non-Apple BCM43602 host where none of this matters.
	 */
	/*
	 * Apple-platform note: ARPT._PS0 and parent-bridge _PS0 both
	 * crash FreeBSD with spin-lock-held-too-long.  Their AML
	 * polls a chip-side bit for up to 10 seconds under the
	 * ACPICA interpreter mutex.  Until we have a way to either
	 * bump the watchdog threshold or trampoline _PS0 outside the
	 * interpreter lock, leave the call out.
	 */
	/*
	 * Attach was wedging when running via `kldunload vmm && devctl
	 * set driver` -- suspect either direct EC port I/O racing
	 * FreeBSD's acpi_ec driver, or WAPS shadow writes while the
	 * chip is transitional after ppt release.
	 *
	 * Risky chip touches are moved from attach() into explicit
	 * sysctls (`apple_ec_unlock`, `apple_powerup`, `waps_redo`).
	 * Attach is now truly passive — just allocates BARs + IRQ +
	 * registers sysctls.
	 */

	/*
	 * BAR window is allocated but not yet readable as registers —
	 * the chip's BAR0 view is gated by the SBTOPCI translation
	 * registers, which the boot ROM may or may not have programmed.
	 * Stage 2 walks the chip-side cores via SBTOPCI[1] (window into
	 * backplane address space) to find ChipCommon + read the chipID.
	 *
	 * Just log what PCI config space already told us about the
	 * device, plus the BAR sizes; defer any register-window reads
	 * until step 2 sets up the windowing.
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
	 * NO BAR0 register access from attach().  On Apple A1398 the
	 * BCM43602's PCIe memory decoder stays gated after EC.APWC=1
	 * alone, and any blind bus_space_read_4 on BAR0 master-aborts
	 * the host (MCE -> immediate reboot, no panic message, nothing
	 * to learn from).
	 *
	 * Everything chip-side is exposed via sysctl handlers (see
	 * brcm_pci_attach_sysctls), so kldload always finishes cleanly.
	 * The user can then opt into probes one at a time:
	 *
	 *   sysctl dev.brcm_pci.0.chip_probe=1   # alive check (BAR0[0,4])
	 *   sysctl dev.brcm_pci.0.chip_id=1      # windowed ChipID read
	 *   sysctl dev.brcm_pci.0.mmio_snapshot_save=1
	 *   sysctl dev.brcm_pci.0.mmio_snapshot_diff=1
	 *   sysctl dev.brcm_pci.0.poke_addr=0x80
	 *   sysctl dev.brcm_pci.0.poke_value=0x18000000
	 *
	 * Step 2 (MSGBUF firmware load + net80211 wiring) will not
	 * start until chip_probe + chip_id both come back alive on at
	 * least one host.
	 */
	brcm_pci_attach_sysctls(sc);

	/*
	 * Run the DSDT APPU warm sequence NOW, before anyone touches BAR0.
	 * On a fresh EFI-primed boot the chip is already warm and this
	 * exits in ~10ms on the fast-path poll.  On a cold chip (recovery
	 * from a wedge, deep S5 wake, etc.) it retries up to 5×10s.
	 *
	 * APPU is EC-port-I/O + PCI config-space poll ONLY -- no BAR0
	 * writes, so it does NOT trip the cold-chip wedge that
	 * chip_reset's watchdog write triggered in earlier attach-time
	 * experiments.  Safe to run unconditionally.
	 *
	 * If APPU fails after all retries, we log and continue attaching
	 * (registering sysctls for manual recovery) rather than refusing
	 * -- the box stays poke-able.  The chip just won't be usable
	 * until something else warms it (macOS boot, physical power-cycle,
	 * etc.).
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

		/* Warm continuation: dstate_cycle + chip_probe (both cfg-only). */
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
	 * subsequent BAR0[0..0x1000) MMIO reads land on chipcommon
	 * registers (CHIPID at BAR0[0], CAPS at BAR0[4], etc).  Every
	 * downstream sysctl (chip_probe_mmio, bringup, mmio_snapshot)
	 * assumes this pointing.  Without it, whatever the firmware /
	 * previous OS left in WIN1 is what BAR0[0] reads — which on
	 * FreeBSD post-attach turned out to be 0x18003000 (PCIe2 core
	 * aperture) whose offset-0 reads as 0xffffffff, misdiagnosed
	 * as "cold chip" for weeks.
	 *
	 * Cfg-space write is safe even on cold BAR0 — config space is
	 * served by the root complex, not the chip.
	 */
	pci_write_config(dev, BRCM_PCI_BAR0_WINDOW, 0x18000000, 4);
	(void)pci_read_config(dev, BRCM_PCI_BAR0_WINDOW, 4);
	device_printf(dev,
	    "attach: BAR0_WIN1 (cfg 0x%02x) = 0x18000000 (CHIPCOMMON)\n",
	    BRCM_PCI_BAR0_WINDOW);

attach_done:

	sc->bus_sc.sc_dev = dev;
	sc->bus_sc.sc_bus_ops = &brcm_pci_bus_ops;
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
	 *   4. Drain brcm.c-owned taskqueue tasks (scan_done, scan, link,
	 *      assoc, disassoc, post_assoc, parent).  These fire from the
	 *      msgbuf ISR path via brcm_handle_event; safe to drain now
	 *      because the ISR is unbound.  brcm_attach TASK_INITs them
	 *      even if brcm_detach ran, so drain unconditionally — TASK
	 *      structs are zero-initialised static memory in the softc so
	 *      draining an untriggered task is a no-op.
	 *   5. Free IRQ + BARs (bus_teardown_intr already done via
	 *      msgbuf_unbind_intr, but free_irq is idempotent — it just
	 *      releases the SYS_RES_IRQ and MSI/MSI-X vectors).
	 *   6. Destroy the sc_ctl_mtx / sc_mtx pair inited by attach.  Must
	 *      come AFTER step 1 (no sleepers left).
	 *   7. pci_disable_busmaster (config-space only, safe after BARs
	 *      released — NEVER touch chip MMIO past this point).
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
		 * they sleep on.  1s poll — sc_dying gets checked on every
		 * wakeup so this is a bounded wait.
		 */
		while (bsc->sc_in_flight_dcmd != 0)
			(void)mtx_sleep(&bsc->sc_in_flight_dcmd,
			    &bsc->sc_ctl_mtx, 0, "brcmdcd", hz);
		mtx_unlock(&bsc->sc_ctl_mtx);
	}

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
	taskqueue_drain(taskqueue_thread, &bsc->sc_scan_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_link_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_assoc_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_disassoc_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_post_assoc_task);
	taskqueue_drain(taskqueue_thread, &bsc->sc_parent_task);

	brcm_pci_free_irq(sc);
	brcm_pci_free_bars(sc);

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
	 * MUST return cached value.  brcm_pci_ramsize_query halts the
	 * ARM CR4 CPU (BRCM_ARMCR4_IOCTL_CPUHALT) to safely read TCM
	 * BANKINFO.  Post-bringup that would kill the running firmware
	 * and hard-hang the host on the next TCM access.  Bringup
	 * caches sc_fw_ramsize.
	 */
	if (sc->sc_fw_ramsize != 0)
		return (sc->sc_fw_ramsize);
	/* Pre-bringup fallback (only chip-alive check paths reach this). */
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

		/* EAPOL: hand to fmac helper which wraps + delivers to
		 * wpa_supplicant via BPF on wlan0. */
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
brcm_pci_sysctl_pmu_init(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	if (sc->sc_devid == BRCM_PCI_DEVICE_BCM4360 ||
	    sc->sc_devid == BRCM_PCI_DEVICE_BCM4360_2)
		return (brcm_pci_pmu_init_4360(sc));
	return (brcm_pci_pmu_init_43602(sc));
}

static int
brcm_pci_sysctl_crwlpciegen2(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_pciedev_crwlpciegen2(sc));
}

static int
brcm_pci_sysctl_reg_pm_clk_period(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_pciedev_reg_pm_clk_period(sc));
}

static int
brcm_pci_sysctl_clkctl_init(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_clkctl_init(sc));
}

static int
brcm_pci_sysctl_LTR_war(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_pcie_hw_LTR_war(sc));
}

static int
brcm_pci_sysctl_pmu_slow_clk(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_pmu_slow_clk_reinit(sc));
}

static int
brcm_pci_sysctl_slave_wrapper(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_slave_wrapper_add(sc));
}

static int
brcm_pci_sysctl_clkctl_clk(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_wlc_clkctl_clk(sc));
}

static int
brcm_pci_sysctl_pci_up(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_si_pci_up(sc));
}

static int
brcm_pci_sysctl_otp_dump(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_otp_dump(sc));
}

/*
 * Self-test: build a synthetic 512-byte OTP buffer with the known
 * board fields at their SROM v11 offsets, run the parser, and log
 * the emitted NVRAM string.  Validates the layout tables without
 * needing chip access.
 */
static int
brcm_pci_srom_parse_self_test(struct brcm_pci_softc *sc)
{
	uint8_t otp[512];
	char *nvram;
	size_t nv_size = 8192, n, i;
	int emitted = 0;

	memset(otp, 0xff, sizeof(otp));	/* unprogrammed = 0xff */
	/* Plant known values at v11 offsets (from srom_rev11_map.txt). */
	otp[0x02] = 0x52; otp[0x03] = 0x01;	/* boardtype = 0x0152 */
	otp[0x30] = 0xba; otp[0x31] = 0x43;	/* devid = 0x43ba */
	otp[0x41] = 0x19; otp[0x42] = 0x13;	/* boardrev = 0x1319 */
	otp[0x42] = 0x13;
	/* Note: overlapping u16 reads (0x41/0x42) — write LE order. */
	otp[0x40] = 0x00; otp[0x41] = 0x19; otp[0x42] = 0x13;

	nvram = malloc(nv_size, M_TEMP, M_WAITOK | M_ZERO);
	n = brcm_pci_srom_parse_v11(otp, sizeof(otp), nvram, nv_size);
	device_printf(sc->sc_dev,
	    "srom_self: parsed %zu bytes total, walking output:\n", n);
	i = 0;
	while (i < n && emitted < 30) {
		const char *s = nvram + i;
		size_t slen = strnlen(s, n - i);
		if (slen == 0)
			break;
		device_printf(sc->sc_dev, "  nv[%d]: %s\n", emitted, s);
		i += slen + 1;
		emitted++;
	}
	device_printf(sc->sc_dev,
	    "srom_self: emitted %d NVRAM keys (main=%zu + perpath=%zu×%d "
	    "chains)\n",
	    emitted, BRCM_SROM_REV11_MAIN_N, BRCM_SROM_REV11_PERPATH_N,
	    BRCM_43602_NPATH);
	free(nvram, M_TEMP);
	return (0);
}

static int
brcm_pci_sysctl_srom_parse_self(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	return (brcm_pci_srom_parse_self_test(sc));
}

static int
brcm_pci_sysctl_msgbuf_attach(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
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
 * We track a per-driver read_idx and drain everything from read_idx
 * to write_idx into printf().  Each call prints new bytes since last
 * call.  Use to observe fw's own log lines including the reason it
 * disassocs after 4-way completes.
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

/* Sysctl: fire a single DCMD to prove round-trip.
 *   DCMD 262 (WLC_GET_VAR) with input "ver\0" → fw returns fw version.
 * Prints the returned string.
 */
#define	BRCM_DCMD_GET_VAR	262
static int
brcm_pci_sysctl_dcmd_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	uint8_t buf[256];
	size_t rlen = sizeof(buf);
	int32_t fwerr = 0;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);

	memset(buf, 0, sizeof(buf));
	memcpy(buf, "ver\0", 4);
	error = brcm_pci_msgbuf_dcmd(sc, BRCM_DCMD_GET_VAR, false,
	    buf, sizeof(buf), buf, &rlen, &fwerr);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "dcmd_probe: error %d\n", error);
		return (0);
	}
	buf[MIN(rlen, sizeof(buf) - 1)] = '\0';
	device_printf(sc->sc_dev,
	    "dcmd_probe: fwerr=%d rlen=%zu ver=\"%s\"\n",
	    fwerr, rlen, (char *)buf);
	return (0);
}

/* Sysctl: create flowring 0 to a fixed test peer.  Idempotent —
 * subsequent writes create additional flowrings (1, 2, ...). */
static int
brcm_pci_sysctl_flow_create(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	static const uint8_t da[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	static const uint8_t sa[6] = { 0x02, 0xf3, 0xd1, 0x00, 0x00, 0x02 };
	uint16_t flowid = 0xffff;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);

	error = brcm_pci_msgbuf_flowring_create(sc, sa, da, 0, 0, &flowid);
	if (error != 0) {
		device_printf(sc->sc_dev,
		    "flow_create: error %d\n", error);
		return (0);
	}
	device_printf(sc->sc_dev,
	    "flow_create: OK local_flowid=%u (fw_id=%u)\n",
	    flowid, flowid + BRCM_H2D_MSGRING_FLOWRING_IDSTART);
	return (0);
}

/* Sysctl: send a small canned Ethernet frame through flowid 0. */
static int
brcm_pci_sysctl_tx_probe(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	struct mbuf *m;
	static const uint8_t da[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	static const uint8_t sa[6] = { 0x02, 0xf3, 0xd1, 0x00, 0x00, 0x02 };
	uint8_t *p;
	int trig = 0, error, i;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (ENOMEM);
	p = mtod(m, uint8_t *);
	memcpy(p, da, 6);
	memcpy(p + 6, sa, 6);
	p[12] = 0x08;	/* ethertype 0x0800 (IPv4) so fw doesn't drop */
	p[13] = 0x00;
	for (i = 14; i < 100; i++)
		p[i] = (uint8_t)(i & 0xff);
	m->m_len = 100;
	m->m_pkthdr.len = 100;

	error = brcm_pci_msgbuf_txmbuf(sc, 0, m, 0);
	if (error != 0) {
		m_freem(m);
		device_printf(sc->sc_dev, "tx_probe: error %d\n", error);
		return (0);
	}
	device_printf(sc->sc_dev,
	    "tx_probe: 100B frame queued via flowid 0 — watch dmesg for "
	    "TX_STATUS\n");
	return (0);
}

/* Sysctl: write 1 → send WLC_UP only. */
static int
brcm_pci_sysctl_wlc_up(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	error = brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_UP, 0);
	device_printf(sc->sc_dev, "wlc_up: %s (err=%d)\n",
	    error == 0 ? "ok" : "fail", error);
	if (error == 0)
		sc->bus_sc.sc_wlc_up = true;
	return (0);
}

/* Sysctl: write 1 → send WLC_DOWN. */
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

/* Sysctl: write int → WLC_SET_INFRA. */
static int
brcm_pci_sysctl_set_infra(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int val = 0, error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	error = brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_SET_INFRA,
	    (uint32_t)val);
	device_printf(sc->sc_dev, "set_infra: %d (err=%d)\n", val, error);
	return (0);
}

/* Sysctl: write int → WLC_SET_WSEC. */
static int
brcm_pci_sysctl_set_wsec(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int val = 0, error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	error = brcm_pci_msgbuf_dcmd_set_int(sc, BRCM_C_SET_WSEC,
	    (uint32_t)val);
	device_printf(sc->sc_dev, "set_wsec: %d (err=%d)\n", val, error);
	return (0);
}

/* Sysctl: write string (2 chars) → WLC_SET_COUNTRY (fixed 4-byte payload:
 * country[3] + rev). */
static int
brcm_pci_sysctl_set_country(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	char buf[4] = { 0 };
	int error;

	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	/* Country payload: 4-char abbrev NUL-padded. */
	error = brcm_pci_msgbuf_dcmd_set_var(sc, "country", buf, 4);
	device_printf(sc->sc_dev, "set_country: \"%s\" (err=%d)\n",
	    buf, error);
	return (0);
}

/*
 * Sysctl: write string → WLC_SET_SSID.  Payload format:
 *   struct { uint32_t len; uint8_t ssid[32]; }
 * Total 36 bytes, LE.
 */
static int
brcm_pci_sysctl_set_ssid(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	char buf[33] = { 0 };
	uint8_t payload[36] = { 0 };
	uint32_t slen;
	int error;

	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	slen = strlen(buf);
	if (slen > 32)
		slen = 32;
	*(uint32_t *)payload = htole32(slen);
	memcpy(payload + 4, buf, slen);
	{
		int32_t fwerr = 0;
		size_t rlen = 0;
		error = brcm_pci_msgbuf_dcmd(sc, BRCM_C_SET_SSID, true,
		    payload, sizeof(payload), NULL, &rlen, &fwerr);
		if (error == 0 && fwerr != 0)
			error = EIO;
	}
	device_printf(sc->sc_dev,
	    "set_ssid: \"%s\" (len=%u err=%d)\n", buf, slen, error);
	return (0);
}

/* Sysctl: read cur_etheraddr iovar and format as MAC string. */
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

/* Steps to bring up chip. */
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
	 * We add the full working set observed on SDIO path (fw defaults
	 * on 43602 don't include ESCAN_RESULT, so a bare add-E_IF
	 * leaves scans silent).
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
 * Sysctl: bring up net80211 attachment.  Reads the chip's MAC via
 * GET_VAR("cur_etheraddr"), populates the shared brcm_softc, runs
 * the preinit DCMD chain, and calls brcm_attach() to expose the
 * driver as wlan0.  Idempotent — subsequent writes with sc_ic
 * already attached return 0 without side effects.
 */
static int
brcm_pci_sysctl_net80211_attach(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	struct brcm_softc *bsc = &sc->bus_sc;
	uint8_t mac[6] = { 0 };
	size_t rlen = sizeof(mac);
	int trig = 0, error;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);

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

	/* Run preinit DCMDs BEFORE net80211 attach so the chip is fully
	 * preconfigured (WLC_UP included) by the time any scan/join
	 * request could arrive from userland. */
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
	 * unconditionally broke fw-supplicant mode entirely (chip would
	 * still not TX data because the wsec_key path wasn't running).
	 */
	brcm_sysctl_attach(bsc);
	device_printf(sc->sc_dev,
	    "net80211_attach: OK — create wlan0 with "
	    "`ifconfig wlan0 create wlandev %s`\n",
	    device_get_nameunit(sc->sc_dev));
	return (0);
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

/* Sysctl: write 1 → WLC_DISASSOC. */
static int
brcm_pci_sysctl_disassoc(SYSCTL_HANDLER_ARGS)
{
	struct brcm_pci_softc *sc = arg1;
	int trig = 0, error;
	int32_t fwerr = 0;
	size_t rlen = 0;

	error = sysctl_handle_int(oidp, &trig, 0, req);
	if (error != 0 || req->newptr == NULL || trig == 0)
		return (error);
	error = brcm_pci_msgbuf_dcmd(sc, BRCM_C_DISASSOC, true,
	    NULL, 0, NULL, &rlen, &fwerr);
	device_printf(sc->sc_dev, "disassoc: err=%d fwerr=%d\n",
	    error, fwerr);
	return (0);
}

/*
 * ACPI S3 / D3 suspend/resume.  Refused by default: on this fw the
 * chip powers off in S3 and comes back cold — reviving it requires
 * the full attach path (chip reset + fw upload + msgbuf attach) which
 * is not yet wired into the resume hook.  Returning EOPNOTSUPP cancels
 * the system suspend cleanly (user's laptop stays awake) instead of
 * letting the kernel proceed and wedging on resume.
 *
 * Opt in by setting `hw.brcm_pci.pm_supported=1` in loader.conf — the
 * best-effort path brings WLC down at suspend and tries a warm resume
 * (chip retained state).  Cold resume is not supported and the driver
 * must be kldunload+kldload to recover.  Full D3-mailbox handshake
 * per Linux brcmfmac (BRCMF_H2D_HOST_D3_INFORM / D2H_DEV_D3_ACK) is
 * follow-up work.
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
	 * silence past the timeout is not fatal — we still let ACPI
	 * transition and cross fingers on resume.
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
	 * Warm-resume: if the chip's ChipID still reads sanely the fw is
	 * probably still alive and we can just re-issue WLC_UP.  A cold-
	 * resumed chip (S3 power off) will fail the DCMD; leave it dead
	 * and note that a kldunload+kldload is required to recover.
	 */
	v = htole32(1);
	if (brcm_dcmd_set(bsc, BRCM_C_UP, &v, sizeof(v)) == 0) {
		bsc->sc_wlc_up = true;
		device_printf(dev, "resume: warm resume ok (chip retained)\n");
		return (0);
	}
	device_printf(dev,
	    "resume: chip cold — full re-init not implemented, "
	    "kldunload+kldload to recover\n");
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
