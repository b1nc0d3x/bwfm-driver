/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom-specific SDIO host-side register definitions for brcm_sdio.
 * These are NOT defined by any SD/SDIO spec — they are documented only
 * in upstream Linux brcmfmac (drivers/net/wireless/broadcom/brcm80211/
 * brcmfmac/sdio.h) and the Broadcom-internal BCMSDH source the chip
 * vendor ships with their SDK.  Values cross-checked against Linux at
 * commit head 2026-06-17.
 *
 * Address-space orientation:
 *
 *   * SDIO function 0 (CCCR) is the standardised control register
 *     block — IO_EN, IO_READY, INT_ENABLE, CIS pointer, etc.
 *
 *   * SDIO function 1 is, on every BCM43xxx WLAN chip, the
 *     "BACKPLANE" function.  The chip is internally a small SoC with
 *     multiple cores (chipcommon, SDIO core, ARM, WLAN MAC, ...)
 *     connected by an internal AXI-like fabric Broadcom calls the
 *     "SiliconBackplane" (hence the "SB" prefix on the constants
 *     below).  Every internal register on every core sits at some
 *     32-bit address on that backplane.  The host reaches them by
 *     programming a "window" inside function 1 and then issuing
 *     CMD52 / CMD53 to func 1.
 *
 *   * SDIO function 2 (when present) is the DMA mailbox used for
 *     bulk packet I/O once firmware is running.  brcm_sdio doesn't
 *     touch it until the firmware-upload phase.
 *
 * Backplane window mechanics:
 *
 *   The window selects a contiguous 32 KB region of chip-internal
 *   address space:
 *     window_base = chip_addr & SBSDIO_SBWINDOW_MASK   (top 17 bits)
 *     sdio_offset = chip_addr & SBSDIO_SB_OFT_ADDR_MASK (low 15 bits)
 *
 *   To access chip_addr:
 *     1.  Program the three SBADDR* bytes so the chip latches the
 *         current window_base.  Byte boundaries:
 *           SBADDRLOW  byte = (chip_addr >> 8)  & 0xFF  (chip bits 8..15)
 *           SBADDRMID  byte = (chip_addr >> 16) & 0xFF  (chip bits 16..23)
 *           SBADDRHIGH byte = (chip_addr >> 24) & 0xFF  (chip bits 24..31)
 *         (Bits 0..14 of chip_addr are redundant here — they come
 *         from the SDIO offset in step 2.  Only bit 15 of SBADDRLOW
 *         actually contributes new information beyond the SDIO
 *         offset; the other 7 bits exist to round to a byte register.)
 *     2.  Issue CMD52 or CMD53 to func 1 at SDIO address
 *         sdio_offset, optionally OR'd with SBSDIO_SB_ACCESS_2_4B_FLAG
 *         for 2- or 4-byte wide access.
 *
 *   Linux caches the current window_base and skips the SBADDR writes
 *   when the new chip_addr falls inside the same 32 KB region — we do
 *   the same to keep firmware uploads from spending 3 CMD52s per
 *   chunk.
 */

#ifndef _BRCM_SDIO_REGS_H_
#define _BRCM_SDIO_REGS_H_

/*
 * SDIO func 1 register addresses for the host-side SDIO interface
 * block on every BCM43xxx WLAN chip.  These are NOT internal chip
 * registers — they live in func 1's CCCR-style register area, before
 * the backplane window kicks in.  Range 0x10000..0x1001F is called
 * SBSDIO_FUNC1_MISC_REG by Broadcom.
 */
#define	SBSDIO_SPROM_CS			0x10000
#define	SBSDIO_SPROM_INFO		0x10001
#define	SBSDIO_SPROM_DATA_LOW		0x10002
#define	SBSDIO_SPROM_DATA_HIGH		0x10003
#define	SBSDIO_SPROM_ADDR_LOW		0x10004
#define	SBSDIO_GPIO_SELECT		0x10005
#define	SBSDIO_GPIO_OUT			0x10006
#define	SBSDIO_GPIO_EN			0x10007
#define	SBSDIO_WATERMARK		0x10008
#define	SBSDIO_DEVICE_CTL		0x10009

#define	SBSDIO_FUNC1_SBADDRLOW		0x1000A
#define	SBSDIO_FUNC1_SBADDRMID		0x1000B
#define	SBSDIO_FUNC1_SBADDRHIGH		0x1000C

#define	SBSDIO_FUNC1_FRAMECTRL		0x1000D
#define	SBSDIO_FUNC1_CHIPCLKCSR		0x1000E
#define	SBSDIO_FUNC1_SDIOPULLUP		0x1000F

/*
 * CHIPCLKCSR bit layout.  The host requests a clock domain by
 * writing the matching *_REQ bit; the chip acknowledges by setting
 * the corresponding *_AVAIL bit.  Polling AVAIL after the REQ write
 * is how we know the backplane clock is up.
 *
 *   ILP   Internal Low-Power clock - always on; SDIO core only
 *   ALP   Active Low-Power clock   - lets us read backplane regs
 *   HT    High-Throughput clock    - lets us write backplane regs
 *                                    and drive any core's wrap
 *
 * On a cold chip (boot ROM running) the only clock is ILP/ALP -- HT
 * is gated off.  CC.CHIPID reads on the ALP clock so it works
 * before HT, but CR4 wrap.IOCTL writes need HT.  Hence the failure
 * we saw on 2026-06-17.
 */
#define	SBSDIO_FORCE_ALP		0x01
#define	SBSDIO_FORCE_HT			0x02
#define	SBSDIO_FORCE_ILP		0x04
#define	SBSDIO_ALP_AVAIL_REQ		0x08
#define	SBSDIO_HT_AVAIL_REQ		0x10
#define	SBSDIO_FORCE_HW_CLKREQ_OFF	0x20
#define	SBSDIO_ALP_AVAIL		0x40
#define	SBSDIO_HT_AVAIL			0x80
#define	SBSDIO_CSR_MASK			0x1F
#define	SBSDIO_AVBITS	(SBSDIO_HT_AVAIL | SBSDIO_ALP_AVAIL)
#define	SBSDIO_FUNC1_WFRAMEBCLO		0x10019
#define	SBSDIO_FUNC1_WFRAMEBCHI		0x1001A
#define	SBSDIO_FUNC1_RFRAMEBCLO		0x1001B
#define	SBSDIO_FUNC1_RFRAMEBCHI		0x1001C
#define	SBSDIO_FUNC1_MESBUSYCTRL	0x1001D
#define	SBSDIO_FUNC1_WAKEUPCTRL		0x1001E
#define	 SBSDIO_WCTRL_WAKE_TILL_ALP_AVAIL	(1 << 0)
#define	 SBSDIO_WCTRL_WAKE_TILL_HT_AVAIL	(1 << 1)
#define	SBSDIO_FUNC1_SLEEPCSR		0x1001F
#define	 SBSDIO_FUNC1_SLEEPCSR_KSO_MASK		0x01
#define	 SBSDIO_FUNC1_SLEEPCSR_KSO_EN		0x01
#define	 SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK	0x02

/*
 * Address-decoding masks for backplane-routed accesses.
 *
 *   SBSDIO_SB_OFT_ADDR_MASK  — low 15 bits of chip_addr come straight
 *                              from the SDIO offset.
 *   SBSDIO_SB_OFT_ADDR_LIMIT — 0x8000; addresses >= this require a
 *                              window reprogram before the next SDIO
 *                              transaction.
 *   SBSDIO_SB_ACCESS_2_4B_FLAG — OR into the SDIO offset to request a
 *                                2- or 4-byte wide access.  Without
 *                                this bit, the chip serves the
 *                                request 1 byte at a time even if
 *                                CMD53 carries more.
 *   SBSDIO_SBWINDOW_MASK     — upper 17 bits of chip_addr; what
 *                              SBADDR{LOW,MID,HIGH} actually program.
 */
#define	SBSDIO_SB_OFT_ADDR_MASK		0x07FFF
#define	SBSDIO_SB_OFT_ADDR_LIMIT	0x08000
#define	SBSDIO_SB_ACCESS_2_4B_FLAG	0x08000
#define	SBSDIO_SBWINDOW_MASK		0xFFFF8000U

/*
 * Vendor-specific CCCR registers Broadcom defines above the standard
 * CCCR layout (0x00..0x17).  brcm_sdio uses BRCM_CARDCAP to learn
 * which CMD14 (sleep-control) variant the chip supports, and
 * BRCM_SEPINT to route the host-wake interrupt out of band when the
 * platform wires it that way.  Pi 4 doesn't need either today.
 */
#define	SDIO_CCCR_BRCM_CARDCAP			0xF0
#define	 SDIO_CCCR_BRCM_CARDCAP_CMD14_SUPPORT	(1u << 1)
#define	 SDIO_CCCR_BRCM_CARDCAP_CMD14_EXT	(1u << 2)
#define	 SDIO_CCCR_BRCM_CARDCAP_CMD_NODEC	(1u << 3)

#define	SDIO_CCCR_BRCM_CARDCTRL			0xF1
#define	 SDIO_CCCR_BRCM_CARDCTRL_WLANRESET	(1u << 1)

#define	SDIO_CCCR_BRCM_SEPINT			0xF2
#define	 SDIO_CCCR_BRCM_SEPINT_MASK		(1u << 0)
#define	 SDIO_CCCR_BRCM_SEPINT_OE		(1u << 1)
#define	 SDIO_CCCR_BRCM_SEPINT_ACT_HI		(1u << 2)

/*
 * Function 1 / Function 2 enable + ready bit masks.  The standard
 * SDIO CCCR.IO_EN (offset 0x02) and CCCR.IO_READY (offset 0x03) each
 * use bit N to mean "function N enabled" / "function N ready".  Linux
 * names these constants in brcmfmac/sdio.h and we reuse the same
 * names for grep-friendliness against the reference driver.
 */
#define	SDIO_FUNC_ENABLE_1	0x02
#define	SDIO_FUNC_ENABLE_2	0x04
#define	SDIO_FUNC_READY_1	0x02
#define	SDIO_FUNC_READY_2	0x04

/*
 * Chip-internal addresses for the chipcommon ("CC") core.  ChipCommon
 * is always the first core on the BCM43xxx backplane, and the BCM
 * silicon team has standardised its address across the entire family:
 * 0x18000000.  CC.CHIPID at offset 0 is the canonical "are you alive"
 * probe register — its low 16 bits hold the chip id (matches the SDIO
 * CIS prodid we already enumerated), bits 16..27 hold revision and
 * package option, bits 28..31 hold the number of cores on the
 * backplane.  Linux reads this exact register right after enabling
 * function 1 as proof the backplane window plumbing works.
 */
#define	BRCM_CC_CORE_BASE	0x18000000U
#define	BRCM_CC_CHIPID		0x00

#define	BRCM_CHIPID_ID(reg)	((reg) & 0x0000FFFF)
#define	BRCM_CHIPID_REV(reg)	(((reg) >> 16) & 0xF)
#define	BRCM_CHIPID_PKG(reg)	(((reg) >> 20) & 0xF)
#define	BRCM_CHIPID_NUMCORES(reg) (((reg) >> 24) & 0xF)

/*
 * BCM chip family identifiers as they appear in CC.CHIPID bits 0..15.
 * Linux brcmfmac names some of these in decimal (43430 == 0xa9a6) and
 * some in hex (0x4345); we use the actual hex register value here for
 * grep-against-the-wire clarity.  The hex value is what the host
 * reads from the chip via the backplane window.
 */
#define	BRCM_CHIP_BCM43430	0xa9a6	/* Linux: BRCM_CC_43430_CHIP_ID */
#define	BRCM_CHIP_BCM4339	0x4339
#define	BRCM_CHIP_BCM4345	0x4345	/* BCM43455/43456 silicon family */
#define	BRCM_CHIP_BCM4354	0x4354
#define	BRCM_CHIP_BCM4356	0x4356
#define	BRCM_CHIP_BCM4359	0x4359
#define	BRCM_CHIP_BCM4373	0x4373	/* CYW4373 */

/*
 * ARM core type at the chip's compute centre.  Determines the
 * passive/active reset sequence we must use:
 *
 *   BRCM_ARM_CM3  Cortex-M3, simple MCU class.  BCM4329, BCM43430,
 *                 BCM43439.  ARM reset is done via SOCRAM core's
 *                 standard reset bit.
 *   BRCM_ARM_CR4  Cortex-R4, real-time class.  BCM4345/43455,
 *                 BCM4339, BCM4354, BCM4356, BCM4359, BCM4373.  Has
 *                 its own "rstvec" register; firmware load address
 *                 isn't necessarily the same as the ARM reset vector
 *                 (we program the vector via the CR4's TCM register).
 *   BRCM_ARM_CA7  Cortex-A7, application class.  Newer chips
 *                 (BCM43596 etc.).  Not on Pi -- listed for
 *                 completeness so the enum tracks Linux's set.
 */
enum brcm_arm_core {
	BRCM_ARM_CM3 = 1,
	BRCM_ARM_CR4 = 2,
	BRCM_ARM_CA7 = 3,
};

/*
 * ChipCommon (CC) core register offsets.  CC always sits at
 * BRCM_CC_CORE_BASE.  Beyond CHIPID at offset 0, we care about
 * EROMPTR at offset 0xFC -- the pointer to the Enumeration ROM
 * that lists every core on the backplane.  Walking the EROM is how
 * we discover the address of the ARM CR4 core (and SOCRAM, WLAN,
 * SDIO core) without hardcoding per-chip addresses.  (Linux uses
 * 0xFC via the struct chipcregs eromptr field; the chip's
 * AHB-style mirror at 0x40C does not exist on the SoC variant we
 * talk to over SDIO.)
 */
#define	BRCM_CC_EROMPTR		0xFC

/*
 * EROM descriptor decode.  Each EROM entry is a 32-bit word read at
 * the running EROM pointer (incremented by 4 each read).  Linux
 * brcmfmac/chip.c documents the layout; we reuse the same names so
 * a side-by-side review against the reference driver is grep-friendly.
 *
 * Each entry's low 4 bits identify the entry type.  Components hold
 * the core's vendor/partnum/rev metadata, address descriptors hold
 * the core's slave-register-window base and wrapper base.  Walking
 * the table builds a per-chip core map.
 */
#define	DMP_DESC_TYPE_MSK	0x0000000F
#define	 DMP_DESC_EMPTY		0x00000000
#define	 DMP_DESC_VALID		0x00000001
#define	 DMP_DESC_COMPONENT	0x00000001
#define	 DMP_DESC_MASTER_PORT	0x00000003
#define	 DMP_DESC_ADDRESS	0x00000005
#define	 DMP_DESC_ADDRSIZE_GT32	0x00000008
#define	 DMP_DESC_EOT		0x0000000F

#define	DMP_COMP_PARTNUM	0x000FFF00
#define	DMP_COMP_PARTNUM_S	8
#define	DMP_COMP_REVISION	0xFF000000
#define	DMP_COMP_REVISION_S	24
#define	DMP_COMP_NUM_SWRAP	0x00F80000
#define	DMP_COMP_NUM_SWRAP_S	19
#define	DMP_COMP_NUM_MWRAP	0x0007C000
#define	DMP_COMP_NUM_MWRAP_S	14

#define	DMP_SLAVE_ADDR_BASE	0xFFFFF000
#define	DMP_SLAVE_TYPE		0x000000C0
#define	DMP_SLAVE_TYPE_S	6
#define	 DMP_SLAVE_TYPE_SLAVE	0
#define	 DMP_SLAVE_TYPE_SWRAP	2
#define	 DMP_SLAVE_TYPE_MWRAP	3
#define	DMP_SLAVE_SIZE_TYPE	0x00000030
#define	DMP_SLAVE_SIZE_TYPE_S	4
#define	 DMP_SLAVE_SIZE_4K	0
#define	 DMP_SLAVE_SIZE_8K	1
#define	 DMP_SLAVE_SIZE_DESC	3

/*
 * Broadcom core IDs (DMP partnum field).  Each ARM-class chip has at
 * least chipcommon + one ARM core + one or more WLAN cores.  We
 * recognise the ones the firmware uploader and runtime touch.
 *
 * Linux uses these names verbatim (drivers/bcma/core.c BCMA_CORE_*),
 * carried over for grep parity.
 */
#define	BCMA_CORE_CHIPCOMMON		0x800
#define	BCMA_CORE_INTERNAL_MEM		0x80E	/* SOCRAM */
#define	BCMA_CORE_PMU			0x827
#define	BCMA_CORE_GCI			0x840	/* General Chip Interface */
#define	BCMA_CORE_80211			0x812	/* d11 (WLAN MAC) */
#define	BCMA_CORE_ARM_CM3		0x82A
#define	BCMA_CORE_ARM_CR4		0x83E
#define	BCMA_CORE_ARM_CA7		0x847
#define	BCMA_CORE_SYS_MEM		0x849
#define	BCMA_CORE_SDIO_DEV		0x829

/*
 * SDIO device-core register offsets — subset of struct sdpcmd_regs in
 * Linux brcmfmac/sdio.h.  Only the fields the chip activate sequence
 * touches are defined here; expand as more of sdio.c is ported.
 */
#define	BRCM_SD_REG_INTSTATUS		0x020

/*
 * Wrapper register offsets shared across cores.  Every core's
 * wrapper exposes the same IOCTL and RESETCTL registers; the wrap
 * base address is what changes per-core.
 *
 *   BCMA_IOCTL     0x408  core-specific control bits (e.g. clock
 *                         enable, PHY reset for d11, CPU halt for
 *                         ARM)
 *   BCMA_RESET_CTL 0x800  bit 0 = "place core in reset"
 *
 * ARMCR4_BCMA_IOCTL_CPUHALT is the CR4-specific bit we OR into
 * BCMA_IOCTL to keep the Cortex-R4 stopped while we write into its
 * tightly-coupled memory (TCM) banks.
 */
#define	BCMA_IOCTL			0x408
#define	 BCMA_IOCTL_CLK			0x0001	/* core clock enable */
#define	 BCMA_IOCTL_FGC			0x0002	/* force gated clock */
#define	BCMA_RESET_CTL			0x800
#define	 BCMA_RESET_CTL_RESET		(1u << 0)
#define	ARMCR4_BCMA_IOCTL_CPUHALT	0x0020

/*
 * Chipcommon PMU control register.  Lives at chipcommon base + 0x600 on
 * every BCM43xxx the SDIO driver currently supports (the PMU is embedded
 * in chipcommon, not a separate core, on these chips).  RES_RELOAD bit
 * tells the PMU to reload its resource table -- on a chip whose boot ROM
 * left the resource state partial, this is what flips the PMU into a
 * mode where it actually generates HT in response to FORCE_HT requests.
 * Without RES_RELOAD the PMU acknowledges FORCE_HT in CHIPCLKCSR but
 * doesn't service it and HT_AVAIL never asserts.
 */
#define	BRCM_CC_PMUCONTROL			0x00000600
#define	 BRCM_CC_PMUCONTROL_RES_MASK		0x00006000
#define	 BRCM_CC_PMUCONTROL_RES_SHIFT		13
#define	 BRCM_CC_PMUCONTROL_RES_RELOAD		0x2
#define	BRCM_CC_PMUCAPABILITIES			0x00000604
#define	BRCM_CC_PMUSTATUS			0x00000608
#define	BRCM_CC_PMU_RES_STATE			0x0000060c
#define	BRCM_CC_PMU_RES_PENDING			0x00000610
#define	BRCM_CC_PMU_MIN_RES_MASK		0x00000618
#define	BRCM_CC_PMU_MAX_RES_MASK		0x0000061c
#define	D11_BCMA_IOCTL_PHYCLOCKEN	0x0004
#define	D11_BCMA_IOCTL_PHYRESET		0x0008

/*
 * Per-chip recipe.  One row per (family, rev range) Linux brcmfmac
 * supports for SDIO.  Matched by chip_id == CC.CHIPID.low16 AND
 * (chiprev_mask & (1 << chip_rev)) != 0.  Linux uses a 32-bit
 * rev_mask precisely because Broadcom respins the same silicon at
 * different revs and switches firmware lineage at revision
 * boundaries -- e.g. BCM4345 rev <9 uses brcmfmac43455-sdio.bin while
 * rev 9 uses brcmfmac43456-sdio.bin.
 *
 *   ram_base    chip-internal address where the firmware blob
 *               starts loading.  For CR4 chips, this is also where
 *               we point the ARM rstvec after upload.
 *   fw_name     short suffix; brcm_sdio prepends "brcmfmac" and
 *               appends "-sdio" + ".bin" / ".txt" to form the
 *               firmware(9) request name, matching Linux's naming
 *               of /lib/firmware/brcm/brcmfmac*-sdio.{bin,txt}.
 *   nvram_board optional board-specific override for the NVRAM
 *               file (Pi 4 needs a different antenna trim from
 *               generic boards).  NULL means use the default
 *               "brcmfmac<fw_name>-sdio.txt" filename.
 */
struct brcm_sdio_chip_recipe {
	uint16_t		chip_id;
	uint32_t		chiprev_mask;
	uint32_t		ram_base;
	enum brcm_arm_core	arm_core;
	const char		*fw_name;
	const char		*nvram_board;
	const char		*desc;
};

#endif /* _BRCM_SDIO_REGS_H_ */
