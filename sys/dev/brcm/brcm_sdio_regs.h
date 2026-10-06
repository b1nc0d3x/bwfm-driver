/*-
 * SPDX-License-Identifier: BSD-2-Clause AND ISC
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 * Copyright (c) 2010-2016 Broadcom Corporation
 * Copyright (c) 2018 Patrick Wildt <patrick@blueri.se>
 *
 * Broadcom-only SDIO host-side registers for brcm_sdio.
 *
 * These are NOT in any SD/SDIO spec. They come from Linux
 * brcmfmac (drivers/net/wireless/broadcom/brcm80211/
 * brcmfmac/sdio.h, with the CHIPCLKCSR bits in sdio.c), the
 * OpenBSD/NetBSD bwfm SDIO driver (if_bwfm_sdio.c/.h), and
 * Broadcom's BCMSDH source that ships with vendor SDKs.
 * Portions derived from Linux brcmfmac (sdio.h, sdio.c, chip.c)
 * and OpenBSD/NetBSD if_bwfm_sdio are ISC licensed.
 *
 * Address-space layout:
 *
 *   * SDIO function 0 (CCCR) is the standard control block.
 *     IO_EN, IO_READY, INT_ENABLE, CIS pointer, etc.
 *
 *   * SDIO function 1 is the "BACKPLANE" function on every
 *     BCM43xxx WLAN chip. The chip is a small SoC with many
 *     cores (chipcommon, SDIO, ARM, WLAN MAC, ...) linked
 *     by an internal AXI-like fabric Broadcom calls the
 *     "SiliconBackplane". That is why the constants below
 *     start with "SB". Every core's registers live at some
 *     32-bit address on the backplane. The host reaches them
 *     by programming a "window" inside func 1 and then doing
 *     CMD52 / CMD53 to func 1.
 *
 *   * SDIO function 2 is the WLAN frame FIFO, used once the
 *     firmware is running (see brcm_sdpcm.c).
 *
 * How the backplane window works:
 *
 *   The window picks a 32 KB slice of chip address space:
 *     window_base = chip_addr & SBSDIO_SBWINDOW_MASK   (top 17 bits)
 *     sdio_offset = chip_addr & SBSDIO_SB_OFT_ADDR_MASK (low 15 bits)
 *
 *   To reach chip_addr:
 *     1. Program the three SBADDR* bytes so the chip latches
 *        the new window_base:
 *          SBADDRLOW  = (chip_addr >> 8)  & 0xFF  (bits 8..15)
 *          SBADDRMID  = (chip_addr >> 16) & 0xFF  (bits 16..23)
 *          SBADDRHIGH = (chip_addr >> 24) & 0xFF  (bits 24..31)
 *        Bits 0..14 of chip_addr are unused here. They come
 *        from the SDIO offset in step 2. Only bit 15 of
 *        SBADDRLOW adds new info. The other 7 bits exist to
 *        round out a byte register.
 *     2. Do CMD52 or CMD53 to func 1 at sdio_offset. OR in
 *        SBSDIO_SB_ACCESS_2_4B_FLAG for 2- or 4-byte access.
 *
 *   Linux caches the current window_base and skips the
 *   SBADDR writes when the new chip_addr is in the same
 *   32 KB region. We do the same so firmware upload does
 *   not spend 3 CMD52s per chunk.
 */

#ifndef _BRCM_SDIO_REGS_H_
#define _BRCM_SDIO_REGS_H_

/*
 * SDIO func 1 register addresses for the host-side SDIO
 * block on every BCM43xxx WLAN chip.
 *
 * These are NOT internal chip registers. They live in func
 * 1's CCCR-style area, before the backplane window kicks in.
 * Broadcom calls the 0x10000..0x1001F range SBSDIO_FUNC1_MISC_REG.
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
 * CHIPCLKCSR bit layout.
 *
 * The host asks for a clock by writing the matching *_REQ
 * bit. The chip acks by setting the matching *_AVAIL bit.
 * Poll AVAIL after writing REQ to know the backplane clock
 * is up.
 *
 *   ILP  Internal Low-Power clock. Always on; SDIO core only.
 *   ALP  Active Low-Power clock. Lets us read backplane regs.
 *   HT   High-Throughput clock. Lets us write backplane regs
 *        and drive any core's wrap.
 *
 * On a cold chip (boot ROM running) only ILP/ALP is on and HT
 * is gated off. CC.CHIPID reads work on ALP, but CR4
 * wrap.IOCTL writes need HT.
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
 *   SBSDIO_SB_OFT_ADDR_MASK  Low 15 bits of chip_addr come
 *                            straight from the SDIO offset.
 *   SBSDIO_SB_OFT_ADDR_LIMIT 0x8000. Addresses >= this need
 *                            a window reprogram before the
 *                            next SDIO transaction.
 *   SBSDIO_SB_ACCESS_2_4B_FLAG OR into the SDIO offset for
 *                            2- or 4-byte access. Without
 *                            it, the chip serves 1 byte at a
 *                            time even if CMD53 carries more.
 *   SBSDIO_SBWINDOW_MASK     Upper 17 bits of chip_addr —
 *                            what SBADDR{LOW,MID,HIGH} sets.
 */
#define	SBSDIO_SB_OFT_ADDR_MASK		0x07FFF
#define	SBSDIO_SB_OFT_ADDR_LIMIT	0x08000
#define	SBSDIO_SB_ACCESS_2_4B_FLAG	0x08000
#define	SBSDIO_SBWINDOW_MASK		0xFFFF8000U

/*
 * Vendor CCCR registers Broadcom adds above the standard
 * CCCR layout (0x00..0x17).
 *
 * BRCM_CARDCAP says which CMD14 (sleep-control) variant the
 * chip supports. BRCM_SEPINT routes the host-wake interrupt
 * out of band on platforms wired that way; this driver does
 * not use it.
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
 * Function 1 / Function 2 enable + ready bit masks.
 *
 * The standard SDIO CCCR.IO_EN (offset 0x02) and
 * CCCR.IO_READY (offset 0x03) use bit N to mean "function N
 * enabled" / "function N ready". Linux names these in
 * brcmfmac/sdio.h. We use the same names so grep works
 * against the reference driver.
 */
#define	SDIO_FUNC_ENABLE_1	0x02
#define	SDIO_FUNC_ENABLE_2	0x04
#define	SDIO_FUNC_READY_1	0x02
#define	SDIO_FUNC_READY_2	0x04

/*
 * Chip-internal addresses for the chipcommon ("CC") core.
 *
 * ChipCommon is always the first core on the BCM43xxx
 * backplane. Broadcom uses the same address across the
 * whole family: 0x18000000.
 *
 * CC.CHIPID at offset 0 is the "are you alive" probe
 * register. Low 16 bits hold the chip id (it matches the SDIO
 * CIS prodid). Bits 16..19 hold the revision,
 * 20..23 the package option, 24..27 the core count, and
 * 28..31 the chip (interconnect) type.
 *
 * Linux reads this register right after enabling function 1
 * to prove the backplane window plumbing works.
 */
#define	BRCM_CC_CORE_BASE	0x18000000U
#define	BRCM_CC_CHIPID		0x00

#define	BRCM_CHIPID_ID(reg)	((reg) & 0x0000FFFF)
#define	BRCM_CHIPID_REV(reg)	(((reg) >> 16) & 0xF)
#define	BRCM_CHIPID_PKG(reg)	(((reg) >> 20) & 0xF)
#define	BRCM_CHIPID_NUMCORES(reg) (((reg) >> 24) & 0xF)

/*
 * BCM chip family IDs as they show up in CC.CHIPID bits 0..15.
 *
 * Linux brcmfmac names some of these in decimal
 * (43430 == 0xa9a6) and some in hex (0x4345). We use the hex
 * register value here so grepping against the wire is easy.
 * That hex value is what the host reads from the chip.
 */
#define	BRCM_CHIP_BCM43430	0xa9a6	/* Linux: BRCM_CC_43430_CHIP_ID */
#define	BRCM_CHIP_BCM4339	0x4339
#define	BRCM_CHIP_BCM4345	0x4345	/* BCM43455/43456 silicon family */
#define	BRCM_CHIP_BCM4354	0x4354
#define	BRCM_CHIP_BCM4356	0x4356
#define	BRCM_CHIP_BCM4359	0x4359
#define	BRCM_CHIP_BCM4373	0x4373	/* CYW4373 */

/*
 * ARM core type at the chip's compute centre.
 *
 * Picks the passive/active reset sequence we use:
 *
 *   BRCM_ARM_CM3 Cortex-M3, simple MCU. BCM4329, BCM43430,
 *                BCM43439. ARM reset uses SOCRAM's standard
 *                reset bit.
 *   BRCM_ARM_CR4 Cortex-R4, real-time. BCM4345/43455,
 *                BCM4339, BCM4354, BCM4356, BCM4359, BCM4373.
 *                Has its own "rstvec" register. Firmware
 *                load address is not always the ARM reset
 *                vector (we program the vector via CR4 TCM).
 *   BRCM_ARM_CA7 Cortex-A7, application class. Newer chips
 *                (BCM43596, etc.). Listed to cover the three
 *                ARM core ids Linux handles
 *                (BCMA_CORE_ARM_CM3/CR4/CA7).
 */
enum brcm_arm_core {
	BRCM_ARM_CM3 = 1,
	BRCM_ARM_CR4 = 2,
	BRCM_ARM_CA7 = 3,
};

/*
 * ChipCommon (CC) core register offsets.
 *
 * CC always sits at BRCM_CC_CORE_BASE. Beyond CHIPID at
 * offset 0, we care about EROMPTR at offset 0xFC. That is
 * the pointer to the Enumeration ROM, which lists every
 * core on the backplane. Walking EROM finds the ARM CR4
 * core (and SOCRAM, WLAN, SDIO core) without hardcoding
 * per-chip addresses.
 *
 * Linux uses 0xFC via the struct chipcregs eromptr field.
 * The chip's AHB-style mirror at 0x40C does not exist on
 * the SoC variant we reach over SDIO.
 */
#define	BRCM_CC_EROMPTR		0xFC

/*
 * EROM descriptor decode.
 *
 * Each EROM entry is a 32-bit word read at the running EROM
 * pointer (incremented by 4 each read). Linux
 * brcmfmac/chip.c documents the layout. We use the same
 * names so side-by-side review with the reference driver is
 * grep-friendly.
 *
 * The low 4 bits of each entry give its type. Components
 * hold vendor / partnum / rev metadata. Address descriptors
 * hold the core's slave-register-window base and wrapper
 * base. Walking the table builds a per-chip core map.
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
 * Broadcom core IDs (DMP partnum field).
 *
 * Every ARM-class chip has at least chipcommon + one ARM
 * core + one or more WLAN cores. We name only the ones the
 * firmware uploader and runtime touch.
 *
 * Linux uses these names as-is (include/linux/bcma/bcma.h
 * BCMA_CORE_*). Kept verbatim for grep parity.
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
 * SDIO device-core register offsets. Subset of struct
 * sdpcmd_regs in Linux brcmfmac/sdio.h.
 *
 * Only the fields the chip activate sequence touches are
 * here.
 */
#define	BRCM_SD_REG_INTSTATUS		0x020

/*
 * Wrapper register offsets, shared across cores.
 *
 * Every core's wrapper has the same IOCTL and RESETCTL
 * registers. Only the wrap base address changes per core.
 *
 *   BCMA_IOCTL     0x408 Core-specific control bits (clock
 *                        enable, PHY reset for d11, CPU
 *                        halt for ARM).
 *   BCMA_RESET_CTL 0x800 Bit 0 = "place core in reset".
 *
 * ARMCR4_BCMA_IOCTL_CPUHALT is the CR4-only bit we OR into
 * BCMA_IOCTL to keep the Cortex-R4 stopped while we write
 * into its tightly-coupled memory (TCM) banks.
 */
#define	BCMA_IOCTL			0x408
#define	 BCMA_IOCTL_CLK			0x0001	/* core clock enable */
#define	 BCMA_IOCTL_FGC			0x0002	/* force gated clock */
#define	BCMA_RESET_CTL			0x800
#define	 BCMA_RESET_CTL_RESET		(1u << 0)
#define	ARMCR4_BCMA_IOCTL_CPUHALT	0x0020

/*
 * Chipcommon PMU control register.
 *
 * Lives at chipcommon base + 0x600. Linux uses chipcommon
 * unless the chip has a separate PMU core (ccrev >= 35 with
 * the AOB capability); see brcm_chip_get_pmu().
 *
 * RES_RELOAD tells the PMU to reload its resource table. On
 * chips whose boot ROM left the resource state partial, the
 * PMU otherwise acks FORCE_HT in CHIPCLKCSR but never asserts
 * HT_AVAIL; after the reload it grants HT.
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
 * Per-chip recipe. One row per (family, rev range) Linux
 * brcmfmac supports for SDIO.
 *
 * Match rule: chip_id == CC.CHIPID.low16 AND
 * (chiprev_mask & (1 << chip_rev)) != 0. Linux uses a
 * 32-bit rev_mask because Broadcom respins the same silicon
 * at different revs and switches firmware at rev boundaries.
 * For example, BCM4345 rev 9 uses brcmfmac43456-sdio.bin
 * while revs 6-8 and 10 and up use brcmfmac43455-sdio.bin
 * (revs 0-5 match no row).
 *
 *   ram_base    Chip-internal address where the firmware
 *               blob starts loading. On CR4 chips, also
 *               where we point the ARM rstvec after upload.
 *   fw_name     Short suffix. brcm_sdio prepends "brcmfmac"
 *               and appends "-sdio.bin" or "-sdio.txt" to
 *               form the firmware(9) request name, following
 *               Linux's brcmfmac*-sdio.{bin,txt} naming.
 *   nvram_board Optional board-specific NVRAM file override.
 *               Some boards need a different antenna trim
 *               from generic ones. NULL means use the default
 *               "brcmfmac<fw_name>-sdio.txt".
 */
struct brcm_sdio_chip_recipe {
	uint16_t		chip_id;	/* chip family id */
	uint32_t		chiprev_mask;	/* which chip revisions match */
	uint32_t		ram_base;
	enum brcm_arm_core	arm_core;	/* which ARM core type */
	const char		*fw_name;
	const char		*nvram_board;
	const char		*desc;	/* human-readable name */
};

#endif /* _BRCM_SDIO_REGS_H_ */
