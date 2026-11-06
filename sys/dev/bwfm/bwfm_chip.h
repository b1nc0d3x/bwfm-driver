/*-
 * SPDX-License-Identifier: BSD-2-Clause AND ISC
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 * Copyright (c) 2014 Broadcom Corporation
 *
 * Chip layer for Broadcom 802.11 chips (BCM43xxx).
 *
 * Works with any bus. Shaped like Linux brcmfmac chip.c but
 * written in FreeBSD style (no linuxkpi). A transport
 * (SDIO, PCIe, USB) fills in bwfm_chip_ops. The chip layer
 * uses that vtable to drive chipcommon, PMU indirect
 * registers, OTP, and the EROM walk.
 *
 * Names: types and functions use bwfm_chip_*.
 * Register macros use BWFM_CC_* (like bwfmreg.h).
 *
 * Portions derived from Linux brcmfmac chip.h are ISC licensed.
 */

#ifndef _DEV_BWFM_BWFM_CHIP_H_
#define _DEV_BWFM_BWFM_CHIP_H_

#include <sys/types.h>
#include <sys/queue.h>

/*
 * ChipCommon register offsets (from the CC core base).
 * Cross-checked against Linux
 * drivers/net/wireless/broadcom/brcm80211/include/chipcommon.h
 * struct chipcregs. Only the ones the chip layer uses are
 * here. The full set lives in bwfmreg.h if needed.
 */
/* BWFM_CC_CHIPID and BWFM_CC_EROMPTR live in bwfm_sdio_regs.h. */
#define	BWFM_CC_CAPABILITIES		0x004
#define	BWFM_CC_CORECONTROL		0x008
#define	BWFM_CC_OTPSTATUS		0x010
#define	BWFM_CC_OTPCONTROL		0x014
#define	BWFM_CC_OTPPROG			0x018
#define	BWFM_CC_OTPLAYOUT		0x01c
#define	BWFM_CC_CHIPSTATUS		0x02c
#define	BWFM_CC_CAPABILITIES_EXT	0x0ac

/*
 * PMU register offsets (CC-relative for the built-in PMU).
 *
 * BWFM_CC_PMUCONTROL / CAPABILITIES / STATUS / RES_STATE /
 * MIN_RES_MASK / MAX_RES_MASK are in bwfm_sdio_regs.h. Only
 * the extra ones not in that file live here.
 */
#define	BWFM_CC_PMU_CAPABILITIES_EXT	0x64c
#define	BWFM_CC_PMU_CHIPCONTROL_ADDR	0x650
#define	BWFM_CC_PMU_CHIPCONTROL_DATA	0x654
#define	BWFM_CC_PMU_REGCONTROL_ADDR	0x658
#define	BWFM_CC_PMU_REGCONTROL_DATA	0x65c
#define	BWFM_CC_PMU_PLLCONTROL_ADDR	0x660
#define	BWFM_CC_PMU_PLLCONTROL_DATA	0x664
#define	BWFM_CC_PMU_RETENTION_CTL	0x670

/* PMUCONTROL bits. */
#define	BWFM_CC_PMUCTL_RES_RELOAD	0x2u
#define	BWFM_CC_PMUCTL_RES_SHIFT	13

/* OTP window: at CC base + 0x800, holds 768 u16 words. */
#define	BWFM_CC_SROMOTP_OFFSET		0x800
#define	BWFM_CC_SROMOTP_WORDS		768

/* OTPSTATUS / OTPCONTROL bits we use. */
#define	BWFM_OTPSTATUS_OL_PRESENT	0x00000001u	/* OTP block present */
#define	BWFM_OTPSTATUS_OL_PROGRAMMED	0x00000004u	/* HW-fuse rows valid */

/*
 * PMU capabilities. Used to pick the right indirect-register
 * layout for chipcontrol / regcontrol probes. pmurev is in
 * the low 8 bits.
 */
#define	BWFM_PMUCAP_REV_MASK		0xffu

/*
 * Chip object. The bus-neutral state the chip layer owns.
 *
 * A transport allocates one (often inside its softc), sets
 * ops, ctx, and identifying fields, then calls
 * bwfm_chip_attach(). The chip layer fills in the public
 * fields during attach. Transports may read them, not write.
 */
struct bwfm_chip_core {
	TAILQ_ENTRY(bwfm_chip_core)	link;	/* list linkage */
	uint16_t			id;	/* core id */
	uint16_t			rev;	/* core revision */
	uint32_t			base;	/* register base address */
	uint32_t			wrap;	/* wrapper base address */
};
TAILQ_HEAD(bwfm_chip_corelist, bwfm_chip_core);

/*
 * Callbacks the bus driver supplies.
 *
 *   read32 / write32: 32-bit access to a chip-side address.
 *     Same address space EROM uses. The bus driver handles
 *     the SBADDR window on its own.
 *   prepare: called once during attach, before the chipid
 *     read. The bus gets the chip into ALPAvail state.
 *     Returns 0 on success.
 *   activate: writes rstvec to chip[0]. Bus-specific because
 *     some transports use DMA instead of F1 word access.
 *     Called from set_active.
 */
struct bwfm_chip;
struct bwfm_chip_ops {
	uint32_t	(*read32)(void *ctx, uint32_t addr);
	void		(*write32)(void *ctx, uint32_t addr, uint32_t val);
	int		(*prepare)(void *ctx);
	void		(*activate)(void *ctx, struct bwfm_chip *pub,
			    uint32_t rstvec);
};

struct bwfm_chip {
	/* Chip identity (set by recognition). */
	uint32_t			chip;		/* CID_ID */
	uint32_t			chiprev;	/* CID_REV */
	uint32_t			enum_base;	/* SI_ENUM_BASE */
	uint32_t			cc_caps;
	uint32_t			cc_caps_ext;
	uint32_t			pmu_caps;
	uint32_t			pmurev;
	uint32_t			ramsize;
	uint32_t			rambase;

	/* Cores found during the EROM walk. */
	struct bwfm_chip_corelist	cores;
	uint32_t			ncores;

	/* Hook back into the bus driver. */
	const struct bwfm_chip_ops	*ops;
	void				*ctx;
};

/*
 * Public API. Lifecycle:
 *
 *   bwfm_chip_init -- set up the chip object. Call once,
 *                     before anything else. Sets ops/ctx and
 *                     the core list head. Safe on re-init.
 *   bwfm_chip_free -- free the core list memory.
 *
 * Inspect cores (after the EROM walk):
 *   bwfm_chip_get_core, bwfm_chip_get_pmu,
 *   bwfm_chip_get_chipcommon
 *
 * PMU indirect register helpers:
 *   bwfm_chip_cc_chipcontrol_read/write32  (PMU chipcontrol)
 *   bwfm_chip_cc_regcontrol_read/write32   (PMU regcontrol)
 *   bwfm_chip_cc_pllcontrol_read/write32   (PMU pllcontrol)
 *
 * OTP (one-time-programmable) access:
 *   bwfm_chip_otp_present -- fuse block exists and is set
 *   bwfm_chip_otp_read16  -- read one word (index 0..767)
 *   bwfm_chip_otp_dump    -- bulk-read the OTP window
 *
 * The indirect helpers need cores loaded (chipcommon + PMU).
 * When the chip has no separate PMU core, PMU registers sit
 * in chipcommon. bwfm_chip_get_pmu() then returns chipcommon.
 */
void	bwfm_chip_init(struct bwfm_chip *, const struct bwfm_chip_ops *,
	    void *ctx);
void	bwfm_chip_free(struct bwfm_chip *);

/*
 * Add one core at the given base address.
 *
 * The SDIO transport uses this to install chipcommon (always
 * at 0x18000000 on BCM43xxx) so the chipcontrol, OTP and
 * sr_capable helpers can run before the full EROM walk.
 * The wrap address is optional (0 is fine for chipcommon).
 * Returns 0 on success. The chip layer then owns the memory.
 */
int	bwfm_chip_add_core(struct bwfm_chip *, uint16_t coreid, uint16_t rev,
	    uint32_t base, uint32_t wrap);

/*
 * Probe and cache the CC and PMU capabilities.
 *
 * Run once after chipcommon has been added and the chip is
 * in ALPAvail state. Fills chip->chip, chiprev, cc_caps,
 * cc_caps_ext, pmurev, pmu_caps.
 */
int	bwfm_chip_probe_caps(struct bwfm_chip *);

struct bwfm_chip_core *bwfm_chip_get_core(struct bwfm_chip *, uint16_t coreid);
struct bwfm_chip_core *bwfm_chip_get_pmu(struct bwfm_chip *);
struct bwfm_chip_core *bwfm_chip_get_chipcommon(struct bwfm_chip *);

/*
 * PMU indirect register access.
 *
 * Linux brcmfmac uses these to set up BCM4345 SR, drive
 * strength, and workarounds. To read chipcontrol register N:
 * write N to chipcontrol_addr, then read chipcontrol_data.
 * Writes work the same way.
 *
 * Returns 0 on success. Reads return the value via *out.
 */
int	bwfm_chip_cc_chipcontrol_read32(struct bwfm_chip *, uint32_t reg,
	    uint32_t *out);
int	bwfm_chip_cc_chipcontrol_write32(struct bwfm_chip *, uint32_t reg,
	    uint32_t val);
int	bwfm_chip_cc_regcontrol_read32(struct bwfm_chip *, uint32_t reg,
	    uint32_t *out);
int	bwfm_chip_cc_regcontrol_write32(struct bwfm_chip *, uint32_t reg,
	    uint32_t val);
int	bwfm_chip_cc_pllcontrol_read32(struct bwfm_chip *, uint32_t reg,
	    uint32_t *out);
int	bwfm_chip_cc_pllcontrol_write32(struct bwfm_chip *, uint32_t reg,
	    uint32_t val);

/* OTP. */
bool	bwfm_chip_otp_present(struct bwfm_chip *);
int	bwfm_chip_otp_read16(struct bwfm_chip *, uint32_t word_idx,
	    uint16_t *out);
int	bwfm_chip_otp_dump(struct bwfm_chip *, uint16_t *buf, uint32_t nwords);

/*
 * Save-restore (SR) probe.
 *
 * Returns true if the chip has an SR engine and it is on
 * right now. For BCM4345 (and the 4354 / 4356 / 43454
 * family) this reads PMU chipcontrol[3] and checks bit 2.
 */
bool	bwfm_chip_sr_capable(struct bwfm_chip *);

/*
 * EROM walk.
 *
 * Reads CC.EROMPTR and walks the chip's Discoverable MMIO
 * Pointers table. Calls bwfm_chip_add_core() for each
 * component with a (regbase, wrapbase) pair. When this
 * returns 0 the core list is full, and bwfm_chip_get_core()
 * can find ARM_CR4, SOCRAM, D11, etc.
 *
 * Caller must add the chipcommon core first (usually via
 * bwfm_chip_add_core in chip_ensure) so CC.EROMPTR works.
 *
 * Calling it twice appends duplicates, so a caller that might
 * run it more than once must keep its own flag.
 */
int	bwfm_chip_walk_erom(struct bwfm_chip *);

/*
 * Stop and start the ARM core.
 *
 * Port of Linux brcmf_chip_disable_arm (chip.c:1068) and
 * brcmf_chip_cr4_set_active (chip.c:1339).
 *
 * bwfm_chip_disable_arm: for CR4/CA7, runs the resetcore
 *   steps so the core comes out of reset still halted
 *   (CPUHALT set). After this returns 0, the core's TCM is
 *   writable by the host for firmware upload. For CM3 Linux
 *   only runs coredisable (core left in reset); this port
 *   runs a full resetcore instead.
 *
 * bwfm_chip_cr4_set_active: writes rstvec to chip[0] via the
 *   transport's activate hook, then resetcore with
 *   prereset=CPUHALT, reset=0, postreset=0. The CR4 comes out
 *   of reset with CPUHALT clear and starts fetching at chip[0].
 *
 * Both need the EROM walk done first so the ARM core is in
 * the list. Return 0 on success, errno on missing core or
 * backplane I/O error.
 */
int	bwfm_chip_disable_arm(struct bwfm_chip *, uint16_t coreid);
int	bwfm_chip_cr4_set_active(struct bwfm_chip *, uint32_t rstvec);

/*
 * Basic wrap-register resetcore call.
 *
 * Used inside _disable_arm and _cr4_set_active. Exposed so
 * callers can also drive non-ARM cores like D11 and SOCRAM.
 *
 *   prereset:  IOCTL bits set before reset is asserted.
 *   reset:     IOCTL bits set while reset is held.
 *   postreset: IOCTL bits OR'd with CLK after reset clears.
 *
 * Returns 0 on success.
 */
int	bwfm_chip_ai_resetcore(struct bwfm_chip *, struct bwfm_chip_core *,
	    uint32_t prereset, uint32_t reset, uint32_t postreset);
bool	bwfm_chip_ai_iscoreup(struct bwfm_chip *, struct bwfm_chip_core *);

#endif /* _DEV_BWFM_BWFM_CHIP_H_ */
