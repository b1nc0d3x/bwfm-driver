/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Bus-agnostic chip layer for Broadcom 802.11 silicon (BCM43xxx).
 *
 * Mirrors Linux brcmfmac chip.c in interface shape, in FreeBSD style
 * (no linuxkpi).  A transport (SDIO/PCIe/USB) supplies brcm_chip_ops;
 * the chip layer drives chipcommon, PMU indirect registers, OTP, and
 * the EROM walk on top of that vtable.
 *
 * Naming: types and functions use the brcm_chip_* prefix, register
 * symbol macros use BRCM_CC_* (matching brcmreg.h conventions).
 */

#ifndef _DEV_BRCM_BRCM_CHIP_H_
#define _DEV_BRCM_BRCM_CHIP_H_

#include <sys/types.h>
#include <sys/queue.h>

/*
 * ChipCommon register offsets (from CC core base).  Verified against
 * linux/drivers/net/wireless/broadcom/brcm80211/include/chipcommon.h
 * struct chipcregs layout.  Only the offsets the chip layer actually
 * touches are defined here; full set lives in brcmreg.h if needed.
 */
/* BRCM_CC_CHIPID and BRCM_CC_EROMPTR live in brcm_sdio_regs.h. */
#define	BRCM_CC_CAPABILITIES		0x004
#define	BRCM_CC_CORECONTROL		0x008
#define	BRCM_CC_OTPSTATUS		0x010
#define	BRCM_CC_OTPCONTROL		0x014
#define	BRCM_CC_OTPPROG			0x018
#define	BRCM_CC_OTPLAYOUT		0x01c
#define	BRCM_CC_CHIPSTATUS		0x02c
#define	BRCM_CC_CAPABILITIES_EXT	0x0ac

/*
 * PMU register offsets (also CC-relative for integrated PMU).
 * BRCM_CC_PMUCONTROL/CAPABILITIES/STATUS/RES_STATE/MIN_RES_MASK/MAX_RES_MASK
 * are defined in brcm_sdio_regs.h.  Only the chip-extension offsets that
 * aren't in regs.h live here.
 */
#define	BRCM_CC_PMU_CAPABILITIES_EXT	0x64c
#define	BRCM_CC_PMU_CHIPCONTROL_ADDR	0x650
#define	BRCM_CC_PMU_CHIPCONTROL_DATA	0x654
#define	BRCM_CC_PMU_REGCONTROL_ADDR	0x658
#define	BRCM_CC_PMU_REGCONTROL_DATA	0x65c
#define	BRCM_CC_PMU_PLLCONTROL_ADDR	0x660
#define	BRCM_CC_PMU_PLLCONTROL_DATA	0x664
#define	BRCM_CC_PMU_RETENTION_CTL	0x670

/* PMUCONTROL bits. */
#define	BRCM_CC_PMUCTL_RES_RELOAD	0x2u
#define	BRCM_CC_PMUCTL_RES_SHIFT	13

/* OTP region: srom/otp window at CC base + 0x800, 768 u16 words. */
#define	BRCM_CC_SROMOTP_OFFSET		0x800
#define	BRCM_CC_SROMOTP_WORDS		768

/* OTPSTATUS / OTPCONTROL bits we care about. */
#define	BRCM_OTPSTATUS_OL_PRESENT	0x00000001u	/* OTP block present */
#define	BRCM_OTPSTATUS_OL_PROGRAMMED	0x00000004u	/* HW-fuse rows valid */

/*
 * PMU capabilities — used to pick the right indirect-register layout
 * for chipcontrol / regcontrol probes.  pmurev sits in low 8 bits.
 */
#define	BRCM_PMUCAP_REV_MASK		0xffu

/*
 * Chip object — the bus-agnostic state the chip layer maintains.  A
 * transport allocates one of these (typically embedded in its softc),
 * fills in `ops` + `ctx` + identifying fields, and calls
 * brcm_chip_attach().  Public fields are filled in by the chip layer
 * during attach; transport code may read them but should not write.
 */
struct brcm_chip_core {
	TAILQ_ENTRY(brcm_chip_core)	link;
	uint16_t			id;
	uint16_t			rev;
	uint32_t			base;
	uint32_t			wrap;
};
TAILQ_HEAD(brcm_chip_corelist, brcm_chip_core);

/*
 * Transport callbacks supplied by the bus driver.
 *
 *   read32/write32:  unbuffered 32-bit access to a chip-side address
 *                    (the same address space EROM uses; bus driver
 *                    handles SBADDR window management internally).
 *   prepare:         called once at attach before the chipid read.
 *                    Bus puts the chip into ALPAvail state etc.
 *                    Returns 0 on success.
 *   activate:        write the rstvec to chip[0] (transport-specific
 *                    because some transports do this via DMA rather
 *                    than F1 word access).  Called from set_active.
 */
struct brcm_chip;
struct brcm_chip_ops {
	uint32_t	(*read32)(void *ctx, uint32_t addr);
	void		(*write32)(void *ctx, uint32_t addr, uint32_t val);
	int		(*prepare)(void *ctx);
	void		(*activate)(void *ctx, struct brcm_chip *pub,
			    uint32_t rstvec);
};

struct brcm_chip {
	/* Identity (filled in by recognition). */
	uint32_t			chip;		/* CID_ID */
	uint32_t			chiprev;	/* CID_REV */
	uint32_t			enum_base;	/* SI_ENUM_BASE */
	uint32_t			cc_caps;
	uint32_t			cc_caps_ext;
	uint32_t			pmu_caps;
	uint32_t			pmurev;
	uint32_t			ramsize;
	uint32_t			rambase;

	/* Cores discovered by EROM walk. */
	struct brcm_chip_corelist	cores;
	uint32_t			ncores;

	/* Transport hook. */
	const struct brcm_chip_ops	*ops;
	void				*ctx;
};

/*
 * Public API.  Lifecycle:
 *
 *   brcm_chip_init   -- transport-supplied chip object init, called
 *                       once before any other call.  Sets ops/ctx
 *                       and the core list head; idempotent on the
 *                       cores list.
 *   brcm_chip_free   -- release core list memory.
 *
 * Core inspection (any time after EROM has been walked):
 *   brcm_chip_get_core, brcm_chip_get_pmu, brcm_chip_get_chipcommon
 *
 * Indirect PMU register helpers:
 *   brcm_chip_cc_chipcontrol_read/write32  (PMU chipcontrol)
 *   brcm_chip_cc_regcontrol_read/write32   (PMU regcontrol)
 *   brcm_chip_cc_pllcontrol_read/write32   (PMU pllcontrol)
 *
 * OTP access (one-time-programmable):
 *   brcm_chip_otp_present  -- otpstatus says fuse block exists + programmed
 *   brcm_chip_otp_read16   -- read u16 at sromotp word index (0..767)
 *   brcm_chip_otp_dump     -- bulk-read sromotp window into caller buffer
 *
 * All indirect helpers assume cores are populated (chipcommon + PMU).
 * On a chip without an external PMU core the PMU registers live in
 * chipcommon at the offsets above; brcm_chip_get_pmu() returns the
 * chipcommon core in that case.
 */
void	brcm_chip_init(struct brcm_chip *, const struct brcm_chip_ops *,
	    void *ctx);
void	brcm_chip_free(struct brcm_chip *);

/*
 * Phase-1 helper: register a single core at the given base.  Used by
 * the SDIO transport to install chipcommon (always at 0x18000000 on
 * BCM43xxx) so chipcontrol / OTP / sr_capable helpers can run before
 * the full EROM port is in place.  Wrap address is optional (0 ok for
 * chipcommon which doesn't need its wrap touched).  Returns 0 on
 * success; the chip layer owns the allocation thereafter.
 */
int	brcm_chip_add_core(struct brcm_chip *, uint16_t coreid, uint16_t rev,
	    uint32_t base, uint32_t wrap);

/*
 * Phase-1 helper: probe + cache CC + PMU caps.  Run once after the
 * chipcommon core has been added and the chip is in ALPAvail state.
 * Fills chip->chip, chiprev, cc_caps, cc_caps_ext, pmurev, pmu_caps.
 */
int	brcm_chip_probe_caps(struct brcm_chip *);

struct brcm_chip_core *brcm_chip_get_core(struct brcm_chip *, uint16_t coreid);
struct brcm_chip_core *brcm_chip_get_pmu(struct brcm_chip *);
struct brcm_chip_core *brcm_chip_get_chipcommon(struct brcm_chip *);

/*
 * PMU indirect register access.  Linux brcmfmac drives BCM4345's SR
 * setup, drive-strength config, and a number of erratum workarounds
 * through these (chipcontrol register N: write N to chipcontrol_addr,
 * read chipcontrol_data; write follows the same shape).
 *
 * Returns 0 on success.  All reads pass the value back through *out.
 */
int	brcm_chip_cc_chipcontrol_read32(struct brcm_chip *, uint32_t reg,
	    uint32_t *out);
int	brcm_chip_cc_chipcontrol_write32(struct brcm_chip *, uint32_t reg,
	    uint32_t val);
int	brcm_chip_cc_regcontrol_read32(struct brcm_chip *, uint32_t reg,
	    uint32_t *out);
int	brcm_chip_cc_regcontrol_write32(struct brcm_chip *, uint32_t reg,
	    uint32_t val);
int	brcm_chip_cc_pllcontrol_read32(struct brcm_chip *, uint32_t reg,
	    uint32_t *out);
int	brcm_chip_cc_pllcontrol_write32(struct brcm_chip *, uint32_t reg,
	    uint32_t val);

/* OTP. */
bool	brcm_chip_otp_present(struct brcm_chip *);
int	brcm_chip_otp_read16(struct brcm_chip *, uint32_t word_idx,
	    uint16_t *out);
int	brcm_chip_otp_dump(struct brcm_chip *, uint16_t *buf, uint32_t nwords);

/*
 * Save-restore (SR) probe.  Returns true iff the chip supports the
 * SR engine and it is enabled in the current chip state.  For BCM4345
 * (and the 4354/4356/43454 family) this reads PMU chipcontrol[3] and
 * checks bit 2.
 */
bool	brcm_chip_sr_capable(struct brcm_chip *);

/*
 * EROM walk.  Reads CC.EROMPTR, walks the chip's Discoverable MMIO
 * Pointers table, and calls brcm_chip_add_core() for every component
 * with a (regbase, wrapbase) pair.  After this returns 0 the chip's
 * core list is fully populated and brcm_chip_get_core() can find
 * ARM_CR4, SOCRAM, D11, etc.
 *
 * Caller must have already added the chipcommon core (typically via
 * brcm_chip_add_core in chip_ensure) so CC.EROMPTR is reachable.
 *
 * Idempotent: a second call will append duplicates.  Caller should
 * gate via its own ready flag if it might be called more than once.
 */
int	brcm_chip_walk_erom(struct brcm_chip *);

/*
 * ARM core halt/release.  Port of Linux brcmf_chip_disable_arm
 * (chip.c:1068) and brcmf_chip_cr4_set_active (chip.c:1339).
 *
 * brcm_chip_disable_arm  — drives the resetcore trio so the ARM core
 *      (id = BCMA_CORE_ARM_CR4 or BCMA_CORE_ARM_CM3) ends up in reset
 *      with CPUHALT preserved.  After this returns 0, the core's TCM
 *      is host-writable for firmware upload.
 * brcm_chip_cr4_set_active  — write rstvec to chip[0] via the
 *      transport's activate hook, then resetcore with prereset=CPUHALT
 *      / reset=0 / postreset=0 so the CR4 comes out of reset with
 *      CPUHALT cleared and starts fetching at chip[0].
 *
 * Both functions assume the EROM walk has populated the chip's core
 * list so the ARM core can be found.  Return 0 on success, errno on
 * missing core or backplane IO error.
 */
int	brcm_chip_disable_arm(struct brcm_chip *, uint16_t coreid);
int	brcm_chip_cr4_set_active(struct brcm_chip *, uint32_t rstvec);

/*
 * Generic wrap-register resetcore primitive — the building block for
 * both _disable_arm and _cr4_set_active, exposed for callers that need
 * to drive non-ARM cores (D11, SOCRAM).
 *
 *   prereset:  IOCTL bits during pre-reset configure (before assert)
 *   reset:     IOCTL bits during in-reset configure (after assert)
 *   postreset: IOCTL bits OR'd with CLK after RESET_CTL clears
 *
 * Returns 0 on success.
 */
int	brcm_chip_ai_resetcore(struct brcm_chip *, struct brcm_chip_core *,
	    uint32_t prereset, uint32_t reset, uint32_t postreset);
bool	brcm_chip_ai_iscoreup(struct brcm_chip *, struct brcm_chip_core *);

#endif /* _DEV_BRCM_BRCM_CHIP_H_ */
