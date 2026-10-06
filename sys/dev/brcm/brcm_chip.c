/*-
 * SPDX-License-Identifier: BSD-2-Clause AND ISC
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 * Copyright (c) 2014 Broadcom Corporation
 *
 * Chip layer for Broadcom 802.11 chips. Bus-neutral.
 *
 * A port of parts of Linux brcmfmac chip.c: PMU indirect
 * register access (chipcontrol / regcontrol / pllcontrol),
 * OTP read, the EROM walk, AI core reset, and ARM halt /
 * CR4 set-active.  The rest of the SDIO set_passive /
 * set_active sequence is still in if_brcm_sdio.c.
 *
 * Portions derived from Linux brcmfmac chip.c are ISC licensed.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/queue.h>

#include "brcm_sdio_regs.h"
#include "brcm_chip.h"

static MALLOC_DEFINE(M_BRCM_CHIP, "brcm_chip", "Broadcom 802.11 chip layer");

/*
 * Small read/write helpers.
 *
 * Keeps the ctx + ops cast in one place so the rest of the
 * file reads cleanly. Each call goes through the transport's
 * backplane window. The transport handles reentrancy.
 */
static inline uint32_t
chip_r32(struct brcm_chip *chip, uint32_t addr)
{

	return (chip->ops->read32(chip->ctx, addr));
}

/* write a 32-bit chip register */
static inline void
chip_w32(struct brcm_chip *chip, uint32_t addr, uint32_t val)
{

	chip->ops->write32(chip->ctx, addr, val);
}

/* set up the chip object */
void
brcm_chip_init(struct brcm_chip *chip, const struct brcm_chip_ops *ops,
    void *ctx)
{

	bzero(chip, sizeof(*chip));
	TAILQ_INIT(&chip->cores);
	chip->ops = ops;
	chip->ctx = ctx;
}

/* free the core list */
void
brcm_chip_free(struct brcm_chip *chip)
{
	struct brcm_chip_core *core, *tmp;

	TAILQ_FOREACH_SAFE(core, &chip->cores, link, tmp) {
		TAILQ_REMOVE(&chip->cores, core, link);
		free(core, M_BRCM_CHIP);
	}
	chip->ncores = 0;
}

/* add one core to the list */
int
brcm_chip_add_core(struct brcm_chip *chip, uint16_t coreid, uint16_t rev,
    uint32_t base, uint32_t wrap)
{
	struct brcm_chip_core *core;

	core = malloc(sizeof(*core), M_BRCM_CHIP, M_NOWAIT | M_ZERO);
	if (core == NULL)
		return (ENOMEM);
	core->id = coreid;
	core->rev = rev;
	core->base = base;
	core->wrap = wrap;
	TAILQ_INSERT_TAIL(&chip->cores, core, link);
	chip->ncores++;
	return (0);
}

/*
 * Read chipid / capabilities / PMU caps from the chipcommon
 * core and save the decoded fields on the chip object.
 *
 * The chipcommon core MUST be added first (via
 * brcm_chip_add_core or the full EROM walk).
 *
 * Linux's brcmf_chip_setup does this as part of
 * brcmf_chip_attach. We split it out so callers that only
 * probe OTP or chipcontrol state before CR4 release can use
 * it without the rest of attach.
 */
#define	CID_ID_MASK		0x0000ffffu
#define	CID_REV_MASK		0x000f0000u
#define	CID_REV_SHIFT		16
#define	CC_CAP_PMU		0x10000000u
#define	BRCM_PCAP_REV_MASK	0xffu

int
brcm_chip_probe_caps(struct brcm_chip *chip)
{
	struct brcm_chip_core *cc;
	uint32_t v;

	cc = brcm_chip_get_chipcommon(chip);
	if (cc == NULL)
		return (ENXIO);

	v = chip_r32(chip, cc->base + BRCM_CC_CHIPID);
	chip->chip = v & CID_ID_MASK;
	chip->chiprev = (v & CID_REV_MASK) >> CID_REV_SHIFT;
	chip->enum_base = cc->base;

	chip->cc_caps = chip_r32(chip, cc->base + BRCM_CC_CAPABILITIES);
	chip->cc_caps_ext = chip_r32(chip, cc->base + BRCM_CC_CAPABILITIES_EXT);

	if (chip->cc_caps & CC_CAP_PMU) {
		v = chip_r32(chip, cc->base + BRCM_CC_PMUCAPABILITIES);
		chip->pmu_caps = v;
		chip->pmurev = v & BRCM_PCAP_REV_MASK;
	}
	return (0);
}

/* find a core by its id */
struct brcm_chip_core *
brcm_chip_get_core(struct brcm_chip *chip, uint16_t coreid)
{
	struct brcm_chip_core *core;

	TAILQ_FOREACH(core, &chip->cores, link) {
		if (core->id == coreid)
			return (core);
	}
	return (NULL);
}

/* get the chipcommon core */
struct brcm_chip_core *
brcm_chip_get_chipcommon(struct brcm_chip *chip)
{

	return (brcm_chip_get_core(chip, BCMA_CORE_CHIPCOMMON));
}

/*
 * On the BCM43xxx chips we care about (4329, 43430, 4345,
 * 4354, 4356, 43454, etc.) the PMU is built into chipcommon.
 * Its registers live at CC + 0x600..CC + 0x67f. A separate
 * PMU core in EROM is the exception.
 *
 * brcm_chip_get_pmu() is like brcmf_chip_get_pmu(): return
 * the chipcommon core when there is no standalone PMU core.
 * Linux also requires ccrev >= 35 and the AOB capability
 * before using the PMU core; we use it whenever the EROM
 * lists one.
 */
struct brcm_chip_core *
brcm_chip_get_pmu(struct brcm_chip *chip)
{
	struct brcm_chip_core *pmu;

	pmu = brcm_chip_get_core(chip, BCMA_CORE_PMU);
	if (pmu != NULL)
		return (pmu);
	return (brcm_chip_get_chipcommon(chip));
}

/*
 * PMU indirect access.
 *
 * Same pattern Linux uses for all three banks (chipcontrol,
 * regcontrol, pllcontrol). Each bank has its own addr/data
 * register pair:
 *
 *   1. Write the bank-index register N -> pmu_*_addr.
 *   2. Read or write pmu_*_data.
 *
 * No locking here. The bus driver serializes chip access
 * with its own lock around backplane transactions. The
 * caller must treat the indirect register pair as atomic.
 */
static int
pmu_indirect_read(struct brcm_chip *chip, uint32_t addr_reg,
    uint32_t data_reg, uint32_t reg, uint32_t *out)
{
	struct brcm_chip_core *pmu;

	pmu = brcm_chip_get_pmu(chip);
	if (pmu == NULL)
		return (ENXIO);
	chip_w32(chip, pmu->base + addr_reg, reg);
	*out = chip_r32(chip, pmu->base + data_reg);
	return (0);
}

/* write one PMU indirect register */
static int
pmu_indirect_write(struct brcm_chip *chip, uint32_t addr_reg,
    uint32_t data_reg, uint32_t reg, uint32_t val)
{
	struct brcm_chip_core *pmu;

	pmu = brcm_chip_get_pmu(chip);
	if (pmu == NULL)
		return (ENXIO);
	chip_w32(chip, pmu->base + addr_reg, reg);
	chip_w32(chip, pmu->base + data_reg, val);
	return (0);
}

/* read a PMU chipcontrol register */
int
brcm_chip_cc_chipcontrol_read32(struct brcm_chip *chip, uint32_t reg,
    uint32_t *out)
{

	return (pmu_indirect_read(chip, BRCM_CC_PMU_CHIPCONTROL_ADDR,
	    BRCM_CC_PMU_CHIPCONTROL_DATA, reg, out));
}

/* write a PMU chipcontrol register */
int
brcm_chip_cc_chipcontrol_write32(struct brcm_chip *chip, uint32_t reg,
    uint32_t val)
{

	return (pmu_indirect_write(chip, BRCM_CC_PMU_CHIPCONTROL_ADDR,
	    BRCM_CC_PMU_CHIPCONTROL_DATA, reg, val));
}

/* read a PMU regcontrol register */
int
brcm_chip_cc_regcontrol_read32(struct brcm_chip *chip, uint32_t reg,
    uint32_t *out)
{

	return (pmu_indirect_read(chip, BRCM_CC_PMU_REGCONTROL_ADDR,
	    BRCM_CC_PMU_REGCONTROL_DATA, reg, out));
}

/* write a PMU regcontrol register */
int
brcm_chip_cc_regcontrol_write32(struct brcm_chip *chip, uint32_t reg,
    uint32_t val)
{

	return (pmu_indirect_write(chip, BRCM_CC_PMU_REGCONTROL_ADDR,
	    BRCM_CC_PMU_REGCONTROL_DATA, reg, val));
}

/* read a PMU pllcontrol register */
int
brcm_chip_cc_pllcontrol_read32(struct brcm_chip *chip, uint32_t reg,
    uint32_t *out)
{

	return (pmu_indirect_read(chip, BRCM_CC_PMU_PLLCONTROL_ADDR,
	    BRCM_CC_PMU_PLLCONTROL_DATA, reg, out));
}

/* write a PMU pllcontrol register */
int
brcm_chip_cc_pllcontrol_write32(struct brcm_chip *chip, uint32_t reg,
    uint32_t val)
{

	return (pmu_indirect_write(chip, BRCM_CC_PMU_PLLCONTROL_ADDR,
	    BRCM_CC_PMU_PLLCONTROL_DATA, reg, val));
}

/*
 * SR-capable probe. Port of brcmf_chip_sr_capable, BCM4345
 * branch.
 *
 * Reads PMU chipcontrol register 3 and checks bit 2 (the
 * SR engine enable bit). Older chips (pmurev < 17) have no
 * save-restore at all, so return false.
 */
bool
brcm_chip_sr_capable(struct brcm_chip *chip)
{
	uint32_t reg;
	int err;

	if (chip->pmurev < 17)
		return (false);
	err = brcm_chip_cc_chipcontrol_read32(chip, 3, &reg);
	if (err != 0)
		return (false);
	return ((reg & (1u << 2)) != 0);
}

/*
 * EROM walk. Port of Linux brcmfmac
 * brcmf_chip_dmp_erom_scan (chip.c:905) +
 * brcmf_chip_dmp_get_regaddr (chip.c:833) +
 * brcmf_chip_dmp_get_desc (chip.c:813).
 *
 * Each chip has a Discoverable MMIO Pointers (DMP) table
 * at a chipcommon-relative address stored in CC.EROMPTR.
 * Walking it gives the (id, rev, regbase, wrapbase) tuple
 * for every IP block on the backplane.
 *
 * Unlike Linux, both the outer and inner loops are capped at
 * 256 entries, so a corrupt EROM cannot keep us issuing
 * CMD53s forever.
 *
 * As in Linux brcmf_chip_dmp_get_regaddr, the master/slave
 * wrap type is peeked at the start of each component, so a
 * master core (ARM_CR4 with its MASTER_PORT descriptor
 * first) collects MWRAP and a slave-only core collects
 * SWRAP. Getting this wrong puts CR4 on a dead SWRAP slot
 * (0x18105000) instead of the live MWRAP (0x18102000).
 */
static uint32_t
dmp_get_desc(struct brcm_chip *chip, uint32_t *eromaddr, uint8_t *type)
{
	uint32_t val;

	val = chip_r32(chip, *eromaddr);
	*eromaddr += 4;

	if (type == NULL)
		return (val);

	*type = (uint8_t)(val & DMP_DESC_TYPE_MSK);
	/*
	 * Fold the address-descriptor encodings into one type so
	 * the caller does not have to mask DMP_DESC_ADDRSIZE_GT32
	 * on every switch.
	 */
	if ((*type & ~DMP_DESC_ADDRSIZE_GT32) == DMP_DESC_ADDRESS)
		*type = DMP_DESC_ADDRESS;
	return (val);
}

/* find a core register and wrapper base */
static int
dmp_get_regaddr(struct brcm_chip *chip, uint32_t *eromaddr,
    uint32_t *regbase, uint32_t *wrapbase)
{
	uint32_t val, szdesc;
	uint8_t desc, stype, sztype, wraptype;
	int iter;

	*regbase = 0;
	*wrapbase = 0;

	val = dmp_get_desc(chip, eromaddr, &desc);
	if (desc == DMP_DESC_MASTER_PORT) {
		wraptype = DMP_SLAVE_TYPE_MWRAP;
	} else if (desc == DMP_DESC_ADDRESS) {
		*eromaddr -= 4;	/* unread; inner loop will re-consume */
		wraptype = DMP_SLAVE_TYPE_SWRAP;
	} else {
		*eromaddr -= 4;
		return (EILSEQ);
	}

	for (iter = 0; iter < 256; iter++) {
		/*
		 * Skip non-address descriptors until the next address
		 * or end-of-component.
		 */
		do {
			val = dmp_get_desc(chip, eromaddr, &desc);
			if (desc == DMP_DESC_EOT) {
				*eromaddr -= 4;
				return (EFAULT);
			}
		} while (desc != DMP_DESC_ADDRESS &&
		    desc != DMP_DESC_COMPONENT);

		if (desc == DMP_DESC_COMPONENT) {
			*eromaddr -= 4;
			return (0);
		}

		if (val & DMP_DESC_ADDRSIZE_GT32)
			(void)dmp_get_desc(chip, eromaddr, NULL);

		sztype = (uint8_t)((val & DMP_SLAVE_SIZE_TYPE) >>
		    DMP_SLAVE_SIZE_TYPE_S);

		if (sztype == DMP_SLAVE_SIZE_DESC) {
			szdesc = dmp_get_desc(chip, eromaddr, NULL);
			if (szdesc & DMP_DESC_ADDRSIZE_GT32)
				(void)dmp_get_desc(chip, eromaddr, NULL);
		}

		if (sztype != DMP_SLAVE_SIZE_4K &&
		    sztype != DMP_SLAVE_SIZE_8K)
			continue;

		stype = (uint8_t)((val & DMP_SLAVE_TYPE) >> DMP_SLAVE_TYPE_S);
		if (*regbase == 0 && stype == DMP_SLAVE_TYPE_SLAVE)
			*regbase = val & DMP_SLAVE_ADDR_BASE;
		if (*wrapbase == 0 && stype == wraptype)
			*wrapbase = val & DMP_SLAVE_ADDR_BASE;
		if (*regbase != 0 && *wrapbase != 0)
			return (0);
	}
	return (EIO);	/* inner cap hit — bad EROM */
}

/* walk the EROM and record every core */
int
brcm_chip_walk_erom(struct brcm_chip *chip)
{
	struct brcm_chip_core *cc;
	uint32_t eromaddr, val, base, wrap;
	uint8_t desc_type, nmw, nsw, rev;
	uint16_t id;
	int outer, err;

	cc = brcm_chip_get_chipcommon(chip);
	if (cc == NULL)
		return (ENXIO);

	eromaddr = chip_r32(chip, cc->base + BRCM_CC_EROMPTR);

	for (outer = 0; outer < 256; outer++) {
		val = dmp_get_desc(chip, &eromaddr, &desc_type);
		if (desc_type == DMP_DESC_EOT)
			break;
		if ((val & DMP_DESC_VALID) == 0)
			continue;
		if (desc_type == DMP_DESC_EMPTY)
			continue;
		if (desc_type != DMP_DESC_COMPONENT)
			continue;

		id = (uint16_t)((val & DMP_COMP_PARTNUM) >> DMP_COMP_PARTNUM_S);

		/* Second component word: rev and master/slave wrap counts. */
		val = dmp_get_desc(chip, &eromaddr, &desc_type);
		if (desc_type != DMP_DESC_COMPONENT)
			return (EFAULT);

		nmw = (uint8_t)((val & DMP_COMP_NUM_MWRAP) >>
		    DMP_COMP_NUM_MWRAP_S);
		nsw = (uint8_t)((val & DMP_COMP_NUM_SWRAP) >>
		    DMP_COMP_NUM_SWRAP_S);
		rev = (uint8_t)((val & DMP_COMP_REVISION) >>
		    DMP_COMP_REVISION_S);

		/*
		 * Skip cores with no wrap, except PMU and GCI, which
		 * the PMU helpers still need. Matches Linux.
		 */
		if (nmw + nsw == 0 &&
		    id != BCMA_CORE_PMU && id != BCMA_CORE_GCI)
			continue;

		err = dmp_get_regaddr(chip, &eromaddr, &base, &wrap);
		if (err != 0)
			continue;

		if (base != 0 || nmw + nsw > 0)
			(void)brcm_chip_add_core(chip, id, rev, base, wrap);
	}
	return (0);
}

/*
 * AI (Advanced Interface) wrap-register core control.
 *
 * All BCM43xxx chips we care about use AI, not the older
 * SSB. These helpers are ports of
 * brcmf_chip_ai_{iscoreup,coredisable,resetcore} in Linux
 * brcmfmac chip.c, minus Linux's handling of a second D11
 * core in resetcore.
 *
 *   iscoreup    IOCTL has CLK on and FGC off, RESET_CTL
 *               clear -> up.
 *   coredisable Assert RESET_CTL with prereset/reset IOCTL
 *               bits.
 *   resetcore   coredisable, then release with
 *               postreset | CLK.
 *
 * Linux uses usleep_range(10,20) after asserting reset,
 * SPINWAIT (udelay(10) steps) for it to read back, and
 * usleep_range(40,60) between release attempts. We use
 * DELAY(20) / DELAY(2) / DELAY(50); DELAY is a busy-wait in
 * microseconds, and we are called with the chip sx lock held,
 * so sleeping would be wrong anyway.
 */
bool
brcm_chip_ai_iscoreup(struct brcm_chip *chip, struct brcm_chip_core *core)
{
	uint32_t v;
	bool ok;

	v = chip_r32(chip, core->wrap + BCMA_IOCTL);
	ok = ((v & (BCMA_IOCTL_FGC | BCMA_IOCTL_CLK)) == BCMA_IOCTL_CLK);
	v = chip_r32(chip, core->wrap + BCMA_RESET_CTL);
	ok = ok && ((v & BCMA_RESET_CTL_RESET) == 0);
	return (ok);
}

/* put a core into reset */
static void
ai_coredisable(struct brcm_chip *chip, struct brcm_chip_core *core,
    uint32_t prereset, uint32_t reset)
{
	uint32_t v;
	int spin;

	v = chip_r32(chip, core->wrap + BCMA_RESET_CTL);
	if ((v & BCMA_RESET_CTL_RESET) != 0)
		goto in_reset_configure;

	/* pre-reset: set IOCTL with prereset bits + FGC | CLK */
	chip_w32(chip, core->wrap + BCMA_IOCTL,
	    prereset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	(void)chip_r32(chip, core->wrap + BCMA_IOCTL);

	/* assert reset */
	chip_w32(chip, core->wrap + BCMA_RESET_CTL, BCMA_RESET_CTL_RESET);
	DELAY(20);

	/* Wait for reset to read back as 1 (Linux SPINWAITs 300 us). */
	for (spin = 0; spin < 150; spin++) {
		v = chip_r32(chip, core->wrap + BCMA_RESET_CTL);
		if (v == BCMA_RESET_CTL_RESET)
			break;
		DELAY(2);
	}

in_reset_configure:
	/* in-reset configure: IOCTL = reset | FGC | CLK */
	chip_w32(chip, core->wrap + BCMA_IOCTL,
	    reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	(void)chip_r32(chip, core->wrap + BCMA_IOCTL);
}

/* reset a core and bring it back up */
int
brcm_chip_ai_resetcore(struct brcm_chip *chip, struct brcm_chip_core *core,
    uint32_t prereset, uint32_t reset, uint32_t postreset)
{
	uint32_t v;
	int count;

	ai_coredisable(chip, core, prereset, reset);

	/*
	 * Clear RESET_CTL, up to 50 tries 50 us apart, as in
	 * Linux's ai_resetcore count loop.
	 */
	for (count = 0; count < 50; count++) {
		v = chip_r32(chip, core->wrap + BCMA_RESET_CTL);
		if ((v & BCMA_RESET_CTL_RESET) == 0)
			break;
		chip_w32(chip, core->wrap + BCMA_RESET_CTL, 0);
		DELAY(50);
	}
	if ((v & BCMA_RESET_CTL_RESET) != 0)
		return (EIO);

	/* Leave clock enabled with postreset bits applied. */
	chip_w32(chip, core->wrap + BCMA_IOCTL, postreset | BCMA_IOCTL_CLK);
	(void)chip_r32(chip, core->wrap + BCMA_IOCTL);
	return (0);
}

/*
 * Halt an ARM core.
 *
 * For CR4/CA7 we OR in CPUHALT so that when the post-halt
 * resetcore release runs, the core comes out of reset
 * still halted, instead of resuming the boot ROM. Linux's
 * brcmf_chip_disable_arm dispatches by core id. We do the
 * same, except that for CM3 Linux only runs coredisable
 * while we run a full resetcore.
 */
int
brcm_chip_disable_arm(struct brcm_chip *chip, uint16_t coreid)
{
	struct brcm_chip_core *core;
	uint32_t val;

	core = brcm_chip_get_core(chip, coreid);
	if (core == NULL)
		return (ENXIO);

	switch (coreid) {
	case BCMA_CORE_ARM_CM3:
		return (brcm_chip_ai_resetcore(chip, core, 0, 0, 0));
	case BCMA_CORE_ARM_CR4:
	case BCMA_CORE_ARM_CA7:
		val = chip_r32(chip, core->wrap + BCMA_IOCTL);
		val &= ARMCR4_BCMA_IOCTL_CPUHALT;
		return (brcm_chip_ai_resetcore(chip, core, val,
		    ARMCR4_BCMA_IOCTL_CPUHALT, ARMCR4_BCMA_IOCTL_CPUHALT));
	default:
		return (EINVAL);
	}
}

/*
 * CR4 set-active.
 *
 * Write rstvec to chip[0] via the transport's activate
 * hook, then resetcore the CR4 with prereset=CPUHALT,
 * reset=0, postreset=0. The core comes out of reset with
 * CPUHALT cleared and starts fetching at chip[0]. Direct
 * port of brcmf_chip_cr4_set_active (chip.c:1339).
 */
int
brcm_chip_cr4_set_active(struct brcm_chip *chip, uint32_t rstvec)
{
	struct brcm_chip_core *cr4;

	cr4 = brcm_chip_get_core(chip, BCMA_CORE_ARM_CR4);
	if (cr4 == NULL)
		return (ENXIO);

	if (chip->ops->activate != NULL)
		chip->ops->activate(chip->ctx, chip, rstvec);

	return (brcm_chip_ai_resetcore(chip, cr4,
	    ARMCR4_BCMA_IOCTL_CPUHALT, 0, 0));
}

/*
 * OTP access.
 *
 * The sromotp window sits at CC base + 0x800 and exposes
 * 768 u16 words straight through to the chip's fuse data
 * once OTP is unlocked by chipcommon itself at power-up.
 * On BCM43xxx-class chips we do not need a special OTP
 * unlock. otpstatus reports the region as PROGRAMMED +
 * PRESENT right after CARDCAP/KSO.
 *
 * Word indexing follows chipcommon: index 0 = sromotp[0] =
 * first u16 from the lowest fuse address. Reads go through
 * the 32-bit backplane, so two u16s share one 32-bit slot.
 * sromotp[2n] is in the low half-word (bits 0..15).
 * sromotp[2n+1] is in the high half-word (bits 16..31).
 */
bool
brcm_chip_otp_present(struct brcm_chip *chip)
{
	struct brcm_chip_core *cc;
	uint32_t st;

	cc = brcm_chip_get_chipcommon(chip);
	if (cc == NULL)
		return (false);
	st = chip_r32(chip, cc->base + BRCM_CC_OTPSTATUS);
	return ((st & (BRCM_OTPSTATUS_OL_PRESENT |
	    BRCM_OTPSTATUS_OL_PROGRAMMED)) ==
	    (BRCM_OTPSTATUS_OL_PRESENT | BRCM_OTPSTATUS_OL_PROGRAMMED));
}

/* read one OTP word */
int
brcm_chip_otp_read16(struct brcm_chip *chip, uint32_t word_idx,
    uint16_t *out)
{
	struct brcm_chip_core *cc;
	uint32_t addr, w;

	if (word_idx >= BRCM_CC_SROMOTP_WORDS)
		return (EINVAL);
	cc = brcm_chip_get_chipcommon(chip);
	if (cc == NULL)
		return (ENXIO);
	addr = cc->base + BRCM_CC_SROMOTP_OFFSET + (word_idx & ~1u) * 2u;
	w = chip_r32(chip, addr);
	if ((word_idx & 1u) == 0)
		*out = (uint16_t)(w & 0xffffu);
	else
		*out = (uint16_t)((w >> 16) & 0xffffu);
	return (0);
}

/* read many OTP words at once */
int
brcm_chip_otp_dump(struct brcm_chip *chip, uint16_t *buf, uint32_t nwords)
{
	struct brcm_chip_core *cc;
	uint32_t i, w;

	if (nwords > BRCM_CC_SROMOTP_WORDS)
		nwords = BRCM_CC_SROMOTP_WORDS;
	cc = brcm_chip_get_chipcommon(chip);
	if (cc == NULL)
		return (ENXIO);
	for (i = 0; i < nwords; i += 2) {
		w = chip_r32(chip, cc->base + BRCM_CC_SROMOTP_OFFSET + i * 2u);
		buf[i] = (uint16_t)(w & 0xffffu);
		if (i + 1 < nwords)
			buf[i + 1] = (uint16_t)((w >> 16) & 0xffffu);
	}
	return (0);
}
