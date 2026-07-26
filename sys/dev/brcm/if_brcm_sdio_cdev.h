/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Userland-facing protocol for /dev/brcm0.  Exposes raw SDIO
 * CMD52/CMD53 + backplane-window operations so userspace (and a TCP
 * bridge) can drive brcm_sdio's chip without going through sysctls.
 */

#ifndef _DEV_BRCM_IF_BRCM_SDIO_CDEV_H_
#define _DEV_BRCM_IF_BRCM_SDIO_CDEV_H_

#include <sys/ioccom.h>
#include <sys/types.h>

#define BRCM_CDEV_NAME		"brcm0"

struct brcm_cmd52 {
	uint8_t		func;		/* 0..7 */
	uint8_t		write;		/* 0=read, 1=write */
	uint8_t		_pad[2];
	uint32_t	addr;		/* 17-bit register address */
	uint8_t		data;		/* in for write, out for read */
	uint8_t		_pad2[3];
	int32_t		mmc_err;	/* output: 0 on success */
};

struct brcm_cmd53 {
	uint8_t		func;		/* 0..7 */
	uint8_t		write;		/* 0=read, 1=write */
	uint8_t		block_mode;	/* 0=byte, 1=block */
	uint8_t		incr;		/* 0=fixed addr, 1=auto-increment */
	uint32_t	addr;		/* 17-bit register address */
	uint32_t	len;		/* bytes to transfer */
	uint64_t	buf;		/* userland pointer (cast from void*) */
	int32_t		mmc_err;	/* output */
};

struct brcm_bp {
	uint32_t	chip_addr;	/* chip-internal 32-bit address */
	uint32_t	value;		/* in for write, out for read */
	int32_t		mmc_err;
};

struct brcm_set_window {
	uint32_t	chip_addr;	/* programs SBADDR{LOW,MID,HIGH} */
	int32_t		mmc_err;
};

struct brcm_chipid {
	uint32_t	chipid;		/* full CC.CHIPID register */
	uint16_t	chip;		/* extracted chip ID field */
	uint8_t		rev;
	uint8_t		pkg;
	uint8_t		num_cores;
	uint8_t		_pad[3];
};

#define BRCM_IOC_CMD52		_IOWR('B', 1, struct brcm_cmd52)
#define BRCM_IOC_CMD53		_IOWR('B', 2, struct brcm_cmd53)
#define BRCM_IOC_SET_WINDOW	_IOWR('B', 3, struct brcm_set_window)
#define BRCM_IOC_BP_READ32	_IOWR('B', 4, struct brcm_bp)
#define BRCM_IOC_BP_WRITE32	_IOWR('B', 5, struct brcm_bp)
#define BRCM_IOC_GET_CHIPID	_IOR('B', 6, struct brcm_chipid)

/*
 * Card-init shim for the virtual MMC host bridge (Linux brcmfmac
 * driving the chip via TCP).  The chip is already CMD0/CMD5/CMD7'd by
 * FreeBSD's sdio_attach when brcm_sdio.ko loaded, so re-issuing those
 * to the chip is risky.  The kernel responds to these ioctls with the
 * cached RCA/OCR it remembers from sdio_attach, so the guest's
 * mmc-core init dance succeeds without re-touching the chip.
 */
struct brcm_card_info {
	uint32_t	ocr;		/* SDIO operating conditions */
	uint16_t	rca;		/* relative card address */
	uint8_t		nfn;		/* number of functions */
	uint8_t		_pad;
};

#define BRCM_IOC_CARD_INFO	_IOR('B', 7, struct brcm_card_info)

/*
 * EROM core enumeration.  Kernel runs the EROM walker on demand and
 * fills core[] with up to 16 (id, rev, base, wrap) triplets.
 * brcm_drive uses this to locate non-CR4 cores (D11, SOCRAM) it must
 * touch for the Linux-equivalent set_passive sequence.
 */
struct brcm_core_entry {
	uint16_t	core_id;
	uint8_t		rev;
	uint8_t		_pad;
	uint32_t	base;
	uint32_t	wrap;
};

struct brcm_cores {
	uint8_t			max;	/* in: capacity (<= 16) */
	uint8_t			count;	/* out: cores written */
	uint8_t			_pad[6];
	struct brcm_core_entry	core[16];
	int32_t			mmc_err;
};

#define BRCM_IOC_GET_CORES	_IOWR('B', 8, struct brcm_cores)

#endif /* _DEV_BRCM_IF_BRCM_SDIO_CDEV_H_ */
