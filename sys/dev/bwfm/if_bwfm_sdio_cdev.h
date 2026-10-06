/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Rules for talking to /dev/bwfm0 from user programs.
 *
 * Lets user code do raw SDIO CMD52 and CMD53 calls and set
 * backplane windows. That way user tools (or a TCP bridge)
 * can drive the chip without using sysctls.
 */

#ifndef _DEV_BWFM_IF_BWFM_SDIO_CDEV_H_
#define _DEV_BWFM_IF_BWFM_SDIO_CDEV_H_

#include <sys/ioccom.h>
#include <sys/types.h>

#define BWFM_CDEV_NAME		"bwfm0"

struct bwfm_cmd52 {
	uint8_t		func;		/* 0..7 */
	uint8_t		write;		/* 0=read, 1=write */
	uint8_t		_pad[2];	/* padding */
	uint32_t	addr;		/* 17-bit register address */
	uint8_t		data;		/* in for write, out for read */
	uint8_t		_pad2[3];	/* padding */
	int32_t		mmc_err;	/* output: 0 on success */
};

struct bwfm_cmd53 {
	uint8_t		func;		/* 0..7 */
	uint8_t		write;		/* 0=read, 1=write */
	uint8_t		block_mode;	/* 0=byte, 1=block */
	uint8_t		incr;		/* 0=fixed addr, 1=auto-increment */
	uint32_t	addr;		/* 17-bit register address */
	uint32_t	len;		/* bytes to transfer */
	uint64_t	buf;		/* userland pointer (cast from void*) */
	int32_t		mmc_err;	/* output */
};

struct bwfm_bp {
	uint32_t	chip_addr;	/* chip-internal 32-bit address */
	uint32_t	value;		/* in for write, out for read */
	int32_t		mmc_err;	/* output: 0 on success */
};

struct bwfm_set_window {
	uint32_t	chip_addr;	/* programs SBADDR{LOW,MID,HIGH} */
	int32_t		mmc_err;	/* output: 0 on success */
};

struct bwfm_chipid {
	uint32_t	chipid;		/* full CC.CHIPID register */
	uint16_t	chip;		/* extracted chip ID field */
	uint8_t		rev;	/* chip revision */
	uint8_t		pkg;	/* package id */
	uint8_t		num_cores;	/* number of cores */
	uint8_t		_pad[3];	/* padding */
};

#define BWFM_IOC_CMD52		_IOWR('B', 1, struct bwfm_cmd52)
#define BWFM_IOC_CMD53		_IOWR('B', 2, struct bwfm_cmd53)
#define BWFM_IOC_SET_WINDOW	_IOWR('B', 3, struct bwfm_set_window)
#define BWFM_IOC_BP_READ32	_IOWR('B', 4, struct bwfm_bp)
#define BWFM_IOC_BP_WRITE32	_IOWR('B', 5, struct bwfm_bp)
#define BWFM_IOC_GET_CHIPID	_IOR('B', 6, struct bwfm_chipid)

/*
 * Card-init helper for the virtual MMC host bridge (Linux
 * brcmfmac driving the chip over TCP).
 *
 * FreeBSD's sdio_attach already did CMD0/CMD5/CMD7 when
 * bwfm_sdio.ko loaded. Doing them again would be risky.
 * These ioctls return the RCA/OCR the kernel remembers from
 * sdio_attach, so the guest's MMC init works without poking
 * the chip a second time.
 */
struct bwfm_card_info {
	uint32_t	ocr;		/* SDIO operating conditions */
	uint16_t	rca;		/* relative card address */
	uint8_t		nfn;		/* number of functions */
	uint8_t		_pad;	/* padding */
};

#define BWFM_IOC_CARD_INFO	_IOR('B', 7, struct bwfm_card_info)

/*
 * List the chip's cores from EROM.
 *
 * The kernel walks EROM when asked and fills core[] with up
 * to 16 entries (id, rev, base, wrap). bwfm_drive uses this
 * to find non-CR4 cores like D11 and SOCRAM. Those cores
 * must be poked for the Linux set_passive sequence.
 */
struct bwfm_core_entry {
	uint16_t	core_id;	/* core id */
	uint8_t		rev;	/* core revision */
	uint8_t		_pad;	/* padding */
	uint32_t	base;	/* core register base */
	uint32_t	wrap;	/* core wrapper base */
};

struct bwfm_cores {
	uint8_t			max;	/* in: capacity (<= 16) */
	uint8_t			count;	/* out: cores written */
	uint8_t			_pad[6];	/* padding */
	struct bwfm_core_entry	core[16];	/* list of cores, up to 16 */
	int32_t			mmc_err;	/* output */
};

#define BWFM_IOC_GET_CORES	_IOWR('B', 8, struct bwfm_cores)

#endif /* _DEV_BWFM_IF_BWFM_SDIO_CDEV_H_ */
