/* $FreeBSD$ */
/* Adapted from NetBSD if_bwfm_sdio.h v1.30 — BSD/ISC licensed. */
/*
 * Copyright (c) 2010-2016 Broadcom Corporation
 * Copyright (c) 2018 Patrick Wildt <patrick@blueri.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * SDPCM (SDIO Packet Common Multiplexer) protocol layer for Broadcom
 * fullmac firmware running over SDIO.  Sits on top of the brcm_sdio
 * backplane primitives; below the brcmfmac-style iovar / BCDC layer.
 *
 * Frame layout on the wire (each direction):
 *
 *   +---------------------+  hw header
 *   | hwhdr (4 B)         |
 *   +---------------------+  optional hwext header (depending on chip)
 *   | hwexthdr (8 B)      |
 *   +---------------------+  sw header
 *   | swhdr (8 B)         |
 *   +---------------------+
 *   | pad to dataoff      |
 *   +---------------------+
 *   | channel payload     |  control / event / data / glom
 *   +---------------------+
 *
 * On TX: host adds hwhdr+swhdr, write via CMD53 to F2.
 * On RX: chip writes hwhdr+swhdr+payload to its TX FIFO; host CMD53
 *   read drains it.
 */

#ifndef _BRCM_SDPCM_H_
#define _BRCM_SDPCM_H_

#include <sys/types.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/bus.h>		/* device_t */
#include <sys/mbuf.h>
#include <sys/queue.h>

/* Protocol versions written into TOSBMAILBOXDATA. */
#define BRCM_SDPCM_PROT_VERSION			4
#define BRCM_SDPCM_PROT_VERSION_SHIFT		16
#define BRCM_SDPCM_PROT_VERSION_MASK		0x00ff0000

/* sdpcm_shared structure version (fw <-> host shared state). */
#define BRCM_SDPCM_SHARED_VERSION		0x0003
#define BRCM_SDPCM_SHARED_VERSION_MASK		0x00ff
#define BRCM_SDPCM_SHARED_ASSERT_BUILT		0x0100
#define BRCM_SDPCM_SHARED_ASSERT		0x0200
#define BRCM_SDPCM_SHARED_TRAP			0x0400

/* Hardware header (always present, prepended by the SDIO core). */
struct brcm_sdpcm_hwhdr {
	uint16_t	frmlen;	/* full frame length incl. all headers */
	uint16_t	cksum;	/* ~frmlen — frame-length sanity check */
} __packed;

/* Extended hardware header (newer chips, including BCM43455). */
struct brcm_sdpcm_hwexthdr {
	uint16_t	pktlen;
	uint8_t		res0;
	uint8_t		flags;
	uint16_t	res1;
	uint16_t	padlen;
} __packed;

/* Software header (channel multiplexing + flow control). */
struct brcm_sdpcm_swhdr {
	uint8_t		seqnr;
	uint8_t		chanflag;
#define BRCM_SDPCM_SWHDR_CHANNEL_CONTROL	0x00
#define BRCM_SDPCM_SWHDR_CHANNEL_EVENT		0x01
#define BRCM_SDPCM_SWHDR_CHANNEL_DATA		0x02
#define BRCM_SDPCM_SWHDR_CHANNEL_GLOM		0x03
#define BRCM_SDPCM_SWHDR_CHANNEL_TEST		0x0f
#define BRCM_SDPCM_SWHDR_CHANNEL_MASK		0x0f
	uint8_t		nextlen;
	uint8_t		dataoff;	/* offset to channel payload */
	uint8_t		flowctl;
	uint8_t		maxseqnr;
	uint16_t	res0;
} __packed;

/* sdpcm_shared — fw publishes pointer to one of these at chip end-1024. */
struct brcm_sdpcm_shared {
	uint32_t	flags;
	uint32_t	trap_addr;
	uint32_t	assert_exp_addr;
	uint32_t	assert_file_addr;
	uint32_t	assert_line;
	uint32_t	console_addr;
	uint32_t	msgtrace_addr;
	uint8_t		tag[32];
	uint32_t	brpt_addr;
} __packed;

/*
 * EVENT channel callback types.  See brcm_sdpcm_set_event_handler
 * comment below for the contract.  Forward-declared here so the
 * function pointers can be embedded in struct brcm_sdpcm_state.
 *
 *   event_cb     called with the fully-decoded brcm_event_msg + data
 *                payload (post-BCDC, post-ether, host byte order).
 *                Use this for in-driver event logic (dmesg trace,
 *                state machines that don't need raw bytes).
 *
 *   event_rx_cb  called with the raw BCDC-prefixed SDPCM payload
 *                exactly as the chip delivered it (BCDC header at
 *                offset 0, ether_header at offset 4 + dataoff*4,
 *                etc.).  This is the shape brcm_rx_frame expects so
 *                the driver can wrap the bytes in an mbuf and hand
 *                them to net80211 / scan cache.
 */
struct brcm_event_msg;
typedef void (*brcm_sdpcm_event_cb_t)(void *arg,
	    const struct brcm_event_msg *msg, const void *data,
	    size_t datalen);
typedef void (*brcm_sdpcm_event_rx_cb_t)(void *arg,
	    const void *body, size_t paylen);

/*
 * SDPCM software state, hung off struct brcm_sdio_softc.  Tracks TX/RX
 * sequence numbers, queues for ctrl messages awaiting fw response, and
 * mailbox state.
 */
struct brcm_sdpcm_state {
	struct mtx	sp_lock;

	/* TX seq counter: incremented per TX frame, mod 256. */
	uint8_t		tx_seq;
	/* RX seq counter: chip-published in swhdr; we track for drop detect. */
	uint8_t		rx_seq;
	/* fw-published max-seq (flow-control limit). */
	uint8_t		max_seq;

	/* BCDC iovar request-id counter; incremented per request so fw
	 * responses can be matched to requests via the ID field in the
	 * dcmd flags word. */
	uint16_t	bcdc_reqid;

	/* fw_ready: TOHOSTMAILBOXDATA bit BRCM_TOHOSTMBOX_FWREADY observed. */
	int		fw_ready;

	/* Pointer to sdpcm_shared in chip; published by fw at chip
	 * SOCRAM_END - 1024 (last word holds 32-bit chip address). */
	uint32_t	shared_addr;
	struct brcm_sdpcm_shared shared;

	/* dying: set during free to wake waiters and refuse new requests. */
	int		dying;

	/* Pending control-message response (filled by RX path). */
	struct mbuf	*ctrl_resp;

	/* SDIO function 2 byte address (caller programs the backplane
	 * window then passes us this addr).  Typically 0x8000 — i.e.
	 * SDIO offset 0 with SBSDIO_SB_ACCESS_2_4B_FLAG set. */
	uint32_t	f2_addr;

	/* Programmed F2 block size in bytes.  Used by the padding rule
	 * in brcm_sdpcm_build_ctrl.  Defaults to 64 (a safe lower bound
	 * for byte-mode CMD53). */
	uint16_t	f2_blksize;

	/* EVENT channel callbacks (NULL = drop without dispatch).  Set
	 * via brcm_sdpcm_set_event_handler / brcm_sdpcm_set_event_rx;
	 * read in rx_frames.  Either or both may be installed. */
	brcm_sdpcm_event_cb_t		event_cb;
	void				*event_arg;
	brcm_sdpcm_event_rx_cb_t	event_rx_cb;
	void				*event_rx_arg;
};

/* Mailbox bits (host side reads SDPCMD_TOHOSTMAILBOXDATA). */
#define BRCM_TOHOSTMBOX_NAKHANDLED	(1u << 0)
#define BRCM_TOHOSTMBOX_DEVREADY	(1u << 1)
#define BRCM_TOHOSTMBOX_FC		(1u << 2)
#define BRCM_TOHOSTMBOX_FWREADY		(1u << 3)
#define BRCM_TOHOSTMBOX_FWHALT		(1u << 4)

/*
 * SDPCM public API.  Takes a state pointer + F2 device_t directly so
 * brcm_sdpcm.c doesn't need to see struct brcm_sdio_softc internals.
 *
 * Caller is responsible for:
 *   - storing the returned state somewhere
 *   - calling brcm_sdpcm_free at detach (it wakes any waiters and
 *     drains ctrl_resp before destroying the lock)
 *   - programming the SDIO backplane window to the chip core whose
 *     base address gives `f2_addr` when masked + OR'd with
 *     SBSDIO_SB_ACCESS_2_4B_FLAG; passing that addr in via the
 *     `f2_addr` argument to tx/rx.
 *
 * brcm_sdpcm_alloc never returns NULL (uses M_WAITOK internally).
 */
struct brcm_sdpcm_state *brcm_sdpcm_alloc(uint32_t f2_addr,
	    uint16_t f2_blksize);
void	brcm_sdpcm_free(struct brcm_sdpcm_state *);

/* Send one control frame (typically a BCDC iovar request).  payload + len
 * are the application-layer bytes; the SDPCM layer prepends hwhdr+swhdr,
 * pads to F2 block size (or 4 bytes for small frames), and CMD53-writes
 * to F2 with no addr increment (the chip's F2 is a fixed-addr FIFO). */
int	brcm_sdpcm_tx_ctrlframe(struct brcm_sdpcm_state *,
	    device_t f2_dev, const void *payload, size_t len);

/* DATA-channel TX: chanflag=DATA, payload is the 802.3 ether frame.
 * Consumes the mbuf chain (m_freem on success or failure). */
int	brcm_sdpcm_tx_dataframe(struct brcm_sdpcm_state *,
	    device_t f2_dev, struct mbuf *m);

/* Drain the F2 RX FIFO of any pending frames.  Reads hwhdr first to
 * learn the frame length, then drains the body in one CMD53.  CONTROL
 * payloads → ctrl_resp queue; EVENT/DATA → counted but dropped (sinks
 * TBD).  Returns 0 if a full burst was drained cleanly, errno on
 * malformed frame or transport failure. */
int	brcm_sdpcm_rx_frames(struct brcm_sdpcm_state *,
	    device_t f2_dev);

/* One-shot wait for the next CONTROL channel reply.  Returns mbuf on
 * success (caller m_freem()s), NULL on timeout, NULL on free-while-
 * waiting (state->dying set). */
struct mbuf *brcm_sdpcm_wait_ctrl_resp(struct brcm_sdpcm_state *,
	    int timeout_ms);

/*
 * EVENT channel callback wiring.  Invoked from brcm_sdpcm_rx_frames
 * whenever a valid BRCM EVENT frame arrives (ether_type=0x886c, OUI
 * matches, usr_subtype=EVENT).  Fields in `msg` are host-byte-order;
 * `msg` points into a temporary buffer owned by the SDPCM layer, so
 * the callback must NOT retain it past return.  `data`/`datalen`
 * cover the event-specific payload that follows the 48-byte msg.
 *
 * Called in the context that drives brcm_sdpcm_rx_frames (typically
 * the sysctl thread for now).  Callbacks must be brief: parse, copy
 * what they need, return.  Heavy work goes to a taskqueue.
 */
void	brcm_sdpcm_set_event_handler(struct brcm_sdpcm_state *,
	    brcm_sdpcm_event_cb_t cb, void *arg);
void	brcm_sdpcm_set_event_rx(struct brcm_sdpcm_state *,
	    brcm_sdpcm_event_rx_cb_t cb, void *arg);

/*
 * BCDC layer helpers.  Wire definitions (struct brcm_bcdc_dcmd,
 * BRCM_C_*, BRCM_BCDC_FLAG_*) live in brcmreg.h and are shared with
 * any future BCDC tooling.  This header only declares the function
 * prototypes the SDPCM layer exposes.
 *
 * Build a BCDC GET_VAR request reading the named iovar.  buf must
 * hold at least sizeof(brcm_bcdc_dcmd) + max(strlen(name)+1,
 * resp_len) bytes.  Returns total bytes written (header + payload),
 * 0 on argument error.
 *
 * Caller passes resp_len = expected response size; the response from
 * fw will overwrite the variable-name region with the value.
 */
size_t	brcm_bcdc_build_getvar(void *buf, size_t bufsz,
	    const char *name, size_t resp_len, uint16_t id_tag);

/*
 * Build a BCDC SET_VAR request writing the named iovar.  buf must
 * hold at least sizeof(brcm_bcdc_dcmd) + strlen(name)+1 + vallen
 * bytes.  Returns total bytes written, 0 on argument error.
 */
size_t	brcm_bcdc_build_setvar(void *buf, size_t bufsz,
	    const char *name, const void *val, size_t vallen,
	    uint16_t id_tag);

/*
 * Build a raw BCDC dcmd request — for the BRCM_C_* opcodes that
 * aren't iovars (BRCM_C_UP, BRCM_C_DOWN, BRCM_C_DISASSOC, etc.).
 * buf must hold sizeof(brcm_bcdc_dcmd) + vallen bytes.  If is_set
 * is nonzero, the SET flag is added (most BRCM_C_* opcodes are
 * SETs that take no value; pass val=NULL vallen=0).  Returns total
 * bytes written, 0 on argument error.
 */
size_t	brcm_bcdc_build_dcmd(void *buf, size_t bufsz,
	    uint32_t cmd_id, const void *val, size_t vallen,
	    int is_set, uint16_t id_tag);

#endif /* _BRCM_SDPCM_H_ */
