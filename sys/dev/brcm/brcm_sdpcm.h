/* $FreeBSD$ */
/* Adapted from NetBSD if_bwfm_sdio.h v1.30 (BSD/ISC licensed). */
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
 * SDPCM (SDIO Packet Common Multiplexer) protocol layer for
 * Broadcom fullmac firmware over SDIO. Sits on top of the
 * brcm_sdio backplane calls. Sits under the brcmfmac-style
 * iovar / BCDC layer.
 *
 * Frame shape on the wire (each way):
 *
 *   +---------------------+  hw header
 *   | hwhdr (4 B)         |
 *   +---------------------+  optional hwext header (some chips)
 *   | hwexthdr (8 B)      |
 *   +---------------------+  sw header
 *   | swhdr (8 B)         |
 *   +---------------------+
 *   | pad to dataoff      |
 *   +---------------------+
 *   | channel payload     |  control / event / data / glom
 *   +---------------------+
 *
 * TX: host adds hwhdr+swhdr, writes via CMD53 to F2.
 * RX: chip writes hwhdr+swhdr+payload to its TX FIFO. Host CMD53
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

/* sdpcm_shared version (fw <-> host shared state). */
#define BRCM_SDPCM_SHARED_VERSION		0x0003
#define BRCM_SDPCM_SHARED_VERSION_MASK		0x00ff
#define BRCM_SDPCM_SHARED_ASSERT_BUILT		0x0100
#define BRCM_SDPCM_SHARED_ASSERT		0x0200
#define BRCM_SDPCM_SHARED_TRAP			0x0400

/* Hardware header. Always there. The SDIO core puts it on the front. */
struct brcm_sdpcm_hwhdr {
	uint16_t	frmlen;	/* full frame length, headers included */
	uint16_t	cksum;	/* ~frmlen. Simple length sanity check */
} __packed;

/* Extra hardware header (newer chips like BCM43455). */
struct brcm_sdpcm_hwexthdr {
	uint16_t	pktlen;
	uint8_t		res0;
	uint8_t		flags;
	uint16_t	res1;
	uint16_t	padlen;
} __packed;

/* Software header. Picks a channel and does flow control. */
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
	uint8_t		dataoff;	/* offset to channel data */
	uint8_t		flowctl;
	uint8_t		maxseqnr;
	uint16_t	res0;
} __packed;

/* sdpcm_shared. Fw puts a pointer to this at chip end-1024. */
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
 * EVENT channel callback types. See brcm_sdpcm_set_event_handler
 * below for the rules. Declared up here so the function pointers
 * can go inside struct brcm_sdpcm_state.
 *
 *   event_cb     called with the fully decoded brcm_event_msg and
 *                data payload (post-BCDC, post-ether, host byte
 *                order). Use for in-driver event logic (dmesg
 *                trace, state machines that do not need raw bytes).
 *
 *   event_rx_cb  called with the raw BCDC-prefixed SDPCM payload
 *                just as the chip sent it (BCDC header at offset 0,
 *                ether_header at offset 4 + dataoff*4, etc.). This
 *                is the shape brcm_rx_frame wants, so the driver
 *                can wrap the bytes in an mbuf and hand them to
 *                net80211 / scan cache.
 */
struct brcm_event_msg;
typedef void (*brcm_sdpcm_event_cb_t)(void *arg,
	    const struct brcm_event_msg *msg, const void *data,
	    size_t datalen);
typedef void (*brcm_sdpcm_event_rx_cb_t)(void *arg,
	    const void *body, size_t paylen);

/*
 * SDPCM software state. Hangs off struct brcm_sdio_softc. Tracks
 * TX/RX sequence numbers, queues for ctrl messages waiting on the
 * fw response, and mailbox state.
 */
struct brcm_sdpcm_state {
	struct mtx	sp_lock;

	/* TX seq counter. Bumped per TX frame, mod 256. */
	uint8_t		tx_seq;
	/* RX seq counter. Chip puts this in swhdr. We track it for drop detect. */
	uint8_t		rx_seq;
	/* Max-seq from fw (flow-control limit). */
	uint8_t		max_seq;

	/* BCDC iovar request-id counter. Bumped per request so fw
	 * responses can be matched to requests via the ID field in
	 * the dcmd flags word. */
	uint16_t	bcdc_reqid;

	/* fw_ready: TOHOSTMAILBOXDATA bit BRCM_TOHOSTMBOX_FWREADY seen. */
	int		fw_ready;

	/* Pointer to sdpcm_shared in chip. Fw puts it at chip
	 * SOCRAM_END - 1024 (last word holds a 32-bit chip address). */
	uint32_t	shared_addr;
	struct brcm_sdpcm_shared shared;

	/* dying: set during free to wake waiters and refuse new work. */
	int		dying;

	/* Waiting control-message response (filled by RX path). */
	struct mbuf	*ctrl_resp;

	/* SDIO function 2 byte address. The caller sets the backplane
	 * window and passes us this addr. Typically 0x8000, that is
	 * SDIO offset 0 with SBSDIO_SB_ACCESS_2_4B_FLAG set. */
	uint32_t	f2_addr;

	/* F2 block size in bytes as programmed. Used by the padding
	 * rule in brcm_sdpcm_build_ctrl. Defaults to 64 (a safe lower
	 * bound for byte-mode CMD53). */
	uint16_t	f2_blksize;

	/* EVENT channel callbacks. NULL means drop without dispatch.
	 * Set via brcm_sdpcm_set_event_handler / brcm_sdpcm_set_event_rx.
	 * Read in rx_frames. Either or both may be installed. */
	brcm_sdpcm_event_cb_t		event_cb;
	void				*event_arg;
	brcm_sdpcm_event_rx_cb_t	event_rx_cb;
	void				*event_rx_arg;
};

/* Mailbox bits. Host reads them from SDPCMD_TOHOSTMAILBOXDATA. */
#define BRCM_TOHOSTMBOX_NAKHANDLED	(1u << 0)
#define BRCM_TOHOSTMBOX_DEVREADY	(1u << 1)
#define BRCM_TOHOSTMBOX_FC		(1u << 2)
#define BRCM_TOHOSTMBOX_FWREADY		(1u << 3)
#define BRCM_TOHOSTMBOX_FWHALT		(1u << 4)

/*
 * SDPCM public API. Takes a state pointer and F2 device_t so
 * brcm_sdpcm.c does not see struct brcm_sdio_softc internals.
 *
 * The caller must:
 *   - keep the returned state somewhere
 *   - call brcm_sdpcm_free at detach (it wakes waiters and drains
 *     ctrl_resp before killing the lock)
 *   - set the SDIO backplane window to the chip core whose base
 *     address gives `f2_addr` when masked and OR'd with
 *     SBSDIO_SB_ACCESS_2_4B_FLAG. Pass that addr in via the
 *     `f2_addr` argument to tx/rx.
 *
 * brcm_sdpcm_alloc never returns NULL (uses M_WAITOK inside).
 */
struct brcm_sdpcm_state *brcm_sdpcm_alloc(uint32_t f2_addr,
	    uint16_t f2_blksize);
void	brcm_sdpcm_free(struct brcm_sdpcm_state *);

/* Send one control frame (usually a BCDC iovar request). payload
 * and len are the app-layer bytes. The SDPCM layer adds hwhdr+swhdr,
 * pads to F2 block size (or 4 bytes for small frames), and CMD53-
 * writes to F2 with no addr increment (chip F2 is a fixed-addr FIFO). */
int	brcm_sdpcm_tx_ctrlframe(struct brcm_sdpcm_state *,
	    device_t f2_dev, const void *payload, size_t len);

/* DATA-channel TX. chanflag=DATA. payload is the 802.3 ether frame.
 * Frees the mbuf chain (m_freem on success or failure). */
int	brcm_sdpcm_tx_dataframe(struct brcm_sdpcm_state *,
	    device_t f2_dev, struct mbuf *m);

/* Drain the F2 RX FIFO of any waiting frames. Reads hwhdr first
 * to learn the frame length, then drains the body in one CMD53.
 * CONTROL payloads go to the ctrl_resp queue. EVENT/DATA are
 * counted but dropped (sinks TBD). Returns 0 if a full burst
 * drained cleanly, errno on bad frame or transport failure. */
int	brcm_sdpcm_rx_frames(struct brcm_sdpcm_state *,
	    device_t f2_dev);

/* Wait once for the next CONTROL channel reply. Returns an mbuf
 * on success (caller m_freem()s). NULL on timeout. NULL on free-
 * while-waiting (state->dying set). */
struct mbuf *brcm_sdpcm_wait_ctrl_resp(struct brcm_sdpcm_state *,
	    int timeout_ms);

/*
 * Wire up an EVENT channel callback. Called from brcm_sdpcm_rx_frames
 * when a good BRCM EVENT frame arrives (ether_type=0x886c, OUI
 * matches, usr_subtype=EVENT). Fields in `msg` are host byte order.
 * `msg` points into a temp buffer owned by the SDPCM layer. The
 * callback must NOT keep it past return. `data`/`datalen` cover
 * the event-specific payload after the 48-byte msg.
 *
 * Runs in the context that drives brcm_sdpcm_rx_frames (usually
 * the sysctl thread for now). Callbacks must be short. Parse,
 * copy what you need, return. Big work goes on a taskqueue.
 */
void	brcm_sdpcm_set_event_handler(struct brcm_sdpcm_state *,
	    brcm_sdpcm_event_cb_t cb, void *arg);
void	brcm_sdpcm_set_event_rx(struct brcm_sdpcm_state *,
	    brcm_sdpcm_event_rx_cb_t cb, void *arg);

/*
 * BCDC layer helpers. Wire types (struct brcm_bcdc_dcmd,
 * BRCM_C_*, BRCM_BCDC_FLAG_*) live in brcmreg.h so any future
 * BCDC tooling can share them. This header only declares the
 * function prototypes the SDPCM layer exposes.
 *
 * Build a BCDC GET_VAR request that reads the named iovar. buf
 * must hold at least sizeof(brcm_bcdc_dcmd) + max(strlen(name)+1,
 * resp_len) bytes. Returns total bytes written (header + payload),
 * 0 on argument error.
 *
 * Caller sets resp_len = expected response size. The fw response
 * overwrites the variable-name region with the value.
 */
size_t	brcm_bcdc_build_getvar(void *buf, size_t bufsz,
	    const char *name, size_t resp_len, uint16_t id_tag);

/*
 * Build a BCDC SET_VAR request that writes the named iovar. buf
 * must hold at least sizeof(brcm_bcdc_dcmd) + strlen(name)+1 +
 * vallen bytes. Returns total bytes written, 0 on argument error.
 */
size_t	brcm_bcdc_build_setvar(void *buf, size_t bufsz,
	    const char *name, const void *val, size_t vallen,
	    uint16_t id_tag);

/*
 * Build a raw BCDC dcmd request. For the BRCM_C_* opcodes that
 * are not iovars (BRCM_C_UP, BRCM_C_DOWN, BRCM_C_DISASSOC, etc.).
 * buf must hold sizeof(brcm_bcdc_dcmd) + vallen bytes. If is_set
 * is nonzero, the SET flag is added. Most BRCM_C_* opcodes are
 * SETs that take no value. Pass val=NULL vallen=0. Returns total
 * bytes written, 0 on argument error.
 */
size_t	brcm_bcdc_build_dcmd(void *buf, size_t bufsz,
	    uint32_t cmd_id, const void *val, size_t vallen,
	    int is_set, uint16_t id_tag);

#endif /* _BRCM_SDPCM_H_ */
