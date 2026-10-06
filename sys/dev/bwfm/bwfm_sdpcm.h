/*-
 * SPDX-License-Identifier: ISC
 *
 * Adapted from NetBSD if_bwfm_sdio.h r1.3, itself from OpenBSD's.
 *
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
 * SDPCM (SDIO Packet Common Multiplexer) protocol layer
 * for Broadcom fullmac firmware over SDIO.
 *
 * Sits on top of the bwfm_sdio backplane primitives, below
 * the brcmfmac-style iovar / BCDC layer.
 *
 * Wire frame layout (each direction):
 *
 *   +---------------------+  hw header
 *   | hwhdr (4 B)         |
 *   +---------------------+  optional hwext header (chip-dependent)
 *   | hwexthdr (8 B)      |
 *   +---------------------+  sw header
 *   | swhdr (8 B)         |
 *   +---------------------+
 *   | pad to dataoff      |
 *   +---------------------+
 *   | channel payload     |  control / event / data / glom
 *   +---------------------+
 *
 * TX: host adds hwhdr+swhdr and writes via CMD53 to F2.
 * RX: chip writes hwhdr+swhdr+payload to its TX FIFO. The
 * host drains it with CMD53 reads.
 */

#ifndef _BWFM_SDPCM_H_
#define _BWFM_SDPCM_H_

#include <sys/types.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/bus.h>		/* device_t */
#include <sys/mbuf.h>
#include <sys/queue.h>

/* Protocol versions written into TOSBMAILBOXDATA. */
#define BWFM_SDPCM_PROT_VERSION			4
#define BWFM_SDPCM_PROT_VERSION_SHIFT		16
#define BWFM_SDPCM_PROT_VERSION_MASK		0x00ff0000

/* sdpcm_shared structure version (fw <-> host shared state). */
#define BWFM_SDPCM_SHARED_VERSION		0x0003
#define BWFM_SDPCM_SHARED_VERSION_MASK		0x00ff
#define BWFM_SDPCM_SHARED_ASSERT_BUILT		0x0100
#define BWFM_SDPCM_SHARED_ASSERT		0x0200
#define BWFM_SDPCM_SHARED_TRAP			0x0400

/* Hardware header. Always present. Added by the SDIO core. */
struct bwfm_sdpcm_hwhdr {
	uint16_t	frmlen;	/* full frame length, all headers included */
	uint16_t	cksum;	/* ~frmlen — sanity check on frame length */
} __packed;

/* Extra hardware header on newer chips (like BCM43455). */
struct bwfm_sdpcm_hwexthdr {
	uint16_t	pktlen;	/* payload length */
	uint8_t		res0;	/* reserved */
	uint8_t		flags;	/* header flags */
	uint16_t	res1;	/* reserved */
	uint16_t	padlen;	/* padding length */
} __packed;

/* Software header. Handles channel mux + flow control. */
struct bwfm_sdpcm_swhdr {
	uint8_t		seqnr;	/* frame sequence number */
	uint8_t		chanflag;	/* channel type in low bits */
#define BWFM_SDPCM_SWHDR_CHANNEL_CONTROL	0x00
#define BWFM_SDPCM_SWHDR_CHANNEL_EVENT		0x01
#define BWFM_SDPCM_SWHDR_CHANNEL_DATA		0x02
#define BWFM_SDPCM_SWHDR_CHANNEL_GLOM		0x03
#define BWFM_SDPCM_SWHDR_CHANNEL_TEST		0x0f
#define BWFM_SDPCM_SWHDR_CHANNEL_MASK		0x0f
	uint8_t		nextlen;	/* hint: size of next frame */
	uint8_t		dataoff;	/* offset to the channel payload */
	uint8_t		flowctl;	/* flow-control flags */
	uint8_t		maxseqnr;	/* highest seq the chip will accept */
	uint16_t	res0;	/* reserved */
} __packed;

/* sdpcm_shared. The last word of RAM holds a pointer to one of these. */
struct bwfm_sdpcm_shared {
	uint32_t	flags;	/* status/trap flags */
	uint32_t	trap_addr;	/* chip address of trap record */
	uint32_t	assert_exp_addr;	/* chip address of assert expression */
	uint32_t	assert_file_addr;	/* chip address of assert file name */
	uint32_t	assert_line;	/* assert line number */
	uint32_t	console_addr;	/* chip address of console buffer */
	uint32_t	msgtrace_addr;	/* chip address of message trace */
	uint8_t		tag[32];	/* firmware build tag */
	uint32_t	brpt_addr;	/* chip address of breakpoint table */
} __packed;

/*
 * EVENT channel callback types, declared here so the function
 * pointers can sit in struct bwfm_sdpcm_state.  See
 * bwfm_sdpcm_set_event_handler below for the contract.
 *
 * event_cb gets the decoded bwfm_event_msg and its data, with the
 * BCDC and Ethernet headers stripped and fields in host byte order,
 * for in-driver event logic that doesn't need the raw bytes.
 *
 * event_rx_cb gets the raw BCDC-prefixed SDPCM payload exactly as
 * the chip sent it (BCDC header at offset 0, ether_header at
 * 4 + dataoff*4).  That is the shape bwfm_rx_frame expects, so the
 * driver can wrap the bytes in an mbuf and hand them on.
 */
struct bwfm_event_msg;
typedef void (*bwfm_sdpcm_event_cb_t)(void *arg,
	    const struct bwfm_event_msg *msg, const void *data,
	    size_t datalen);
typedef void (*bwfm_sdpcm_event_rx_cb_t)(void *arg,
	    const void *body, size_t paylen);

/*
 * SDPCM software state. Hangs off struct bwfm_sdio_softc.
 *
 * Tracks TX/RX sequence numbers, queues for ctrl messages
 * waiting on a fw response, and mailbox state.
 */
struct bwfm_sdpcm_state {
	struct mtx	sp_lock;	/* protects this state */

	/* TX seq counter. Bumped per TX frame, mod 256. */
	uint8_t		tx_seq;
	/* RX seq counter, from the chip's swhdr; detects drops. */
	uint8_t		rx_seq;
	/*
	 * Transmit credit: the firmware accepts frames whose sequence
	 * number is before max_seq, which it publishes in the swhdr of every
	 * frame it sends (maxseqnr).  credit_seen is false until the first
	 * one arrives; fc_off is the firmware's flow-control "stop" from
	 * the host mailbox.  See bwfm_sdpcm_tx_credit().
	 */
	uint8_t		max_seq;
	bool		credit_seen;
	bool		fc_off;
	/* Statistics, exported as dev.bwfm.N.sdio_stats. */
	uint32_t	max_seq_updates;	/* credit values taken from rx */
	uint32_t	data_tx;		/* data frames sent */
	uint32_t	window_violations;	/* data frames sent past max_seq */

	/*
	 * BCDC request-id counter, bumped per request so firmware
	 * replies can be matched by the ID field in the dcmd flags.
	 */
	uint16_t	bcdc_reqid;

	/* BWFM_TOHOSTMBOX_FWREADY seen in TOHOSTMAILBOXDATA. */
	int		fw_ready;

	/*
	 * Chip address of sdpcm_shared, which the firmware publishes
	 * in the last word of RAM (ram_base + ramsize - 4).
	 */
	uint32_t	shared_addr;
	struct bwfm_sdpcm_shared shared;	/* local copy of the shared block */

	/* Set during free to wake waiters and refuse new requests. */
	int		dying;

	/* Pending control-message response (filled by RX path). */
	struct mbuf	*ctrl_resp;

	/*
	 * SDIO function 2 byte address, used after the caller has
	 * programmed the backplane window.  Usually 0x8000: offset 0
	 * with SBSDIO_SB_ACCESS_2_4B_FLAG set.
	 */
	uint32_t	f2_addr;

	/*
	 * Programmed F2 block size in bytes, for the padding rule.
	 * Defaults to 64, a safe lower bound for byte-mode CMD53.
	 */
	uint16_t	f2_blksize;

	/*
	 * EVENT channel callbacks, set via bwfm_sdpcm_set_event_handler
	 * and bwfm_sdpcm_set_event_rx and read in rx_frames.  Either or
	 * both may be installed; NULL means the frame is not dispatched.
	 */
	bwfm_sdpcm_event_cb_t		event_cb;
	void				*event_arg;
	bwfm_sdpcm_event_rx_cb_t	event_rx_cb;
	void				*event_rx_arg;
};

/*
 * SDIO device-core mailbox registers and bits (Linux brcmfmac sdio.h
 * struct sdpcmd_regs; I_HMB_* and SMB_* in sdio.c).  The firmware
 * raises I_HMB_HOST_INT with a reason in TOHOSTMAILBOXDATA; the host
 * answers SMB_INT_ACK in TOSBMAILBOX.  I_HMB_FC_CHANGE says the
 * flow-control state changed, and I_HMB_FC_STATE is that state (set:
 * stop sending data).
 */
#define	BWFM_SD_REG_TOSBMAILBOX		0x040
#define	BWFM_SD_REG_TOHOSTMAILBOX	0x044
#define	BWFM_SD_REG_TOSBMAILBOXDATA	0x048
#define	BWFM_SD_REG_TOHOSTMAILBOXDATA	0x04c
#define	BWFM_I_HMB_FC_STATE		(1u << 4)
#define	BWFM_I_HMB_FC_CHANGE		(1u << 5)
#define	BWFM_I_HMB_FRAME_IND		(1u << 6)
#define	BWFM_I_HMB_HOST_INT		(1u << 7)
#define	BWFM_SMB_NAK			(1u << 0)
#define	BWFM_SMB_INT_ACK		(1u << 1)

/* Mailbox bits (host side reads SDPCMD_TOHOSTMAILBOXDATA). */
#define BWFM_TOHOSTMBOX_NAKHANDLED	(1u << 0)
#define BWFM_TOHOSTMBOX_DEVREADY	(1u << 1)
#define BWFM_TOHOSTMBOX_FC		(1u << 2)
#define BWFM_TOHOSTMBOX_FWREADY		(1u << 3)
#define BWFM_TOHOSTMBOX_FWHALT		(1u << 4)

/*
 * SDPCM public API.
 *
 * Takes a state pointer plus an F2 device_t directly so
 * bwfm_sdpcm.c does not need to see struct bwfm_sdio_softc
 * internals.
 *
 * The caller stores the returned state and calls bwfm_sdpcm_free
 * at detach, which wakes waiters and drains ctrl_resp before
 * destroying the lock.  It also programs the SDIO backplane window
 * to the chip core whose base address, masked and OR'd with
 * SBSDIO_SB_ACCESS_2_4B_FLAG, gives `f2_addr`, and passes that
 * address in as `f2_addr`.
 *
 * bwfm_sdpcm_alloc never returns NULL (uses M_WAITOK).
 */
struct bwfm_sdpcm_state *bwfm_sdpcm_alloc(uint32_t f2_addr,
	    uint16_t f2_blksize);
void	bwfm_sdpcm_free(struct bwfm_sdpcm_state *);

/*
 * Send one control frame (usually a BCDC iovar request).  The SDPCM
 * layer adds hwhdr+swhdr, pads to the F2 block size (or 4 bytes for
 * small frames) and writes it with CMD53 without address increment,
 * since the chip's F2 is a fixed-address FIFO.
 */
int	bwfm_sdpcm_tx_ctrlframe(struct bwfm_sdpcm_state *,
	    device_t f2_dev, const void *payload, size_t len);

/*
 * Send an 802.3 frame on the DATA channel.  Always consumes the mbuf
 * chain, on success and failure.
 */
int	bwfm_sdpcm_tx_dataframe(struct bwfm_sdpcm_state *,
	    device_t f2_dev, struct mbuf *m);

/*
 * Drain any pending frames from the F2 RX FIFO.  Reads the hwhdr
 * first to learn the frame length, then the body in one CMD53.
 * CONTROL payloads go on the ctrl_resp queue; EVENT and DATA frames
 * go to the event callbacks.  Returns 0 if the burst was drained
 * cleanly, or an errno on a bad frame or transport failure.
 */
int	bwfm_sdpcm_rx_frames(struct bwfm_sdpcm_state *,
	    device_t f2_dev);

/*
 * True if the firmware will take another frame now: inside its credit
 * window and not flow-controlled.  Linux brcmfmac's data_ok().  Before
 * the first credit arrives, assume yes.
 */
bool	bwfm_sdpcm_tx_credit(struct bwfm_sdpcm_state *st);

/*
 * Wait for the next CONTROL channel reply.  Returns an mbuf the
 * caller frees, or NULL on timeout or if bwfm_sdpcm_free was called
 * while waiting.
 */
struct mbuf *bwfm_sdpcm_wait_ctrl_resp(struct bwfm_sdpcm_state *,
	    int timeout_ms);

/*
 * EVENT channel callback wiring.
 *
 * Called from bwfm_sdpcm_rx_frames whenever a valid BWFM
 * EVENT frame arrives (ether_type=0x886c, OUI matches,
 * usr_subtype=EVENT). Fields in `msg` are host byte order.
 * `msg` points into a temporary buffer owned by the SDPCM
 * layer, so the callback must NOT keep it past return.
 * `data`/`datalen` cover the event-specific payload after
 * the 48-byte msg.
 *
 * Called in whatever context drives bwfm_sdpcm_rx_frames.
 * Callbacks must be quick: parse, copy what they need and
 * return, leaving heavy work to a taskqueue.
 */
void	bwfm_sdpcm_set_event_handler(struct bwfm_sdpcm_state *,
	    bwfm_sdpcm_event_cb_t cb, void *arg);
void	bwfm_sdpcm_set_event_rx(struct bwfm_sdpcm_state *,
	    bwfm_sdpcm_event_rx_cb_t cb, void *arg);

/*
 * BCDC layer helpers.
 *
 * The wire definitions (struct bwfm_bcdc_dcmd, BWFM_C_*,
 * BWFM_BCDC_FLAG_*) live in bwfmreg.h; this header only
 * declares the builders the SDPCM layer exposes.
 *
 * Build a BCDC GET_VAR request reading the named iovar.
 * buf must hold at least sizeof(bwfm_bcdc_dcmd) +
 * max(strlen(name)+1, resp_len) bytes. Returns total bytes
 * written (header + payload), or 0 on argument error.
 *
 * Pass resp_len = expected response size. The response from
 * fw overwrites the variable-name area with the value.
 */
size_t	bwfm_bcdc_build_getvar(void *buf, size_t bufsz,
	    const char *name, size_t resp_len, uint16_t id_tag);

/*
 * Build a BCDC SET_VAR request writing the named iovar.
 *
 * buf must hold at least sizeof(bwfm_bcdc_dcmd) +
 * strlen(name)+1 + vallen bytes. Returns total bytes
 * written, or 0 on argument error.
 */
size_t	bwfm_bcdc_build_setvar(void *buf, size_t bufsz,
	    const char *name, const void *val, size_t vallen,
	    uint16_t id_tag);

/*
 * Build a raw BCDC dcmd request.
 *
 * For BWFM_C_* opcodes that aren't iovars (BWFM_C_UP,
 * BWFM_C_DOWN, BWFM_C_DISASSOC, etc.). buf must hold
 * sizeof(bwfm_bcdc_dcmd) + vallen bytes. If is_set is
 * non-zero, the SET flag is added (most BWFM_C_* opcodes
 * are SETs that take no value; pass val=NULL vallen=0).
 * Returns total bytes written, or 0 on argument error.
 */
size_t	bwfm_bcdc_build_dcmd(void *buf, size_t bufsz,
	    uint32_t cmd_id, const void *val, size_t vallen,
	    int is_set, uint16_t id_tag);

#endif /* _BWFM_SDPCM_H_ */
