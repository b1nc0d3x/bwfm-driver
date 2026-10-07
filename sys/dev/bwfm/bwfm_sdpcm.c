/*-
 * SPDX-License-Identifier: ISC
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
 * SDPCM, the framing Broadcom FullMAC firmware speaks over SDIO function 2.
 * The frame structures come from NetBSD/OpenBSD if_bwfm_sdio.h (see
 * bwfm_sdpcm.h); the implementation was written for this driver.
 *
 * Every frame starts with a 4-byte hardware header (length and its
 * complement) and an 8-byte software header (sequence number, channel,
 * data offset, and the firmware's transmit credit).  Transmit builds
 * control frames for dcmds and data frames with a BDC header, numbers
 * them, and pads them to the F2 block rules.  Receive reads each frame in
 * whole 32-bit words, takes the credit from it, and sorts it by channel:
 * control replies onto a queue for the waiting dcmd, events to the event
 * callback, data to the receive callback, and superframes (glom) split
 * into their sub-frames.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/condvar.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/libkern.h>		/* memcpy/memset */
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>		/* struct sockaddr — pulled by net/if.h */

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <dev/mmc/sdio_func.h>

#include "bwfmvar.h"
#include "bwfmreg.h"
#include "bwfm_sdpcm.h"

/* Forward to the existing softc layout. */

struct bwfm_sdio_softc;

/* Framing helpers. */

/*
 * Compute the wire-padded length for a frame, following the SDPCM
 * framing rule in Linux brcmfmac sdio.c:2419: a frame longer than the
 * F2 block size that is not already a multiple of it is rounded up to
 * a whole number of blocks (block-mode CMD53); anything else is rounded
 * up to 4 bytes (byte-mode CMD53).
 *
 * The block size is per-state because Linux programs different values
 * for different chips (256 for BCM4354/4356/4359, the 512 default for
 * BCM43455; this driver uses 256 on BCM43455).  bwfm_sdpcm_alloc sets
 * a default of 64, which the caller overrides once the chip's F2 block
 * size is programmed.
 */
static __inline size_t
bwfm_sdpcm_padded_len(size_t len, uint16_t blksize)
{
	size_t blk = blksize ? (size_t)blksize : 64u;
	size_t roundto = (len > blk && (len % blk) != 0) ? blk : 4u;
	return (roundup(len, roundto));
}

/*
 * Build a CONTROL-channel frame in `buf` from `payload` of length `len`.
 * `buf` must hold at least `bwfm_sdpcm_padded_len(hdrlen + len)` bytes.
 * Returns the padded length written.
 *
 * Caller increments tx_seq under sp_lock.
 */
static size_t
bwfm_sdpcm_build_ctrl(uint8_t *buf, size_t bufsz,
    const void *payload, size_t len, uint8_t tx_seq, uint16_t blksize)
{
	struct bwfm_sdpcm_hwhdr *hwhdr;
	struct bwfm_sdpcm_swhdr *swhdr;
	size_t framelen;
	size_t padded;

	framelen = sizeof(*hwhdr) + sizeof(*swhdr) + len;
	padded = bwfm_sdpcm_padded_len(framelen, blksize);

	KASSERT(padded <= bufsz, ("bwfm_sdpcm: tx bounce too small"));

	hwhdr = (struct bwfm_sdpcm_hwhdr *)buf;
	hwhdr->frmlen = htole16((uint16_t)framelen);
	hwhdr->cksum  = htole16((uint16_t)~framelen);

	swhdr = (struct bwfm_sdpcm_swhdr *)(hwhdr + 1);
	swhdr->seqnr    = tx_seq;
	swhdr->chanflag = BWFM_SDPCM_SWHDR_CHANNEL_CONTROL;
	swhdr->nextlen  = 0;
	swhdr->dataoff  = (uint8_t)(sizeof(*hwhdr) + sizeof(*swhdr));
	swhdr->flowctl  = 0;
	swhdr->maxseqnr = 0;
	swhdr->res0     = 0;

	memcpy(swhdr + 1, payload, len);

	/* Zero-pad to wire alignment. */
	if (padded > framelen)
		memset(buf + framelen, 0, padded - framelen);

	return (padded);
}

/*
 * Validate the inbound hwhdr+swhdr.  Returns 0 on success and fills
 * the out parameters.
 *
 * The chip marks end-of-stream with frmlen=0, cksum=0 (ENOENT).  That
 * pair fails the complement check, so it is recognised first.
 *
 * Header errors return EINVAL; the caller should drop the frame and
 * resync the F2 stream.  `buflen` is the size of the bounce buffer; a
 * framelen larger than that is malformed, since rx_frames already
 * arranged for a frame-sized read.
 */
static int
bwfm_sdpcm_parse_headers(const uint8_t *buf, size_t buflen,
    uint8_t *out_chanflag, uint8_t *out_dataoff,
    uint16_t *out_framelen)
{
	const struct bwfm_sdpcm_hwhdr *hwhdr;
	const struct bwfm_sdpcm_swhdr *swhdr;
	uint16_t framelen, cksum;

	if (buflen < sizeof(*hwhdr) + sizeof(*swhdr))
		return (EINVAL);

	hwhdr = (const struct bwfm_sdpcm_hwhdr *)buf;
	framelen = le16toh(hwhdr->frmlen);
	cksum    = le16toh(hwhdr->cksum);

	/* End-of-stream: the chip publishes (0, 0). */
	if (framelen == 0 && cksum == 0)
		return (ENOENT);

	/* Cheap sanity: frmlen ^ cksum should be 0xFFFF. */
	if ((uint16_t)(framelen ^ cksum) != 0xffffu)
		return (EINVAL);

	if (framelen > buflen)
		return (EINVAL);

	swhdr = (const struct bwfm_sdpcm_swhdr *)(hwhdr + 1);
	if (swhdr->dataoff < sizeof(*hwhdr) + sizeof(*swhdr) ||
	    swhdr->dataoff > framelen)
		return (EINVAL);

	*out_chanflag  = swhdr->chanflag & BWFM_SDPCM_SWHDR_CHANNEL_MASK;
	*out_dataoff   = swhdr->dataoff;
	*out_framelen  = framelen;
	return (0);
}

/*
 * F2 transport: CMD53 directly against the F2 sdio_func device_t.
 * SDPCM frames go both ways through SDIO function 2.  The F2 device_t
 * comes from the bwfm_sdio_f2 sibling driver in if_bwfm_sdio.c and is
 * passed in by the caller.
 *
 * F2 is a fixed-address FIFO, so CMD53 must use incr=false (Linux
 * brcmfmac/bcmsdh.c:347 skips address increment for func != 1).  With
 * incr=true, FreeBSD's sdio_write_multi steps `addr` by 512 per chunk,
 * the chip treats each chunk as a separate backplane offset, and the
 * frame is lost.
 */
static int
bwfm_sdpcm_f2_xfer(device_t f2_dev, uint32_t addr,
    void *buf, size_t len, bool write)
{
	if (f2_dev == NULL)
		return (ENXIO);
	if (write)
		return (sdio_write_multi(f2_dev, addr, buf, len, false));
	return (sdio_read_multi(f2_dev, addr, buf, len, false));
}

/* Public API. */

static MALLOC_DEFINE(M_BWFM_SDPCM, "bwfm_sdpcm", "Broadcom SDPCM state");

/*
 * Allocate a fresh bwfm_sdpcm_state with mtx_init'd lock and zeroed
 * sequence counters.  Never returns NULL (M_WAITOK).  Caller is
 * responsible for calling bwfm_sdpcm_free at detach.
 *
 * f2_addr is the SDIO function-2 byte address used in CMD53 (typically
 * 0x8000 — backplane offset 0 with SBSDIO_SB_ACCESS_2_4B_FLAG).
 * f2_blksize is the F2 block size programmed in CCCR (used for the
 * padding rule); pass 0 to use the safe 64-byte default.
 */
struct bwfm_sdpcm_state *
bwfm_sdpcm_alloc(uint32_t f2_addr, uint16_t f2_blksize)
{
	struct bwfm_sdpcm_state *st;

	st = malloc(sizeof(*st), M_BWFM_SDPCM, M_WAITOK | M_ZERO);
	mtx_init(&st->sp_lock, "bwfm_sdpcm", NULL, MTX_DEF);
	st->f2_addr = f2_addr;
	st->f2_blksize = f2_blksize ? f2_blksize : 64u;
	/*
	 * Seed to 1, not 0.  reqid 0 is reserved for events: bwfm_rxctl
	 * in bwfm.c drops responses with reqid 0.  Every ++bcdc_reqid
	 * site must also skip 0 on wrap, or every 65,536th request would
	 * have its reply dropped and time out.  The USB transport seeds
	 * the same way at attach.
	 */
	st->bcdc_reqid = 1;
	st->dying = 0;
	return (st);
}

/*
 * Install (or remove with cb=NULL) the EVENT-channel callback.  The
 * only writer is attach and the only reader is rx_frames, which runs
 * single-threaded, but take sp_lock anyway so callers need not reason
 * about memory ordering.
 */
void
bwfm_sdpcm_set_event_handler(struct bwfm_sdpcm_state *st,
    bwfm_sdpcm_event_cb_t cb, void *arg)
{
	if (st == NULL)
		return;
	mtx_lock(&st->sp_lock);
	st->event_cb = cb;
	st->event_arg = arg;
	mtx_unlock(&st->sp_lock);
}

/* Install the raw-payload event callback. */
void
bwfm_sdpcm_set_event_rx(struct bwfm_sdpcm_state *st,
    bwfm_sdpcm_event_rx_cb_t cb, void *arg)
{
	if (st == NULL)
		return;
	mtx_lock(&st->sp_lock);
	st->event_rx_cb = cb;
	st->event_rx_arg = arg;
	mtx_unlock(&st->sp_lock);
}

/* Free the SDPCM state and wake any waiters. */
void
bwfm_sdpcm_free(struct bwfm_sdpcm_state *st)
{
	struct mbuf *m;

	if (st == NULL)
		return;
	mtx_lock(&st->sp_lock);
	st->dying = 1;
	wakeup(&st->ctrl_resp);
	while ((m = st->ctrl_resp) != NULL) {
		st->ctrl_resp = m->m_nextpkt;
		m_freem(m);
	}
	mtx_unlock(&st->sp_lock);
	mtx_destroy(&st->sp_lock);
	free(st, M_BWFM_SDPCM);
}

/*
 * Send a CONTROL-channel frame (BCDC iovar request).
 *
 * Wraps the `len`-byte BCDC request body in hwhdr+swhdr, pads it and
 * writes it to F2 with CMD53.
 */
int
bwfm_sdpcm_tx_ctrlframe(struct bwfm_sdpcm_state *st, device_t f2_dev,
    const void *payload, size_t len)
{
	uint8_t *bounce;
	size_t padded;
	int err;
	uint8_t tx_seq;

	if (st == NULL)
		return (ENXIO);
	if (payload == NULL || len == 0 || len > 1500)
		return (EINVAL);

	padded = bwfm_sdpcm_padded_len(sizeof(struct bwfm_sdpcm_hwhdr) +
	    sizeof(struct bwfm_sdpcm_swhdr) + len, st->f2_blksize);

	bounce = malloc(padded, M_BWFM_SDPCM, M_NOWAIT | M_ZERO);
	if (bounce == NULL)
		return (ENOMEM);

	mtx_lock(&st->sp_lock);
	tx_seq = st->tx_seq++;
	mtx_unlock(&st->sp_lock);

	(void)bwfm_sdpcm_build_ctrl(bounce, padded, payload, len, tx_seq,
	    st->f2_blksize);

	err = bwfm_sdpcm_f2_xfer(f2_dev, st->f2_addr, bounce, padded, true);

	free(bounce, M_BWFM_SDPCM);
	return (err);
}

/*
 * Send a DATA-channel frame.  Same shape as tx_ctrlframe, but on the
 * DATA channel and carrying a complete 802.3 frame from the mbuf
 * chain, which is freed on success or failure.
 *
 * There is no BCDC dcmd header; that belongs to the CONTROL channel.
 * Data frames carry the 4-byte BDC header instead (see below).
 */
int
bwfm_sdpcm_tx_dataframe(struct bwfm_sdpcm_state *st, device_t f2_dev,
    struct mbuf *m)
{
	struct bwfm_sdpcm_hwhdr *hwhdr;
	struct bwfm_sdpcm_swhdr *swhdr;
	uint8_t *bounce;
	size_t mlen, framelen, padded;
	int err;
	uint8_t tx_seq;

	if (st == NULL || m == NULL)
		return (ENXIO);
	mlen = m->m_pkthdr.len;
	if (mlen == 0 || mlen > 1514) {
		m_freem(m);
		return (EINVAL);
	}

	/*
	 * Data frames carry a 4-byte BDC header between the SDPCM headers
	 * and the 802.3 frame (Linux brcmf_proto_bcdc_hdrpush; the USB
	 * transport sends the same struct bwfm_bcdc_hdr).  Without it the
	 * firmware reads the first four bytes of the destination MAC as
	 * the header.
	 */
	framelen = sizeof(*hwhdr) + sizeof(*swhdr) +
	    sizeof(struct bwfm_bcdc_hdr) + mlen;
	padded = bwfm_sdpcm_padded_len(framelen, st->f2_blksize);

	bounce = malloc(padded, M_BWFM_SDPCM, M_NOWAIT | M_ZERO);
	if (bounce == NULL) {
		m_freem(m);
		return (ENOMEM);
	}

	mtx_lock(&st->sp_lock);
	tx_seq = st->tx_seq++;
	mtx_unlock(&st->sp_lock);

	hwhdr = (struct bwfm_sdpcm_hwhdr *)bounce;
	hwhdr->frmlen = htole16((uint16_t)framelen);
	hwhdr->cksum  = htole16((uint16_t)~framelen);

	swhdr = (struct bwfm_sdpcm_swhdr *)(hwhdr + 1);
	swhdr->seqnr    = tx_seq;
	swhdr->chanflag = BWFM_SDPCM_SWHDR_CHANNEL_DATA;
	swhdr->nextlen  = 0;
	swhdr->dataoff  = (uint8_t)(sizeof(*hwhdr) + sizeof(*swhdr));
	swhdr->flowctl  = 0;
	swhdr->maxseqnr = 0;
	swhdr->res0     = 0;

	{
		struct bwfm_bcdc_hdr *bdc = (struct bwfm_bcdc_hdr *)(swhdr + 1);
		uint8_t etb[2] = { 0, 0 };

		memset(bdc, 0, sizeof(*bdc));
		bdc->flags = BWFM_BCDC_FLAG_VER(BWFM_BCDC_FLAG_PROTO_VER);
		/*
		 * EAPOL rides priority 7, as on our PCI path.  (Linux
		 * brcmfmac has no EAPOL override; it leaves priority to
		 * cfg80211_classify8021d.)
		 */
		if (mlen >= ETHER_HDR_LEN)
			m_copydata(m, 12, 2, (caddr_t)etb);
		bdc->priority = (etb[0] == 0x88 && etb[1] == 0x8e) ? 7 : 0;
		m_copydata(m, 0, mlen, (caddr_t)(bdc + 1));
	}
	m_freem(m);

	err = bwfm_sdpcm_f2_xfer(f2_dev, st->f2_addr, bounce, padded, true);

	free(bounce, M_BWFM_SDPCM);
	return (err);
}

/*
 * Drain the F2 RX FIFO.  Reads frames one at a time until an
 * end-of-stream marker (length-zero hwhdr) and dispatches them by
 * channel: CONTROL payloads are queued on ctrl_resp for the waiting
 * dcmd, EVENT frames go to bwfm_sdpcm_dispatch_event, DATA frames to
 * the event_rx callback, and GLOM superframes are split into their
 * sub-frames.
 *
 * Each call mallocs a bounce buffer of up to 2 KB; a pre-allocated
 * per-softc buffer would suit heavy data traffic better.  sp_lock is
 * not held across the F2 read.
 */
#define BWFM_SDPCM_RX_BOUNCE_MAX	2048u

/*
 * Validate the BWFM event encapsulation (ether_header + bwfm OUI +
 * usr_subtype) at `body`, byte-swap the event_msg into host order,
 * and invoke the registered callback.  `paylen` is the SDPCM body
 * size (already trimmed past hwhdr+swhdr+dataoff).  Frames that don't
 * match the BWFM event signature are not decoded, though they have
 * already been passed to the raw event_rx callback.
 */
static void
bwfm_sdpcm_dispatch_event(struct bwfm_sdpcm_state *st,
    const uint8_t *body, size_t paylen)
{
	const size_t off_bh = sizeof(struct ether_header);
	const size_t off_msg = off_bh + sizeof(struct bwfm_bwfm_ethhdr);
	const size_t hdr_total = off_msg + sizeof(struct bwfm_event_msg);
	const struct bwfm_bcdc_hdr *bcdc;
	const struct ether_header *eh;
	const struct bwfm_bwfm_ethhdr *bh;
	struct bwfm_event_msg msg;
	size_t datalen, bcdc_skip;

	/*
	 * Hand the raw BCDC-prefixed body off first so the driver can
	 * wrap it in an mbuf and route it through bwfm_rx_frame (scan
	 * cache, link state, etc.) before the in-layer decode.
	 */
	if (st->event_rx_cb != NULL)
		st->event_rx_cb(st->event_rx_arg, body, paylen);

	/*
	 * Sub-frames on the EVENT/DATA channels carry a 4-byte BCDC
	 * data header, optionally followed by `data_offset` 32-bit
	 * words of extra metadata (FWS / flow control), then the
	 * Ethernet frame.  Peel BCDC + metadata before validating
	 * the BWFM event signature.
	 */
	if (paylen < sizeof(*bcdc))
		return;
	bcdc = (const struct bwfm_bcdc_hdr *)(uintptr_t)body;
	bcdc_skip = sizeof(*bcdc) + ((size_t)bcdc->data_offset << 2);
	if (paylen <= bcdc_skip)
		return;
	body  += bcdc_skip;
	paylen -= bcdc_skip;

	if (paylen < hdr_total)
		return;

	eh = (const struct ether_header *)(uintptr_t)body;
	bh = (const struct bwfm_bwfm_ethhdr *)(uintptr_t)(body + off_bh);

	if (ntohs(eh->ether_type) != BWFM_ETHERTYPE_BWFM)
		return;
	if (memcmp(bh->oui, "\x00\x10\x18", sizeof(bh->oui)) != 0)
		return;
	if (ntohs(bh->usr_subtype) != BWFM_BWFM_SUBTYPE_EVENT)
		return;

	memcpy(&msg, body + off_msg, sizeof(msg));
	msg.version    = ntohs(msg.version);
	msg.flags      = ntohs(msg.flags);
	msg.event_type = ntohl(msg.event_type);
	msg.status     = ntohl(msg.status);
	msg.reason     = ntohl(msg.reason);
	msg.auth_type  = ntohl(msg.auth_type);
	msg.datalen    = ntohl(msg.datalen);

	datalen = paylen - hdr_total;
	if (msg.datalen < datalen)
		datalen = msg.datalen;

	if (st->event_cb != NULL)
		st->event_cb(st->event_arg, &msg, body + hdr_total, datalen);
}

bool
bwfm_sdpcm_tx_credit(struct bwfm_sdpcm_state *st)
{
	uint8_t room;
	bool ok;

	if (st == NULL)
		return (false);
	mtx_lock(&st->sp_lock);
	room = (uint8_t)(st->max_seq - st->tx_seq);
	ok = !st->fc_off && (!st->credit_seen ||
	    (room != 0 && (room & 0x80) == 0));
	mtx_unlock(&st->sp_lock);
	return (ok);
}

/* Read and sort incoming frames from the chip. */
int
bwfm_sdpcm_rx_frames(struct bwfm_sdpcm_state *st, device_t f2_dev)
{
	uint8_t *bounce;
	struct bwfm_sdpcm_hwhdr hwhdr;
	uint8_t chanflag, dataoff;
	uint16_t framelen, fcksum;
	struct mbuf *m;
	size_t nextlen = 0;
	int err;
	int frames = 0;

	if (st == NULL)
		return (ENXIO);

	bounce = malloc(BWFM_SDPCM_RX_BOUNCE_MAX, M_BWFM_SDPCM, M_NOWAIT);
	if (bounce == NULL)
		return (ENOMEM);

	for (;;) {
		/*
		 * Read-ahead.  Each frame's swhdr carries nextlen, the
		 * padded length of the frame behind it in 16-byte units, so
		 * that whole frame comes in one CMD53 instead of a header
		 * read and a body read, as Linux brcmf_sdio_readframes and
		 * OpenBSD bwfm_sdio_rx_frames do.  A frame longer than
		 * promised gets its remainder in a second read.
		 */
		if (nextlen != 0) {
			err = bwfm_sdpcm_f2_xfer(f2_dev, st->f2_addr, bounce,
			    nextlen, false);
			if (err != 0) {
				break;
			}
			memcpy(&hwhdr, bounce, sizeof(hwhdr));
		} else {
		/*
		 * No hint: read only the hwhdr to learn the frame length,
		 * then the body.  Linux brcmf_sdio_readframes reads a
		 * 64-byte first chunk (BRCMF_FIRSTREAD) instead; peeking
		 * only the 4-byte hwhdr right-sizes the body read and
		 * spots the (0,0) end-of-stream marker at once.
		 */
		err = bwfm_sdpcm_f2_xfer(f2_dev, st->f2_addr, &hwhdr,
		    sizeof(hwhdr), false);
		if (err != 0) {
			break;
		}
		}

		framelen = le16toh(hwhdr.frmlen);
		fcksum   = le16toh(hwhdr.cksum);

		if (framelen == 0 && fcksum == 0) {
			/* Clean end-of-stream. */
			break;
		}
		if ((uint16_t)(framelen ^ fcksum) != 0xffffu ||
		    framelen < sizeof(hwhdr) + sizeof(struct bwfm_sdpcm_swhdr) ||
		    roundup2((size_t)framelen, 4) > BWFM_SDPCM_RX_BOUNCE_MAX) {
			err = EINVAL;
			break;
		}

		/*
		 * Body = framelen - 4 (hwhdr already drained), read rounded
		 * up to a whole 32-bit word.  (Linux brcmf_sdio_pad rounds
		 * to head_align, 4 or 8 on 64-bit DMA platforms, or to the
		 * block size.)  The host controller moves the FIFO in words,
		 * and the tail of a read whose length is not a multiple of 4
		 * comes back as garbage, which corrupts the end of EAPOL
		 * frames and breaks the 4-way handshake.  The firmware pads
		 * frames in the FIFO, so the extra bytes are its own.
		 */
		if (nextlen != 0) {
			/* Read-ahead fell short: fetch the rest. */
			if (roundup2((size_t)framelen, 4) > nextlen) {
				err = bwfm_sdpcm_f2_xfer(f2_dev, st->f2_addr,
				    bounce + nextlen,
				    roundup2((size_t)framelen, 4) - nextlen,
				    false);
				if (err != 0) {
					break;
				}
			}
		} else {
			memcpy(bounce, &hwhdr, sizeof(hwhdr));
			err = bwfm_sdpcm_f2_xfer(f2_dev, st->f2_addr,
			    bounce + sizeof(hwhdr),
			    roundup2((size_t)framelen - sizeof(hwhdr), 4),
			    false);
			if (err != 0) {
				break;
			}
		}
		/*
		 * The next frame's length, for the read-ahead above.  The
		 * BCM43455's control replies carry an all-0xff swhdr, and a
		 * superframe's nextlen describes its own layout; take
		 * neither, and nothing that would not fit the bounce buffer.
		 */
		{
			uint8_t nl = bounce[sizeof(hwhdr) + 2];
			uint8_t cf = bounce[sizeof(hwhdr) + 1] & 0x0f;

			nextlen = (size_t)nl << 4;
			if (nl == 0xff ||
			    cf == BWFM_SDPCM_SWHDR_CHANNEL_GLOM ||
			    nextlen < sizeof(hwhdr) +
			    sizeof(struct bwfm_sdpcm_swhdr) ||
			    nextlen > BWFM_SDPCM_RX_BOUNCE_MAX)
				nextlen = 0;
		}

		err = bwfm_sdpcm_parse_headers(bounce, framelen,
		    &chanflag, &dataoff, &framelen);
		if (err == ENOENT) {
			err = 0;
			break;
		}
		if (err != 0)
			break;

		frames++;
		st->rx_frames++;

		/*
		 * Credit: take the firmware's max sequence number from every
		 * frame, with brcmf_sdio_hdparse's sanity check.  The
		 * BCM43455 dcmd replies with an all-0xff swhdr (below) carry
		 * none.  The firmware drops data frames sent outside the
		 * window, so bwfm_sdpcm_tx_credit gates transmit on it.
		 */
		{
			const struct bwfm_sdpcm_swhdr *sw =
			    (const struct bwfm_sdpcm_swhdr *)(bounce +
			    sizeof(hwhdr));

			if (!(sw->seqnr == 0xff && sw->chanflag == 0xff)) {
				uint8_t mx = sw->maxseqnr;

				mtx_lock(&st->sp_lock);
				if ((uint8_t)(mx - st->tx_seq) > 0x40)
					mx = st->tx_seq + 2;
				st->max_seq = mx;
				st->credit_seen = true;
				mtx_unlock(&st->sp_lock);
			}
		}

		/*
		 * BCM43455 firmware often sends its replies to BCDC dcmd
		 * requests (SET_VAR, GET_VAR, BWFM_C_*) with the swhdr
		 * seq, chan and nextlen bytes all 0xff, so `chanflag & 0x0f`
		 * yields 0x0f (TEST) instead of 0x0 (CONTROL).  The frame is
		 * still a valid CONTROL response, with dataoff pointing at
		 * the BCDC dcmd header, so treat any frame whose first three
		 * swhdr bytes are 0xff as CONTROL.
		 */
		if (chanflag != BWFM_SDPCM_SWHDR_CHANNEL_CONTROL &&
		    bounce[4] == 0xff && bounce[5] == 0xff &&
		    bounce[6] == 0xff) {
			chanflag = BWFM_SDPCM_SWHDR_CHANNEL_CONTROL;
		}

		if (chanflag == BWFM_SDPCM_SWHDR_CHANNEL_CONTROL) {
			size_t paylen;

			if (dataoff >= framelen) {
				/* Empty payload — discard. */
				continue;
			}
			paylen = (size_t)framelen - (size_t)dataoff;
			m = m_getm2(NULL, paylen, M_NOWAIT, MT_DATA, M_PKTHDR);
			if (m == NULL) {
				err = ENOMEM;
				break;
			}
			m_copyback(m, 0, paylen, bounce + dataoff);
			m->m_pkthdr.len = paylen;

			mtx_lock(&st->sp_lock);
			/* Enqueue at the tail; waiter unlinks from head. */
			if (st->ctrl_resp == NULL) {
				st->ctrl_resp = m;
			} else {
				struct mbuf *tail = st->ctrl_resp;
				while (tail->m_nextpkt != NULL)
					tail = tail->m_nextpkt;
				tail->m_nextpkt = m;
			}
			wakeup(&st->ctrl_resp);
			mtx_unlock(&st->sp_lock);
		} else if (chanflag == BWFM_SDPCM_SWHDR_CHANNEL_EVENT) {
			bwfm_sdpcm_dispatch_event(st, bounce + dataoff,
			    (size_t)framelen - (size_t)dataoff);
		} else if (chanflag == BWFM_SDPCM_SWHDR_CHANNEL_GLOM) {
			/*
			 * GLOM superframe: zero or more concatenated
			 * sub-frames at [dataoff, framelen).  Each sub-
			 * frame is its own SDPCM hwhdr+swhdr+payload.
			 * We walk linearly, dispatching EVENT/CONTROL by
			 * sub-chanflag, and skipping anything else.
			 */
			size_t off = dataoff;
			while (off + sizeof(struct bwfm_sdpcm_hwhdr) +
			    sizeof(struct bwfm_sdpcm_swhdr) <= framelen) {
				uint8_t s_chan, s_doff;
				uint16_t s_flen;
				int rc;

				rc = bwfm_sdpcm_parse_headers(bounce + off,
				    framelen - off, &s_chan, &s_doff, &s_flen);
				if (rc != 0)
					break;
				/* Same 0xff fallback inside GLOM sub-frames. */
				if (s_chan != BWFM_SDPCM_SWHDR_CHANNEL_CONTROL &&
				    bounce[off + 4] == 0xff &&
				    bounce[off + 5] == 0xff &&
				    bounce[off + 6] == 0xff) {
					s_chan = BWFM_SDPCM_SWHDR_CHANNEL_CONTROL;
				}

				if (s_chan == BWFM_SDPCM_SWHDR_CHANNEL_EVENT) {
					if (s_doff < s_flen) {
						bwfm_sdpcm_dispatch_event(st,
						    bounce + off + s_doff,
						    (size_t)s_flen -
						    (size_t)s_doff);
					}
				} else if (s_chan == BWFM_SDPCM_SWHDR_CHANNEL_DATA) {
					if (st->event_rx_cb != NULL &&
					    s_doff < s_flen) {
						st->event_rx_cb(
						    st->event_rx_arg,
						    bounce + off + s_doff,
						    (size_t)s_flen -
						    (size_t)s_doff);
					}
				}
				/* Advance to next sub-frame, 4-byte aligned. */
				off += roundup2((size_t)s_flen, 4);
			}
		} else if (chanflag == BWFM_SDPCM_SWHDR_CHANNEL_DATA) {
			/*
			 * DATA channel: BCDC+ether-wrapped 802.3 frame from
			 * the chip.  Same on-wire shape as the EVENT channel
			 * (BCDC header at offset 0, ether at offset 4 +
			 * dataoff*4) — `bwfm_rx_frame` already splits on
			 * ethertype (0x886c=event, else=data) so we can
			 * route through the existing event_rx_cb path.  The
			 * transport's callback queues an mbuf onto the evrx
			 * worker, which dispatches via bwfm_rx_frame.
			 */
			if (st->event_rx_cb != NULL &&
			    dataoff < framelen) {
				st->event_rx_cb(st->event_rx_arg,
				    bounce + dataoff,
				    (size_t)framelen - (size_t)dataoff);
			}
		} else {
			/* TEST or unknown sub-channel — drop. */
		}
	}

	free(bounce, M_BWFM_SDPCM);
	if (frames > 0 && err == ENOENT)
		err = 0;
	return (err);
}

/*
 * Block until a CONTROL channel response is available, or `timeout_ms`
 * elapses.  Returns NULL on timeout.
 */
struct mbuf *
bwfm_sdpcm_wait_ctrl_resp(struct bwfm_sdpcm_state *st, int timeout_ms)
{
	struct mbuf *m;
	int rc;

	if (st == NULL)
		return (NULL);

	mtx_lock(&st->sp_lock);
	while (st->ctrl_resp == NULL) {
		if (st->dying) {
			mtx_unlock(&st->sp_lock);
			return (NULL);
		}
		rc = msleep(&st->ctrl_resp, &st->sp_lock, PZERO,
		    "bwfm_sdpcm", MSEC_2_TICKS(timeout_ms));
		if (rc == EWOULDBLOCK) {
			mtx_unlock(&st->sp_lock);
			return (NULL);
		}
		if (st->dying) {
			mtx_unlock(&st->sp_lock);
			return (NULL);
		}
	}
	m = st->ctrl_resp;
	st->ctrl_resp = m->m_nextpkt;
	m->m_nextpkt = NULL;
	mtx_unlock(&st->sp_lock);
	return (m);
}

/*
 * BCDC iovar GET_VAR request builder.
 *
 * Wire layout:
 *   +-------------------------+
 *   | bwfm_bcdc_dcmd          |  16 bytes
 *   +-------------------------+
 *   | "name\0\0\0..."         |  resp_len bytes (caller's buffer)
 *   +-------------------------+
 *
 * len in the header = max(strlen(name)+1, resp_len), so fw has space
 * to write the response value over the variable-name region.
 */
size_t
bwfm_bcdc_build_getvar(void *buf, size_t bufsz, const char *name,
    size_t resp_len, uint16_t id_tag)
{
	struct bwfm_bcdc_dcmd *h;
	size_t nlen, payload, total;
	uint32_t flags;

	if (buf == NULL || name == NULL || bufsz < sizeof(*h) + 1)
		return (0);

	nlen = strlen(name) + 1;
	payload = (nlen > resp_len) ? nlen : resp_len;
	total = sizeof(*h) + payload;
	if (total > bufsz)
		return (0);

	memset(buf, 0, total);

	h = (struct bwfm_bcdc_dcmd *)buf;
	h->cmd = htole32(BWFM_C_GET_VAR);
	h->len = htole32((uint32_t)payload);

	/* dcmd flags: just GET (0) + id_tag.  The dcmd carries no
	 * protocol version (the 4-byte BDC header with the version is
	 * used on data frames only); fw matches responses to requests
	 * via the id field. */
	flags = ((uint32_t)id_tag &
	    BWFM_BCDC_DCMD_ID_MASK) << BWFM_BCDC_DCMD_ID_SHIFT;
	h->flags = htole32(flags);
	h->status = 0;

	memcpy((uint8_t *)buf + sizeof(*h), name, nlen);
	return (total);
}

/*
 * BCDC iovar SET_VAR request builder.
 *
 * Wire layout:
 *   +-------------------------+
 *   | bwfm_bcdc_dcmd          |  16 bytes
 *   +-------------------------+
 *   | "name\0"                |  strlen(name)+1
 *   +-------------------------+
 *   | value bytes             |  vallen
 *   +-------------------------+
 *
 * dcmd->len = nlen + vallen so fw knows the total payload size.
 * dcmd->flags carries BWFM_BCDC_DCMD_SET + id_tag.
 */
size_t
bwfm_bcdc_build_setvar(void *buf, size_t bufsz, const char *name,
    const void *val, size_t vallen, uint16_t id_tag)
{
	struct bwfm_bcdc_dcmd *h;
	size_t nlen, payload, total;
	uint32_t flags;

	if (buf == NULL || name == NULL || bufsz < sizeof(*h) + 1)
		return (0);
	if (vallen > 0 && val == NULL)
		return (0);

	nlen = strlen(name) + 1;
	payload = nlen + vallen;
	total = sizeof(*h) + payload;
	if (total > bufsz)
		return (0);

	memset(buf, 0, total);

	h = (struct bwfm_bcdc_dcmd *)buf;
	h->cmd = htole32(BWFM_C_SET_VAR);
	h->len = htole32((uint32_t)payload);

	flags = BWFM_BCDC_DCMD_SET |
	    (((uint32_t)id_tag & BWFM_BCDC_DCMD_ID_MASK) <<
	     BWFM_BCDC_DCMD_ID_SHIFT);
	h->flags = htole32(flags);
	h->status = 0;

	memcpy((uint8_t *)buf + sizeof(*h), name, nlen);
	if (vallen > 0)
		memcpy((uint8_t *)buf + sizeof(*h) + nlen, val, vallen);
	return (total);
}

/*
 * BCDC raw dcmd request builder.  Used for BWFM_C_* opcodes that
 * aren't iovars — most notably BWFM_C_UP and BWFM_C_DOWN which
 * carry no payload.
 */
size_t
bwfm_bcdc_build_dcmd(void *buf, size_t bufsz, uint32_t cmd_id,
    const void *val, size_t vallen, int is_set, uint16_t id_tag)
{
	struct bwfm_bcdc_dcmd *h;
	size_t total;
	uint32_t flags;

	if (buf == NULL || bufsz < sizeof(*h))
		return (0);
	if (vallen > 0 && val == NULL)
		return (0);

	total = sizeof(*h) + vallen;
	if (total > bufsz)
		return (0);

	memset(buf, 0, total);
	h = (struct bwfm_bcdc_dcmd *)buf;
	h->cmd = htole32(cmd_id);
	h->len = htole32((uint32_t)vallen);

	flags = (((uint32_t)id_tag & BWFM_BCDC_DCMD_ID_MASK) <<
	    BWFM_BCDC_DCMD_ID_SHIFT);
	if (is_set)
		flags |= BWFM_BCDC_DCMD_SET;
	h->flags = htole32(flags);
	h->status = 0;

	if (vallen > 0)
		memcpy((uint8_t *)buf + sizeof(*h), val, vallen);
	return (total);
}
