/* $FreeBSD$ */
/* Adapted from NetBSD if_bwfm_sdio.c v1.30 — BSD/ISC licensed. */
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
 * SDPCM (SDIO Packet Common Multiplexer) frame TX/RX for Broadcom
 * fullmac firmware.  Sits between the iovar/BCDC layer above and the
 * raw SDIO CMD53 transport below.
 *
 * State of this port :
 *
 *  - Framing: hwhdr+swhdr construct/parse, padding, seqnr.  DONE.
 *  - F2 transport: STUB (brcm_sdpcm_f2_xfer).  Wire to a CMD53 helper
 *    that uses sdio_cmd53_byte with fn=2 once the F2 sibling device_t
 *    plumbing is decided.  See TODO in brcm_sdpcm_f2_xfer.
 *  - Control-response queue: minimal mbuf chain; locks via sp_lock.
 *  - Event channel and data channel: NOT YET IMPLEMENTED.  rx_frames
 *    parses the swhdr->chanflag but only the CONTROL channel is hooked
 *    to a useful sink; EVENT and DATA frames are logged and dropped.
 *
 * Next port chunks (in order of value):
 *   1. Wire brcm_sdpcm_f2_xfer to the F2 sibling sdio_func device_t.
 *      Smoke-test by sending a hardcoded `cur_etheraddr` BCDC iovar
 *      and watching for a response in CONTROL.
 *   2. Implement EVENT channel dispatch (forward to net80211 once we
 *      have a net80211 binding).
 *   3. Implement DATA channel (mbuf in → BCDC unwrap → net80211 input).
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

#include "brcmvar.h"
#include "brcmreg.h"
#include "brcm_sdpcm.h"

/* Forward to the existing softc layout. */
struct brcm_sdio_softc;

/*
 * Framing helpers
 * ---------------
 */

/*
 * Compute the wire-padded length for a frame.  SDPCM framing rules
 * (Linux brcmfmac sdio.c:2419):
 *   - if frame > programmed F2 blksize and not already a multiple,
 *     round up to a blksize multiple (block-mode CMD53 chunking)
 *   - else round up to 4 bytes (byte-mode CMD53)
 *
 * blksize is per-state because Linux programs different values for
 * different chips (BCM43455 uses 256, BCM4356 uses 512).  Default 64
 * is set in brcm_sdpcm_alloc but should be overridden by the caller
 * after the chip-specific F2 block size is programmed.
 */
static __inline size_t
brcm_sdpcm_padded_len(size_t len, uint16_t blksize)
{
	size_t blk = blksize ? (size_t)blksize : 64u;
	size_t roundto = (len > blk && (len % blk) != 0) ? blk : 4u;
	return (roundup(len, roundto));
}

/*
 * Build a CONTROL-channel frame in `buf` from `payload` of length `len`.
 * `buf` must hold at least `brcm_sdpcm_padded_len(hdrlen + len)` bytes.
 * Returns the padded length written.
 *
 * Caller increments tx_seq under sp_lock.
 */
static size_t
brcm_sdpcm_build_ctrl(uint8_t *buf, size_t bufsz,
    const void *payload, size_t len, uint8_t tx_seq, uint16_t blksize)
{
	struct brcm_sdpcm_hwhdr *hwhdr;
	struct brcm_sdpcm_swhdr *swhdr;
	size_t framelen;
	size_t padded;

	framelen = sizeof(*hwhdr) + sizeof(*swhdr) + len;
	padded = brcm_sdpcm_padded_len(framelen, blksize);

	KASSERT(padded <= bufsz, ("brcm_sdpcm: tx bounce too small"));

	hwhdr = (struct brcm_sdpcm_hwhdr *)buf;
	hwhdr->frmlen = htole16((uint16_t)framelen);
	hwhdr->cksum  = htole16((uint16_t)~framelen);

	swhdr = (struct brcm_sdpcm_swhdr *)(hwhdr + 1);
	swhdr->seqnr    = tx_seq;
	swhdr->chanflag = BRCM_SDPCM_SWHDR_CHANNEL_CONTROL;
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
 * End-of-stream:
 *   - Linux/NetBSD chips publish (frmlen=0, cksum=0).  Recognised
 *     FIRST (before the XOR check) because that pair fails XOR
 *     validation (would be EINVAL otherwise).
 *
 * Header errors return EINVAL; caller should drop + resync the F2
 * stream.  `buflen` is the size of the bounce buffer; we treat a
 * framelen > buflen as malformed since rx_frames already arranged
 * for a frame-sized read.
 */
static int
brcm_sdpcm_parse_headers(const uint8_t *buf, size_t buflen,
    uint8_t *out_chanflag, uint8_t *out_dataoff,
    uint16_t *out_framelen)
{
	const struct brcm_sdpcm_hwhdr *hwhdr;
	const struct brcm_sdpcm_swhdr *swhdr;
	uint16_t framelen, cksum;

	if (buflen < sizeof(*hwhdr) + sizeof(*swhdr))
		return (EINVAL);

	hwhdr = (const struct brcm_sdpcm_hwhdr *)buf;
	framelen = le16toh(hwhdr->frmlen);
	cksum    = le16toh(hwhdr->cksum);

	/* End-of-stream: real chips publish (0, 0). */
	if (framelen == 0 && cksum == 0)
		return (ENOENT);

	/* Cheap sanity: frmlen ^ cksum should be 0xFFFF. */
	if ((uint16_t)(framelen ^ cksum) != 0xffffu)
		return (EINVAL);

	if (framelen > buflen)
		return (EINVAL);

	swhdr = (const struct brcm_sdpcm_swhdr *)(hwhdr + 1);
	if (swhdr->dataoff < sizeof(*hwhdr) + sizeof(*swhdr) ||
	    swhdr->dataoff > framelen)
		return (EINVAL);

	*out_chanflag  = swhdr->chanflag & BRCM_SDPCM_SWHDR_CHANNEL_MASK;
	*out_dataoff   = swhdr->dataoff;
	*out_framelen  = framelen;
	return (0);
}

/*
 * F2 transport — direct CMD53 against the F2 sdio_func device_t.
 * Both TX and RX of SDPCM frames go through SDIO function 2.  The F2
 * device_t is plumbed by the brcm_sdio_f2 sibling driver in
 * if_brcm_sdio.c and passed in by the caller.
 *
 * F2 is a fixed-address FIFO; CMD53 must use incr=false (Linux
 * brcmfmac/bcmsdh.c:347 explicitly skips addr-increment for
 * func != 1).  Passing incr=true makes the FreeBSD sdio_write_multi
 * step `addr` by 512 per chunk, which the chip-side router
 * interprets as separate backplane offsets and the frame is lost.
 */
static int
brcm_sdpcm_f2_xfer(device_t f2_dev, uint32_t addr,
    void *buf, size_t len, bool write)
{
	if (f2_dev == NULL)
		return (ENXIO);
	if (write)
		return (sdio_write_multi(f2_dev, addr, buf, len, false));
	return (sdio_read_multi(f2_dev, addr, buf, len, false));
}

/*
 * Public API
 * ----------
 */

static MALLOC_DEFINE(M_BRCM_SDPCM, "brcm_sdpcm", "Broadcom SDPCM state");

/*
 * Allocate a fresh brcm_sdpcm_state with mtx_init'd lock and zeroed
 * sequence counters.  Never returns NULL (M_WAITOK).  Caller is
 * responsible for calling brcm_sdpcm_free at detach.
 *
 * f2_addr is the SDIO function-2 byte address used in CMD53 (typically
 * 0x8000 — backplane offset 0 with SBSDIO_SB_ACCESS_2_4B_FLAG).
 * f2_blksize is the F2 block size programmed in CCCR (used for the
 * padding rule); pass 0 to use the safe 64-byte default.
 */
struct brcm_sdpcm_state *
brcm_sdpcm_alloc(uint32_t f2_addr, uint16_t f2_blksize)
{
	struct brcm_sdpcm_state *st;

	st = malloc(sizeof(*st), M_BRCM_SDPCM, M_WAITOK | M_ZERO);
	mtx_init(&st->sp_lock, "brcm_sdpcm", NULL, MTX_DEF);
	st->f2_addr = f2_addr;
	st->f2_blksize = f2_blksize ? f2_blksize : 64u;
	st->bcdc_reqid = 0;
	st->dying = 0;
	return (st);
}

/*
 * Install (or remove with cb=NULL) the EVENT-channel callback.  Lock
 * not strictly necessary today because the only writer is attach-time
 * and the only reader is rx_frames which runs single-threaded, but
 * take sp_lock anyway so future callers don't have to think about
 * memory ordering.
 */
void
brcm_sdpcm_set_event_handler(struct brcm_sdpcm_state *st,
    brcm_sdpcm_event_cb_t cb, void *arg)
{
	if (st == NULL)
		return;
	mtx_lock(&st->sp_lock);
	st->event_cb = cb;
	st->event_arg = arg;
	mtx_unlock(&st->sp_lock);
}

void
brcm_sdpcm_set_event_rx(struct brcm_sdpcm_state *st,
    brcm_sdpcm_event_rx_cb_t cb, void *arg)
{
	if (st == NULL)
		return;
	mtx_lock(&st->sp_lock);
	st->event_rx_cb = cb;
	st->event_rx_arg = arg;
	mtx_unlock(&st->sp_lock);
}

void
brcm_sdpcm_free(struct brcm_sdpcm_state *st)
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
	free(st, M_BRCM_SDPCM);
}

/*
 * Send a CONTROL-channel frame (BCDC iovar request).
 *
 * Wraps payload+len in hwhdr+swhdr, pads, CMD53-writes to F2.  Caller
 * supplies a kernel-space buffer of `len` bytes containing the BCDC
 * request body.
 */
int
brcm_sdpcm_tx_ctrlframe(struct brcm_sdpcm_state *st, device_t f2_dev,
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

	padded = brcm_sdpcm_padded_len(sizeof(struct brcm_sdpcm_hwhdr) +
	    sizeof(struct brcm_sdpcm_swhdr) + len, st->f2_blksize);

	bounce = malloc(padded, M_BRCM_SDPCM, M_NOWAIT | M_ZERO);
	if (bounce == NULL)
		return (ENOMEM);

	mtx_lock(&st->sp_lock);
	tx_seq = st->tx_seq++;
	mtx_unlock(&st->sp_lock);

	(void)brcm_sdpcm_build_ctrl(bounce, padded, payload, len, tx_seq,
	    st->f2_blksize);

	err = brcm_sdpcm_f2_xfer(f2_dev, st->f2_addr, bounce, padded, true);

	free(bounce, M_BRCM_SDPCM);
	return (err);
}

/*
 * Send a DATA-channel frame.  Same shape as tx_ctrlframe but
 * chanflag=DATA and `payload` is a complete 802.3 ether frame
 * (dst + src + ethertype + body).  Caller passes the mbuf chain;
 * we m_freem on success or failure.
 *
 * BCDC dcmd header is NOT prepended -- that's CONTROL-channel
 * specific.  Linux brcmfmac wraps DATA frames in only the SDPCM
 * hwhdr+swhdr + the 802.3 frame; chip's DATA path strips swhdr
 * and forwards the bytes over the air.
 */
int
brcm_sdpcm_tx_dataframe(struct brcm_sdpcm_state *st, device_t f2_dev,
    struct mbuf *m)
{
	struct brcm_sdpcm_hwhdr *hwhdr;
	struct brcm_sdpcm_swhdr *swhdr;
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

	framelen = sizeof(*hwhdr) + sizeof(*swhdr) + mlen;
	padded = brcm_sdpcm_padded_len(framelen, st->f2_blksize);

	bounce = malloc(padded, M_BRCM_SDPCM, M_NOWAIT | M_ZERO);
	if (bounce == NULL) {
		m_freem(m);
		return (ENOMEM);
	}

	mtx_lock(&st->sp_lock);
	tx_seq = st->tx_seq++;
	mtx_unlock(&st->sp_lock);

	hwhdr = (struct brcm_sdpcm_hwhdr *)bounce;
	hwhdr->frmlen = htole16((uint16_t)framelen);
	hwhdr->cksum  = htole16((uint16_t)~framelen);

	swhdr = (struct brcm_sdpcm_swhdr *)(hwhdr + 1);
	swhdr->seqnr    = tx_seq;
	swhdr->chanflag = BRCM_SDPCM_SWHDR_CHANNEL_DATA;
	swhdr->nextlen  = 0;
	swhdr->dataoff  = (uint8_t)(sizeof(*hwhdr) + sizeof(*swhdr));
	swhdr->flowctl  = 0;
	swhdr->maxseqnr = 0;
	swhdr->res0     = 0;

	m_copydata(m, 0, mlen, (caddr_t)(swhdr + 1));
	m_freem(m);

	err = brcm_sdpcm_f2_xfer(f2_dev, st->f2_addr, bounce, padded, true);

	free(bounce, M_BRCM_SDPCM);
	return (err);
}

/*
 * Drain the F2 RX FIFO.  Reads frames one at a time until we get an
 * end-of-stream marker (length-zero hwhdr).  Dispatches by channel:
 *   - CONTROL → enqueue payload mbuf on ctrl_resp, wake waiter.
 *   - EVENT   → TODO forward to event handler (currently logged + dropped).
 *   - DATA    → TODO forward to net80211 input (currently logged + dropped).
 *
 * Memory: each call mallocs a fresh bounce up to 2 KB.  This is fine
 * for a control-message round-trip but data-path traffic will need a
 * pre-allocated per-sc buffer.  Don't hold sp_lock across the F2 read.
 */
#define BRCM_SDPCM_RX_BOUNCE_MAX	2048u

/*
 * Validate the BRCM event encapsulation (ether_header + brcm OUI +
 * usr_subtype) at `body`, byte-swap the event_msg into host order,
 * and invoke the registered callback.  `paylen` is the SDPCM body
 * size (already trimmed past hwhdr+swhdr+dataoff).  Silently drops
 * frames that don't match the BRCM EVENT signature — including
 * data-plane RX frames that share the EVENT channel until net80211
 * is wired in.
 */
static void
brcm_sdpcm_dispatch_event(struct brcm_sdpcm_state *st,
    const uint8_t *body, size_t paylen)
{
	const size_t off_bh = sizeof(struct ether_header);
	const size_t off_msg = off_bh + sizeof(struct brcm_brcm_ethhdr);
	const size_t hdr_total = off_msg + sizeof(struct brcm_event_msg);
	const struct brcm_bcdc_hdr *bcdc;
	const struct ether_header *eh;
	const struct brcm_brcm_ethhdr *bh;
	struct brcm_event_msg msg;
	size_t datalen, bcdc_skip;

	/*
	 * Hand the raw BCDC-prefixed body off first so the driver can
	 * wrap it in an mbuf and route through brcm_rx_frame (scan
	 * cache, link state, etc.) before we do the in-layer decode.
	 */
	if (st->event_rx_cb != NULL)
		st->event_rx_cb(st->event_rx_arg, body, paylen);

	/*
	 * Sub-frames on the EVENT/DATA channels carry a 4-byte BCDC
	 * data header, optionally followed by `data_offset` 32-bit
	 * words of extra metadata (FWS / flow control), then the
	 * Ethernet frame.  Peel BCDC + metadata before validating
	 * the BRCM event signature.
	 */
	if (paylen < sizeof(*bcdc))
		return;
	bcdc = (const struct brcm_bcdc_hdr *)(uintptr_t)body;
	bcdc_skip = sizeof(*bcdc) + ((size_t)bcdc->data_offset << 2);
	if (paylen <= bcdc_skip)
		return;
	body  += bcdc_skip;
	paylen -= bcdc_skip;

	if (paylen < hdr_total)
		return;

	eh = (const struct ether_header *)(uintptr_t)body;
	bh = (const struct brcm_brcm_ethhdr *)(uintptr_t)(body + off_bh);

	if (ntohs(eh->ether_type) != BRCM_ETHERTYPE_BRCM)
		return;
	if (memcmp(bh->oui, "\x00\x10\x18", sizeof(bh->oui)) != 0)
		return;
	if (ntohs(bh->usr_subtype) != BRCM_BRCM_SUBTYPE_EVENT)
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

int
brcm_sdpcm_rx_frames(struct brcm_sdpcm_state *st, device_t f2_dev)
{
	uint8_t *bounce;
	struct brcm_sdpcm_hwhdr hwhdr;
	uint8_t chanflag, dataoff;
	uint16_t framelen, fcksum;
	struct mbuf *m;
	int err;
	int frames = 0;

	if (st == NULL)
		return (ENXIO);

	bounce = malloc(BRCM_SDPCM_RX_BOUNCE_MAX, M_BRCM_SDPCM, M_NOWAIT);
	if (bounce == NULL)
		return (ENOMEM);

	for (;;) {
		/*
		 * Read hwhdr only — learn frame length, then drain body.
		 * Linux brcmfmac does the same (sdio.c brcmf_sdio_readframes):
		 * peeking the 4-byte hwhdr lets us right-size the body read
		 * and immediately recognise (0,0) end-of-stream.
		 */
		err = brcm_sdpcm_f2_xfer(f2_dev, st->f2_addr, &hwhdr,
		    sizeof(hwhdr), false);
		if (err != 0)
			break;

		framelen = le16toh(hwhdr.frmlen);
		fcksum   = le16toh(hwhdr.cksum);

		if (framelen == 0 && fcksum == 0) {
			/* Clean end-of-stream. */
			break;
		}
		if ((uint16_t)(framelen ^ fcksum) != 0xffffu ||
		    framelen < sizeof(hwhdr) + sizeof(struct brcm_sdpcm_swhdr) ||
		    framelen > BRCM_SDPCM_RX_BOUNCE_MAX) {
			err = EINVAL;
			break;
		}

		/* Body = framelen - 4 (hwhdr already drained). */
		memcpy(bounce, &hwhdr, sizeof(hwhdr));
		err = brcm_sdpcm_f2_xfer(f2_dev, st->f2_addr,
		    bounce + sizeof(hwhdr),
		    (size_t)framelen - sizeof(hwhdr), false);
		if (err != 0)
			break;

		err = brcm_sdpcm_parse_headers(bounce, framelen,
		    &chanflag, &dataoff, &framelen);
		if (err == ENOENT) {
			err = 0;
			break;
		}
		if (err != 0)
			break;

		frames++;

		/*
		 * BCM43455 quirk: fw replies to BCDC dcmd requests
		 * (SET_VAR, GET_VAR, BRCM_C_*) often arrive with the
		 * swhdr seq+chan+nextlen bytes filled with 0xff — so the
		 * standard `chanflag & 0x0f` extraction yields 0x0f
		 * (TEST channel) instead of 0x0 (CONTROL).  The frame is
		 * still a valid CONTROL response: dataoff points at the
		 * BCDC dcmd header.  Treat any frame whose first three
		 * swhdr bytes are 0xff as CONTROL.
		 */
		if (chanflag != BRCM_SDPCM_SWHDR_CHANNEL_CONTROL &&
		    bounce[4] == 0xff && bounce[5] == 0xff &&
		    bounce[6] == 0xff) {
			chanflag = BRCM_SDPCM_SWHDR_CHANNEL_CONTROL;
		}

		if (chanflag == BRCM_SDPCM_SWHDR_CHANNEL_CONTROL) {
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
		} else if (chanflag == BRCM_SDPCM_SWHDR_CHANNEL_EVENT) {
			brcm_sdpcm_dispatch_event(st, bounce + dataoff,
			    (size_t)framelen - (size_t)dataoff);
		} else if (chanflag == BRCM_SDPCM_SWHDR_CHANNEL_GLOM) {
			/*
			 * GLOM superframe: zero or more concatenated
			 * sub-frames at [dataoff, framelen).  Each sub-
			 * frame is its own SDPCM hwhdr+swhdr+payload.
			 * We walk linearly, dispatching EVENT/CONTROL by
			 * sub-chanflag, and skipping anything else.
			 */
			size_t off = dataoff;
			while (off + sizeof(struct brcm_sdpcm_hwhdr) +
			    sizeof(struct brcm_sdpcm_swhdr) <= framelen) {
				uint8_t s_chan, s_doff;
				uint16_t s_flen;
				int rc;

				rc = brcm_sdpcm_parse_headers(bounce + off,
				    framelen - off, &s_chan, &s_doff, &s_flen);
				if (rc != 0)
					break;
				/* Same 0xff fallback inside GLOM sub-frames. */
				if (s_chan != BRCM_SDPCM_SWHDR_CHANNEL_CONTROL &&
				    bounce[off + 4] == 0xff &&
				    bounce[off + 5] == 0xff &&
				    bounce[off + 6] == 0xff) {
					s_chan = BRCM_SDPCM_SWHDR_CHANNEL_CONTROL;
				}

				if (s_chan == BRCM_SDPCM_SWHDR_CHANNEL_EVENT) {
					if (s_doff < s_flen) {
						brcm_sdpcm_dispatch_event(st,
						    bounce + off + s_doff,
						    (size_t)s_flen -
						    (size_t)s_doff);
					}
				} else if (s_chan == BRCM_SDPCM_SWHDR_CHANNEL_DATA) {
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
		} else if (chanflag == BRCM_SDPCM_SWHDR_CHANNEL_DATA) {
			/*
			 * DATA channel: BCDC+ether-wrapped 802.3 frame from
			 * the chip.  Same on-wire shape as the EVENT channel
			 * (BCDC header at offset 0, ether at offset 4 +
			 * dataoff*4) — `brcm_rx_frame` already splits on
			 * ethertype (0x886c=event, else=data) so we can
			 * route through the existing event_rx_cb path.  The
			 * transport's callback queues an mbuf onto the evrx
			 * worker, which dispatches via brcm_rx_frame.
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

	free(bounce, M_BRCM_SDPCM);
	if (frames > 0 && err == ENOENT)
		err = 0;
	return (err);
}

/*
 * Block until a CONTROL channel response is available, or `timeout_ms`
 * elapses.  Returns NULL on timeout.
 */
struct mbuf *
brcm_sdpcm_wait_ctrl_resp(struct brcm_sdpcm_state *st, int timeout_ms)
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
		    "brcm_sdpcm", MSEC_2_TICKS(timeout_ms));
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
 *   | brcm_bcdc_dcmd          |  16 bytes
 *   +-------------------------+
 *   | "name\0\0\0..."         |  resp_len bytes (caller's buffer)
 *   +-------------------------+
 *
 * len in the header = max(strlen(name)+1, resp_len), so fw has space
 * to write the response value over the variable-name region.
 */
size_t
brcm_bcdc_build_getvar(void *buf, size_t bufsz, const char *name,
    size_t resp_len, uint16_t id_tag)
{
	struct brcm_bcdc_dcmd *h;
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

	h = (struct brcm_bcdc_dcmd *)buf;
	h->cmd = htole32(BRCM_C_GET_VAR);
	h->len = htole32((uint32_t)payload);

	/* dcmd flags: just GET (0) + id_tag.  BCDC version goes in the
	 * separate proto header (not built here); fw matches responses to
	 * requests via the id field. */
	flags = ((uint32_t)id_tag &
	    BRCM_BCDC_DCMD_ID_MASK) << BRCM_BCDC_DCMD_ID_SHIFT;
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
 *   | brcm_bcdc_dcmd          |  16 bytes
 *   +-------------------------+
 *   | "name\0"                |  strlen(name)+1
 *   +-------------------------+
 *   | value bytes             |  vallen
 *   +-------------------------+
 *
 * dcmd->len = nlen + vallen so fw knows the total payload size.
 * dcmd->flags carries BRCM_BCDC_DCMD_SET + id_tag.
 */
size_t
brcm_bcdc_build_setvar(void *buf, size_t bufsz, const char *name,
    const void *val, size_t vallen, uint16_t id_tag)
{
	struct brcm_bcdc_dcmd *h;
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

	h = (struct brcm_bcdc_dcmd *)buf;
	h->cmd = htole32(BRCM_C_SET_VAR);
	h->len = htole32((uint32_t)payload);

	flags = BRCM_BCDC_DCMD_SET |
	    (((uint32_t)id_tag & BRCM_BCDC_DCMD_ID_MASK) <<
	     BRCM_BCDC_DCMD_ID_SHIFT);
	h->flags = htole32(flags);
	h->status = 0;

	memcpy((uint8_t *)buf + sizeof(*h), name, nlen);
	if (vallen > 0)
		memcpy((uint8_t *)buf + sizeof(*h) + nlen, val, vallen);
	return (total);
}

/*
 * BCDC raw dcmd request builder.  Used for BRCM_C_* opcodes that
 * aren't iovars — most notably BRCM_C_UP and BRCM_C_DOWN which
 * carry no payload.
 */
size_t
brcm_bcdc_build_dcmd(void *buf, size_t bufsz, uint32_t cmd_id,
    const void *val, size_t vallen, int is_set, uint16_t id_tag)
{
	struct brcm_bcdc_dcmd *h;
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
	h = (struct brcm_bcdc_dcmd *)buf;
	h->cmd = htole32(cmd_id);
	h->len = htole32((uint32_t)vallen);

	flags = (((uint32_t)id_tag & BRCM_BCDC_DCMD_ID_MASK) <<
	    BRCM_BCDC_DCMD_ID_SHIFT);
	if (is_set)
		flags |= BRCM_BCDC_DCMD_SET;
	h->flags = htole32(flags);
	h->status = 0;

	if (vallen > 0)
		memcpy((uint8_t *)buf + sizeof(*h), val, vallen);
	return (total);
}
