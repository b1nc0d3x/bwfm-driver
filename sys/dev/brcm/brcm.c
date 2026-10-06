/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC (brcm) bus-agnostic core.
 *
 * This module is the layer above the transport (USB, SDIO, PCIe).  It
 * owns the chip-info dispatch table, the BCDC dcmd / iovar request
 * machinery, and the net80211 attachment (ieee80211_ifattach,
 * vap_create, scans, joins and key install).  Bus transports call into here
 * via brcm_attach() and the bus_ops vtable; we call back through
 * sc->sc_bus_ops to push BCDC frames out to the chip.
 *
 * Design reference: OpenBSD sys/dev/ic/bwfm.c.  No source lines are
 * carried over; the protocol-level structure mirrors Patrick Wildt's
 * 2016-2017 work but the FreeBSD-native shape (taskqueue(9),
 * mtx + sx locks, ieee80211vap clone tracking, firmware(9) loader,
 * malloc(9) M_BRCM region) is original.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/firmware.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>	/* priv_check(td, PRIV_DRIVER) */
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_input.h>
#include <net80211/ieee80211_scan.h>

#include "brcmvar.h"
#include "brcmreg.h"
#include "ieee80211_fullmac.h"

MALLOC_DEFINE(M_BRCM, "brcm", "Broadcom FullMAC scratch");

/*
 * Cached chanspec from the last ESCAN_RESULT for a given BSSID --
 * lets the join path send the chip's preferred wire-format
 * chanspec (40MHz / VHT etc.) rather than our minimal 20MHz
 * recomputation that misses the AP's actual bandwidth.  One entry per
 * device: chanspecs are in the firmware's own encoding (D11N or
 * D11AC), so one chip's value is wrong for another.  A BCM43236 (D11N)
 * handed a BCM43455's D11AC chanspec for the same AP fails the join
 * with BCME_BADCHAN.
 */
static void
brcm_cache_bssid_chanspec(struct brcm_softc *sc, const uint8_t bssid[6],
    uint16_t chanspec)
{
	memcpy(sc->sc_join_cs_bssid, bssid, 6);
	sc->sc_join_cs = chanspec;
}

/* recall the saved channel for an AP, or 0 if none */
static uint16_t
brcm_lookup_bssid_chanspec(struct brcm_softc *sc, const uint8_t bssid[6])
{
	if (memcmp(sc->sc_join_cs_bssid, bssid, 6) == 0)
		return (sc->sc_join_cs);
	return (0);
}

/*
 * Acquire sc_join_busy with stale-timeout recovery.  If a prior join
 * dispatch wedged (chip silently never emitted LINK/SET_SSID/DISASSOC),
 * sc_join_busy stays set forever and blocks every subsequent attempt.
 *
 * Caller pattern: `if (brcm_join_busy_acquire(sc, "open")) return EAGAIN;`
 * Returns 0 on success (busy now claimed) or 1 if another join is
 * legitimately in flight (less than BRCM_JOIN_BUSY_TIMEOUT_S old).
 *
 * 15 s is our own choice.  Linux brcmfmac has no driver-side join timeout
 * (cfg80211's SME owns it); its BRCMF_VIF_EVENT_TIMEOUT is 1.5 s and only
 * covers virtual-interface add/delete events.
 */
#define	BRCM_JOIN_BUSY_TIMEOUT_S	15

static int
brcm_join_busy_acquire(struct brcm_softc *sc, const char *who)
{
	time_t now = time_uptime;

	if (sc->sc_join_busy != 0) {
		if (sc->sc_join_busy_ts != 0 &&
		    now - sc->sc_join_busy_ts >= BRCM_JOIN_BUSY_TIMEOUT_S) {
			DPRINTF(sc, 0,
			    "%s: stale join_busy after %llds -- force-reset\n",
			    who,
			    (long long)(now - sc->sc_join_busy_ts));
			/* fall through, claim */
		} else {
			return (1);	/* in-flight, retry later */
		}
	}
	sc->sc_join_busy = 1;
	sc->sc_join_busy_ts = now;
	return (0);
}

/*
 * Chip dispatch table.  Lookup is keyed on (chip silicon ID, chiprev)
 * returned by DL_GETVER.  fwname is the firmware(9) name (no .bin
 * suffix; firmware(9) handles resolution).  Adding a row makes a new
 * chip recognized across all transports.
 */
const struct brcm_chip_info brcm_chip_table[] = {
	{ 0xa887, 0,  0xff, "brcmfmac43143",  "BCM43143",        true  },
	{ 0xa8e4, 3,  0xff, "brcmfmac43236b", "BCM43236 rev B",  true  },
	{ 0xa8ea, 0,  0xff, "brcmfmac43242a", "BCM43242",        true  },
	{ 0xaa31, 0,  0xff, "brcmfmac43569",  "BCM43569",        false },
	{ 0,      0,  0,    NULL,             NULL,              false },
};

/* find the table entry for a given chip id and revision */
const struct brcm_chip_info *
brcm_chip_lookup(uint32_t chip, uint32_t chiprev)
{
	const struct brcm_chip_info *info;

	for (info = brcm_chip_table; info->fwname != NULL; info++) {
		if (info->chip != chip)
			continue;
		if (chiprev < info->chiprev_min ||
		    chiprev > info->chiprev_max)
			continue;
		return (info);
	}
	return (NULL);
}

/*
 * Pack a BCDC dcmd request into a host buffer for bs_txctl.  Returns
 * the number of bytes written.  The layout is:
 *
 *     +-----------+----- 16 bytes ------+
 *     |  cmd (LE) | len | flags | status |
 *     +-----------+--------------------+
 *     |  payload (payload_len bytes)   |
 *     +--------------------------------+
 *
 * reqid is packed into the high 16 bits of flags so the rxctl side
 * can demultiplex replies vs. unrelated events.
 */
size_t
brcm_proto_bcdc_pack(uint16_t reqid, uint32_t cmd, uint32_t flags,
    const void *payload, size_t payload_len, void *out, size_t out_cap)
{
	struct brcm_bcdc_dcmd hdr;
	uint8_t *p = out;

	if (out_cap < sizeof(hdr) + payload_len)
		return (0);

	memset(&hdr, 0, sizeof(hdr));
	hdr.cmd = htole32(cmd);
	hdr.len = htole32((uint32_t)payload_len);
	hdr.flags = htole32(flags |
	    (((uint32_t)reqid & BRCM_BCDC_DCMD_ID_MASK) <<
	    BRCM_BCDC_DCMD_ID_SHIFT));
	hdr.status = 0;
	memcpy(p, &hdr, sizeof(hdr));
	if (payload_len != 0)
		memcpy(p + sizeof(hdr), payload, payload_len);
	return (sizeof(hdr) + payload_len);
}

/*
 * Issue a BCDC GET dcmd and wait for the matching reply.  The reply
 * payload (after the 16-byte BCDC header the firmware echoes) is
 * copied into buf; *lenp updates to the actual length.  Returns 0 on
 * success or an errno on failure.
 *
 * The reply demultiplex happens in the bus transport: it parses
 * incoming control packets, looks them up by reqid in sc_ctl_pending,
 * and copies the payload into the matching req's reply_buf.
 */
int
brcm_dcmd_get(struct brcm_softc *sc, uint32_t cmd, void *buf, size_t *lenp)
{
	uint8_t stage[sizeof(struct brcm_bcdc_dcmd) + 4096];
	struct brcm_ctl_req req;
	uint32_t flags;
	size_t framelen;
	size_t want;
	int error;

	/*
	 * Transports that own their own command protocol (PCIe MSGBUF
	 * for the BCM4360 / BCM43602 / BCM4366 family) install a
	 * bs_dcmd_get hook on the bus_ops vtable and bypass the
	 * BCDC + sc_ctl_pending machinery below.  USB leaves the slot
	 * NULL and uses the in-core BCDC path.
	 */
	if (sc->sc_bus_ops->bs_dcmd_get != NULL)
		return (sc->sc_bus_ops->bs_dcmd_get(sc, cmd, buf, lenp));

	if (lenp == NULL)
		return (EINVAL);
	want = *lenp;
	if (want > 4096)
		return (E2BIG);

	memset(&req, 0, sizeof(req));
	mtx_lock(&sc->sc_ctl_mtx);
	if (sc->sc_dying) {
		mtx_unlock(&sc->sc_ctl_mtx);
		return (ENXIO);
	}
	sc->sc_in_flight_dcmd++;
	if (++sc->sc_bcdc_reqid == 0)	/* skip 0 on wrap */
		sc->sc_bcdc_reqid = 1;
	req.reqid = sc->sc_bcdc_reqid;
	req.reply_buf = buf;
	req.reply_capacity = want;
	TAILQ_INSERT_TAIL(&sc->sc_ctl_pending, &req, link);
	mtx_unlock(&sc->sc_ctl_mtx);

	flags = BRCM_BCDC_DCMD_GET;
	framelen = brcm_proto_bcdc_pack(req.reqid, cmd, flags, buf, want,
	    stage, sizeof(stage));
	if (framelen == 0) {
		error = ENOMEM;
		goto out;
	}

	error = sc->sc_bus_ops->bs_txctl(sc, stage, framelen);
	if (error != 0)
		goto out;

	/*
	 * Wait for the rxctl path to mark req.done.  Timeout is generous
	 * (2 seconds) since dcmd round-trips on USB are usually < 50 ms
	 * but can stall during firmware boot.  Detach wakes every entry
	 * on sc_ctl_pending so a dying transport breaks the sleep
	 * immediately rather than running out the 2 s timeout.
	 */
	mtx_lock(&sc->sc_ctl_mtx);
	while (!req.done && !sc->sc_dying) {
		error = mtx_sleep(&req, &sc->sc_ctl_mtx, PCATCH, "brcmdcmd",
		    hz * 2);
		if (error == EWOULDBLOCK)
			break;
	}
	mtx_unlock(&sc->sc_ctl_mtx);

	if (!req.done) {
		error = sc->sc_dying ? ENXIO : ETIMEDOUT;
		goto out;
	}
	*lenp = req.reply_actlen;
	if (req.reply_flags & BRCM_BCDC_DCMD_ERROR) {
		DPRINTF(sc, 0,
		    "dcmd_get cmd=%u BCME=%d\n", cmd, req.reply_status);
		error = EIO;
	} else
		error = 0;
out:
	mtx_lock(&sc->sc_ctl_mtx);
	TAILQ_REMOVE(&sc->sc_ctl_pending, &req, link);
	sc->sc_in_flight_dcmd--;
	if (sc->sc_in_flight_dcmd == 0 && sc->sc_dying)
		wakeup(&sc->sc_in_flight_dcmd);
	mtx_unlock(&sc->sc_ctl_mtx);
	return (error);
}

/* send a command with data to the firmware */
int
brcm_dcmd_set(struct brcm_softc *sc, uint32_t cmd, const void *buf, size_t len)
{
	uint8_t stage[sizeof(struct brcm_bcdc_dcmd) + 4096];
	struct brcm_ctl_req req;
	uint32_t flags;
	size_t framelen;
	int error;

	/* See banner on brcm_dcmd_get for the rationale. */
	if (sc->sc_bus_ops->bs_dcmd_set != NULL)
		return (sc->sc_bus_ops->bs_dcmd_set(sc, cmd, buf, len));

	if (len > 4096)
		return (E2BIG);

	memset(&req, 0, sizeof(req));
	mtx_lock(&sc->sc_ctl_mtx);
	if (sc->sc_dying) {
		mtx_unlock(&sc->sc_ctl_mtx);
		return (ENXIO);
	}
	sc->sc_in_flight_dcmd++;
	if (++sc->sc_bcdc_reqid == 0)	/* skip 0 on wrap */
		sc->sc_bcdc_reqid = 1;
	req.reqid = sc->sc_bcdc_reqid;
	TAILQ_INSERT_TAIL(&sc->sc_ctl_pending, &req, link);
	mtx_unlock(&sc->sc_ctl_mtx);

	flags = BRCM_BCDC_DCMD_SET;
	framelen = brcm_proto_bcdc_pack(req.reqid, cmd, flags, buf, len,
	    stage, sizeof(stage));
	if (framelen == 0) {
		error = ENOMEM;
		goto out;
	}

	error = sc->sc_bus_ops->bs_txctl(sc, stage, framelen);
	if (error != 0)
		goto out;

	mtx_lock(&sc->sc_ctl_mtx);
	while (!req.done && !sc->sc_dying) {
		error = mtx_sleep(&req, &sc->sc_ctl_mtx, PCATCH, "brcmdcmd",
		    hz * 2);
		if (error == EWOULDBLOCK)
			break;
	}
	mtx_unlock(&sc->sc_ctl_mtx);

	if (!req.done)
		error = sc->sc_dying ? ENXIO : ETIMEDOUT;
	else if (req.reply_flags & BRCM_BCDC_DCMD_ERROR) {
		/*
		 * Expose the firmware BCME_* code so join
		 * failures (rc=EIO from callers) point at the real cause
		 * (e.g. BCME_UNSUPPORTED, BCME_BADARG, BCME_NOTFOUND).
		 */
		DPRINTF(sc, 0,
		    "dcmd_set cmd=%u len=%zu BCME=%d\n",
		    cmd, len, req.reply_status);
		error = EIO;
	} else
		error = 0;
out:
	mtx_lock(&sc->sc_ctl_mtx);
	TAILQ_REMOVE(&sc->sc_ctl_pending, &req, link);
	sc->sc_in_flight_dcmd--;
	if (sc->sc_in_flight_dcmd == 0 && sc->sc_dying)
		wakeup(&sc->sc_in_flight_dcmd);
	mtx_unlock(&sc->sc_ctl_mtx);
	return (error);
}

/*
 * IOVAR get/set are convenience wrappers around dcmd GET_VAR /
 * SET_VAR (262 / 263).  Payload layout is NUL-terminated iovar name
 * followed by the value.
 */
int
brcm_iovar_get(struct brcm_softc *sc, const char *name, void *buf, size_t *lenp)
{
	uint8_t scratch[1024];
	size_t namelen, want, total;
	int error;

	if (lenp == NULL || name == NULL)
		return (EINVAL);

	/*
	 * MSGBUF chips have no chip-side iovar string table; the
	 * transport translates `name` to a numeric ID against its own
	 * fwil-style table.  ENOENT means "name not in my table" and
	 * lets us fall through to the BCDC dcmd-shaped path below
	 * (still useful for iovars we haven't catalogued numerically).
	 */
	if (sc->sc_bus_ops->bs_iovar_get != NULL) {
		error = sc->sc_bus_ops->bs_iovar_get(sc, name, buf, lenp);
		if (error != ENOENT)
			return (error);
	}

	namelen = strlen(name) + 1;
	want = *lenp;
	total = namelen + want;
	if (total > sizeof(scratch))
		return (E2BIG);

	memset(scratch, 0, sizeof(scratch));
	memcpy(scratch, name, namelen);
	*lenp = total;
	error = brcm_dcmd_get(sc, BRCM_C_GET_VAR, scratch, lenp);
	if (error != 0)
		return (error);
	if (*lenp > want)
		*lenp = want;
	memcpy(buf, scratch, *lenp);
	return (0);
}

/* set a named firmware variable */
int
brcm_iovar_set(struct brcm_softc *sc, const char *name, const void *buf,
    size_t len)
{
	uint8_t scratch[1024];
	size_t namelen, total;
	int error;

	if (name == NULL)
		return (EINVAL);

	/* See banner on brcm_iovar_get for the fallback rationale. */
	if (sc->sc_bus_ops->bs_iovar_set != NULL) {
		error = sc->sc_bus_ops->bs_iovar_set(sc, name, buf, len);
		if (error != ENOENT)
			return (error);
	}

	namelen = strlen(name) + 1;
	total = namelen + len;
	if (total > sizeof(scratch))
		return (E2BIG);

	memset(scratch, 0, sizeof(scratch));
	memcpy(scratch, name, namelen);
	if (len != 0)
		memcpy(scratch + namelen, buf, len);
	return (brcm_dcmd_set(sc, BRCM_C_SET_VAR, scratch, total));
}

/*
 * Variant of brcm_iovar_get that lets the caller append `plen` bytes
 * of params after the iovar name, then fetches up to `*lenp` bytes of
 * reply.  Used by sup_dump (and any other patched iovar that wants
 * input params): the chip's iovar dispatcher only forwards bytes
 * AFTER the name into the handler's params buffer.
 */
int
brcm_iovar_get_with_params(struct brcm_softc *sc, const char *name,
    const void *params, size_t plen, void *buf, size_t *lenp)
{
	uint8_t scratch[1024];
	size_t namelen, want, total;
	int error;

	if (lenp == NULL || name == NULL)
		return (EINVAL);
	namelen = strlen(name) + 1;
	want = *lenp;
	if (want < plen)
		want = plen;
	total = namelen + want;
	if (total > sizeof(scratch))
		return (E2BIG);

	memset(scratch, 0, sizeof(scratch));
	memcpy(scratch, name, namelen);
	if (params != NULL && plen != 0)
		memcpy(scratch + namelen, params, plen);
	*lenp = total;
	error = brcm_dcmd_get(sc, BRCM_C_GET_VAR, scratch, lenp);
	if (error != 0)
		return (error);
	if (*lenp > want)
		*lenp = want;
	memcpy(buf, scratch, *lenp);
	return (0);
}

/*
 * RXCTL dispatch.  Called by the transport when a BCDC control reply
 * arrives.  Strips the dcmd header, matches reqid, copies payload to
 * the waiting request and wakes the caller.  Replies that do not
 * match an outstanding reqid are silently dropped (they're typically
 * events the transport is routing through the wrong path).
 */
void
brcm_rxctl(struct brcm_softc *sc, const void *buf, size_t len)
{
	struct brcm_bcdc_dcmd hdr;
	struct brcm_ctl_req *req;
	uint32_t flags;
	uint16_t reqid;
	size_t payload_len;

	if (len < sizeof(hdr))
		return;
	memcpy(&hdr, buf, sizeof(hdr));
	flags = le32toh(hdr.flags);
	reqid = (flags >> BRCM_BCDC_DCMD_ID_SHIFT) & BRCM_BCDC_DCMD_ID_MASK;
	payload_len = len - sizeof(hdr);

	/*
	 * reqid 0 is reserved for async events (firmware emits them with
	 * id 0 in this slot).  Refusing to match it keeps our first dcmd
	 * (id 1) from ever colliding with an event that races in at boot.
	 */
	if (reqid == 0)
		return;

	mtx_lock(&sc->sc_ctl_mtx);
	TAILQ_FOREACH(req, &sc->sc_ctl_pending, link) {
		if (req->reqid != reqid)
			continue;
		if (payload_len > req->reply_capacity)
			payload_len = req->reply_capacity;
		if (req->reply_buf != NULL && payload_len != 0)
			memcpy(req->reply_buf,
			    (const uint8_t *)buf + sizeof(hdr),
			    payload_len);
		req->reply_actlen = payload_len;
		req->reply_flags = flags;
		req->reply_status = (int32_t)le32toh(hdr.status);
		req->done = true;
		wakeup(req);
		break;
	}
	mtx_unlock(&sc->sc_ctl_mtx);
}

/*
 * Walk a firmware-supplied IE blob and populate the IE-pointer fields
 * of an ieee80211_scanparams.  Same shape as ieee80211_parse_beacon's
 * IE switch, but operates on a raw byte range — no mbuf, no node, no
 * IEEE80211_DISCARD logging.  Caller must zero `sp` first.
 *
 * Stack budget on aarch64 is ~16 KB.  Going through ieee80211_input ->
 * sta_recv_mgmt -> ieee80211_parse_beacon costs ~3 frames and ~1 KB
 * of locals per call.  We're invoked once per BSS inside a per-event
 * loop, so trimming that fat is required for sustained scans not to
 * overflow the kthread stack.
 */
static void
brcm_walk_ies(const uint8_t *ies, size_t ies_len,
    struct ieee80211_scanparams *sp)
{
	const uint8_t *frm, *efrm;

	frm = ies;
	efrm = ies + ies_len;
	while (efrm - frm > 1) {
		if (frm[1] + 2 > efrm - frm)
			break;
		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			sp->ssid = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_RATES:
			sp->rates = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_COUNTRY:
			sp->country = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_DSPARMS:
			if (frm[1] >= 1)
				sp->chan = frm[2];
			break;
		case IEEE80211_ELEMID_TIM:
			sp->tim = __DECONST(uint8_t *, frm);
			sp->timoff = frm - ies;
			break;
		case IEEE80211_ELEMID_XRATES:
			sp->xrates = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_ERP:
			if (frm[1] == 1)
				sp->erp = frm[2] | 0x100;
			break;
		case IEEE80211_ELEMID_HTCAP:
			sp->htcap = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_VHT_CAP:
			sp->vhtcap = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_VHT_OPMODE:
			sp->vhtopmode = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_RSN:
			sp->rsn = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_HTINFO:
			sp->htinfo = __DECONST(uint8_t *, frm);
			break;
#ifdef IEEE80211_SUPPORT_MESH
		case IEEE80211_ELEMID_MESHID:
			sp->meshid = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_MESHCONF:
			sp->meshconf = __DECONST(uint8_t *, frm);
			break;
#endif
		case IEEE80211_ELEMID_VENDOR: {
			static const uint8_t wpa_oui[4] = { 0x00, 0x50, 0xf2, 1 };
			static const uint8_t wme_oui[4] = { 0x00, 0x50, 0xf2, 2 };
			if (frm[1] >= 4 && memcmp(&frm[2], wpa_oui, 4) == 0)
				sp->wpa = __DECONST(uint8_t *, frm);
			else if (frm[1] >= 4 && memcmp(&frm[2], wme_oui, 4) == 0)
				sp->wme = __DECONST(uint8_t *, frm);
			break;
		}
		default:
			break;
		}
		frm += frm[1] + 2;
	}
}

/*
 * Hand one firmware-supplied BSS straight to net80211's scan cache,
 * rather than building a synthetic beacon mbuf and running it through
 * ieee80211_fmac_input_beacon and the full ieee80211_parse_beacon IE
 * walker.  Linux brcmfmac's brcmf_inform_single_bss does the same flat
 * thing (calls cfg80211_inform_bss_data with the IE blob).  Flattening
 * saves ~3-4 stack frames per BSS, which keeps sustained scans from
 * overflowing the evrx worker's stack.
 *
 * The on-stack ieee80211_frame is the minimum sc_add_scan needs:
 * i_addr2 (source) and i_addr3 (bssid) — both set to the BSSID from
 * the firmware.  No IE memory is allocated by us; sc_add_scan's
 * ieee80211_ies_init does the copy under the scan-table lock.
 */
static void
brcm_add_scan_result(struct brcm_softc *sc,
    const struct brcm_bss_info *bss, uint32_t blen, int16_t rssi)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211vap *vap;
	struct ieee80211_channel *rxchan;
	struct ieee80211_scanparams sp;
	struct ieee80211_frame wh;
	uint8_t tstamp_zero[8];
	uint16_t ie_offset, chanspec;
	uint32_t ie_length;
	const uint8_t *ies;
	int rssi_n80, freq;
	int8_t nf;
	uint8_t chan;
	bool is5g;

	if (!sc->sc_ic_attached)
		return;

	ie_offset = le16toh(bss->ie_offset);
	ie_length = le32toh(bss->ie_length);
	if ((size_t)ie_offset + ie_length > blen)
		return;
	if (ie_length > 2048)
		return;
	ies = (const uint8_t *)bss + ie_offset;

	/*
	 * Cache the fw-reported chanspec for this BSSID before the
	 * net80211-scan gate below.  The cache is consulted by the join
	 * path so it can pass the chip's preferred chanspec back verbatim;
	 * a driver-initiated scan (dev.brcm.0.cmd_scan) bypasses
	 * ieee80211_F_SCAN and would otherwise leave the cache empty,
	 * forcing brcm_chan_to_chanspec_d11ac's minimal 20MHz fallback.
	 */
	brcm_cache_bssid_chanspec(sc, bss->bssid, le16toh(bss->chanspec));

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;
	/*
	 * Only deliver while a scan is live.  We bypass
	 * ic_scan_methods->sc_add_scan (= ieee80211_swscan_add_scan)
	 * and call the scanner-policy scan_add (= sta_add) directly.
	 * swscan_add_scan drops every event in the ISCAN_DISCARD
	 * window (ieee80211_scan_sw.c:970) — set at scan_start and
	 * cleared only after the SW engine's first per-channel
	 * callout.  For a FullMAC driver the chip emits its first
	 * ESCAN_RESULT within milliseconds of the escan iovar, well
	 * before that clear, so the DISCARD gate would silently
	 * eat every scan result and leave `ifconfig list scan`
	 * empty even with sp.ssid set and rssi sane.  Going direct
	 * to scan_add (the scanner policy) skips the gate; sta_add
	 * then drops the result into st->st_entry / st_hash where
	 * scan_iterate can find it.
	 */
	if (ic->ic_scan == NULL || ic->ic_scan->ss_ops == NULL ||
	    ic->ic_scan->ss_ops->scan_add == NULL ||
	    (ic->ic_flags & IEEE80211_F_SCAN) == 0 ||
	    ic->ic_scan->ss_vap == NULL)
		return;

	chanspec = le16toh(bss->chanspec);
	is5g = brcm_chanspec_is_5ghz(chanspec);
	chan = bss->ctl_ch != 0 ? bss->ctl_ch :
	    brcm_chanspec_to_chan(chanspec);
	freq = ieee80211_ieee2mhz(chan,
	    is5g ? IEEE80211_CHAN_5GHZ : IEEE80211_CHAN_2GHZ);
	rxchan = ieee80211_find_channel(ic, freq,
	    is5g ? IEEE80211_CHAN_A : IEEE80211_CHAN_G);
	if (rxchan == NULL)
		rxchan = ic->ic_curchan;
	if (rxchan == NULL)
		return;

	nf = ieee80211_fmac_noise_floor(bss->phy_noise);
	rssi_n80 = ((int)rssi - (int)nf) * 2;
	if (rssi_n80 < 0)
		rssi_n80 = 0;
	if (rssi_n80 > 127)
		rssi_n80 = 127;

	memset(&sp, 0, sizeof(sp));
	memset(tstamp_zero, 0, sizeof(tstamp_zero));
	sp.bchan = ieee80211_chan2ieee(ic, rxchan);
	sp.chan = sp.bchan;
	sp.bintval = le16toh(bss->beacon_period);
	sp.capinfo = le16toh(bss->capability);
	sp.ies = __DECONST(uint8_t *, ies);
	sp.ies_len = ie_length;
	sp.tstamp = tstamp_zero;	/* sta_add memcpys 8 B from this */
	brcm_walk_ies(ies, ie_length, &sp);

	/*
	 * sta_add (ieee80211_scan_sta.c:280) does
	 *   memcpy(ise->se_rates, sp->rates, 2 + sp->rates[1])
	 *   memcpy(ise->se_ssid,  sp->ssid,  2 + sp->ssid[1])
	 * with no NULL or length check (KASSERT is a no-op on
	 * non-DEBUG kernels and the destination buffer is fixed
	 * IEEE80211_RATE_MAXSIZE / IEEE80211_NWID_LEN bytes).
	 * Since we bypass swscan_add_scan's ISCAN_DISCARD gate,
	 * malformed firmware beacon clones would reach sta_add and
	 * NULL-deref or overflow.  Drop the BSS in either case.
	 */
	if (sp.rates == NULL || sp.ssid == NULL)
		return;
	if (sp.rates[1] > IEEE80211_RATE_MAXSIZE)
		return;
	if (sp.ssid[1] > IEEE80211_NWID_LEN)
		return;
	if (sp.xrates != NULL && sp.rates[1] + sp.xrates[1] >
	    IEEE80211_RATE_MAXSIZE)
		return;

	memset(&wh, 0, sizeof(wh));
	wh.i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	memset(wh.i_addr1, 0xff, 6);
	memcpy(wh.i_addr2, bss->bssid, 6);
	memcpy(wh.i_addr3, bss->bssid, 6);

	if (sc->sc_debug > 0)
		device_printf(sc->sc_dev,
		    "scan_result chan=%u freq=%d rssi=%d ie_len=%u "
		    "ssid_present=%d F_SCAN=%d\n",
		    chan, freq, (int)rssi, ie_length,
		    sp.ssid != NULL,
		    (ic->ic_flags & IEEE80211_F_SCAN) != 0);

	(void)ic->ic_scan->ss_ops->scan_add(ic->ic_scan, rxchan, &sp, &wh,
	    IEEE80211_FC0_SUBTYPE_BEACON, rssi_n80, nf);
}

/*
 * Walk the bss_info entries in an ESCAN_RESULT PARTIAL event and feed
 * each as a synthesised beacon to net80211's scan cache.
 */
static void
brcm_parse_escan_partial(struct brcm_softc *sc, const uint8_t *p, size_t len,
    size_t pos)
{
	const struct brcm_escan_results *res;
	const struct brcm_bss_info *bss;
	const uint8_t *cursor, *end;
	uint32_t blen;
	uint16_t bss_count;
	int16_t rssi;

	if (len < pos + sizeof(*res))
		return;
	res = (const struct brcm_escan_results *)(p + pos);
	/*
	 * bss_count is uint16_t on the wire (see brcm_escan_results in
	 * brcmreg.h).  A 32-bit read would pick up the first 2 bytes of
	 * the bss_info that follows, and the resulting huge count would
	 * walk the loop through arbitrary kernel memory.
	 */
	bss_count = le16toh(res->bss_count);
	cursor = p + pos + sizeof(*res);
	end = p + len;

	for (uint32_t i = 0; i < bss_count && cursor < end; i++) {
		if (cursor + sizeof(*bss) > end)
			break;
		bss = (const struct brcm_bss_info *)cursor;
		blen = le32toh(bss->length);
		if (blen < sizeof(*bss) || cursor + blen > end)
			break;

		rssi = (int16_t)le16toh((uint16_t)bss->rssi);
		DPRINTF(sc, 1, "bss[%u]: ver=%u len=%u bssid=%02x:%02x:%02x:"
		    "%02x:%02x:%02x rssi=%d phy_noise=%d snr=%d chanspec="
		    "0x%04x ctl_ch=%u\n",
		    i, le32toh(bss->version), blen,
		    bss->bssid[0], bss->bssid[1], bss->bssid[2],
		    bss->bssid[3], bss->bssid[4], bss->bssid[5],
		    rssi, (int)bss->phy_noise, (int)le16toh(bss->snr),
		    le16toh(bss->chanspec), bss->ctl_ch);
		brcm_add_scan_result(sc, bss, blen, rssi);

		cursor += blen;
	}
}

/*
 * Handle one decoded BRCM firmware event.  Called from brcm_rx_frame
 * after the BCDC + Ethernet + BRCM headers have been peeled.  Each
 * event_type runs a tiny state machine over net80211 — most fast
 * transitions belong here because the firmware has already done the
 * mgmt-frame work for us.
 *
 * Caller must NOT be holding the transport sc_mtx; this code reaches
 * into ieee80211_new_state / ieee80211_scan_done which can re-enter
 * the driver.
 */
void
brcm_handle_event(struct brcm_softc *sc, const uint8_t *p, size_t len,
    size_t evpos)
{
	const struct brcm_event_msg *emsg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211vap *vap;
	uint32_t evtype, status;
	uint16_t eflags;

	if (len < evpos + sizeof(*emsg))
		return;
	emsg = (const struct brcm_event_msg *)(p + evpos);
	evtype = be32toh(emsg->event_type);
	status = be32toh(emsg->status);
	if (evtype < nitems(sc->sc_evt_by_type))
		atomic_add_32(&sc->sc_evt_by_type[evtype], 1);

	if (evtype == BRCM_E_TYPE_ESCAN_RESULT &&
	    status == BRCM_E_STATUS_PARTIAL) {
		brcm_parse_escan_partial(sc, p, len, evpos + sizeof(*emsg));
		return;
	}
	if (evtype == BRCM_E_TYPE_ESCAN_RESULT &&
	    status != BRCM_E_STATUS_PARTIAL) {
		/*
		 * Terminator ESCAN_RESULT: status is SUCCESS, ABORT,
		 * or one of the failure codes.  Clear the in-flight
		 * guard so the next cmd_scan can proceed (matches
		 * Linux brcmf_notify_escan_complete clearing
		 * BRCMF_SCAN_STATUS_BUSY).
		 */
		DPRINTF(sc, 1, "scan complete (status=%u)\n", status);
		sc->sc_scan_busy = 0;
		atomic_add_32(&sc->sc_escan_done_evts, 1);
		if (sc->sc_ic_attached) {
			atomic_add_32(&sc->sc_scan_done_reqs, 1);
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_scan_done_task);
		}
		return;
	}
	if (evtype == BRCM_E_TYPE_LINK) {
		eflags = be16toh(emsg->flags);
		DPRINTF(sc, 0, "LINK %s status=%u\n",
		    (eflags & BRCM_E_FLAG_LINK_UP) ? "up" : "down", status);
		sc->sc_link_up = (eflags & BRCM_E_FLAG_LINK_UP) != 0;
		sc->sc_join_busy = 0;	/* terminator: either success or fail */
		if (sc->sc_ic_attached) {
			atomic_add_32(&sc->sc_link_reqs, 1);
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_link_task);
		}
		return;
	}
	if (evtype == BRCM_E_TYPE_SET_SSID) {
		/*
		 * Per Linux brcmf_is_linkup (cfg80211.c:6040), E_SET_SSID
		 * status=SUCCESS is the PRIMARY linkup trigger for our
		 * host-EAPOL path (FWSUP_NONE).  E_LINK with LINK_UP flag
		 * may fire much later or not at all on some fw.  Process
		 * this as the linkup signal too -- belt + braces with the
		 * existing E_LINK handler above.
		 */
		DPRINTF(sc, 0, "SET_SSID status=%u%s\n", status,
		    status == BRCM_E_STATUS_SUCCESS ?
		    " -> linkup" : " -> failure");
		if (status == BRCM_E_STATUS_SUCCESS) {
			sc->sc_link_up = 1;
			sc->sc_join_busy = 0;
			if (sc->sc_ic_attached) {
				atomic_add_32(&sc->sc_link_reqs, 1);
				(void)taskqueue_enqueue(taskqueue_thread,
				    &sc->sc_link_task);
			}
		} else {
			/* connect failure (NO_NETWORKS, timeout, etc.) */
			sc->sc_join_busy = 0;
		}
		return;
	}
	if (evtype == BRCM_E_TYPE_AUTH || evtype == BRCM_E_TYPE_ASSOC) {
		DPRINTF(sc, 1, "%s status=%u reason=%u\n",
		    evtype == BRCM_E_TYPE_AUTH ? "AUTH" : "ASSOC",
		    status, be32toh(emsg->reason));
		/*
		 * On ASSOC success, dispatch post-assoc handshake taskqueue.
		 * Linux brcmfmac issues these GETs (assoc_info, assoc_req_ies,
		 * assoc_resp_ies, wme_ac_sta via brcmf_get_assoc_ies, then
		 * GET_BSS_INFO via brcmf_update_bss_info) from
		 * brcmf_bss_connect_done on the SET_SSID-success linkup; we
		 * issue them earlier, on E_ASSOC.  Chip may tear down LINK if
		 * host doesn't interact within a window -- keep chip happy.
		 *
		 * Also treat E_TYPE_ASSOC SUCCESS as the linkup trigger --
		 * BCM43455 fw 7.45.x never emits E_TYPE_LINK (16) nor
		 * E_TYPE_SET_SSID (0) on the host-EAPOL path until AFTER
		 * 4-way completes.  If we wait for those, wpa_supplicant
		 * stalls at ASSOCIATING (no RTM_IEEE80211_ASSOC on
		 * PF_ROUTE) and never drives the 4-way in response to the
		 * EAPOL M1 we already forwarded to wlan0 via
		 * ieee80211_fmac_eapol_rx.  Linux reports the connection
		 * (cfg80211_connect_done) on E_SET_SSID success; this fw does
		 * not send that before the 4-way, so we use E_ASSOC instead.
		 * Walk vap AUTH/ASSOC -> RUN via the framework's
		 * fast-forward (link_task -> ieee80211_fmac_link_up).
		 */
		if (evtype == BRCM_E_TYPE_ASSOC &&
		    status == BRCM_E_STATUS_SUCCESS && sc->sc_ic_attached) {
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_post_assoc_task);
			sc->sc_link_up = 1;
			sc->sc_join_busy = 0;
			atomic_add_32(&sc->sc_link_reqs, 1);
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_link_task);
		}
		return;
	}
	if (evtype == BRCM_E_TYPE_DISASSOC) {
		DPRINTF(sc, 0, "DISASSOC reason=%u\n",
		    be32toh(emsg->reason));
		sc->sc_join_busy = 0;	/* allow next join attempt */
		if (sc->sc_ic_attached) {
			/*
			 * Use the framework's link-down up-call instead
			 * of driving directly to SCAN: the framework
			 * walks every STA vap to INIT and lets net80211
			 * decide whether to rescan based on iv_des_ssid.
			 * Falls back to a direct ieee80211_new_state if
			 * the framework has no STA vap registered.
			 */
			if (ieee80211_fmac_link_down(ic,
			    (uint16_t)be32toh(emsg->reason)) != 0) {
				vap = TAILQ_FIRST(&ic->ic_vaps);
				if (vap != NULL)
					(void)ieee80211_new_state(vap,
					    IEEE80211_S_SCAN, -1);
			}
		}
		return;
	}
	if (evtype == BRCM_E_EAPOL_MSG) {
		/*
		 * Firmware-delivered EAPOL frame.  With sup_wpa=0 the chip
		 * emits each EAPOL packet from the AP as event type 25
		 * instead of consuming it in its own supplicant.  Forward
		 * the body to the FullMAC framework, which wraps it in a
		 * synthetic 802.3 header (dst=our_mac, src=ap_mac,
		 * ethertype=0x888e) and delivers it to the vap so
		 * net80211 routes to userspace wpa_supplicant via the
		 * wlan(4) BPF / EAPOL subscription.
		 */
		uint32_t plen = be32toh(emsg->datalen);
		size_t payload_off = evpos + sizeof(*emsg);

		if (!sc->sc_ic_attached)
			return;
		if (plen == 0 || plen > MCLBYTES - 14 ||
		    payload_off + plen > len) {
			DPRINTF(sc, 0,
			    "EAPOL event: bogus plen=%u len=%zu\n",
			    plen, len);
			return;
		}
		DPRINTF(sc, 1,
		    "EAPOL event: %u bytes from %02x:%02x:%02x:%02x:%02x:%02x"
		    " status=%u\n", plen,
		    emsg->addr[0], emsg->addr[1], emsg->addr[2],
		    emsg->addr[3], emsg->addr[4], emsg->addr[5], status);
		ieee80211_fmac_eapol_rx(ic, emsg->addr,
		    p + payload_off, plen);
		return;
	}
	DPRINTF(sc, 1, "evt type=%u status=%u datalen=%u\n",
	    evtype, status, be32toh(emsg->datalen));
}

/*
 * RX data path.  Transport supplies an mbuf with the BCDC bulk-IN
 * header at the head.  We strip the BCDC header, demultiplex BRCM
 * event frames (ethertype 0x886c) from real 802.3 data, and either
 * dispatch the event or hand the frame to net80211 via
 * ieee80211_input_all.
 */
void
brcm_rx_frame(struct brcm_softc *sc, struct mbuf *m)
{
	struct brcm_bcdc_hdr bcdc;
	const uint8_t *p;
	size_t offset, len, evpos;
	uint16_t ethertype;

	if (m == NULL)
		return;
	if (m->m_pkthdr.len < (int)sizeof(bcdc)) {
		m_freem(m);
		return;
	}
	m_copydata(m, 0, sizeof(bcdc), (caddr_t)&bcdc);
	offset = sizeof(bcdc) + ((size_t)bcdc.data_offset * 4);
	if ((int)offset > m->m_pkthdr.len) {
		m_freem(m);
		return;
	}
	m_adj(m, offset);

	/*
	 * Need a contiguous mbuf head over the Ethernet header to read
	 * the ethertype.  The bus drivers always hand us a freshly
	 * allocated single-cluster mbuf, but be defensive.
	 */
	if (m->m_pkthdr.len < 14) {
		m_freem(m);
		return;
	}
	if (m->m_len < 14) {
		m = m_pullup(m, 14);
		if (m == NULL)
			return;
	}
	p = mtod(m, const uint8_t *);
	len = m->m_pkthdr.len;
	ethertype = (uint16_t)p[12] << 8 | p[13];

	if (ethertype != BRCM_ETHERTYPE_BRCM) {
		struct ieee80211com *ic = &sc->sc_ic;
		struct ieee80211vap *vap;

		if (!sc->sc_ic_attached) {
			m_freem(m);
			return;
		}
		vap = TAILQ_FIRST(&ic->ic_vaps);
		if (vap == NULL) {
			m_freem(m);
			return;
		}

		/*
		 * EAPOL fast path: chip in FWSUP_NONE mode (sup_wpa=0)
		 * delivers 802.1X frames as plain DATA (ethertype 0x888e),
		 * NOT as BRCM_E_EAPOL_MSG events.  ieee80211_input_all
		 * expects 802.11 frames, not 802.3, so handing them there
		 * would never get them to wpa_supplicant.
		 *
		 * Route through the FullMAC shim's eapol hook which wraps
		 * a synthetic 802.3 header (already correct in our case)
		 * and feeds the wlan(4) BPF subscription wpa_supplicant
		 * watches.  src MAC at offset 6 is the AP.
		 */
		if (ethertype == 0x888e) {
			uint8_t ap_mac[6];
			memcpy(ap_mac, p + 6, 6);
			DPRINTF(sc, 0, "EAPOL DATA len=%zu ap=%02x:%02x:%02x:"
			    "%02x:%02x:%02x\n", len - 14, ap_mac[0], ap_mac[1],
			    ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
			ieee80211_fmac_eapol_rx(ic, ap_mac, p + 14, len - 14);
			m_freem(m);
			return;
		}

		/*
		 * The firmware hands up decrypted 802.3 frames: deliver them
		 * to the vap as the PCIe transport does.  ieee80211_input_all
		 * parses an 802.11 header and would count every one of these
		 * as an input error and drop it.
		 */
		DPRINTF(sc, 1, "DATA eth=0x%04x len=%zu\n", ethertype, len);
		m->m_pkthdr.rcvif = vap->iv_ifp;
		ieee80211_vap_deliver_data(vap, m);
		return;
	}

	evpos = 14 + sizeof(struct brcm_brcm_ethhdr);
	atomic_add_int(&sc->sc_evt_count, 1);
	brcm_handle_event(sc, p, len, evpos);
	m_freem(m);
}

/*
 * Push a WPA2 PMK / passphrase down to the firmware so its 4-way
 * handshake runs without host involvement.  Pulls the staged secret
 * from the softc: raw 32-byte PMK preferred if both are set.
 * Tries BRCM_C_SET_WSEC_PMK opcode 268 (legacy / 2011 firmware) first
 * and falls back to the SET_VAR "wsec_pmk" iovar.
 */
static int
brcm_install_pmk(struct brcm_softc *sc)
{
	struct brcm_wsec_pmk wp;
	int error_op, error_iovar;

	memset(&wp, 0, sizeof(wp));

	if (sc->sc_wpa_pmk_raw_set) {
		wp.key_len = htole16(BRCM_WSEC_MAX_PSK_LEN);
		wp.flags = 0;
		memcpy(wp.key, sc->sc_wpa_pmk_raw, BRCM_WSEC_MAX_PSK_LEN);
	} else if (sc->sc_wpa_set) {
		size_t pmklen = strlen(sc->sc_wpa_pmk);

		/*
		 * 2011 BCM43236 firmware uses the short (37-byte) wsec_pmk
		 * struct so the on-chip PBKDF2 path accepts at most 32-char
		 * passphrases.  Standard WPA2 allows up to 63 chars; longer
		 * ones must be pre-derived on the host and pushed via the
		 * raw-PMK path (dev.brcm.<n>.wpa_pmk_hex).
		 */
		if (pmklen < 8 || pmklen > BRCM_WSEC_MAX_PSK_LEN)
			return (EINVAL);
		wp.key_len = htole16((uint16_t)pmklen);
		wp.flags = htole16(BRCM_WSEC_PASSPHRASE);
		memcpy(wp.key, sc->sc_wpa_pmk, pmklen);
	} else {
		return (EINVAL);
	}

	/*
	 * Linux brcmfmac drives this exclusively via BRCM_C_SET_WSEC_PMK
	 * opcode 268, never the "wsec_pmk" iovar.  For the 2011 firmware
	 * the iovar string is not in the dispatcher at all (confirmed by
	 * scanning the blob's string table), so the opcode is the only
	 * working path here.  Try the opcode first; keep the iovar
	 * fallback for completeness so newer firmware that exposes it as
	 * a named iovar also works.
	 */
	error_op = brcm_dcmd_set(sc, BRCM_C_SET_WSEC_PMK, &wp, sizeof(wp));
	if (error_op == 0)
		return (0);
	error_iovar = brcm_iovar_set(sc, "wsec_pmk", &wp, sizeof(wp));
	if (error_iovar == 0)
		return (0);
	DPRINTF(sc, 0,
	    "install_pmk: opcode 268 rc=%d, iovar wsec_pmk rc=%d "
	    "(payload %u bytes, flags=0x%x)\n",
	    error_op, error_iovar, (unsigned)sizeof(wp),
	    le16toh(wp.flags));
	return (error_op);
}

/*
 * Program WPA2-PSK security and dispatch SET_SSID with the given
 * BSSID + SSID.  Works both from net80211's newstate hook (passing
 * vap->iv_bss bits) and from the direct-join sysctl path (which
 * bypasses net80211 so the radio can be brought up before the
 * userland integration is complete).
 *
 * Our own order: DOWN -> infra / auth / wsec / wpa_auth / sup_wpa /
 * wsec_pmk -> UP -> join.  (OpenBSD bwfm sets wpaie / wpa_auth / wsec /
 * auth / mfp with no DOWN/UP and leaves the 4-way to the host.)  The 2011
 * firmware rejects wsec_pmk with -23 (BCME_UNSUPPORTED) unless the data
 * plane is DOWN.  A wsec_pmk failure is non-fatal here so the join can
 * still proceed if the chip's supplicant already holds the credentials
 * from an earlier join.
 */
static int
brcm_join_wpa2_raw(struct brcm_softc *sc, const uint8_t bssid[6],
    const char *ssid, size_t ssid_len)
{
	uint32_t v;
	int error;

	if (brcm_join_busy_acquire(sc, "wpa2_raw"))
		return (EAGAIN);
	if (ssid_len > BRCM_MAX_SSID_LEN)
		ssid_len = BRCM_MAX_SSID_LEN;

	v = htole32(0);
	(void)brcm_dcmd_set(sc, BRCM_C_DOWN, &v, sizeof(v));

	v = htole32(1);
	error = brcm_dcmd_set(sc, BRCM_C_SET_INFRA, &v, sizeof(v));
	if (error != 0)
		goto fail;

	v = htole32(BRCM_AUTH_OPEN);
	error = brcm_dcmd_set(sc, BRCM_C_SET_AUTH, &v, sizeof(v));
	if (error != 0)
		goto fail;

	v = htole32(BRCM_WSEC_AES);
	error = brcm_iovar_set(sc, "wsec", &v, sizeof(v));
	if (error != 0)
		goto fail;

	v = htole32(BRCM_WPA_AUTH_WPA2_PSK);
	error = brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v));
	if (error != 0)
		goto fail;

	/*
	 * Enable the in-firmware supplicant, after wsec/wpa_auth are set.
	 * Required by BCM43455 fw 7.45.x: without sup_wpa=1 the chip
	 * rejects the wsec_pmk install with BCME_BADARG (-2) and the 4-way
	 * handshake never runs.  Linux brcmfmac sets this before
	 * brcmf_set_pmk for FWSUP_PSK, at connect time rather than at
	 * bringup.  Do NOT gate this on brcm_probe_wpa_sup(): the bringup
	 * probe can reject sup_wpa before the security mode is configured.
	 * A failure is logged so it surfaces, but the join carries on.
	 */
	{
		v = htole32(1);
		error = brcm_iovar_set(sc, "sup_wpa", &v, sizeof(v));
		if (error != 0) {
			DPRINTF(sc, 0,
			    "sup_wpa=1 rejected at join (rc=%d) — "
			    "wsec_pmk install may fail with BCME_BADARG\n",
			    error);
		} else {
			sc->sc_sup_wpa_ok = true;
			sc->sc_sup_wpa_current = 1;
		}
	}

	error = brcm_install_pmk(sc);
	if (error != 0) {
		DPRINTF(sc, 0,
		    "wsec_pmk failed (%d) -- continuing; firmware may "
		    "fall back to open mode or fail at 4-way handshake\n",
		    error);
		error = 0;
	}

	v = htole32(1);
	(void)brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));

	/* join_pref: matches Linux brcmf_c_set_joinpref_default. */
	{
		struct brcm_join_pref_params jp[2];
		int rc;

		memset(jp, 0, sizeof(jp));
		jp[0].type = BRCM_JOIN_PREF_RSSI_DELTA;
		jp[0].len = 2;
		jp[0].rssi_gain = BRCM_JOIN_PREF_RSSI_BOOST;
		jp[0].band = BRCM_WLC_BAND_5G;
		jp[1].type = BRCM_JOIN_PREF_RSSI;
		jp[1].len = 2;
		jp[1].rssi_gain = 0;
		jp[1].band = 0;
		rc = brcm_iovar_set(sc, "join_pref", jp, sizeof(jp));
		DPRINTF(sc, 0, "join WPA2: join_pref rc=%d\n", rc);
	}

	/*
	 * Dispatch via the "join" iovar (bsscfg:join) with the 70-byte
	 * ext_join_params, exactly as Linux brcmfmac does during connect
	 * (docs/LINUX_MFP_IOVAR_TRACE.md).  The SET_SSID dcmd leaves the
	 * fw-supplicant 4-way incomplete on this fw (LINK reason=2).
	 */
	{
		struct brcm_ext_join_params ejp;
		size_t join_params_size;
		uint16_t chanspec;

		chanspec = brcm_lookup_bssid_chanspec(sc, bssid);
		if (chanspec == 0) {
			/*
			 * The chanspec cache holds only the last-scanned
			 * bssid; on a miss, fall back to the net80211 bss
			 * node channel (populated by ieee80211_sta_join),
			 * else bsscfg:join auto-scans and can miss the AP
			 * (SET_SSID NO_NETWORKS).
			 */
			struct ieee80211vap *jv =
			    TAILQ_FIRST(&sc->sc_ic.ic_vaps);
			if (jv != NULL && jv->iv_bss != NULL &&
			    jv->iv_bss->ni_chan != NULL &&
			    jv->iv_bss->ni_chan != IEEE80211_CHAN_ANYC &&
			    jv->iv_bss->ni_chan->ic_ieee != 0)
				chanspec = brcm_chan_to_chanspec(sc,
				    jv->iv_bss->ni_chan->ic_ieee);
		}

		memset(&ejp, 0, sizeof(ejp));
		ejp.ssid.len = htole32(ssid_len);
		memcpy(ejp.ssid.ssid, ssid, ssid_len);
		ejp.scan.scan_type = 0;
		ejp.scan.home_time = htole32((uint32_t)-1);
		memcpy(ejp.assoc.bssid, bssid, 6);
		if (chanspec != 0) {
			ejp.assoc.chanspec_num = htole32(1);
			ejp.assoc.chanspec_list[0] = htole16(chanspec);
			ejp.scan.active_time  = htole32(320);
			ejp.scan.passive_time = htole32(400);
			ejp.scan.nprobes      = htole32(16);
			join_params_size = sizeof(ejp);
		} else {
			ejp.scan.nprobes      = htole32((uint32_t)-1);
			ejp.scan.active_time  = htole32((uint32_t)-1);
			ejp.scan.passive_time = htole32((uint32_t)-1);
			join_params_size =
			    offsetof(struct brcm_ext_join_params, assoc) +
			    offsetof(struct brcm_ext_assoc_params,
			    chanspec_list);
		}

		DPRINTF(sc, 0,
		    "join WPA2: ssid=\"%.*s\" "
		    "bssid=%02x:%02x:%02x:%02x:%02x:%02x chanspec=0x%04x "
		    "size=%zu (bsscfg:join)\n",
		    (int)ssid_len, ssid,
		    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
		    chanspec, join_params_size);

		error = brcm_iovar_set(sc, "join", &ejp, join_params_size);
		if (error != 0)
			goto fail;
	}
	/* sc_join_busy stays set until LINK or DISASSOC event clears it. */
	return (0);
fail:
	sc->sc_join_busy = 0;
	return (error);
}

/* join a WPA2 network using the stored passphrase */
static int
brcm_join_wpa2(struct brcm_softc *sc, struct ieee80211vap *vap)
{
	struct ieee80211_node *ni;

	ni = vap->iv_bss;
	if (ni == NULL)
		return (EINVAL);
	return (brcm_join_wpa2_raw(sc, ni->ni_bssid,
	    (const char *)ni->ni_essid, ni->ni_esslen));
}

/*
 * Drive an open-system join via BCDC.  Build the join params from the
 * VAP's bss_node (SSID + BSSID picked by net80211's scan picker) and
 * issue SET_SSID; firmware does auth + assoc and emits a LINK event
 * on success.
 */
static int
brcm_join_open(struct brcm_softc *sc, struct ieee80211vap *vap)
{
	struct brcm_join_params join;
	struct ieee80211_node *ni;
	size_t jlen;
	uint16_t chanspec;
	uint8_t slen;
	uint32_t v;
	int error;

	if (brcm_join_busy_acquire(sc, "open"))
		return (EAGAIN);
	ni = vap->iv_bss;
	if (ni == NULL) {
		sc->sc_join_busy = 0;
		return (EINVAL);
	}

	slen = ni->ni_esslen;
	if (slen > BRCM_MAX_SSID_LEN)
		slen = BRCM_MAX_SSID_LEN;

	/*
	 * Reset chip security/infra state to known-open before
	 * SET_SSID.  Without this, leftover wsec=AES + wpa_auth=
	 * WPA2_PSK from an earlier brcm_join_wpa2_raw keeps the
	 * chip in WPA2 mode -- it'll silently drop probe responses
	 * that don't include matching RSN IEs and never reach AUTH.
	 *
	 * Do NOT wrap in DOWN/UP -- Linux brcmfmac doesn't, and the
	 * BCM43455 fw 7.45.98 join state machine never fires AUTH
	 * after a DOWN/UP cycle (the iovars take effect, but
	 * SET_SSID returns 0 and nothing goes out on the air).
	 * Just program the iovars on the already-UP chip.
	 */
	v = htole32(1);
	(void)brcm_dcmd_set(sc, BRCM_C_SET_INFRA, &v, sizeof(v));
	v = htole32(BRCM_AUTH_OPEN);
	(void)brcm_dcmd_set(sc, BRCM_C_SET_AUTH, &v, sizeof(v));
	v = htole32(0);
	(void)brcm_iovar_set(sc, "wsec", &v, sizeof(v));
	v = htole32(0);
	(void)brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v));

	memset(&join, 0, sizeof(join));
	join.ssid.len = htole32(slen);
	memcpy(join.ssid.ssid, ni->ni_essid, slen);
	memcpy(join.assoc.bssid, ni->ni_bssid, 6);

	/*
	 * Push the fw-cached chanspec into the SET_SSID payload when we
	 * have one.  chanspec_num=0 ("any channel") forces the chip to
	 * re-scan for the target SSID, and on BCM43455 fw 7.45.x that
	 * silent-scan path doesn't always converge to AUTH (SET_SSID
	 * returns rc=0 but no AUTH event ever fires).  Passing the
	 * exact chanspec the fw itself reported in the last ESCAN_RESULT
	 * lets the chip skip the rediscovery and park directly.
	 */
	chanspec = brcm_lookup_bssid_chanspec(sc, ni->ni_bssid);
	if (chanspec != 0) {
		join.assoc.chanspec_num = htole32(1);
		join.assoc.chanspec_list[0] = htole16(chanspec);
		jlen = BRCM_JOIN_PARAMS_FIXED_SIZE + sizeof(uint16_t);
	} else {
		join.assoc.chanspec_num = 0;
		jlen = BRCM_JOIN_PARAMS_FIXED_SIZE;
	}

	DPRINTF(sc, 0,
	    "join OPEN: ssid=\"%.*s\" bssid=%02x:%02x:%02x:%02x:%02x:%02x "
	    "chanspec=0x%04x jlen=%zu\n",
	    (int)slen, ni->ni_essid,
	    ni->ni_bssid[0], ni->ni_bssid[1], ni->ni_bssid[2],
	    ni->ni_bssid[3], ni->ni_bssid[4], ni->ni_bssid[5],
	    chanspec, jlen);

	error = brcm_dcmd_set(sc, BRCM_C_SET_SSID, &join, jlen);
	DPRINTF(sc, 0, "join OPEN: SET_SSID rc=%d\n", error);
	if (error != 0)
		sc->sc_join_busy = 0;
	return (error);
}

/*
 * Trace-only newstate hook.  AUTH/ASSOC join dispatch is owned by
 * the FullMAC framework (fmac_newstate -> brcm_fmop_assoc, which
 * defers to brcm_assoc_task on taskqueue_thread); this wrapper
 * keeps the per-transition log line and chains to net80211's
 * default sta_newstate so SCAN / INIT / RUN walks behave.
 */
static int
brcm_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct brcm_vap *bv = BRCM_VAP(vap);
	struct brcm_softc *sc = vap->iv_ic->ic_softc;

	DPRINTF(sc, 1, "newstate %d -> %d arg=%d\n",
	    vap->iv_state, nstate, arg);
	/*
	 * Give the bss node its association ID before net80211 runs RUN,
	 * not after (brcm_link_ran does it too, late).  sta_newstate's RUN
	 * notifies wpa_supplicant, which answers an already-queued message
	 * 1 within a millisecond.  When the firmware's EAPOL arrives ahead
	 * of the link-up and ni_associd is still 0, ieee80211_start_pkt
	 * drops message 2 as "sta not associated", the send fails and
	 * wpa_supplicant deauthenticates with reason 1.  The FullMAC
	 * firmware owns the real AID.
	 */
	if (nstate == IEEE80211_S_RUN && vap->iv_opmode == IEEE80211_M_STA &&
	    vap->iv_bss != NULL && vap->iv_bss->ni_associd == 0) {
		vap->iv_bss->ni_associd = 1;
		vap->iv_bss->ni_flags |= IEEE80211_NODE_ASSOCID;
	}
	return (bv->bv_newstate(vap, nstate, arg));
}

/*
 * Deferred scan-completion notifier.  Runs on taskqueue_thread so we
 * call ieee80211_scan_done() with the correct lock context; USB
 * callback context is not safe.
 */
static void
brcm_scan_done_task(void *arg, int pending)
{
	struct brcm_softc *sc = arg;
	struct ieee80211vap *vap;

	atomic_add_32(&sc->sc_scan_done_cover, (uint32_t)pending);

	if (!sc->sc_ic_attached)
		return;
	vap = TAILQ_FIRST(&sc->sc_ic.ic_vaps);
	if (vap == NULL)
		return;
	/*
	 * The firmware's escan has delivered every result, so end
	 * net80211's scan.  ieee80211_scan_done alone only wakes the
	 * software scanner, which then walks on through its whole channel
	 * list (about 10 s) while an association request from
	 * wpa_supplicant waits behind it until wpa_supplicant's own 10 s
	 * authentication timeout fires.  So cancel the scan as well; a
	 * cancelled scan still sends the scan-done notification.
	 */
	ieee80211_scan_done(vap);
	if (sc->sc_ic.ic_flags & IEEE80211_F_SCAN)
		ieee80211_cancel_scan(vap);
}

/*
 * Deferred link state transition.  Firmware emits LINK up when it's
 * fully associated and the 4-way handshake completed; net80211 at
 * that point is sitting in AUTH (from ieee80211_sta_join walking the
 * vap there in the join_target sysctl path).  We fast-forward
 * AUTH -> ASSOC -> RUN here because the firmware did the actual
 * mgmt-frame work that net80211's SoftMAC state machine would
 * otherwise expect us to do.
 *
 * This is the iwm-style hook-override pattern: each transition
 * shortcuts to the next because the chip is already past it.
 */
static int	brcm_sta_join_from_cache(struct brcm_softc *sc);

static int	brcm_scb_authorize(struct brcm_softc *, const uint8_t[6]);

/*
 * net80211 has just been walked to RUN on the firmware's link-up: give
 * the bss node an association ID and, when the firmware ran the 4-way
 * itself, open the 802.1x port.
 */
static void
brcm_link_ran(struct brcm_softc *sc, struct ieee80211vap *vap)
{
	/*
	 * net80211 was fast-forwarded to RUN without parsing a real
	 * association response, so the bss node's association ID stays
	 * 0.  ieee80211_start_pkt() discards every data frame from a
	 * node with ni_associd == 0 ("sta not associated"), which
	 * silently drops all DHCP/IP traffic before it reaches the
	 * driver.  The FullMAC firmware owns the real association; give
	 * net80211 a valid-looking (nonzero) AID so the data path opens.
	 */
	if (vap->iv_bss != NULL && vap->iv_bss->ni_associd == 0) {
		vap->iv_bss->ni_associd = 1;
		vap->iv_bss->ni_flags |= IEEE80211_NODE_ASSOCID;
	}
	/*
	 * FullMAC port authorization.  When the firmware ran the
	 * 4-way itself (fw supplicant, sup_wpa=1) there is no host
	 * supplicant to open net80211's 802.1x controlled port, so
	 * net80211 leaves it closed and only EAPOL crosses the link
	 * -- DHCP/IP get dropped and the vap is torn down.  The fw
	 * link-up means the 4-way completed and keys are plumbed in
	 * the chip, so open the port here to let data flow.
	 */
	if (sc->sc_sup_wpa_current != 0 &&
	    vap != NULL && vap->iv_bss != NULL) {
		ieee80211_node_authorize(vap->iv_bss);
		/*
		 * Also authorize the chip data-plane SCB, or the
		 * fw drops every data frame despite the completed
		 * 4-way.  The host-EAPOL path does this from
		 * brcm_fmop_set_key; the fw-supplicant path never
		 * calls set_key, so do it here on link-up.
		 */
		(void)brcm_scb_authorize(sc, vap->iv_bss->ni_bssid);
		DPRINTF(sc, 0, "link task: authorized 802.1x port "
		    "+ SCB data plane (fw supplicant)\n");
	}
}

static void
brcm_link_task(void *arg, int pending)
{
	struct brcm_softc *sc = arg;
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;

	atomic_add_32(&sc->sc_link_cover, (uint32_t)pending);

	if (!sc->sc_ic_attached) {
		DPRINTF(sc, 0,
		    "link task: ic not attached; firmware link %s ignored\n",
		    sc->sc_link_up ? "up" : "down");
		return;
	}
	vap = TAILQ_FIRST(&sc->sc_ic.ic_vaps);
	if (vap == NULL) {
		DPRINTF(sc, 0, "link task: no vap\n");
		return;
	}

	if (!sc->sc_link_up) {
		DPRINTF(sc, 0,
		    "link task: firmware link down; driving to INIT\n");
		(void)ieee80211_fmac_link_down(&sc->sc_ic, 0);
		return;
	}

	/*
	 * Ask the FullMAC framework to fast-forward to RUN.  It only
	 * does the walk when the vap is already in AUTH/ASSOC with a
	 * populated iv_bss + ni_chan — exactly the safe case for
	 * ieee80211_sync_curchan.  ENOENT means "not in a fast-
	 * forwardable state": fall back to the driver-specific
	 * scan-cache lookup / kick-a-scan recovery below.  Without
	 * this fallback, raw join dispatch leaves the vap stuck in
	 * INIT and the EAPOL events the chip is forwarding
	 * (BRCM_E_EAPOL_MSG) hit a vap with no listener.
	 */
	if (ieee80211_fmac_link_up(&sc->sc_ic, NULL) == 0) {
		DPRINTF(sc, 0, "link task: framework walked vap to RUN\n");
		brcm_link_ran(sc, vap);
		return;
	}

	/*
	 * The firmware is joined but net80211 is still in INIT or SCAN (a
	 * join that wpa_supplicant's MLME request could not anchor, or a
	 * scan still running): put net80211 on the BSS from the scan
	 * cache, then finish the walk to RUN here.  The firmware sends one
	 * LINK up per join, so waiting for the next LINK event would wait
	 * forever and wpa_supplicant would time out.
	 */
	if ((vap->iv_state == IEEE80211_S_INIT ||
	    vap->iv_state == IEEE80211_S_SCAN) &&
	    sc->sc_join_ssid_len != 0) {
		int i, rc;

		/*
		 * Stop net80211's scan before joining from its cache.  Calling
		 * sta_join while the scan task is still adding and ageing
		 * entries corrupts the scan list, and the next flush on INIT
		 * panics in sta_flush.
		 */
		if (sc->sc_ic.ic_flags & IEEE80211_F_SCAN) {
			ieee80211_cancel_scan(vap);
			for (i = 0; i < 20 &&
			    (sc->sc_ic.ic_flags & IEEE80211_F_SCAN); i++)
				pause("brcmscx", hz / 20);
			if (sc->sc_ic.ic_flags & IEEE80211_F_SCAN) {
				DPRINTF(sc, 0, "link task: scan would not stop; "
				    "not joining from the cache\n");
				return;
			}
		}
		rc = brcm_sta_join_from_cache(sc);

		DPRINTF(sc, 0, "link task: vap state=%d, "
		    "sta_join_from_cache rc=%d\n", vap->iv_state, rc);
		if (rc != 0) {
			/* Nothing to join to in cache yet.  Kick a scan so
			 * the next LINK up has a populated cache to anchor
			 * the vap walk on. */
			if (vap->iv_state == IEEE80211_S_INIT)
				(void)ieee80211_new_state(vap,
				    IEEE80211_S_SCAN, -1);
			return;
		}
		/* sta_join's walk to AUTH runs on net80211's taskqueue. */
		for (i = 0; i < 20 && !sc->sc_dying && sc->sc_link_up; i++) {
			pause("brcmlnk", hz / 10);
			if (ieee80211_fmac_link_up(&sc->sc_ic, NULL) == 0) {
				DPRINTF(sc, 0, "link task: walked vap to RUN "
				    "after sta_join (%d ms)\n", (i + 1) * 100);
				brcm_link_ran(sc, vap);
				return;
			}
		}
		DPRINTF(sc, 0, "link task: vap never reached AUTH/ASSOC "
		    "after sta_join (state=%d)\n", vap->iv_state);
		return;
	}
	ni = vap->iv_bss;
	DPRINTF(sc, 0,
	    "link task: vap state=%d ni_chan=%p; framework declined "
	    "and no cache fallback applies\n",
	    vap->iv_state, ni ? ni->ni_chan : NULL);
}

/*
 * Install a derived PTK / GTK / WEP key on the chip via
 * the "wsec_key" iovar.  Called from iv_key_set after userspace
 * wpa_supplicant completes the 4-way handshake and hands us the PTK
 * (key_index=0 with peer EA + PRIMARY_KEY flag) and GTK
 * (key_index=1..3 with broadcast EA).  algo=OFF + len=0 clears the
 * slot.
 */
static int
brcm_set_key(struct brcm_softc *sc, uint32_t key_index, uint32_t algo,
    uint32_t flags, const uint8_t *key, uint32_t key_len,
    const uint8_t ea[6])
{
	struct brcm_wsec_key_le wk;
	int error;

	if (key_len > sizeof(wk.data))
		return (EINVAL);

	/*
	 * 164-byte "wsec_key" iovar -- matches Linux brcmf_wsec_key_le
	 * exactly.  Used instead of the 37-byte BRCM_C_SET_KEY=45 dcmd:
	 * BCM43455 fw 7.45.x rejects the legacy dcmd with BCME_BADARG
	 * and only services the iovar form.
	 */
	memset(&wk, 0, sizeof(wk));
	wk.index = htole32(key_index);
	wk.len = htole32(key_len);
	if (key_len > 0 && key != NULL)
		memcpy(wk.data, key, key_len);
	wk.algo = htole32(algo);
	wk.flags = htole32(flags);
	memcpy(wk.ea, ea, 6);

	DPRINTF(sc, 0,
	    "wsec_key: idx=%u len=%u algo=%u flags=0x%x peer=%02x:%02x"
	    ":%02x:%02x:%02x:%02x\n",
	    key_index, key_len, algo, flags,
	    ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);

	error = brcm_iovar_set(sc, "wsec_key", &wk, sizeof(wk));
	DPRINTF(sc, 0, "wsec_key: rc=%d\n", error);
	return (error);
}

/*
 * BRCMF_C_SET_SCB_AUTHORIZE (121) with the AP's MAC.  Linux sends it when
 * cfg80211's change_station marks the peer authorized (wpa_supplicant
 * does that after the 4-way); we send it after the pairwise key.  It
 * tells the chip's data-plane that frames to/from the AP are now authorized
 * (i.e. keys are in place and encryption can run).  Without this
 * the chip drops every data frame even after successful 4-way.
 */
static int
brcm_scb_authorize(struct brcm_softc *sc, const uint8_t ap_mac[6])
{
	uint8_t buf[6];
	int error;

	memcpy(buf, ap_mac, 6);
	error = brcm_dcmd_set(sc, BRCM_C_SET_SCB_AUTHORIZE,
	    buf, sizeof(buf));
	DPRINTF(sc, 0,
	    "scb_authorize: ap=%02x:%02x:%02x:%02x:%02x:%02x rc=%d\n",
	    ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4],
	    ap_mac[5], error);
	return (error);
}

/*
 * FullMAC key hooks.  userspace wpa_supplicant runs the 4-way
 * handshake (because sup_wpa=0 disables the firmware supplicant) and
 * then asks net80211 to install the derived PTK + GTK.  net80211 calls
 * these hooks; we forward the keys to the chip via the "wsec_key" iovar.
 *
 * net80211's IEEE80211_CIPHER_* maps to BRCM_CRYPTO_ALGO_* one-to-one
 * for AES-CCM and TKIP.  WEP is supported for completeness.
 */
static uint32_t
brcm_cipher_to_algo(uint8_t cipher)
{

	switch (cipher) {
	case IEEE80211_CIPHER_AES_CCM:
		return (BRCM_CRYPTO_ALGO_AES_CCM);
	case IEEE80211_CIPHER_TKIP:
		return (BRCM_CRYPTO_ALGO_TKIP);
	case IEEE80211_CIPHER_WEP:
		return (BRCM_CRYPTO_ALGO_WEP1);
	default:
		return (BRCM_CRYPTO_ALGO_OFF);
	}
}

/*
 * net80211 vap clone hook.  Returns a freshly-minted ieee80211vap
 * wrapper; we chain the parent's iv_newstate through bv_newstate so
 * the brcm hook can intercept transitions and push them to the
 * firmware before falling through to the net80211 default.
 */
/*
 * Give the firmware the vap's address.  A FullMAC chip builds and filters
 * frames on the chip from its cur_etheraddr, so a vap created with an
 * address of its own (wlan create ... wlanaddr, which lagg(4) failover
 * needs so the wired and wireless ports share one) does nothing until the
 * firmware has it.  Written on every create, which also puts the factory
 * address back after an override.
 */
static void
brcm_set_fw_macaddr(struct brcm_softc *sc,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	uint8_t cur[IEEE80211_ADDR_LEN];
	size_t len = sizeof(cur);
	uint32_t v = 0;
	int error;

	if (brcm_iovar_get(sc, "cur_etheraddr", cur, &len) == 0 &&
	    len >= sizeof(cur) && IEEE80211_ADDR_EQ(cur, mac))
		return;
	/*
	 * Change it with the WLC down.  Linux sets cur_etheraddr directly;
	 * the DOWN/UP around it is our own: changed with the radio up, this
	 * firmware kept join state from the old address, and joins from the
	 * new one timed out authenticating.
	 */
	(void)brcm_dcmd_set(sc, BRCM_C_DOWN, &v, sizeof(v));
	error = brcm_iovar_set(sc, "cur_etheraddr", mac, IEEE80211_ADDR_LEN);
	(void)brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));
	if (error != 0)
		device_printf(sc->sc_dev, "vap: setting cur_etheraddr %6D "
		    "failed (%d); the chip keeps its own address\n", mac, ":",
		    error);
	else if (!IEEE80211_ADDR_EQ(mac, sc->sc_macaddr))
		device_printf(sc->sc_dev, "vap: using address %6D in place of "
		    "the chip's %6D\n", mac, ":", sc->sc_macaddr, ":");
}

static struct ieee80211vap *
brcm_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct brcm_softc *sc = ic->ic_softc;
	struct brcm_vap *bv;
	struct ieee80211vap *vap;

	if (!TAILQ_EMPTY(&ic->ic_vaps))
		return (NULL);

	bv = malloc(sizeof(*bv), M_BRCM, M_WAITOK | M_ZERO);
	vap = &bv->bv_vap;
	if (ieee80211_vap_setup(ic, vap, name, unit, opmode,
	    flags | IEEE80211_CLONE_NOBEACONS, bssid) != 0) {
		free(bv, M_BRCM);
		return (NULL);
	}

	bv->bv_newstate = vap->iv_newstate;
	vap->iv_newstate = brcm_newstate;

	brcm_set_fw_macaddr(sc, mac);

	/*
	 * FullMAC: the firmware monitors the BSS and reports LINK-down
	 * when the AP is genuinely gone.  net80211's default software
	 * beacon-miss timer would otherwise fire ~1s after RUN (this
	 * driver never feeds beacons up to net80211), and with
	 * ROAMING_AUTO that drives a reassociate (RUN->ASSOC) which
	 * tears the link down mid-connection.  Disable swbmiss and mark
	 * roaming as driver-controlled so the firmware owns BSS
	 * monitoring and roaming.
	 */
	vap->iv_flags_ext &= ~IEEE80211_FEXT_SWBMISS;
	vap->iv_roaming = IEEE80211_ROAMING_DEVICE;

	/*
	 * Hand vap-level slots to the FullMAC framework.  fmac_newstate
	 * intercepts AUTH/ASSOC and side-effect-dispatches the join via
	 * fmop_assoc, then chains to brcm_newstate (the saved hook).
	 * fmac_key_set / fmac_key_delete forward straight into the
	 * fmop_set_key / fmop_del_key ops; the chip-side dispatch lives
	 * in brcm_fmop_*.
	 */
	ieee80211_fmac_vap_attach(vap);

	/*
	 * Wire the standard net80211 ifmedia callbacks.  With NULL
	 * media_status wpa_supplicant's BSD driver bails at
	 * SIOCGIFMEDIA with "Programming error" and never runs a
	 * scan, and the kernel logs `wlan0: ifmedia_ioctl: ifm_status
	 * is NULL; please fix miibus/driver order`.  wlan.ko exports
	 * both functions, and userland tools rely on them being wired.
	 */
	ieee80211_vap_attach(vap, ieee80211_media_change,
	    ieee80211_media_status, mac);
	ic->ic_opmode = opmode;
	return (vap);
}

/*
 * Leave the current network now, telling the AP: WLC_DISASSOC with reason
 * 3 (deauthenticated because the station is leaving) to the BSS we are
 * joined to.  Without it, taking wlan0 down or destroying it leaves the
 * firmware, and so the AP, still associated, and the next join to that AP
 * starts from stale state on both sides.  Synchronous: callers can sleep
 * and need it done before they go on.
 */
static void
brcm_leave(struct brcm_softc *sc, const struct ieee80211vap *vap)
{
	struct brcm_scb_val_le sv;
	int error;

	if (!sc->sc_link_up)
		return;
	memset(&sv, 0, sizeof(sv));
	sv.val = htole32(IEEE80211_REASON_AUTH_LEAVE);
	if (vap != NULL && vap->iv_bss != NULL)
		memcpy(sv.ea, vap->iv_bss->ni_bssid, sizeof(sv.ea));
	error = brcm_dcmd_set(sc, BRCM_C_DISASSOC, &sv, sizeof(sv));
	DPRINTF(sc, 0, "leave: WLC_DISASSOC rc=%d\n", error);
	sc->sc_join_busy = 0;
}

/* tear down a virtual wifi interface */
static void
brcm_vap_delete(struct ieee80211vap *vap)
{
	struct brcm_vap *bv = BRCM_VAP(vap);

	brcm_leave(vap->iv_ic->ic_softc, vap);
	ieee80211_vap_detach(vap);
	free(bv, M_BRCM);
}

/*
 * The interface went up or down; net80211 calls this from its taskqueue,
 * so it may sleep.  When the last running vap goes down, leave the
 * network (so "ifconfig wlan0 down" deauthenticates from the AP instead
 * of leaving the firmware joined) and take the radio down with WLC_DOWN.
 * The first one up brings the radio back with WLC_UP.  The firmware
 * stays loaded throughout, so coming back is quick.  Linux brcmfmac
 * likewise disconnects in ndo_stop, but it does not send WLC_DOWN; it
 * sends WLC_UP once, when the dongle is configured on open.
 */
static void
brcm_parent(struct ieee80211com *ic)
{
	struct brcm_softc *sc = ic->ic_softc;
	uint32_t v = htole32(1);
	int error;

	if (sc->sc_dying)
		return;
	if (ic->ic_nrunning == 0) {
		brcm_leave(sc, TAILQ_FIRST(&ic->ic_vaps));
		if (!sc->sc_wlc_up)
			return;
		error = brcm_dcmd_set(sc, BRCM_C_DOWN, &v, sizeof(v));
		DPRINTF(sc, 0, "parent: last vap down; WLC_DOWN rc=%d\n",
		    error);
		if (error == 0)
			sc->sc_wlc_up = false;
	} else if (!sc->sc_wlc_up) {
		error = brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));
		DPRINTF(sc, 0, "parent: vap up; WLC_UP rc=%d\n", error);
		if (error == 0)
			sc->sc_wlc_up = true;
	}
}

/* hand a data frame to the transport to send */
/*
 * net80211 hands ic_transmit 802.11-encapsulated frames (802.11 header +
 * RFC1042 LLC/SNAP); FullMAC firmware takes plain 802.3 and does its own
 * encapsulation.  Convert back.  The same as brcm_pci_deencap_80211, which
 * the PCI transport keeps; the SDIO and USB transports use this one.  The
 * firmware cannot parse 802.11 frames sent as if they were Ethernet, and
 * wpa_supplicant's 4-way replies would never reach the AP.
 *
 * 0 with *mp rewritten to 802.3; EAGAIN for a management/control frame
 * (the firmware runs MLME: drop it); or an errno if the mbuf could not be
 * made contiguous (*mp is then NULL).
 */
int
brcm_deencap_80211(struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct ieee80211_frame *wh;
	uint8_t dst[6], src[6];
	uint8_t *eh;
	const uint8_t *snap;
	uint16_t etype;
	int hdrlen;

	if (m->m_len < sizeof(struct ieee80211_frame) &&
	    (m = m_pullup(m, sizeof(struct ieee80211_frame))) == NULL) {
		*mp = NULL;
		return (ENOMEM);
	}
	wh = mtod(m, struct ieee80211_frame *);
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_DATA) {
		/* Management/control frame: the firmware runs its own MLME. */
		*mp = m;
		return (EAGAIN);
	}
	hdrlen = ieee80211_hdrsize(wh);
	/* Need the 802.11 header + 8-byte LLC/SNAP contiguous. */
	if (m->m_len < hdrlen + 8 &&
	    (m = m_pullup(m, hdrlen + 8)) == NULL) {
		*mp = NULL;
		return (ENOMEM);
	}
	wh = mtod(m, struct ieee80211_frame *);
	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_TODS:		/* STA uplink (normal case) */
		IEEE80211_ADDR_COPY(dst, wh->i_addr3);
		IEEE80211_ADDR_COPY(src, wh->i_addr2);
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		IEEE80211_ADDR_COPY(dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(src, wh->i_addr3);
		break;
	default:				/* NODS */
		IEEE80211_ADDR_COPY(dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(src, wh->i_addr2);
		break;
	}
	/* RFC1042 SNAP: aa aa 03 00 00 00 <ethertype:2>. */
	snap = mtod(m, const uint8_t *) + hdrlen;
	etype = ((uint16_t)snap[6] << 8) | snap[7];
	/* Collapse (802.11 header + SNAP) into a 14-byte ethernet header. */
	m_adj(m, (hdrlen + 8) - ETHER_HDR_LEN);
	eh = mtod(m, uint8_t *);
	IEEE80211_ADDR_COPY(eh, dst);
	IEEE80211_ADDR_COPY(eh + 6, src);
	eh[12] = etype >> 8;
	eh[13] = etype & 0xff;
	*mp = m;
	return (0);
}

static int
brcm_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	struct brcm_softc *sc = ic->ic_softc;

	return (sc->sc_bus_ops->bs_txdata(sc, m));
}

/*
 * A raw 802.11 frame from net80211: probe requests from its software
 * scan, and the like.  A FullMAC chip builds and sends its own
 * management frames, and the transports' data path only carries 802.3,
 * so complete the frame as sent and drop it.  Passing it on would be
 * wrong twice over: the chip cannot use it, and on SDIO the send sleeps
 * in the MMC stack while net80211's scan task holds the com lock, which
 * panics ("sleeping thread holds brcm0_com_lock").
 * ieee80211_tx_complete frees the mbuf and the node reference
 * ieee80211_raw_output took.
 */
static int
brcm_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params __unused)
{
	ieee80211_tx_complete(ni, m, 0);
	return (0);
}

/*
 * Build a broadcast passive escan request and shove it at the
 * firmware via the "escan" iovar.  All-channel walk + zero SSID list
 * = "find every AP you can hear."  The firmware emits an
 * ESCAN_RESULT event per BSS discovered, then a terminating
 * ESCAN_RESULT with status=SUCCESS.
 */
static int
brcm_dispatch_scan(struct brcm_softc *sc)
{
	struct brcm_escan_params_v0 params;
	int err;

	/*
	 * Refuse if a scan is already in flight.  Same guard as
	 * brcm_sdio_sysctl_cmd_scan but at the brcm_softc layer so
	 * BOTH the fmop_scan_start path (this function) and the
	 * cmd_scan sysctl share state.  Mirrors Linux brcmfmac's
	 * BRCMF_SCAN_STATUS_BUSY (cfg80211.c:1524) returning
	 * -EAGAIN.  Without it, three back-to-back
	 * `ifconfig wlan0 scan` invocations push three escan iovars
	 * to the chip and panic the kernel as their ESCAN_RESULT
	 * streams interleave through the SDPCM ctl path.
	 *
	 * Cleared by the terminator ESCAN_RESULT (any non-PARTIAL
	 * status) routed through brcm_handle_event, mirroring
	 * brcmf_notify_escan_complete.
	 */
	if (sc->sc_scan_busy)
		return (EAGAIN);
	sc->sc_scan_busy = 1;

	memset(&params, 0, sizeof(params));
	memset(params.scan_params.bssid, 0xff,
	    sizeof(params.scan_params.bssid));
	params.scan_params.bss_type = BRCM_DOT11_BSSTYPE_ANY;
	params.scan_params.scan_type = BRCM_SCANTYPE_PASSIVE;
	params.scan_params.nprobes = htole32((uint32_t)-1);
	params.scan_params.active_time = htole32((uint32_t)-1);
	params.scan_params.passive_time = htole32((uint32_t)-1);
	params.scan_params.home_time = htole32((uint32_t)-1);
	params.scan_params.channel_num = 0;	/* all channels */

	params.version = htole32(BRCM_ESCAN_REQ_VERSION);
	params.action = htole16(BRCM_WL_ESCAN_ACTION_START);
	params.sync_id = htole16(0x1234);

	err = brcm_iovar_set(sc, "escan", &params, sizeof(params));
	if (err != 0) {
		sc->sc_scan_busy = 0;	/* fw rejected; nothing to wait for */
		return (err);
	}

	/*
	 * Pump rx synchronously until the terminator ESCAN_RESULT
	 * clears sc_scan_busy (or 3 s elapse).  Required because
	 * SDIO has no async rx thread — events only get processed
	 * inside an rx_frames poll.  Without this the caller returns
	 * before any ESCAN_RESULT is delivered and the scan cache
	 * stays empty AND sc_scan_busy stays set, rejecting the next
	 * scan request with EAGAIN forever.
	 */
	if (sc->sc_bus_ops->bs_pump_rx != NULL)
		sc->sc_bus_ops->bs_pump_rx(sc, 3000, &sc->sc_scan_busy);
	if (sc->sc_scan_busy)
		sc->sc_scan_busy = 0;	/* pump timed out; force-clear */
	return (0);
}

/* switch the radio to a channel (not yet implemented) */
static void
brcm_set_channel(struct ieee80211com *ic)
{
	/* TODO: BRCM_C_SET_CHANNEL.  Needs HW. */
	(void)ic;
}

/*
 * Promiscuous-mode and multicast-filter callbacks.  Called from
 * net80211's update_promisc / update_mcast taskqueue entrypoints
 * (ieee80211_proto.c:1832-1846) -- safe to sleep, BCDC iovars OK.
 *
 * What Linux does (brcmfmac/core.c:_brcmf_set_multicast_list):
 *   - mcast_list iovar:  list of host's multicast group MAC addresses
 *     so chip RXes their frames.  Payload = {u32 count; u8 mac[count][6];}.
 *   - allmulti iovar:    bool; if true chip RXes ALL multicast (promisc
 *     subset).  Linux sets it from IFF_ALLMULTI, and forces it on if
 *     mcast_list is rejected.
 *   - cmd 10 SET_PROMISC: full promisc mode toggle.
 *
 * We always send allmulti=1 (cheap, chip RXes all multicast), and let
 * SET_PROMISC reflect IFF_PROMISC.  Per-group mcast_list filtering
 * would be an optimisation; the chip-side packet count with
 * allmulti=1 is small enough not to need it.
 *
 * BCME_UNSUPPORTED on SET_PROMISC is OK -- chip just doesn't support
 * it; we already filter by MAC at the chip via cur_etheraddr.
 */
static void
brcm_update_promisc(struct ieee80211com *ic)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);
	uint32_t v;
	int error;

	if (vap == NULL || vap->iv_ifp == NULL)
		return;
	v = htole32((if_getflags(vap->iv_ifp) & IFF_PROMISC) ? 1 : 0);
	error = brcm_dcmd_set(sc, 10 /* BRCM_C_SET_PROMISC */,
	    &v, sizeof(v));
	DPRINTF(sc, 1, "SET_PROMISC=%u rc=%d\n", le32toh(v), error);
}

/* update the chip's multicast reception setting */
static void
brcm_update_mcast(struct ieee80211com *ic)
{
	struct brcm_softc *sc = ic->ic_softc;
	uint32_t v;
	int error;

	v = htole32(1);	/* always-on multicast pass-through */
	error = brcm_iovar_set(sc, "allmulti", &v, sizeof(v));
	DPRINTF(sc, 1, "allmulti=1 rc=%d\n", error);
}

/*
 * Decode the pre-2014 Broadcom chanspec encoding used by the 43236
 * firmware blob.  bits[15:12] = band (1 = 5 GHz, 2 = 2.4 GHz),
 * bits[7:0] = channel number.  Newer firmware uses a different layout
 * (band in the top 2 bits); see below for how both are handled.
 */
bool
brcm_chanspec_is_5ghz(uint16_t chanspec)
{
	uint8_t chan = (uint8_t)(chanspec & 0xff);

	/*
	 * Two encodings in the wild:
	 *  - Pre-2014 (BCM43236-era): band lives in bits 15-12,
	 *    0x1000 = 5G, 0x2000 = 2G.
	 *  - Modern (BCM43455 fw 7.45.x):
	 *    band in bits 15-14, 0xc000 = 5G, 0x0000 = 2G;
	 *    chanspecs in this scheme look like 0x10xx for 2.4 GHz
	 *    (e.g. 0x1001 for ch 1, 0x1002 for ch 2) where the
	 *    high nibble is BW + sideband, not band.
	 *
	 * Rather than guess which encoding fw is using, derive the
	 * band from the channel number (1-14 = 2.4G, 36+ = 5G).
	 * channel numbers are unambiguous within the regulatory
	 * domain and what `ieee80211_ieee2mhz` actually needs.
	 */
	if (chan >= 1 && chan <= 14)
		return (false);
	if (chan >= 36)
		return (true);
	/* Fall back to the legacy bit pattern for unknown channels. */
	return ((chanspec & 0xf000) == 0x1000);
}

/* pull the channel number out of a chanspec */
uint8_t
brcm_chanspec_to_chan(uint16_t chanspec)
{

	return ((uint8_t)(chanspec & 0xff));
}

/*
 * Compute a Broadcom d11ac chanspec from an IEEE channel number.
 * Used when building bsscfg:join ext_assoc_params for a target AP
 * whose ni_chan->ic_ieee we know.  Format (per Linux brcmu_d11ac):
 *   [15:14] band: 00 = 2.4 GHz, 11 = 5 GHz
 *   [13:11] bw:   010 = 20 MHz (we only set 20 here; chip will
 *                 negotiate wider with the AP via HT/VHT IEs)
 *   [10:8]  sb:   000 = none (control = center for 20 MHz)
 *   [7:0]   channel number
 *
 * Examples: ch1/2.4G/20MHz = 0x1001; ch36/5G/20MHz = 0xd024.
 */
uint16_t
brcm_chan_to_chanspec_d11ac(uint8_t chan)
{
	uint16_t chanspec = chan;

	chanspec |= 0x1000;	/* 20 MHz */
	if (chan >= 36)
		chanspec |= 0xc000;	/* 5 GHz band */
	return (chanspec);
}

/*
 * D11N chanspec for pre-2014 firmware (BCM43143 / BCM43236 / BCM43242).
 * Layout (Linux brcmu_d11.h, brcmu_d11n_encchspec):
 *   [13:12] band: 0x2000 = 2.4 GHz, 0x1000 = 5 GHz
 *   [11:10] bw:   0x0800 = 20 MHz  (wider negotiated via HT IEs)
 *   [9:8]   sb:   0x0300 = none; brcmu_d11n_encchspec sets it for every
 *                 20 MHz channel (0x0100 and 0x0200 are the 40 MHz
 *                 control sidebands)
 *   [7:0]   channel number
 *
 * Examples: ch9/2.4G/20MHz = 0x2b09; ch36/5G/20MHz = 0x1b24.  The
 * BCM43236b rejects SET_SSID with BCME_BADCHAN (-20) when the sideband
 * is left at 00 (0x2809), and likewise for the D11AC value 0x1009.
 */
uint16_t
brcm_chan_to_chanspec_d11n(uint8_t chan)
{
	uint16_t chanspec = chan;

	chanspec |= 0x0800;	/* 20 MHz */
	chanspec |= 0x0300;	/* no sideband: the only one a 20 MHz channel has */
	if (chan >= 36)
		chanspec |= 0x1000;	/* 5 GHz */
	else
		chanspec |= 0x2000;	/* 2.4 GHz */
	return (chanspec);
}

/*
 * Dispatcher: pick the encoder that matches the firmware this chip runs.
 * Falls back to D11AC when sc_chip is unset (SDIO recipe path, or an
 * unrecognized chip that reached attach anyway).
 */
uint16_t
brcm_chan_to_chanspec(struct brcm_softc *sc, uint8_t chan)
{
	if (sc->sc_chip != NULL && sc->sc_chip->d11n)
		return (brcm_chan_to_chanspec_d11n(chan));
	return (brcm_chan_to_chanspec_d11ac(chan));
}

/* report which channels the radio supports */
static void
brcm_getradiocaps(struct ieee80211com *ic, int maxchans, int *nchans,
    struct ieee80211_channel chans[])
{
	static const uint8_t unii_1[] = { 36, 40, 44, 48 };
	static const uint8_t unii_2[] = { 52, 56, 60, 64 };
	static const uint8_t unii_2_ext[] = {
	    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
	};
	static const uint8_t unii_3[] = { 149, 153, 157, 161, 165 };
	uint8_t bands[IEEE80211_MODE_BYTES];

	(void)ic;
	memset(bands, 0, sizeof(bands));
	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11G);
	*nchans = 0;
	ieee80211_add_channels_default_2ghz(chans, maxchans, nchans,
	    bands, 0);

	memset(bands, 0, sizeof(bands));
	setbit(bands, IEEE80211_MODE_11A);
	ieee80211_add_channel_list_5ghz(chans, maxchans, nchans,
	    unii_1, nitems(unii_1), bands, 0);
	ieee80211_add_channel_list_5ghz(chans, maxchans, nchans,
	    unii_2, nitems(unii_2), bands, 0);
	ieee80211_add_channel_list_5ghz(chans, maxchans, nchans,
	    unii_2_ext, nitems(unii_2_ext), bands, 0);
	ieee80211_add_channel_list_5ghz(chans, maxchans, nchans,
	    unii_3, nitems(unii_3), bands, 0);
}

/*
 * FullMAC ops table.  Each op drives the underlying dcmd / iovar.
 *
 * ENXIO is the agreed "I declined this op; framework, fall
 * through to the saved hook" sentinel.  Any other non-zero return
 * propagates to the caller as a real error.
 */
static int
brcm_fmop_scan_start(struct ieee80211com *ic,
    const uint8_t *ssid __unused, size_t ssidlen __unused,
    bool active __unused)
{
	struct brcm_softc *sc = ic->ic_softc;
	uint32_t v;
	int error;

	/*
	 * Bring the WLC layer up first if nothing has yet.
	 *
	 * Firmware refuses a scan with BCME_NOTUP (-4) until it has seen
	 * BRCM_C_UP, and nothing else on the net80211 path issues it.
	 * The fullmac ops have no "interface up" hook, and the join paths
	 * that do issue UP cannot run first, because associating needs
	 * scan results.  Without this a freshly created wlan0 comes up,
	 * reports no carrier and returns an empty scan list forever, the
	 * only clue being a status=-4 on the scan DCMD completion.
	 *
	 * Doing it here rather than adding an op puts it where the
	 * failure is: this is the first thing net80211 asks the chip to
	 * do that firmware can refuse for being down.
	 */
	if (!sc->sc_wlc_up) {
		v = htole32(1);
		error = brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));
		if (error != 0) {
			device_printf(sc->sc_dev,
			    "scan_start: WLC_UP failed rc=%d\n", error);
			return (error);
		}
		sc->sc_wlc_up = true;
		DPRINTF(sc, 0, "scan_start: WLC_UP issued\n");
	}

	return (brcm_dispatch_scan(sc));
}

/*
 * Configure chip for WPA2 with HOST-side EAPOL.  Used when net80211
 * (or wpa_supplicant via net80211) requests a WPA-protected assoc
 * but no PSK was staged via dev.brcm.<n>.wpa_pmk -- meaning the
 * 4-way handshake will run in userspace, not in firmware.
 *
 * Differs from brcm_join_wpa2_raw in two ways:
 *   - Skips sup_wpa (in-firmware supplicant enable).  BCM43455 fw
 *     7.45.x returns BCME_UNSUPPORTED on it anyway.
 *   - Skips wsec_pmk install entirely.  Host will install PTK/GTK
 *     via iv_key_set -> brcm_fmop_set_key after the 4-way completes.
 *
 * Chip-side: SET_INFRA + SET_AUTH(OPEN) + wsec=AES + wpa_auth=
 * WPA2_PSK + UP + SET_SSID.  Chip then does OPEN auth + ASSOC with
 * RSN IE; AP sends EAPOL M1 as a regular DATA frame (ethertype
 * 0x888e); chip emits BRCM_E_EAPOL_MSG event; brcm_handle_event
 * forwards via ieee80211_fmac_eapol_rx -> ieee80211_vap_deliver_data
 * -> BPF where wpa_supplicant picks it up.
 */
static int
brcm_join_wpa2_host_eapol(struct brcm_softc *sc, struct ieee80211vap *vap)
{
	struct brcm_ext_join_params ejp;
	struct ieee80211_node *ni;
	size_t join_params_size;
	uint16_t chanspec;
	uint8_t slen, chan;
	uint32_t v;
	int error;

	if (brcm_join_busy_acquire(sc, "host_eapol"))
		return (EAGAIN);
	ni = vap->iv_bss;
	if (ni == NULL) {
		sc->sc_join_busy = 0;
		return (EINVAL);
	}

	slen = ni->ni_esslen;
	if (slen > BRCM_MAX_SSID_LEN)
		slen = BRCM_MAX_SSID_LEN;

	/*
	 * BCM43455 fw requires DOWN/UP around wsec + wpa_auth for
	 * the new values to actually take effect (returns BCME_BADARG
	 * if changed while data plane is up).  The chip's internal
	 * BSS table from a prior scan survives DOWN/UP -- it's the
	 * RUN-state machinery that resets, not the cache.
	 */
#define	HOSTEAP_RC(iovar_or_cmd, call)					\
	do {								\
		int _rc = (call);					\
		DPRINTF(sc, 0, "host-EAPOL: " iovar_or_cmd " rc=%d\n",	\
		    _rc);						\
	} while (0)

	/*
	 * DOWN before iovar block.  The chip-supplicant path
	 * (brcm_join_wpa2_raw) does DOWN->iovars->UP->join and
	 * AUTH+ASSOC succeed; without the DOWN/UP wrap here host-EAPOL
	 * gets AUTH status=2 TIMEOUT.  The wpaie, double wpa_auth,
	 * cmd 205 and mfp/join_pref iovars below are compatible with
	 * the DOWN/UP wrap.
	 */
	v = htole32(0);
	(void)brcm_dcmd_set(sc, BRCM_C_DOWN, &v, sizeof(v));
	DPRINTF(sc, 0, "host-EAPOL: DOWN\n");

	/*
	 * bs_flowring_purge is deliberately not called here: purging at
	 * this point breaks DHCP against a freshly restarted AP (the STA
	 * associates and the 4-way appears to complete, but DHCPDISCOVER
	 * never gets an OFFER and hostapd disassociates).  The purge
	 * itself works (dev.brcm_pci.N.delete_flowring); calling it here
	 * is the wrong place.  The cause is not yet understood, likely
	 * M4/M2 racing the PTK install on the fresh TID-7 ring, so the
	 * hook stays in bus_ops until a better trigger point is found.
	 */

	v = htole32(1);
	HOSTEAP_RC("SET_INFRA",
	    brcm_dcmd_set(sc, BRCM_C_SET_INFRA, &v, sizeof(v)));

	/*
	 * wpaie iovar - required together with the rest of the sequence
	 * (double wpa_auth write, cmd 205, bsscfg:join).
	 *
	 * The RSN IE we send here MUST byte-for-byte match the IE
	 * wpa_supplicant will send in M2 EAPOL / assoc-req.  Prefer the
	 * exact bytes wpa_supplicant deposited into iv_appie_wpa via
	 * IEEE80211_IOC_APPIE(IEEE80211_APPIE_WPA); fall back to a
	 * WPA2-PSK+CCMP+MFPC template only if none was set.
	 *
	 * Also: whether wpa_supplicant advertises MFPC in that IE tells
	 * us whether to set the mfp iovar to CAPABLE — the fw uses that
	 * to include MFP fields in its own beacon-frame processing so
	 * BIP-CMAC-128 mgmt-frame encryption can be negotiated.
	 */
	{
		const uint8_t *rsn_ie = NULL;
		size_t rsn_ie_len = 0;
		uint32_t mfp = BRCM_MFP_NONE;
		static const uint8_t wpa2_psk_ccmp_rsn_ie[] = {
			0x30, 0x14, 0x01, 0x00,
			0x00, 0x0f, 0xac, 0x04,
			0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
			0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
			0x0c, 0x00,
		};

		if (vap->iv_appie_wpa != NULL &&
		    vap->iv_appie_wpa->ie_len > 4) {
			rsn_ie = vap->iv_appie_wpa->ie_data;
			rsn_ie_len = vap->iv_appie_wpa->ie_len;
			/*
			 * Walk the RSN IE to find the RSN capabilities word
			 * and translate MFPC (0x0080) / MFPR (0x0040) into
			 * BRCM_MFP_CAPABLE / BRCM_MFP_REQUIRED.  Layout is
			 * tag(1) len(1) ver(2) group(4) pcnt(2)
			 * pcs(4*pcnt) akmcnt(2) akm(4*akmcnt) caps(2)
			 * ... optional pmkid + group_mgmt after caps.  Send
			 * REQUIRED when the caller's IE has MFPR set,
			 * CAPABLE when only MFPC is set, otherwise NONE.
			 * Fw uses the mfp iovar as its own required/optional
			 * gate during 4-way; a MFP-required AP will reject
			 * an assoc that only advertises MFP_CAPABLE.
			 */
			if (rsn_ie_len >= 10) {
				size_t pcnt = rsn_ie[8] |
				    ((size_t)rsn_ie[9] << 8);
				size_t off = 10 + 4 * pcnt;
				if (off + 2 <= rsn_ie_len) {
					size_t akmcnt = rsn_ie[off] |
					    ((size_t)rsn_ie[off + 1] << 8);
					size_t ai;
					/*
					 * Scan the AKM list for AKM=18 (OWE,
					 * RFC 8110).  BCM43602 fw v7.35.177.61
					 * predates RFC 8110 and has no OWE
					 * support; if userspace tries to join
					 * an OWE-only network the fw would
					 * either reject the AKM or silently
					 * fall back to open (unencrypted).
					 * Log it here so the failure mode is
					 * discoverable in dmesg instead of a
					 * mystery post-assoc data-plane silence.
					 */
					for (ai = 0; ai < akmcnt &&
					    off + 2 + 4 * (ai + 1) <=
					    rsn_ie_len; ai++) {
						const uint8_t *akm =
						    &rsn_ie[off + 2 + 4 * ai];
						if (akm[0] == 0x00 &&
						    akm[1] == 0x0f &&
						    akm[2] == 0xac &&
						    akm[3] == 18) {
							device_printf(
							    sc->sc_dev,
							    "wpaie: OWE AKM "
							    "(00-0f-ac-18) in "
							    "RSN — fw has no "
							    "OWE support "
							    "(BCM43602 fw "
							    "predates RFC "
							    "8110); assoc "
							    "will fail\n");
						}
					}
					off += 2 + 4 * akmcnt;
					if (off + 2 <= rsn_ie_len) {
						uint16_t caps = rsn_ie[off] |
						    ((uint16_t)rsn_ie[off + 1]
						    << 8);
						if (caps & 0x0040)
							mfp =
							  BRCM_MFP_REQUIRED;
						else if (caps & 0x0080)
							mfp =
							  BRCM_MFP_CAPABLE;
					}
				}
			}
		} else {
			rsn_ie = wpa2_psk_ccmp_rsn_ie;
			rsn_ie_len = sizeof(wpa2_psk_ccmp_rsn_ie);
		}
		/* WPA3-SAE requires MFP by spec — force REQUIRED. */
		if (sc->sc_sae_join)
			mfp = BRCM_MFP_REQUIRED;

		DPRINTF(sc, 1,
		    "wpaie source=%s len=%zu mfp=%u\n",
		    (vap->iv_appie_wpa != NULL) ? "iv_appie_wpa" : "default",
		    rsn_ie_len, mfp);
		HOSTEAP_RC("wpaie",
		    brcm_iovar_set(sc, "wpaie", rsn_ie, rsn_ie_len));

		{
			uint32_t mfpv = htole32(mfp);
			HOSTEAP_RC("mfp",
			    brcm_iovar_set(sc, "mfp", &mfpv, sizeof(mfpv)));
		}
	}

	/*
	 * Use the BRCM_C_SET_AUTH dcmd (cmd 22) for auth, NOT the "auth"
	 * iovar -- the chip-supplicant path (brcm_join_wpa2_raw) succeeds
	 * with the dcmd form.
	 */
	v = htole32(BRCM_AUTH_OPEN);
	HOSTEAP_RC("SET_AUTH dcmd",
	    brcm_dcmd_set(sc, BRCM_C_SET_AUTH, &v, sizeof(v)));

	/*
	 * Linux brcmfmac writes wpa_auth TWICE around wsec/mfp:
	 *   1) 0xc0 = WPA2_UNSPEC | WPA2_PSK  (set_wpa_version)
	 *   2) 0x80 = WPA2_PSK                (set_key_mgmt, after mfp)
	 * The first pass seems to prep the fw's MFP state machine — see
	 * the on-air trace of an identical BCM43602 + fw v7.35.177.61
	 * on Linux brcmfmac connecting to an MFP-capable AP
	 * (docs/LINUX_MFP_IOVAR_TRACE.md).  Without
	 * the first pass, SET_SSID / bsscfg:join returns FAIL(1) when
	 * the mfp iovar is nonzero.
	 */
	if (sc->sc_sae_join) {
		/*
		 * WPA3-SAE (fw offload).  Fw runs the SAE exchange, derives
		 * the PMK, and hands us LINK-up with fw's own supplicant.
		 * SET_WSEC_PMK below carries the plaintext password with
		 * PASSPHRASE flag — same shape as WPA2, different AKM.
		 */
		v = htole32(BRCM_WPA_AUTH_WPA3_SAE_PSK);
		HOSTEAP_RC("wpa_auth=0x40000(SAE)",
		    brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v)));

		v = htole32(BRCM_WSEC_AES);
		HOSTEAP_RC("wsec", brcm_iovar_set(sc, "wsec", &v, sizeof(v)));

		/* Second wpa_auth pass — keep SAE AKM. */
		v = htole32(BRCM_WPA_AUTH_WPA3_SAE_PSK);
		HOSTEAP_RC("wpa_auth=0x40000(SAE-final)",
		    brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v)));
	} else {
		v = htole32(BRCM_WPA_AUTH_WPA2_UNSPEC | BRCM_WPA_AUTH_WPA2_PSK);
		HOSTEAP_RC("wpa_auth=0xc0(first)",
		    brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v)));

		v = htole32(BRCM_WSEC_AES);
		HOSTEAP_RC("wsec", brcm_iovar_set(sc, "wsec", &v, sizeof(v)));

		/* Second wpa_auth pass = final AKM (plain WPA2_PSK). */
		v = htole32(BRCM_WPA_AUTH_WPA2_PSK);
		HOSTEAP_RC("wpa_auth=0x80(final)",
		    brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v)));
	}

	/*
	 * UP before the join dispatch.  Chip must be UP for the join
	 * state machine to start AUTH.
	 */
	v = htole32(1);
	(void)brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));
	sc->sc_wlc_up = true;
	DPRINTF(sc, 0, "host-EAPOL: UP\n");

	/*
	 * Push the PMK / passphrase to fw via the 132-byte SAE-capable
	 * form of SET_WSEC_PMK.  Linux pushes the PMK only for
	 * firmware-supplicant joins (FWSUP_PSK / SAE); we push it here as
	 * well, empirically.  The 4-way still runs in userspace either way.
	 */
	if (sc->sc_wpa_set || sc->sc_wpa_pmk_raw_set) {
		struct brcm_wsec_pmk_le wp;
		size_t klen;
		int rc;

		memset(&wp, 0, sizeof(wp));
		if (sc->sc_wpa_pmk_raw_set) {
			klen = BRCM_WSEC_MAX_PSK_LEN;
			wp.key_len = htole16((uint16_t)klen);
			wp.flags = 0;
			memcpy(wp.key, sc->sc_wpa_pmk_raw, klen);
		} else {
			klen = strlen(sc->sc_wpa_pmk);
			if (klen < 8 || klen > BRCM_WSEC_MAX_PSK_LEN)
				klen = 0;
			wp.key_len = htole16((uint16_t)klen);
			wp.flags = htole16(BRCM_WSEC_PASSPHRASE);
			memcpy(wp.key, sc->sc_wpa_pmk, klen);
		}
		if (klen > 0) {
			rc = brcm_dcmd_set(sc, BRCM_C_SET_WSEC_PMK, &wp,
			    sizeof(wp));
			DPRINTF(sc, 0,
			    "host-EAPOL: SET_WSEC_PMK(132) rc=%d klen=%zu\n",
			    rc, klen);
		}
	}

	/*
	 * join_pref: prefer 5GHz by RSSI boost + fall through to RSSI.
	 * Matches Linux brcmf_c_set_joinpref_default (called during
	 * connect via brcmf_set_join_pref → default path).  Not strictly
	 * required for association but fw expects to see it before
	 * bsscfg:join for MFP-negotiated joins.
	 */
	{
		struct brcm_join_pref_params jp[2];
		int rc;

		memset(jp, 0, sizeof(jp));
		jp[0].type = BRCM_JOIN_PREF_RSSI_DELTA;
		jp[0].len = 2;
		jp[0].rssi_gain = BRCM_JOIN_PREF_RSSI_BOOST;
		jp[0].band = BRCM_WLC_BAND_5G;
		jp[1].type = BRCM_JOIN_PREF_RSSI;
		jp[1].len = 2;
		jp[1].rssi_gain = 0;
		jp[1].band = 0;
		rc = brcm_iovar_set(sc, "join_pref", jp, sizeof(jp));
		DPRINTF(sc, 0, "host-EAPOL: join_pref rc=%d\n", rc);

		v = htole32(BRCM_WLC_BAND_AUTO);
		rc = brcm_dcmd_set(sc, BRCM_C_SET_ASSOC_PREFER, &v, sizeof(v));
		DPRINTF(sc, 0, "host-EAPOL: SET_ASSOC_PREFER rc=%d\n", rc);
	}

#undef HOSTEAP_RC

	/*
	 * Prefer the "join" iovar (bsscfg:join) on recent fw.  Bundles
	 * scan params + an explicit chanspec_list so the chip parks the
	 * radio on the target channel before issuing AUTH.  Plain
	 * BRCM_C_SET_SSID can leave the chip never reaching AUTH on
	 * BCM43455 fw 7.45.x when no chanspec is known.
	 */
	/*
	 * ni_chan can be IEEE80211_CHAN_ANYC, net80211's (void *)0xffff
	 * for "no channel yet", so a NULL check alone is not enough.
	 */
	chan = (ni->ni_chan != NULL && ni->ni_chan != IEEE80211_CHAN_ANYC &&
	    ni->ni_chan->ic_ieee != 0) ? ni->ni_chan->ic_ieee : 0;
	/*
	 * Always supply chanspec -- NEVER send chanspec_num=0 to
	 * bsscfg:join.  Prefer fw-cached value from last ESCAN_RESULT
	 * (captures AP's real BW + sideband); fall back to computed BW20
	 * from ni->ni_chan as last resort.
	 */
	chanspec = brcm_lookup_bssid_chanspec(sc, ni->ni_bssid);
	if (chanspec == 0 && chan != 0)
		chanspec = brcm_chan_to_chanspec(sc, chan);

	memset(&ejp, 0, sizeof(ejp));
	ejp.ssid.len = htole32(slen);
	memcpy(ejp.ssid.ssid, ni->ni_essid, slen);
	ejp.scan.scan_type = 0;
	ejp.scan.home_time = htole32((uint32_t)-1);
	memcpy(ejp.assoc.bssid, ni->ni_bssid, 6);
	/*
	 * Variable-length tail:
	 *   base = offsetof(ext_join_params, assoc) +
	 *          offsetof(assoc_params, chanspec_list)
	 *   if (chan)   tail += sizeof(u16);
	 * Sending the full struct with a trailing zero chanspec_list[0]
	 * leaves chanspec_num=0 BUT chanspec_list non-zero, which trips
	 * the chip's "you told me 0 channels but here's 1" sanity check
	 * and the iovar silently doesn't ack (ETIMEDOUT).  Cap len at
	 * the chanspec_list offset when no channel.
	 *
	 * Join-time scan dwells:
	 *   active_time  = 320 ms per channel
	 *   passive_time = 400 ms per channel
	 *   nprobes      = 320/20 = 16 probes per channel
	 * These OVERRIDE the chip's idle SCAN_CHANNEL_TIME (40 ms from
	 * preinit) ONLY during this single join attempt -- the longer
	 * window gives the chip room to RX the AP's probe-response +
	 * TX the AUTH frame before the channel slot closes.  Sending
	 * -1/-1/-1 lets the chip fall back to idle defaults, which on
	 * this fw is too short to fit AUTH between dwells.
	 */
	if (chanspec != 0) {
		ejp.assoc.chanspec_num = htole32(1);
		ejp.assoc.chanspec_list[0] = htole16(chanspec);
		ejp.scan.active_time  = htole32(320);
		ejp.scan.passive_time = htole32(400);
		ejp.scan.nprobes      = htole32(16);
		join_params_size = sizeof(ejp);	/* full -- includes 1 chanspec */
	} else {
		/* No channel known -- let chip auto-scan with its defaults. */
		ejp.scan.nprobes      = htole32((uint32_t)-1);
		ejp.scan.active_time  = htole32((uint32_t)-1);
		ejp.scan.passive_time = htole32((uint32_t)-1);
		join_params_size = offsetof(struct brcm_ext_join_params,
		    assoc) + offsetof(struct brcm_ext_assoc_params,
		    chanspec_list);
	}

	/*
	 * Remember what we asked the firmware to join, so the link-up path
	 * can put net80211 on the same BSS if it is still in SCAN when the
	 * firmware reports the link (brcm_link_task).  The join sysctl sets
	 * these too; a wpa_supplicant join only comes through here.
	 */
	memcpy(sc->sc_join_bssid, ni->ni_bssid, sizeof(sc->sc_join_bssid));
	sc->sc_join_ssid_len = (uint8_t)MIN(slen, BRCM_MAX_SSID_LEN);
	memcpy(sc->sc_join_ssid, ni->ni_essid, sc->sc_join_ssid_len);
	sc->sc_join_ssid[sc->sc_join_ssid_len] = '\0';

	DPRINTF(sc, 0,
	    "join WPA2/host-EAPOL: ssid=\"%.*s\" "
	    "bssid=%02x:%02x:%02x:%02x:%02x:%02x chan=%u chanspec=0x%04x "
	    "join_params_size=%zu\n",
	    (int)slen, ni->ni_essid,
	    ni->ni_bssid[0], ni->ni_bssid[1], ni->ni_bssid[2],
	    ni->ni_bssid[3], ni->ni_bssid[4], ni->ni_bssid[5],
	    chan, chanspec, join_params_size);

	/*
	 * Join dispatch: use the "join" iovar (bsscfg:join) with the 70-byte
	 * ext_join_params.  Linux brcmfmac tries this first during connect and
	 * falls back to SET_SSID only if it fails, and the on-air trace on
	 * identical BCM43602 + fw v7.35.177.61 confirms MFP-negotiated
	 * associations only succeed via this path (SET_SSID dcmd 26 returns
	 * FAIL(1) when mfp iovar is nonzero — see
	 * docs/LINUX_MFP_IOVAR_TRACE.md).
	 *
	 * On BCM43455 fw 7.45.18, bsscfg:join hits AUTH status=5 (NO_ACK)
	 * without the preceding SET_WSEC_PMK + join_pref + double-wpa_auth
	 * sequence Linux uses; with the full sequence in place it is the
	 * path the fw expects.
	 */
	error = brcm_iovar_set(sc, "join", &ejp, join_params_size);
	DPRINTF(sc, 0,
	    "host-EAPOL: bsscfg:join iovar rc=%d (size=%zu)\n",
	    error, join_params_size);
	if (error != 0)
		sc->sc_join_busy = 0;
	return (error);
}


/* deferred work that joins the chosen network */
static void
brcm_assoc_task(void *arg, int pending)
{
	struct brcm_softc *sc = arg;
	struct ieee80211vap *vap = sc->sc_assoc_vap;
	bool wpa_vap;
	int error;

	atomic_add_32(&sc->sc_assoc_cover, (uint32_t)pending);

	if (vap == NULL || !sc->sc_ic_attached)
		return;

	/*
	 * Dispatch by intended security mode:
	 *   - PSK staged via dev.brcm.<n>.wpa_pmk[_hex] => in-firmware
	 *     supplicant path (legacy / old fw).
	 *   - net80211 vap has WPA flags set but no PSK staged =>
	 *     host-EAPOL path (wpa_supplicant runs the 4-way).
	 *   - Otherwise => open.
	 *
	 * vap->iv_flags WPA bits are set when ifconfig wlan0 wpa /
	 * wpaakm psk / etc. is configured, or when wpa_supplicant
	 * calls SIOCS80211_WPA.
	 */
	wpa_vap = (vap->iv_flags &
	    (IEEE80211_F_WPA1 | IEEE80211_F_WPA2)) != 0;

	if (sc->sc_wpa_set || sc->sc_wpa_pmk_raw_set)
		error = brcm_join_wpa2(sc, vap);
	else if (wpa_vap)
		error = brcm_join_wpa2_host_eapol(sc, vap);
	else
		error = brcm_join_open(sc, vap);
	if (error != 0)
		DPRINTF(sc, 0, "assoc task: join dispatch rc=%d\n", error);
}

/* framework asks us to associate to a network */
static int
brcm_fmop_assoc(struct ieee80211com *ic, const struct ieee80211_fmac_assoc *fa)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);
	time_t now;

	(void)fa;	/* helpers read iv_bss directly */
	if (vap == NULL || vap->iv_bss == NULL)
		return (EINVAL);

	/*
	 * Retry rate-limit.  wpa_supplicant retries connect ~every second
	 * when it doesn't see a successful 4-way; each retry cycles the
	 * chip through DOWN/UP/join/AUTH/ASSOC/LINK_DOWN which starves
	 * the SDIO transport (the chip stops acknowledging CMD53 after
	 * ~5-8 back-to-back cycles).  Drop redundant requests
	 * within a 3-second cooldown -- lets the chip settle + gives
	 * wpa_supplicant time to run 4-way if a join lands.  The cooldown
	 * is our own; Linux brcmfmac has no such throttle.
	 */
#define	BRCM_ASSOC_MIN_INTERVAL_S	3
	now = time_uptime;
	if (sc->sc_last_assoc_ts != 0 &&
	    now - sc->sc_last_assoc_ts < BRCM_ASSOC_MIN_INTERVAL_S) {
		DPRINTF(sc, 1, "fmop_assoc: throttled (%llds since last)\n",
		    (long long)(now - sc->sc_last_assoc_ts));
		return (0);	/* pretend success; wpa_supplicant will retry */
	}
	sc->sc_last_assoc_ts = now;

	/*
	 * fmop_assoc runs under IEEE80211_LOCK in the framework's
	 * newstate shim.  Defer the sleeping BCDC dcmd to a
	 * taskqueue and return immediately; the firmware's later
	 * LINK event is what fast-forwards net80211 to RUN via
	 * ieee80211_fmac_link_up.
	 */
	sc->sc_assoc_vap = vap;
	atomic_add_32(&sc->sc_assoc_reqs, 1);
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_assoc_task);
	return (0);
}

/*
 * Post-ASSOC handshake -- issue the iovar GETs Linux issues from
 * brcmf_bss_connect_done (brcmf_get_assoc_ies, brcmf_update_bss_info) on the
 * SET_SSID-success linkup; we issue them on E_ASSOC instead.  On BCM43455 fw
 * 7.45.18 chip appears to tear down LINK reason=2 if host doesn't interact
 * within ~50-100ms of assoc-complete.  These GETs are cheap keepalives that
 * also populate assoc telemetry we can expose to userspace later.
 *
 * Runs on taskqueue_thread; safe to sleep in iovar_get.
 */
static void
brcm_post_assoc_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	uint8_t buf[512];
	size_t len;
	int rc;

	if (!sc->sc_ic_attached)
		return;

	/*
	 * BRCMF_C_GET_BSS_INFO: Linux (brcmf_update_bss_info) prefixes the
	 * buffer with its __le32 size before the dcmd_get.  Without that
	 * the chip returns -45 (BCME_IOCTL_ERROR).
	 */
	memset(buf, 0, sizeof(buf));
	*(uint32_t *)buf = htole32(sizeof(buf));
	len = sizeof(buf);
	rc = brcm_dcmd_get(sc, BRCM_C_GET_BSS_INFO, buf, &len);
	DPRINTF(sc, 0, "post-assoc: GET_BSS_INFO rc=%d len=%zu\n", rc, len);

	/* assoc_info -- returns req_len + resp_len */
	len = sizeof(buf);
	rc = brcm_iovar_get(sc, "assoc_info", buf, &len);
	DPRINTF(sc, 0, "post-assoc: assoc_info rc=%d len=%zu\n", rc, len);

	/* assoc_req_ies / assoc_resp_ies -- IE bytes */
	len = sizeof(buf);
	rc = brcm_iovar_get(sc, "assoc_req_ies", buf, &len);
	DPRINTF(sc, 1, "post-assoc: assoc_req_ies rc=%d len=%zu\n", rc, len);
	len = sizeof(buf);
	rc = brcm_iovar_get(sc, "assoc_resp_ies", buf, &len);
	DPRINTF(sc, 1, "post-assoc: assoc_resp_ies rc=%d len=%zu\n", rc, len);

	/*
	 * wme_ac_sta -- Linux brcmfmac reads this in brcmf_get_assoc_ies when
	 * the association response carries IEs, on linkup.  Returns 4 x struct
	 * edcf_acparam (16 bytes, one per BE/BK/VI/VO AC) that AP included in
	 * its assoc-resp WMM Parameter Element.  On BCM43455 fw 7.45.18 the
	 * chip appears to REQUIRE this GET to commit the WMM state internally
	 * -- without it, chip treats subsequent EAPOL/DATA frames as invalid
	 * and self-tears down LINK reason=2 within milliseconds of ASSOC.
	 *
	 * Linux then feeds the result into brcmf_wifi_prioritize_acparams
	 * to build the tid->AC map used by their TX classifier.  We don't
	 * classify per-AC yet; getting the values is enough to keep the
	 * chip's link machine happy.
	 */
	len = sizeof(buf);
	rc = brcm_iovar_get(sc, "wme_ac_sta", buf, &len);
	DPRINTF(sc, 0, "post-assoc: wme_ac_sta rc=%d len=%zu\n", rc, len);
}

/* deferred work that leaves the current network */
static void
brcm_disassoc_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	struct brcm_scb_val_le sv;
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;
	int error;

	if (!sc->sc_ic_attached)
		return;

	/*
	 * Linux brcmf_cfg80211_disconnect (cfg80211.c:2595) sends a
	 * 12-byte brcmf_scb_val_le payload to BRCM_C_DISASSOC (cmd 52):
	 *   { __le32 reason; u8 bssid[6]; }
	 * GCC pads to 12 bytes (2-byte alignment after bssid).  A bare
	 * 4-byte zero payload is also accepted, but the 12-byte form is
	 * what the fw expects.
	 *
	 * Reason code: pull from sc->sc_disassoc_reason if set by the
	 * caller (fmop_disassoc stashes vap->iv_disassoc_reason), else
	 * default to IEEE80211_REASON_AUTH_LEAVE (3).
	 */
	memset(&sv, 0, sizeof(sv));
	sv.val = htole32(sc->sc_disassoc_reason != 0 ?
	    sc->sc_disassoc_reason : 3);
	vap = TAILQ_FIRST(&sc->sc_ic.ic_vaps);
	if (vap != NULL && (ni = vap->iv_bss) != NULL)
		memcpy(sv.ea, ni->ni_bssid, 6);

	error = brcm_dcmd_set(sc, BRCM_C_DISASSOC, &sv, sizeof(sv));
	if (error != 0)
		DPRINTF(sc, 0, "disassoc task: WLC_DISASSOC rc=%d "
		    "(reason=%u)\n", error, le32toh(sv.val));
	sc->sc_join_busy = 0;	/* explicit operator-requested disassoc */
	sc->sc_disassoc_reason = 0;
}

/* framework asks us to leave the network */
static int
brcm_fmop_disassoc(struct ieee80211com *ic, uint16_t reason)
{
	struct brcm_softc *sc = ic->ic_softc;
	time_t now;

	/*
	 * Skip the WLC_DISASSOC dcmd entirely when the chip already
	 * reports link down.  Chip-initiated LINK-down events walk the
	 * vap to INIT via fmac_link_down, which calls us again — sending
	 * WLC_DISASSOC then is pure SDIO churn (chip is already at IDLE).
	 * During AP retries the chip fires LINK-down every ~200 ms;
	 * answering each with a WLC_DISASSOC + PMU wake wedges the SDIO
	 * transport after 5-8 cycles.
	 */
	if (!sc->sc_link_up)
		return (0);

	/*
	 * Cooldown gate mirroring fmop_assoc.  Even when
	 * sc_link_up is set, wpa_supplicant can bounce us through
	 * INIT/AUTH rapidly.  3 s matches assoc side; drop redundant
	 * fires with rc=0 so the newstate walk still succeeds.
	 */
#define	BRCM_DISASSOC_MIN_INTERVAL_S	3
	now = time_uptime;
	if (sc->sc_last_disassoc_ts != 0 &&
	    now - sc->sc_last_disassoc_ts < BRCM_DISASSOC_MIN_INTERVAL_S) {
		DPRINTF(sc, 1, "fmop_disassoc: throttled (%llds since last)\n",
		    (long long)(now - sc->sc_last_disassoc_ts));
		return (0);
	}
	sc->sc_last_disassoc_ts = now;

	/*
	 * fmop_disassoc runs under IEEE80211_LOCK in the framework's
	 * newstate shim.  The BCDC dcmd sleeps over USB, so defer the
	 * actual WLC_DISASSOC (52) to sc_disassoc_task on
	 * taskqueue_thread.  Stash the reason for the task to include
	 * in the 12-byte scb_val payload (Linux-canonical).  Chip walks
	 * itself to IDLE and emits its own DISASSOC event which our
	 * event handler forwards to ieee80211_fmac_link_down — so the
	 * host-side state walk progresses regardless of dcmd timing.
	 */
	sc->sc_disassoc_reason = reason;
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_disassoc_task);
	return (0);
}

/*
 * Perform one deferred firmware key operation.  net80211 hands us key
 * installs and removals with its node lock held, but the firmware command
 * sleeps, so brcm_fmop_set_key / brcm_fmop_del_key only queue the work and
 * this task runs it here on taskqueue_thread, where sleeping is allowed.
 */
static void
brcm_key_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	struct brcm_key_op *ko;
	int rc;

	for (;;) {
		mtx_lock(&sc->sc_key_mtx);
		ko = TAILQ_FIRST(&sc->sc_key_ops);
		if (ko != NULL)
			TAILQ_REMOVE(&sc->sc_key_ops, ko, ko_link);
		mtx_unlock(&sc->sc_key_mtx);
		if (ko == NULL)
			break;

		/*
		 * For a pairwise key, let any queued EAPOL frame reach the
		 * air before the key goes in.  wpa_supplicant sends the final
		 * handshake frame and the key back to back; if the firmware
		 * had the key first, that frame would go out encrypted and the
		 * AP would drop it.  Only the PCIe transport provides the wait.
		 */
		if (ko->ko_wait_eapol && sc->sc_bus_ops != NULL &&
		    sc->sc_bus_ops->bs_wait_eapol_drain != NULL)
			(void)sc->sc_bus_ops->bs_wait_eapol_drain(sc, 100);

		rc = brcm_set_key(sc, ko->ko_index, ko->ko_algo, ko->ko_flags,
		    ko->ko_key, ko->ko_key_len, ko->ko_ea);
		if (rc != 0)
			DPRINTF(sc, 0, "key task: %s rc=%d\n",
			    ko->ko_algo == BRCM_CRYPTO_ALGO_OFF ?
			    "del_key (failure ignored)" : "set_key", rc);

		/*
		 * After a pairwise key, tell the chip's data path to start
		 * passing this peer's frames.  (Linux sends the same command
		 * when wpa_supplicant marks the peer authorized.)
		 */
		if (rc == 0 && ko->ko_authorize)
			(void)brcm_scb_authorize(sc, ko->ko_auth_mac);

		free(ko, M_BRCM);
	}
}

/*
 * Copy a key request onto the deferred queue and wake brcm_key_task.
 * Safe to call with a net80211 lock held: it allocates with M_NOWAIT and
 * takes only the leaf sc_key_mtx, so it never sleeps.  Returns 0 once the
 * request is queued; the real firmware result is logged from the task.
 */
static int
brcm_key_enqueue(struct brcm_softc *sc, uint32_t index, uint32_t algo,
    uint32_t flags, const uint8_t *key, uint32_t key_len, const uint8_t ea[6],
    bool wait_eapol, const uint8_t *authorize_mac)
{
	struct brcm_key_op *ko;

	ko = malloc(sizeof(*ko), M_BRCM, M_NOWAIT | M_ZERO);
	if (ko == NULL) {
		DPRINTF(sc, 0, "key enqueue: out of memory\n");
		return (ENOMEM);
	}
	ko->ko_index = index;
	ko->ko_algo = algo;
	ko->ko_flags = flags;
	if (key != NULL && key_len > 0) {
		if (key_len > sizeof(ko->ko_key))
			key_len = sizeof(ko->ko_key);
		memcpy(ko->ko_key, key, key_len);
		ko->ko_key_len = key_len;
	}
	memcpy(ko->ko_ea, ea, 6);
	ko->ko_wait_eapol = wait_eapol;
	if (authorize_mac != NULL) {
		ko->ko_authorize = true;
		memcpy(ko->ko_auth_mac, authorize_mac, 6);
	}

	mtx_lock(&sc->sc_key_mtx);
	TAILQ_INSERT_TAIL(&sc->sc_key_ops, ko, ko_link);
	mtx_unlock(&sc->sc_key_mtx);
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_key_task);
	return (0);
}

/* install an encryption key on the chip */
static int
brcm_fmop_set_key(struct ieee80211com *ic, const struct ieee80211_key *k)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap;
	uint32_t algo, flags = 0;
	const uint8_t *ea, *authorize;
	static const uint8_t bcast[6] = {
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	/*
	 * A group key goes in with a zero peer address, as Linux brcmfmac
	 * does (brcmf_cfg80211_add_key, formerly brcmf_add_keyext, fills ea
	 * only for a unicast peer).  The BCM43236's firmware rejects the
	 * broadcast address with BCME_BADARG.
	 */
	static const uint8_t group_ea[6] = { 0 };

	algo = brcm_cipher_to_algo(k->wk_cipher->ic_cipher);
	if (algo == BRCM_CRYPTO_ALGO_OFF) {
		DPRINTF(sc, 0, "fmop_set_key: unsupported cipher %u\n",
		    k->wk_cipher->ic_cipher);
		return (EINVAL);
	}

	/*
	 * Pull the peer BSSID off the first STA vap.  brcm rejects
	 * multi-vap configurations in brcm_vap_create so this is
	 * unambiguous; if no vap exists yet the broadcast EA is the
	 * safe default for a group key install.
	 */
	vap = TAILQ_FIRST(&ic->ic_vaps);

	if (k->wk_keyix == IEEE80211_KEYIX_NONE ||
	    (k->wk_flags & IEEE80211_KEY_GROUP) == 0) {
		/*
		 * Pairwise key.  Drain EAPOL first, and afterwards authorize
		 * the peer's data path (both done by brcm_key_task).
		 */
		flags |= BRCM_WSEC_PRIMARY_KEY;
		ea = (vap != NULL && vap->iv_bss != NULL) ?
		    vap->iv_bss->ni_bssid : bcast;
		authorize = (vap != NULL && vap->iv_bss != NULL) ?
		    vap->iv_bss->ni_bssid : NULL;
		return (brcm_key_enqueue(sc, 0, algo, flags,
		    k->wk_key, k->wk_keylen, ea, true, authorize));
	}

	/* Group key. */
	if (algo == BRCM_CRYPTO_ALGO_TKIP) {
		uint8_t tk[32];
		int rc;

		/*
		 * A TKIP key is 32 bytes on the chip: the 16-byte key and
		 * both Michael MIC keys.  net80211 counts only the 16 in
		 * wk_keylen and keeps the MIC keys after them, TX then RX
		 * from this station's side; the firmware wants RX first,
		 * as Linux brcmfmac (brcmf_cfg80211_add_key) swaps them for a
		 * station.  Sending only 16 bytes gets rc=5 and no group key,
		 * and with a TKIP group cipher no broadcast traffic passes.
		 */
		memcpy(tk, k->wk_key, 16);
		memcpy(tk + 16, k->wk_rxmic, 8);
		memcpy(tk + 24, k->wk_txmic, 8);
		rc = brcm_key_enqueue(sc, k->wk_keyix, algo, flags, tk,
		    sizeof(tk), group_ea, false, NULL);
		explicit_bzero(tk, sizeof(tk));
		return (rc);
	}
	return (brcm_key_enqueue(sc, k->wk_keyix, algo, flags,
	    k->wk_key, k->wk_keylen, group_ea, false, NULL));
}

/* remove an encryption key from the chip */
static int
brcm_fmop_del_key(struct ieee80211com *ic, const struct ieee80211_key *k)
{
	struct brcm_softc *sc = ic->ic_softc;
	static const uint8_t bcast[6] = {
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	uint32_t idx = (k->wk_keyix == IEEE80211_KEYIX_NONE) ?
	    0 : k->wk_keyix;

	/*
	 * Firmware rejects a zero-length wsec_key with algo OFF (rc=5),
	 * and net80211 issues exactly that during a normal WPA2
	 * association -- right after the pairwise key installs and the
	 * peer is authorized, as it clears the slot before the group key
	 * lands.  Propagating the rejection takes the link down every
	 * time: PTK in, scb authorized, then DISASSOC reason 8 and back
	 * to INIT.
	 *
	 * Deleting a key the chip does not have is not an error worth
	 * dropping a working link over, so the request is still sent and
	 * its result is logged, but a failure is not propagated.
	 */
	(void)brcm_key_enqueue(sc, idx, BRCM_CRYPTO_ALGO_OFF, 0, NULL, 0,
	    bcast, false, NULL);
	return (0);
}

/* tell the chip which country's rules to use */
static int
brcm_fmop_set_country(struct ieee80211com *ic, const char cc[3])
{
	struct brcm_softc *sc = ic->ic_softc;
	uint8_t country[4] = { (uint8_t)cc[0], (uint8_t)cc[1], 0, 0 };

	(void)cc[2];
	return (brcm_iovar_set(sc, "country", country, sizeof(country)));
}

static const struct ieee80211_fullmac_ops brcm_fmops = {
	.fmop_name	   = "brcm",
	.fmop_scan_start   = brcm_fmop_scan_start,
	.fmop_assoc	   = brcm_fmop_assoc,
	.fmop_disassoc	   = brcm_fmop_disassoc,
	.fmop_set_key	   = brcm_fmop_set_key,
	.fmop_del_key	   = brcm_fmop_del_key,
	.fmop_set_country  = brcm_fmop_set_country,
};

/* set up the driver and attach it to the wifi stack */
int
brcm_attach(struct brcm_softc *sc)
{
	struct ieee80211com *ic;

	/*
	 * Mutexes + ctl_pending TAILQ are owned by the transport attach,
	 * so they survive a failure after kproc_create.  Re-initing them
	 * here would clobber pointers the ctlrx thread is already using.
	 */
	TASK_INIT(&sc->sc_scan_done_task, 0, brcm_scan_done_task, sc);
	TASK_INIT(&sc->sc_link_task, 0, brcm_link_task, sc);
	TASK_INIT(&sc->sc_assoc_task, 0, brcm_assoc_task, sc);
	TASK_INIT(&sc->sc_disassoc_task, 0, brcm_disassoc_task, sc);
	TASK_INIT(&sc->sc_post_assoc_task, 0, brcm_post_assoc_task, sc);
	TASK_INIT(&sc->sc_key_task, 0, brcm_key_task, sc);
	mtx_init(&sc->sc_key_mtx, "brcm key", NULL, MTX_DEF);
	TAILQ_INIT(&sc->sc_key_ops);
	sc->sc_tasks_inited = true;

	ic = &sc->sc_ic;
	ic->ic_softc = sc;
	ic->ic_name = device_get_nameunit(sc->sc_dev);
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_caps =
	    IEEE80211_C_STA |
	    IEEE80211_C_WPA;

	/*
	 * Advertise the WPA2 ciphers we can install on the chip via
	 * the "wsec_key" iovar.  This lets userspace wpa_supplicant negotiate
	 * RSN with WPA2-PSK + CCMP and then call iv_key_set with these key
	 * types.  TKIP is added too because some legacy APs require it for the
	 * GTK even when CCMP is the pairwise cipher.
	 */
	ic->ic_cryptocaps =
	    IEEE80211_CRYPTO_AES_CCM |
	    IEEE80211_CRYPTO_TKIP |
	    IEEE80211_CRYPTO_WEP;

	brcm_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans,
	    ic->ic_channels);

	IEEE80211_ADDR_COPY(ic->ic_macaddr, sc->sc_macaddr);

	ieee80211_ifattach(ic);
	sc->sc_ic_attached = true;

	/*
	 * Attach the FullMAC framework.  It takes over ic_scan_start /
	 * ic_scan_end here; the vap-level shims (fmac_newstate,
	 * fmac_key_set) are installed by ieee80211_fmac_vap_attach()
	 * from brcm_vap_create.
	 */
	(void)ieee80211_fmac_attach(ic, &brcm_fmops,
	    IEEE80211_FMAC_CAP_FW_SCAN | IEEE80211_FMAC_CAP_ONCHIP_SUP);

	ic->ic_vap_create = brcm_vap_create;
	ic->ic_vap_delete = brcm_vap_delete;
	ic->ic_parent = brcm_parent;
	ic->ic_transmit = brcm_transmit;
	ic->ic_raw_xmit = brcm_raw_xmit;
	ic->ic_set_channel = brcm_set_channel;
	/* ic_scan_start / ic_scan_end belong to the FullMAC framework. */
	ic->ic_getradiocaps = brcm_getradiocaps;
	ic->ic_update_promisc = brcm_update_promisc;
	ic->ic_update_mcast = brcm_update_mcast;

	/*
	 * Tell devd the device is ready for a vap.  The firmware can come up
	 * after rc's netif has already created the wlans_<dev> interfaces,
	 * or the device can be plugged in later; etc/devd/brcm.conf creates
	 * them on this event.
	 */
	devctl_notify("BRCM", device_get_nameunit(sc->sc_dev), "ATTACH", NULL);

	return (0);
}

/*
 * WPA2-PSK passphrase sysctl.  Stores the ASCII passphrase (8..63
 * bytes per WPA2 spec) in the softc; brcm_assoc_task checks
 * sc_wpa_set on the next join to pick the WPA2 dispatch path.
 * Read-back returns the "<set>" sentinel so the
 * passphrase does not leak through sysctl introspection.  Empty
 * write clears.
 */
static int
brcm_pmk_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	char buf[64];
	size_t len;
	int error;

	memset(buf, 0, sizeof(buf));
	if (sc->sc_wpa_set)
		strlcpy(buf, "<set>", sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL) {
		/*
		 * explicit_bzero the local passphrase buffer
		 * even on read/error paths.  Plain memset is elided by
		 * the compiler when it can prove the memory dies with
		 * the stack frame; explicit_bzero is the guaranteed
		 * "you WILL zero this" primitive.  Prevents leftover
		 * PMK bytes surviving on a reused kernel stack page.
		 */
		explicit_bzero(buf, sizeof(buf));
		return (error);
	}
	if (strcmp(buf, "<set>") == 0) {
		explicit_bzero(buf, sizeof(buf));
		return (0);
	}
	len = strnlen(buf, sizeof(buf));
	if (len == 0) {
		sc->sc_wpa_set = false;
		explicit_bzero(sc->sc_wpa_pmk, sizeof(sc->sc_wpa_pmk));
		DPRINTF(sc, 0, "WPA2 PMK cleared\n");
		explicit_bzero(buf, sizeof(buf));
		return (0);
	}
	if (len < 8 || len > 63) {
		explicit_bzero(buf, sizeof(buf));
		return (EINVAL);
	}
	explicit_bzero(sc->sc_wpa_pmk, sizeof(sc->sc_wpa_pmk));
	memcpy(sc->sc_wpa_pmk, buf, len);
	sc->sc_wpa_set = true;
	DPRINTF(sc, 0, "WPA2 PMK stored (%zu bytes)\n", len);
	explicit_bzero(buf, sizeof(buf));
	return (0);
}

/*
 * Look up the BSS we just joined in net80211's scan cache and call
 * ieee80211_sta_join with it.  sta_join sets ic_curchan + builds an
 * iv_bss node + transitions vap state, which is exactly the
 * scaffolding our deferred link task needs before it can call
 * ieee80211_new_state(RUN) without NULL-derefing in sync_curchan.
 *
 * The scan cache must be populated for this to work — caller is
 * expected to have triggered a scan before the direct-join sysctl.
 */
struct brcm_mlme_lookup {
	const uint8_t			*bssid;
	const char			*ssid;
	uint8_t				 ssid_len;
	bool				 found;
	struct ieee80211_scan_entry	 se;
};

/* scan-cache callback: match one saved AP entry */
static void
brcm_mlme_iter(void *arg, const struct ieee80211_scan_entry *se)
{
	struct brcm_mlme_lookup *l = arg;

	if (l->found)
		return;
	if (!IEEE80211_ADDR_EQ(l->bssid, se->se_macaddr))
		return;
	if (l->ssid_len != 0) {
		if (se->se_ssid[1] != l->ssid_len)
			return;
		if (memcmp(l->ssid, se->se_ssid + 2, l->ssid_len) != 0)
			return;
	}
	/*
	 * Copy the entry, but give the copy its own IE buffer.  The struct
	 * copy shares se_ies.data with the scan entry; ieee80211_ies_init
	 * would reuse that buffer (same length) and ieee80211_ies_cleanup in
	 * brcm_sta_join_from_cache would free it under the live entry, a
	 * use-after-free that corrupts net80211's scan list.  net80211's own
	 * mlmelookup clears the pointer first for the same reason.
	 */
	l->se = *se;
	l->se.se_ies.data = NULL;
	l->se.se_ies.len = 0;
	if (ieee80211_ies_init(&l->se.se_ies, se->se_ies.data,
	    se->se_ies.len))
		ieee80211_ies_expand(&l->se.se_ies);
	l->found = true;
}

static int
brcm_sta_join_from_cache(struct brcm_softc *sc)
{
	struct ieee80211vap *vap;
	struct brcm_mlme_lookup lookup;
	int rv;

	if (!sc->sc_ic_attached)
		return (ENXIO);
	vap = TAILQ_FIRST(&sc->sc_ic.ic_vaps);
	if (vap == NULL)
		return (ENXIO);

	memset(&lookup, 0, sizeof(lookup));
	lookup.bssid = sc->sc_join_bssid;
	lookup.ssid = sc->sc_join_ssid;
	lookup.ssid_len = sc->sc_join_ssid_len;
	ieee80211_scan_iterate(vap, brcm_mlme_iter, &lookup);
	if (!lookup.found) {
		DPRINTF(sc, 0,
		    "sta_join: BSS %02x:%02x:%02x:%02x:%02x:%02x not in "
		    "scan cache -- run a scan first\n",
		    sc->sc_join_bssid[0], sc->sc_join_bssid[1],
		    sc->sc_join_bssid[2], sc->sc_join_bssid[3],
		    sc->sc_join_bssid[4], sc->sc_join_bssid[5]);
		return (ENOENT);
	}
	rv = ieee80211_sta_join(vap, lookup.se.se_chan, &lookup.se);
	ieee80211_ies_cleanup(&lookup.se.se_ies);
	if (rv == 0) {
		DPRINTF(sc, 0, "sta_join refused the entry\n");
		return (EIO);
	}
	DPRINTF(sc, 0, "sta_join queued (ic_curchan now set)\n");
	return (0);
}

/*
 * scan_now sysctl.  Writing any non-zero int triggers a broadcast
 * escan; useful for kicking the firmware in a non-net80211 path
 * (e.g. before any vap exists or when net80211's scan-cache aged
 * everything out).
 */
static int
brcm_scan_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	int trigger = 0;
	int error;

	error = sysctl_handle_int(oidp, &trigger, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (trigger == 0)
		return (0);
	error = brcm_dispatch_scan(sc);
	DPRINTF(sc, 0, "scan_now dispatch rc=%d\n", error);
	return (error);
}

/*
 * Direct WPA2 join sysctl.  Bypasses net80211's SCAN/AUTH state
 * machine — writes the BCDC iovars and SET_SSID directly, letting the
 * firmware handle auth + 4-way handshake using the PMK already
 * installed via wpa_pmk.  Format: "BSSID:SSID" with BSSID as 6
 * colon-separated hex bytes.  Useful for radio-side testing without
 * net80211 or wpa_supplicant in the loop.
 * Empty string means "abort" (BRCM_C_DOWN).
 */
static int
brcm_join_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	char buf[96];
	uint8_t bssid[6];
	const char *ssid;
	unsigned int b[6];
	size_t ssid_len;
	int error, n, off, matched;

	memset(buf, 0, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (buf[0] == '\0') {
		uint32_t v = htole32(0);

		(void)brcm_dcmd_set(sc, BRCM_C_DOWN, &v, sizeof(v));
		DPRINTF(sc, 0, "join aborted\n");
		return (0);
	}
	/*
	 * If no PSK staged, fall through to brcm_join_open: useful for
	 * (a) joining an OPEN AP and (b) chip-side iovar validation
	 * against a WPA2 AP (chip will auth + assoc, AP will deauth
	 * after timeout; the chip's AUTH/ASSOC_IND events confirm the
	 * join sequence reached the air).
	 */
	off = 0;
	matched = sscanf(buf, "%x:%x:%x:%x:%x:%x:%n",
	    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &off);
	if (matched != 6 || off == 0 || buf[off] == '\0')
		return (EINVAL);
	n = off;
	for (int i = 0; i < 6; i++) {
		if (b[i] > 0xff)
			return (EINVAL);
		bssid[i] = (uint8_t)b[i];
	}
	ssid = buf + n;
	ssid_len = strnlen(ssid, sizeof(buf) - n);
	if (ssid_len == 0 || ssid_len > BRCM_MAX_SSID_LEN)
		return (EINVAL);

	memcpy(sc->sc_join_bssid, bssid, 6);
	memcpy(sc->sc_join_ssid, ssid, ssid_len);
	sc->sc_join_ssid[ssid_len] = '\0';
	sc->sc_join_ssid_len = ssid_len;

	/*
	 * Preferred path: route the join through net80211's state
	 * machine.  sta_join_from_cache calls ieee80211_sta_join, which
	 * walks the vap to AUTH; the framework's newstate shim then
	 * dispatches the firmware join (brcm_fmop_assoc).  When firmware
	 * emits LINK up,
	 * brcm_link_task fast-forwards ASSOC -> RUN.  This is what makes
	 * wlan0 usable from dhclient + userland sockets.
	 *
	 * If the scan cache has no matching BSS (no scan run yet, or BSS
	 * aged out), fall back to the raw direct dispatch which at least
	 * gets the radio associated -- useful for end-to-end firmware
	 * validation even if userland can't use the link.
	 */
	error = brcm_sta_join_from_cache(sc);
	if (error == 0) {
		DPRINTF(sc, 0,
		    "join_target: dispatched via sta_join (net80211 tracked)\n");
		return (0);
	}
	DPRINTF(sc, 0,
	    "join_target: sta_join_from_cache rc=%d; falling back to "
	    "raw direct dispatch\n", error);

	if (sc->sc_wpa_set || sc->sc_wpa_pmk_raw_set) {
		error = brcm_join_wpa2_raw(sc, bssid, ssid, ssid_len);
		DPRINTF(sc, 0, "join_target raw WPA2 dispatch rc=%d\n", error);
	} else {
		struct brcm_join_params join;
		uint32_t v;

		size_t jlen;
		uint16_t chanspec;

		if (sc->sc_join_busy) {
			DPRINTF(sc, 0, "join_target: join in flight, EAGAIN\n");
			return (EAGAIN);
		}
		sc->sc_join_busy = 1;

		/*
		 * No DOWN/UP wrap -- Linux brcmfmac doesn't, and BCM43455
		 * fw 7.45.x's join state machine doesn't fire AUTH after
		 * a DOWN/UP bounce.  Just reset RSN config in place.
		 */
		v = htole32(1);
		(void)brcm_dcmd_set(sc, BRCM_C_SET_INFRA, &v, sizeof(v));
		v = htole32(BRCM_AUTH_OPEN);
		(void)brcm_dcmd_set(sc, BRCM_C_SET_AUTH, &v, sizeof(v));
		v = htole32(0);
		(void)brcm_iovar_set(sc, "wsec", &v, sizeof(v));
		v = htole32(0);
		(void)brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v));

		memset(&join, 0, sizeof(join));
		join.ssid.len = htole32(ssid_len);
		memcpy(join.ssid.ssid, ssid, ssid_len);
		memcpy(join.assoc.bssid, bssid, 6);

		/*
		 * Pass the fw-cached chanspec via chanspec_list[0] so the
		 * chip parks on the AP's actual channel instead of doing
		 * a from-scratch SSID hunt that often doesn't converge to
		 * AUTH on BCM43455 fw 7.45.x.
		 */
		chanspec = brcm_lookup_bssid_chanspec(sc, bssid);
		if (chanspec != 0) {
			join.assoc.chanspec_num = htole32(1);
			join.assoc.chanspec_list[0] = htole16(chanspec);
			jlen = BRCM_JOIN_PARAMS_FIXED_SIZE + sizeof(uint16_t);
		} else {
			join.assoc.chanspec_num = 0;
			jlen = BRCM_JOIN_PARAMS_FIXED_SIZE;
		}

		DPRINTF(sc, 0,
		    "join OPEN: ssid=\"%.*s\" bssid=%02x:%02x:%02x:%02x:%02x:%02x "
		    "chanspec=0x%04x jlen=%zu\n",
		    (int)ssid_len, ssid,
		    bssid[0], bssid[1], bssid[2],
		    bssid[3], bssid[4], bssid[5],
		    chanspec, jlen);
		error = brcm_dcmd_set(sc, BRCM_C_SET_SSID, &join, jlen);
		if (error != 0)
			sc->sc_join_busy = 0;
		DPRINTF(sc, 0, "join_target raw OPEN dispatch rc=%d\n", error);
	}
	return (error);
}

/*
 * Raw 32-byte PMK sysctl.  Userspace computes the PMK with
 *   wpa_passphrase <ssid> <passphrase>
 * and writes the 64-char hex string here.  Preferred over wpa_pmk
 * because the 2011 BCM43236 firmware rejects the passphrase-form
 * wsec_pmk install with BCME_BADARG.  Empty string clears.
 */
static int
brcm_pmk_hex_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	char buf[80];
	uint8_t pmk[32];
	size_t len;
	int error;

	memset(buf, 0, sizeof(buf));
	if (sc->sc_wpa_pmk_raw_set)
		strlcpy(buf, "<set>", sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (strcmp(buf, "<set>") == 0)
		return (0);
	len = strnlen(buf, sizeof(buf));
	if (len == 0) {
		sc->sc_wpa_pmk_raw_set = false;
		memset(sc->sc_wpa_pmk_raw, 0, sizeof(sc->sc_wpa_pmk_raw));
		DPRINTF(sc, 0, "WPA2 raw PMK cleared\n");
		return (0);
	}
	if (len != 64)
		return (EINVAL);
	for (int i = 0; i < 32; i++) {
		unsigned int b;

		if (sscanf(buf + i * 2, "%2x", &b) != 1 || b > 0xff)
			return (EINVAL);
		pmk[i] = (uint8_t)b;
	}
	memcpy(sc->sc_wpa_pmk_raw, pmk, 32);
	sc->sc_wpa_pmk_raw_set = true;
	DPRINTF(sc, 0, "WPA2 raw PMK stored (32 bytes)\n");
	return (0);
}

/*
 * iovar_get sysctl.  Write an iovar name to fetch; subsequent read
 * returns the last-fetched value as a hex byte string.  Useful for
 * probing the firmware's live state — caps, ver, mfp, etc.
 */
static int
brcm_iovar_get_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	char namebuf[64];
	size_t outlen;
	int error;

	memset(namebuf, 0, sizeof(namebuf));
	if (req->newptr == NULL) {
		char hex[BRCM_IOVAR_DUMP_MAX * 3 + 1];
		size_t i, n;

		mtx_lock(&sc->sc_ctl_mtx);
		n = sc->sc_iovar_value_len;
		if (n > BRCM_IOVAR_DUMP_MAX)
			n = BRCM_IOVAR_DUMP_MAX;
		for (i = 0; i < n; i++)
			snprintf(hex + i * 3, 4, "%02x ",
			    sc->sc_iovar_value[i]);
		hex[i ? i * 3 - 1 : 0] = '\0';
		mtx_unlock(&sc->sc_ctl_mtx);
		return (sysctl_handle_string(oidp, hex, sizeof(hex), req));
	}

	error = sysctl_handle_string(oidp, namebuf, sizeof(namebuf), req);
	if (error != 0)
		return (error);

	mtx_lock(&sc->sc_ctl_mtx);
	strlcpy(sc->sc_iovar_name, namebuf, sizeof(sc->sc_iovar_name));
	mtx_unlock(&sc->sc_ctl_mtx);

	outlen = BRCM_IOVAR_DUMP_MAX;
	{
		uint8_t scratch[BRCM_IOVAR_DUMP_MAX];

		memset(scratch, 0, sizeof(scratch));
		error = brcm_iovar_get(sc, namebuf, scratch, &outlen);
		mtx_lock(&sc->sc_ctl_mtx);
		if (error != 0) {
			sc->sc_iovar_value_len = 0;
			DPRINTF(sc, 0, "iovar_get(\"%s\") rc=%d\n",
			    namebuf, error);
		} else {
			memcpy(sc->sc_iovar_value, scratch, outlen);
			sc->sc_iovar_value_len = outlen;
			DPRINTF(sc, 0,
			    "iovar_get(\"%s\") returned %zu bytes\n",
			    namebuf, outlen);
		}
		mtx_unlock(&sc->sc_ctl_mtx);
	}
	return (0);
}

/*
 * event_stats: what the firmware reported, and whether every resulting
 * task request was handled.  "req" counts enqueues; "cover" sums the
 * taskqueue's pending count over the task's runs.  req == cover means no
 * request was lost (coalesced requests are covered by one run).
 */
static int
brcm_event_stats_sysctl(SYSCTL_HANDLER_ARGS)
{
	static const struct { int t; const char *n; } names[] = {
		{ 0, "SET_SSID" }, { 1, "JOIN" }, { 3, "AUTH" }, { 5, "DEAUTH" },
		{ 6, "DEAUTH_IND" }, { 7, "ASSOC" }, { 11, "DISASSOC" },
		{ 12, "DISASSOC_IND" }, { 16, "LINK" }, { 25, "EAPOL_MSG" },
		{ 46, "PSK_SUP" }, { 54, "IF" }, { 69, "ESCAN_RESULT" },
		{ 74, "FIFO_CREDIT_MAP" },
	};
	struct brcm_softc *sc = arg1;
	struct sbuf *sb;
	const char *nm;
	int error, t;
	size_t k;

	sb = sbuf_new_for_sysctl(NULL, NULL, 512, req);
	sbuf_printf(sb, "events:");
	for (t = 0; t < (int)nitems(sc->sc_evt_by_type); t++) {
		if (sc->sc_evt_by_type[t] == 0)
			continue;
		nm = NULL;
		for (k = 0; k < nitems(names); k++)
			if (names[k].t == t)
				nm = names[k].n;
		if (nm != NULL)
			sbuf_printf(sb, " %s=%u", nm, sc->sc_evt_by_type[t]);
		else
			sbuf_printf(sb, " E%d=%u", t, sc->sc_evt_by_type[t]);
	}
	sbuf_printf(sb, "\nescan_done_events=%u\n", sc->sc_escan_done_evts);
	sbuf_printf(sb, "scan_done_task req=%u cover=%u%s\n",
	    sc->sc_scan_done_reqs, sc->sc_scan_done_cover,
	    sc->sc_scan_done_reqs == sc->sc_scan_done_cover ? " ok" : " LOST");
	sbuf_printf(sb, "link_task req=%u cover=%u%s\n",
	    sc->sc_link_reqs, sc->sc_link_cover,
	    sc->sc_link_reqs == sc->sc_link_cover ? " ok" : " LOST");
	sbuf_printf(sb, "assoc_task req=%u cover=%u%s",
	    sc->sc_assoc_reqs, sc->sc_assoc_cover,
	    sc->sc_assoc_reqs == sc->sc_assoc_cover ? " ok" : " LOST");
	error = sbuf_finish(sb);
	sbuf_delete(sb);
	return (error);
}

/*
 * iovar_set sysctl.  Format: "name:hexbytes" where hexbytes is an
 * even-length hex string (no separators).  Lets operators push a raw
 * iovar payload for protocol forensics without recompiling.
 */
static int
brcm_iovar_set_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	char buf[768];
	uint8_t bytes[256];
	const char *colon, *hex;
	char name[64];
	size_t namelen, hexlen, nbytes, i;
	int error;

	/*
	 * Safety gate.  Two conditions must hold before we push
	 * a raw operator-supplied iovar payload at the firmware:
	 *   1. sc_unsafe_iovars must be non-zero (opt-in flag).
	 *   2. The caller must hold PRIV_DRIVER.  Redundant against
	 *      the sysctl's own root check on most systems, but the
	 *      explicit priv_check adds jail restriction: a jailed
	 *      root without PRIV_DRIVER cannot reach the chip.
	 * Without this gate the ~65 iovar handlers on the chip (2011
	 * blob) are a live pipe to a decade of Broadcom firmware CVEs
	 * for anyone who owns root.  Compile with
	 * `options BRCM_UNSAFE_IOVARS_DEFAULT_ON` to skip the opt-in flag.
	 */
#ifndef BRCM_UNSAFE_IOVARS_DEFAULT_ON
	if (sc->sc_unsafe_iovars == 0)
		return (EPERM);
#endif
	error = priv_check(req->td, PRIV_DRIVER);
	if (error != 0)
		return (error);

	memset(buf, 0, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	colon = strchr(buf, ':');
	if (colon == NULL)
		return (EINVAL);
	namelen = (size_t)(colon - buf);
	if (namelen == 0 || namelen >= sizeof(name))
		return (EINVAL);
	memcpy(name, buf, namelen);
	name[namelen] = '\0';

	hex = colon + 1;
	hexlen = strnlen(hex, sizeof(buf) - namelen - 1);
	if (hexlen % 2 != 0 || hexlen / 2 > sizeof(bytes))
		return (EINVAL);
	nbytes = hexlen / 2;
	for (i = 0; i < nbytes; i++) {
		unsigned int v;

		if (sscanf(&hex[i * 2], "%2x", &v) != 1)
			return (EINVAL);
		bytes[i] = (uint8_t)v;
	}

	error = brcm_iovar_set(sc, name, bytes, nbytes);
	DPRINTF(sc, 0, "iovar_set(\"%s\", %zu bytes) rc=%d\n",
	    name, nbytes, error);
	return (error);
}

/*
 * sup_dump sysctl.  Paired with the patched BCM43236 firmware (see
 * tools/patch_sup_dump.py): the injected "sup_dump" iovar reads
 * bytes from the on-chip supplicant context [*(wlc+0x12) + offset]
 * and returns them via the iovar reply.
 *
 * Wire format on the iovar GET path:
 *
 *     "sup_dump\0" | <u32 offset LE> | <u32 length LE>
 *
 * Writes: parse "OFFSET LENGTH" (decimal or 0x-prefixed hex).
 * Reads:  return the last fetched bytes as space-separated hex.
 */
static int
brcm_sup_dump_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	char input[64];
	uint8_t params[8];
	uint8_t scratch[BRCM_SUP_DUMP_MAX];
	uint64_t off, len;
	char *p;
	size_t outlen;
	int error;

	if (req->newptr == NULL) {
		char hex[BRCM_SUP_DUMP_MAX * 3 + 64];
		size_t i, n, used;

		mtx_lock(&sc->sc_ctl_mtx);
		n = sc->sc_sup_dump_len;
		used = snprintf(hex, sizeof(hex), "off=%#x len=%zu",
		    sc->sc_sup_dump_off, n);
		if (n != 0 && used + 1 < sizeof(hex))
			hex[used++] = ' ';
		for (i = 0; i < n && used + 3 < sizeof(hex); i++) {
			used += snprintf(hex + used, sizeof(hex) - used,
			    "%02x ", sc->sc_sup_dump[i]);
		}
		if (used > 0 && hex[used - 1] == ' ')
			hex[used - 1] = '\0';
		mtx_unlock(&sc->sc_ctl_mtx);
		return (sysctl_handle_string(oidp, hex, sizeof(hex), req));
	}

	memset(input, 0, sizeof(input));
	error = sysctl_handle_string(oidp, input, sizeof(input), req);
	if (error != 0)
		return (error);

	off = strtouq(input, &p, 0);
	if (p == input)
		return (EINVAL);
	while (*p == ' ' || *p == '\t')
		p++;
	len = strtouq(p, NULL, 0);
	if (len == 0 || len > BRCM_SUP_DUMP_MAX)
		return (EINVAL);
	if (off > 0xffffffffULL)
		return (EINVAL);

	params[0] = (uint8_t)(off >>  0);
	params[1] = (uint8_t)(off >>  8);
	params[2] = (uint8_t)(off >> 16);
	params[3] = (uint8_t)(off >> 24);
	params[4] = (uint8_t)(len >>  0);
	params[5] = (uint8_t)(len >>  8);
	params[6] = (uint8_t)(len >> 16);
	params[7] = (uint8_t)(len >> 24);

	outlen = (size_t)len;
	memset(scratch, 0, sizeof(scratch));
	error = brcm_iovar_get_with_params(sc, "sup_dump",
	    params, sizeof(params), scratch, &outlen);

	mtx_lock(&sc->sc_ctl_mtx);
	sc->sc_sup_dump_off = (uint32_t)off;
	if (error != 0) {
		sc->sc_sup_dump_len = 0;
		DPRINTF(sc, 0, "sup_dump(off=%#jx len=%ju) rc=%d\n",
		    (uintmax_t)off, (uintmax_t)len, error);
	} else {
		if (outlen > BRCM_SUP_DUMP_MAX)
			outlen = BRCM_SUP_DUMP_MAX;
		memcpy(sc->sc_sup_dump, scratch, outlen);
		sc->sc_sup_dump_len = outlen;
		DPRINTF(sc, 0,
		    "sup_dump(off=%#jx len=%ju) returned %zu bytes\n",
		    (uintmax_t)off, (uintmax_t)len, outlen);
	}
	mtx_unlock(&sc->sc_ctl_mtx);
	return (error);
}

/*
 * Bring the firmware to the operating point net80211 expects.  Order:
 *   BRCM_C_UP            - data plane up
 *   event_msgs           - subscribe to the events the driver demuxes
 *   country = "US"       - regulatory domain (most blobs refuse to scan
 *                          until country is programmed)
 *   sup_wpa = 0          - host-side EAPOL mode for fresh credentials
 *
 * Called from each transport's attach once the BCDC path is alive.
 * All errors are non-fatal; the transport logs them but continues so
 * the user can still poke the firmware via the iovar_* sysctls.
 */
/*
 * CLM (Country Locale Matrix) blob upload via the "clmload" iovar.
 *
 * Mirrors Linux brcmf_c_process_clm_blob + brcmf_c_download_blob.  The
 * BCM43455 chip's TX is restricted to a small default set without this
 * regulatory blob: the chip reports PROBERESP_MSG from the AP but never
 * transmits an AUTH frame, because its regulatory data forbids the
 * operation on the target channel.
 *
 * Walks the blob in MAX_CHUNK_LEN-sized chunks; each chunk wraps the
 * payload in struct brcm_dload_data and sends via iovar_set("clmload").
 * First chunk has DL_BEGIN, last has DL_END (both set if the whole blob
 * fits in one chunk).
 *
 * fwname comes from the per-chip table; the blob registers as
 * "<fwname>.clm_blob" (see sys/modules/brcmfmac43455_fw/Makefile).
 */
static int
brcm_upload_clm_blob(struct brcm_softc *sc, const char *fwname)
{
	const struct firmware *fw;
	struct brcm_dload_data *hdr;
	char blobname[64];
	size_t hdrsz, bufsz, off;
	uint16_t flag;
	int error;

	snprintf(blobname, sizeof(blobname), "%s.clm_blob", fwname);
	fw = firmware_get(blobname);
	if (fw == NULL) {
		DPRINTF(sc, 0,
		    "clmload: no %s firmware registered; chip's TX limited "
		    "to default regulatory set (no AUTH on most channels)\n",
		    blobname);
		return (ENOENT);
	}
	DPRINTF(sc, 0, "clmload: uploading %s (%zu bytes)\n",
	    blobname, fw->datasize);

	hdrsz = sizeof(*hdr);
	bufsz = hdrsz + BRCM_DLOAD_MAX_CHUNK_LEN;
	hdr = malloc(bufsz, M_BRCM, M_WAITOK | M_ZERO);

	off = 0;
	flag = BRCM_DL_BEGIN;
	error = 0;
	while (off < fw->datasize) {
		size_t chunk = fw->datasize - off;
		if (chunk > BRCM_DLOAD_MAX_CHUNK_LEN)
			chunk = BRCM_DLOAD_MAX_CHUNK_LEN;
		else
			flag |= BRCM_DL_END;

		memcpy(hdr->data, (const uint8_t *)fw->data + off, chunk);

		hdr->flag = htole16(flag |
		    (BRCM_DLOAD_HANDLER_VER << BRCM_DLOAD_FLAG_VER_SHIFT));
		hdr->dload_type = htole16(BRCM_DL_TYPE_CLM);
		hdr->len = htole32((uint32_t)chunk);
		hdr->crc = 0;

		error = brcm_iovar_set(sc, "clmload", hdr, hdrsz + chunk);
		if (error != 0) {
			DPRINTF(sc, 0,
			    "clmload: chunk@%zu (%zu bytes) failed rc=%d\n",
			    off, chunk, error);
			break;
		}
		off += chunk;
		flag &= ~BRCM_DL_BEGIN;
	}

	free(hdr, M_BRCM);
	firmware_put(fw, 0);
	if (error == 0)
		DPRINTF(sc, 0, "clmload: %zu bytes uploaded OK\n",
		    fw->datasize);
	return (error);
}

/* program the firmware's default settings after startup */
void
brcm_runtime_iovars(struct brcm_softc *sc)
{
	uint8_t mask[BRCM_EVENT_MASK_LEN];
	uint8_t country[4] = { 'U', 'S', 0, 0 };
	uint32_t v;
	int error;

	/*
	 * Upload CLM blob FIRST -- chip needs regulatory before any TX.
	 * The blob is named after sc_fw_basename, set by the transport at
	 * attach time (SDIO: brcmfmac<n>-sdio; USB: brcmfmac<n>b).
	 * Skipping when the basename is empty is non-fatal: the 2011 BCM43236
	 * blob ships without a CLM and chips with working defaults scan
	 * + AUTH without one.
	 */
	if (sc->sc_fw_basename[0] != '\0')
		(void)brcm_upload_clm_blob(sc, sc->sc_fw_basename);

	v = htole32(1);
	error = brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_UP rc=%d\n", error);

	memset(mask, 0, sizeof(mask));
#define	SETBIT(m, b)	((m)[(b) / 8] |= 1u << ((b) % 8))
	SETBIT(mask, BRCM_E_IF);
	SETBIT(mask, BRCM_E_TYPE_SET_SSID);	/* primary linkup signal */
	SETBIT(mask, BRCM_E_TYPE_JOIN);
	SETBIT(mask, BRCM_E_TYPE_LINK);
	SETBIT(mask, BRCM_E_TYPE_AUTH);
	SETBIT(mask, BRCM_E_TYPE_ASSOC);
	SETBIT(mask, BRCM_E_DEAUTH);
	SETBIT(mask, BRCM_E_TYPE_DISASSOC);
	SETBIT(mask, BRCM_E_EAPOL_MSG);
	SETBIT(mask, BRCM_E_TYPE_ESCAN_RESULT);
#undef SETBIT
	error = brcm_iovar_set(sc, "event_msgs", mask, sizeof(mask));
	DPRINTF(sc, 0, "event_msgs iovar rc=%d\n", error);

	error = brcm_iovar_set(sc, "country", country, sizeof(country));
	DPRINTF(sc, 0, "country=US iovar rc=%d\n", error);

	/*
	 * Probe the sup_wpa iovar.  We prefer host-side EAPOL at
	 * bringup (sup_wpa=0), but some fw revisions reject the set
	 * (BCM43455 fw 7.45.x returns -23, BCME_UNSUPPORTED: that build
	 * has no in-firmware supplicant).  If the set fails, try a get: iovar
	 * exists → we can toggle at join time.  If get also fails →
	 * fw lacks the iovar entirely → host-EAPOL-only.  Record the
	 * observed state in sc_sup_wpa_ok / sc_sup_wpa_current.
	 */
	v = htole32(0);
	error = brcm_iovar_set(sc, "sup_wpa", &v, sizeof(v));
	if (error == 0) {
		sc->sc_sup_wpa_ok = true;
		sc->sc_sup_wpa_current = 0;
		DPRINTF(sc, 0, "sup_wpa=0 iovar ok (host-side EAPOL)\n");
	} else {
		size_t glen = sizeof(v);
		int gerror;

		v = 0;
		gerror = brcm_iovar_get(sc, "sup_wpa", &v, &glen);
		if (gerror == 0) {
			sc->sc_sup_wpa_ok = true;
			sc->sc_sup_wpa_current = le32toh(v);
			DPRINTF(sc, 0,
			    "sup_wpa: set=0 rc=%d rejected, get=%u; "
			    "keeping fw default and toggling at join\n",
			    error, sc->sc_sup_wpa_current);
		} else {
			sc->sc_sup_wpa_ok = false;
			sc->sc_sup_wpa_current = 0;
			DPRINTF(sc, 0,
			    "sup_wpa iovar unavailable (set rc=%d get "
			    "rc=%d) — host-side EAPOL only, wsec_pmk "
			    "installs may fail on fw that requires "
			    "in-firmware supplicant\n", error, gerror);
		}
	}

	/*
	 * Hardening for the 2011 BCM43236 blob.  Only the iovars the
	 * firmware actually accepts go here; tdls/wps iovars are absent
	 * from this firmware revision (Cypress added them later) and
	 * p2p_disc rejects a uint32 write — its argument shape is
	 * undocumented for this blob, so leave it to manual probing via
	 * dev.brcm.<n>.iovar_set.  See SECURITY.md for the CVE backlog
	 * this firmware predates.
	 *
	 *   mpc=0        - radio stays on; closes the RX-window-gone
	 *                  class of attacks at the cost of more power
	 *
	 * roam_off=1 would close the on-chip beacon-parser surface too,
	 * but breaks joins; see below.
	 */
	v = htole32(0);
	error = brcm_iovar_set(sc, "mpc", &v, sizeof(v));
	DPRINTF(sc, 0, "harden mpc=0 rc=%d\n", error);
	/*
	 * mfp=0 (MFP_NONE).  Chip-default on BCM43455 fw 7.45.98 is
	 * mfp=1 (MFP_CAPABLE), which makes the chip advertise PMF in
	 * its assoc-req IEs and refuse to associate to a non-PMF AP.
	 * For a vanilla WPA2-PSK/CCMP target (hostapd's default, no
	 * ieee80211w) the chip emits SET_SSID rc=0 then silently
	 * never fires AUTH because PMF can't be negotiated.  Set
	 * MFP_NONE at attach so any join path -- open or WPA2 --
	 * lands cleanly.  brcm_join_wpa2_host_eapol sets mfp again
	 * per join, from the RSN IE.
	 */
	v = htole32(0);
	error = brcm_iovar_set(sc, "mfp", &v, sizeof(v));
	DPRINTF(sc, 0, "harden mfp=0 rc=%d\n", error);

	/*
	 * Power management.  Chip default may be PM_MAX (1) = aggressive
	 * doze-between-beacons.  In PM_MAX the chip's PS state machine can hold
	 * TX queues during the doze window, killing the on-air AUTH-frame TX
	 * window during a join.  Linux's brcmf_config_dongle defaults to
	 * PM_FAST (2), or PM_OFF when power save is disabled -- wake briefly
	 * between beacons but never doze through AUTH.  We pick PM_OFF (0) =
	 * always-awake at attach: best for debug + initial join, and Linux's
	 * tested PM_FAST path can be enabled later via iovar_set.
	 *
	 *   PM_OFF  = 0  always awake
	 *   PM_MAX  = 1  max power save (chip default suspect)
	 *   PM_FAST = 2  fast power save (Linux default)
	 */
	v = htole32(0);	/* PM_OFF */
	error = brcm_dcmd_set(sc, BRCM_C_SET_PM, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_SET_PM=PM_OFF rc=%d\n", error);

	/*
	 * Beacon timeout = 4 (Linux BRCMF_DEFAULT_BCN_TIMEOUT_ROAM_OFF).
	 * Time in seconds before chip declares the AP gone if no beacon
	 * RXed.  Default may be 2 which is aggressive -- if AP misses a
	 * couple of beacons during 4-way the chip self-disassocs.
	 */
	v = htole32(4);
	error = brcm_iovar_set(sc, "bcn_timeout", &v, sizeof(v));
	DPRINTF(sc, 0, "bcn_timeout=4 rc=%d\n", error);

	/*
	 * Frameburst on -- Linux's brcmf_config_dongle sets this for
	 * higher A-MPDU throughput.  Harmless if chip already enables it.
	 */
	v = htole32(1);
	error = brcm_dcmd_set(sc, BRCM_C_SET_FAKEFRAG, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_SET_FAKEFRAG=1 rc=%d\n", error);

	/*
	 * Scan dwell and txbf are left at the chip defaults: setting
	 * either stops AUTH events from firing on BCM43455 fw 7.45.x.
	 * Linux sets these but the values it picks (SCAN_CHANNEL_TIME=
	 * 40 ms) are too aggressive for this fw's join-scan path --
	 * chip can't fit an AUTH window between dwells.
	 */

	/*
	 * roam_off=1 disables the chip's on-chip roaming AND its
	 * pre-assoc beacon parser -- which is exactly what consumes
	 * beacons + probe responses during a join.  On BCM43455 fw
	 * 7.45.98 with roam_off=1 set at attach, SET_SSID returns
	 * rc=0 but the chip never emits AUTH/ASSOC because it can't
	 * parse the AP's beacons to know when to fire.  Skip it; the
	 * "hardening" trade isn't worth losing join.
	 */

	device_printf(sc->sc_dev,
	    "WARNING: firmware blob is from 2011 and predates Broadpwn/Kr00k/"
	    "FragAttacks; see brcm/SECURITY.md.  Use for experimental/CTF "
	    "only.\n");
}

/*
 * Register the operator-facing sysctls that live on the brcm core.
 * Transports call this after brcm_attach() so the sysctl tree exists
 * and the softc is fully initialised.
 */
void
brcm_sysctl_attach(struct brcm_softc *sc)
{
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(sc->sc_dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(sc->sc_dev);

	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "wpa_pmk",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pmk_sysctl, "A",
	    "WPA2-PSK passphrase (8..63 ASCII; empty clears)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "wpa_pmk_hex",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_pmk_hex_sysctl, "A",
	    "Raw 32-byte PMK as 64 hex chars (preferred for "
	    "2011 BCM43236 firmware; compute via wpa_passphrase)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "scan_now",
	    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, sc, 0,
	    brcm_scan_sysctl, "I",
	    "Trigger broadcast escan (write 1)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "join_target",
	    CTLTYPE_STRING | CTLFLAG_WR | CTLFLAG_MPSAFE, sc, 0,
	    brcm_join_sysctl, "A",
	    "Direct WPA2 join: 'aa:bb:cc:dd:ee:ff:SSID' "
	    "(set wpa_pmk first; empty to abort)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "iovar_get",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_iovar_get_sysctl, "A",
	    "Write iovar name to fetch; read returns hex value");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "event_stats",
	    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, sc, 0,
	    brcm_event_stats_sysctl, "A",
	    "Firmware events by type, and each task's requests vs coverage");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "iovar_set",
	    CTLTYPE_STRING | CTLFLAG_WR | CTLFLAG_MPSAFE, sc, 0,
	    brcm_iovar_set_sysctl, "A",
	    "Write 'name:hexpayload' to push a raw iovar "
	    "(gated by dev.brcm.<n>.unsafe=1)");
	/*
	 * Safety gate for the raw iovar_set path.  Also gates
	 * the CMD52/CMD53 raw-SDIO path on the SDIO transport's cdev.
	 * Default 0.  See sc_unsafe_iovars comment in brcmvar.h.
	 */
	SYSCTL_ADD_INT(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "unsafe",
	    CTLFLAG_RW, &sc->sc_unsafe_iovars, 0,
	    "Allow raw iovar_set + cdev CMD52/CMD53 (chip-CVE surface). "
	    "0=off (default), 1=on (root+PRIV_DRIVER still required).");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "sup_dump",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_sup_dump_sysctl, "A",
	    "Write 'OFFSET LEN' (patched fw); read returns hex bytes "
	    "from *(wlc+0x12)+OFFSET");
}

/* detach the driver from the wifi stack */
void
brcm_detach(struct brcm_softc *sc)
{
	/*
	 * Net80211 detach only.  Transport owns the mutex + ctl_pending
	 * lifetime and tears them down after stopping its own threads.
	 */
	if (sc->sc_ic_attached) {
		ieee80211_fmac_detach(&sc->sc_ic);
		ieee80211_ifdetach(&sc->sc_ic);
		sc->sc_ic_attached = false;
	}
}

/*
 * Common transport-teardown helper.  Called as the FIRST act of every
 * transport's detach path (SDIO, PCI, USB) and from attach-fail
 * cleanup.  Handles the state that every transport shares:
 *   1. sc_dying: gates future dcmds through ENXIO before any bus
 *      resource goes away.
 *   2. Wake every waiter parked in sc_ctl_pending so sleepers bail
 *      through the sc_dying check.
 *   3. Wait for sc_in_flight_dcmd to drain so no sleeper still owns
 *      &sc_ctl_mtx as its wchan when the caller destroys it.
 *   4. taskqueue_drain the scan-done and link tasks so no deferred
 *      work fires against freed state.
 *   5. ieee80211 ifdetach if attached — drains vaps and their locks.
 *
 * The transport still owns everything AFTER this returns:
 *   - stopping its transport-specific tasks/callouts/kprocs (SDIO
 *     watchdog callout+taskqueue, USB ctlrx_proc, PCI msgbuf reap)
 *   - unwinding its bus resources (BARs, xfers, F1/F2 disable)
 *   - the final mtx_destroy of sc_ctl_mtx / sc_mtx
 *
 * Idempotent w.r.t. sc_ctl_mtx: if the transport bailed before
 * mtx_init, we just flip sc_dying so any late-arriving dcmd fails.
 *
 * Skipping these steps leads to a callout firing after detach (the
 * SDIO watchdog), a sleeping dcmd waking on a destroyed mutex, or BARs
 * freed while the ic is still attached.
 */
void
brcm_transport_teardown(struct brcm_softc *sc)
{
	struct brcm_ctl_req *r;

	if (!mtx_initialized(&sc->sc_ctl_mtx)) {
		sc->sc_dying = true;
		goto post_ctl;
	}

	mtx_lock(&sc->sc_ctl_mtx);
	sc->sc_dying = true;
	TAILQ_FOREACH(r, &sc->sc_ctl_pending, link)
		wakeup(r);
	while (sc->sc_in_flight_dcmd != 0) {
		(void)mtx_sleep(&sc->sc_in_flight_dcmd, &sc->sc_ctl_mtx,
		    0, "brcmdcd", hz);
	}
	mtx_unlock(&sc->sc_ctl_mtx);

post_ctl:
	/*
	 * Guard the task drains: transport attach can fail (goto fail)
	 * before brcm_attach() runs TASK_INIT, in which case the task
	 * structs are zeroed memory and taskqueue_drain would be UB.
	 * sc_tasks_inited is set at the end of the TASK_INIT sequence
	 * in brcm_attach.
	 */
	if (sc->sc_tasks_inited) {
		taskqueue_drain(taskqueue_thread, &sc->sc_scan_done_task);
		taskqueue_drain(taskqueue_thread, &sc->sc_link_task);
		taskqueue_drain(taskqueue_thread, &sc->sc_assoc_task);
		taskqueue_drain(taskqueue_thread, &sc->sc_disassoc_task);
		taskqueue_drain(taskqueue_thread, &sc->sc_post_assoc_task);
	}

	if (sc->sc_ic_attached) {
		ieee80211_fmac_detach(&sc->sc_ic);
		ieee80211_ifdetach(&sc->sc_ic);
		sc->sc_ic_attached = false;
	}

	if (sc->sc_tasks_inited) {
		struct brcm_key_op *ko;

		taskqueue_drain(taskqueue_thread, &sc->sc_key_task);
		while ((ko = TAILQ_FIRST(&sc->sc_key_ops)) != NULL) {
			TAILQ_REMOVE(&sc->sc_key_ops, ko, ko_link);
			free(ko, M_BRCM);
		}
		mtx_destroy(&sc->sc_key_mtx);
	}
}
