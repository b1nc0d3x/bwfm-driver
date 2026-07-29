/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC (brcm) bus-agnostic core.
 *
 * This module is the layer above the transport (USB, SDIO, PCIe).  It
 * owns the chip-info dispatch table, the BCDC dcmd / iovar request
 * machinery, and the net80211 attachment surface (ieee80211_ifattach,
 * vap_create, scan/assoc/key stubs).  Bus transports call into here
 * via brcm_attach() and the bus_ops vtable; we call back through
 * sc->sc_bus_ops to push BCDC frames out to the chip.
 *
 * Design reference: OpenBSD sys/dev/ic/brcm.c.  No source lines are
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
#include <sys/queue.h>
#include <sys/socket.h>
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
 * recomputation that misses the AP's actual bandwidth.  Single
 * entry is enough for our STA-only single-vap usage.
 */
static uint8_t  brcm_join_chanspec_bssid[6];
static uint16_t brcm_join_chanspec_cached;

static void
brcm_cache_bssid_chanspec(const uint8_t bssid[6], uint16_t chanspec)
{
	memcpy(brcm_join_chanspec_bssid, bssid, 6);
	brcm_join_chanspec_cached = chanspec;
}

static uint16_t
brcm_lookup_bssid_chanspec(const uint8_t bssid[6])
{
	if (memcmp(brcm_join_chanspec_bssid, bssid, 6) == 0)
		return (brcm_join_chanspec_cached);
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
 * 15s matches the firmware's join-event timeout.
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
	{ 0xa9a6, 0,  0xff, "brcmfmac43143",  "BCM43143"        },
	{ 0xa8e4, 0,  2,    "brcmfmac43236a", "BCM43236 rev A"  },
	{ 0xa8e4, 3,  0xff, "brcmfmac43236b", "BCM43236 rev B"  },
	{ 0xa962, 0,  0xff, "brcmfmac43242a", "BCM43242"        },
	{ 0xa9bf, 0,  0xff, "brcmfmac43569",  "BCM43569"        },
	{ 0,      0,  0,    NULL,             NULL              },
};

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
	sc->sc_bcdc_reqid++;
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
	if (req.reply_flags & BRCM_BCDC_DCMD_ERROR)
		error = EIO;
	else
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
	sc->sc_bcdc_reqid++;
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
	else if (req.reply_flags & BRCM_BCDC_DCMD_ERROR)
		error = EIO;
	else
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
 * overflow the kthread stack.  See project_brcm_net80211_phase1c.
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
 * Hand one firmware-supplied BSS straight to net80211's scan cache.
 *
 * Replaces the previous brcm_inject_beacon path that built a synthetic
 * beacon mbuf, called ieee80211_fmac_input_beacon, ran the full
 * ieee80211_parse_beacon IE walker, and only then reached sc_add_scan.
 * Flattening saves ~3-4 stack frames per BSS, which is what kept
 * sustained scans from overflowing the evrx worker's stack.
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
	brcm_cache_bssid_chanspec(bss->bssid, le16toh(bss->chanspec));

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

	nf = bss->phy_noise != 0 ? bss->phy_noise : -95;
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
	 * swscan_add_scan's ISCAN_DISCARD drop had been hiding
	 * this; once we bypass that gate, malformed firmware
	 * beacon clones reach sta_add and NULL-deref or overflow.
	 * Drop the BSS in either case.
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
	 * brcmreg.h); the previous le32toh read 4 bytes from a 2-byte
	 * slot, picking up the first 2 bytes of the bss_info that
	 * follows.  Garbage values (typically ~7 million) caused the
	 * per-BSS loop to iterate until cursor < end tripped, treating
	 * arbitrary kernel memory as bss_info and eventually memcpying
	 * from an unmapped kva — vm_fault_lookup on nofault entry.
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
	struct ieee80211com *ic __unused = &sc->sc_ic;
	struct ieee80211vap *vap __unused;
	uint32_t evtype, status;
	uint16_t eflags;

	if (len < evpos + sizeof(*emsg))
		return;
	emsg = (const struct brcm_event_msg *)(p + evpos);
	evtype = be32toh(emsg->event_type);
	status = be32toh(emsg->status);

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
		 * guard so the next cmd_scan can proceed.
		 */
		DPRINTF(sc, 1, "scan complete (status=%u)\n", status);
		sc->sc_scan_busy = 0;
		if (sc->sc_ic_attached)
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_scan_done_task);
		return;
	}
	if (evtype == BRCM_E_TYPE_LINK) {
		eflags = be16toh(emsg->flags);
		DPRINTF(sc, 0, "LINK %s status=%u\n",
		    (eflags & BRCM_E_FLAG_LINK_UP) ? "up" : "down", status);
		sc->sc_link_up = (eflags & BRCM_E_FLAG_LINK_UP) != 0;
		sc->sc_join_busy = 0;	/* terminator: either success or fail */
		if (sc->sc_ic_attached)
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_link_task);
		return;
	}
	if (evtype == BRCM_E_TYPE_SET_SSID) {
		/*
		 * E_SET_SSID status=SUCCESS is the PRIMARY linkup trigger
		 * for the host-EAPOL path (FWSUP_NONE).  E_LINK with
		 * LINK_UP flag may fire much later or not at all on some
		 * fw.  Process this as the linkup signal too -- belt +
		 * braces with the existing E_LINK handler above.
		 */
		DPRINTF(sc, 0, "SET_SSID status=%u%s\n", status,
		    status == BRCM_E_STATUS_SUCCESS ?
		    " -> linkup" : " -> failure");
		if (status == BRCM_E_STATUS_SUCCESS) {
			sc->sc_link_up = 1;
			sc->sc_join_busy = 0;
			/*
			 * Seed the join cache from the SET_SSID event so
			 * brcm_link_task's sta_join_from_cache branch fires
			 * even when the fw auto-joined off its own escan
			 * match instead of net80211's MLME_ASSOC.  emsg->addr
			 * is the AP BSSID; vap->iv_des_ssid[0] is whatever
			 * wpa_supplicant asked for via SIOCS80211 IOC_SSID.
			 */
			if (sc->sc_ic_attached && sc->sc_join_ssid_len == 0) {
				struct ieee80211vap *_vap =
				    TAILQ_FIRST(&sc->sc_ic.ic_vaps);
				if (_vap != NULL && _vap->iv_des_nssid > 0 &&
				    _vap->iv_des_ssid[0].len > 0 &&
				    _vap->iv_des_ssid[0].len <=
				    sizeof(sc->sc_join_ssid) - 1) {
					memcpy(sc->sc_join_bssid,
					    emsg->addr, 6);
					memcpy(sc->sc_join_ssid,
					    _vap->iv_des_ssid[0].ssid,
					    _vap->iv_des_ssid[0].len);
					sc->sc_join_ssid[
					    _vap->iv_des_ssid[0].len] = '\0';
					sc->sc_join_ssid_len =
					    _vap->iv_des_ssid[0].len;
					DPRINTF(sc, 0,
					    "SET_SSID: cached "
					    "%02x:%02x:%02x:%02x:%02x:%02x "
					    "ssid=\"%s\" for link fast-forward\n",
					    emsg->addr[0], emsg->addr[1],
					    emsg->addr[2], emsg->addr[3],
					    emsg->addr[4], emsg->addr[5],
					    sc->sc_join_ssid);
				}
			}
			if (sc->sc_ic_attached)
				(void)taskqueue_enqueue(taskqueue_thread,
				    &sc->sc_link_task);
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
		 * On ASSOC success, dispatch post-assoc handshake taskqueue
		 * to fire the GET iovars: assoc_info, assoc_req_ies,
		 * assoc_resp_ies, wme_ac_sta, and BRCMF_C_GET_BSS_INFO.
		 * Chip may tear down LINK if host doesn't interact within
		 * a window -- keep chip happy.
		 *
		 * Also treat E_TYPE_ASSOC SUCCESS as the linkup trigger --
		 * BCM43455 fw 7.45.x never emits E_TYPE_LINK (16) nor
		 * E_TYPE_SET_SSID (0) on the host-EAPOL path until AFTER
		 * 4-way completes.  If we wait for those, wpa_supplicant
		 * stalls at ASSOCIATING (no RTM_IEEE80211_ASSOC on
		 * PF_ROUTE) and never drives the 4-way in response to the
		 * EAPOL M1 we already forwarded to wlan0 via
		 * ieee80211_fmac_eapol_rx.  Walk vap AUTH/ASSOC -> RUN via
		 * the framework's fast-forward (link_task ->
		 * ieee80211_fmac_link_up).
		 */
		if (evtype == BRCM_E_TYPE_ASSOC &&
		    status == BRCM_E_STATUS_SUCCESS && sc->sc_ic_attached) {
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_post_assoc_task);
			sc->sc_link_up = 1;
			sc->sc_join_busy = 0;
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->sc_link_task);
		}
		return;
	}
	if (evtype == BRCM_E_TYPE_DISASSOC) {
		DPRINTF(sc, 0, "DISASSOC reason=%u\n",
		    be32toh(emsg->reason));
		sc->sc_join_busy = 0;	/* allow next join attempt */
		/*
		 * Scanning disabled while investigating post-4-way disassoc.
		 * Let the vap stay wherever it is instead of driving to SCAN;
		 * this stops the re-associate churn so we can read the chip's
		 * console / shared memory in a stable state.
		 */
		return;
	}
	if (evtype == BRCM_E_EAPOL_MSG) {
		/*
		 * With sup_wpa=0 the chip delivers each EAPOL frame BOTH
		 * as a BRCM_E_EAPOL_MSG event AND as an 802.3 data frame
		 * on the msgbuf RX ring.  The data path already forwards
		 * to ieee80211_fmac_eapol_rx (see if_brcm_pci.c
		 * brcm_pci_msgbuf_rx_up) so dispatching the event copy
		 * here delivers the same frame to wpa_supplicant twice.
		 * Symptom: each M1 triggers two M2 sends, first M2 arrives
		 * ~1s late, hostapd 4-way timeout kills the association
		 * and DHCPDISCOVER starves.  Ignore the event copy; keep
		 * subscription enabled so fw stays in host-supplicant
		 * mode (some fw revs gate that off event-mask presence).
		 */
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
		 * NOT as BRCM_E_EAPOL_MSG events.  AP TXes EAPOL M1
		 * unicast + chip RXes it, but wpa_supplicant never saw M1
		 * because ieee80211_input_all expects 802.11+radiotap not
		 * 802.3.
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

		DPRINTF(sc, 1, "DATA eth=0x%04x len=%zu\n", ethertype, len);
		m->m_pkthdr.rcvif = vap->iv_ifp;
		(void)ieee80211_input_all(ic, m, -50, -95);
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
 * Tries the SET_VAR "wsec_pmk" path first (modern firmware) and
 * falls back to BRCM_C_SET_WSEC_PMK opcode 268 (legacy / 2011
 * firmware).
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
	 * Drive this exclusively via BRCM_C_SET_WSEC_PMK opcode 268.
	 * For the 2011 firmware the "wsec_pmk" iovar string is not in
	 * the dispatcher at all, so the opcode is the only working
	 * path here.  Try the opcode first; keep the iovar fallback
	 * for completeness so newer firmware that exposes it as a
	 * named iovar also works.
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
 * Order matches OpenBSD brcm: DOWN -> infra / auth / wsec / wpa_auth
 * / wsec_pmk -> UP -> SET_SSID.  The 2011 firmware rejects wsec_pmk
 * with BCME_BADARG (-23) unless the data plane is DOWN; non-fatal
 * here so the join can still proceed if the chip's supplicant has
 * the credentials from a previous session.
 */
static int
brcm_join_wpa2_raw(struct brcm_softc *sc, const uint8_t bssid[6],
    const char *ssid, size_t ssid_len, uint16_t chanspec_hint)
{
	struct brcm_join_params join;
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

	v = htole32(sc->sc_sae_join ? BRCM_WPA_AUTH_WPA3_SAE_PSK :
	    BRCM_WPA_AUTH_WPA2_PSK);
	error = brcm_iovar_set(sc, "wpa_auth", &v, sizeof(v));
	if (error != 0)
		goto fail;
	if (sc->sc_sae_join) {
		uint32_t mfp = htole32(BRCM_MFP_REQUIRED);
		(void)brcm_iovar_set(sc, "mfp", &mfp, sizeof(mfp));
	}

	/*
	 * Enable the in-firmware supplicant.  Required by BCM43455 fw
	 * 7.45.x: without sup_wpa=1 the chip rejects wsec_pmk install
	 * with BCME_BADARG (-2) and the 4-way handshake never runs.
	 * Non-fatal: older fw (2011 BCM43236) doesn't have the iovar
	 * and runs 4-way via host EAPOL instead.  For WPA3-SAE the fw
	 * supplicant is mandatory — SAE exchange runs inside fw.
	 */
	v = htole32(1);
	(void)brcm_iovar_set(sc, "sup_wpa", &v, sizeof(v));

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
	sc->sc_wlc_up = true;

	memset(&join, 0, sizeof(join));
	join.ssid.len = htole32(ssid_len);
	memcpy(join.ssid.ssid, ssid, ssid_len);
	memcpy(join.assoc.bssid, bssid, 6);

	/*
	 * chanspec_num=0 ("any channel") forces the chip to re-scan for
	 * the target SSID.  On BCM43602 v7.35 that silent-scan path leaves
	 * the chip stuck at channel 1 with ssid="" (SET_SSID rc=0 but no
	 * SET_SSID event ever fires).  Pass the fw-cached chanspec from
	 * the last ESCAN_RESULT for this BSSID so the chip parks directly.
	 */
	{
		uint16_t chanspec = chanspec_hint != 0 ? chanspec_hint :
		    brcm_lookup_bssid_chanspec(bssid);
		size_t jlen;

		if (chanspec != 0) {
			join.assoc.chanspec_num = htole32(1);
			join.assoc.chanspec_list[0] = htole16(chanspec);
			jlen = BRCM_JOIN_PARAMS_FIXED_SIZE + sizeof(uint16_t);
		} else {
			join.assoc.chanspec_num = 0;
			jlen = BRCM_JOIN_PARAMS_FIXED_SIZE;
		}

		DPRINTF(sc, 0,
		    "join WPA2: ssid=\"%.*s\" bssid=%02x:%02x:%02x:%02x:%02x:%02x chanspec=0x%04x jlen=%zu\n",
		    (int)ssid_len, ssid,
		    bssid[0], bssid[1], bssid[2],
		    bssid[3], bssid[4], bssid[5], chanspec, jlen);

		error = brcm_dcmd_set(sc, BRCM_C_SET_SSID, &join, jlen);
	}
	if (error != 0)
		goto fail;
	/* sc_join_busy stays set until LINK or DISASSOC event clears it. */
	return (0);
fail:
	sc->sc_join_busy = 0;
	return (error);
}

static int
brcm_join_wpa2(struct brcm_softc *sc, struct ieee80211vap *vap)
{
	struct ieee80211_node *ni;

	ni = vap->iv_bss;
	if (ni == NULL)
		return (EINVAL);
	return (brcm_join_wpa2_raw(sc, ni->ni_bssid,
	    (const char *)ni->ni_essid, ni->ni_esslen, 0));
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
	 * WPA2_PSK from a previous brcm_join_wpa2_raw on this
	 * session keeps the chip in WPA2 mode -- it'll silently
	 * drop probe responses that don't include matching RSN
	 * IEs and never reach AUTH.
	 *
	 * Do NOT wrap in DOWN/UP -- the BCM43455 fw 7.45.98 join
	 * state machine never fires AUTH after a DOWN/UP cycle
	 * (iovars take effect but SET_SSID rc=0 produces zero on-air
	 * frames).  Just program the iovars on the already-UP chip.
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
	chanspec = brcm_lookup_bssid_chanspec(ni->ni_bssid);
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
	return (bv->bv_newstate(vap, nstate, arg));
}

/*
 * Deferred scan-completion notifier.  Runs on taskqueue_thread so we
 * call ieee80211_scan_done() with the correct lock context; USB
 * callback context is not safe.
 */
static void
brcm_scan_done_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	struct ieee80211vap *vap;

	if (!sc->sc_ic_attached)
		return;
	vap = TAILQ_FIRST(&sc->sc_ic.ic_vaps);
	if (vap == NULL)
		return;
	ieee80211_scan_done(vap);
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

static void
brcm_link_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;

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
		return;
	}

	if (vap->iv_state != IEEE80211_S_RUN &&
	    sc->sc_join_ssid_len != 0) {
		int rc = brcm_sta_join_from_cache(sc);

		DPRINTF(sc, 0,
		    "link task: vap=%d, sta_join_from_cache rc=%d\n",
		    vap->iv_state, rc);
		if (rc != 0) {
			/* Nothing to join to in cache yet.  Kick a scan so
			 * the next LINK up has a populated cache to anchor
			 * the vap walk on. */
			(void)ieee80211_new_state(vap, IEEE80211_S_SCAN, -1);
			return;
		}
		/*
		 * sta_join walks the vap to AUTH.  This is the LINK-up event
		 * that woke us; there is no follow-up event to trigger the
		 * fast-forward, so drive it now.  Without this the vap sits
		 * at AUTH indefinitely while the chip already has an
		 * association and wpa_supplicant races the 4-way against
		 * the assoc-response timeout.
		 */
		if (ieee80211_fmac_link_up(&sc->sc_ic, NULL) == 0)
			DPRINTF(sc, 0,
			    "link task: vap walked to RUN via sta_join + "
			    "fast-forward\n");
		return;
	}
	ni = vap->iv_bss;
	DPRINTF(sc, 0,
	    "link task: vap state=%d ni_chan=%p; framework declined "
	    "and no cache fallback applies\n",
	    vap->iv_state, ni ? ni->ni_chan : NULL);
}

/*
 * Phase 10: install a derived PTK / GTK / WEP key on the chip via
 * WLC_SET_KEY (opcode 45).  Called from iv_key_set after userspace
 * wpa_supplicant completes the 4-way handshake and hands us the PTK
 * (key_index=0 with peer EA + PRIMARY_KEY flag) and GTK
 * (key_index=1..3 with broadcast EA).  algo=OFF + len=0 clears the
 * slot.
 */
static int
brcm_set_key(struct brcm_softc *sc, uint32_t key_index, uint32_t algo,
    uint32_t flags, const uint8_t *key, uint32_t key_len,
    const uint8_t ea[6], uint64_t rsc)
{
	struct brcm_wsec_key_le wk;
	int error;

	if (key_len > sizeof(wk.data))
		return (EINVAL);

	/*
	 * 164-byte "wsec_key" iovar.  Replaces the 37-byte
	 * BRCM_C_SET_KEY=45 dcmd path: BCM43455 fw 7.45.x rejects the
	 * legacy dcmd with BCME_BADARG, only services the iovar form.
	 */
	memset(&wk, 0, sizeof(wk));
	wk.index = htole32(key_index);
	wk.len = htole32(key_len);
	if (key_len > 0 && key != NULL)
		memcpy(wk.data, key, key_len);
	wk.algo = htole32(algo);
	wk.flags = htole32(flags);
	/*
	 * For a group-key install fw expects the RSC (48-bit PN) from M3
	 * plus iv_initialized=1.  Without these, GTK install returns
	 * BCME_ERROR (5).  Pairwise (PTK) install MUST use rsc=0 and
	 * iv_initialized=0 — Linux brcmfmac only sets iv_initialized
	 * when the userspace supplicant supplied a `seq` (which happens
	 * for GTK from M3, not for the freshly-derived PTK).  Forcing
	 * iv_initialized=1 for the PTK case makes the fw think the RX PN
	 * counter is already at some non-zero value; subsequent post-
	 * 4-way data frames get encrypted with a PN mis-aligned relative
	 * to the AP's expectation and the AP silently drops every one
	 * (verified via cross-STA `iw dev X station dump` on the AP —
	 * rx bytes stays 0 forever).
	 */
	if (rsc != 0) {
		wk.iv_initialized = htole32(1);
		wk.rxiv.hi = htole32((uint32_t)((rsc >> 16) & 0xffffffff));
		wk.rxiv.lo = htole16((uint16_t)(rsc & 0xffff));
	}
	memcpy(wk.ea, ea, 6);

	DPRINTF(sc, 0,
	    "wsec_key: idx=%u len=%u algo=%u flags=0x%x peer=%02x:%02x"
	    ":%02x:%02x:%02x:%02x\n",
	    key_index, key_len, algo, flags,
	    ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);

	error = brcm_iovar_set(sc, "wsec_key", &wk, sizeof(wk));
	DPRINTF(sc, 0, "wsec_key: rc=%d\n", error);
	if (error == 0 && algo != BRCM_CRYPTO_ALGO_OFF && key_len > 0)
		sc->sc_last_key_ts = time_uptime;
	return (error);
}

/*
 * After both PTK + GTK are installed via wsec_key, fire
 * BRCMF_C_SET_SCB_AUTHORIZE=121 with the AP's MAC.  This tells the
 * chip's data-plane that frames to/from the AP are now authorized
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
 * Stub BIP-CMAC-128 cipher.  FreeBSD 15.x does not ship a
 * `wlan_bip_cmac` cipher module in the base tree, so a FullMAC driver
 * that wants to advertise `IEEE80211_CRYPTO_BIP_CMAC_128` in its
 * ic_cryptocaps cannot rely on the usual auto-load path — net80211's
 * ieee80211_crypto_newkey() calls ieee80211_load_module("wlan_bip_cmac")
 * which fails, and the IGTK install from wpa_supplicant returns
 * "Failed to configure IGTK to the driver."
 *
 * For a FullMAC driver where the firmware performs the actual BIP
 * integrity checking on protected management frames, the net80211
 * cipher module only has to satisfy the key allocation path so the
 * IGTK can be forwarded to the driver via iv_key_set / fmop_set_key.
 * All wire-side operations (encap/decap/enmic/demic) are no-ops at the
 * net80211 layer because the frames never traverse the software crypto
 * stack — they are handed to the fw as-is and the fw applies BIP
 * protection on TX and validates it on RX.
 *
 * Registered from brcm_ic_attach() via ieee80211_crypto_register() and
 * unregistered at detach.
 */
struct brcm_bip_ctx {
	struct ieee80211vap	*bc_vap;
};

static void *
brcm_bip_attach(struct ieee80211vap *vap, struct ieee80211_key *k __unused)
{
	struct brcm_bip_ctx *ctx;

	ctx = IEEE80211_MALLOC(sizeof(*ctx), M_80211_CRYPTO,
	    IEEE80211_M_NOWAIT | IEEE80211_M_ZERO);
	if (ctx == NULL) {
		vap->iv_stats.is_crypto_nomem++;
		return (NULL);
	}
	ctx->bc_vap = vap;
	return (ctx);
}

static void
brcm_bip_detach(struct ieee80211_key *k)
{

	IEEE80211_FREE(k->wk_private, M_80211_CRYPTO);
}

static int	brcm_bip_setkey(struct ieee80211_key *k __unused) { return (1); }
static void	brcm_bip_setiv(struct ieee80211_key *k __unused,
    uint8_t *iv __unused) { }
static int	brcm_bip_encap(struct ieee80211_key *k __unused,
    struct mbuf *m __unused) { return (1); }
static int	brcm_bip_decap(struct ieee80211_key *k __unused,
    struct mbuf *m __unused, int off __unused) { return (1); }
static int	brcm_bip_enmic(struct ieee80211_key *k __unused,
    struct mbuf *m __unused, int off __unused) { return (1); }
static int	brcm_bip_demic(struct ieee80211_key *k __unused,
    struct mbuf *m __unused, int off __unused) { return (1); }

static const struct ieee80211_cipher brcm_bip_cipher = {
	.ic_name	= "AES-128-CMAC",
	.ic_cipher	= IEEE80211_CIPHER_BIP_CMAC_128,
	.ic_header	= 0,
	.ic_trailer	= 0,
	.ic_miclen	= 0,
	.ic_attach	= brcm_bip_attach,
	.ic_detach	= brcm_bip_detach,
	.ic_setkey	= brcm_bip_setkey,
	.ic_setiv	= brcm_bip_setiv,
	.ic_encap	= brcm_bip_encap,
	.ic_decap	= brcm_bip_decap,
	.ic_enmic	= brcm_bip_enmic,
	.ic_demic	= brcm_bip_demic,
};

/*
 * Phase 10 FullMAC key hooks.  userspace wpa_supplicant runs the 4-way
 * handshake (because sup_wpa=0 disables the firmware supplicant) and
 * then asks net80211 to install the derived PTK + GTK.  net80211 calls
 * these hooks; we forward the keys to the chip via WLC_SET_KEY (45).
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
	case IEEE80211_CIPHER_BIP_CMAC_128:
		/*
		 * Broadcom fw has no separate BIP algo — the IGTK is installed
		 * with CRYPTO_ALGO_AES_CCM and a management key index (4 or 5
		 * per 802.11).  Fw picks BIP vs CCMP based on the key index.
		 * Linux brcmfmac does the same at cfg80211.c:2883.
		 */
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
static struct ieee80211vap *
brcm_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
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

	/*
	 * Hand vap-level slots to the FullMAC framework.  fmac_newstate
	 * intercepts AUTH/ASSOC and side-effect-dispatches the join via
	 * fmop_assoc, then chains to brcm_newstate (the saved hook).
	 * fmac_key_set / fmac_key_delete forward straight into the
	 * fmop_set_key / fmop_del_key ops — brcm_key_set / _delete are
	 * gone, the chip-side dispatch lives directly in brcm_fmop_*.
	 */
	ieee80211_fmac_vap_attach(vap);

	/* Media change/status callbacks.  On amd64 the standard net80211
	 * helpers are exported and let ifconfig(8) render `list scan` etc.
	 * Some older arm64 FreeBSD builds don't export these symbols, so
	 * the stub build falls back to NULL (net80211 tolerates it but
	 * ifconfig SIOCGIFMEDIA prints "Programming error"). */
#ifdef __amd64__
	ieee80211_vap_attach(vap, ieee80211_media_change,
	    ieee80211_media_status, mac);
#else
	ieee80211_vap_attach(vap, NULL, NULL, mac);
#endif
	ic->ic_opmode = opmode;
	return (vap);
}

static void
brcm_vap_delete(struct ieee80211vap *vap)
{
	struct brcm_vap *bv = BRCM_VAP(vap);

	ieee80211_vap_detach(vap);
	free(bv, M_BRCM);
}

static void
brcm_parent_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	uint32_t v;
	int error;
	bool want_up;

	want_up = sc->sc_parent_want_up;
	if (want_up && !sc->sc_wlc_up) {
		v = htole32(1);
		error = brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));
		DPRINTF(sc, 0, "brcm_parent_task: BRCM_C_UP rc=%d\n", error);
		if (error == 0)
			sc->sc_wlc_up = true;
	}
	/*
	 * `ifconfig wlan0 down` walks every vap to INIT.  Fire an explicit
	 * WLC_DISASSOC so fw leaves the AP cleanly and drops its own
	 * flowring tables — otherwise fw retains its assoc state, the next
	 * `ifconfig up` + wpa_supplicant restart lands on a chip that
	 * thinks it's still joined, and the hostapd 4-way times out in
	 * ~4 s.  Skip when link is already down (chip-initiated disassoc
	 * already tore things down) and when we're in the join blackout
	 * (post-key-install, wpa_supplicant may bounce the vap through
	 * INIT briefly).
	 */
	if (!want_up && sc->sc_link_up) {
		struct brcm_scb_val_le sv;
		time_t now = time_uptime;

		if (sc->sc_last_key_ts != 0 &&
		    now - sc->sc_last_key_ts < 5) {
			DPRINTF(sc, 0, "brcm_parent_task: DOWN "
			    "post-key blackout — skipping WLC_DISASSOC\n");
			return;
		}
		memset(&sv, 0, sizeof(sv));
		sv.val = htole32(3);	/* reason: unspecified */
		error = brcm_dcmd_set(sc, BRCM_C_DISASSOC, &sv, sizeof(sv));
		DPRINTF(sc, 0,
		    "brcm_parent_task: WLC_DISASSOC rc=%d (vap→INIT)\n",
		    error);
	}
}

static void
brcm_parent(struct ieee80211com *ic)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap;
	bool want_up = false;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_state != IEEE80211_S_INIT) {
			want_up = true;
			break;
		}
	}

	sc->sc_parent_want_up = want_up;
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_parent_task);
}

static int
brcm_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	struct brcm_softc *sc = ic->ic_softc;

	return (sc->sc_bus_ops->bs_txdata(sc, m));
}

static int
brcm_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params __unused)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct brcm_softc *sc = ic->ic_softc;

	return (sc->sc_bus_ops->bs_txdata(sc, m));
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
	 * cmd_scan sysctl share state.  Without it, three back-to-back
	 * `ifconfig wlan0 scan` invocations push three escan iovars
	 * to the chip and panic the kernel as their ESCAN_RESULT
	 * streams interleave through the SDPCM ctl path.
	 *
	 * Cleared by the terminator ESCAN_RESULT (any non-PARTIAL
	 * status) routed through brcm_handle_event.
	 */
	if (sc->sc_scan_busy)
		return (EAGAIN);
	sc->sc_scan_busy = 1;

	memset(&params, 0, sizeof(params));
	memset(params.scan_params.bssid, 0xff,
	    sizeof(params.scan_params.bssid));
	params.scan_params.bss_type = BRCM_DOT11_BSSTYPE_ANY;
	/*
	 * Use SCANTYPE_ACTIVE for broadcast escan.  PASSIVE requires
	 * fw-side channel dwelling setup we don't do -- on BCM43602
	 * v7.35.177.61 the escan iovar with PASSIVE + all channels +
	 * no preflight wedges the host (fw hangs, subsequent MMIO
	 * faults).
	 */
	params.scan_params.scan_type = BRCM_SCANTYPE_ACTIVE;
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
 * Production semantics:
 *   - mcast_list iovar:  list of host's multicast group MAC addresses
 *     so chip RXes their frames.  Payload = {u32 count; u8 mac[count][6];}.
 *   - allmulti iovar:    bool; if true chip RXes ALL multicast (promisc
 *     subset).  Set to 1 only if mcast_list rejected.
 *   - cmd 10 SET_PROMISC: full promisc mode toggle.
 *
 * Minimal-but-correct first cut: always send allmulti=1 (cheap, chip
 * RXes all multicast), and let SET_PROMISC reflect IFF_PROMISC.
 * mcast_list-per-group is a P3 optimisation -- chip-side packet count
 * with allmulti=1 is small enough for production.
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
 * (band in the top 2 bits) — handle later when newer blobs ship.
 */
bool
brcm_chanspec_is_5ghz(uint16_t chanspec)
{
	uint8_t chan = (uint8_t)(chanspec & 0xff);

	/*
	 * Two encodings in the wild:
	 *  - Pre-2014 (BCM43236-era): band lives in bits 15-12,
	 *    0x1000 = 5G, 0x2000 = 2G.
	 *  - Modern (BCM43455 fw 7.45.x as observed on Pi 4):
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

uint8_t
brcm_chanspec_to_chan(uint16_t chanspec)
{

	return ((uint8_t)(chanspec & 0xff));
}

/*
 * Compute a Broadcom d11ac chanspec from an IEEE channel number.
 * Used when building bsscfg:join ext_assoc_params for a target AP
 * whose ni_chan->ic_ieee we know.  Format (Broadcom d11ac):
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

/* Storage + accessors moved to file scope -- referenced from
 * brcm_add_scan_result (much earlier in the file). */

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
 * FullMAC ops table.  Phase 2: leaf ops (set_country, set_key,
 * disassoc, scan_start) are now wired through to the underlying
 * dcmd / iovar.  fmop_assoc still returns ENXIO so the framework
 * falls through to bv_newstate — driver-specific join dispatch
 * (cache lookup, raw-join fallback, channel-mismatch heuristics)
 * stays inside brcm_newstate until Phase 3.
 *
 * ENXIO is the agreed "I declined this op; framework, fall
 * through to the saved hook" sentinel.  Any other non-zero return
 * propagates to the caller as a real error.
 */
static void
brcm_scan_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	int rc;

	DPRINTF(sc, 0, "SCAN_DBG: scan_task START\n");
	rc = brcm_dispatch_scan(sc);
	DPRINTF(sc, 0, "SCAN_DBG: scan_task done rc=%d\n", rc);
}

/*
 * Called from ic_scan_start under IEEE80211_LOCK.  We MUST return
 * quickly without acquiring any sleep locks — the DCMD path
 * (sx_xlock + cv_wait) can wedge if IEEE80211_LOCK is held.  Queue
 * the actual escan iovar send to taskqueue_thread.
 *
 * Return 0 unconditionally: the async task carries scan status via
 * sc_scan_busy, and results arrive via ESCAN_RESULT events.  Even if
 * fw rejects the iovar, net80211 will time out its own scan window.
 */
static int
brcm_fmop_scan_start(struct ieee80211com *ic,
    const uint8_t *ssid __unused, size_t ssidlen __unused,
    bool active __unused)
{
	struct brcm_softc *sc = ic->ic_softc;

	/*
	 * Suppress background scans while the vap is at RUN.  net80211's
	 * STA state machine periodically transitions RUN -> SCAN -> RUN
	 * for a background scan; on this FullMAC driver each SCAN
	 * transition drops the ifp link state and dhclient refuses to
	 * send DISCOVER without carrier.  Initial (pre-associated) scans
	 * still fire so wpa_supplicant can seed the scan cache and pick
	 * an AP.
	 */
	{
		struct ieee80211vap *_vap = TAILQ_FIRST(&ic->ic_vaps);
		if (_vap != NULL && _vap->iv_state == IEEE80211_S_RUN) {
			DPRINTF(sc, 0, "SCAN_DBG: fmop_scan_start "
			    "suppressed (vap at RUN)\n");
			return (0);
		}
	}
	DPRINTF(sc, 0, "SCAN_DBG: fmop_scan_start active=%d "
	    "→ queue task\n", active);
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_scan_task);
	return (0);
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
 * forwards via ieee80211_fmac_eapol_rx -> ieee80211_input_all ->
 * BPF where wpa_supplicant picks it up.
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
	 * (brcm_join_wpa2_raw) does DOWN->iovars->UP->SET_SSID and
	 * AUTH+ASSOC succeed; without the DOWN/UP wrap here host-EAPOL
	 * gets AUTH status=2 TIMEOUT.  The prior "DOWN/UP wedges chip"
	 * finding was specific to the bsscfg:join iovar path, which is
	 * no longer in use.
	 *
	 * We still keep the wpaie + double wpa_auth + cmd 205 +
	 * mfp/mpc/join_pref iovars -- they're compatible with the
	 * DOWN/UP wrap.
	 */
	v = htole32(0);
	(void)brcm_dcmd_set(sc, BRCM_C_DOWN, &v, sizeof(v));
	DPRINTF(sc, 0, "host-EAPOL: DOWN\n");

	/*
	 * Purge every host-side flowring after WLC_DOWN.  Fw drops its
	 * own flowring tables on WLC_DOWN, so a stale-OPEN host-side ring
	 * would send M2 into a dead peer.  We send FLOW_RING_DELETE
	 * synchronously and wait for CMPLT — each slot goes CLOSED so the
	 * next TX creates a fresh ring.  Non-fatal on failure.  Only PCIe
	 * transports install this op; USB/SDIO leave it NULL.
	 */
	if (sc->sc_bus_ops->bs_flowring_purge != NULL) {
		sc->sc_bus_ops->bs_flowring_purge(sc);
		DPRINTF(sc, 0, "host-EAPOL: flowring purge done\n");
	}

	v = htole32(1);
	HOSTEAP_RC("SET_INFRA",
	    brcm_dcmd_set(sc, BRCM_C_SET_INFRA, &v, sizeof(v)));

	/*
	 * wpaie iovar - required.  Earlier commit removed this thinking
	 * it broke us, but with the rest of the sequence (double
	 * wpa_auth write, cmd 205, bsscfg:join) it's needed.
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
			 * Sniff RSN caps for MFPC bit.  IE layout:
			 *   30 LL 01 00 <gcs 4B> <pcnt 2B> <psuite 4B*n>
			 *   <akmcnt 2B> <akm 4B*n> <cap 2B> ...
			 * We can't robustly parse without knowing n, but the
			 * cap byte with MFPC is the last 2 bytes of the "own
			 * WPA IE default" (22-byte 1-AKM+1-pairwise form)
			 * or 6 bytes back from end of the 30-byte
			 * MFP-included form.  Cheapest heuristic: scan the
			 * IE for any 2-byte pattern (cap word) that has
			 * MFPC (0x80) or MFPR (0x40) set — but that's a
			 * false-positive risk.  Since our own IE isn't
			 * user-controlled and comes straight from
			 * wpa_supplicant, either it wants MFP or it
			 * doesn't; check by pattern-searching the RSN
			 * capability offset when possible.  Fall back to
			 * MFP_CAPABLE if length >= 28 (has room for
			 * PMKID+GroupMgmt suffix).
			 */
			if (rsn_ie_len >= 28)
				mfp = BRCM_MFP_CAPABLE;
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
	 * Minimal post-DOWN iovar set -- mirrors chip-supplicant
	 * brcm_join_wpa2_raw which produces EVENT JOIN status=0.
	 *
	 * Use BRCM_C_SET_AUTH dcmd (cmd 22) for auth, NOT "auth" iovar --
	 * chip-supplicant succeeded with the dcmd form.  Use single
	 * wpa_auth write (just WPA2_PSK=0x80) -- chip-supplicant skips
	 * the 0xC0 preface some drivers emit.
	 *
	 * Drop mfp + ASSOC_PREFER + mpc + join_pref iovars.  Already set
	 * to safe defaults in brcm_runtime_iovars at attach; redundant
	 * sets here only add chip-state churn during the join window.
	 */
	v = htole32(BRCM_AUTH_OPEN);
	HOSTEAP_RC("SET_AUTH dcmd",
	    brcm_dcmd_set(sc, BRCM_C_SET_AUTH, &v, sizeof(v)));

	/*
	 * Linux brcmfmac writes wpa_auth TWICE around wsec/mfp:
	 *   1) 0xc0 = WPA2_UNSPEC | WPA2_PSK  (set_wpa_version)
	 *   2) 0x80 = WPA2_PSK                (set_key_mgmt, after mfp)
	 * The first pass seems to prep the fw's MFP state machine — see
	 * the on-air trace captured 2026-07-24 from an identical
	 * BCM43602 + fw v7.35.177.61 on Ubuntu brcmfmac connecting to
	 * an MFP-capable AP (docs/LINUX_MFP_IOVAR_TRACE.md).  Without
	 * the first pass, SET_SSID / bsscfg:join returns FAIL(1) when
	 * the mfp iovar is nonzero.
	 */
	if (sc->sc_sae_join) {
		/* WPA3-SAE (fw offload).  Fw runs the SAE exchange, derives
		 * the PMK, and hands us LINK-up with fw's own supplicant.
		 * SET_WSEC_PMK below carries the plaintext password with
		 * PASSPHRASE flag — same shape as WPA2, different AKM. */
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
	 * form of SET_WSEC_PMK.  Linux does this even in host-EAPOL
	 * mode: fw uses the PMK to derive MFP key material (IGTK /
	 * BIP-CMAC) so it can validate protected mgmt frames without
	 * bouncing to host.  On non-MFP joins this is a no-op inside fw
	 * — the 4-way still runs in userspace either way.
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
	 * BRCM_C_SET_SSID (our fallback) has historically left the chip
	 * never reaching AUTH on BCM43455 fw 7.45.x when no chanspec is
	 * known.
	 */
	chan = (ni->ni_chan != NULL && ni->ni_chan->ic_ieee != 0) ?
	    ni->ni_chan->ic_ieee : 0;
	/*
	 * Always supply chanspec -- NEVER send chanspec_num=0 to
	 * bsscfg:join.  Prefer fw-cached value from last ESCAN_RESULT
	 * (captures AP's real BW + sideband); fall back to computed BW20
	 * from ni->ni_chan as last resort.
	 */
	chanspec = brcm_lookup_bssid_chanspec(ni->ni_bssid);
	if (chanspec == 0 && chan != 0)
		chanspec = brcm_chan_to_chanspec_d11ac(chan);

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

	DPRINTF(sc, 0,
	    "join WPA2/host-EAPOL: ssid=\"%.*s\" "
	    "bssid=%02x:%02x:%02x:%02x:%02x:%02x chan=%u chanspec=0x%04x "
	    "join_params_size=%zu\n",
	    (int)slen, ni->ni_essid,
	    ni->ni_bssid[0], ni->ni_bssid[1], ni->ni_bssid[2],
	    ni->ni_bssid[3], ni->ni_bssid[4], ni->ni_bssid[5],
	    chan, chanspec, join_params_size);

	/*
	 * Join dispatch: use the "join" iovar (bsscfg:join) with the
	 * 70-byte ext_join_params.  Linux brcmfmac uses this exclusively
	 * during connect, and the on-air trace on identical BCM43602 +
	 * fw v7.35.177.61 confirms MFP-negotiated associations only
	 * succeed via this path (SET_SSID dcmd 26 returns FAIL(1) when
	 * mfp iovar is nonzero — see docs/LINUX_MFP_IOVAR_TRACE.md).
	 *
	 * Prior comment claimed bsscfg:join hit AUTH status=5 (NO_ACK)
	 * on BCM43455 fw 7.45.18.  That was without the preceding
	 * SET_WSEC_PMK + join_pref + double-wpa_auth sequence Linux uses;
	 * with the full sequence in place the bsscfg:join path is what
	 * fw expects.
	 */
	error = brcm_iovar_set(sc, "join", &ejp, join_params_size);
	DPRINTF(sc, 0,
	    "host-EAPOL: bsscfg:join iovar rc=%d (size=%zu)\n",
	    error, join_params_size);
	if (error != 0)
		sc->sc_join_busy = 0;
	return (error);
}

static void
brcm_assoc_task(void *arg, int pending __unused)
{
	struct brcm_softc *sc = arg;
	struct ieee80211vap *vap = sc->sc_assoc_vap;
	bool wpa_vap;
	int error;

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

static int
brcm_fmop_assoc(struct ieee80211com *ic, const struct ieee80211_fmac_assoc *fa)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);
	time_t now;

	if (vap == NULL || vap->iv_bss == NULL)
		return (EINVAL);

	/*
	 * Cache the target BSS so a later chip LINK-up event with the vap
	 * still at INIT can walk it up via sta_join_from_cache.  Symptom
	 * without this: chip fires JOIN/AUTH/LINK-up, brcm_link_task reads
	 * vap state=0, prints "framework declined and no cache fallback
	 * applies", wpa_supplicant sits at ASSOCIATING forever.  The
	 * join_target sysctl path populated these fields as a side effect;
	 * the wpa_supplicant mlme path did not.
	 */
	if (fa != NULL && fa->fa_ssidlen > 0 &&
	    fa->fa_ssidlen <= sizeof(sc->sc_join_ssid) - 1) {
		memcpy(sc->sc_join_bssid, fa->fa_bssid,
		    sizeof(sc->sc_join_bssid));
		memcpy(sc->sc_join_ssid, fa->fa_ssid, fa->fa_ssidlen);
		sc->sc_join_ssid[fa->fa_ssidlen] = '\0';
		sc->sc_join_ssid_len = fa->fa_ssidlen;
	}

	/*
	 * If the chip is already linked, treat this as a no-op.  Without
	 * this gate, wpa_supplicant's post-4-way re-authentication path
	 * (or net80211 walking a briefly-transitioning vap back through
	 * AUTH) queues brcm_join_wpa2_host_eapol, which sends
	 * BRCM_C_DOWN as its very first DCMD.  That DOWN tears down the
	 * association we just finished 4-waying — the chip then fires
	 * DISASSOC reason=8 (STA leaving) about 5 seconds later, and the
	 * whole join/4-way cycle restarts.  The fw is already in the
	 * associated + PTK+GTK-installed state we want; re-running the
	 * join dance from userspace intent alone is destructive.
	 */
	if (sc->sc_link_up) {
		DPRINTF(sc, 0,
		    "fmop_assoc: chip already linked; ignoring re-assoc "
		    "trigger to avoid DOWN/UP tear-down\n");
		return (0);
	}

	/*
	 * Retry rate-limit.  wpa_supplicant retries connect ~every second
	 * when it doesn't see a successful 4-way; each retry cycles the
	 * chip through DOWN/UP/join/AUTH/ASSOC/LINK_DOWN which starves
	 * the SDIO transport (chip stops acknowledging CMD53 after ~5-8
	 * back-to-back cycles, wedges Pi 4).  Drop redundant requests
	 * within a 3-second cooldown -- lets the chip settle + gives
	 * wpa_supplicant time to run 4-way if a join lands.
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
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_assoc_task);
	return (0);
}

/*
 * Post-ASSOC handshake -- issue the iovar GETs immediately after
 * ASSOC success.  On BCM43455 fw 7.45.18 the chip tears down LINK
 * reason=2 if host doesn't interact within ~50-100ms of
 * assoc-complete.  These GETs are cheap keepalives that also
 * populate assoc telemetry we can expose to userspace later.
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
	 * BRCMF_C_GET_BSS_INFO: prefix buffer with __le32 buffer size
	 * before the dcmd_get.  Without that the chip returns
	 * BCME_NOTFOUND (-45).
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
	 * wme_ac_sta -- ALWAYS read this immediately after ASSOC.
	 * Returns 4 x struct edcf_acparam (16 bytes, one per BE/BK/VI/VO
	 * AC) that AP included in its assoc-resp WMM Parameter Element.
	 * On BCM43455 fw 7.45.18 the chip REQUIRES this GET to commit
	 * the WMM state internally -- without it, chip treats subsequent
	 * EAPOL/DATA frames as invalid and self-tears down LINK reason=2
	 * within milliseconds of ASSOC.
	 *
	 * We don't classify per-AC yet; getting the values is enough to
	 * keep the chip's link machine happy.
	 */
	len = sizeof(buf);
	rc = brcm_iovar_get(sc, "wme_ac_sta", buf, &len);
	DPRINTF(sc, 0, "post-assoc: wme_ac_sta rc=%d len=%zu\n", rc, len);
}

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
	 * Send a 12-byte brcm_scb_val_le payload to BRCM_C_DISASSOC
	 * (cmd 52):  { __le32 reason; u8 bssid[6]; }, padded to 12
	 * bytes (2-byte alignment after bssid).  A previous 4-byte
	 * zero payload worked but isn't what fw expects; chip ignores
	 * extra bytes but may log a length warning.
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
	 * This is the storm reproducer: chip fires LINK-down every
	 * ~200 ms during AP retry, each cycle bursts a WLC_DISASSOC
	 * + PMU wake, and after 5-8 cycles the SDIO transport wedges
	 * the whole Pi.
	 */
	if (!sc->sc_link_up)
		return (0);

	/*
	 * Post-4-way blackout.  After a successful PTK/GTK install
	 * wpa_supplicant on FreeBSD (driver_bsd.c) walks the vap through
	 * a few intermediate states before RUN, and one of those
	 * transitions arrives here as fmop_disassoc.  Firing WLC_DISASSOC
	 * then wipes the fresh association.  Skip the DCMD for 5 s after
	 * the last successful key install; the connection is stable by
	 * then and any real disassoc request will retry after cooldown.
	 */
	now = time_uptime;
	if (sc->sc_last_key_ts != 0 && now - sc->sc_last_key_ts < 5) {
		DPRINTF(sc, 0, "fmop_disassoc: post-key blackout (%llds)\n",
		    (long long)(now - sc->sc_last_key_ts));
		return (0);
	}

	/*
	 * Cooldown gate mirroring fmop_assoc (2855990).  Even when
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
	 * in the 12-byte scb_val payload.  Chip walks
	 * itself to IDLE and emits its own DISASSOC event which our
	 * event handler forwards to ieee80211_fmac_link_down — so the
	 * host-side state walk progresses regardless of dcmd timing.
	 */
	sc->sc_disassoc_reason = reason;
	(void)taskqueue_enqueue(taskqueue_thread, &sc->sc_disassoc_task);
	return (0);
}

static int
brcm_fmop_set_key(struct ieee80211com *ic, const struct ieee80211_key *k)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap;
	uint32_t algo, flags = 0;
	const uint8_t *ea;
	static const uint8_t bcast[6] = {
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	algo = brcm_cipher_to_algo(k->wk_cipher->ic_cipher);
	if (algo == BRCM_CRYPTO_ALGO_OFF) {
		DPRINTF(sc, 0, "fmop_set_key: unsupported cipher %u\n",
		    k->wk_cipher->ic_cipher);
		return (0);
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
		 * PTK (pairwise): flags=0, ea=AP_MAC.  Broadcom fw's
		 * PRIMARY_KEY flag marks the group tx key, not the
		 * pairwise; setting it on a pairwise key install makes
		 * the chip drop broadcast RX after 4-way completes.
		 */
		ea = (vap != NULL && vap->iv_bss != NULL) ?
		    vap->iv_bss->ni_bssid : bcast;
		return (brcm_set_key(sc, 0, algo, flags,
		    k->wk_key, k->wk_keylen, ea, 0));
	}
	/*
	 * GTK (group): flags=PRIMARY_KEY, ea=00:00:00:00:00:00.  Marks
	 * this as the primary group tx key.  fw rejects GTK install with
	 * a non-zero ea (broadcast returns BCME_ERROR=5 on v7.35.177.61),
	 * and needs the PRIMARY flag or it will not decrypt group frames.
	 *
	 * IGTK (BIP-CMAC-128 at key idx 4 or 5) uses the same install
	 * path but WITHOUT the PRIMARY_KEY flag — Linux brcmfmac only
	 * sets BRCMF_PRIMARY_KEY when the key install is NOT an "ext_key"
	 * (i.e. keys with a peer MAC set are not primary).  IGTKs are
	 * group RX-only management protection keys; the fw distinguishes
	 * them from data-plane GTKs by the key index (>= 4 == IGTK).
	 * Also skip SCB_AUTHORIZE / wpa_ok — those are only meaningful
	 * after the data-plane 4-way completes, which happened when GTK
	 * (idx 1..3) was installed.
	 */
	{
		static const uint8_t zero_ea[6] = { 0, 0, 0, 0, 0, 0 };
		bool is_igtk = (k->wk_keyix >= 4);
		uint32_t kflags = flags;
		int rc;

		if (!is_igtk)
			kflags |= BRCM_WSEC_PRIMARY_KEY;
		rc = brcm_set_key(sc, k->wk_keyix, algo, kflags,
		    k->wk_key, k->wk_keylen, zero_ea,
		    (uint64_t)k->wk_keyrsc[IEEE80211_NONQOS_TID]);
		DPRINTF(sc, 0,
		    "fmop_set_key: %s idx=%u algo=%u rc=%d\n",
		    is_igtk ? "IGTK" : "GTK", k->wk_keyix, algo, rc);
		/*
		 * Post-GTK (not IGTK): fire SCB_AUTHORIZE for the AP.  This
		 * tells the chip's data-plane encryption layer that both
		 * PTK and GTK are ready and the STA is authorized to send
		 * data.  Doing it after PTK-only causes the chip's
		 * supplicant-watchdog to still count us as unauthenticated
		 * and it disassocs with reason=8 (STA leaving) about 5
		 * seconds later.
		 */
		if (!is_igtk && rc == 0 && vap != NULL &&
		    vap->iv_bss != NULL) {
			uint32_t one = htole32(1);
			(void)brcm_scb_authorize(sc,
			    vap->iv_bss->ni_bssid);
			/*
			 * Some Broadcom fw variants gate their internal
			 * supplicant-watchdog on a "wpa_ok" iovar.  If the
			 * iovar isn't recognised the iovar_set fails
			 * harmlessly.  If it IS recognised, chip stops its
			 * 5-second post-M3 disassoc timer and lets the host
			 * keep the connection.
			 */
			(void)brcm_iovar_set(sc, "wpa_ok", &one, sizeof(one));
		}
		return (rc);
	}
}

static int
brcm_fmop_del_key(struct ieee80211com *ic __unused,
    const struct ieee80211_key *k __unused)
{
	/*
	 * NO-OP.  wpa_supplicant on FreeBSD sends DELKEY after installing
	 * the PTK as part of its stale-key sweep.  Forwarding that to the
	 * chip as a wsec_key(algo=OFF, peer=bcast) wipes the freshly
	 * installed PTK because Broadcom fw treats key idx=0 as the
	 * primary key regardless of the peer address, and the chip then
	 * disassocs.  Chip manages key lifecycle on ASSOC/DISASSOC so
	 * we don't need to help.
	 */
	return (0);
}

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
	TASK_INIT(&sc->sc_scan_task, 0, brcm_scan_task, sc);
	TASK_INIT(&sc->sc_link_task, 0, brcm_link_task, sc);
	TASK_INIT(&sc->sc_assoc_task, 0, brcm_assoc_task, sc);
	TASK_INIT(&sc->sc_disassoc_task, 0, brcm_disassoc_task, sc);
	TASK_INIT(&sc->sc_post_assoc_task, 0, brcm_post_assoc_task, sc);
	TASK_INIT(&sc->sc_parent_task, 0, brcm_parent_task, sc);

	ic = &sc->sc_ic;
	ic->ic_softc = sc;
	ic->ic_name = device_get_nameunit(sc->sc_dev);
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_caps =
	    IEEE80211_C_STA |
	    IEEE80211_C_WPA;

	/*
	 * Phase 10: advertise the WPA2 ciphers we can install on the chip
	 * via WLC_SET_KEY.  This lets userspace wpa_supplicant negotiate
	 * RSN with WPA2-PSK + CCMP and then call iv_key_set with these
	 * key types.  TKIP is added too because some legacy APs require
	 * it for the GTK even when CCMP is the pairwise cipher.
	 */
	ic->ic_cryptocaps =
	    IEEE80211_CRYPTO_AES_CCM |
	    IEEE80211_CRYPTO_TKIP |
	    IEEE80211_CRYPTO_WEP |
	    /*
	     * BIP-CMAC-128 for MFP (802.11w).  Without this, wpa_supplicant
	     * reports `available mgmt_group_cipher 0x0` and refuses to
	     * negotiate MFP, so MFPC=1 APs (any modern hostapd default)
	     * embed a 30-byte RSN IE in beacons and a 24-byte one in M3.
	     * hostap's wpa_compare_rsn_ie does byte-exact match for non-FT,
	     * so it deauths reason=17 (IE_IN_4WAY_DIFFERS).  Advertising
	     * BIP lets wpa_supplicant negotiate MFP; AP then mirrors the
	     * MFP fields in M3 and the compare succeeds.  IGTK install for
	     * MFP goes through brcm_set_key with BRCM_CRYPTO_ALGO_AES_CCM
	     * and key_index 4 or 5 (fw distinguishes BIP by index).
	     */
	    IEEE80211_CRYPTO_BIP_CMAC_128;

	brcm_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans,
	    ic->ic_channels);

	IEEE80211_ADDR_COPY(ic->ic_macaddr, sc->sc_macaddr);

	/*
	 * Register the stub BIP-CMAC-128 cipher (see comment above the
	 * cipher definition).  Idempotent per-module — safe to call once
	 * per attach as long as detach unregisters the same struct.
	 */
	ieee80211_crypto_register(&brcm_bip_cipher);

	ieee80211_ifattach(ic);
	sc->sc_ic_attached = true;

	/*
	 * Attach the FullMAC framework as a passive observer for now.
	 * Phase 1 of the migration: only the up-call helpers
	 * (link_up, link_down, eapol_rx) are wired through.  The vap-
	 * level shims (fmac_newstate, fmac_key_set) are installed by
	 * ieee80211_fmac_vap_attach() from brcm_vap_create; with the
	 * brcm_fmop_assoc stub returning ENXIO they fall through to
	 * the saved bv_newstate so existing behavior is preserved.
	 */
	(void)ieee80211_fmac_attach(ic, &brcm_fmops,
	    IEEE80211_FMAC_CAP_FW_SCAN | IEEE80211_FMAC_CAP_ONCHIP_SUP);

	ic->ic_vap_create = brcm_vap_create;
	ic->ic_vap_delete = brcm_vap_delete;
	ic->ic_parent = brcm_parent;
	ic->ic_transmit = brcm_transmit;
	ic->ic_raw_xmit = brcm_raw_xmit;
	ic->ic_set_channel = brcm_set_channel;
	/* ic_scan_start / ic_scan_end are owned by the FullMAC
	 * framework — see ieee80211_fmac_attach above. */
	ic->ic_getradiocaps = brcm_getradiocaps;
	ic->ic_update_promisc = brcm_update_promisc;
	ic->ic_update_mcast = brcm_update_mcast;

	return (0);
}

/*
 * WPA2-PSK passphrase sysctl.  Stores the ASCII passphrase (8..63
 * bytes per WPA2 spec) in the softc; brcm_newstate consumes
 * sc_wpa_set on the next SCAN->AUTH transition to pick the WPA2
 * dispatch path.  Read-back returns the "<set>" sentinel so the
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
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (strcmp(buf, "<set>") == 0)
		return (0);
	len = strnlen(buf, sizeof(buf));
	if (len == 0) {
		sc->sc_wpa_set = false;
		memset(sc->sc_wpa_pmk, 0, sizeof(sc->sc_wpa_pmk));
		DPRINTF(sc, 0, "WPA2 PMK cleared\n");
		return (0);
	}
	if (len < 8 || len > 63)
		return (EINVAL);
	memset(sc->sc_wpa_pmk, 0, sizeof(sc->sc_wpa_pmk));
	memcpy(sc->sc_wpa_pmk, buf, len);
	sc->sc_wpa_set = true;
	DPRINTF(sc, 0, "WPA2 PMK stored (%zu bytes)\n", len);
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
	l->se = *se;
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
 * colon-separated hex bytes.  Useful for end-to-end radio-side
 * validation before the userland<->net80211 integration is complete.
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

	/*
	 * Optional trailing ":chan_decimal" — a channel number the caller
	 * knows the target BSS is on, so the fw-supplicant join path can
	 * pass a real chanspec to SET_SSID even when the driver's local
	 * chanspec cache is empty (no prior ESCAN_RESULT).  Without a
	 * chanspec, BCM43602 v7.35 SET_SSID rc=0 but the chip parks at
	 * ch 1 with ssid="".  Format: "bssid:ssid" or "bssid:ssid:chan".
	 */
	int chan_hint = 0;
	{
		const char *colon = ssid + ssid_len;
		while (colon > ssid && *--colon != ':')
			continue;
		if (colon > ssid && *colon == ':') {
			int p, k;
			if (sscanf(colon + 1, "%d%n", &p, &k) == 1 &&
			    p > 0 && p <= 200 && colon[1 + k] == '\0') {
				chan_hint = p;
				ssid_len = (size_t)(colon - ssid);
			}
		}
	}

	memcpy(sc->sc_join_bssid, bssid, 6);
	memcpy(sc->sc_join_ssid, ssid, ssid_len);
	sc->sc_join_ssid[ssid_len] = '\0';
	sc->sc_join_ssid_len = ssid_len;
	ssid = sc->sc_join_ssid;

	/*
	 * Preferred path: route the join through net80211's state
	 * machine.  sta_join_from_cache calls ieee80211_sta_join, which
	 * walks the vap to AUTH; brcm_newstate(AUTH) then dispatches the
	 * firmware join through BCDC.  When firmware emits LINK up,
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
		uint16_t chanspec = 0;
		if (chan_hint > 0)
			chanspec = brcm_chan_to_chanspec_d11ac(
			    (uint8_t)chan_hint);
		error = brcm_join_wpa2_raw(sc, bssid, ssid, ssid_len,
		    chanspec);
		DPRINTF(sc, 0,
		    "join_target raw WPA2 dispatch chan=%d chanspec=0x%04x rc=%d\n",
		    chan_hint, chanspec, error);
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
		 * No DOWN/UP wrap -- BCM43455 fw 7.45.x's join state
		 * machine doesn't fire AUTH after a DOWN/UP bounce.  Just
		 * reset RSN config in place.
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
		chanspec = brcm_lookup_bssid_chanspec(bssid);
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
 * The BCM43455 chip's TX is restricted to a small default set without
 * this regulatory blob; symptom is the chip emits PROBERESP_MSG from
 * the AP but never transmits an AUTH frame because its regulatory data
 * forbids the operation on the target channel.
 *
 * Walks the blob in MAX_CHUNK_LEN-sized chunks; each chunk wraps the
 * payload in struct brcm_dload_data and sends via iovar_set("clmload").
 * First chunk has DL_BEGIN, last has DL_END (both set if the whole blob
 * fits in one chunk).
 *
 * fwname comes from the per-chip table; the blob registers as
 * "<fwname>.clm_blob".
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

void
brcm_runtime_iovars(struct brcm_softc *sc)
{
	uint8_t mask[BRCM_EVENT_MASK_LEN];
	uint8_t country[4] = { 'U', 'S', 0, 0 };
	uint32_t v;
	int error;

	/*
	 * Upload CLM blob FIRST -- chip needs regulatory before any TX.
	 * For BCM43455/CYW43455 the registered firmware blob name is
	 * "brcmfmac43455-sdio".  Non-fatal on miss: chips that have
	 * working defaults will scan + AUTH without it.
	 *
	 * TODO: derive blob basename from chip-info table once brcm.c's
	 * brcm_chip_table has the 4345 entry (currently only USB-side
	 * chips listed there; SDIO uses if_brcm_sdio.c's separate table).
	 */
	(void)brcm_upload_clm_blob(sc, "brcmfmac43455-sdio");

	v = htole32(1);
	error = brcm_dcmd_set(sc, BRCM_C_UP, &v, sizeof(v));
	if (error == 0)
		sc->sc_wlc_up = true;
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

	v = htole32(0);
	error = brcm_iovar_set(sc, "sup_wpa", &v, sizeof(v));
	DPRINTF(sc, 0, "sup_wpa=0 iovar rc=%d%s\n", error,
	    error == 0 ? " (host-side EAPOL mode)" : "");

	/*
	 * Hardening for the 2011 BCM43236 blob.  Only the iovars the
	 * firmware actually accepts go here; tdls/wps iovars are absent
	 * from this firmware revision (Cypress added them later) and
	 * p2p_disc rejected our uint32 write — its argument shape is
	 * undocumented for this blob, so leave it to manual probing via
	 * dev.brcm.<n>.iovar_set.  See SECURITY.md for the CVE backlog
	 * this firmware predates.
	 *
	 *   mpc=0        - radio stays on; closes the RX-window-gone
	 *                  class of attacks at the cost of more power
	 *   roam_off=1   - on-chip roaming/beacon parser disabled;
	 *                  pre-assoc beacon-parser surface is closed
	 */
	v = htole32(0);
	error = brcm_iovar_set(sc, "mpc", &v, sizeof(v));
	DPRINTF(sc, 0, "harden mpc=0 rc=%d\n", error);
	/*
	 * mfp=0 (MFP_NONE).  Chip-default on BCM43455 fw 7.45.98 is
	 * mfp=1 (MFP_CAPABLE), which makes the chip advertise PMF in
	 * its assoc-req IEs and refuse to associate to a non-PMF AP.
	 * For a vanilla WPA2-PSK/CCMP target (TESTAP_WPA2 hostapd
	 * default, no ieee80211w) the chip emits SET_SSID rc=0 then
	 * silently never fires AUTH because PMF can't be negotiated.
	 * Set MFP_NONE at attach so any join path -- open or WPA2 --
	 * lands cleanly.  Brcm_join_wpa2_host_eapol sets it again to
	 * 0 redundantly; that's fine.
	 */
	v = htole32(0);
	error = brcm_iovar_set(sc, "mfp", &v, sizeof(v));
	DPRINTF(sc, 0, "harden mfp=0 rc=%d\n", error);

	/*
	 * Power management.  Chip default may be PM_MAX (1) = aggressive
	 * doze-between-beacons.  In PM_MAX the chip's PS state machine
	 * can hold TX queues during the doze window, killing the on-air
	 * AUTH-frame TX window during a join.  Pick PM_OFF (0) =
	 * always-awake at attach: best for debug + initial join.
	 * PM_FAST (2) can be enabled later via iovar_set.
	 *
	 *   PM_OFF  = 0  always awake
	 *   PM_MAX  = 1  max power save (chip default suspect)
	 *   PM_FAST = 2  fast power save
	 */
	v = htole32(0);	/* PM_OFF */
	error = brcm_dcmd_set(sc, BRCM_C_SET_PM, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_SET_PM=PM_OFF rc=%d\n", error);

	/*
	 * Beacon timeout = 4 seconds before chip declares the AP gone
	 * if no beacon RXed.  Default may be 2 which is aggressive --
	 * if AP misses a couple of beacons during 4-way the chip
	 * self-disassocs.
	 */
	v = htole32(4);
	error = brcm_iovar_set(sc, "bcn_timeout", &v, sizeof(v));
	DPRINTF(sc, 0, "bcn_timeout=4 rc=%d\n", error);

	/*
	 * Frameburst on for higher A-MPDU throughput.  Harmless if
	 * chip already enables it.
	 */
	v = htole32(1);
	error = brcm_dcmd_set(sc, BRCM_C_SET_FAKEFRAG, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_SET_FAKEFRAG=1 rc=%d\n", error);

	/*
	 * Scan dwell settings.  On BCM43602 fw 7.35.177.61 the chip
	 * needs SCAN_CHANNEL_TIME + SCAN_UNASSOC_TIME programmed or
	 * the escan iovar submit returns nothing and net80211 wedges
	 * waiting for ESCAN_RESULT.
	 *
	 * BCM43455 fw 7.45.x can regress AUTH firing during a
	 * join-scan when these are set (chip can't fit an AUTH window
	 * between dwells).  If that recurs, gate on transport / chip
	 * family before applying.
	 */
	v = htole32(40);
	error = brcm_dcmd_set(sc, BRCM_C_SET_SCAN_CHANNEL_TIME, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_SET_SCAN_CHANNEL_TIME=40 rc=%d\n", error);
	v = htole32(40);
	error = brcm_dcmd_set(sc, BRCM_C_SET_SCAN_UNASSOC_TIME, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_SET_SCAN_UNASSOC_TIME=40 rc=%d\n", error);
	v = htole32(130);
	error = brcm_dcmd_set(sc, BRCM_C_SET_SCAN_PASSIVE_TIME, &v, sizeof(v));
	DPRINTF(sc, 0, "BRCM_C_SET_SCAN_PASSIVE_TIME=130 rc=%d\n", error);

	/*
	 * roam_off=1 disables the chip's on-chip roaming AND its
	 * pre-assoc beacon parser -- which is exactly what consumes
	 * beacons + probe responses during a join.  On BCM43455 fw
	 * 7.45.98 with roam_off=1 set at attach, SET_SSID returns
	 * rc=0 but the chip never emits AUTH/ASSOC because it can't
	 * parse the AP's beacons to know when to fire.  Skip it; the
	 * "hardening" trade isn't worth losing join.
	 */

	/*
	 * Explicit ARP + ND offload disable.  brcmfmac's
	 * brcmf_configure_arp_nd_offload sets these to a non-zero mode
	 * when the host is not promiscuous; we want them off so
	 * DHCPOFFER + unsolicited ARP replies reach wpa_supplicant /
	 * net80211 verbatim in host-supplicant mode.  Older fw returns
	 * BCME_UNSUPPORTED — harmless.  Reference: brcmfmac core.c:96-131.
	 */
	v = htole32(0);
	error = brcm_iovar_set(sc, "arp_ol", &v, sizeof(v));
	DPRINTF(sc, 0, "arp_ol=0 rc=%d\n", error);
	v = htole32(0);
	error = brcm_iovar_set(sc, "arpoe", &v, sizeof(v));
	DPRINTF(sc, 0, "arpoe=0 rc=%d\n", error);
	v = htole32(0);
	error = brcm_iovar_set(sc, "ndoe", &v, sizeof(v));
	DPRINTF(sc, 0, "ndoe=0 rc=%d\n", error);

	device_printf(sc->sc_dev,
	    "WARNING: firmware blob is from 2011 and predates Broadpwn/Kr00k/"
	    "FragAttacks; see brcm/SECURITY.md.  Use for experimental/CTF "
	    "only.\n");
}

/*
 * SAE capability probe.  Attempts to set wpa_auth = WPA3_AUTH_SAE_PSK
 * (0x40000) and reports rc back to userspace.  0 means fw accepts the
 * WPA3-SAE AKM (a necessary but not sufficient signal — chip still
 * needs SAE hostapd on the other side to complete an exchange).
 * BCME_UNSUPPORTED (-23) means this fw doesn't know SAE at all.
 *
 * Idempotent: probing does NOT persist wpa_auth — we snapshot the
 * prior value, try SAE, then restore.  Safe to run at any time.
 */
static int
brcm_sae_probe_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcm_softc *sc = arg1;
	uint32_t old, sae, restore;
	int probe_rc, restore_rc, error;
	char buf[64];

	if (req->newptr == NULL) {
		snprintf(buf, sizeof(buf), "run 'sysctl -w %s=1' to probe\n",
		    "dev.brcm_pci.0.sae_probe");
		return (sysctl_handle_string(oidp, buf, sizeof(buf), req));
	}

	old = 0;
	{
		size_t l = sizeof(old);
		(void)brcm_iovar_get(sc, "wpa_auth", &old, &l);
	}
	sae = htole32(BRCM_WPA_AUTH_WPA3_SAE_PSK);
	probe_rc = brcm_iovar_set(sc, "wpa_auth", &sae, sizeof(sae));
	restore = old;
	restore_rc = brcm_iovar_set(sc, "wpa_auth", &restore, sizeof(restore));
	device_printf(sc->sc_dev,
	    "sae_probe: wpa_auth=0x%x probe_rc=%d, restored=0x%x rc=%d\n",
	    BRCM_WPA_AUTH_WPA3_SAE_PSK, probe_rc, le32toh(old), restore_rc);

	snprintf(buf, sizeof(buf),
	    "sae_probe rc=%d (0=fw accepts SAE, -23=BCME_UNSUPPORTED)\n",
	    probe_rc);
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	return (error);
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
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "sae_probe",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_sae_probe_sysctl, "A",
	    "Test whether firmware accepts WPA3-SAE wpa_auth (write 1)");
	SYSCTL_ADD_BOOL(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "sae_join",
	    CTLFLAG_RW, &sc->sc_sae_join, 0,
	    "Switch the next join to WPA3-SAE (fw offload).  Set the "
	    "SAE password via wpa_pmk (or wpa_pmk_hex for a raw key), "
	    "then set sae_join=1 before running wpa_supplicant.");
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
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "iovar_set",
	    CTLTYPE_STRING | CTLFLAG_WR | CTLFLAG_MPSAFE, sc, 0,
	    brcm_iovar_set_sysctl, "A",
	    "Write 'name:hexpayload' to push a raw iovar");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "sup_dump",
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcm_sup_dump_sysctl, "A",
	    "Write 'OFFSET LEN' (patched fw); read returns hex bytes "
	    "from *(wlc+0x12)+OFFSET");
}

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
		ieee80211_crypto_unregister(&brcm_bip_cipher);
		sc->sc_ic_attached = false;
	}
}
