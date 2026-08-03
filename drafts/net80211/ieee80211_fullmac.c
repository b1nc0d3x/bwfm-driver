/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * net80211 FullMAC adaptation layer — implementation.
 *
 * The framework keeps one struct fmac_state hung off ic_softc-ish
 * private storage (actually attached by ieee80211_fmac_attach via
 * a new ic->ic_fmac slot proposed at the bottom of this file).
 * Drivers don't touch it; they only call the public helpers in
 * ieee80211_fullmac.h.
 *
 * Status: DRAFT.  Compiles standalone against a recent FreeBSD
 * net80211 once ic->ic_fmac is added to ieee80211_var.h (see
 * drafts/net80211/README.md for the one-line struct field
 * extension).
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_media.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_input.h>
#include <net80211/ieee80211_proto.h>
#include <net80211/ieee80211_regdomain.h>

#include "ieee80211_fullmac.h"

static MALLOC_DEFINE(M_80211_FMAC, "80211_fmac",
    "net80211 FullMAC framework");

/*
 * Per-com framework state.  Allocated in attach, freed in detach.
 * The driver's ic doesn't see this directly; the framework reaches
 * it via ic->ic_fmac.
 */
struct fmac_state {
	const struct ieee80211_fullmac_ops *fs_ops;
	uint32_t			    fs_caps;

	/*
	 * Saved net80211 slots so detach can restore them.  These are
	 * the entry points the framework rewires to its own shims.
	 */
	int	(*fs_save_newstate)(struct ieee80211vap *,
		    enum ieee80211_state, int);
	void	(*fs_save_scan_start)(struct ieee80211com *);
	void	(*fs_save_scan_end)(struct ieee80211com *);
	int	(*fs_save_key_set)(struct ieee80211vap *,
		    const struct ieee80211_key *);
	int	(*fs_save_key_delete)(struct ieee80211vap *,
		    const struct ieee80211_key *);
};

static int	fmac_newstate(struct ieee80211vap *,
		    enum ieee80211_state, int);
static void	fmac_scan_start(struct ieee80211com *);
static void	fmac_scan_end(struct ieee80211com *);
static int	fmac_key_set(struct ieee80211vap *,
		    const struct ieee80211_key *);
static int	fmac_key_delete(struct ieee80211vap *,
		    const struct ieee80211_key *);

/* ------------------------------------------------------------------
 * Attach / detach
 * ------------------------------------------------------------------ */

int
ieee80211_fmac_attach(struct ieee80211com *ic,
    const struct ieee80211_fullmac_ops *ops, uint32_t caps)
{
	struct fmac_state *fs;

	if (ic == NULL || ops == NULL || ops->fmop_name == NULL)
		return (EINVAL);
	if (ops->fmop_scan_start == NULL || ops->fmop_assoc == NULL ||
	    ops->fmop_disassoc == NULL || ops->fmop_set_key == NULL ||
	    ops->fmop_set_country == NULL)
		return (EINVAL);

	fs = malloc(sizeof(*fs), M_80211_FMAC, M_WAITOK | M_ZERO);
	fs->fs_ops  = ops;
	fs->fs_caps = caps;

	/*
	 * Save and rewire ic-level slots.  vap-level slots
	 * (iv_newstate, iv_key_set, iv_key_delete) get rewired in
	 * fmac_vap_create_hook, called from the driver's vap_create.
	 * That keeps the framework from needing to walk a vap list
	 * that may not exist yet at attach time.
	 */
	fs->fs_save_scan_start = ic->ic_scan_start;
	fs->fs_save_scan_end   = ic->ic_scan_end;
	ic->ic_scan_start = fmac_scan_start;
	ic->ic_scan_end   = fmac_scan_end;

	ic->ic_fmac = fs;
	return (0);
}

void
ieee80211_fmac_detach(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	if (ic == NULL || ic->ic_fmac == NULL)
		return;
	fs = ic->ic_fmac;

	ic->ic_scan_start = fs->fs_save_scan_start;
	ic->ic_scan_end   = fs->fs_save_scan_end;

	free(fs, M_80211_FMAC);
	ic->ic_fmac = NULL;
}

/*
 * Helper drivers call from their vap_create after the vap is
 * allocated but before they return it.  Wires the per-vap shims.
 * Exposed as a static inline in the header in a future revision;
 * for the draft, the driver calls it explicitly so the order is
 * obvious.
 */
void
ieee80211_fmac_vap_attach(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs;

	if (ic->ic_fmac == NULL)
		return;
	fs = ic->ic_fmac;

	fs->fs_save_newstate   = vap->iv_newstate;
	fs->fs_save_key_set    = vap->iv_key_set;
	fs->fs_save_key_delete = vap->iv_key_delete;

	vap->iv_newstate   = fmac_newstate;
	vap->iv_key_set    = fmac_key_set;
	vap->iv_key_delete = fmac_key_delete;
}

/* ------------------------------------------------------------------
 * net80211 -> driver shims
 * ------------------------------------------------------------------ */

static void
fmac_scan_start(struct ieee80211com *ic)
{
	struct fmac_state *fs = ic->ic_fmac;
	struct ieee80211_scan_state *ss = ic->ic_scan;
	const uint8_t *ssid = NULL;
	size_t ssidlen = 0;
	bool active;

	if (ss != NULL && ss->ss_nssid > 0) {
		ssid    = ss->ss_ssid[0].ssid;
		ssidlen = ss->ss_ssid[0].len;
	}
	active = (ss == NULL) ? true :
	    (ss->ss_flags & IEEE80211_SCAN_ACTIVE) != 0;

	(void)fs->fs_ops->fmop_scan_start(ic, ssid, ssidlen, active);
}

static void
fmac_scan_end(struct ieee80211com *ic)
{
	struct fmac_state *fs = ic->ic_fmac;

	if (fs->fs_ops->fmop_scan_cancel != NULL)
		fs->fs_ops->fmop_scan_cancel(ic);
	if (fs->fs_save_scan_end != NULL)
		fs->fs_save_scan_end(ic);
}

static int
fmac_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = ic->ic_fmac;
	struct ieee80211_fmac_assoc fa;
	int rc;

	/*
	 * The interesting transitions are RUN-bound (host says
	 * "associate") and INIT-bound (host says "stop").  Everything
	 * in between is a side-effect of the firmware's own state
	 * machine that we already know about via fmac_link_up.
	 */
	switch (nstate) {
	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC: {
		struct ieee80211_node *ni = vap->iv_bss;

		memset(&fa, 0, sizeof(fa));
		if (ni != NULL) {
			memcpy(fa.fa_bssid, ni->ni_bssid,
			    IEEE80211_ADDR_LEN);
			fa.fa_ssidlen = MIN(ni->ni_esslen,
			    sizeof(fa.fa_ssid));
			memcpy(fa.fa_ssid, ni->ni_essid, fa.fa_ssidlen);
			fa.fa_chan_freq = (ni->ni_chan != NULL) ?
			    ni->ni_chan->ic_freq : 0;
		}
		/*
		 * wpa_auth / wsec / RSN IE are driver-private; the
		 * framework can't read them out of net80211 without
		 * layering violation.  Leave them as zero and let the
		 * driver layer fill them in from its own staging.
		 */
		rc = fs->fs_ops->fmop_assoc(ic, &fa);
		if (rc != 0)
			return (rc);
		/*
		 * Suppress net80211's own AUTH/ASSOC walk; firmware
		 * will tell us when it's RUN via ieee80211_fmac_link_up.
		 */
		return (0);
	}
	case IEEE80211_S_INIT:
		(void)fs->fs_ops->fmop_disassoc(ic,
		    IEEE80211_REASON_AUTH_LEAVE);
		break;
	default:
		break;
	}
	return (fs->fs_save_newstate(vap, nstate, arg));
}

static int
fmac_key_set(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = ic->ic_fmac;

	return (fs->fs_ops->fmop_set_key(ic, key));
}

static int
fmac_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = ic->ic_fmac;

	if (fs->fs_ops->fmop_del_key != NULL)
		return (fs->fs_ops->fmop_del_key(ic, key));
	if (fs->fs_save_key_delete != NULL)
		return (fs->fs_save_key_delete(vap, key));
	return (0);
}

/* ------------------------------------------------------------------
 * Driver -> net80211 up-calls
 * ------------------------------------------------------------------ */

/*
 * Synthesise a probe-response-shaped frame from the firmware's
 * scan-result event and feed it through ieee80211_add_scan().
 * net80211's scan cache is the source of truth for ssid-match
 * later, so this path matters even on chips with on-chip scan
 * filtering.
 *
 * The synthesised frame is built on the stack — bounded by
 * IEEE80211_NWID_LEN + bb->fb_ielen — and discarded after the call.
 */
void
ieee80211_fmac_scan_result(struct ieee80211com *ic,
    const struct ieee80211_fmac_bss *bb)
{
	struct ieee80211_scanparams sp;
	struct ieee80211_channel *chan;
	uint8_t *frm, *buf;
	size_t need;

	chan = ieee80211_find_channel(ic, bb->fb_chan_freq, 0);
	if (chan == NULL)
		return;

	need = 12 /* fixed prresp fields */ + 2 + bb->fb_ssidlen +
	    bb->fb_ielen;
	buf = malloc(need, M_TEMP, M_NOWAIT | M_ZERO);
	if (buf == NULL)
		return;
	frm = buf;

	/* timestamp (8) + beacon interval (2) + capinfo (2) */
	memset(frm, 0, 8); frm += 8;
	*frm++ = (uint8_t)(bb->fb_bintval >> 0);
	*frm++ = (uint8_t)(bb->fb_bintval >> 8);
	*frm++ = (uint8_t)(bb->fb_capinfo >> 0);
	*frm++ = (uint8_t)(bb->fb_capinfo >> 8);

	/* SSID IE */
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = bb->fb_ssidlen;
	memcpy(frm, bb->fb_ssid, bb->fb_ssidlen);
	frm += bb->fb_ssidlen;

	/* concat firmware-supplied IEs */
	if (bb->fb_ies != NULL && bb->fb_ielen != 0) {
		memcpy(frm, bb->fb_ies, bb->fb_ielen);
		frm += bb->fb_ielen;
	}

	memset(&sp, 0, sizeof(sp));
	sp.tstamp[0] = 0;
	sp.bintval   = bb->fb_bintval;
	sp.capinfo   = bb->fb_capinfo;
	sp.ssid      = buf + 12;
	sp.rates     = NULL;
	sp.xrates    = NULL;
	sp.country   = NULL;

	(void)ieee80211_add_scan(ic->ic_scan->ss_vap, chan, &sp,
	    NULL /* wh */, 0, bb->fb_rssi, bb->fb_noise);

	free(buf, M_TEMP);
}

void
ieee80211_fmac_scan_done(struct ieee80211com *ic)
{
	if (ic->ic_scan != NULL)
		ieee80211_scan_done(ic->ic_scan->ss_vap);
}

/*
 * Firmware-reported link-up.  Walk the bss vap from whatever state
 * net80211 thinks it's in to RUN.  Skip intermediate transitions —
 * the firmware did them.
 */
void
ieee80211_fmac_link_up(struct ieee80211com *ic,
    const uint8_t bssid[IEEE80211_ADDR_LEN])
{
	struct ieee80211vap *vap;
	struct fmac_state *fs = ic->ic_fmac;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_STA)
			continue;
		if (vap->iv_bss != NULL && bssid != NULL)
			memcpy(vap->iv_bss->ni_bssid, bssid,
			    IEEE80211_ADDR_LEN);
		/* Save -> stub -> RUN. */
		(void)fs->fs_save_newstate(vap, IEEE80211_S_AUTH, 0);
		(void)fs->fs_save_newstate(vap, IEEE80211_S_ASSOC, 0);
		(void)fs->fs_save_newstate(vap, IEEE80211_S_RUN, 0);
	}
}

void
ieee80211_fmac_link_down(struct ieee80211com *ic, uint16_t reason)
{
	struct ieee80211vap *vap;
	struct fmac_state *fs = ic->ic_fmac;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_STA)
			continue;
		(void)fs->fs_save_newstate(vap, IEEE80211_S_INIT,
		    (int)reason);
	}
}

/*
 * EAPOL up-call.  When the chip's supplicant is disabled, the host
 * (wpa_supplicant) is responsible for the 4-way; the driver hands
 * the chip-delivered EAPOL frame here so the framework can feed
 * net80211, which forwards it via the standard mgmt path.
 *
 * The frame supplied is the bare EAPOL body (ethertype 0x888e),
 * not a full 802.3 / 802.11 frame.  The framework wraps it in
 * an mbuf with a synthetic Ethernet header so ieee80211_input
 * can route it.
 */
void
ieee80211_fmac_eapol_rx(struct ieee80211com *ic,
    const void *buf, size_t len)
{
	struct fmac_state *fs = ic->ic_fmac;
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);
	struct ether_header *eh;
	struct mbuf *m;

	if (vap == NULL || vap->iv_bss == NULL)
		return;
	(void)fs;	/* eapol_tx is opposite direction; unused here */

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return;
	if (sizeof(*eh) + len > MCLBYTES) {
		m_freem(m);
		return;
	}
	eh = mtod(m, struct ether_header *);
	memcpy(eh->ether_dhost, vap->iv_myaddr, ETHER_ADDR_LEN);
	memcpy(eh->ether_shost, vap->iv_bss->ni_bssid, ETHER_ADDR_LEN);
	eh->ether_type = htons(ETHERTYPE_PAE);
	memcpy(eh + 1, buf, len);
	m->m_len = m->m_pkthdr.len = sizeof(*eh) + len;
	m->m_pkthdr.rcvif = vap->iv_ifp;
	ieee80211_input_all(ic, m, 0, NULL);
}
