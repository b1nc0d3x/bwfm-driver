/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * net80211 FullMAC adaptation layer — implementation.
 *
 * Per-ieee80211com state lives in a small list looked up by ic
 * pointer.  A version inside net80211 would keep it in a void
 * *ic_fmac slot on struct ieee80211com instead, behind the same API.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
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
 * Per-com framework state.  Tracked in a global list rather than a
 * direct ic-slot pointer; see the file banner for why.
 */
struct fmac_state {
	struct ieee80211com		   *fs_ic;	/* the net80211 device */
	const struct ieee80211_fullmac_ops *fs_ops;	/* driver callbacks */
	uint32_t			    fs_caps;	/* capability flags */

	int	(*fs_save_newstate)(struct ieee80211vap *,
		    enum ieee80211_state, int);
	void	(*fs_save_scan_start)(struct ieee80211com *);
	void	(*fs_save_scan_end)(struct ieee80211com *);
	int	(*fs_save_key_set)(struct ieee80211vap *,
		    const struct ieee80211_key *);
	int	(*fs_save_key_delete)(struct ieee80211vap *,
		    const struct ieee80211_key *);

	/*
	 * Outstanding-lookup refcount.  fmac_lookup bumps fs_refs before
	 * returning, so a concurrent ieee80211_fmac_detach can't free the
	 * struct out from under the caller.  Callers must pair every
	 * non-NULL lookup with fmac_release(fs).  Detach unlinks from the
	 * list (blocking new lookups) then waits for fs_refs to hit 0.
	 */
	u_int				    fs_refs;

	LIST_ENTRY(fmac_state)		    fs_link;	/* list linkage */
};

static struct mtx			fmac_list_mtx;
static LIST_HEAD(fmac_list_head, fmac_state) fmac_list =
    LIST_HEAD_INITIALIZER(fmac_list);

/*
 * fmac_list_mtx is initialized via MTX_SYSINIT so that two transports
 * attaching in parallel (bwfm_pci and bwfm_sdio loaded concurrently,
 * say) can't race a lazy mtx_init and initialize the mutex twice.
 */
MTX_SYSINIT(fmac_list_mtx, &fmac_list_mtx, "80211_fmac_list", MTX_DEF);

/*
 * Look up the fmac_state for `ic`.  On success bumps fs_refs so the
 * struct can't be freed while the caller works with it.  The caller
 * MUST pair a non-NULL return with fmac_release(fs).
 */
static struct fmac_state *
fmac_lookup(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	mtx_lock(&fmac_list_mtx);
	LIST_FOREACH(fs, &fmac_list, fs_link) {
		if (fs->fs_ic == ic) {
			fs->fs_refs++;
			break;
		}
	}
	mtx_unlock(&fmac_list_mtx);
	return (fs);
}

/*
 * Drop the lookup ref taken by fmac_lookup.  Safe to call with NULL.
 * If a concurrent ieee80211_fmac_detach is waiting for us, the drop
 * to zero wakes it.
 */
static void
fmac_release(struct fmac_state *fs)
{

	if (fs == NULL)
		return;
	mtx_lock(&fmac_list_mtx);
	KASSERT(fs->fs_refs > 0,
	    ("fmac_release: fs_refs already 0"));
	if (--fs->fs_refs == 0)
		wakeup(fs);
	mtx_unlock(&fmac_list_mtx);
}

static int	fmac_newstate(struct ieee80211vap *,
		    enum ieee80211_state, int);
static int	fmac_key_set(struct ieee80211vap *,
		    const struct ieee80211_key *);
static int	fmac_key_delete(struct ieee80211vap *,
		    const struct ieee80211_key *);

/* ------------------------------------------------------------------
 * Attach / detach
 * ------------------------------------------------------------------ */

static void	fmac_scan_start_shim(struct ieee80211com *);
static void	fmac_scan_end_shim(struct ieee80211com *);

/* start the FullMAC framework for this device */
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

	/* fmac_list_mtx is MTX_SYSINIT'd — no explicit init call needed. */
	{
		struct fmac_state *existing = fmac_lookup(ic);

		if (existing != NULL) {
			fmac_release(existing);
			return (EBUSY);
		}
	}

	fs = malloc(sizeof(*fs), M_80211_FMAC, M_WAITOK | M_ZERO);
	fs->fs_ic   = ic;
	fs->fs_ops  = ops;
	fs->fs_caps = caps;

	/*
	 * Save and rewire ic-level scan dispatch.  Drivers therefore
	 * never need to set ic->ic_scan_start / ic_scan_end themselves;
	 * fmop_scan_start owns the chip-side dispatch.
	 */
	fs->fs_save_scan_start = ic->ic_scan_start;
	fs->fs_save_scan_end   = ic->ic_scan_end;
	ic->ic_scan_start = fmac_scan_start_shim;
	ic->ic_scan_end   = fmac_scan_end_shim;

	mtx_lock(&fmac_list_mtx);
	LIST_INSERT_HEAD(&fmac_list, fs, fs_link);
	mtx_unlock(&fmac_list_mtx);
	return (0);
}

/* stop the framework for this device */
void
ieee80211_fmac_detach(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	/*
	 * Locate and remove atomically, then wait for outstanding
	 * lookups to drop their refs before freeing.  Once fs is off
	 * the list no new lookup can find it, so fs_refs only
	 * decreases.  This keeps detach correct regardless of the
	 * caller's ordering relative to ieee80211_ifdetach.
	 */
	mtx_lock(&fmac_list_mtx);
	LIST_FOREACH(fs, &fmac_list, fs_link) {
		if (fs->fs_ic == ic)
			break;
	}
	if (fs == NULL) {
		mtx_unlock(&fmac_list_mtx);
		return;
	}
	LIST_REMOVE(fs, fs_link);
	/*
	 * Bounded drain, capped at 30 s.  If refs don't reach zero by
	 * then a caller is stuck (a wedged firmware command, a livelocked
	 * thread) and blocking forever would hang the system, so leak fs
	 * instead of freeing it.  Print the ref count and saved ic slots
	 * to help diagnose the hang.
	 */
	{
		int wi;

		for (wi = 0; wi < 30; wi++) {
			if (fs->fs_refs == 0)
				break;
			(void)mtx_sleep(fs, &fmac_list_mtx, 0, "fmacdet", hz);
		}
		if (fs->fs_refs != 0) {
			printf("ieee80211_fmac_detach: fs_refs=%u after 30s "
			    "wait, leaking fs=%p ic=%p to avoid hang "
			    "(save_newstate=%p scan_start=%p key_set=%p)\n",
			    fs->fs_refs, fs, ic, fs->fs_save_newstate,
			    fs->fs_save_scan_start, fs->fs_save_key_set);
			/*
			 * Rearm the list link (we already REMOVE'd) then
			 * unlock and bail.  ic slots stay pointing at our
			 * shims — the caller must not free ic yet.
			 */
			LIST_INSERT_HEAD(&fmac_list, fs, fs_link);
			mtx_unlock(&fmac_list_mtx);
			return;
		}
	}
	mtx_unlock(&fmac_list_mtx);

	/*
	 * Restore saved ic slots.  Safe outside the list lock because
	 * every reader that could have raced us just released its ref.
	 */
	ic->ic_scan_start = fs->fs_save_scan_start;
	ic->ic_scan_end   = fs->fs_save_scan_end;

	free(fs, M_80211_FMAC);
}

/*
 * Helper drivers call from vap_create after the vap is allocated
 * but before they return it.  Saves and rewires the per-vap entry
 * points (iv_newstate, iv_key_set, iv_key_delete) onto the
 * framework's shims.  When the driver later calls
 * ieee80211_fmac_link_up / link_down, the shims walk net80211
 * state via the saved hooks.
 */
void
ieee80211_fmac_vap_attach(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL)
		return;

	if (fs->fs_save_newstate == NULL)
		fs->fs_save_newstate = vap->iv_newstate;
	if (fs->fs_save_key_set == NULL)
		fs->fs_save_key_set = vap->iv_key_set;
	if (fs->fs_save_key_delete == NULL)
		fs->fs_save_key_delete = vap->iv_key_delete;

	vap->iv_newstate   = fmac_newstate;
	vap->iv_key_set    = fmac_key_set;
	vap->iv_key_delete = fmac_key_delete;

	fmac_release(fs);
}

/* ------------------------------------------------------------------
 * net80211 -> driver shims
 * ------------------------------------------------------------------ */

static int
fmac_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211_fmac_assoc fa;
	int rc;

	if (fs == NULL)
		return (EINVAL);

	switch (nstate) {
	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC: {
		struct ieee80211_node *ni = vap->iv_bss;

		if (vap->iv_state != IEEE80211_S_AUTH &&
		    vap->iv_state != IEEE80211_S_ASSOC) {
			memset(&fa, 0, sizeof(fa));
			if (ni != NULL) {
				memcpy(fa.fa_bssid, ni->ni_bssid,
				    IEEE80211_ADDR_LEN);
				fa.fa_ssidlen = MIN(ni->ni_esslen,
				    sizeof(fa.fa_ssid));
				memcpy(fa.fa_ssid, ni->ni_essid,
				    fa.fa_ssidlen);
				fa.fa_chan_freq = (ni->ni_chan != NULL &&
				    ni->ni_chan != IEEE80211_CHAN_ANYC) ?
				    ni->ni_chan->ic_freq : 0;
			}
			(void)fs->fs_ops->fmop_assoc(ic, &fa);
		}
		break;
	}
	case IEEE80211_S_INIT:
		(void)fs->fs_ops->fmop_disassoc(ic,
		    IEEE80211_REASON_AUTH_LEAVE);
		break;
	default:
		break;
	}
	rc = fs->fs_save_newstate(vap, nstate, arg);
	fmac_release(fs);
	return (rc);
}

/*
 * Install a key into the chip.
 *
 * The two sides of this shim use opposite conventions, and mixing them
 * up is what kept WPA2 from ever completing.  The driver ops return an
 * errno -- 0 on success, ENXIO for "not mine, use net80211's own".  But
 * iv_key_set and iv_key_delete follow net80211's crypto convention:
 * nonzero means success, 0 means failure (null_key_set returns 1, and
 * ieee80211_ioctl_setkey turns a 0 into EIO).  Passing the errno
 * straight through turned every successful PTK install into EIO, so
 * wpa_supplicant finished the 4-way, failed "Installing PTK to the
 * driver", deauthenticated, and blamed the pre-shared key -- once a
 * second, forever.  Translate here; the saved net80211 hooks already
 * speak net80211's convention and pass through as they are.
 */
static int
fmac_key_set(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	int ok, rc;

	if (fs == NULL)
		return (0);
	rc = fs->fs_ops->fmop_set_key(ic, key);
	if (rc == ENXIO && fs->fs_save_key_set != NULL)
		ok = fs->fs_save_key_set(vap, key);
	else
		ok = (rc == 0);
	fmac_release(fs);
	return (ok);
}

/* remove a key from the chip; same conventions as fmac_key_set */
static int
fmac_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	int ok = 1, rc;

	if (fs == NULL)
		return (0);
	if (fs->fs_ops->fmop_del_key != NULL) {
		rc = fs->fs_ops->fmop_del_key(ic, key);
		if (rc != ENXIO) {
			fmac_release(fs);
			return (rc == 0);
		}
	}
	if (fs->fs_save_key_delete != NULL)
		ok = fs->fs_save_key_delete(vap, key);
	fmac_release(fs);
	return (ok);
}

/*
 * ic_scan_start / ic_scan_end shims.  Drivers don't set these
 * directly; the framework owns them.  fmop_scan_start receives a
 * single SSID at most (net80211's ic_scan_state may have more but
 * almost every FullMAC chip's scan engine takes one).  When the
 * driver returns non-zero, fall back to the saved net80211 hook
 * (which is typically a no-op for SoftMAC-shaped scan engines).
 */
static void
fmac_scan_start_shim(struct ieee80211com *ic)
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211_scan_state *ss;
	const uint8_t *ssid = NULL;
	size_t ssidlen = 0;
	bool active = true;
	int rc;

	if (fs == NULL)
		return;
	ss = ic->ic_scan;
	if (ss != NULL) {
		if (ss->ss_nssid > 0) {
			ssid    = ss->ss_ssid[0].ssid;
			ssidlen = ss->ss_ssid[0].len;
		}
		active = (ss->ss_flags & IEEE80211_SCAN_ACTIVE) != 0;
	}
	rc = fs->fs_ops->fmop_scan_start(ic, ssid, ssidlen, active);
	if (rc != 0 && fs->fs_save_scan_start != NULL)
		fs->fs_save_scan_start(ic);
	fmac_release(fs);
}

/* end of scan: tell the chip to stop */
static void
fmac_scan_end_shim(struct ieee80211com *ic)
{
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL)
		return;
	if (fs->fs_ops->fmop_scan_cancel != NULL)
		fs->fs_ops->fmop_scan_cancel(ic);
	if (fs->fs_save_scan_end != NULL)
		fs->fs_save_scan_end(ic);
	fmac_release(fs);
}

/* ------------------------------------------------------------------
 * Driver -> net80211 up-calls
 * ------------------------------------------------------------------ */

/*
 * Accept a driver-built mgmt-frame mbuf (a beacon or probe-response
 * shape, with the firmware's IE block concatenated) plus per-frame
 * receive info, parse it into ieee80211_scanparams, and call the
 * scan module's ss_ops->scan_add (sta_add) directly, bypassing
 * ic_scan_methods->sc_add_scan (ieee80211_swscan_add_scan).
 *
 * We don't go through ieee80211_input_mimo_all -> sta_recv_mgmt ->
 * ieee80211_add_scan because sta_recv_mgmt only processes beacons
 * while IEEE80211_F_SCAN is set, and that flag belongs to the software
 * scan engine walking channels.  With the chip driving the scan,
 * every injected beacon would be silently dropped.  Bypassing
 * sta_recv_mgmt also avoids a deep call chain that brings the kernel
 * close to its stack limit during sustained scans.
 *
 * Channel resolution: look up an ieee80211_channel by frequency from
 * ic_channels (ieee80211_find_channel handles the mode mapping).
 *
 * The mbuf is consumed by this function on every return path.
 */
void
ieee80211_fmac_input_beacon(struct ieee80211com *ic, struct mbuf *m,
    const struct ieee80211_fmac_rxinfo *ri)
{
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;
	struct ieee80211_scanparams sp;
	struct ieee80211_channel *rxchan;
	const struct ieee80211_frame *wh;
	int rssi_n80, subtype;
	int8_t nf;

	if (m == NULL)
		return;
	if (ri == NULL) {
		m_freem(m);
		return;
	}

	/*
	 * Pick the first STA vap.  fmac is single-vap by contract
	 * (bwfm_vap_create rejects a second vap).
	 */
	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL || vap->iv_bss == NULL) {
		m_freem(m);
		return;
	}
	/*
	 * Only inject beacons while a scan is actually live and bound
	 * to a vap.  Outside that window:
	 *   - ic->ic_scan is allocated at attach but its ss_priv /
	 *     ss_vap / ss_ops are wired by sw_scan's ss_ops->scan_start
	 *     and torn down by scan_done.
	 *   - ss->ss_vap is NULL after scan_done, and sta_add (sw scan
	 *     engine's scan_add) immediately derefs it -> NULL panic.
	 *
	 * IEEE80211_F_SCAN is the cheapest live-scan indicator.
	 */
	if (ic->ic_scan == NULL || ic->ic_scan->ss_ops == NULL ||
	    ic->ic_scan->ss_ops->scan_add == NULL ||
	    (ic->ic_flags & IEEE80211_F_SCAN) == 0 ||
	    ic->ic_scan->ss_vap == NULL) {
		m_freem(m);
		return;
	}

	if (m->m_len < (int)sizeof(struct ieee80211_frame)) {
		m = m_pullup(m, sizeof(struct ieee80211_frame));
		if (m == NULL)
			return;
	}
	wh = mtod(m, const struct ieee80211_frame *);
	subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	rxchan = ieee80211_find_channel(ic, ri->fri_chan_freq,
	    (ri->fri_chan_freq >= 5000) ?
	    IEEE80211_CHAN_A : IEEE80211_CHAN_G);
	if (rxchan == NULL)
		rxchan = ic->ic_curchan;
	if (rxchan == NULL) {
		m_freem(m);
		return;
	}

	nf = ieee80211_fmac_noise_floor(ri->fri_noise_dbm);
	rssi_n80 = ((int)ri->fri_rssi_dbm - (int)nf) * 2;
	if (rssi_n80 < 0)
		rssi_n80 = 0;
	if (rssi_n80 > 127)
		rssi_n80 = 127;

	ni = ieee80211_ref_node(vap->iv_bss);
	if (ni == NULL) {
		m_freem(m);
		return;
	}

	memset(&sp, 0, sizeof(sp));
	{
		uint32_t st;
		st = ieee80211_parse_beacon(ni, m, rxchan, &sp);
		/*
		 * Bypass swscan_add_scan and call scan_add (= sta_add)
		 * directly; see bwfm_add_scan_result for the same
		 * ISCAN_DISCARD rationale.  parse_beacon has fully
		 * populated sp (tstamp, rates, ssid, ies, ...) so
		 * sta_add has no NULL fields to deref.
		 */
		if ((st & ~IEEE80211_BPARSE_OFFCHAN) == 0)
			(void)ic->ic_scan->ss_ops->scan_add(ic->ic_scan,
			    rxchan, &sp, wh, subtype, rssi_n80, nf);
	}

	ieee80211_free_node(ni);
	m_freem(m);
}

/*
 * Fast-forward the bss vap to RUN when the firmware says "linked".
 * Conservative: only walks from AUTH or ASSOC (i.e., when net80211
 * is in a state where sta_newstate(RUN) won't NULL-deref on
 * ieee80211_sync_curchan).  Returns ENOENT if no vap is in a
 * fast-forwardable state — the driver does its own recovery (a
 * scan-cache lookup, for instance).
 */
int
ieee80211_fmac_link_up(struct ieee80211com *ic,
    const uint8_t bssid[IEEE80211_ADDR_LEN])
{
	struct ieee80211vap *vap;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_STA)
			continue;
		if (vap->iv_bss == NULL || vap->iv_bss->ni_chan == NULL ||
		    vap->iv_bss->ni_chan == IEEE80211_CHAN_ANYC)
			return (ENOENT);
		if (vap->iv_state != IEEE80211_S_AUTH &&
		    vap->iv_state != IEEE80211_S_ASSOC)
			return (ENOENT);
		if (bssid != NULL)
			memcpy(vap->iv_bss->ni_bssid, bssid,
			    IEEE80211_ADDR_LEN);
		(void)ieee80211_new_state(vap, IEEE80211_S_RUN, -1);
		return (0);
	}
	return (ENOENT);
}

/* firmware says the link dropped: reset to init */
int
ieee80211_fmac_link_down(struct ieee80211com *ic, uint16_t reason)
{
	struct ieee80211vap *vap;
	int n = 0;

	(void)reason;
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_STA)
			continue;
		(void)ieee80211_new_state(vap, IEEE80211_S_INIT, -1);
		n++;
	}
	return (n != 0 ? 0 : ENOENT);
}

/*
 * EAPOL up-call.  When the chip's supplicant is disabled, the host
 * (wpa_supplicant) runs the 4-way; the driver hands chip-delivered
 * EAPOL frames here.  We wrap them in a synthetic 802.3 header
 * (dst=our_mac, src=ap_mac, type=0x888e) and deliver it with
 * ieee80211_vap_deliver_data so the wlan(4) bpf path routes it to
 * userspace.
 */
void
ieee80211_fmac_eapol_rx(struct ieee80211com *ic,
    const uint8_t ap_mac[IEEE80211_ADDR_LEN],
    const void *buf, size_t len)
{
	struct ieee80211vap *vap;
	uint8_t *eh;
	struct mbuf *m;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;
	if (len == 0 || 14 + len > MCLBYTES)
		return;

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return;
	eh = mtod(m, uint8_t *);
	memcpy(eh + 0, vap->iv_myaddr, ETHER_ADDR_LEN);
	memcpy(eh + 6, ap_mac, ETHER_ADDR_LEN);
	eh[12] = 0x88;
	eh[13] = 0x8e;
	memcpy(eh + 14, buf, len);
	m->m_len = m->m_pkthdr.len = 14 + len;
	m->m_pkthdr.rcvif = vap->iv_ifp;
	/*
	 * ieee80211_input_all expects 802.11 frames and would silently
	 * drop this synthetic 802.3 frame, so feed the vap's ifnet
	 * directly; wpa_supplicant sees it through bpf and drives the
	 * 4-way handshake.
	 */
	/*
	 * if_input must run inside the network epoch.
	 * ieee80211_vap_deliver_data is the net80211 helper that wraps
	 * it in NET_EPOCH_ENTER/NET_EPOCH_EXIT; calling if_input
	 * without the epoch leaves the frame undelivered.
	 */
	ieee80211_vap_deliver_data(vap, m);
}

/*
 * Scan-result up-call.  The API takes a structured description, but
 * bwfm still uses its own synthesised-beacon path because the scan
 * path is more invasive to change than the state-machine paths.
 * This is a stub until a second driver needs it.
 */
void
ieee80211_fmac_scan_result(struct ieee80211com *ic __unused,
    const struct ieee80211_fmac_bss *bb __unused)
{
}

/* tell net80211 the scan is finished */
void
ieee80211_fmac_scan_done(struct ieee80211com *ic)
{
	if (ic->ic_scan != NULL && ic->ic_scan->ss_vap != NULL)
		ieee80211_scan_done(ic->ic_scan->ss_vap);
}
