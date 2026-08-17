/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * net80211 FullMAC adaptation layer, C code.
 *
 * This in-driver copy has the same shape as the upstream
 * candidate at drafts/net80211/ieee80211_fullmac.c. The only
 * difference: the upstream version stores per-com state in a
 * new `void *ic_fmac` slot on struct ieee80211com. Until that
 * one-line net80211 patch lands, this copy keeps per-com state
 * in a small linked list looked up by ic pointer. Both paths
 * share the same public API in ieee80211_fullmac.h.
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
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/if_media.h>
#include <net/netisr.h>
#include <net/bpf.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_input.h>
#include <net80211/ieee80211_proto.h>
#include <net80211/ieee80211_regdomain.h>

#include "ieee80211_fullmac.h"

static MALLOC_DEFINE(M_80211_FMAC, "80211_fmac",
    "net80211 FullMAC framework");

/*
 * Per-com framework state. Kept in a global list, not in a
 * direct ic-slot pointer. See the file banner for why.
 */
struct fmac_state {
	struct ieee80211com		   *fs_ic;
	const struct ieee80211_fullmac_ops *fs_ops;
	uint32_t			    fs_caps;

	/*
	 * Chip-side link state. Set true by ieee80211_fmac_link_up.
	 * Set false by ieee80211_fmac_link_down. fmac_newstate uses
	 * it to refuse vap RUN -> non-RUN transitions while the fw
	 * still has an association, so the ifp carrier stays stable
	 * under dhclient.
	 */
	bool				    fs_linked;

	int	(*fs_save_newstate)(struct ieee80211vap *,
		    enum ieee80211_state, int);
	void	(*fs_save_scan_start)(struct ieee80211com *);
	void	(*fs_save_scan_end)(struct ieee80211com *);
	void	(*fs_save_scan_curchan)(struct ieee80211_scan_state *,
		    unsigned long);
	void	(*fs_save_scan_mindwell)(struct ieee80211_scan_state *);
	int	(*fs_save_key_set)(struct ieee80211vap *,
		    const struct ieee80211_key *);
	int	(*fs_save_key_delete)(struct ieee80211vap *,
		    const struct ieee80211_key *);
	int	(*fs_save_setregdomain)(struct ieee80211com *,
		    struct ieee80211_regdomain *,
		    int, struct ieee80211_channel []);

	/*
	 * fmop_disassoc walks the fw through a synchronous DCMD,
	 * which can sleep. The RUN -> INIT newstate transition
	 * from ifconfig-down runs with the driver's com lock held.
	 * Calling fmop_disassoc from that callback panics with
	 * `sleeping thread holds <driver>_com_l`. So we enqueue
	 * this task on taskqueue_thread. It runs outside the
	 * newstate lock and sends the DCMD there. The state
	 * machine walks to INIT right away, and the chip-side
	 * teardown happens shortly after.
	 */
	struct task			    fs_disassoc_task;
	int				    fs_disassoc_reason;

	LIST_ENTRY(fmac_state)		    fs_link;
};

static struct mtx			fmac_list_mtx;
static LIST_HEAD(fmac_list_head, fmac_state) fmac_list =
    LIST_HEAD_INITIALIZER(fmac_list);
static bool				fmac_list_initted;

static void
fmac_list_init_once(void)
{
	if (fmac_list_initted)
		return;
	mtx_init(&fmac_list_mtx, "80211_fmac_list", NULL, MTX_DEF);
	fmac_list_initted = true;
}

static struct fmac_state *
fmac_lookup(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	if (!fmac_list_initted)
		return (NULL);
	mtx_lock(&fmac_list_mtx);
	LIST_FOREACH(fs, &fmac_list, fs_link)
		if (fs->fs_ic == ic)
			break;
	mtx_unlock(&fmac_list_mtx);
	return (fs);
}

static int	fmac_newstate(struct ieee80211vap *,
		    enum ieee80211_state, int);
static int	fmac_key_set(struct ieee80211vap *,
		    const struct ieee80211_key *);
static int	fmac_key_delete(struct ieee80211vap *,
		    const struct ieee80211_key *);
static void	fmac_disassoc_task(void *, int);

/* ------------------------------------------------------------------
 * Attach / detach
 * ------------------------------------------------------------------ */

static void	fmac_scan_start_shim(struct ieee80211com *);
static void	fmac_scan_end_shim(struct ieee80211com *);
static void	fmac_scan_curchan_noop(struct ieee80211_scan_state *,
		    unsigned long);
static void	fmac_scan_mindwell_noop(struct ieee80211_scan_state *);
static int	fmac_setregdomain_shim(struct ieee80211com *,
		    struct ieee80211_regdomain *,
		    int, struct ieee80211_channel []);

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

	fmac_list_init_once();
	if (fmac_lookup(ic) != NULL)
		return (EBUSY);

	fs = malloc(sizeof(*fs), M_80211_FMAC, M_WAITOK | M_ZERO);
	fs->fs_ic   = ic;
	fs->fs_ops  = ops;
	fs->fs_caps = caps;
	TASK_INIT(&fs->fs_disassoc_task, 0, fmac_disassoc_task, fs);

	/*
	 * Save and rewire ic-level scan dispatch. Drivers never need
	 * to set ic->ic_scan_start / ic_scan_end themselves.
	 * fmop_scan_start owns the chip-side dispatch.
	 */
	fs->fs_save_scan_start    = ic->ic_scan_start;
	fs->fs_save_scan_end      = ic->ic_scan_end;
	fs->fs_save_scan_curchan  = ic->ic_scan_curchan;
	fs->fs_save_scan_mindwell = ic->ic_scan_mindwell;
	ic->ic_scan_start    = fmac_scan_start_shim;
	ic->ic_scan_end      = fmac_scan_end_shim;
	/*
	 * The chip does per-channel dwell + probe TX by itself after
	 * we send the escan iovar in fmop_scan_start. Net80211's
	 * default ic_scan_curchan runs scan_curchan_task under
	 * IEEE80211_LOCK and calls ic->ic_transmit -> bs_txdata ->
	 * flowring_create -> sleep, which panics with
	 * "sleeping thread holds *_com_l" (2026-07-21 fbsdmac).
	 * So point them at no-op shims for FullMAC.
	 */
	ic->ic_scan_curchan  = fmac_scan_curchan_noop;
	ic->ic_scan_mindwell = fmac_scan_mindwell_noop;

	/*
	 * Regulatory-domain sync. Route ic_setregdomain (fired by
	 * `ifconfig wlan0 regdomain <sku> country <cc>`) through
	 * the fmac op so the fw's `country` iovar tracks the host's
	 * regdomain.
	 */
	fs->fs_save_setregdomain = ic->ic_setregdomain;
	ic->ic_setregdomain = fmac_setregdomain_shim;

	mtx_lock(&fmac_list_mtx);
	LIST_INSERT_HEAD(&fmac_list, fs, fs_link);
	mtx_unlock(&fmac_list_mtx);
	return (0);
}

void
ieee80211_fmac_detach(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	fs = fmac_lookup(ic);
	if (fs == NULL)
		return;

	/*
	 * Drain any pending disassoc task before we free fs. The
	 * task body reads fs->fs_ic and fs->fs_ops.
	 */
	taskqueue_drain(taskqueue_thread, &fs->fs_disassoc_task);

	/* Restore saved ic slots. */
	ic->ic_scan_start    = fs->fs_save_scan_start;
	ic->ic_scan_end      = fs->fs_save_scan_end;
	ic->ic_scan_curchan  = fs->fs_save_scan_curchan;
	ic->ic_scan_mindwell = fs->fs_save_scan_mindwell;
	ic->ic_setregdomain  = fs->fs_save_setregdomain;

	mtx_lock(&fmac_list_mtx);
	LIST_REMOVE(fs, fs_link);
	mtx_unlock(&fmac_list_mtx);

	free(fs, M_80211_FMAC);
}

/*
 * Helper drivers call from vap_create after the vap is made but
 * before they return it. Saves and rewires the per-vap entry
 * points (iv_newstate, iv_key_set, iv_key_delete) onto the
 * framework's shims. When the driver later calls
 * ieee80211_fmac_link_up / link_down, the shims walk net80211
 * state via the saved hooks.
 */
/*
 * FullMAC transmit shim. net80211's default if_transmit routes
 * the mbuf through ieee80211_start_pkt, which wraps it into an
 * 802.11 frame (LLC/SNAP + 802.11 header). Our chip is FullMAC
 * and wants 802.3 Ethernet frames. The old symptom was
 * FLOW_CREATE with da=40:00:00:00:ff:ff, which is 802.11 FC
 * bytes read as a MAC. Skip the encap by calling ic->ic_transmit
 * (which points to our brcm_transmit -> bs_txdata) with the
 * 802.3 mbuf built by ether_output.
 */
static int
fmac_transmit_shim(struct ifnet *ifp, struct mbuf *m)
{
	struct ieee80211vap *vap = if_getsoftc(ifp);
	struct ieee80211com *ic = vap->iv_ic;
	uint16_t etype = 0;

	if (m->m_pkthdr.len >= 14 && m->m_len >= 14) {
		const uint8_t *p = mtod(m, const uint8_t *);
		etype = (uint16_t)p[12] << 8 | p[13];
	}
	/* Hex-dump EAPOL frames so we can compare with wpa_supplicant's
	 * "WPA: Send EAPOL-Key frame" DBG log and prove the host-side
	 * path is clean. EAPOL only. Anything else would spam. */
	if (etype == 0x888e && m->m_pkthdr.len <= 256) {
		int i, n = m->m_pkthdr.len;
		const uint8_t *p = mtod(m, const uint8_t *);
		char line[80];
		int off;
		printf("fmac_transmit EAPOL len=%d\n", n);
		for (i = 0; i < n; i += 16) {
			off = 0;
			off += snprintf(line + off, sizeof(line) - off,
			    "  %03x:", i);
			for (int j = 0; j < 16 && i + j < n; j++)
				off += snprintf(line + off, sizeof(line) - off,
				    " %02x", p[i + j]);
			printf("%s\n", line);
		}
	}
	if (vap->iv_state != IEEE80211_S_RUN &&
	    vap->iv_state != IEEE80211_S_SLEEP) {
		m_freem(m);
		return (ENETDOWN);
	}
	return (ic->ic_transmit(ic, m));
}

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

	/* Skip net80211's 802.11 encap on outbound. */
	if_settransmitfn(vap->iv_ifp, fmac_transmit_shim);
}

/* ------------------------------------------------------------------
 * net80211 -> driver shims
 * ------------------------------------------------------------------ */

/*
 * Deferred fmop_disassoc. fmac_newstate schedules this on
 * taskqueue_thread when the vap walks RUN -> INIT so the DCMD
 * sleep happens outside the driver's com lock. (ifconfig-down
 * holds that lock across the newstate callback.) The reason
 * code was captured at schedule time so the fw sees the right
 * byte on-air.
 */
static void
fmac_disassoc_task(void *arg, int pending __unused)
{
	struct fmac_state *fs = arg;

	if (fs == NULL || fs->fs_ops == NULL ||
	    fs->fs_ops->fmop_disassoc == NULL)
		return;
	(void)fs->fs_ops->fmop_disassoc(fs->fs_ic, fs->fs_disassoc_reason);
}

static int
fmac_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211_fmac_assoc fa;

	if (fs == NULL)
		return (EINVAL);

	/*
	 * fmop_assoc / fmop_disassoc are side-effects on the fw. We
	 * tell the chip what to do, then always run net80211 through
	 * its own newstate walk. The chip's later LINK event is what
	 * fast-forwards the vap to RUN (via ieee80211_fmac_link_up).
	 */
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
				fa.fa_chan_freq = (ni->ni_chan != NULL) ?
				    ni->ni_chan->ic_freq : 0;
			}
			(void)fs->fs_ops->fmop_assoc(ic, &fa);
		}
		break;
	}
	case IEEE80211_S_INIT:
		/*
		 * Defer the fw disassoc to taskqueue_thread. The caller
		 * here is often ifconfig-down, which holds the driver's
		 * com lock. fmop_disassoc sends a synchronous DCMD that
		 * sleeps. Running the DCMD from the newstate callback
		 * would panic `sleeping thread holds <drv>_com_l`. The
		 * state machine still walks to INIT right below. The
		 * task fires shortly after, and the chip gets its
		 * teardown DCMD outside any net80211 lock.
		 */
		fs->fs_disassoc_reason = IEEE80211_REASON_AUTH_LEAVE;
		taskqueue_enqueue(taskqueue_thread, &fs->fs_disassoc_task);
		break;
	default:
		break;
	}
	/*
	 * If the chip still has an active association and net80211
	 * tries to walk the vap RUN -> SCAN or RUN -> AUTH (bg scan,
	 * bmiss timer, wpa_supplicant re-auth trigger), refuse the
	 * transition. Without this, the ifp link state flaps DOWN/UP
	 * every few seconds during a fresh association, and dhclient
	 * can't hold carrier long enough to receive the DHCP OFFER.
	 *
	 * RUN -> INIT is allowed here. With fmop_disassoc deferred
	 * onto taskqueue_thread (S_INIT case above), the lock-order
	 * panic is gone. Refusing INIT would wedge the vap at RUN so
	 * a later ifconfig-up + wpa_supplicant cycle never triggers
	 * a fresh scan. A LINK-down event from the fw clears
	 * fs_linked before this callback returns for the second
	 * cycle, so the wedge only bites when the fw has not yet
	 * reported the disassoc it is about to be told to do.
	 */
	if (fs->fs_linked && vap->iv_state == IEEE80211_S_RUN &&
	    (nstate == IEEE80211_S_SCAN ||
	     nstate == IEEE80211_S_AUTH)) {
		printf("fmac: refuse vap RUN -> %d (chip still linked)\n",
		    (int)nstate);
		return (0);
	}
	return (fs->fs_save_newstate(vap, nstate, arg));
}

static int
fmac_key_set(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	int rc;

	if (fs == NULL)
		return (0);	/* net80211 truth rule */
	rc = fs->fs_ops->fmop_set_key(ic, key);
	if (rc == ENXIO && fs->fs_save_key_set != NULL)
		return (fs->fs_save_key_set(vap, key));
	/*
	 * net80211's iv_key_set rule is 1 = success, 0 = failure
	 * (see null_key_set). fmop_set_key uses the POSIX 0-on-
	 * success rule, so translate here. Without this, net80211
	 * reports EIO to wpa_supplicant for every PTK install even
	 * though the DCMD worked. wpa_supplicant then deauths
	 * locally with reason=1.
	 */
	return (rc == 0 ? 1 : 0);
}

static int
fmac_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	int rc;

	/* iv_key_delete rule: 1 = success, 0 = failure. */
	if (fs == NULL)
		return (1);
	if (fs->fs_ops->fmop_del_key != NULL) {
		rc = fs->fs_ops->fmop_del_key(ic, key);
		if (rc != ENXIO)
			return (rc == 0 ? 1 : 0);
	}
	if (fs->fs_save_key_delete != NULL)
		return (fs->fs_save_key_delete(vap, key));
	return (1);
}

/*
 * ic_scan_start / ic_scan_end shims. Drivers do not set these
 * directly. The framework owns them. fmop_scan_start gets at
 * most one SSID (net80211's ic_scan_state may have more, but
 * almost every FullMAC chip's scan engine takes one). If the
 * driver returns non-zero, fall back to the saved net80211
 * hook (usually a no-op for SoftMAC-shaped scan engines).
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
}

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
}

/*
 * scan_curchan / scan_mindwell are no-ops for FullMAC. The chip
 * owns per-channel dwell + probe-req TX after we fired the
 * escan iovar. Net80211's default scan_curchan runs a task
 * that TXes a probe-req via ic->ic_transmit under IEEE80211_LOCK.
 * On brcm_pci that path sleeps in flowring_create, which
 * WITNESS flags as sleep-with-com_l held.
 */
static void
fmac_scan_curchan_noop(struct ieee80211_scan_state *ss __unused,
    unsigned long maxdwell __unused)
{
}

static void
fmac_scan_mindwell_noop(struct ieee80211_scan_state *ss __unused)
{
}

/*
 * Regdomain shim. Net80211 calls this from ieee80211_setregdomain
 * when userspace runs
 * `ifconfig wlan0 regdomain <sku> country <cc>`. Route the ISO
 * country code into the chip-side `country` iovar via
 * fmop_set_country. Then let net80211's saved handler apply
 * the channel/txpower table update. Always return 0 on
 * set-country failure so net80211 still records the new
 * regdomain. Worst case the chip stays on the old country
 * until reboot.
 */
static int
fmac_setregdomain_shim(struct ieee80211com *ic,
    struct ieee80211_regdomain *reg, int nchans,
    struct ieee80211_channel chans[])
{
	struct fmac_state *fs = fmac_lookup(ic);
	char cc[3];
	int rc;

	if (fs != NULL && fs->fs_ops->fmop_set_country != NULL) {
		cc[0] = reg->isocc[0];
		cc[1] = reg->isocc[1];
		cc[2] = '\0';
		rc = fs->fs_ops->fmop_set_country(ic, cc);
		if (rc != 0)
			printf("fmac: fmop_set_country(%c%c) rc=%d "
			    "chip regdomain not updated\n",
			    cc[0], cc[1], rc);
	}
	if (fs != NULL && fs->fs_save_setregdomain != NULL)
		return (fs->fs_save_setregdomain(ic, reg, nchans, chans));
	return (0);
}

/* ------------------------------------------------------------------
 * Driver -> net80211 up-calls
 * ------------------------------------------------------------------ */

/*
 * Take a driver-built mgmt-frame mbuf (beacon or probe-response
 * shape, with the firmware's IE block joined on) plus per-frame
 * receive info. Parse into ieee80211_scanparams. Then call
 * ic_scan_methods->sc_add_scan directly.
 *
 * Older code routed the mbuf through ieee80211_input_mimo_all
 * -> sta_recv_mgmt -> ieee80211_add_scan. sta_recv_mgmt gates
 * beacon processing on `ic->ic_flags & IEEE80211_F_SCAN`, which
 * the SW scan engine sets while it walks channels. For a fmac
 * driver the chip drives the scan and the SW engine never gets
 * to set F_SCAN. So every injected beacon hit the silent-drop
 * branch and `ifconfig wlan0 list scan` stayed empty.
 *
 * Bypassing sta_recv_mgmt also avoids a deep call chain that
 * pushed the kernel close to its stack budget during long scans
 * (see project_brcm_net80211_phase1c_2026_06_25. m_devget panic
 * on Pi 4).
 *
 * Channel resolution: look up an ieee80211_channel by frequency
 * in ic_channels (ieee80211_find_channel handles the mode
 * mapping).
 *
 * This function frees the mbuf on every return path.
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
	 * Pick the first STA vap. fmac is single-vap by contract
	 * today (brcm_vap_create rejects a second vap).
	 */
	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL || vap->iv_bss == NULL) {
		m_freem(m);
		return;
	}
	/*
	 * Only inject beacons while a scan is actually live and
	 * bound to a vap. Outside that window:
	 *   - ic->ic_scan is allocated at attach, but its ss_priv,
	 *     ss_vap, ss_ops are wired by sw_scan's ss_ops->scan_start
	 *     and torn down by scan_done.
	 *   - ss->ss_vap is NULL after scan_done, and sta_add (sw
	 *     scan engine's scan_add) derefs it right away -> NULL
	 *     panic.
	 *
	 * IEEE80211_F_SCAN is the cheapest "scan live" check.
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

	nf = (ri->fri_noise_dbm != 0) ? ri->fri_noise_dbm : -95;
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
		 * Skip swscan_add_scan and call scan_add (= sta_add)
		 * directly. See brcm_add_scan_result for the same
		 * ISCAN_DISCARD reason. parse_beacon has fully filled
		 * sp (tstamp, rates, ssid, ies, ...) so sta_add has no
		 * NULL fields to deref.
		 */
		if ((st & ~IEEE80211_BPARSE_OFFCHAN) == 0)
			(void)ic->ic_scan->ss_ops->scan_add(ic->ic_scan,
			    rxchan, &sp, wh, subtype, rssi_n80, nf);
	}

	ieee80211_free_node(ni);
	m_freem(m);
}

/*
 * Fast-forward the bss vap to RUN when the firmware says
 * "linked". Careful. Only walks from AUTH or ASSOC (i.e. when
 * net80211 is in a state where sta_newstate(RUN) will not
 * NULL-deref on ieee80211_sync_curchan). Returns ENOENT if no
 * vap is in a fast-forwardable state. The driver then does its
 * own recovery (a scan-cache lookup, for example).
 */
int
ieee80211_fmac_link_up(struct ieee80211com *ic,
    const uint8_t bssid[IEEE80211_ADDR_LEN])
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211vap *vap;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_STA)
			continue;
		if (vap->iv_bss == NULL || vap->iv_bss->ni_chan == NULL)
			return (ENOENT);
		if (vap->iv_state != IEEE80211_S_AUTH &&
		    vap->iv_state != IEEE80211_S_ASSOC)
			return (ENOENT);
		if (bssid != NULL)
			memcpy(vap->iv_bss->ni_bssid, bssid,
			    IEEE80211_ADDR_LEN);
		if (fs != NULL)
			fs->fs_linked = true;
		(void)ieee80211_new_state(vap, IEEE80211_S_RUN, -1);
		return (0);
	}
	return (ENOENT);
}

int
ieee80211_fmac_link_down(struct ieee80211com *ic, uint16_t reason)
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211vap *vap;
	int n = 0;

	(void)reason;
	if (fs != NULL)
		fs->fs_linked = false;
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_STA)
			continue;
		(void)ieee80211_new_state(vap, IEEE80211_S_INIT, -1);
		n++;
	}
	return (n != 0 ? 0 : ENOENT);
}

/*
 * EAPOL up-call. When the chip's supplicant is off, the host
 * (wpa_supplicant) runs the 4-way. The driver hands chip-
 * delivered EAPOL frames here. We wrap them in a fake 802.3
 * header (dst=our_mac, src=ap_mac, type=0x888e) and feed them
 * via ieee80211_input_all so the wlan(4) bpf / mgmt path
 * routes them to userspace.
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
	 * Bench 2026-06-30: ieee80211_input_all wants 802.11+radiotap
	 * frames and silently DROPS our fake 802.3 EAPOL. wlan0 Ipkts
	 * stayed at 0 even though the chip delivered 3 M1 frames.
	 *
	 * Feed the wlan0 ifnet directly via its if_input callback.
	 * BPF subscribers (wpa_supplicant uses AF_PACKET-equivalent)
	 * see the frame and can drive the 4-way handshake.
	 */
	/*
	 * NET_EPOCH wrapping is needed for if_input on FreeBSD 15.
	 * ieee80211_vap_deliver_data is the standard net80211 helper
	 * (see ieee80211_freebsd.c:1252). It does NET_EPOCH_ENTER +
	 * if_input + NET_EPOCH_EXIT. Calling raw if_input from a
	 * driver callback without epoch leaves wlan0's input chain
	 * unable to deliver, and Ipkts stays at zero.
	 */
	/*
	 * Tap BPF once and drop the mbuf. wpa_supplicant's driver_bsd
	 * reads EAPOL frames from a BPF socket bound to ethertype
	 * 0x888e. That is the only consumer. Do NOT also call
	 * ieee80211_vap_deliver_data. That walks the frame through
	 * ether_input, which fires BPF a second time, so
	 * wpa_supplicant sees every EAPOL frame twice. Symptom of
	 * the duplicate: on each M1, wpa_supplicant sends two M2s.
	 * The AP receives one about 1 s late and gives up on the
	 * 4-way in about 4 s, so dhclient times out on DHCPDISCOVER.
	 */
	{
		struct bpf_if *ifbpf = if_getbpf(vap->iv_ifp);
		if (ifbpf != NULL && bpf_peers_present(ifbpf))
			bpf_mtap(ifbpf, m);
	}
	m_freem(m);
}

/*
 * Scan-result up-call. The draft API takes a structured
 * description. The brcm migration today still uses its own
 * fake-beacon path because the scan path is harder to change
 * than the state-machine paths. Stub the API for now. Once a
 * second driver wants it, fill in the synthesis here.
 */
void
ieee80211_fmac_scan_result(struct ieee80211com *ic __unused,
    const struct ieee80211_fmac_bss *bb __unused)
{
}

void
ieee80211_fmac_scan_done(struct ieee80211com *ic)
{
	if (ic->ic_scan != NULL && ic->ic_scan->ss_vap != NULL)
		ieee80211_scan_done(ic->ic_scan->ss_vap);
}
