/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * net80211 FullMAC adaptation layer.  See ieee80211_fullmac.h for the
 * interface a driver sees.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/callout.h>
#include <sys/endian.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/if_media.h>
#include <net/route.h>
#include <net/vnet.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_input.h>
#include <net80211/ieee80211_proto.h>
#include <net80211/ieee80211_regdomain.h>

#include <net80211/ieee80211_fullmac.h>

static MALLOC_DEFINE(M_80211_FMAC, "80211_fmac",
    "net80211 FullMAC framework");

/* What fs_ap_task should do with the firmware's BSS next. */
#define	FMAC_AP_NONE		0
#define	FMAC_AP_START		1
#define	FMAC_AP_STOP		2

/* One station event waiting for fs_ap_task. */
struct fmac_ap_evt {
	STAILQ_ENTRY(fmac_ap_evt)	fe_link;
	int				fe_type;	/* FMAC_EVT_* */
	uint8_t				fe_mac[IEEE80211_ADDR_LEN];
	uint16_t			fe_reason;
	size_t				fe_ielen;
	uint8_t				fe_ies[];	/* JOIN: request IEs */
};
#define	FMAC_EVT_JOIN		1
#define	FMAC_EVT_REJOIN		2
#define	FMAC_EVT_LEAVE		3
#define	FMAC_EVT_DEAUTH		4	/* net80211 -> fmop_sta_deauth */

/* Bound on queued station events; a stuck task must not eat memory. */
#define	FMAC_AP_MAXEVTS		256
#define	FMAC_SCAN_TIMEOUT_MS	15000	/* longest firmware scan we wait for */
#define	FMAC_SCAN_RETRY_MS	1000	/* end a scan the firmware refused */
static const struct timeval fmac_scan_fail_iv = { 5, 0 };

/*
 * Management frame protection (802.11w) needs a BIP-CMAC-128 cipher
 * in net80211 for wpa_supplicant and hostapd to install the IGTK, and
 * FreeBSD ships none (ieee80211_crypto_newkey tries to load
 * wlan_bip_cmac and fails, "Failed to configure IGTK").  On a FullMAC
 * chip the firmware signs and checks protected management frames
 * itself, so net80211's side only has to allocate the key and pass it
 * to the driver through iv_key_set; nothing here touches a frame.
 * The framework registers this stub when the driver advertises
 * IEEE80211_CRYPTO_BIP_CMAC_128 and no BIP cipher is registered yet.
 */
static void *
fmac_bip_attach(struct ieee80211vap *vap __unused,
    struct ieee80211_key *k __unused)
{
	/* No state; a non-NULL token marks the key as allocated. */
	return (__DECONST(void *, &fmac_bip_attach));
}

static void
fmac_bip_detach(struct ieee80211_key *k __unused)
{
}

static int
fmac_bip_setkey(struct ieee80211_key *k __unused)
{
	return (1);
}

static void
fmac_bip_setiv(struct ieee80211_key *k __unused, uint8_t *ivp __unused)
{
}

static int
fmac_bip_encap(struct ieee80211_key *k __unused, struct mbuf *m __unused)
{
	return (1);
}

static int
fmac_bip_decap(struct ieee80211_key *k __unused, struct mbuf *m __unused,
    int hdrlen __unused)
{
	return (1);
}

static int
fmac_bip_enmic(struct ieee80211_key *k __unused, struct mbuf *m __unused,
    int force __unused)
{
	return (1);
}

static int
fmac_bip_demic(struct ieee80211_key *k __unused, struct mbuf *m __unused,
    int force __unused)
{
	return (1);
}

static const struct ieee80211_cipher fmac_bip_cipher = {
	.ic_name	= "AES-128-CMAC",
	.ic_cipher	= IEEE80211_CIPHER_BIP_CMAC_128,
	.ic_header	= 0,
	.ic_trailer	= 0,
	.ic_miclen	= 0,
	.ic_attach	= fmac_bip_attach,
	.ic_detach	= fmac_bip_detach,
	.ic_setkey	= fmac_bip_setkey,
	.ic_setiv	= fmac_bip_setiv,
	.ic_encap	= fmac_bip_encap,
	.ic_decap	= fmac_bip_decap,
	.ic_enmic	= fmac_bip_enmic,
	.ic_demic	= fmac_bip_demic,
};

/* Each vap's saved net80211 hooks, on a global list under fmac_mtx. */
struct fmac_vap {
	LIST_ENTRY(fmac_vap)	fv_link;
	struct ieee80211vap	*fv_vap;
	int	(*fv_newstate)(struct ieee80211vap *, enum ieee80211_state,
		    int);
	int	(*fv_key_set)(struct ieee80211vap *,
		    const struct ieee80211_key *);
	int	(*fv_key_delete)(struct ieee80211vap *,
		    const struct ieee80211_key *);
	int	(*fv_reset)(struct ieee80211vap *, u_long);
	bool	fv_ioctl;		/* if_ioctl replaced */
};

/*
 * Per-com framework state.  Tracked in a global list rather than a
 * direct ic-slot pointer; see the file banner for why.
 */
struct fmac_left_bss {
	struct ieee80211_fmac_bss	fl_bss;
	uint8_t				fl_ies[];
};

struct fmac_state {
	struct ieee80211com		   *fs_ic;	/* the net80211 device */
	const struct ieee80211_fullmac_ops *fs_ops;	/* driver callbacks */

	void	(*fs_save_scan_start)(struct ieee80211com *);
	void	(*fs_save_scan_end)(struct ieee80211com *);
	void	(*fs_save_scan_curchan)(struct ieee80211_scan_state *,
		    unsigned long);
	void	(*fs_save_scan_mindwell)(struct ieee80211_scan_state *);
	int	(*fs_save_setregdomain)(struct ieee80211com *,
		    struct ieee80211_regdomain *, int,
		    struct ieee80211_channel []);
	struct ieee80211vap *(*fs_save_vap_create)(struct ieee80211com *,
		    const char [IFNAMSIZ], int, enum ieee80211_opmode, int,
		    const uint8_t [IEEE80211_ADDR_LEN],
		    const uint8_t [IEEE80211_ADDR_LEN]);
	void	(*fs_save_vap_delete)(struct ieee80211vap *);

	/*
	 * fs_vap_going: a vap being deleted.  fs_dying: framework detaching.
	 * Both under fs_ap_mtx.
	 */
	struct ieee80211vap		   *fs_vap_going;
	bool				    fs_dying;

	/*
	 * Country change.  net80211 calls ic_setregdomain with the com
	 * lock held, and fmop_set_country sleeps in a firmware command,
	 * so the shim records the code here and fs_country_task applies
	 * it.  fs_country is written and read under the com lock.
	 */
	struct task			    fs_country_task;
	char				    fs_country[3];

	/*
	 * A firmware scan started by fmac_scan_start_shim is still
	 * running: set when fmop_scan_start succeeds, cleared when the
	 * driver reports ieee80211_fmac_scan_done or the scan is
	 * cancelled.  fmac_scan_end_shim cancels only a running scan.
	 */
	volatile bool			    fs_scan_active;
	/* the firmware refused net80211's scan; fs_scan_timeout ends it */
	volatile bool			    fs_scan_retry;
	struct timeval			    fs_scan_fail_log;
	/* ends a firmware scan whose completion never arrives */
	struct timeout_task		    fs_scan_timeout;

	/*
	 * ieee80211_fmac_roamed is moving a station vap to a new BSS:
	 * ieee80211_sta_join has installed the new node and queued the
	 * RUN -> AUTH step net80211 uses to rejoin, which fmac_newstate
	 * turns into a reassociation report instead, then clears this.
	 */
	volatile bool			    fs_roaming;

	/* fmac_bip_cipher is ours to unregister at detach. */
	bool				    fs_bip_registered;

	/*
	 * Link signal, polled through fmop_get_signal while a station
	 * vap is in RUN.  net80211 reads it from its node getters, which
	 * can run with node locks held, so they return the cached values
	 * instead of asking the firmware.
	 */
	struct callout			    fs_sig_callout;
	struct task			    fs_sig_task;
	volatile int			    fs_sig_rssi;	/* dBm */
	volatile int			    fs_sig_noise;	/* dBm */
	volatile bool			    fs_sig_valid;
	int8_t	(*fs_save_getrssi)(const struct ieee80211_node *);
	void	(*fs_save_getsignal)(const struct ieee80211_node *,
		    int8_t *, int8_t *);

	/*
	 * Access point.  fmac_newstate runs with the com lock held and
	 * the driver's AP ops sleep, so it records what it wants in
	 * fs_ap_want (with the BSS to start in fs_ap_conf) and
	 * fs_ap_task carries it out.  Station joins and leaves from the
	 * driver, and deauthentications net80211 sends, queue on
	 * fs_ap_evts for the same task, which keeps them in order behind
	 * the start or stop.  fs_ap_mtx is a leaf lock covering these.
	 */
	struct mtx			    fs_ap_mtx;
	struct task			    fs_ap_task;
	/*
	 * Security of the BSS the firmware runs (or will after a queued
	 * start), to notice hostapd's WPA/RSN element arriving after the
	 * vap reached RUN.  fs_ap_sec_valid is false while no AP runs.
	 */
	bool				    fs_ap_sec_valid;
	uint8_t				    fs_ap_sec_wpa;
	uint32_t			    fs_ap_sec_ucast, fs_ap_sec_mcast;
	uint32_t			    fs_ap_sec_akms;
	uint16_t			    fs_ap_sec_rsncaps;
	/* Station aging from fmop_sta_idle, while our AP runs. */
	struct callout			    fs_age_callout;
	struct task			    fs_age_task;
	int				    fs_ap_want;
	struct ieee80211_fmac_ap	    fs_ap_conf;
	STAILQ_HEAD(, fmac_ap_evt)	    fs_ap_evts;
	u_int				    fs_ap_nevts;
	int	(*fs_save_raw_xmit)(struct ieee80211_node *, struct mbuf *,
		    const struct ieee80211_bpf_params *);

	/*
	 * wpa_supplicant's PMKSA list for fmop_set_pmksa, oldest first.
	 * Changed only by IEEE80211_IOC_PMKSA, whose callers fs_pmksa_sx
	 * serializes so the firmware sees each change in order.
	 */
	struct sx			    fs_pmksa_sx;
	struct ieee80211_fmac_pmksa	    fs_pmksa[IEEE80211_FMAC_MAX_PMKSA];
	int				    fs_npmksa;

	/*
	 * The BSS a station vap just left.  Entering INIT flushes net80211's
	 * scan cache, so wpa_supplicant reassociating without a new scan
	 * would find nothing (IEEE80211_IOC_MLME fails with ENOENT) and wait
	 * out its timeout; fs_left_task puts the BSS back after the flush.
	 */
	struct task			    fs_left_task;
	struct fmac_left_bss		   *volatile fs_left;

	/* our last association request's elements, under the com lock */
	uint8_t				    fs_assoc_ie[IEEE80211_FMAC_ASSOC_IE_MAX];
	size_t				    fs_assoc_ielen;

	/*
	 * Outstanding-lookup refcount.  fmac_lookup bumps fs_refs before
	 * returning, so a concurrent ieee80211_fmac_detach can't free the
	 * struct out from under the caller.  Callers must pair every
	 * non-NULL lookup with fmac_release(fs).  Detach unlinks it
	 * (blocking new lookups) then waits for fs_refs to hit 0.
	 */
	u_int				    fs_refs;

#ifndef IEEE80211_FMAC_INTREE
	LIST_ENTRY(fmac_state)		    fs_link;	/* list linkage */
#endif
};

/*
 * fmac_mtx guards finding the state and its reference count.  It is
 * initialized via MTX_SYSINIT so that two drivers attaching in
 * parallel can't race a lazy mtx_init and initialize it twice.
 */
static struct mtx			fmac_mtx;
MTX_SYSINIT(fmac_mtx, &fmac_mtx, "80211_fmac", MTX_DEF);

/* Every vap the framework has rewired, under fmac_mtx. */
static LIST_HEAD(, fmac_vap)		fmac_vaps =
    LIST_HEAD_INITIALIZER(fmac_vaps);

static struct fmac_vap *
fmac_vap_find_locked(struct ieee80211vap *vap)
{
	struct fmac_vap *fv;

	mtx_assert(&fmac_mtx, MA_OWNED);
	LIST_FOREACH(fv, &fmac_vaps, fv_link)
		if (fv->fv_vap == vap)
			return (fv);
	return (NULL);
}

static int	fmac_newstate(struct ieee80211vap *,
		    enum ieee80211_state, int);
static int	fmac_reset(struct ieee80211vap *, u_long);
static int	fmac_key_set(struct ieee80211vap *,
		    const struct ieee80211_key *);
static int	fmac_key_delete(struct ieee80211vap *,
		    const struct ieee80211_key *);

/*
 * A copy of the vap's saved hooks.  Once detach has put the originals
 * back on the vap, a shim already running gets those instead.
 */
static void
fmac_vap_hooks(struct ieee80211vap *vap, struct fmac_vap *out)
{
	struct fmac_vap *fv;

	mtx_lock(&fmac_mtx);
	fv = fmac_vap_find_locked(vap);
	if (fv != NULL) {
		*out = *fv;
	} else {
		memset(out, 0, sizeof(*out));
		if (vap->iv_newstate != fmac_newstate)
			out->fv_newstate = vap->iv_newstate;
		if (vap->iv_key_set != fmac_key_set)
			out->fv_key_set = vap->iv_key_set;
		if (vap->iv_key_delete != fmac_key_delete)
			out->fv_key_delete = vap->iv_key_delete;
		if (vap->iv_reset != fmac_reset)
			out->fv_reset = vap->iv_reset;
	}
	mtx_unlock(&fmac_mtx);
}

/* Restore the saved hooks on every vap of ic.  Called from detach. */
static void
fmac_vap_restore_all(struct ieee80211com *ic)
{
	struct fmac_vap *fv, *tmp;
	struct ieee80211vap *vap;

	mtx_lock(&fmac_mtx);
	LIST_FOREACH_SAFE(fv, &fmac_vaps, fv_link, tmp) {
		vap = fv->fv_vap;
		if (vap->iv_ic != ic)
			continue;
		vap->iv_newstate = fv->fv_newstate;
		vap->iv_key_set = fv->fv_key_set;
		vap->iv_key_delete = fv->fv_key_delete;
		vap->iv_reset = fv->fv_reset;
		if (fv->fv_ioctl)
			if_setioctlfn(vap->iv_ifp, ieee80211_ioctl);
		LIST_REMOVE(fv, fv_link);
		free(fv, M_80211_FMAC);
	}
	mtx_unlock(&fmac_mtx);
}

/* Forget a vap that has been deleted. */
static void
fmac_vap_forget(struct ieee80211vap *vap)
{
	struct fmac_vap *fv;

	mtx_lock(&fmac_mtx);
	fv = fmac_vap_find_locked(vap);
	if (fv != NULL)
		LIST_REMOVE(fv, fv_link);
	mtx_unlock(&fmac_mtx);
	free(fv, M_80211_FMAC);
}

#ifdef IEEE80211_FMAC_INTREE
/* The state hangs off the device's ic_fmac. */
static struct fmac_state *
fmac_find_locked(struct ieee80211com *ic)
{
	return (ic->ic_fmac);
}

static void
fmac_link_locked(struct fmac_state *fs)
{
	fs->fs_ic->ic_fmac = fs;
}

static void
fmac_unlink_locked(struct fmac_state *fs)
{
	fs->fs_ic->ic_fmac = NULL;
}
#else
/*
 * Built into a driver module against a kernel without the framework,
 * where ieee80211com has no slot for it: keep a list instead.
 */
static LIST_HEAD(fmac_list_head, fmac_state) fmac_list =
    LIST_HEAD_INITIALIZER(fmac_list);

static struct fmac_state *
fmac_find_locked(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	LIST_FOREACH(fs, &fmac_list, fs_link) {
		if (fs->fs_ic == ic)
			break;
	}
	return (fs);
}

static void
fmac_link_locked(struct fmac_state *fs)
{
	LIST_INSERT_HEAD(&fmac_list, fs, fs_link);
}

static void
fmac_unlink_locked(struct fmac_state *fs)
{
	LIST_REMOVE(fs, fs_link);
}
#endif

/*
 * Look up the fmac_state for `ic`.  On success bumps fs_refs so the
 * struct can't be freed while the caller works with it.  The caller
 * MUST pair a non-NULL return with fmac_release(fs).
 */
static struct fmac_state *
fmac_lookup(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	mtx_lock(&fmac_mtx);
	fs = fmac_find_locked(ic);
	if (fs != NULL)
		fs->fs_refs++;
	mtx_unlock(&fmac_mtx);
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
	mtx_lock(&fmac_mtx);
	KASSERT(fs->fs_refs > 0,
	    ("fmac_release: fs_refs already 0"));
	if (--fs->fs_refs == 0)
		wakeup(fs);
	mtx_unlock(&fmac_mtx);
}

static int	fmac_vap_ioctl(if_t, u_long, caddr_t);
static void	fmac_scan_add(struct ieee80211com *,
		    const struct ieee80211_fmac_bss *, bool);
static void	fmac_note_left(struct fmac_state *, struct ieee80211vap *);
static void	fmac_left_task(void *, int);
static int	fmac_setregdomain(struct ieee80211com *,
		    struct ieee80211_regdomain *, int,
		    struct ieee80211_channel []);
static void	fmac_country_task(void *, int);
static void fmac_vap_delete(struct ieee80211vap *);
static struct ieee80211vap *fmac_vap_create(struct ieee80211com *,
		    const char [IFNAMSIZ], int, enum ieee80211_opmode, int,
		    const uint8_t [IEEE80211_ADDR_LEN],
		    const uint8_t [IEEE80211_ADDR_LEN]);
static int	fmac_pmk_sysctl(SYSCTL_HANDLER_ARGS);
static void	fmac_sig_callout(void *);
static void	fmac_sig_task(void *, int);
static int8_t	fmac_node_getrssi(const struct ieee80211_node *);
static void	fmac_node_getsignal(const struct ieee80211_node *, int8_t *,
		    int8_t *);

/* ------------------------------------------------------------------
 * Attach / detach
 * ------------------------------------------------------------------ */

static void	fmac_scan_start_shim(struct ieee80211com *);
static void	fmac_scan_end_shim(struct ieee80211com *);
static void	fmac_scan_curchan(struct ieee80211_scan_state *,
		    unsigned long);
static void	fmac_scan_mindwell(struct ieee80211_scan_state *);
static void	fmac_scan_timeout(void *, int);
static void	fmac_ap_task(void *, int);
static void	fmac_age_task(void *, int);
static void	fmac_ap_sec_save(struct fmac_state *,
		    const struct ieee80211_fmac_ap *);
static void	fmac_ap_sec_check(struct fmac_state *, struct ieee80211vap *);
static void	fmac_age_callout(void *);
static void	fmac_ap_snapshot(struct ieee80211vap *,
		    struct ieee80211_fmac_ap *);
static int	fmac_raw_xmit(struct ieee80211_node *, struct mbuf *,
		    const struct ieee80211_bpf_params *);
static void	fmac_ap_queue(struct fmac_state *, int,
		    const uint8_t [IEEE80211_ADDR_LEN], uint16_t,
		    const uint8_t *, size_t);

/* start the FullMAC framework for this device */
int
ieee80211_fmac_attach(struct ieee80211com *ic,
    const struct ieee80211_fullmac_ops *ops)
{
	struct fmac_state *fs;

	if (ic == NULL || ops == NULL || ops->fmop_name == NULL)
		return (EINVAL);
	if (ops->fmop_scan_start == NULL || ops->fmop_assoc == NULL ||
	    ops->fmop_disassoc == NULL || ops->fmop_set_key == NULL) {
		ic_printf(ic, "%s: FullMAC attach refused: scan_start, assoc, "
		    "disassoc and set_key are all required\n", ops->fmop_name);
		return (EINVAL);
	}
	if ((ops->fmop_mgmt_tx == NULL) != (ops->fmop_extauth_status == NULL)) {
		ic_printf(ic, "%s: FullMAC attach refused: external SAE needs "
		    "both mgmt_tx and extauth_status\n", ops->fmop_name);
		return (EINVAL);
	}
	if (ic->ic_vap_create == NULL) {
		ic_printf(ic, "%s: FullMAC attach refused: set ic_vap_create "
		    "before calling ieee80211_fmac_attach\n", ops->fmop_name);
		return (EINVAL);
	}

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

	/*
	 * Save and rewire ic-level scan dispatch.  Drivers therefore
	 * never need to set ic->ic_scan_start / ic_scan_end themselves;
	 * fmop_scan_start owns the chip-side dispatch.
	 */
	/* a reattach finds our shims still installed; never chain to them */
	if (ic->ic_scan_start != fmac_scan_start_shim)
		fs->fs_save_scan_start = ic->ic_scan_start;
	if (ic->ic_scan_end != fmac_scan_end_shim)
		fs->fs_save_scan_end = ic->ic_scan_end;
	ic->ic_scan_start = fmac_scan_start_shim;
	ic->ic_scan_end   = fmac_scan_end_shim;
	/* the firmware walks the channels, so net80211 must not time them */
	fs->fs_save_scan_curchan  = ic->ic_scan_curchan;
	fs->fs_save_scan_mindwell = ic->ic_scan_mindwell;
	ic->ic_scan_curchan  = fmac_scan_curchan;
	ic->ic_scan_mindwell = fmac_scan_mindwell;
	TIMEOUT_TASK_INIT(taskqueue_thread, &fs->fs_scan_timeout, 0,
	    fmac_scan_timeout, fs);

	/* Every vap the driver creates is set up here as well. */
	fs->fs_save_vap_create = ic->ic_vap_create;
	ic->ic_vap_create = fmac_vap_create;
	fs->fs_save_vap_delete = ic->ic_vap_delete;
	ic->ic_vap_delete = fmac_vap_delete;

	/* Regulatory: country changes reach the firmware through the op. */
	TASK_INIT(&fs->fs_country_task, 0, fmac_country_task, fs);
	if (ops->fmop_set_country != NULL) {
		fs->fs_save_setregdomain = ic->ic_setregdomain;
		ic->ic_setregdomain = fmac_setregdomain;
	}

	/*
	 * Power save: advertise it only when the driver can do it, so
	 * `ifconfig powersave` fails cleanly on chips without the op.
	 * Vaps copy ic_caps when they are created, which is after this.
	 */
	if (ops->fmop_set_powersave != NULL)
		ic->ic_caps |= IEEE80211_C_PMGT;

	/* Signal: poll the firmware while linked, answer from a cache. */
	callout_init(&fs->fs_sig_callout, 1);
	TASK_INIT(&fs->fs_sig_task, 0, fmac_sig_task, fs);
	if (ops->fmop_get_signal != NULL) {
		fs->fs_save_getrssi = ic->ic_node_getrssi;
		fs->fs_save_getsignal = ic->ic_node_getsignal;
		ic->ic_node_getrssi = fmac_node_getrssi;
		ic->ic_node_getsignal = fmac_node_getsignal;
	}

	/*
	 * Access point.  net80211 checks ic_caps when a hostap vap is
	 * cloned, so setting the bit after ieee80211_ifattach is enough.
	 * Deauthentications go out as raw management frames, which a
	 * FullMAC chip cannot send, so watch ic_raw_xmit for them.
	 */
	mtx_init(&fs->fs_ap_mtx, "80211_fmac_ap", NULL, MTX_DEF);
	sx_init(&fs->fs_pmksa_sx, "80211_fmac_pmksa");
	TASK_INIT(&fs->fs_left_task, 0, fmac_left_task, fs);
	TASK_INIT(&fs->fs_ap_task, 0, fmac_ap_task, fs);
	callout_init(&fs->fs_age_callout, 1);
	TASK_INIT(&fs->fs_age_task, 0, fmac_age_task, fs);
	STAILQ_INIT(&fs->fs_ap_evts);
	if ((ic->ic_cryptocaps & IEEE80211_CRYPTO_BIP_CMAC_128) != 0 &&
	    !ieee80211_crypto_available(IEEE80211_CIPHER_BIP_CMAC_128)) {
		ieee80211_crypto_register(&fmac_bip_cipher);
		fs->fs_bip_registered = true;
	}
	if (ops->fmop_start_ap != NULL && ops->fmop_stop_ap != NULL) {
		ic->ic_caps |= IEEE80211_C_HOSTAP;
		fs->fs_save_raw_xmit = ic->ic_raw_xmit;
		ic->ic_raw_xmit = fmac_raw_xmit;
	}

	mtx_lock(&fmac_mtx);
	fmac_link_locked(fs);
	mtx_unlock(&fmac_mtx);
	return (0);
}

/* stop the framework for this device */
void
ieee80211_fmac_detach(struct ieee80211com *ic)
{
	struct fmac_state *fs;

	/*
	 * Locate and remove atomically, then wait for outstanding
	 * lookups to drop their refs before freeing.  Once fs is
	 * unlinked no new lookup can find it, so fs_refs only
	 * decreases.  This keeps detach correct regardless of the
	 * caller's ordering relative to ieee80211_ifdetach.
	 */
	mtx_lock(&fmac_mtx);
	fs = fmac_find_locked(ic);
	if (fs == NULL) {
		mtx_unlock(&fmac_mtx);
		return;
	}
	fmac_unlink_locked(fs);
	/*
	 * Wait for outstanding lookups to drop their references.  The
	 * caller frees ic once this returns, so leaking fs and leaving
	 * the shims in place would only move the crash; keep waiting and
	 * say so every 30 s.
	 */
	{
		int wi = 0;

		while (fs->fs_refs != 0) {
			(void)mtx_sleep(fs, &fmac_mtx, 0, "fmacdet", hz);
			if (++wi % 30 == 0)
				printf("ieee80211_fmac_detach: still waiting "
				    "for %u reference(s) on %p\n",
				    fs->fs_refs, ic);
		}
	}
	mtx_unlock(&fmac_mtx);

	/*
	 * Restore saved ic slots and every vap's hooks.  Safe outside
	 * fmac_mtx because every reader that could have raced us just
	 * released its ref, and the vap shims fall back to the saved
	 * hooks once fs is unlinked.
	 */
	mtx_lock(&fs->fs_ap_mtx);
	fs->fs_dying = true;
	mtx_unlock(&fs->fs_ap_mtx);
	fmac_vap_restore_all(ic);
	/* net80211 calls these until ifdetach; the shims cope without fs */
	if (fs->fs_save_scan_start != NULL)
		ic->ic_scan_start = fs->fs_save_scan_start;
	if (fs->fs_save_scan_end != NULL)
		ic->ic_scan_end = fs->fs_save_scan_end;
	ic->ic_scan_curchan  = fs->fs_save_scan_curchan;
	ic->ic_scan_mindwell = fs->fs_save_scan_mindwell;
	taskqueue_drain_timeout(taskqueue_thread, &fs->fs_scan_timeout);
	ic->ic_vap_create = fs->fs_save_vap_create;
	ic->ic_vap_delete = fs->fs_save_vap_delete;
	if (fs->fs_ops->fmop_set_country != NULL)
		ic->ic_setregdomain = fs->fs_save_setregdomain;
	taskqueue_drain(taskqueue_thread, &fs->fs_country_task);
	fs->fs_sig_valid = false;
	callout_drain(&fs->fs_sig_callout);
	taskqueue_drain(taskqueue_thread, &fs->fs_sig_task);
	callout_drain(&fs->fs_sig_callout);
	if (fs->fs_ops->fmop_get_signal != NULL) {
		ic->ic_node_getrssi = fs->fs_save_getrssi;
		ic->ic_node_getsignal = fs->fs_save_getsignal;
	}
	if (fs->fs_save_raw_xmit != NULL)
		ic->ic_raw_xmit = fs->fs_save_raw_xmit;
	/*
	 * The AP task can start the age callout, so drain it first;
	 * fs_dying keeps both from re-arming the callout.
	 */
	taskqueue_drain(taskqueue_thread, &fs->fs_ap_task);
	callout_drain(&fs->fs_age_callout);
	taskqueue_drain(taskqueue_thread, &fs->fs_age_task);
	callout_drain(&fs->fs_age_callout);
	{
		struct fmac_ap_evt *fe;

		while ((fe = STAILQ_FIRST(&fs->fs_ap_evts)) != NULL) {
			STAILQ_REMOVE_HEAD(&fs->fs_ap_evts, fe_link);
			free(fe, M_80211_FMAC);
		}
	}
	ieee80211_draintask(ic, &fs->fs_left_task);
	free(__DEVOLATILE(void *, fs->fs_left), M_80211_FMAC);
	mtx_destroy(&fs->fs_ap_mtx);
	sx_destroy(&fs->fs_pmksa_sx);
	/*
	 * Another FullMAC device that found the stub registered and
	 * skipped its own loses BIP here, until it attaches again.
	 */
	if (fs->fs_bip_registered)
		ieee80211_crypto_unregister(&fmac_bip_cipher);

	free(fs, M_80211_FMAC);
}

/*
 * ic_vap_create wrapper.  The driver's own vap_create builds the vap
 * (ieee80211_vap_setup through ieee80211_vap_attach); the framework
 * then rewires its entry points onto the shims and sets what every
 * FullMAC vap needs, so drivers never touch these themselves:
 *
 *   - iv_newstate, iv_key_set, iv_key_delete and iv_reset go through
 *     the framework;
 *   - net80211's software beacon-miss timer is off: no beacons reach
 *     net80211, so it would fire about a second after RUN and, with
 *     auto roaming, reassociate and drop the link.  The firmware
 *     watches the BSS and reports link loss instead;
 *   - roaming is the device's (IEEE80211_ROAMING_DEVICE), and so is
 *     scanning (IEEE80211_FEXT_SCAN_OFFLOAD): net80211's scanner sends
 *     no probe requests and no power-save frames of its own;
 *   - a scan asked for through the ioctl always reaches the firmware
 *     (fmac_vap_ioctl), as with Linux;
 *   - net.wlan.N.fullmac_pmk exists when the driver can take a PMK.
 */
/*
 * ic_vap_delete wrapper: drain the AP and age tasks before the
 * driver deletes the vap.
 */
static void
fmac_vap_delete(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	void (*del)(struct ieee80211vap *);

	if (fs == NULL) {
		/* Not reached: detach puts ic_vap_delete back first. */
		fmac_vap_forget(vap);
		return;
	}
	del = fs->fs_save_vap_delete;
	mtx_lock(&fs->fs_ap_mtx);
	fs->fs_vap_going = vap;
	mtx_unlock(&fs->fs_ap_mtx);
	taskqueue_drain(taskqueue_thread, &fs->fs_ap_task);
	callout_drain(&fs->fs_age_callout);
	taskqueue_drain(taskqueue_thread, &fs->fs_age_task);
	callout_drain(&fs->fs_age_callout);
	fmac_release(fs);

	del(vap);
	fmac_vap_forget(vap);

	if ((fs = fmac_lookup(ic)) != NULL) {
		mtx_lock(&fs->fs_ap_mtx);
		if (fs->fs_vap_going == vap)
			fs->fs_vap_going = NULL;
		mtx_unlock(&fs->fs_ap_mtx);
		fmac_release(fs);
	}
}

static struct ieee80211vap *
fmac_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211vap *vap;
	struct fmac_vap *fv;

	if (fs == NULL)
		return (NULL);
	vap = fs->fs_save_vap_create(ic, name, unit, opmode, flags, bssid,
	    mac);
	if (vap == NULL) {
		fmac_release(fs);
		return (NULL);
	}

	fv = malloc(sizeof(*fv), M_80211_FMAC, M_WAITOK | M_ZERO);
	fv->fv_vap = vap;
	fv->fv_newstate = vap->iv_newstate;
	fv->fv_key_set = vap->iv_key_set;
	fv->fv_key_delete = vap->iv_key_delete;
	fv->fv_reset = vap->iv_reset;
	fv->fv_ioctl = (opmode == IEEE80211_M_STA);
	mtx_lock(&fmac_mtx);
	LIST_INSERT_HEAD(&fmac_vaps, fv, fv_link);
	mtx_unlock(&fmac_mtx);
	vap->iv_newstate   = fmac_newstate;
	vap->iv_key_set    = fmac_key_set;
	vap->iv_key_delete = fmac_key_delete;
	vap->iv_reset      = fmac_reset;

	vap->iv_flags_ext &= ~IEEE80211_FEXT_SWBMISS;
	vap->iv_flags_ext |= IEEE80211_FEXT_SCAN_OFFLOAD;
	vap->iv_roaming = IEEE80211_ROAMING_DEVICE;

	/* SAE and PMKSA requests (fmac_vap_ioctl); others go to net80211. */
	if (opmode == IEEE80211_M_STA)
		if_setioctlfn(vap->iv_ifp, fmac_vap_ioctl);

	/*
	 * An access point's data never passes through ieee80211_input,
	 * so net80211 would see every station as idle and age it out of
	 * the station table after a few minutes, cutting off its
	 * traffic.  With fmop_sta_idle the framework keeps each station's
	 * net80211 idle counter in step with the firmware's (fmac_age_task)
	 * and net80211's aging stays on; without it aging is off and only
	 * the firmware's own reports remove stations.
	 */
	if (opmode == IEEE80211_M_HOSTAP && fs->fs_ops->fmop_sta_idle == NULL)
		vap->iv_flags_ext &= ~IEEE80211_FEXT_INACT;

	if (fs->fs_ops->fmop_set_pmk != NULL && vap->iv_sysctl != NULL &&
	    vap->iv_oid != NULL)
		SYSCTL_ADD_PROC(vap->iv_sysctl, SYSCTL_CHILDREN(vap->iv_oid),
		    OID_AUTO, "fullmac_pmk",
		    CTLTYPE_STRING | CTLFLAG_WR | CTLFLAG_MPSAFE, vap, 0,
		    fmac_pmk_sysctl, "A",
		    "PMK for the chip's own supplicant, write-only: 64 hex "
		    "digits as printed by wpa_passphrase(8); empty clears");

	fmac_release(fs);
	return (vap);
}

/*
 * net.wlan.N.fullmac_pmk: take a PMK for the chip's own supplicant.
 * It is never readable back, and every copy is zeroed after use.
 */
static int
fmac_pmk_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct ieee80211vap *vap = arg1;
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs;
	char buf[80];
	uint8_t pmk[32];
	size_t len;
	int error, i, hi, lo;

	memset(buf, 0, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		goto out;
	len = strnlen(buf, sizeof(buf));
	if (len != 0 && len != 2 * sizeof(pmk)) {
		error = EINVAL;
		goto out;
	}
	for (i = 0; i < (int)len / 2; i++) {
		hi = buf[2 * i];
		lo = buf[2 * i + 1];
#define	HEXVAL(c) ((c) >= '0' && (c) <= '9' ? (c) - '0' :		\
	    (c) >= 'a' && (c) <= 'f' ? (c) - 'a' + 10 :			\
	    (c) >= 'A' && (c) <= 'F' ? (c) - 'A' + 10 : -1)
		hi = HEXVAL(hi);
		lo = HEXVAL(lo);
#undef HEXVAL
		if (hi < 0 || lo < 0) {
			error = EINVAL;
			goto out;
		}
		pmk[i] = (uint8_t)(hi << 4 | lo);
	}
	fs = fmac_lookup(ic);
	if (fs == NULL) {
		error = ENXIO;
		goto out;
	}
	error = fs->fs_ops->fmop_set_pmk(ic, len == 0 ? NULL : pmk, len / 2);
	fmac_release(fs);
out:
	explicit_bzero(buf, sizeof(buf));
	explicit_bzero(pmk, sizeof(pmk));
	return (error);
}

/* ------------------------------------------------------------------
 * net80211 -> driver shims
 * ------------------------------------------------------------------ */

static int
fmac_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs;
	struct ieee80211_fmac_assoc fa;
	struct fmac_vap hooks;
	enum ieee80211_state ostate;
	int rc;

	fmac_vap_hooks(vap, &hooks);
	if (hooks.fv_newstate == NULL)
		return (EINVAL);
	fs = fmac_lookup(ic);
	if (fs == NULL)		/* detaching: plain net80211 */
		return (hooks.fv_newstate(vap, nstate, arg));

	/*
	 * The firmware has roamed and ieee80211_sta_join has put the new
	 * AP's node in iv_bss.  Its RUN -> AUTH step would report a lost
	 * link to wpa_supplicant (ieee80211_sta_leave) and send the
	 * firmware to join again; the firmware is already associated.
	 * Stay in RUN instead and report a reassociation, as net80211 does
	 * when it reassociates itself.  Returning an error makes net80211
	 * treat the step as not taken, so nothing else runs.
	 */
	if (fs->fs_roaming && vap->iv_opmode == IEEE80211_M_STA &&
	    vap->iv_state == IEEE80211_S_RUN && nstate == IEEE80211_S_AUTH &&
	    vap->iv_bss != NULL) {
		struct ieee80211_node *ni = vap->iv_bss;

		if (ni->ni_associd == 0) {
			ni->ni_associd = 0xc001;
			ni->ni_flags |= IEEE80211_NODE_ASSOCID;
		}
		/* WPA authorizes the port again after the new handshake. */
		if ((vap->iv_flags & IEEE80211_F_WPA) == 0)
			ieee80211_node_authorize(ni);
		ieee80211_notify_node_join(ni, 0);
		fs->fs_roaming = false;
		fmac_release(fs);
		return (EALREADY);
	}

	/*
	 * A station leaving its BSS for INIT, which flushes net80211's scan
	 * cache once this returns.  Keep the BSS and queue fmac_left_task,
	 * which runs on this taskqueue after the flush and puts it back.
	 */
	if (vap->iv_opmode == IEEE80211_M_STA && nstate == IEEE80211_S_INIT &&
	    vap->iv_state >= IEEE80211_S_AUTH) {
		fmac_note_left(fs, vap);
		if (fs->fs_left != NULL)
			ieee80211_runtask(ic, &fs->fs_left_task);
	}

	/*
	 * Access point: start the firmware's BSS on entering RUN and stop
	 * it on leaving.  A restart (an ENETRESET from a changed setting)
	 * walks through INIT, so it stops and starts with the new values.
	 * The station logic below does not apply.
	 */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		int want = FMAC_AP_NONE;

		ostate = vap->iv_state;
		rc = hooks.fv_newstate(vap, nstate, arg);
		if (fs->fs_ops->fmop_start_ap != NULL) {
			if (nstate == IEEE80211_S_RUN &&
			    ostate != IEEE80211_S_RUN && rc == 0)
				want = FMAC_AP_START;
			else if (nstate != IEEE80211_S_RUN &&
			    ostate == IEEE80211_S_RUN)
				want = FMAC_AP_STOP;
		}
		if (want != FMAC_AP_NONE) {
			/* the latest request wins; a pending start is dropped */
			mtx_lock(&fs->fs_ap_mtx);
			if (want == FMAC_AP_START) {
				fmac_ap_snapshot(vap, &fs->fs_ap_conf);
				fmac_ap_sec_save(fs, &fs->fs_ap_conf);
			} else
				fs->fs_ap_sec_valid = false;
			fs->fs_ap_want = want;
			mtx_unlock(&fs->fs_ap_mtx);
			taskqueue_enqueue(taskqueue_thread, &fs->fs_ap_task);
		}
		fmac_release(fs);
		return (rc);
	}

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
	case IEEE80211_S_SCAN:
		/* a lost link: keep the firmware from rejoining by itself */
		if (vap->iv_state >= IEEE80211_S_AUTH)
			(void)fs->fs_ops->fmop_disassoc(ic,
			    IEEE80211_REASON_AUTH_LEAVE);
		break;
	default:
		break;
	}
	ostate = vap->iv_state;
	rc = hooks.fv_newstate(vap, nstate, arg);
	/* net80211 rescans only for ROAMING_AUTO; a device-roaming STA rescans here */
	if (rc == 0 && vap->iv_opmode == IEEE80211_M_STA &&
	    nstate == IEEE80211_S_SCAN && ostate >= IEEE80211_S_AUTH &&
	    vap->iv_roaming == IEEE80211_ROAMING_DEVICE)
		ieee80211_check_scan_current(vap);
	fmac_release(fs);
	return (rc);
}

/*
 * Install a key into the chip.
 *
 * The two sides of this shim use opposite conventions, and mixing them
 * up is what kept WPA2 from ever completing.  The driver ops return an
 * errno -- 0 on success.  But
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
	struct fmac_vap hooks;
	int rc;

	if (fs == NULL) {
		fmac_vap_hooks(vap, &hooks);
		return (hooks.fv_key_set != NULL ?
		    hooks.fv_key_set(vap, key) : 0);
	}
	if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
	    (key->wk_flags & IEEE80211_KEY_GROUP) != 0)
		fmac_ap_sec_check(fs, vap);
	rc = fs->fs_ops->fmop_set_key(ic, key);
	fmac_release(fs);
	return (rc == 0);
}

/*
 * Remove a key from the chip; same conventions as fmac_key_set.  Without
 * fmop_del_key, net80211's own hook handles it.
 */
static int
fmac_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	struct fmac_vap hooks;
	int ok = 1;

	fmac_vap_hooks(vap, &hooks);
	if (fs == NULL)
		return (hooks.fv_key_delete != NULL ?
		    hooks.fv_key_delete(vap, key) : 1);
	if (fs->fs_ops->fmop_del_key != NULL)
		ok = fs->fs_ops->fmop_del_key(ic, key) == 0;
	else if (hooks.fv_key_delete != NULL)
		ok = hooks.fv_key_delete(vap, key);
	fmac_release(fs);
	return (ok);
}

/*
 * ic_setregdomain shim.  net80211 calls it with the com lock held and
 * every vap down, after the user picks a country or regdomain.  Let
 * the saved hook vet the request, then queue the firmware update:
 * fmop_set_country sleeps, which this context does not allow.  A
 * regdomain without a two-letter country (a bare "regdomain ETSI")
 * leaves the firmware's country alone.
 */
static int
fmac_setregdomain(struct ieee80211com *ic, struct ieee80211_regdomain *rd,
    int nchans, struct ieee80211_channel chans[])
{
	struct fmac_state *fs = fmac_lookup(ic);
	char a, b;
	int rc = 0;

	if (fs == NULL)
		return (0);
	if (fs->fs_save_setregdomain != NULL)
		rc = fs->fs_save_setregdomain(ic, rd, nchans, chans);
	a = rd->isocc[0];
	b = rd->isocc[1];
	if (a >= 'a' && a <= 'z')
		a -= 'a' - 'A';
	if (b >= 'a' && b <= 'z')
		b -= 'a' - 'A';
	if (rc == 0 && a >= 'A' && a <= 'Z' && b >= 'A' && b <= 'Z') {
		fs->fs_country[0] = a;
		fs->fs_country[1] = b;
		fs->fs_country[2] = '\0';
		taskqueue_enqueue(taskqueue_thread, &fs->fs_country_task);
	}
	fmac_release(fs);
	return (rc);
}

/* hand the country recorded by fmac_setregdomain to the firmware */
static void
fmac_country_task(void *arg, int pending __unused)
{
	struct fmac_state *fs = arg;
	struct ieee80211com *ic = fs->fs_ic;
	char cc[3];
	int rc;

	IEEE80211_LOCK(ic);
	memcpy(cc, fs->fs_country, sizeof(cc));
	IEEE80211_UNLOCK(ic);
	if (cc[0] == '\0')
		return;
	rc = fs->fs_ops->fmop_set_country(ic, cc);
	if (rc != 0)
		ic_printf(ic, "%s: firmware refused country %s (error %d)\n",
		    fs->fs_ops->fmop_name, cc, rc);
}

/*
 * iv_reset shim.  A setting net80211 cannot apply itself comes back
 * from the ioctl as ERESTART, and when the interface is up net80211
 * calls iv_reset; the default answer, ENETRESET, restarts the vap and
 * drops the link.  Power save is applied to the firmware in place
 * instead.  Anything else goes to the saved hook.  Called from the
 * ioctl path with no net80211 lock held, so the op may sleep.
 */
static int
fmac_reset(struct ieee80211vap *vap, u_long cmd)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	struct fmac_vap hooks;
	int rc;

	fmac_vap_hooks(vap, &hooks);
	if (fs == NULL)
		return (hooks.fv_reset != NULL ? hooks.fv_reset(vap, cmd) :
		    ENETRESET);
	if (cmd == IEEE80211_IOC_POWERSAVE &&
	    fs->fs_ops->fmop_set_powersave != NULL)
		rc = fs->fs_ops->fmop_set_powersave(ic,
		    (vap->iv_flags & IEEE80211_F_PMGTON) != 0);
	else if (hooks.fv_reset != NULL)
		rc = hooks.fv_reset(vap, cmd);
	else
		rc = ENETRESET;
	fmac_release(fs);
	return (rc);
}

/*
 * ic_scan_start / ic_scan_end shims.  Drivers don't set these
 * directly; the framework owns them.  fmop_scan_start receives a
 * single SSID at most (net80211's ic_scan_state may have more but
 * almost every FullMAC chip's scan engine takes one).  When the
 * driver returns ENXIO, fall back to the saved net80211 hook
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
	if (rc == 0) {
		fs->fs_scan_active = true;
		taskqueue_enqueue_timeout(taskqueue_thread,
		    &fs->fs_scan_timeout, MSEC_2_TICKS(FMAC_SCAN_TIMEOUT_MS));
	} else if (rc == ENXIO) {
		if (fs->fs_save_scan_start != NULL)
			fs->fs_save_scan_start(ic);
	} else {
		/* nothing will end net80211's scan; end it so it retries */
		if (ratecheck(&fs->fs_scan_fail_log, &fmac_scan_fail_iv))
			ic_printf(ic, "firmware refused a scan (%d), "
			    "retrying\n", rc);
		fs->fs_scan_retry = true;
		taskqueue_enqueue_timeout(taskqueue_thread,
		    &fs->fs_scan_timeout, MSEC_2_TICKS(FMAC_SCAN_RETRY_MS));
	}
	fmac_release(fs);
}

/*
 * End of net80211's scan.  It ends this way every time, including
 * after the firmware already finished, so stop the firmware only when
 * its scan is still running (net80211 gave up first: a timeout, or a
 * new request).  net80211 calls this without its lock held.
 */
static void
fmac_scan_end_shim(struct ieee80211com *ic)
{
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL)
		return;
	taskqueue_cancel_timeout(taskqueue_thread, &fs->fs_scan_timeout, NULL);
	fs->fs_scan_retry = false;
	if (fs->fs_scan_active) {
		fs->fs_scan_active = false;
		if (fs->fs_ops->fmop_scan_cancel != NULL)
			fs->fs_ops->fmop_scan_cancel(ic);
	}
	if (fs->fs_save_scan_end != NULL)
		fs->fs_save_scan_end(ic);
	fmac_release(fs);
}

/*
 * Per-channel hooks.  The firmware scans every channel itself, so
 * these do nothing and net80211 waits for ieee80211_fmac_scan_done,
 * as iwm, iwx and rsu do.
 */
static void
fmac_scan_curchan(struct ieee80211_scan_state *ss __unused,
    unsigned long maxdwell __unused)
{
}

static void
fmac_scan_mindwell(struct ieee80211_scan_state *ss __unused)
{
}

/* the firmware never reported the end of its scan, or refused it */
static void
fmac_scan_timeout(void *arg, int pending __unused)
{
	struct fmac_state *fs = arg;
	struct ieee80211com *ic = fs->fs_ic;

	if (fs->fs_scan_active) {
		ic_printf(ic, "firmware scan timed out\n");
		if (fs->fs_ops->fmop_scan_cancel != NULL)
			fs->fs_ops->fmop_scan_cancel(ic);
	} else if (!fs->fs_scan_retry)
		return;
	fs->fs_scan_retry = false;
	ieee80211_fmac_scan_done(ic);
}

/* ------------------------------------------------------------------
 * Driver -> net80211 up-calls
 * ------------------------------------------------------------------ */

/*
 * Signal polling.  fmac_sig_start runs the first poll at once and the
 * task re-arms itself every two seconds while a station vap is in RUN;
 * fmac_sig_stop forgets the cached values so net80211's own getters
 * answer again.
 */
#define	FMAC_SIG_POLL_MS	2000

static void
fmac_sig_start(struct ieee80211com *ic)
{
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL)
		return;
	if (fs->fs_ops->fmop_get_signal != NULL)
		taskqueue_enqueue(taskqueue_thread, &fs->fs_sig_task);
	fmac_release(fs);
}

static void
fmac_sig_stop(struct ieee80211com *ic)
{
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL)
		return;
	fs->fs_sig_valid = false;
	callout_stop(&fs->fs_sig_callout);
	fmac_release(fs);
}

static void
fmac_sig_callout(void *arg)
{
	struct fmac_state *fs = arg;

	taskqueue_enqueue(taskqueue_thread, &fs->fs_sig_task);
}

static void
fmac_sig_task(void *arg, int pending __unused)
{
	struct fmac_state *fs = arg;
	struct ieee80211com *ic = fs->fs_ic;
	struct ieee80211vap *vap;
	int rssi, noise;
	bool linked = false;

	IEEE80211_LOCK(ic);
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
		if (vap->iv_opmode == IEEE80211_M_STA &&
		    vap->iv_state == IEEE80211_S_RUN)
			linked = true;
	IEEE80211_UNLOCK(ic);
	if (!linked) {
		fs->fs_sig_valid = false;
		return;
	}
	if (fs->fs_ops->fmop_get_signal(ic, &rssi, &noise) == 0 &&
	    rssi < 0 && rssi > -128) {
		fs->fs_sig_rssi = rssi;
		fs->fs_sig_noise = ieee80211_fmac_noise_floor(noise);
		fs->fs_sig_valid = true;
	}
	callout_reset(&fs->fs_sig_callout, MSEC_2_TICKS(FMAC_SIG_POLL_MS),
	    fmac_sig_callout, fs);
}

/* net80211's signal for a node: half-dB above the noise floor */
static int8_t
fmac_node_getrssi(const struct ieee80211_node *ni)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	int8_t v;
	int r;

	if (fs == NULL)
		return (0);
	if (fs->fs_sig_valid && ni == ni->ni_vap->iv_bss) {
		r = (fs->fs_sig_rssi - fs->fs_sig_noise) * 2;
		v = r < 0 ? 0 : r > 127 ? 127 : r;
	} else
		v = fs->fs_save_getrssi(ni);
	fmac_release(fs);
	return (v);
}

static void
fmac_node_getsignal(const struct ieee80211_node *ni, int8_t *rssi,
    int8_t *noise)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL) {
		*rssi = 0;
		*noise = 0;
		return;
	}
	if (fs->fs_sig_valid && ni == ni->ni_vap->iv_bss) {
		*rssi = fmac_node_getrssi(ni);
		*noise = fs->fs_sig_noise;
	} else
		fs->fs_save_getsignal(ni, rssi, noise);
	fmac_release(fs);
}

/*
 * Re-send the vap's power-save setting after a link comes up, so a
 * setting made while the interface was down (when net80211 skips
 * iv_reset) still reaches the firmware.
 */
static void
fmac_apply_powersave(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs = fmac_lookup(ic);
	int rc;

	if (fs == NULL)
		return;
	if (fs->fs_ops->fmop_set_powersave != NULL) {
		rc = fs->fs_ops->fmop_set_powersave(ic,
		    (vap->iv_flags & IEEE80211_F_PMGTON) != 0);
		if (rc != 0)
			ic_printf(ic, "%s: power save setting failed "
			    "(error %d)\n", fs->fs_ops->fmop_name, rc);
	}
	fmac_release(fs);
}

/*
 * Fast-forward the bss vap to RUN when the firmware says "linked".
 * Conservative: only walks from AUTH or ASSOC (i.e., when net80211
 * is in a state where sta_newstate(RUN) won't NULL-deref on
 * ieee80211_sync_curchan).  Returns ENOENT if no vap is in a
 * fast-forwardable state — the driver does its own recovery (a
 * scan-cache lookup, for instance).
 */
/*
 * Put back a station vap's running flag that net80211 lost to a race.
 * SIOCSIFFLAGS restarts a vap only when it is in INIT, while going down
 * clears IFF_DRV_RUNNING at once but reaches INIT later, on the state
 * task.  So a quick down and up, which wpa_supplicant does at start,
 * can leave the interface UP, never running again, and the firmware
 * then joins it anyway: the vap reaches RUN and every send fails with
 * ENETDOWN.  Mark it running as ieee80211_start_locked would, without
 * that function's restart of the state machine, which would drop the
 * link the firmware just made.
 */
static void
fmac_repair_running(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	bool repaired = false, parent = false;

	IEEE80211_LOCK(ic);
	if ((if_getflags(vap->iv_ifp) & IFF_UP) != 0 &&
	    !ieee80211_vap_ifp_check_is_running(vap)) {
		ieee80211_vap_ifp_set_running_state(vap, true);
		ieee80211_notify_ifnet_change(vap, IFF_DRV_RUNNING);
		parent = ic->ic_nrunning++ == 0;
		repaired = true;
	}
	IEEE80211_UNLOCK(ic);
	if (parent)
		ieee80211_runtask(ic, &ic->ic_parent_task);
	if (repaired)
		if_printf(vap->iv_ifp, "fullmac: link up on an UP interface "
		    "that was not running; marked it running\n");
}

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
		fmac_repair_running(vap);
		(void)ieee80211_new_state(vap, IEEE80211_S_RUN, -1);
		fmac_apply_powersave(vap);
		fmac_sig_start(ic);
		return (0);
	}
	return (ENOENT);
}

/* the state a vap ends in once its queued transitions have run */
static enum ieee80211_state
fmac_last_state(const struct ieee80211vap *vap)
{
	if (vap->iv_nstate_n == 0)
		return (vap->iv_state);
	return (vap->iv_nstates[(vap->iv_nstate_b + vap->iv_nstate_n - 1) %
	    NET80211_IV_NSTATE_NUM]);
}

/* firmware says the link dropped: rescan, as after a beacon miss */
int
ieee80211_fmac_link_down(struct ieee80211com *ic, uint16_t reason)
{
	struct ieee80211vap *vap;
	int n = 0;

	(void)reason;
	fmac_sig_stop(ic);
	ieee80211_fmac_assoc_ies(ic, NULL, 0);
	IEEE80211_LOCK(ic);
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_STA)
			continue;
		n++;
		/* not one going down, or already headed for INIT */
		if (ieee80211_vap_ifp_check_is_running(vap) &&
		    fmac_last_state(vap) >= IEEE80211_S_AUTH)
			(void)ieee80211_new_state_locked(vap,
			    IEEE80211_S_SCAN, 0);
	}
	IEEE80211_UNLOCK(ic);
	return (n != 0 ? 0 : ENOENT);
}

/* Keep a copy of the BSS this station vap is leaving, for fmac_left_task. */
static void
fmac_note_left(struct fmac_state *fs, struct ieee80211vap *vap)
{
	struct ieee80211_node *ni = vap->iv_bss;
	struct fmac_left_bss *fl, *old;

	if (vap->iv_state < IEEE80211_S_AUTH || ni == NULL ||
	    ni->ni_chan == NULL || ni->ni_chan == IEEE80211_CHAN_ANYC ||
	    ni->ni_ies.data == NULL || ni->ni_ies.len == 0)
		return;
	fl = malloc(sizeof(*fl) + ni->ni_ies.len, M_80211_FMAC,
	    M_NOWAIT | M_ZERO);
	if (fl == NULL)
		return;
	IEEE80211_ADDR_COPY(fl->fl_bss.fb_bssid, ni->ni_bssid);
	fl->fl_bss.fb_capinfo = ni->ni_capinfo;
	fl->fl_bss.fb_bintval = ni->ni_intval;
	fl->fl_bss.fb_rssi = fs->fs_sig_valid ? fs->fs_sig_rssi : -60;
	fl->fl_bss.fb_noise = fs->fs_sig_valid ? fs->fs_sig_noise :
	    IEEE80211_FMAC_NF_DEFAULT;
	fl->fl_bss.fb_chan_freq = ni->ni_chan->ic_freq;
	fl->fl_bss.fb_chan_flags = IEEE80211_IS_CHAN_5GHZ(ni->ni_chan) ? 5 : 2;
	memcpy(fl->fl_ies, ni->ni_ies.data, ni->ni_ies.len);
	fl->fl_bss.fb_ies = fl->fl_ies;
	fl->fl_bss.fb_ielen = ni->ni_ies.len;
	old = (struct fmac_left_bss *)atomic_swap_ptr(
	    (volatile uintptr_t *)&fs->fs_left, (uintptr_t)fl);
	free(old, M_80211_FMAC);
}

/*
 * Runs on the com taskqueue after a link-down's INIT transition: put the
 * BSS the station left back into the scan cache that INIT flushed.
 */
static void
fmac_left_task(void *arg, int pending __unused)
{
	struct fmac_state *fs = arg;
	struct fmac_left_bss *fl;

	fl = (struct fmac_left_bss *)atomic_swap_ptr(
	    (volatile uintptr_t *)&fs->fs_left, 0);
	if (fl == NULL)
		return;
	fmac_scan_add(fs->fs_ic, &fl->fl_bss, true);
	free(fl, M_80211_FMAC);
}

/*
 * Receive up-call: an Ethernet (802.3) frame the firmware handed up,
 * data and EAPOL alike.  The firmware has decrypted and converted it,
 * so it goes straight to the vap's interface, where wpa_supplicant and
 * hostapd take EAPOL off with bpf.  Consumes m.
 */
void
ieee80211_fmac_rx(struct ieee80211com *ic, struct mbuf *m)
{
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);

	if (vap == NULL || m->m_pkthdr.len < ETHER_HDR_LEN) {
		m_freem(m);
		return;
	}
	if (m->m_len < ETHER_HDR_LEN &&
	    (m = m_pullup(m, ETHER_HDR_LEN)) == NULL)
		return;
	m->m_pkthdr.rcvif = vap->iv_ifp;
	ieee80211_vap_deliver_data(vap, m);
}

/*
 * Walk a firmware-supplied IE blob and populate the IE-pointer fields
 * of an ieee80211_scanparams.  Same shape as ieee80211_parse_beacon's
 * IE switch, but operates on a raw byte range — no mbuf, no node, no
 * IEEE80211_DISCARD logging.  Caller must zero `sp` first.  An element
 * too short (or, for the mesh ID, too long) for the checks that
 * ieee80211_parse_beacon would make is left out, since later code reads
 * these at fixed sizes.
 *
 * Stack budget on aarch64 is ~16 KB.  Going through ieee80211_input ->
 * sta_recv_mgmt -> ieee80211_parse_beacon costs ~3 frames and ~1 KB
 * of locals per call.  We're invoked once per BSS inside a per-event
 * loop, so trimming that fat is required for sustained scans not to
 * overflow the kthread stack.
 */
static void
fmac_walk_ies(const uint8_t *ies, size_t ies_len,
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
			if (frm[1] >= 3)
				sp->country = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_DSPARMS:
			if (frm[1] >= 1)
				sp->chan = frm[2];
			break;
		case IEEE80211_ELEMID_TIM:
			if (frm[1] >= 4) {
				sp->tim = __DECONST(uint8_t *, frm);
				sp->timoff = frm - ies;
			}
			break;
		case IEEE80211_ELEMID_XRATES:
			sp->xrates = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_ERP:
			if (frm[1] == 1)
				sp->erp = frm[2] | 0x100;
			break;
		case IEEE80211_ELEMID_HTCAP:
			if (frm[1] >= sizeof(struct ieee80211_ie_htcap) - 2)
				sp->htcap = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_VHT_CAP:
			if (frm[1] >= sizeof(struct ieee80211_vht_cap))
				sp->vhtcap = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_VHT_OPMODE:
			if (frm[1] >= sizeof(struct ieee80211_vht_operation))
				sp->vhtopmode = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_RSN:
			sp->rsn = __DECONST(uint8_t *, frm);
			break;
		case IEEE80211_ELEMID_HTINFO:
			if (frm[1] >= sizeof(struct ieee80211_ie_htinfo) - 2)
				sp->htinfo = __DECONST(uint8_t *, frm);
			break;
#ifdef IEEE80211_SUPPORT_MESH
		case IEEE80211_ELEMID_MESHID:
			/* sta_add copies it into a 2 + 32 byte buffer. */
			if (frm[1] <= IEEE80211_MESHID_LEN)
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
 * Scan-result up-call: one BSS the firmware found, described by
 * struct ieee80211_fmac_bss.  The framework builds the scan entry from
 * the IE blob and hands it straight to the scan module's scan_add, so
 * the driver never builds an 802.11 frame.
 *
 * It goes past ic_scan_methods->sc_add_scan (ieee80211_swscan_add_scan)
 * on purpose: that drops every result in the ISCAN_DISCARD window, set
 * at scan start and cleared only after the software engine's first
 * per-channel callout, and the firmware's first results arrive within
 * milliseconds, well before then.  Results arriving outside a net80211
 * scan are dropped.  The on-stack frame header carries only what
 * scan_add reads: the BSSID as source and bssid.  scan_add copies the
 * IEs itself, so the driver's buffer is free once this returns.
 */
void
ieee80211_fmac_scan_result(struct ieee80211com *ic,
    const struct ieee80211_fmac_bss *bb)
{
	fmac_scan_add(ic, bb, false);
}

/*
 * Add one BSS to net80211's scan cache.  Results only count while a scan
 * runs; restoring the BSS a station just left (fmac_left_task) is the
 * one caller that may add outside a scan.
 */
static void
fmac_scan_add(struct ieee80211com *ic, const struct ieee80211_fmac_bss *bb,
    bool anytime)
{
	struct ieee80211_channel *rxchan;
	struct ieee80211_scanparams sp;
	struct ieee80211_frame wh;
	uint8_t tstamp_zero[8];
	int rssi, nf;
	bool is5g;

	if (bb == NULL || bb->fb_ies == NULL || bb->fb_ielen == 0)
		return;
	is5g = bb->fb_chan_flags == 5 || bb->fb_chan_freq >= 4900;
	rxchan = ieee80211_find_channel(ic, bb->fb_chan_freq,
	    is5g ? IEEE80211_CHAN_A : IEEE80211_CHAN_G);
	if (rxchan == NULL)
		rxchan = ic->ic_curchan;
	if (rxchan == NULL)
		return;

	/* net80211 wants signal as half-dB above the noise floor. */
	nf = ieee80211_fmac_noise_floor(bb->fb_noise);
	rssi = (bb->fb_rssi - nf) * 2;
	if (rssi < 0)
		rssi = 0;
	if (rssi > 127)
		rssi = 127;

	memset(&sp, 0, sizeof(sp));
	memset(tstamp_zero, 0, sizeof(tstamp_zero));
	sp.bchan = ieee80211_chan2ieee(ic, rxchan);
	sp.chan = sp.bchan;
	sp.bintval = bb->fb_bintval;
	sp.capinfo = bb->fb_capinfo;
	sp.ies = __DECONST(uint8_t *, bb->fb_ies);
	sp.ies_len = bb->fb_ielen;
	sp.tstamp = tstamp_zero;	/* sta_add copies 8 bytes from it */
	fmac_walk_ies(bb->fb_ies, bb->fb_ielen, &sp);

	/*
	 * sta_add copies 2 + sp->rates[1] and 2 + sp->ssid[1] bytes into
	 * fixed buffers with no NULL or length check (its KASSERT is gone
	 * on non-DEBUG kernels), and skipping sc_add_scan skips the checks
	 * it would have made.  Drop malformed results here.
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
	memset(wh.i_addr1, 0xff, IEEE80211_ADDR_LEN);
	memcpy(wh.i_addr2, bb->fb_bssid, IEEE80211_ADDR_LEN);
	memcpy(wh.i_addr3, bb->fb_bssid, IEEE80211_ADDR_LEN);

	/* vap detach frees the scan table under the com lock. */
	IEEE80211_LOCK(ic);
	if (TAILQ_FIRST(&ic->ic_vaps) != NULL && ic->ic_scan != NULL &&
	    ic->ic_scan->ss_ops != NULL &&
	    ic->ic_scan->ss_ops->scan_add != NULL &&
	    (anytime || (ic->ic_flags & IEEE80211_F_SCAN) != 0) &&
	    ic->ic_scan->ss_vap != NULL)
		(void)ic->ic_scan->ss_ops->scan_add(ic->ic_scan, rxchan, &sp,
		    &wh, IEEE80211_FC0_SUBTYPE_BEACON, rssi, nf);
	IEEE80211_UNLOCK(ic);
}

/*
 * The firmware's scan has delivered every result: end net80211's scan.
 * Call from a context that can sleep, without the com lock.
 */
void
ieee80211_fmac_scan_done(struct ieee80211com *ic)
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211vap *vap;

	if (fs != NULL) {
		fs->fs_scan_active = false;
		taskqueue_cancel_timeout(taskqueue_thread,
		    &fs->fs_scan_timeout, NULL);
		fmac_release(fs);
	}
	vap = (ic->ic_scan != NULL && ic->ic_scan->ss_vap != NULL) ?
	    ic->ic_scan->ss_vap : TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;
	ieee80211_scan_done(vap);
}

/*
 * A scan entry for ieee80211_sta_join, built from a firmware BSS as
 * ieee80211_fmac_scan_result would add it to the scan cache.  se_ies
 * is allocated; the caller frees it with ieee80211_ies_cleanup.
 */
static int
fmac_bss_to_se(struct ieee80211com *ic, const struct ieee80211_fmac_bss *bb,
    struct ieee80211_scan_entry *se, struct ieee80211_channel **chanp)
{
	struct ieee80211_scanparams sp;
	struct ieee80211_channel *c;
	int rssi, nf;
	bool is5g;

	if (bb->fb_ies == NULL || bb->fb_ielen == 0)
		return (EINVAL);
	is5g = bb->fb_chan_flags == 5 || bb->fb_chan_freq >= 4900;
	c = ieee80211_find_channel(ic, bb->fb_chan_freq,
	    is5g ? IEEE80211_CHAN_A : IEEE80211_CHAN_G);
	if (c == NULL)
		return (EINVAL);

	memset(&sp, 0, sizeof(sp));
	fmac_walk_ies(bb->fb_ies, bb->fb_ielen, &sp);
	if (sp.ssid == NULL || sp.ssid[1] > IEEE80211_NWID_LEN ||
	    sp.rates == NULL || sp.rates[1] > IEEE80211_RATE_MAXSIZE ||
	    (sp.xrates != NULL && sp.xrates[1] > IEEE80211_RATE_MAXSIZE))
		return (EINVAL);

	nf = ieee80211_fmac_noise_floor(bb->fb_noise);
	rssi = (bb->fb_rssi - nf) * 2;
	if (rssi < 0)
		rssi = 0;
	if (rssi > 127)
		rssi = 127;

	memset(se, 0, sizeof(*se));
	IEEE80211_ADDR_COPY(se->se_macaddr, bb->fb_bssid);
	IEEE80211_ADDR_COPY(se->se_bssid, bb->fb_bssid);
	memcpy(se->se_ssid, sp.ssid, 2 + sp.ssid[1]);
	memcpy(se->se_rates, sp.rates, 2 + sp.rates[1]);
	if (sp.xrates != NULL)
		memcpy(se->se_xrates, sp.xrates, 2 + sp.xrates[1]);
	se->se_intval = bb->fb_bintval;
	se->se_capinfo = bb->fb_capinfo;
	se->se_chan = c;
	if (sp.tim != NULL && sp.tim[1] >= 2) {
		se->se_timoff = sp.timoff;
		se->se_dtimperiod = sp.tim[3];
	}
	se->se_erp = sp.erp;
	se->se_rssi = rssi;
	se->se_noise = nf;
	if (!ieee80211_ies_init(&se->se_ies, bb->fb_ies, bb->fb_ielen))
		return (ENOMEM);
	*chanp = c;
	return (0);
}

/* The firmware roamed to another AP: follow it.  See the header. */
int
ieee80211_fmac_roamed(struct ieee80211com *ic,
    const struct ieee80211_fmac_bss *bb)
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211_scan_entry se;
	struct ieee80211_channel *chan;
	struct ieee80211vap *vap;
	int error, i;

	if (fs == NULL)
		return (ENXIO);
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
		if (vap->iv_opmode == IEEE80211_M_STA &&
		    vap->iv_state == IEEE80211_S_RUN && vap->iv_bss != NULL)
			break;
	if (vap == NULL) {
		fmac_release(fs);
		return (ENOENT);
	}
	if (IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, bb->fb_bssid)) {
		fmac_release(fs);
		return (0);
	}
	error = fmac_bss_to_se(ic, bb, &se, &chan);
	if (error != 0) {
		fmac_release(fs);
		return (error);
	}

	fs->fs_roaming = true;
	if (ieee80211_sta_join(vap, chan, &se) == 0) {
		fs->fs_roaming = false;
		error = EIO;
	} else {
		/* fmac_newstate reports the reassociation and clears it. */
		for (i = 0; i < 40 && fs->fs_roaming; i++)
			pause("fmacroam", hz / 20);
		if (fs->fs_roaming) {
			fs->fs_roaming = false;
			error = ETIMEDOUT;
		}
	}
	ieee80211_ies_cleanup(&se.se_ies);
	if (error == 0)
		if_printf(vap->iv_ifp, "fullmac: roamed to %6D\n",
		    bb->fb_bssid, ":");
	fmac_release(fs);
	return (error);
}

/* ------------------------------------------------------------------
 * Access point
 * ------------------------------------------------------------------ */

/* An RSN or WPA cipher suite type as a 1 << IEEE80211_CIPHER_* bit. */
static uint32_t
fmac_suite_cipher(uint8_t type)
{
	switch (type) {
	case 1:			/* WEP-40 */
	case 5:			/* WEP-104 */
		return (1u << IEEE80211_CIPHER_WEP);
	case 2:
		return (1u << IEEE80211_CIPHER_TKIP);
	case 4:
		return (1u << IEEE80211_CIPHER_AES_CCM);
	case 8:
		return (1u << IEEE80211_CIPHER_AES_GCM_128);
	default:
		return (0);
	}
}

/*
 * Read the ciphers, key management and RSN capabilities out of one RSN
 * element (48) or WPA vendor element (dd 00:50:f2:01).  Both share the
 * layout after their headers: version, group suite, pairwise list, AKM
 * list, then (RSN only) capabilities.  A short element keeps whatever
 * it got through; hostapd always sends complete ones.
 */
static void
fmac_parse_wpa_ie(struct ieee80211_fmac_ap *ap, const uint8_t *ie)
{
	static const uint8_t rsn_oui[3] = { 0x00, 0x0f, 0xac };
	static const uint8_t wpa_oui[3] = { 0x00, 0x50, 0xf2 };
	const uint8_t *p, *end, *oui;
	uint16_t n;
	bool rsn;

	rsn = ie[0] == IEEE80211_ELEMID_RSN;
	p = ie + 2;
	end = p + ie[1];
	if (rsn) {
		oui = rsn_oui;
		ap->fp_wpa |= 2;
	} else {
		oui = wpa_oui;
		p += 4;			/* OUI + type */
		ap->fp_wpa |= 1;
	}
	p += 2;				/* version */
	if (end - p < 4)
		return;
	if (memcmp(p, oui, 3) == 0)
		ap->fp_mcast |= fmac_suite_cipher(p[3]);
	p += 4;
	if (end - p < 2)
		return;
	n = le16dec(p);
	p += 2;
	for (; n > 0 && end - p >= 4; n--, p += 4)
		if (memcmp(p, oui, 3) == 0)
			ap->fp_ucast |= fmac_suite_cipher(p[3]);
	if (end - p < 2)
		return;
	n = le16dec(p);
	p += 2;
	for (; n > 0 && end - p >= 4; n--, p += 4)
		if (memcmp(p, oui, 3) == 0 && p[3] < 32)
			ap->fp_akms |= 1u << p[3];
	if (!rsn || end - p < 2)
		return;
	ap->fp_rsncaps = le16dec(p);
	p += 2;
	/*
	 * With MFP the element may name the group management cipher
	 * after the PMKID list; when it does not, the default is
	 * BIP-CMAC-128 (802.11-2016 9.4.2.25.2).
	 */
	if ((ap->fp_rsncaps & IEEE80211_FMAC_RSNCAP_MFPC) == 0)
		return;
	ap->fp_mgmt_suite = 6;		/* BIP-CMAC-128 */
	if (end - p < 2)
		return;
	n = le16dec(p);
	p += 2;
	if (end - p < 16 * (ptrdiff_t)n)
		return;
	p += 16 * n;
	if (end - p >= 4 && memcmp(p, oui, 3) == 0)
		ap->fp_mgmt_suite = p[3];
}

/*
 * Take down the BSS a hostap vap in RUN describes.  Called from
 * fmac_newstate with the com lock held, so it copies and never sleeps.
 * hostapd gives net80211 its WPA/RSN elements (IEEE80211_IOC_APPIE,
 * held in iv_appie_wpa) and the WPA mode, but no cipher settings, so
 * the elements are the only record of them.
 */
static void
fmac_ap_snapshot(struct ieee80211vap *vap, struct ieee80211_fmac_ap *ap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_node *ni = vap->iv_bss;
	const struct ieee80211_appie *aie = vap->iv_appie_wpa;
	struct ieee80211_channel *c;
	const uint8_t *p, *end;

	memset(ap, 0, sizeof(*ap));
	if (ni == NULL)
		return;
	IEEE80211_ADDR_COPY(ap->fp_bssid, ni->ni_bssid);
	ap->fp_ssidlen = MIN(ni->ni_esslen, IEEE80211_NWID_LEN);
	memcpy(ap->fp_ssid, ni->ni_essid, ap->fp_ssidlen);
	ap->fp_hidden = (vap->iv_flags & IEEE80211_F_HIDESSID) != 0;
	c = ni->ni_chan;
	if (c == NULL || c == IEEE80211_CHAN_ANYC)
		c = ic->ic_bsschan;
	if (c != NULL && c != IEEE80211_CHAN_ANYC) {
		ap->fp_chan_freq = c->ic_freq;
		ap->fp_chan_ieee = c->ic_ieee;
		ap->fp_chan_flags = c->ic_flags;
		ap->fp_chan_center = c->ic_vht_ch_freq1;
	}
	ap->fp_chan_auto = vap->iv_des_chan == IEEE80211_CHAN_ANYC;
	ap->fp_bintval = ni->ni_intval != 0 ? ni->ni_intval : ic->ic_bintval;
	ap->fp_dtim = vap->iv_dtim_period != 0 ? vap->iv_dtim_period : 1;
	ap->fp_privacy = (vap->iv_flags & IEEE80211_F_PRIVACY) != 0;

	if (aie != NULL && aie->ie_len <= sizeof(ap->fp_ies)) {
		ap->fp_ielen = aie->ie_len;
		memcpy(ap->fp_ies, aie->ie_data, aie->ie_len);
		p = ap->fp_ies;
		end = p + ap->fp_ielen;
		while (end - p >= 2 && end - p >= 2 + p[1]) {
			if ((p[0] == IEEE80211_ELEMID_RSN && p[1] >= 2) ||
			    (p[0] == IEEE80211_ELEMID_VENDOR && p[1] >= 6 &&
			    p[2] == 0x00 && p[3] == 0x50 && p[4] == 0xf2 &&
			    p[5] == 0x01))
				fmac_parse_wpa_ie(ap, p);
			p += 2 + p[1];
		}
	}
	/* WPA flags without elements: assume the common WPA2-PSK/CCMP. */
	if (ap->fp_wpa == 0 &&
	    (vap->iv_flags & (IEEE80211_F_WPA1 | IEEE80211_F_WPA2)) != 0) {
		if (vap->iv_flags & IEEE80211_F_WPA1)
			ap->fp_wpa |= 1;
		if (vap->iv_flags & IEEE80211_F_WPA2)
			ap->fp_wpa |= 2;
		ap->fp_ucast = ap->fp_mcast = 1u << IEEE80211_CIPHER_AES_CCM;
		ap->fp_akms = 1u << RSN_ASE_8021X_PSK;
	}
}

/* Record the security of a BSS being started.  fs_ap_mtx held. */
static void
fmac_ap_sec_save(struct fmac_state *fs, const struct ieee80211_fmac_ap *ap)
{
	mtx_assert(&fs->fs_ap_mtx, MA_OWNED);
	fs->fs_ap_sec_valid = true;
	fs->fs_ap_sec_wpa = ap->fp_wpa;
	fs->fs_ap_sec_ucast = ap->fp_ucast;
	fs->fs_ap_sec_mcast = ap->fp_mcast;
	fs->fs_ap_sec_akms = ap->fp_akms;
	fs->fs_ap_sec_rsncaps = ap->fp_rsncaps;
}

/*
 * hostapd brings the interface up before it hands net80211 its WPA/RSN
 * element (bsd_ctrl_iface, then bsd_set_opt_ie, then the group keys),
 * and net80211 does not announce the element, so the BSS can start on
 * the WPA defaults without hostapd's ciphers, key management or MFP.
 * The group keys always follow the element, so check when one is
 * installed: if the security now differs from what the firmware runs,
 * queue a start with the element.  It runs on the same taskqueue ahead
 * of the driver's deferred key install, so the keys land in the new
 * BSS.  Called from iv_key_set; does not sleep.
 */
static void
fmac_ap_sec_check(struct fmac_state *fs, struct ieee80211vap *vap)
{
	struct ieee80211_fmac_ap *ap;
	bool changed;

	if (fs->fs_ops->fmop_start_ap == NULL ||
	    vap->iv_state != IEEE80211_S_RUN)
		return;
	ap = malloc(sizeof(*ap), M_80211_FMAC, M_NOWAIT | M_ZERO);
	if (ap == NULL)
		return;
	/* The ioctl path swaps and frees iv_appie_wpa under the com lock. */
	IEEE80211_LOCK(vap->iv_ic);
	fmac_ap_snapshot(vap, ap);
	IEEE80211_UNLOCK(vap->iv_ic);
	mtx_lock(&fs->fs_ap_mtx);
	changed = fs->fs_ap_sec_valid && ap->fp_ielen != 0 &&
	    (ap->fp_wpa != fs->fs_ap_sec_wpa ||
	    ap->fp_ucast != fs->fs_ap_sec_ucast ||
	    ap->fp_mcast != fs->fs_ap_sec_mcast ||
	    ap->fp_akms != fs->fs_ap_sec_akms ||
	    ap->fp_rsncaps != fs->fs_ap_sec_rsncaps);
	if (changed) {
		fs->fs_ap_conf = *ap;
		fmac_ap_sec_save(fs, ap);
		fs->fs_ap_want = FMAC_AP_START;
	}
	mtx_unlock(&fs->fs_ap_mtx);
	explicit_bzero(ap, sizeof(*ap));
	free(ap, M_80211_FMAC);
	if (changed) {
		ic_printf(vap->iv_ic, "%s: hostapd's WPA/RSN element arrived "
		    "after the access point started; restarting it with "
		    "those settings\n", fs->fs_ops->fmop_name);
		taskqueue_enqueue(taskqueue_thread, &fs->fs_ap_task);
	}
}

/*
 * A station the firmware accepted: put it in net80211's station table
 * as hostap_auth_open and hostap_recv_mgmt would have, then join it,
 * which assigns the association ID, opens the data path to it and
 * tells hostapd (RTM_IEEE80211_JOIN).  hostapd reads the station's
 * WPA/RSN element back through IEEE80211_IOC_WPAIE, so keep the
 * request's elements on the node.
 */
static void
fmac_ap_join(struct ieee80211vap *vap, const struct fmac_ap_evt *fe)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_node *ni;
	const uint8_t *p, *end, *rates = NULL, *xrates = NULL;

	ni = ieee80211_find_vap_node(&ic->ic_sta, vap, fe->fe_mac);
	if (ni == vap->iv_bss) {
		/* A report for our own address; not a station. */
		ieee80211_free_node(ni);
		return;
	}
	if (ni == NULL) {
		ni = ieee80211_dup_bss(vap, fe->fe_mac);
		if (ni == NULL)
			return;
	} else if ((ni->ni_flags & IEEE80211_NODE_AREF) != 0) {
		/* already holds its association reference */
		ieee80211_free_node(ni);
	}
	ni->ni_flags |= IEEE80211_NODE_AREF;

	if (fe->fe_ielen > 0 &&
	    ieee80211_ies_init(&ni->ni_ies, fe->fe_ies, fe->fe_ielen))
		ieee80211_ies_expand(&ni->ni_ies);
	p = fe->fe_ies;
	end = p + fe->fe_ielen;
	while (end - p >= 2 && end - p >= 2 + p[1]) {
		if (p[0] == IEEE80211_ELEMID_RATES &&
		    p[1] <= IEEE80211_RATE_MAXSIZE)
			rates = p;
		else if (p[0] == IEEE80211_ELEMID_XRATES)
			xrates = p;
		p += 2 + p[1];
	}
	if (rates != NULL && (xrates == NULL ||
	    rates[1] + xrates[1] <= IEEE80211_RATE_MAXSIZE))
		(void)ieee80211_setup_rates(ni, rates, xrates,
		    IEEE80211_F_DOSORT);

	/*
	 * Without WPA or 802.1X nothing else opens the port, as
	 * hostap_auth_open does; with them hostapd authorizes the
	 * station once the handshake is done, so a station coming back
	 * starts closed again.
	 */
	if ((vap->iv_flags & IEEE80211_F_WPA) == 0 &&
	    ni->ni_authmode != IEEE80211_AUTH_8021X)
		ieee80211_node_authorize(ni);
	else
		ieee80211_node_unauthorize(ni);
	ieee80211_node_join(ni, fe->fe_type == FMAC_EVT_REJOIN ?
	    IEEE80211_FC0_SUBTYPE_REASSOC_RESP :
	    IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
}

/* A station the firmware dropped, or that left: forget it. */
static void
fmac_ap_leave(struct ieee80211vap *vap, const struct fmac_ap_evt *fe)
{
	struct ieee80211_node *ni;

	ni = ieee80211_find_vap_node(&vap->iv_ic->ic_sta, vap, fe->fe_mac);
	if (ni == NULL)
		return;
	if (ni != vap->iv_bss)
		ieee80211_node_leave(ni);
	ieee80211_free_node(ni);
}

/* The running hostap vap, passing over one being deleted. */
static struct ieee80211vap *
fmac_ap_vap(struct fmac_state *fs)
{
	struct ieee80211com *ic = fs->fs_ic;
	struct ieee80211vap *vap, *going;
	bool dying;

	mtx_lock(&fs->fs_ap_mtx);
	going = fs->fs_vap_going;
	dying = fs->fs_dying;
	mtx_unlock(&fs->fs_ap_mtx);
	if (dying)
		return (NULL);
	IEEE80211_LOCK(ic);
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
		if (vap != going && vap->iv_opmode == IEEE80211_M_HOSTAP &&
		    vap->iv_state == IEEE80211_S_RUN)
			break;
	IEEE80211_UNLOCK(ic);
	return (vap);
}

/*
 * Carry out the latest start or stop, then the queued station events,
 * in order.  Runs on taskqueue_thread with no locks held, so the
 * driver ops and net80211's node calls may sleep or take the com lock.
 */
static void
fmac_ap_task(void *arg, int pending __unused)
{
	struct fmac_state *fs = arg;
	struct ieee80211com *ic = fs->fs_ic;
	struct ieee80211_fmac_ap ap;
	struct ieee80211vap *vap;
	struct fmac_ap_evt *fe;
	int want, rc;

	mtx_lock(&fs->fs_ap_mtx);
	want = fs->fs_ap_want;
	fs->fs_ap_want = FMAC_AP_NONE;
	if (want == FMAC_AP_START)
		ap = fs->fs_ap_conf;
	mtx_unlock(&fs->fs_ap_mtx);

	if (want == FMAC_AP_START) {
		rc = fs->fs_ops->fmop_start_ap(ic, &ap);
		if (rc != 0)
			ic_printf(ic, "%s: access point \"%.*s\" did not "
			    "start: error %d\n", fs->fs_ops->fmop_name,
			    ap.fp_ssidlen, ap.fp_ssid, rc);
		else if (fs->fs_ops->fmop_sta_idle != NULL &&
		    fmac_ap_vap(fs) != NULL)
			callout_reset(&fs->fs_age_callout,
			    IEEE80211_INACT_WAIT * hz, fmac_age_callout, fs);
		/*
		 * With no channel set, net80211's AP scan picks the least
		 * busy one.  hostapd's channel= does not set it on FreeBSD:
		 * its bsd driver reports no hardware modes, so hostapd never
		 * applies the channel.  Say so, since that surprises people.
		 */
		if (rc == 0 && ap.fp_chan_auto)
			ic_printf(ic, "%s: access point on channel %u, picked "
			    "by net80211 since none was set; set one with "
			    "ifconfig (hostapd's channel= is not applied on "
			    "FreeBSD)\n", fs->fs_ops->fmop_name,
			    ap.fp_chan_ieee);
		explicit_bzero(&ap, sizeof(ap));
	} else if (want == FMAC_AP_STOP) {
		callout_stop(&fs->fs_age_callout);
		rc = fs->fs_ops->fmop_stop_ap(ic);
		if (rc != 0)
			ic_printf(ic, "%s: access point stop: error %d\n",
			    fs->fs_ops->fmop_name, rc);
	}

	for (;;) {
		mtx_lock(&fs->fs_ap_mtx);
		fe = STAILQ_FIRST(&fs->fs_ap_evts);
		if (fe != NULL) {
			STAILQ_REMOVE_HEAD(&fs->fs_ap_evts, fe_link);
			fs->fs_ap_nevts--;
		}
		mtx_unlock(&fs->fs_ap_mtx);
		if (fe == NULL)
			break;
		if (fe->fe_type == FMAC_EVT_DEAUTH) {
			if (fs->fs_ops->fmop_sta_deauth != NULL)
				(void)fs->fs_ops->fmop_sta_deauth(ic,
				    fe->fe_mac, fe->fe_reason);
		} else if ((vap = fmac_ap_vap(fs)) != NULL) {
			if (fe->fe_type == FMAC_EVT_LEAVE)
				fmac_ap_leave(vap, fe);
			else
				fmac_ap_join(vap, fe);
		}
		free(fe, M_80211_FMAC);
	}
}

/*
 * Station aging.  net80211 counts each node down from ni_inact_reload
 * every IEEE80211_INACT_WAIT seconds and deauthenticates the station
 * when it reaches zero (ieee80211_timeout_stations); anything heard
 * from the station resets it, in ieee80211_input.  Our stations are
 * heard only by the firmware, so this sets the count from the
 * firmware's idle time instead, once per net80211 tick.  The firmware
 * also ages stations itself and reports the ones it drops, so it stays
 * the authority: a station it cannot report on this time is counted as
 * heard, rather than let a failed query age out a live station.
 */
#define	FMAC_AGE_MAX	64

struct fmac_age_list {
	struct ieee80211vap	*al_vap;
	int			 al_n;
	uint8_t			 al_mac[FMAC_AGE_MAX][IEEE80211_ADDR_LEN];
};

static void
fmac_age_collect(void *arg, struct ieee80211_node *ni)
{
	struct fmac_age_list *al = arg;

	if (ni->ni_vap != al->al_vap || ni == al->al_vap->iv_bss ||
	    ni->ni_associd == 0 || al->al_n >= FMAC_AGE_MAX)
		return;
	IEEE80211_ADDR_COPY(al->al_mac[al->al_n], ni->ni_macaddr);
	al->al_n++;
}

static void
fmac_age_callout(void *arg)
{
	struct fmac_state *fs = arg;

	taskqueue_enqueue(taskqueue_thread, &fs->fs_age_task);
}

static void
fmac_age_task(void *arg, int pending __unused)
{
	struct fmac_state *fs = arg;
	struct ieee80211com *ic = fs->fs_ic;
	struct fmac_age_list *al;
	struct ieee80211_node *ni;
	uint32_t idle, waits;
	int i;

	al = malloc(sizeof(*al), M_80211_FMAC, M_WAITOK | M_ZERO);
	al->al_vap = fmac_ap_vap(fs);
	if (al->al_vap == NULL)
		goto out;
	ieee80211_iterate_nodes(&ic->ic_sta, fmac_age_collect, al);
	for (i = 0; i < al->al_n; i++) {
		if (fs->fs_ops->fmop_sta_idle(ic, al->al_mac[i], &idle) != 0)
			idle = 0;
		ni = ieee80211_find_vap_node(&ic->ic_sta, al->al_vap,
		    al->al_mac[i]);
		if (ni == NULL)
			continue;
		waits = idle / IEEE80211_INACT_WAIT;
		ni->ni_inact = waits < (uint32_t)ni->ni_inact_reload ?
		    ni->ni_inact_reload - waits : 0;
		ieee80211_free_node(ni);
	}
out:
	if (al->al_vap != NULL)
		callout_reset(&fs->fs_age_callout, IEEE80211_INACT_WAIT * hz,
		    fmac_age_callout, fs);
	free(al, M_80211_FMAC);
}

/* Queue a station event for fmac_ap_task; safe in any context. */
static void
fmac_ap_queue(struct fmac_state *fs, int type,
    const uint8_t mac[IEEE80211_ADDR_LEN], uint16_t reason,
    const uint8_t *ies, size_t ielen)
{
	struct fmac_ap_evt *fe;

	if (ies == NULL || ielen > 1024)
		ielen = 0;
	fe = malloc(sizeof(*fe) + ielen, M_80211_FMAC, M_NOWAIT | M_ZERO);
	if (fe == NULL)
		return;
	fe->fe_type = type;
	IEEE80211_ADDR_COPY(fe->fe_mac, mac);
	fe->fe_reason = reason;
	fe->fe_ielen = ielen;
	if (ielen > 0)
		memcpy(fe->fe_ies, ies, ielen);
	mtx_lock(&fs->fs_ap_mtx);
	if (fs->fs_ap_nevts >= FMAC_AP_MAXEVTS) {
		mtx_unlock(&fs->fs_ap_mtx);
		free(fe, M_80211_FMAC);
		return;
	}
	STAILQ_INSERT_TAIL(&fs->fs_ap_evts, fe, fe_link);
	fs->fs_ap_nevts++;
	mtx_unlock(&fs->fs_ap_mtx);
	taskqueue_enqueue(taskqueue_thread, &fs->fs_ap_task);
}

/* a station associated with our access point */
void
ieee80211_fmac_sta_join(struct ieee80211com *ic,
    const uint8_t mac[IEEE80211_ADDR_LEN],
    const uint8_t *ies, size_t ielen, bool reassoc)
{
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL)
		return;
	fmac_ap_queue(fs, reassoc ? FMAC_EVT_REJOIN : FMAC_EVT_JOIN, mac, 0,
	    ies, ielen);
	fmac_release(fs);
}

/* a station left our access point */
void
ieee80211_fmac_sta_leave(struct ieee80211com *ic,
    const uint8_t mac[IEEE80211_ADDR_LEN], uint16_t reason)
{
	struct fmac_state *fs = fmac_lookup(ic);

	if (fs == NULL)
		return;
	fmac_ap_queue(fs, FMAC_EVT_LEAVE, mac, reason, NULL, 0);
	fmac_release(fs);
}

/*
 * ic_raw_xmit shim.  net80211 sends a hostap vap's deauthentication
 * and disassociation frames itself (hostapd's MLME requests, or the
 * vap going down), and the chip cannot transmit them; turn each into
 * a firmware request and let the driver's hook finish the frame.
 * This may run with node or com locks held, hence the queue.
 */
static int
fmac_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	struct fmac_state *fs;
	const struct ieee80211_frame *wh;
	uint8_t type, subtype;
	uint16_t reason;
	int rc;

	fs = fmac_lookup(ic);
	if (fs == NULL) {
		/* on an error net80211 drops the node reference itself */
		m_freem(m);
		return (ENXIO);
	}
	if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
	    fs->fs_ops->fmop_sta_deauth != NULL &&
	    m->m_len >= (int)sizeof(*wh) + 2) {
		wh = mtod(m, const struct ieee80211_frame *);
		type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
		subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
		if (type == IEEE80211_FC0_TYPE_MGT &&
		    (subtype == IEEE80211_FC0_SUBTYPE_DEAUTH ||
		    subtype == IEEE80211_FC0_SUBTYPE_DISASSOC)) {
			reason = le16dec((const uint8_t *)(wh + 1));
			fmac_ap_queue(fs, FMAC_EVT_DEAUTH, wh->i_addr1,
			    reason, NULL, 0);
		}
	}
	rc = fs->fs_save_raw_xmit(ni, m, params);
	fmac_release(fs);
	return (rc);
}

/*
 * External SAE.  The firmware joins as usual but, at authentication,
 * asks the host to run SAE; wpa_supplicant does so through the
 * RTM_IEEE80211_EXTAUTH / RTM_IEEE80211_MGMT_RX events and the
 * IEEE80211_IOC_MGMT_TX / IEEE80211_IOC_EXTAUTH_STATUS requests, which
 * the framework adds to a station vap's ioctl handler.
 */
static struct ieee80211vap *
fmac_sta_vap(struct ieee80211com *ic)
{
	struct ieee80211vap *vap;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
		if (vap->iv_opmode == IEEE80211_M_STA)
			return (vap);
	return (NULL);
}

void
ieee80211_fmac_extauth_req(struct ieee80211com *ic,
    const uint8_t bssid[IEEE80211_ADDR_LEN], const uint8_t *ssid,
    size_t ssid_len)
{
	struct ieee80211_extauth_event ev;
	struct ieee80211vap *vap = fmac_sta_vap(ic);

	if (vap == NULL)
		return;
	memset(&ev, 0, sizeof(ev));
	IEEE80211_ADDR_COPY(ev.iev_bssid, bssid);
	ev.iev_action = IEEE80211_EXTAUTH_START;
	ev.iev_ssid_len = MIN(ssid_len, sizeof(ev.iev_ssid));
	memcpy(ev.iev_ssid, ssid, ev.iev_ssid_len);
	ev.iev_key_mgmt = 0x000fac08;		/* SAE */
	/* Routing sockets are per VNET; the driver's taskqueue has none set. */
	CURVNET_SET(if_getvnet(vap->iv_ifp));
	rt_ieee80211msg(vap->iv_ifp, RTM_IEEE80211_EXTAUTH, &ev, sizeof(ev));
	CURVNET_RESTORE();
}

void
ieee80211_fmac_mgmt_rx(struct ieee80211com *ic, const uint8_t *frame,
    size_t len, uint16_t freq, int8_t rssi)
{
	struct ieee80211_mgmt_rx_event *ev;
	struct ieee80211vap *vap = fmac_sta_vap(ic);

	if (vap == NULL || len < sizeof(struct ieee80211_frame) ||
	    len > IEEE80211_MGMT_TX_MAXLEN)
		return;
	/*
	 * Drop a payload too big for one mbuf; rt_ieee80211msg()
	 * does not check.
	 */
	if (sizeof(*ev) + len > MLEN) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
		    "%s: %zu byte frame too long for a routing message\n",
		    __func__, len);
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}
	ev = malloc(sizeof(*ev) + len, M_TEMP, M_NOWAIT | M_ZERO);
	if (ev == NULL)
		return;
	ev->iev_len = len;
	ev->iev_freq = freq;
	ev->iev_rssi = rssi;
	memcpy(ev + 1, frame, len);
	CURVNET_SET(if_getvnet(vap->iv_ifp));
	rt_ieee80211msg(vap->iv_ifp, RTM_IEEE80211_MGMT_RX, ev,
	    sizeof(*ev) + len);
	CURVNET_RESTORE();
	free(ev, M_TEMP);
}

void
ieee80211_fmac_assoc_reject(struct ieee80211com *ic,
    const uint8_t bssid[IEEE80211_ADDR_LEN], uint16_t status)
{
	struct ieee80211_assoc_reject_event ev;
	struct ieee80211_join_event jev;
	struct ieee80211vap *vap = fmac_sta_vap(ic);

	if (vap == NULL)
		return;
	memset(&ev, 0, sizeof(ev));
	IEEE80211_ADDR_COPY(ev.iev_bssid, bssid);
	ev.iev_status = status;
	memset(&jev, 0, sizeof(jev));
	IEEE80211_ADDR_COPY(jev.iev_addr, bssid);
	/* Leave AUTH first, as net80211 does on a refused join, so a retry joins again. */
	IEEE80211_LOCK(ic);
	if (ieee80211_vap_ifp_check_is_running(vap) &&
	    (fmac_last_state(vap) == IEEE80211_S_AUTH ||
	    fmac_last_state(vap) == IEEE80211_S_ASSOC))
		(void)ieee80211_new_state_locked(vap, IEEE80211_S_SCAN,
		    IEEE80211_SCAN_FAIL_STATUS);
	IEEE80211_UNLOCK(ic);
	CURVNET_SET(if_getvnet(vap->iv_ifp));
	rt_ieee80211msg(vap->iv_ifp, RTM_IEEE80211_ASSOC_REJECT, &ev,
	    sizeof(ev));
	/* a supplicant without ASSOC_REJECT retries on disassoc */
	rt_ieee80211msg(vap->iv_ifp, RTM_IEEE80211_DISASSOC, &jev,
	    sizeof(jev));
	CURVNET_RESTORE();
}

void
ieee80211_fmac_assoc_ies(struct ieee80211com *ic, const uint8_t *ies,
    size_t len)
{
	struct fmac_state *fs;

	fs = fmac_lookup(ic);
	if (fs == NULL)
		return;
	if (len > sizeof(fs->fs_assoc_ie))
		len = 0;
	IEEE80211_LOCK(ic);
	if (len != 0)
		memcpy(fs->fs_assoc_ie, ies, len);
	fs->fs_assoc_ielen = len;
	IEEE80211_UNLOCK(ic);
	fmac_release(fs);
}

/* IEEE80211_IOC_ASSOC_REQ_IE: ENOENT when the driver gave none */
static int
fmac_assoc_ie_ioctl(struct ieee80211vap *vap, struct ieee80211req *ireq)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct fmac_state *fs;
	uint8_t *buf;
	size_t len;
	int error;

	fs = fmac_lookup(ic);
	if (fs == NULL)
		return (ENXIO);
	buf = malloc(sizeof(fs->fs_assoc_ie), M_TEMP, M_WAITOK);
	IEEE80211_LOCK(ic);
	len = fs->fs_assoc_ielen;
	memcpy(buf, fs->fs_assoc_ie, len);
	IEEE80211_UNLOCK(ic);
	fmac_release(fs);
	if (len == 0)
		error = ENOENT;
	else if (ireq->i_len < len)
		error = ENOSPC;
	else {
		error = copyout(buf, ireq->i_data, len);
		ireq->i_len = len;
	}
	free(buf, M_TEMP);
	return (error);
}

/*
 * IEEE80211_IOC_PMKSA: change the PMKSA list and hand all of it to the
 * driver.  A new entry for a BSSID already listed replaces it; when the
 * list is full the oldest entry goes.
 */
static int
fmac_pmksa_ioctl(struct ieee80211vap *vap, u_long cmd,
    struct ieee80211req *ireq)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_pmksa_req req;
	struct fmac_state *fs;
	int error, i;

	if (cmd != SIOCS80211)
		return (EINVAL);
	error = ieee80211_priv_check_vap_manage(cmd, vap, vap->iv_ifp);
	if (error != 0)
		return (error);
	fs = fmac_lookup(ic);
	if (fs == NULL)
		return (ENXIO);
	if (fs->fs_ops->fmop_set_pmksa == NULL ||
	    vap->iv_opmode != IEEE80211_M_STA) {
		error = EOPNOTSUPP;
		goto out;
	}
	if (ireq->i_val != IEEE80211_PMKSA_FLUSH) {
		if (ireq->i_len != sizeof(req)) {
			error = EINVAL;
			goto out;
		}
		error = copyin(ireq->i_data, &req, sizeof(req));
		if (error != 0)
			goto out;
	}

	sx_xlock(&fs->fs_pmksa_sx);
	for (i = 0; i < fs->fs_npmksa; i++)
		if (ireq->i_val != IEEE80211_PMKSA_FLUSH &&
		    IEEE80211_ADDR_EQ(fs->fs_pmksa[i].pm_bssid, req.ip_bssid))
			break;
	switch (ireq->i_val) {
	case IEEE80211_PMKSA_ADD:
	case IEEE80211_PMKSA_DEL:
		/* Drop the BSSID's old entry, or the oldest if full. */
		if (i == fs->fs_npmksa && ireq->i_val == IEEE80211_PMKSA_ADD &&
		    fs->fs_npmksa == IEEE80211_FMAC_MAX_PMKSA)
			i = 0;
		if (i < fs->fs_npmksa) {
			memmove(&fs->fs_pmksa[i], &fs->fs_pmksa[i + 1],
			    (fs->fs_npmksa - i - 1) * sizeof(fs->fs_pmksa[0]));
			fs->fs_npmksa--;
		}
		if (ireq->i_val == IEEE80211_PMKSA_ADD) {
			IEEE80211_ADDR_COPY(
			    fs->fs_pmksa[fs->fs_npmksa].pm_bssid, req.ip_bssid);
			memcpy(fs->fs_pmksa[fs->fs_npmksa].pm_pmkid,
			    req.ip_pmkid, sizeof(req.ip_pmkid));
			fs->fs_npmksa++;
		}
		break;
	case IEEE80211_PMKSA_FLUSH:
		fs->fs_npmksa = 0;
		break;
	default:
		error = EINVAL;
		break;
	}
	if (error == 0)
		error = fs->fs_ops->fmop_set_pmksa(ic, fs->fs_pmksa,
		    fs->fs_npmksa);
	sx_xunlock(&fs->fs_pmksa_sx);
out:
	fmac_release(fs);
	return (error);
}

static int
fmac_extauth_ioctl(struct ieee80211vap *vap, u_long cmd,
    struct ieee80211req *ireq)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_extauth_status st;
	struct fmac_state *fs;
	const struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	uint8_t *frame;
	uint16_t chan;
	bool have;
	int error;

	fs = fmac_lookup(ic);
	if (fs == NULL)
		return (ENXIO);
	have = fs->fs_ops->fmop_mgmt_tx != NULL &&
	    vap->iv_opmode == IEEE80211_M_STA;

	if (ireq->i_type == IEEE80211_IOC_EXTAUTH_CAPS) {
		error = 0;
		if (cmd == SIOCG80211)
			ireq->i_val = have ? IEEE80211_EXTAUTH_CAP_SAE : 0;
		else
			error = EINVAL;
		goto out;
	}
	if (cmd != SIOCS80211) {
		error = EINVAL;
		goto out;
	}
	error = ieee80211_priv_check_vap_manage(cmd, vap, vap->iv_ifp);
	if (error != 0)
		goto out;
	if (!have) {
		error = EOPNOTSUPP;
		goto out;
	}

	switch (ireq->i_type) {
	case IEEE80211_IOC_MGMT_TX:
		if (ireq->i_len < sizeof(struct ieee80211_frame) + 6 ||
		    ireq->i_len > IEEE80211_MGMT_TX_MAXLEN) {
			error = EINVAL;
			break;
		}
		frame = malloc(ireq->i_len, M_TEMP, M_WAITOK | M_ZERO);
		error = copyin(ireq->i_data, frame, ireq->i_len);
		wh = (const struct ieee80211_frame *)frame;
		/* Only Authentication frames: that is all SAE needs. */
		if (error == 0 &&
		    (wh->i_fc[0] & (IEEE80211_FC0_TYPE_MASK |
		    IEEE80211_FC0_SUBTYPE_MASK)) !=
		    (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH))
			error = EINVAL;
		if (error == 0) {
			ni = vap->iv_bss;
			chan = (ni != NULL && ni->ni_chan != NULL &&
			    ni->ni_chan != IEEE80211_CHAN_ANYC) ?
			    ni->ni_chan->ic_ieee : ic->ic_curchan->ic_ieee;
			error = fs->fs_ops->fmop_mgmt_tx(ic, frame,
			    ireq->i_len, chan);
		}
		free(frame, M_TEMP);
		break;
	case IEEE80211_IOC_EXTAUTH_STATUS:
		if (ireq->i_len != sizeof(st)) {
			error = EINVAL;
			break;
		}
		error = copyin(ireq->i_data, &st, sizeof(st));
		if (error == 0 && st.is_ssid_len > sizeof(st.is_ssid))
			error = EINVAL;
		if (error == 0)
			error = fs->fs_ops->fmop_extauth_status(ic,
			    (uint16_t)ireq->i_val, st.is_bssid, st.is_ssid,
			    st.is_ssid_len);
		break;
	default:
		error = EINVAL;
		break;
	}
out:
	fmac_release(fs);
	return (error);
}

/* A station vap's ioctl handler: SAE and PMKSA requests, then net80211. */
static int
fmac_vap_ioctl(if_t ifp, u_long cmd, caddr_t data)
{
	struct ieee80211vap *vap = if_getsoftc(ifp);
	struct ieee80211req *ireq = (struct ieee80211req *)data;

	if ((cmd == SIOCS80211 || cmd == SIOCG80211) &&
	    (ireq->i_type == IEEE80211_IOC_MGMT_TX ||
	    ireq->i_type == IEEE80211_IOC_EXTAUTH_STATUS ||
	    ireq->i_type == IEEE80211_IOC_EXTAUTH_CAPS))
		return (fmac_extauth_ioctl(vap, cmd, ireq));
	if ((cmd == SIOCS80211 || cmd == SIOCG80211) &&
	    ireq->i_type == IEEE80211_IOC_PMKSA)
		return (fmac_pmksa_ioctl(vap, cmd, ireq));
	if (cmd == SIOCG80211 && ireq->i_type == IEEE80211_IOC_ASSOC_REQ_IE)
		return (fmac_assoc_ie_ioctl(vap, ireq));
	/* A scan asked for by ioctl runs on the firmware, not from the cache. */
	if (cmd == SIOCS80211 && ireq->i_type == IEEE80211_IOC_SCAN_REQ) {
		struct ieee80211com *ic = vap->iv_ic;

		IEEE80211_LOCK(ic);
		ic->ic_lastscan = ticks - vap->iv_scanvalid - 1;
		IEEE80211_UNLOCK(ic);
	}
	return (ieee80211_ioctl(ifp, cmd, data));
}
