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
#include <sys/taskqueue.h>
#include <sys/callout.h>
#include <sys/endian.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/if_media.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_input.h>
#include <net80211/ieee80211_proto.h>
#include <net80211/ieee80211_regdomain.h>

#include "ieee80211_fullmac.h"

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
	int	(*fs_save_setregdomain)(struct ieee80211com *,
		    struct ieee80211_regdomain *, int,
		    struct ieee80211_channel []);
	int	(*fs_save_reset)(struct ieee80211vap *, u_long);
	struct ieee80211vap *(*fs_save_vap_create)(struct ieee80211com *,
		    const char [IFNAMSIZ], int, enum ieee80211_opmode, int,
		    const uint8_t [IEEE80211_ADDR_LEN],
		    const uint8_t [IEEE80211_ADDR_LEN]);

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
	int				    fs_ap_want;
	struct ieee80211_fmac_ap	    fs_ap_conf;
	STAILQ_HEAD(, fmac_ap_evt)	    fs_ap_evts;
	u_int				    fs_ap_nevts;
	int	(*fs_save_raw_xmit)(struct ieee80211_node *, struct mbuf *,
		    const struct ieee80211_bpf_params *);

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
static int	fmac_setregdomain(struct ieee80211com *,
		    struct ieee80211_regdomain *, int,
		    struct ieee80211_channel []);
static void	fmac_country_task(void *, int);
static int	fmac_reset(struct ieee80211vap *, u_long);
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
static int	fmac_key_set(struct ieee80211vap *,
		    const struct ieee80211_key *);
static int	fmac_key_delete(struct ieee80211vap *,
		    const struct ieee80211_key *);

/* ------------------------------------------------------------------
 * Attach / detach
 * ------------------------------------------------------------------ */

static void	fmac_scan_start_shim(struct ieee80211com *);
static void	fmac_scan_end_shim(struct ieee80211com *);
static void	fmac_ap_task(void *, int);
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
    const struct ieee80211_fullmac_ops *ops, uint32_t caps)
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
	if (ic->ic_vap_create == NULL) {
		ic_printf(ic, "%s: FullMAC attach refused: set ic_vap_create "
		    "before calling ieee80211_fmac_attach\n", ops->fmop_name);
		return (EINVAL);
	}

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

	/* Every vap the driver creates is set up here as well. */
	fs->fs_save_vap_create = ic->ic_vap_create;
	ic->ic_vap_create = fmac_vap_create;

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
	TASK_INIT(&fs->fs_ap_task, 0, fmac_ap_task, fs);
	STAILQ_INIT(&fs->fs_ap_evts);
	if (ops->fmop_start_ap != NULL && ops->fmop_stop_ap != NULL) {
		ic->ic_caps |= IEEE80211_C_HOSTAP;
		fs->fs_save_raw_xmit = ic->ic_raw_xmit;
		ic->ic_raw_xmit = fmac_raw_xmit;
	}

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
	ic->ic_vap_create = fs->fs_save_vap_create;
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
	taskqueue_drain(taskqueue_thread, &fs->fs_ap_task);
	{
		struct fmac_ap_evt *fe;

		while ((fe = STAILQ_FIRST(&fs->fs_ap_evts)) != NULL) {
			STAILQ_REMOVE_HEAD(&fs->fs_ap_evts, fe_link);
			free(fe, M_80211_FMAC);
		}
	}
	mtx_destroy(&fs->fs_ap_mtx);

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
 *   - roaming is the device's (IEEE80211_ROAMING_DEVICE);
 *   - net.wlan.N.fullmac_pmk exists when the driver can take a PMK.
 */
static struct ieee80211vap *
fmac_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211vap *vap;

	if (fs == NULL)
		return (NULL);
	vap = fs->fs_save_vap_create(ic, name, unit, opmode, flags, bssid,
	    mac);
	if (vap == NULL) {
		fmac_release(fs);
		return (NULL);
	}

	if (fs->fs_save_newstate == NULL)
		fs->fs_save_newstate = vap->iv_newstate;
	if (fs->fs_save_key_set == NULL)
		fs->fs_save_key_set = vap->iv_key_set;
	if (fs->fs_save_key_delete == NULL)
		fs->fs_save_key_delete = vap->iv_key_delete;
	if (fs->fs_save_reset == NULL)
		fs->fs_save_reset = vap->iv_reset;
	vap->iv_newstate   = fmac_newstate;
	vap->iv_key_set    = fmac_key_set;
	vap->iv_key_delete = fmac_key_delete;
	vap->iv_reset      = fmac_reset;

	vap->iv_flags_ext &= ~IEEE80211_FEXT_SWBMISS;
	vap->iv_roaming = IEEE80211_ROAMING_DEVICE;

	/*
	 * An access point's data never passes through ieee80211_input,
	 * so net80211 would see every station as idle and age it out of
	 * the station table after a few minutes, cutting off its
	 * traffic.  The firmware ages stations itself and reports the
	 * ones it drops.
	 */
	if (opmode == IEEE80211_M_HOSTAP)
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
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211_fmac_assoc fa;
	int rc;

	if (fs == NULL)
		return (EINVAL);

	/*
	 * Access point: start the firmware's BSS on entering RUN and stop
	 * it on leaving.  A restart (an ENETRESET from a changed setting)
	 * walks through INIT, so it stops and starts with the new values.
	 * The station logic below does not apply.
	 */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		enum ieee80211_state ostate = vap->iv_state;
		int want = FMAC_AP_NONE;

		rc = fs->fs_save_newstate(vap, nstate, arg);
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
			if (want == FMAC_AP_START)
				fmac_ap_snapshot(vap, &fs->fs_ap_conf);
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
	int rc;

	if (fs == NULL)
		return (ENETRESET);
	if (cmd == IEEE80211_IOC_POWERSAVE &&
	    fs->fs_ops->fmop_set_powersave != NULL)
		rc = fs->fs_ops->fmop_set_powersave(ic,
		    (vap->iv_flags & IEEE80211_F_PMGTON) != 0);
	else if (fs->fs_save_reset != NULL)
		rc = fs->fs_save_reset(vap, cmd);
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
	if (rc == 0)
		fs->fs_scan_active = true;
	else if (fs->fs_save_scan_start != NULL)
		fs->fs_save_scan_start(ic);
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
	if (fs->fs_scan_active) {
		fs->fs_scan_active = false;
		if (fs->fs_ops->fmop_scan_cancel != NULL)
			fs->fs_ops->fmop_scan_cancel(ic);
	}
	if (fs->fs_save_scan_end != NULL)
		fs->fs_save_scan_end(ic);
	fmac_release(fs);
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

/* firmware says the link dropped: reset to init */
int
ieee80211_fmac_link_down(struct ieee80211com *ic, uint16_t reason)
{
	struct ieee80211vap *vap;
	int n = 0;

	(void)reason;
	fmac_sig_stop(ic);
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
 * Scan-result up-call: one BSS the firmware found, described by
 * struct ieee80211_fmac_bss.  The framework builds the scan entry from
 * the IE blob and hands it straight to the scan module's scan_add, the
 * same flat path Linux brcmfmac takes with cfg80211_inform_bss_data;
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
	struct ieee80211_channel *rxchan;
	struct ieee80211_scanparams sp;
	struct ieee80211_frame wh;
	uint8_t tstamp_zero[8];
	int rssi, nf;
	bool is5g;

	if (bb == NULL || bb->fb_ies == NULL || bb->fb_ielen == 0)
		return;
	if (TAILQ_FIRST(&ic->ic_vaps) == NULL)
		return;
	if (ic->ic_scan == NULL || ic->ic_scan->ss_ops == NULL ||
	    ic->ic_scan->ss_ops->scan_add == NULL ||
	    (ic->ic_flags & IEEE80211_F_SCAN) == 0 ||
	    ic->ic_scan->ss_vap == NULL)
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

	(void)ic->ic_scan->ss_ops->scan_add(ic->ic_scan, rxchan, &sp, &wh,
	    IEEE80211_FC0_SUBTYPE_BEACON, rssi, nf);
}

/*
 * The firmware's scan has delivered every result: end net80211's scan.
 * ieee80211_scan_done alone only wakes the software scanner, which
 * then walks its whole channel list (about 10 s) while an association
 * request waits behind it, so cancel the scan too; a cancelled scan
 * still sends the scan-done notification.  Call from a context that
 * can sleep, without the com lock.
 */
void
ieee80211_fmac_scan_done(struct ieee80211com *ic)
{
	struct fmac_state *fs = fmac_lookup(ic);
	struct ieee80211vap *vap;

	if (fs != NULL) {
		fs->fs_scan_active = false;
		fmac_release(fs);
	}
	vap = (ic->ic_scan != NULL && ic->ic_scan->ss_vap != NULL) ?
	    ic->ic_scan->ss_vap : TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;
	ieee80211_scan_done(vap);
	/*
	 * Only a station's scan is cancelled.  A cancelled scan skips the
	 * scan module's end, and for an access point that end is where
	 * net80211 creates the BSS on the configured channel, so a hostap
	 * vap whose scan was cancelled never reaches RUN.
	 */
	if ((ic->ic_flags & IEEE80211_F_SCAN) &&
	    vap->iv_opmode == IEEE80211_M_STA)
		ieee80211_cancel_scan(vap);
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
	if (rsn && end - p >= 2)
		ap->fp_rsncaps = le16dec(p);
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
	}
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

/* The hostap vap stations belong to, if it is running. */
static struct ieee80211vap *
fmac_ap_vap(struct ieee80211com *ic)
{
	struct ieee80211vap *vap;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
		if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
		    vap->iv_state == IEEE80211_S_RUN)
			return (vap);
	return (NULL);
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
		explicit_bzero(&ap, sizeof(ap));
	} else if (want == FMAC_AP_STOP) {
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
		} else if ((vap = fmac_ap_vap(ic)) != NULL) {
			if (fe->fe_type == FMAC_EVT_LEAVE)
				fmac_ap_leave(vap, fe);
			else
				fmac_ap_join(vap, fe);
		}
		free(fe, M_80211_FMAC);
	}
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
