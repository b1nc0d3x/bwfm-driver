/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC (brcm) per-instance state + bus-abstraction
 * interface.  The brcm driver is split into:
 *
 *   brcm.c          Bus-agnostic core: chip-info table, BCDC
 *                   proto helpers, net80211 ifattach / vap glue.
 *   if_brcm_usb.c   USB bus glue: probe / attach, endpoint
 *                   discovery, bulk + control xfer setup, the EP0
 *                   ctlrx kthread, bus-ops vtable supplied to the
 *                   core.
 *
 * The interface contract is the `brcm_bus_ops` vtable filled in by
 * each transport driver before calling brcm_attach().  Future SDIO /
 * PCIe ports plug into the same shape.
 */

#ifndef _DEV_BRCM_BRCMVAR_H_
#define _DEV_BRCM_BRCMVAR_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>	/* log() */
#include <sys/syslog.h>	/* LOG_INFO */
#include <sys/taskqueue.h>
#include <sys/mbuf.h>

#include <net80211/ieee80211_var.h>

#include "brcmreg.h"

struct brcm_softc;

/*
 * Bus operations vtable.  Each transport (USB, SDIO, PCIe) supplies
 * one of these so the brcm core can speak to the chip without caring
 * about the underlying wire.  All entries return 0 on success.
 *
 *   bs_txctl   Send a BCDC dcmd request out over the control path
 *              (USB EP0 vendor-class).  Synchronous: returns once the
 *              chip has acked the request frame.
 *   bs_rxctl   Block until a BCDC dcmd reply lands.  On success copies
 *              up to *lenp bytes into buf and updates *lenp with the
 *              actual payload length.
 *   bs_txdata  Push a host-built data mbuf (BCDC header already
 *              prepended by the caller) out over the bulk OUT pipe.
 *              The mbuf is consumed regardless of return value.
 *   bs_stop    Tear down outstanding xfers and any bus-side threads
 *              so detach can free softc memory safely.
 */
struct brcm_bus_ops {
	int	(*bs_txctl)(struct brcm_softc *, const void *buf, size_t len);
	int	(*bs_rxctl)(struct brcm_softc *, void *buf, size_t *lenp,
		    int timeout_ms);
	int	(*bs_txdata)(struct brcm_softc *, struct mbuf *);
	void	(*bs_stop)(struct brcm_softc *);

	/*
	 * Optional protocol-layer overrides.  When non-NULL, the brcm.c
	 * front-ends hand the request to the transport instead of running
	 * the in-core BCDC path.  USB leaves all four NULL; PCIe MSGBUF
	 * chips install them to drive their own command machinery.
	 *
	 * bs_dcmd_*    pass numeric WLC opcodes (BRCM_C_UP, BRCM_C_SET_KEY,
	 *              etc.) with an opaque value buffer.  For BCDC the
	 *              wire format is `brcm_bcdc_dcmd` header + value;
	 *              for MSGBUF the value sits in a SUBMIT-ring entry.
	 *
	 * bs_iovar_*   pass an iovar identified by NUL-terminated name.
	 *              For BCDC the host frames it as
	 *              `name\0 || value` payload over BRCM_C_GET_VAR /
	 *              SET_VAR.  MSGBUF chips don't carry a chip-side
	 *              iovar string table — the transport translates the
	 *              name to a numeric ID against its own host-side
	 *              fwil-style table before pushing the MSGBUF entry.
	 *              Returning ENOENT lets brcm.c fall back to the
	 *              dcmd-shaped path for any name the transport
	 *              hasn't mapped yet (so the BCDC code keeps working
	 *              when both sets of hooks are installed).
	 */
	int	(*bs_dcmd_get)(struct brcm_softc *, uint32_t cmd, void *buf,
		    size_t *lenp);
	int	(*bs_dcmd_set)(struct brcm_softc *, uint32_t cmd,
		    const void *buf, size_t len);
	int	(*bs_iovar_get)(struct brcm_softc *, const char *name,
		    void *buf, size_t *lenp);
	int	(*bs_iovar_set)(struct brcm_softc *, const char *name,
		    const void *buf, size_t len);

	/*
	 * Drain pending rx frames for up to `max_ms` milliseconds, or
	 * until `*until_clear` becomes 0 (whichever fires first).
	 * Used by brcm_dispatch_scan to pump ESCAN_RESULTs until the
	 * terminator event clears sc_scan_busy.  Without this the
	 * fmop_scan_start path returns immediately, no one polls
	 * SDPCM rx, and scan results never reach the driver.
	 * Transport may set NULL if it has its own async rx (USB
	 * bulk completion path, PCIe doorbell).
	 */
	void	(*bs_pump_rx)(struct brcm_softc *, int max_ms,
		    volatile int *until_clear);

	/*
	 * Synchronously tear down every host-side TX flowring the
	 * transport is currently tracking.  For PCIe MSGBUF this fires
	 * FLOW_RING_DELETE on each OPEN flowring and waits for the
	 * fw CMPLT (marks the slot CLOSED so a subsequent TX allocates
	 * a fresh ring).  Called from brcm_join_wpa2_host_eapol right
	 * after WLC_DOWN so any prior-generation flowring is retired
	 * before the fw rebuilds its ring tables during the new join.
	 * Transports without a flowring model (USB/SDIO/BCDC) leave
	 * this NULL.
	 */
	void	(*bs_flowring_purge)(struct brcm_softc *);
};

/*
 * net80211 vap wrapper.  Saves the parent newstate so the brcm driver
 * can chain into the firmware before invoking the net80211 default.
 */
struct brcm_vap {
	struct ieee80211vap	bv_vap;
	int			(*bv_newstate)(struct ieee80211vap *,
				    enum ieee80211_state, int);
};
#define	BRCM_VAP(vap)	((struct brcm_vap *)(vap))

/*
 * Pending control request.  A brcm_dcmd_get / brcm_dcmd_set call
 * inserts one of these on sc_ctl_pending while sleeping; the bus
 * rxctl path wakes the sleeper when a reply matching reqid lands.
 */
struct brcm_ctl_req {
	TAILQ_ENTRY(brcm_ctl_req)	link;
	uint16_t			reqid;
	bool				done;
	void				*reply_buf;
	size_t				reply_capacity;
	size_t				reply_actlen;
	uint32_t			reply_flags;
	int32_t				reply_status;
};
TAILQ_HEAD(brcm_ctl_pending, brcm_ctl_req);

/*
 * Per-device state shared between brcm.c and if_brcm_usb.c.  Bus-
 * private state (USB endpoints, xfer pointers, etc.) lives in the
 * transport softc which embeds a brcm_softc as its first member.
 */
struct brcm_softc {
	struct ieee80211com		 sc_ic;
	device_t			 sc_dev;
	const struct brcm_bus_ops	*sc_bus_ops;
	int				 sc_debug;
	bool				 sc_ic_attached;
	bool				 sc_dying;
	uint16_t			 sc_bcdc_reqid;
	uint32_t			 sc_evt_count;
	uint8_t				 sc_macaddr[IEEE80211_ADDR_LEN];

	struct mtx			 sc_mtx;
	struct mtx			 sc_ctl_mtx;
	struct brcm_ctl_pending		 sc_ctl_pending;
	/*
	 * Outstanding dcmd_get / dcmd_set callers (sysctl handlers etc.
	 * can sleep here for seconds).  Detach must wait for this to drain
	 * before destroying sc_ctl_mtx; the dying flag plus per-request
	 * wakeup() lets the sleepers bail promptly.
	 */
	uint32_t			 sc_in_flight_dcmd;

	const struct brcm_chip_info	*sc_chip;
	struct brcm_bootrom_id		 sc_brom;

	struct task			 sc_scan_done_task;

	/*
	 * Scan dispatch task.  fmop_scan_start is invoked by net80211 from
	 * ic_scan_start under IEEE80211_LOCK, and the DCMD path (sx_xlock +
	 * cv_wait) can't safely be called under that lock — the ISR that
	 * would signal cv_dcmd may itself need locks that block behind
	 * IEEE80211_LOCK, resulting in a hard wedge (2026-07-20 fbsdmac
	 * scan-wedge, requires physical reboot).
	 *
	 * Defer the escan iovar send to taskqueue_thread.  fmop_scan_start
	 * queues + returns 0 immediately.  brcm_scan_task runs the DCMD
	 * with no net80211 locks held.
	 */
	struct task			 sc_scan_task;
	struct task			 sc_link_task;
	bool				 sc_link_up;

	/*
	 * Fw data-plane state.  Set true after we send BRCM_C_UP,
	 * cleared after BRCM_C_DOWN.  brcm_parent uses this to avoid
	 * re-issuing BRCM_C_UP on every SIOCS* that hits ic_parent.
	 * Fw's `_wlc_scan_request_ex` returns -EBUSY when
	 * wlc->pub->up==0, so any scan issued before UP silently
	 * vanishes and net80211 wedges waiting for ESCAN_RESULT.
	 * (Confirmed 2026-07-19 via Ghidra decomp of AirPortBrcmNIC
	 * — see project_brcm_pci_scan_wedge_root_cause memory.)
	 */
	bool				 sc_wlc_up;

	/*
	 * brcm_parent runs under net80211's IEEE80211_LOCK; our msgbuf
	 * DCMD path sleeps on sc_ctl_mtx.  Firing BRCM_C_UP directly
	 * from brcm_parent deadlocks.  Defer to taskqueue_thread; the
	 * task reads sc_parent_want_up and issues the DCMD without
	 * holding any net80211 lock.
	 */
	struct task			 sc_parent_task;
	bool				 sc_parent_want_up;

	/*
	 * Scan-in-flight guard.  Linux brcmfmac
	 * (BRCMF_SCAN_STATUS_BUSY in cfg80211.c:1524) rejects
	 * overlapping scans because the chip is single-scan.
	 * Set by transport at cmd_scan entry, cleared either by
	 * the terminator ESCAN_RESULT (status COMPLETE/ABORT)
	 * routed through brcm_handle_event, or by the transport's
	 * own poll-loop timeout — whichever fires first.
	 */
	int				 sc_scan_busy;

	/*
	 * Join-in-flight guard.  Set at brcm_join_open / brcm_join_wpa2
	 * entry, cleared by LINK or DISASSOC event in brcm_handle_event
	 * (terminator of the chip-driven auth+assoc+4-way sequence).
	 * Refuses overlapping join attempts with EAGAIN -- back-to-back
	 * joins overlap SET_DOWN with an in-flight 4-way handshake and
	 * wedge the chip / panic the host (2026-06-26 PM regression).
	 */
	int				 sc_join_busy;
	time_t				 sc_join_busy_ts;	/* when join_busy was set */
	time_t				 sc_last_assoc_ts;	/* fmop_assoc rate-limit */
	time_t				 sc_last_disassoc_ts;	/* fmop_disassoc rate-limit */
	time_t				 sc_last_key_ts;	/* PTK/GTK install stamp */

	/*
	 * Join / leave dispatch deferral.  fmop_assoc + fmop_disassoc
	 * are called from the framework's newstate shim with
	 * IEEE80211_LOCK held; the BCDC dcmd path sleeps, so each
	 * dispatch stages here and runs on taskqueue_thread.
	 */
	struct task			 sc_assoc_task;
	struct ieee80211vap		*sc_assoc_vap;
	struct task			 sc_disassoc_task;
	uint16_t			 sc_disassoc_reason;	/* IEEE80211 reason */
	struct task			 sc_post_assoc_task;	/* Linux post-ASSOC iovar GETs */

	/* Target of the most-recent direct join. */
	uint8_t				 sc_join_bssid[6];
	char				 sc_join_ssid[BRCM_MAX_SSID_LEN + 1];
	uint8_t				 sc_join_ssid_len;

	/* WPA secret material staged from userspace. */
	char				 sc_wpa_pmk[64];
	bool				 sc_wpa_set;
	uint8_t				 sc_wpa_pmk_raw[32];
	bool				 sc_wpa_pmk_raw_set;

	/*
	 * When true, brcm_join_wpa2_host_eapol switches wpa_auth to
	 * WPA3_AUTH_SAE_PSK and lets the chip run SAE (fw offload).
	 * Set via dev.<drv>.N.sae_join sysctl before the next assoc
	 * attempt.  Cleared automatically after LINK-up.
	 */
	bool				 sc_sae_join;

	/*
	 * Per-instance scratch for the iovar_get / iovar_set sysctls.
	 * Held here (not as file-scope statics) so multiple adapters
	 * do not stomp each other's last-fetched value.  Guarded by
	 * sc_ctl_mtx.
	 */
#define	BRCM_IOVAR_DUMP_MAX	256
	char				 sc_iovar_name[64];
	uint8_t				 sc_iovar_value[BRCM_IOVAR_DUMP_MAX];
	size_t				 sc_iovar_value_len;

	/*
	 * sup_dump scratch: paired with the patched firmware (see
	 * tools/patch_sup_dump.py).  Writes parse "OFFSET LENGTH",
	 * issue a GET on the injected "sup_dump" iovar with those 8
	 * bytes as params, and stash the reply here.  Reads return
	 * the most recent dump as hex.  Guarded by sc_ctl_mtx.
	 */
#define	BRCM_SUP_DUMP_MAX	256
	uint8_t				 sc_sup_dump[BRCM_SUP_DUMP_MAX];
	size_t				 sc_sup_dump_len;
	uint32_t			 sc_sup_dump_off;
};

/*
 * Chatter and debug output — routed through the FreeBSD kernel log(9)
 * facility, NOT device_printf().  log() writes to /dev/klog with a
 * syslog priority and is read by syslogd; kern.info goes to
 * /var/log/messages by default and does NOT clutter the boot console.
 *
 * A stock /etc/syslog.conf directs `!kernel` messages of priority info
 * and above to /var/log/messages; operators wanting a dedicated log
 * can add a rule like `!brcm_pci\n*.*  /var/log/brcm_pci.log`.
 *
 * BINFO(sc, fmt, ...) — always-on operator info line (attach banners,
 * link up/down, key install, wpa_supplicant hints).  Never on console;
 * always in /var/log/messages.
 *
 * DPRINTF(sc, level, fmt, ...) — gated on sc->sc_debug via the
 * per-instance dev.brcm{,_pci}.<n>.debug sysctl (tunable, default 0):
 *   sc_debug >= 1: level 0 — attach/bringup step trace
 *   sc_debug >= 2: level 1 — protocol trace
 *   sc_debug >= 3: level 2 — data-path chatter
 *   sc_debug >= 4: level 3 — register-poke forensics
 *
 * Genuine errors (probe/attach fail, DCMD wedges) still use
 * device_printf() so they appear on console for operator attention.
 */
#define	BINFO(sc, fmt, ...)						\
	log(LOG_INFO, "%s: " fmt, device_get_nameunit((sc)->sc_dev),	\
	    ##__VA_ARGS__)
/*
 * BRLIMIT: rate-limited error print (per call-site) capped at 1
 * message per second via ppsratecheck().  Wrap hot-path failure
 * prints that could burst if the chip enters a fault loop, so a
 * wedged chip doesn't fill /var/log/messages faster than logrotate
 * can trim it.  Goes to console via device_printf() so the operator
 * still notices; the rate cap only prevents storm.
 */
#define	BRLIMIT(sc, fmt, ...)	do {					\
	static struct timeval _brl_last;				\
	static int _brl_cnt;						\
	if (ppsratecheck(&_brl_last, &_brl_cnt, 1))			\
		device_printf((sc)->sc_dev, fmt, ##__VA_ARGS__);	\
} while (0)
#define	DPRINTF(sc, level, fmt, ...)	do {				\
	if ((sc)->sc_debug > (level))					\
		log(LOG_INFO, "%s: " fmt,				\
		    device_get_nameunit((sc)->sc_dev),			\
		    ##__VA_ARGS__);					\
} while (0)

MALLOC_DECLARE(M_BRCM);

extern const struct brcm_chip_info brcm_chip_table[];

/* Bus-agnostic entry points implemented in brcm.c. */
const struct brcm_chip_info *brcm_chip_lookup(uint32_t chip, uint32_t chiprev);
int	brcm_attach(struct brcm_softc *);
void	brcm_detach(struct brcm_softc *);
void	brcm_sysctl_attach(struct brcm_softc *);
void	brcm_runtime_iovars(struct brcm_softc *);
int	brcm_dcmd_get(struct brcm_softc *, uint32_t cmd, void *buf,
	    size_t *lenp);
int	brcm_dcmd_set(struct brcm_softc *, uint32_t cmd, const void *buf,
	    size_t len);
int	brcm_iovar_get(struct brcm_softc *, const char *name, void *buf,
	    size_t *lenp);
int	brcm_iovar_set(struct brcm_softc *, const char *name, const void *buf,
	    size_t len);
int	brcm_iovar_get_with_params(struct brcm_softc *, const char *name,
	    const void *params, size_t plen, void *buf, size_t *lenp);

/* RX dispatch: called by transport layer after stripping bulk-IN BCDC. */
void	brcm_rx_frame(struct brcm_softc *, struct mbuf *);
void	brcm_rxctl(struct brcm_softc *, const void *buf, size_t len);
/* WL_EVENT dispatch: transports with their own event framing (msgbuf
 * on PCIe) hand the payload here.  `p` is the buffer, `evpos` is the
 * offset of struct brcm_event_msg within it.  For the PCIe/msgbuf
 * layout evpos = 24 (14 B ethhdr + 10 B brcm_ethhdr). */
void	brcm_handle_event(struct brcm_softc *, const uint8_t *p, size_t len,
	    size_t evpos);

/* Chanspec helpers (pre-2014 Broadcom encoding). */
bool	brcm_chanspec_is_5ghz(uint16_t chanspec);
uint8_t	brcm_chanspec_to_chan(uint16_t chanspec);
uint16_t brcm_chan_to_chanspec_d11ac(uint8_t chan);

/* Helper: turn a host buffer into a BCDC dcmd frame ready for bs_txctl. */
size_t	brcm_proto_bcdc_pack(uint16_t reqid, uint32_t cmd, uint32_t flags,
	    const void *payload, size_t payload_len, void *out, size_t out_cap);

#endif /* _DEV_BRCM_BRCMVAR_H_ */
