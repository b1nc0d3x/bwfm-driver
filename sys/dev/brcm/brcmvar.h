/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC (brcm) per-instance state and the bus interface.
 * brcm.c is the bus-agnostic core (chip table, BCDC dcmds and iovars,
 * net80211 attach, joins and key install); if_brcm_usb.c,
 * if_brcm_sdio.c and if_brcm_pci.c are the transports.  Each fills in
 * a brcm_bus_ops vtable before calling brcm_attach().
 */

#ifndef _DEV_BRCM_BRCMVAR_H_
#define _DEV_BRCM_BRCMVAR_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
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
	 *              SET_VAR.  MSGBUF uses the same `name\0 || value`
	 *              payload over GET_VAR / SET_VAR (as Linux fwil.c
	 *              does for every bus); it just carries the dcmd in
	 *              an IOCTLPTR_REQ ring entry, not a BCDC header.
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
	 * terminator event clears sc_scan_busy; on SDIO nothing else
	 * polls rx while the scan runs.  Transports with their own
	 * async rx (USB bulk completion, PCIe doorbell) leave it NULL.
	 */
	void	(*bs_pump_rx)(struct brcm_softc *, int max_ms,
		    volatile int *until_clear);

	/*
	 * brcm_pci-only: purge msgbuf flow rings, and wait for queued
	 * EAPOL frames to drain before a key install.  Left NULL by the
	 * SDIO/USB transports.
	 */
	void	(*bs_flowring_purge)(struct brcm_softc *);
	int	(*bs_wait_eapol_drain)(struct brcm_softc *, int timeout_ms);
};

/*
 * net80211 vap wrapper.  Saves the parent newstate so the brcm driver
 * can chain into the firmware before invoking the net80211 default.
 */
struct brcm_vap {
	struct ieee80211vap	bv_vap;	/* net80211 base vap */
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
	TAILQ_ENTRY(brcm_ctl_req)	link;	/* list linkage */
	uint16_t			reqid;	/* matches a reply to its request */
	bool				done;	/* set true when the reply arrives */
	void				*reply_buf;	/* where to copy the reply */
	size_t				reply_capacity;	/* size of reply_buf */
	size_t				reply_actlen;	/* actual reply length */
	uint32_t			reply_flags;	/* reply header flags */
	int32_t				reply_status;	/* firmware status code */
};
TAILQ_HEAD(brcm_ctl_pending, brcm_ctl_req);

/*
 * Per-device state shared between brcm.c and if_brcm_usb.c.  Bus-
 * private state (USB endpoints, xfer pointers, etc.) lives in the
 * transport softc which embeds a brcm_softc as its first member.
 */

/*
 * One firmware key install or remove, copied out of the net80211 key.
 * net80211 calls the key callbacks with its node lock (a plain mutex)
 * held, but the firmware command sleeps -- doing it right there panics
 * the kernel ("sleeping thread holds ... node").  So the callbacks fill
 * one of these and hand it to brcm_key_task, which runs later with no
 * lock held.
 */
struct brcm_key_op {
	TAILQ_ENTRY(brcm_key_op) ko_link;
	uint32_t		 ko_index;	/* key slot */
	uint32_t		 ko_algo;	/* BRCM_CRYPTO_ALGO_* */
	uint32_t		 ko_flags;	/* BRCM_WSEC_* */
	uint32_t		 ko_key_len;	/* valid bytes in ko_key */
	uint8_t			 ko_key[32];	/* key material */
	uint8_t			 ko_ea[6];	/* peer or group address */
	bool			 ko_wait_eapol;	/* drain EAPOL TX first */
	bool			 ko_authorize;	/* authorize the peer after */
	uint8_t			 ko_auth_mac[6];/* peer to authorize */
};
TAILQ_HEAD(brcm_key_ops, brcm_key_op);

struct brcm_softc {
	struct ieee80211com		 sc_ic;	/* net80211 common state */
	device_t			 sc_dev;	/* backing device */
	const struct brcm_bus_ops	*sc_bus_ops;	/* transport operations table */
	int				 sc_debug;	/* debug verbosity level */
	bool				 sc_ic_attached;	/* net80211 attach done */
	bool				 sc_dying;	/* detach in progress */
	bool				 sc_tasks_inited;	/* TASK_INITs done */
	uint16_t			 sc_bcdc_reqid;	/* next control request id */
	uint32_t			 sc_evt_count;	/* count of firmware events seen */
	/*
	 * Verification counters (dev.brcm.N.event_stats): events by type,
	 * and for each task how often it was requested and how many
	 * requests its runs covered (the taskqueue "pending" sum).  The
	 * two must match, or a request was lost.
	 */
	uint32_t			 sc_evt_by_type[128];
	uint32_t			 sc_escan_done_evts;
	uint32_t			 sc_scan_done_reqs, sc_scan_done_cover;
	uint32_t			 sc_link_reqs, sc_link_cover;
	uint32_t			 sc_assoc_reqs, sc_assoc_cover;
	uint8_t				 sc_macaddr[IEEE80211_ADDR_LEN];	/* our MAC address */

	struct mtx			 sc_mtx;	/* main softc lock */
	struct mtx			 sc_ctl_mtx;	/* control-request lock */
	struct brcm_ctl_pending		 sc_ctl_pending;	/* waiting control requests */
	/*
	 * Outstanding dcmd_get / dcmd_set callers (sysctl handlers etc.
	 * can sleep here for seconds).  Detach must wait for this to drain
	 * before destroying sc_ctl_mtx; the dying flag plus per-request
	 * wakeup() lets the sleepers bail promptly.
	 */
	uint32_t			 sc_in_flight_dcmd;

	const struct brcm_chip_info	*sc_chip;	/* matched chip-table entry */
	/* Last scanned AP's chanspec, in this firmware's encoding. */
	uint8_t				 sc_join_cs_bssid[6];
	uint16_t			 sc_join_cs;
	struct brcm_bootrom_id		 sc_brom;	/* boot ROM identity */
	/*
	 * Transport-supplied firmware basename, used by
	 * brcm_upload_clm_blob to find the matching CLM blob.  SDIO sets
	 * it to "brcmfmac<r->fw_name>-sdio" (e.g. brcmfmac43455-sdio);
	 * USB sets it to bsc->sc_chip->fwname (e.g. brcmfmac43236b).  An
	 * empty string skips the CLM upload, for firmware without one.
	 */
	char				 sc_fw_basename[64];

	struct task			 sc_scan_done_task;	/* deferred scan-done work */
	struct task			 sc_link_task;	/* deferred link-change work */
	bool				 sc_link_up;	/* link is currently up */

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
	bool				 sc_wlc_up;	/* brcm_pci: fw pub->up mirror */
	bool				 sc_sae_join;	/* WPA3-SAE join selected (else WPA2-PSK) */

	/*
	 * Join-in-flight guard.  Set at brcm_join_open / brcm_join_wpa2
	 * entry, cleared by LINK or DISASSOC event in brcm_handle_event
	 * (terminator of the chip-driven auth+assoc+4-way sequence).
	 * Refuses overlapping join attempts with EAGAIN: back-to-back
	 * joins overlap SET_DOWN with an in-flight 4-way handshake and
	 * can wedge the chip or panic the host.
	 */
	int				 sc_join_busy;
	time_t				 sc_join_busy_ts;	/* when join_busy was set */
	time_t				 sc_last_assoc_ts;	/* fmop_assoc rate-limit */
	time_t				 sc_last_disassoc_ts;	/* fmop_disassoc rate-limit */

	/*
	 * Firmware WPA supplicant capability.  Probed at bringup by
	 * brcm_probe_wpa_sup(): some fw revisions reject the sup_wpa
	 * iovar entirely (BCM43455 fw 7.45.x returns -23 on set=0),
	 * others accept it but need specific values.  sc_sup_wpa_ok
	 * is true iff the driver can toggle the mode; join paths must
	 * NOT touch sup_wpa when this is false or the firmware may
	 * fall into an ambiguous state.  sc_sup_wpa_current tracks
	 * what we last observed the firmware to hold (0 = host EAPOL,
	 * 1 = in-fw supplicant) so join_wpa2 knows whether to install
	 * PMK via wsec_pmk (in-fw) or seed keys via host EAPOL.
	 */
	bool				 sc_sup_wpa_ok;
	uint32_t			 sc_sup_wpa_current;

	/*
	 * Safety gate on the raw iovar_set / cdev CMD52/CMD53 paths.
	 * Default 0 (off); set `dev.brcm.<n>.unsafe=1` before poking the
	 * chip through those sysctls / ioctls.  This chip family has a
	 * large CVE backlog (Broadpwn, Kr00k, FragAttacks) reachable
	 * through arbitrary iovar_set payloads, so the driver shouldn't
	 * hand root (much less every jail with PRIV_DRIVER) a live pipe
	 * to them without an explicit opt-in.  Compile with
	 * `options BRCM_UNSAFE_IOVARS_DEFAULT_ON` to default it on.
	 */
	int				 sc_unsafe_iovars;

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

	/*
	 * Deferred firmware key work.  Filled by the key callbacks (which
	 * run under net80211's node lock) and drained by sc_key_task on
	 * taskqueue_thread, where sleeping for the firmware is allowed.
	 */
	struct mtx			 sc_key_mtx;	/* protects sc_key_ops */
	struct brcm_key_ops		 sc_key_ops;
	struct task			 sc_key_task;

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
 * Debug levels — gated on sc->sc_debug via the per-instance
 * dev.brcm.<n>.debug sysctl.  Level 0 prints milestones and errors;
 * level 1 adds protocol traces (newstate, event-header summaries);
 * level 2 adds high-volume data-path noise; level 3 is the
 * everything-bucket for protocol forensics.  Lower-level prints
 * outrank higher: a DPRINTF(level=1, ...) fires when sc_debug >= 1.
 */
#define	DPRINTF(sc, level, ...)	do {					\
	if ((sc)->sc_debug >= (level))					\
		device_printf((sc)->sc_dev, __VA_ARGS__);		\
} while (0)

MALLOC_DECLARE(M_BRCM);

extern const struct brcm_chip_info brcm_chip_table[];

/* Bus-agnostic entry points implemented in brcm.c. */
const struct brcm_chip_info *brcm_chip_lookup(uint32_t chip, uint32_t chiprev);
int	brcm_attach(struct brcm_softc *);
void	brcm_detach(struct brcm_softc *);
/*
 * Common transport-teardown: must be the FIRST act of every
 * transport's detach path.  Idempotent across attach-fail paths
 * where the mutex/pending list may or may not be initialized.
 * See brcm.c for the full contract.
 */
void	brcm_transport_teardown(struct brcm_softc *);
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

/* Chanspec helpers (both D11N and D11AC encodings). */
bool	brcm_chanspec_is_5ghz(uint16_t chanspec);
uint8_t	brcm_chanspec_to_chan(uint16_t chanspec);
uint16_t brcm_chan_to_chanspec_d11ac(uint8_t chan);
uint16_t brcm_chan_to_chanspec_d11n(uint8_t chan);
uint16_t brcm_chan_to_chanspec(struct brcm_softc *sc, uint8_t chan);
struct mbuf;
int	brcm_deencap_80211(struct mbuf **mp);

/* Helper: turn a host buffer into a BCDC dcmd frame ready for bs_txctl. */
size_t	brcm_proto_bcdc_pack(uint16_t reqid, uint32_t cmd, uint32_t flags,
	    const void *payload, size_t payload_len, void *out, size_t out_cap);

#endif /* _DEV_BRCM_BRCMVAR_H_ */
