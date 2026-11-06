/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC (bwfm) per-instance state and the bus interface.
 * bwfm.c is the bus-agnostic core (chip table, BCDC dcmds and iovars,
 * net80211 attach, joins and key install); if_bwfm_usb.c,
 * if_bwfm_sdio.c and if_bwfm_pci.c are the transports.  Each fills in
 * a bwfm_bus_ops vtable before calling bwfm_attach().
 */

#ifndef _DEV_BWFM_BWFMVAR_H_
#define _DEV_BWFM_BWFMVAR_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/taskqueue.h>
#include <sys/mbuf.h>

#include <net80211/ieee80211_var.h>

#include "bwfmreg.h"
#include <net80211/ieee80211_fullmac.h>

struct bwfm_softc;

/*
 * Bus operations vtable.  Each transport (USB, SDIO, PCIe) supplies
 * one of these so the bwfm core can speak to the chip without caring
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
struct bwfm_bus_ops {
	int	(*bs_txctl)(struct bwfm_softc *, const void *buf, size_t len);
	int	(*bs_rxctl)(struct bwfm_softc *, void *buf, size_t *lenp,
		    int timeout_ms);
	int	(*bs_txdata)(struct bwfm_softc *, struct mbuf *);
	void	(*bs_stop)(struct bwfm_softc *);

	/*
	 * Optional protocol-layer overrides.  When non-NULL, the bwfm.c
	 * front-ends hand the request to the transport instead of running
	 * the in-core BCDC path.  USB leaves all four NULL; PCIe MSGBUF
	 * chips install them to drive their own command machinery.
	 *
	 * bs_dcmd_*    pass numeric WLC opcodes (BWFM_C_UP, BWFM_C_SET_KEY,
	 *              etc.) with an opaque value buffer.  For BCDC the
	 *              wire format is `bwfm_bcdc_dcmd` header + value;
	 *              for MSGBUF the value sits in a SUBMIT-ring entry.
	 *
	 * bs_iovar_*   pass an iovar identified by NUL-terminated name.
	 *              For BCDC the host frames it as
	 *              `name\0 || value` payload over BWFM_C_GET_VAR /
	 *              SET_VAR.  MSGBUF uses the same `name\0 || value`
	 *              payload over GET_VAR / SET_VAR (as Linux fwil.c
	 *              does for every bus); it just carries the dcmd in
	 *              an IOCTLPTR_REQ ring entry, not a BCDC header.
	 *              Returning ENOENT lets bwfm.c fall back to the
	 *              dcmd-shaped path for any name the transport
	 *              hasn't mapped yet (so the BCDC code keeps working
	 *              when both sets of hooks are installed).
	 */
	int	(*bs_dcmd_get)(struct bwfm_softc *, uint32_t cmd, void *buf,
		    size_t *lenp);
	int	(*bs_dcmd_set)(struct bwfm_softc *, uint32_t cmd,
		    const void *buf, size_t len);
	int	(*bs_iovar_get)(struct bwfm_softc *, const char *name,
		    void *buf, size_t *lenp);
	int	(*bs_iovar_set)(struct bwfm_softc *, const char *name,
		    const void *buf, size_t len);

	/*
	 * Drain pending rx frames for up to `max_ms` milliseconds, or
	 * until `*until_clear` becomes 0 (whichever fires first).
	 * Used by bwfm_dispatch_scan to pump ESCAN_RESULTs until the
	 * terminator event clears sc_scan_busy; on SDIO nothing else
	 * polls rx while the scan runs.  Transports with their own
	 * async rx (USB bulk completion, PCIe doorbell) leave it NULL.
	 */
	void	(*bs_pump_rx)(struct bwfm_softc *, int max_ms,
		    volatile int *until_clear);

	/*
	 * bwfm_pci-only: purge msgbuf flow rings.  Left NULL by the
	 * SDIO/USB transports.
	 */
	void	(*bs_flowring_purge)(struct bwfm_softc *);
	/*
	 * Optional: a station left our access point, so drop whatever the
	 * transport keeps per peer (the PCIe transport's flow rings).
	 * Called from the event path, which may not sleep.
	 */
	void	(*bs_peer_gone)(struct bwfm_softc *, const uint8_t mac[6]);
	/* Wait for queued EAPOL frames to reach the chip. */
	int	(*bs_wait_eapol_drain)(struct bwfm_softc *, int timeout_ms);

	/*
	 * The transport cannot run with firmware power save on; bwfm then
	 * leaves power save out of the ops it gives the FullMAC framework.
	 * No transport sets it now (SDIO did until firmware 7.45.265).
	 */
	bool	bs_no_powersave;

	/*
	 * The transport cannot carry an access point's traffic.  bwfm then
	 * leaves the AP ops out, and net80211 refuses hostap vaps.
	 */
	bool	bs_no_hostap;

	/*
	 * The transport has been tested with HT and VHT channels in net80211,
	 * so bwfm offers them when the firmware reports the modes.
	 */
	bool	bs_ht;
};

/*
 * net80211 vap wrapper.  Saves the parent newstate so the bwfm driver
 * can chain into the firmware before invoking the net80211 default.
 */
struct bwfm_vap {
	struct ieee80211vap	bv_vap;	/* net80211 base vap */
	int			(*bv_newstate)(struct ieee80211vap *,
				    enum ieee80211_state, int);
};
#define	BWFM_VAP(vap)	((struct bwfm_vap *)(vap))

/*
 * Pending control request.  A bwfm_dcmd_get / bwfm_dcmd_set call
 * inserts one of these on sc_ctl_pending while sleeping; the bus
 * rxctl path wakes the sleeper when a reply matching reqid lands.
 */
struct bwfm_ctl_req {
	TAILQ_ENTRY(bwfm_ctl_req)	link;	/* list linkage */
	uint16_t			reqid;	/* matches a reply to its request */
	bool				done;	/* set true when the reply arrives */
	bool				closed;	/* waiter stopped; take no reply */
	void				*reply_buf;	/* where to copy the reply */
	size_t				reply_capacity;	/* size of reply_buf */
	size_t				reply_actlen;	/* actual reply length */
	uint32_t			reply_flags;	/* reply header flags */
	int32_t				reply_status;	/* firmware status code */
};
TAILQ_HEAD(bwfm_ctl_pending, bwfm_ctl_req);

/*
 * Per-device state shared between bwfm.c and if_bwfm_usb.c.  Bus-
 * private state (USB endpoints, xfer pointers, etc.) lives in the
 * transport softc which embeds a bwfm_softc as its first member.
 */

/*
 * One firmware key install or remove, copied out of the net80211 key.
 * net80211 calls the key callbacks with its node lock (a plain mutex)
 * held, but the firmware command sleeps -- doing it right there panics
 * the kernel ("sleeping thread holds ... node").  So the callbacks fill
 * one of these and hand it to bwfm_key_task, which runs later with no
 * lock held.
 */
struct bwfm_key_op {
	TAILQ_ENTRY(bwfm_key_op) ko_link;
	uint32_t		 ko_index;	/* key slot */
	uint32_t		 ko_algo;	/* BWFM_CRYPTO_ALGO_* */
	uint32_t		 ko_flags;	/* BWFM_WSEC_* */
	uint32_t		 ko_key_len;	/* valid bytes in ko_key */
	uint8_t			 ko_key[32];	/* key material */
	uint8_t			 ko_ea[6];	/* peer or group address */
	bool			 ko_wait_eapol;	/* drain EAPOL TX first */
	bool			 ko_authorize;	/* authorize the peer after */
	uint8_t			 ko_auth_mac[6];/* peer to authorize */
};
TAILQ_HEAD(bwfm_key_ops, bwfm_key_op);

struct bwfm_softc {
	struct ieee80211com		 sc_ic;	/* net80211 common state */
	device_t			 sc_dev;	/* backing device */
	const struct bwfm_bus_ops	*sc_bus_ops;	/* transport operations table */
	int				 sc_debug;	/* debug verbosity level */
	bool				 sc_ic_attached;	/* net80211 attach done */
	bool				 sc_dying;	/* detach in progress */
	bool				 sc_tasks_inited;	/* TASK_INITs done */
	/*
	 * Receive gate: see bwfm_rx_enter, bwfm_rx_exit, bwfm_rx_close.
	 * sc_rx_closed counts closers.
	 */
	volatile u_int			 sc_rx_closed;
	volatile u_int			 sc_rx_busy;
	uint16_t			 sc_bcdc_reqid;	/* next control request id */
	uint8_t				 sc_macaddr[IEEE80211_ADDR_LEN];	/* our MAC address */

	struct mtx			 sc_mtx;	/* main softc lock */
	struct mtx			 sc_ctl_mtx;	/* control-request lock */
	struct sx			 sc_bcdc_sx;	/* one BCDC command at a time */
	struct bwfm_ctl_pending		 sc_ctl_pending;	/* waiting control requests */
	/*
	 * Outstanding dcmd_get / dcmd_set callers (net80211 tasks etc.
	 * can sleep here for seconds).  Detach must wait for this to drain
	 * before destroying sc_ctl_mtx; the dying flag plus per-request
	 * wakeup() lets the sleepers bail promptly.
	 */
	uint32_t			 sc_in_flight_dcmd;

	const struct bwfm_chip_info	*sc_chip;	/* matched chip-table entry */
	/* Last scanned AP's chanspec, in this firmware's encoding. */
	struct {
		uint8_t		 bssid[6];
		uint16_t	 chanspec;
	}				 sc_bss_cs[32];	/* per-BSS chanspec */
	u_int				 sc_bss_cs_next;
	struct bwfm_bootrom_id		 sc_brom;	/* boot ROM identity */
	/*
	 * Transport-supplied firmware basename, used by
	 * bwfm_upload_clm_blob to find the matching CLM blob.  SDIO sets
	 * it to "brcmfmac<r->fw_name>-sdio" (e.g. brcmfmac43455-sdio);
	 * USB sets it to bsc->sc_chip->fwname (e.g. brcmfmac43236b).  An
	 * empty string skips the CLM upload, for firmware without one.
	 */
	char				 sc_fw_basename[64];

	struct task			 sc_scan_done_task;	/* deferred scan-done work */
	struct task			 sc_link_task;	/* deferred link-change work */
	bool				 sc_link_up;	/* link is currently up */
	bool				 sc_ap_up;	/* firmware runs our BSS */

	/*
	 * Scan-in-flight guard.  Linux brcmfmac
	 * (BRCMF_SCAN_STATUS_BUSY in cfg80211.c:1524) rejects
	 * overlapping scans because the chip is single-scan.
	 * Set by transport at cmd_scan entry, cleared either by
	 * the terminator ESCAN_RESULT (status COMPLETE/ABORT)
	 * routed through bwfm_handle_event, or by the transport's
	 * own poll-loop timeout — whichever fires first.
	 */
	int				 sc_scan_busy;
	time_t				 sc_scan_busy_ts;	/* when scan_busy was set */
	bool				 sc_wlc_up;	/* bwfm_pci: fw pub->up mirror */
	bool				 sc_sae_join;	/* WPA3-SAE join selected (else WPA2-PSK) */
	bool				 sc_ext_sae;	/* firmware leaves SAE to the host */
	bool				 sc_sae_pmksa;	/* SAE join presents a cached PMKID */
	uint32_t			 sc_mgmt_pktid;	/* mgmt_frame packet ids */

	/*
	 * Join-in-flight guard.  Set at bwfm_join_open / bwfm_join_wpa2
	 * entry, cleared by LINK or DISASSOC event in bwfm_handle_event
	 * (terminator of the chip-driven auth+assoc+4-way sequence).
	 * Refuses overlapping join attempts with EAGAIN: back-to-back
	 * joins overlap SET_DOWN with an in-flight 4-way handshake and
	 * can wedge the chip or panic the host.
	 */
	int				 sc_join_busy;
	time_t				 sc_join_busy_ts;	/* when join_busy was set */
	/*
	 * WLC_DISASSOCs sent, and the count when the latest join began.  A
	 * DISASSOC event with no disassoc sent since that join is the old
	 * link's, arriving late.
	 */
	volatile u_int			 sc_leave_seq;
	u_int				 sc_join_leave_seq;
	bool				 sc_join_seen;
	int				 sc_last_assoc_ticks;	/* fmop_assoc spacing */
	bool				 sc_assoc_ticks_set;
	time_t				 sc_last_disassoc_ts;	/* fmop_disassoc rate-limit */

	/*
	 * Firmware WPA supplicant capability.  Probed at bringup by
	 * bwfm_probe_wpa_sup(): some fw revisions reject the sup_wpa
	 * iovar entirely (BCM43455 fw 7.45.x returns -23 on set=0),
	 * others accept it but need specific values.  sc_sup_wpa_ok
	 * is true iff the driver can toggle the mode; join paths must
	 * NOT touch sup_wpa when this is false or the firmware may
	 * fall into an ambiguous state.  sc_sup_wpa_current tracks
	 * what we last observed the firmware to hold (0 = host EAPOL,
	 * 1 = in-fw supplicant) so join_wpa2 knows whether to install
	 * PMK via wsec_pmk (in-fw) or seed keys via host EAPOL.
	 */
	/* FullMAC ops handed to the framework: bwfm_fmops minus what the
	 * transport cannot do. */
	struct ieee80211_fullmac_ops	 sc_fmops;
	/*
	 * Radio capabilities read from the firmware at attach
	 * (bwfm_query_radio): which bands it has, and its 20 MHz 5 GHz
	 * channels.  bwfm_getradiocaps falls back to a fixed table when
	 * sc_radio_known is false.
	 */
	bool				 sc_radio_known;
	bool				 sc_radio_2g;
	bool				 sc_radio_5g;
	int				 sc_radio_n5g;
	uint8_t				 sc_radio_5g_chans[64];
	/* HT and VHT as the firmware reports them (bs_ht transports only) */
	bool				 sc_radio_ht;
	bool				 sc_radio_vht;
	uint8_t				 sc_radio_bw2g;	/* BWFM_BW_*_BIT */
	uint8_t				 sc_radio_bw5g;
	uint8_t				 sc_radio_nchains;
	bool				 sc_sup_wpa_ok;
	uint32_t			 sc_sup_wpa_current;

	/*
	 * Join / leave dispatch deferral.  fmop_assoc + fmop_disassoc
	 * are called from the framework's newstate shim with
	 * IEEE80211_LOCK held; the BCDC dcmd path sleeps, so each
	 * dispatch stages here and runs on taskqueue_thread.
	 */
	struct timeout_task		 sc_assoc_task;
	struct ieee80211vap		*sc_assoc_vap;
	struct task			 sc_disassoc_task;
	u_int				 sc_disassoc_reason;	/* IEEE80211 reason */
	struct task			 sc_post_assoc_task;	/* Linux post-ASSOC iovar GETs */
	struct task			 sc_roam_task;	/* follow a firmware roam */
	/*
	 * Link check: a STA that keeps sending unicast frames but hears no
	 * unicast for sc_lh_secs leaves the network, so a link the AP
	 * dropped without telling the firmware heals.  0 turns it off.
	 */
	struct timeout_task		 sc_lh_task;
	volatile u_int			 sc_lh_rx;	/* unicast frames received */
	volatile u_int			 sc_lh_tx;	/* unicast frames sent */
	u_int				 sc_lh_rx_seen;	/* sc_lh_rx at the last check */
	u_int				 sc_lh_tx_base;	/* sc_lh_tx when rx last moved */
	time_t				 sc_lh_rx_ts;	/* uptime when rx last moved */
	int				 sc_lh_secs;
	u_int				 sc_lh_kicks;	/* times it left the network */
	u_int				 sc_lh_nudges;	/* times it toggled PM to wake the AP */
	bool				 sc_lh_nudged;	/* nudged since rx last moved */
	long				 sc_starve_ts;	/* uptime of the last rx buffer shortage */
	u_int				 sc_starve_nudges; /* PM toggles soon after a shortage */
	/*
	 * Firmware roaming: look for a better AP below sc_roam_trigger dBm,
	 * and move when one is sc_roam_delta dB better.  Linux brcmfmac's
	 * defaults (brcmf_dongle_roam); dev.bwfm.N.roam_trigger/roam_delta.
	 */
	int				 sc_roam_trigger;
	int				 sc_roam_delta;

	/*
	 * Deferred firmware key work.  Filled by the key callbacks (which
	 * run under net80211's node lock) and drained by sc_key_task on
	 * taskqueue_thread, where sleeping for the firmware is allowed.
	 */
	struct mtx			 sc_key_mtx;	/* protects sc_key_ops */
	struct sx			 sc_drain_sx;	/* one drainer of the timeout tasks */
	struct bwfm_key_ops		 sc_key_ops;
	struct task			 sc_key_task;
	/* When the transport last handed an EAPOL frame to the chip. */
	volatile uint64_t		 sc_eapol_sent_sbt;
	int				 sc_eapol_settle_ms;

	/* Target of the most-recent direct join. */
	uint8_t				 sc_join_bssid[6];
	char				 sc_join_ssid[BWFM_MAX_SSID_LEN + 1];
	uint8_t				 sc_join_ssid_len;

	/* PMK from net.wlan.N.fullmac_pmk, for the chip's own supplicant. */
	uint8_t				 sc_wpa_pmk_raw[32];
	bool				 sc_wpa_pmk_raw_set;
};

/*
 * Debug levels — gated on sc->sc_debug via the per-instance
 * dev.bwfm.<n>.debug sysctl.  Level 0 prints milestones and errors;
 * level 1 adds protocol traces (newstate, event-header summaries);
 * level 2 adds high-volume data-path noise; level 3 is the
 * everything-bucket for protocol forensics.  Lower-level prints
 * outrank higher: a DPRINTF(level=1, ...) fires when sc_debug >= 1.
 */
#define	DPRINTF(sc, level, ...)	do {					\
	if ((sc)->sc_debug >= (level))					\
		device_printf((sc)->sc_dev, __VA_ARGS__);		\
} while (0)

MALLOC_DECLARE(M_BWFM);

extern const struct bwfm_chip_info bwfm_chip_table[];

/* Bus-agnostic entry points implemented in bwfm.c. */
const struct bwfm_chip_info *bwfm_chip_lookup(uint32_t chip, uint32_t chiprev);
/* Flags read without a lock from other contexts; KCSAN wants these atomic. */
#define	BWFM_DYING(sc)		atomic_load_bool(&(sc)->sc_dying)
#define	BWFM_IC_UP(sc)		atomic_load_bool(&(sc)->sc_ic_attached)
#define	BWFM_LINK_UP(sc)	atomic_load_bool(&(sc)->sc_link_up)
#define	BWFM_WLC_UP(sc)		atomic_load_bool(&(sc)->sc_wlc_up)
#define	BWFM_BUSY_CLEAR(p)	atomic_store_int((volatile u_int *)(p), 0)

int	bwfm_attach(struct bwfm_softc *) __result_use_check;
void	bwfm_detach(struct bwfm_softc *);
/*
 * Common transport-teardown: must be the FIRST act of every
 * transport's detach path.  Idempotent across attach-fail paths
 * where the mutex/pending list may or may not be initialized.
 * See bwfm.c for the full contract.
 */
void	bwfm_transport_teardown(struct bwfm_softc *);
void	bwfm_detach_leave(struct bwfm_softc *);
struct proc;
int	bwfm_kproc_start(void (*)(void *), void *, struct proc **,
	    const char *);
void	bwfm_kproc_wait(struct proc **);
void	bwfm_regulatory_init(struct bwfm_softc *);
void	bwfm_runtime_iovars(struct bwfm_softc *);
int	bwfm_dcmd_get(struct bwfm_softc *, uint32_t cmd, void *buf,
	    size_t *lenp) __result_use_check;
int	bwfm_dcmd_set(struct bwfm_softc *, uint32_t cmd, const void *buf,
	    size_t len);
int	bwfm_iovar_get(struct bwfm_softc *, const char *name, void *buf,
	    size_t *lenp) __result_use_check;
int	bwfm_iovar_set(struct bwfm_softc *, const char *name, const void *buf,
	    size_t len);
int	bwfm_iovar_get_with_params(struct bwfm_softc *, const char *name,
	    const void *params, size_t plen, void *buf, size_t *lenp)
	    __result_use_check;

/* RX dispatch: called by transport layer after stripping bulk-IN BCDC. */
void	bwfm_rx_frame(struct bwfm_softc *, struct mbuf *, bool events_ok);
bool	bwfm_rx_enter(struct bwfm_softc *) __result_use_check;
void	bwfm_rx_exit(struct bwfm_softc *);
void	bwfm_rx_close(struct bwfm_softc *);
void	bwfm_rx_reopen(struct bwfm_softc *);
int	bwfm_op_enter(struct bwfm_softc *) __result_use_check;
void	bwfm_op_exit(struct bwfm_softc *);
void	bwfm_drain_tasks(struct bwfm_softc *);
bool	bwfm_is_event_frame(const uint8_t *p, size_t len);
bool	bwfm_rxctl(struct bwfm_softc *, const void *buf, size_t len);
/* WL_EVENT dispatch: transports with their own event framing (msgbuf
 * on PCIe) hand the payload here.  `p` is the buffer, `evpos` is the
 * offset of struct bwfm_event_msg within it.  For the PCIe/msgbuf
 * layout evpos = 24 (14 B ethhdr + 10 B bwfm_ethhdr). */
void	bwfm_handle_event(struct bwfm_softc *, const uint8_t *p, size_t len,
	    size_t evpos);

/* Chanspec helpers (both D11N and D11AC encodings). */
bool	bwfm_chanspec_is_5ghz(uint16_t chanspec);
uint8_t	bwfm_chanspec_to_chan(struct bwfm_softc *, uint16_t);
uint16_t bwfm_chan_to_chanspec_d11ac(uint8_t chan);
uint16_t bwfm_chan_to_chanspec_d11n(uint8_t chan);
uint16_t bwfm_chan_to_chanspec(struct bwfm_softc *sc, uint8_t chan);
struct mbuf;
int	bwfm_deencap_80211(struct mbuf **mp);
bool	bwfm_mbuf_is_eapol(struct mbuf *m);
void	bwfm_rx_data(struct bwfm_softc *, struct mbuf *);
void	bwfm_rx_starved(struct bwfm_softc *);
void	bwfm_eapol_sent(struct bwfm_softc *sc);

/* Helper: turn a host buffer into a BCDC dcmd frame ready for bs_txctl. */
size_t	bwfm_proto_bcdc_pack(uint16_t reqid, uint32_t cmd, uint32_t flags,
	    const void *payload, size_t payload_len, void *out, size_t out_cap);

#endif /* _DEV_BWFM_BWFMVAR_H_ */
