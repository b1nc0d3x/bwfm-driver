/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * net80211 FullMAC adaptation layer.
 *
 * net80211's native shape is SoftMAC: the driver feeds raw 802.11
 * frames and the stack runs scan, authentication, association and key
 * handling, with wpa_supplicant running the 4-way handshake.  FullMAC
 * firmware (Broadcom, Marvell and Quantenna chips, and a number of USB
 * dongles) does all of that on the chip and gives the host 802.3
 * frames.  Without a framework each FullMAC driver repeats the same
 * glue:
 *
 *   * intercept iv_newstate so net80211 doesn't walk a state machine
 *     the firmware is already past;
 *   * fast-forward INIT -> AUTH -> ASSOC -> RUN when the firmware
 *     reports the link;
 *   * turn firmware scan results into net80211 scan entries;
 *   * turn iv_key_set / iv_key_delete into firmware key commands;
 *   * keep the firmware's country in step with net80211's regdomain.
 *
 * This header provides a small ops table and a handful of up-calls
 * that absorb that glue once.  A driver fills in a struct
 * ieee80211_fullmac_ops, calls ieee80211_fmac_attach() after
 * ieee80211_ifattach(), and the framework takes over the relevant
 * ic_* and iv_* methods.  Driver code reduces to implementing the ops
 * and calling the up-calls when firmware events land.
 *
 * bwfm(4) is the first user.
 */

#ifndef _NET80211_IEEE80211_FULLMAC_H_
#define _NET80211_IEEE80211_FULLMAC_H_

#ifndef IEEE80211_FMAC_INTREE
#include <sys/types.h>

/*
 * External SAE (WPA3-Personal with the SAE exchange run by the host).
 * Firmware that keeps its own join state machine but leaves SAE to the
 * host asks for it when a join reaches authentication; wpa_supplicant
 * then runs the exchange through the driver and reports the outcome,
 * after which the firmware associates and the 4-way handshake follows
 * as usual.  The interface is a routing socket event each way up and an
 * SIOCS80211 request each way down.  The numbers follow net80211's own;
 * in kernels that carry the framework they are in ieee80211_freebsd.h
 * and ieee80211_ioctl.h, and this copy is only for building against
 * kernels without it.
 */
#define	RTM_IEEE80211_EXTAUTH		117	/* start/abort external auth */
#define	RTM_IEEE80211_MGMT_RX		118	/* management frame for us */
#define	RTM_IEEE80211_ASSOC_REJECT	119	/* the join was refused */

#define	IEEE80211_IOC_MGMT_TX		211	/* send a management frame */
#define	IEEE80211_IOC_EXTAUTH_STATUS	212	/* external auth outcome */
#define	IEEE80211_IOC_EXTAUTH_CAPS	213	/* get: IEEE80211_EXTAUTH_CAP_* */
#define	IEEE80211_IOC_PMKSA		214	/* set: PMKSA cache entry */
#define	IEEE80211_IOC_ASSOC_REQ_IE	215	/* get: our association request's elements */

#define	IEEE80211_FMAC_ASSOC_IE_MAX	512	/* most elements kept for 215 */

#define	IEEE80211_EXTAUTH_CAP_SAE	0x0001	/* external SAE (station) */

#define	IEEE80211_EXTAUTH_START		0
#define	IEEE80211_EXTAUTH_ABORT		1

/* RTM_IEEE80211_EXTAUTH payload. */
struct ieee80211_extauth_event {
	uint8_t		iev_bssid[6];
	uint8_t		iev_action;		/* IEEE80211_EXTAUTH_* */
	uint8_t		iev_ssid_len;
	uint8_t		iev_ssid[32];
	uint32_t	iev_key_mgmt;		/* AKM suite, e.g. 0x000fac08 */
};

/* RTM_IEEE80211_MGMT_RX payload: this, then iev_len bytes of frame. */
struct ieee80211_mgmt_rx_event {
	uint16_t	iev_len;		/* frame length, header included */
	uint16_t	iev_freq;		/* MHz, 0 if unknown */
	int8_t		iev_rssi;		/* dBm, 0 if unknown */
	uint8_t		iev_pad[3];
};

/* IEEE80211_IOC_EXTAUTH_STATUS i_data; i_val is the 802.11 status. */
struct ieee80211_extauth_status {
	uint8_t		is_bssid[6];
	uint8_t		is_ssid_len;
	uint8_t		is_ssid[32];
	uint8_t		is_pad;
};

#define	IEEE80211_MGMT_TX_MAXLEN	2048

/*
 * PMKSA caching.  wpa_supplicant tells the firmware which PMKIDs it
 * holds, so a later join to the same access point can present one
 * instead of running SAE again.  IEEE80211_IOC_PMKSA's i_val is the
 * operation and i_data a struct ieee80211_pmksa_req (ignored by FLUSH).
 */
#define	IEEE80211_PMKSA_ADD		0
#define	IEEE80211_PMKSA_DEL		1
#define	IEEE80211_PMKSA_FLUSH		2

struct ieee80211_pmksa_req {
	uint8_t		ip_bssid[6];
	uint8_t		ip_pmkid[16];
};

/*
 * RTM_IEEE80211_ASSOC_REJECT payload.  A join that the firmware could
 * not complete, so wpa_supplicant tries again at once instead of
 * waiting out its timeout, and drops a PMKSA it tried to use.
 */
struct ieee80211_assoc_reject_event {
	uint8_t		iev_bssid[6];
	uint16_t	iev_status;		/* 802.11 status code */
};
#endif /* !IEEE80211_FMAC_INTREE */

#ifdef _KERNEL

#include <net80211/ieee80211_var.h>

struct mbuf;
struct ieee80211com;
struct ieee80211vap;
struct ieee80211_key;
struct ieee80211_scanparams;

/*
 * net80211 takes signal as dB above the noise floor (rssi - nf, in half
 * dB) and refuses to join a BSS too close to it.  Firmware noise figures
 * are not always plausible: the BCM43602 at times reports phy_noise =
 * -22 dBm for every BSS, which puts each AP at or below the floor, so
 * sta_pick_bss finds no scan candidate and never joins.  Use the
 * firmware's figure only when it is a plausible noise floor, and -95 dBm
 * otherwise; 0 means "none".
 */
#define	IEEE80211_FMAC_NF_DEFAULT	(-95)
#define	IEEE80211_FMAC_NF_MIN		(-110)
#define	IEEE80211_FMAC_NF_MAX		(-70)

static __inline int
ieee80211_fmac_noise_floor(int dbm)
{
	if (dbm < IEEE80211_FMAC_NF_MIN || dbm > IEEE80211_FMAC_NF_MAX)
		return (IEEE80211_FMAC_NF_DEFAULT);
	return (dbm);
}

/*
 * One BSS the firmware found, filled in by the driver and handed up
 * with ieee80211_fmac_scan_result().  The SSID, rates and the other
 * elements come from fb_ies, the information elements exactly as the
 * firmware reported them; the framework parses them and adds the
 * entry to net80211's scan cache.  Signal and noise are plain dBm.
 */
struct ieee80211_fmac_bss {
	uint8_t		fb_bssid[IEEE80211_ADDR_LEN];	/* AP MAC address */
	uint16_t	fb_capinfo;	/* host byte order */
	uint16_t	fb_bintval;	/* beacon interval */
	int		fb_rssi;	/* dBm; negative */
	int		fb_noise;	/* dBm; negative */
	uint16_t	fb_chan_freq;	/* MHz */
	uint8_t		fb_chan_flags;	/* 2 = 2.4 GHz, 5 = 5 GHz */
	const uint8_t  *fb_ies;		/* concatenated TLVs from chip */
	size_t		fb_ielen;	/* length of fb_ies */
};

/*
 * Association request the framework hands the driver when net80211
 * (or a userspace JOIN sysctl) asks for an association.  Set fields
 * are non-zero; zero ssidlen means "use stored configuration"
 * (some FullMAC chips associate without a host-side SSID at all).
 */
struct ieee80211_fmac_assoc {
	uint8_t		fa_bssid[IEEE80211_ADDR_LEN];	/* AP MAC address to join */
	uint8_t		fa_ssid[IEEE80211_NWID_LEN];	/* network name to join */
	uint8_t		fa_ssidlen;	/* network name length */
	uint16_t	fa_chan_freq;	/* channel frequency (MHz) */
	uint32_t	fa_wpa_auth;	/* WPA_AUTH_* */
	uint32_t	fa_wsec;	/* CRYPTO_WEP/TKIP/AES bits */
	const uint8_t  *fa_ies;		/* host-built RSN IE etc. */
	size_t		fa_ielen;	/* length of fa_ies */
};

/*
 * Access point the framework asks the driver to run, when a hostap
 * vap reaches RUN.  The firmware builds its own beacons and answers
 * probes, so this is the whole BSS as net80211 and hostapd(8)
 * configured it.  Security comes from the RSN (or WPA) element
 * hostapd hands net80211; with fp_wpa zero the BSS is open, and
 * fp_privacy alone means static WEP.  Ciphers are IEEE80211_CIPHER_*
 * bit sets (1 << cipher); fp_akms holds RSN_ASE_* bits (1 << akm).
 */
struct ieee80211_fmac_ap {
	uint8_t		fp_bssid[IEEE80211_ADDR_LEN];	/* our address */
	uint8_t		fp_ssid[IEEE80211_NWID_LEN];	/* network name */
	uint8_t		fp_ssidlen;
	bool		fp_hidden;	/* no SSID in beacons */
	uint16_t	fp_chan_freq;	/* MHz */
	uint8_t		fp_chan_ieee;	/* channel number */
	bool		fp_chan_auto;	/* none was set: net80211 picked it */
	uint32_t	fp_chan_flags;	/* IEEE80211_CHAN_*: HT40U/D, VHT80 */
	uint8_t		fp_chan_center;	/* VHT80: centre channel number */
	uint16_t	fp_bintval;	/* beacon interval, TU */
	uint8_t		fp_dtim;	/* DTIM period, beacons */
	bool		fp_privacy;	/* privacy bit (WEP or WPA) */
	uint8_t		fp_wpa;		/* 1 = WPA, 2 = RSN, 3 = both */
	uint32_t	fp_ucast;	/* pairwise ciphers */
	uint32_t	fp_mcast;	/* group cipher */
	uint32_t	fp_akms;	/* key management suites */
	uint16_t	fp_rsncaps;	/* RSN capabilities (MFPC 0x80, MFPR 0x40) */
	uint8_t		fp_mgmt_suite;	/* group mgmt cipher, 00-0f-ac-N; 0 none */
	uint8_t		fp_ielen;
	uint8_t		fp_ies[255];	/* hostapd's WPA/RSN elements, raw */
};

#define	IEEE80211_FMAC_RSNCAP_MFPR	0x0040	/* MFP required */
#define	IEEE80211_FMAC_RSNCAP_MFPC	0x0080	/* MFP capable */

/* One cached PMKSA, as fmop_set_pmksa receives the list. */
#define	IEEE80211_FMAC_MAX_PMKSA	16
struct ieee80211_fmac_pmksa {
	uint8_t		pm_bssid[IEEE80211_ADDR_LEN];
	uint8_t		pm_pmkid[16];
};

/*
 * Ops vtable.  Required entries are marked; optional ones may be
 * NULL when the chip doesn't expose that path.  All ops are called
 * from process or taskqueue context (never IRQ) — the framework
 * defers anything that would arrive from a hardirq.
 *
 * Return value convention: 0 on success, errno on failure.
 */
struct ieee80211_fullmac_ops {
	const char	*fmop_name;	/* driver tag for diag (required) */

	/*
	 * Scan.  fmop_scan_start is required: start the firmware's scan
	 * and report each result, then call ieee80211_fmac_scan_done.
	 * fmop_scan_cancel is optional: the framework calls it only when
	 * net80211 ends a scan the firmware is still running.
	 */
	int		(*fmop_scan_start)(struct ieee80211com *,
			    const uint8_t *ssid, size_t ssidlen,
			    bool active);
	void		(*fmop_scan_cancel)(struct ieee80211com *);

	/* Association.  Required. */
	int		(*fmop_assoc)(struct ieee80211com *,
			    const struct ieee80211_fmac_assoc *);
	int		(*fmop_disassoc)(struct ieee80211com *,
			    uint16_t reason);

	/*
	 * Key install.  fmop_set_key required; del optional (without it
	 * net80211's own hook removes keys).  Both return 0 or an errno;
	 * the framework translates to net80211's nonzero-is-success
	 * iv_key_set convention.
	 */
	int		(*fmop_set_key)(struct ieee80211com *,
			    const struct ieee80211_key *);
	int		(*fmop_del_key)(struct ieee80211com *,
			    const struct ieee80211_key *);

	/*
	 * Optional: regulatory.  Called with the two-letter country
	 * (NUL-terminated) after the user changes it, from a taskqueue
	 * thread.  Without it the firmware keeps its own default.
	 */
	int		(*fmop_set_country)(struct ieee80211com *,
			    const char cc[3]);

	/*
	 * Optional: PMK for chips whose own supplicant runs the 4-way.
	 * The framework adds a write-only net.wlan.N.fullmac_pmk sysctl
	 * and passes a 32-byte PMK, or NULL and 0 to clear it.  Called
	 * from the sysctl path; may sleep.
	 */
	int		(*fmop_set_pmk)(struct ieee80211com *,
			    const uint8_t *pmk, size_t pmklen);


	/*
	 * Optional: power save.  When present the framework advertises
	 * IEEE80211_C_PMGT, applies `ifconfig powersave` without
	 * restarting the vap, and re-sends the setting each time the
	 * link comes up.  Called from the ioctl path or the context
	 * that called ieee80211_fmac_link_up; may sleep.
	 */
	int		(*fmop_set_powersave)(struct ieee80211com *,
			    bool enabled);

	/*
	 * Optional: current signal and noise of the associated AP, in
	 * dBm.  The framework polls it every two seconds while a station
	 * link is up, from a taskqueue thread, and reports the cached
	 * values to net80211 (ifconfig, wpa_supplicant), which otherwise
	 * sees only scan-time signal on a FullMAC device.
	 */
	int		(*fmop_get_signal)(struct ieee80211com *,
			    int *rssi_dbm, int *noise_dbm);

	/*
	 * Optional: access point.  With fmop_start_ap and fmop_stop_ap
	 * both present the framework advertises IEEE80211_C_HOSTAP.
	 * When a hostap vap reaches RUN it calls fmop_start_ap with the
	 * BSS to run (again, with the new settings, if the vap restarts),
	 * and fmop_stop_ap when the vap leaves RUN.  The driver reports
	 * stations with ieee80211_fmac_sta_join and _sta_leave; the
	 * framework keeps net80211's station table, so hostapd and
	 * `ifconfig list sta` work unchanged.  fmop_sta_deauth, also
	 * optional, sends a station away when net80211 or hostapd
	 * deauthenticates or disassociates it (a broadcast address means
	 * every station).  All three are called from a taskqueue thread
	 * and may sleep.
	 */
	int		(*fmop_start_ap)(struct ieee80211com *,
			    const struct ieee80211_fmac_ap *);
	int		(*fmop_stop_ap)(struct ieee80211com *);
	int		(*fmop_sta_deauth)(struct ieee80211com *,
			    const uint8_t mac[IEEE80211_ADDR_LEN],
			    uint16_t reason);

	/*
	 * Optional: how long the firmware has heard nothing from one of
	 * our access point's stations, in seconds.  A station's traffic
	 * never reaches net80211, so without this the framework turns
	 * net80211's station aging off and leaves aging to the firmware,
	 * which drops stations that stop answering.
	 * With it, the framework feeds the idle time to net80211 every
	 * IEEE80211_INACT_WAIT seconds and net80211 ages stations as it
	 * always does (iv_inact_run).  A failed query counts the station
	 * as heard.  Called from a taskqueue thread; may sleep.
	 */
	int		(*fmop_sta_idle)(struct ieee80211com *,
			    const uint8_t mac[IEEE80211_ADDR_LEN],
			    uint32_t *idle_sec);

	/*
	 * Optional, together: external SAE for a station.  When the
	 * firmware asks for SAE the driver calls ieee80211_fmac_extauth_req,
	 * and passes the access point's Authentication frames up with
	 * ieee80211_fmac_mgmt_rx.  wpa_supplicant's frames come down
	 * through fmop_mgmt_tx (a whole 802.11 Authentication frame, header
	 * included, to send on channel chan) and its verdict through
	 * fmop_extauth_status (an 802.11 status code; 0 means SAE
	 * succeeded and the firmware may associate).  Called from ioctl
	 * context; may sleep.
	 */
	int		(*fmop_mgmt_tx)(struct ieee80211com *,
			    const uint8_t *frame, size_t len, uint16_t chan);
	int		(*fmop_extauth_status)(struct ieee80211com *,
			    uint16_t status,
			    const uint8_t bssid[IEEE80211_ADDR_LEN],
			    const uint8_t *ssid, size_t ssid_len);

	/*
	 * Optional: load the firmware's PMKSA list.  The framework keeps
	 * the list wpa_supplicant builds with IEEE80211_IOC_PMKSA and
	 * hands over all of it (n entries, at most IEEE80211_FMAC_MAX_PMKSA)
	 * on every change.  Called from ioctl context; may sleep.
	 */
	int		(*fmop_set_pmksa)(struct ieee80211com *,
			    const struct ieee80211_fmac_pmksa *list, int n);
};

/*
 * Management frame protection: a driver whose firmware does BIP sets
 * IEEE80211_CRYPTO_BIP_CMAC_128 in ic_cryptocaps before attaching, and
 * the framework registers a key-only BIP cipher for the IGTK if net80211
 * has none.  The IGTK then reaches fmop_set_key as a group key with key
 * index 4 or 5 and cipher IEEE80211_CIPHER_BIP_CMAC_128.
 */

/* Attach / detach. */
int	ieee80211_fmac_attach(struct ieee80211com *,
	    const struct ieee80211_fullmac_ops *);
void	ieee80211_fmac_detach(struct ieee80211com *);

/* Firmware event -> framework. */
void	ieee80211_fmac_scan_result(struct ieee80211com *,
	    const struct ieee80211_fmac_bss *);
/* scan_done ends net80211's scan: call it once the firmware is done. */
void	ieee80211_fmac_scan_done(struct ieee80211com *);
/* link_up may call driver ops: call it from a context that can sleep. */
int	ieee80211_fmac_link_up(struct ieee80211com *,
	    const uint8_t bssid[IEEE80211_ADDR_LEN]);
int	ieee80211_fmac_link_down(struct ieee80211com *, uint16_t reason);

/*
 * Received frames.  ieee80211_fmac_rx takes an Ethernet (802.3) frame
 * as the firmware hands it up, data or EAPOL, and consumes it.
 */
void	ieee80211_fmac_rx(struct ieee80211com *, struct mbuf *);

/*
 * The firmware roamed: it left the access point it was joined to for
 * another of the same network, described by bb as for scan results.
 * The framework moves net80211's station onto the new BSS and reports
 * a reassociation (RTM_IEEE80211_REASSOC), so wpa_supplicant runs the
 * handshake with the new AP while the link stays up.  Call from a
 * context that can sleep.  0, or ENOENT with no station vap in RUN.
 */
int	ieee80211_fmac_roamed(struct ieee80211com *,
	    const struct ieee80211_fmac_bss *bb);

/*
 * Access point: a station associated (ies = the elements of its
 * (re)association request, as the firmware passed them up) or left.
 * Both copy what they need and return at once, so they are safe from
 * any context the driver's event path runs in.
 */
void	ieee80211_fmac_sta_join(struct ieee80211com *,
	    const uint8_t mac[IEEE80211_ADDR_LEN],
	    const uint8_t *ies, size_t ielen, bool reassoc);
void	ieee80211_fmac_sta_leave(struct ieee80211com *,
	    const uint8_t mac[IEEE80211_ADDR_LEN], uint16_t reason);

/*
 * External SAE: the firmware wants wpa_supplicant to run SAE with this
 * access point, or a received Authentication frame (whole, header
 * included) for it.  Both only queue a routing socket message, so they
 * are safe from the driver's event path.
 */
void	ieee80211_fmac_extauth_req(struct ieee80211com *,
	    const uint8_t bssid[IEEE80211_ADDR_LEN],
	    const uint8_t *ssid, size_t ssid_len);
void	ieee80211_fmac_mgmt_rx(struct ieee80211com *,
	    const uint8_t *frame, size_t len, uint16_t freq, int8_t rssi);

/*
 * A station join the firmware gave up on (status is an 802.11 status
 * code, 1 when the firmware gives none).  Queues a routing socket
 * message; safe from the driver's event path.
 */
void	ieee80211_fmac_assoc_reject(struct ieee80211com *,
	    const uint8_t bssid[IEEE80211_ADDR_LEN], uint16_t status);

/*
 * The elements of the association request the firmware sent, for
 * IEEE80211_IOC_ASSOC_REQ_IE: wpa_supplicant builds 4-way message 2 from
 * them.  Call before ieee80211_fmac_link_up; len 0 forgets them.
 */
void	ieee80211_fmac_assoc_ies(struct ieee80211com *,
	    const uint8_t *ies, size_t len);

#endif /* _KERNEL */
#endif /* _NET80211_IEEE80211_FULLMAC_H_ */
