/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * net80211 FullMAC adaptation layer.
 *
 * net80211's native shape is SoftMAC: the driver feeds raw 802.11
 * frames and the stack runs scan / AUTH / ASSOC and key handling,
 * with wpa_supplicant running the 4-way.  FullMAC firmware
 * (Broadcom brcmfmac, Marvell mwifiex, Quantenna qtnfmac, a
 * number of USB dongles) does all of
 * that on the chip and gives the host 802.3.  Without a framework
 * each FullMAC driver re-implements the same dance:
 *
 *   * intercept iv_newstate so net80211 doesn't try to walk a state
 *     machine the firmware is already past;
 *   * fast-forward INIT -> AUTH -> ASSOC -> RUN when the chip
 *     announces "linked";
 *   * synthesise a beacon (or carry the firmware-captured IEs
 *     forward) so ieee80211_add_scan() has something believable to
 *     match the ssid_match against;
 *   * forward EAPOL only when the firmware supplicant is disabled
 *     and the host is running wpa_supplicant;
 *   * forward iv_key_set / iv_key_delete into a firmware-side
 *     "install key" command instead of programming hardware
 *     crypto keys directly;
 *   * keep the firmware's idea of country / channel set in sync
 *     with net80211's regdomain.
 *
 * This header provides a small ops vtable and a handful of up-call
 * helpers that absorb that glue once.  Drivers register their
 * struct ieee80211_fullmac_ops in attach, the framework hooks the
 * relevant ic_* / vap_* slots before ieee80211_ifattach(), and
 * driver code reduces to: implement the ops, call the up-calls
 * when firmware events land.
 *
 * bwfm is the only user so far, and the API may still change.
 */

#ifndef _NET80211_IEEE80211_FULLMAC_H_
#define _NET80211_IEEE80211_FULLMAC_H_

#ifdef _KERNEL

#include <sys/types.h>
#include <net80211/ieee80211_var.h>

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
	uint16_t	fp_bintval;	/* beacon interval, TU */
	uint8_t		fp_dtim;	/* DTIM period, beacons */
	bool		fp_privacy;	/* privacy bit (WEP or WPA) */
	uint8_t		fp_wpa;		/* 1 = WPA, 2 = RSN, 3 = both */
	uint32_t	fp_ucast;	/* pairwise ciphers */
	uint32_t	fp_mcast;	/* group cipher */
	uint32_t	fp_akms;	/* key management suites */
	uint16_t	fp_rsncaps;	/* RSN capabilities (MFPC 0x80, MFPR 0x40) */
	uint8_t		fp_ielen;
	uint8_t		fp_ies[255];	/* hostapd's WPA/RSN elements, raw */
};

#define	IEEE80211_FMAC_RSNCAP_MFPR	0x0040	/* MFP required */
#define	IEEE80211_FMAC_RSNCAP_MFPC	0x0080	/* MFP capable */

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
	 * Key install.  fmop_set_key required; del optional.  Both return
	 * an errno (0 = done, ENXIO = let net80211's own hook handle it);
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
};

/*
 * Capability bits the driver passes to ieee80211_fmac_attach() so
 * the framework knows which net80211 slots to take over.
 */
#define	IEEE80211_FMAC_CAP_ONCHIP_SUP	0x0001	/* on-chip supplicant */
#define	IEEE80211_FMAC_CAP_FW_SCAN	0x0002	/* fw owns scan engine */
#define	IEEE80211_FMAC_CAP_NO_RAWIE	0x0004	/* no raw beacon IEs */

/* Attach / detach. */
int	ieee80211_fmac_attach(struct ieee80211com *,
	    const struct ieee80211_fullmac_ops *, uint32_t caps);
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
void	ieee80211_fmac_eapol_rx(struct ieee80211com *,
	    const uint8_t ap_mac[IEEE80211_ADDR_LEN],
	    const void *buf, size_t len);

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

#endif /* _KERNEL */
#endif /* _NET80211_IEEE80211_FULLMAC_H_ */
