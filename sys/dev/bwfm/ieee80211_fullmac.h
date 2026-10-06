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
 * Per-frame receive info attached by the driver when handing a
 * mgmt-frame mbuf up via ieee80211_fmac_input_beacon().  The
 * framework converts these absolute-dBm values into net80211's
 * half-dB-above-noise units and hands the parsed frame, with that
 * rssi and noise floor, straight to the scan module's scan_add.
 */
struct ieee80211_fmac_rxinfo {
	uint16_t	fri_chan_freq;	/* MHz */
	uint8_t		fri_chan_ieee;	/* IEEE channel number */
	int8_t		fri_rssi_dbm;	/* signed dBm */
	int8_t		fri_noise_dbm;	/* signed dBm; see below */
};

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
 * Per-scan-result payload the driver assembles from a firmware
 * "scan result" event and hands up via ieee80211_fmac_scan_result().
 * The framework synthesises a probe-response-equivalent buffer from
 * these fields plus the supplied IE blob and feeds it into the
 * usual net80211 scan cache.
 */
struct ieee80211_fmac_bss {
	uint8_t		fb_bssid[IEEE80211_ADDR_LEN];	/* AP MAC address */
	uint8_t		fb_ssid[IEEE80211_NWID_LEN];	/* network name */
	uint8_t		fb_ssidlen;	/* network name length */
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
 * Ops vtable.  Required entries are marked; optional ones may be
 * NULL when the chip doesn't expose that path.  All ops are called
 * from process or taskqueue context (never IRQ) — the framework
 * defers anything that would arrive from a hardirq.
 *
 * Return value convention: 0 on success, errno on failure.
 */
struct ieee80211_fullmac_ops {
	const char	*fmop_name;	/* driver tag for diag (required) */

	/* Scan.  Required. */
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

	/* Regulatory.  Required. */
	int		(*fmop_set_country)(struct ieee80211com *,
			    const char cc[3]);

	/* Optional: PMK install (chips with on-chip supplicant). */
	int		(*fmop_set_pmk)(struct ieee80211com *,
			    const uint8_t *pmk, size_t pmklen);

	/*
	 * Optional: emit an EAPOL frame back at the host's
	 * wpa_supplicant.  Not called by the framework yet; EAPOL
	 * is delivered by ieee80211_fmac_eapol_rx through
	 * ieee80211_vap_deliver_data.
	 */
	int		(*fmop_eapol_tx)(struct ieee80211com *,
			    const void *buf, size_t len);

	/* Optional: power save knob. */
	int		(*fmop_set_powersave)(struct ieee80211com *,
			    bool enabled);
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
void	ieee80211_fmac_vap_attach(struct ieee80211vap *);

/* Firmware event -> framework. */
void	ieee80211_fmac_scan_result(struct ieee80211com *,
	    const struct ieee80211_fmac_bss *);
void	ieee80211_fmac_scan_done(struct ieee80211com *);
void	ieee80211_fmac_input_beacon(struct ieee80211com *, struct mbuf *,
	    const struct ieee80211_fmac_rxinfo *);
int	ieee80211_fmac_link_up(struct ieee80211com *,
	    const uint8_t bssid[IEEE80211_ADDR_LEN]);
int	ieee80211_fmac_link_down(struct ieee80211com *, uint16_t reason);
void	ieee80211_fmac_eapol_rx(struct ieee80211com *,
	    const uint8_t ap_mac[IEEE80211_ADDR_LEN],
	    const void *buf, size_t len);

#endif /* _KERNEL */
#endif /* _NET80211_IEEE80211_FULLMAC_H_ */
