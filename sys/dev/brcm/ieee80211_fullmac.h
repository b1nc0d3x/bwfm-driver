/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Glue layer for net80211 with FullMAC chips.
 *
 * net80211 is built for SoftMAC. The driver feeds raw 802.11
 * frames and the stack does scan, AUTH, ASSOC, 4-way, keymgmt.
 * FullMAC firmware (Broadcom brcmfmac, iwlwifi MVM-mode,
 * mt76 firmware-mode, and many USB dongles) does all that on
 * the chip and gives the host plain 802.3. Without a framework,
 * each FullMAC driver has to redo the same dance:
 *
 *   * hook iv_newstate so net80211 does not try to walk a state
 *     machine the firmware already finished;
 *   * jump from INIT to AUTH to ASSOC to RUN when the chip
 *     says "linked";
 *   * make a fake beacon (or reuse IEs the firmware captured)
 *     so ieee80211_add_scan() has something to match ssid on;
 *   * forward EAPOL only when the firmware supplicant is off
 *     and the host runs wpa_supplicant;
 *   * turn iv_key_set / iv_key_delete into a firmware-side
 *     "install key" command instead of poking hardware crypto
 *     keys directly;
 *   * keep the firmware's country / channel list in sync with
 *     net80211's regdomain.
 *
 * This header adds a small ops table and a few up-call helpers
 * that soak up that glue in one place. Drivers register their
 * ieee80211_fullmac_ops in attach. The framework hooks the
 * ic_* / vap_* slots before ieee80211_ifattach(). Driver code
 * shrinks to: fill the ops, call the up-calls on firmware events.
 *
 * Status: DRAFT. The API can still change while brcm moves to
 * it. Lock the shape after at least one merged driver uses it.
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
 * Extra info per frame. The driver attaches this when it hands
 * a mgmt-frame mbuf up with ieee80211_fmac_input_beacon(). The
 * framework turns these dBm values into net80211's half-dB-above-
 * noise units, fills an ieee80211_rx_stats, attaches the stats
 * mtag, and calls ieee80211_input_mimo_all.
 */
struct ieee80211_fmac_rxinfo {
	uint16_t	fri_chan_freq;	/* MHz */
	uint8_t		fri_chan_ieee;	/* IEEE channel number */
	int8_t		fri_rssi_dbm;	/* signed dBm */
	int8_t		fri_noise_dbm;	/* signed dBm; 0 means "use -95" */
};

/*
 * One scan result. The driver builds this from a firmware
 * "scan result" event and passes it in via
 * ieee80211_fmac_scan_result(). The framework makes a fake
 * probe-response buffer from these fields plus the IE blob
 * and drops it into the normal net80211 scan cache.
 */
struct ieee80211_fmac_bss {
	uint8_t		fb_bssid[IEEE80211_ADDR_LEN];
	uint8_t		fb_ssid[IEEE80211_NWID_LEN];
	uint8_t		fb_ssidlen;
	uint16_t	fb_capinfo;	/* host byte order */
	uint16_t	fb_bintval;
	int		fb_rssi;	/* dBm; negative */
	int		fb_noise;	/* dBm; negative */
	uint16_t	fb_chan_freq;	/* MHz */
	uint8_t		fb_chan_flags;	/* 2 = 2.4 GHz, 5 = 5 GHz */
	const uint8_t  *fb_ies;		/* concatenated TLVs from chip */
	size_t		fb_ielen;
};

/*
 * Assoc request. The framework passes this to the driver when
 * net80211 (or a user JOIN sysctl) asks to associate. Set fields
 * are non-zero. ssidlen of 0 means "use the stored config"
 * (some FullMAC chips associate with no host SSID at all).
 */
struct ieee80211_fmac_assoc {
	uint8_t		fa_bssid[IEEE80211_ADDR_LEN];
	uint8_t		fa_ssid[IEEE80211_NWID_LEN];
	uint8_t		fa_ssidlen;
	uint16_t	fa_chan_freq;
	uint32_t	fa_wpa_auth;	/* WPA_AUTH_* */
	uint32_t	fa_wsec;	/* CRYPTO_WEP/TKIP/AES bits */
	const uint8_t  *fa_ies;		/* host-built RSN IE etc. */
	size_t		fa_ielen;
};

/*
 * Ops table. Required entries are marked. Optional ones can be
 * NULL when the chip has no path for that. All ops run in
 * process or taskqueue context, never in an IRQ. The framework
 * defers anything that would come from a hardirq.
 *
 * Return value: 0 on success, errno on failure.
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

	/* Key install.  fmop_set_key required; del optional. */
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
	 * Optional. Send an EAPOL frame back to the host's
	 * wpa_supplicant. When NULL, the framework forwards it
	 * via ieee80211_input_all() like plain 802.3.
	 */
	int		(*fmop_eapol_tx)(struct ieee80211com *,
			    const void *buf, size_t len);

	/* Optional: power save knob. */
	int		(*fmop_set_powersave)(struct ieee80211com *,
			    bool enabled);
};

/*
 * Feature bits the driver passes to ieee80211_fmac_attach() so
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
