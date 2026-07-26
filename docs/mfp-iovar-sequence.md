# MFP-negotiated association: iovar sequence

Reference iovar sequence for a WPA2-PSK + 802.11w association on a
Broadcom FullMAC chip, as observed on `brcmfmac` (Linux) and mirrored
in `brcm_join_wpa2_host_eapol` in `brcm.c`.  Any of the four
`* NEW *` steps that get skipped will cause the fw to reject the join
(SET_SSID FAIL / status=1) or drop the association during the group
handshake.

```
DOWN                                                              # WLC_DOWN
SET_INFRA(1)                                                      # dcmd 20
wpaie(<28-byte MFP-capable RSN IE from vap->iv_appie_wpa>)        # iovar
mfp(BRCM_MFP_CAPABLE)                                             # iovar
SET_AUTH(BRCM_AUTH_OPEN)                                          # dcmd 22
wpa_auth = 0xc0    (WPA2_UNSPEC|WPA2_PSK)                         # * NEW *  first pass
wsec = BRCM_WSEC_AES                                              # iovar
wpa_auth = 0x80    (WPA2_PSK)                                     # * NEW *  final AKM
UP                                                                # WLC_UP
SET_WSEC_PMK(brcm_wsec_pmk_le, 132 bytes)                         # * NEW *  cmd 268
join_pref(2 * brcm_join_pref_params, 8 bytes)                     # * NEW *  iovar
SET_ASSOC_PREFER(WLC_BAND_AUTO)                                   # dcmd 205
join(brcm_ext_join_params, 70 bytes)      # bsscfg:join iovar     # * NEW *  NOT SET_SSID dcmd
  ^-- fw responds with AUTH → ASSOC → LINK → SET_SSID events
```

Then userspace wpa_supplicant runs the 4-way handshake, driver
forwards each derived key to fw via `wsec_key` iovar (164 bytes):

```
wsec_key(idx=0, algo=AES_CCM, ea=AP_MAC,   flags=0)              # PTK
wsec_key(idx=1, algo=AES_CCM, ea=00:00…,   flags=PRIMARY_KEY)    # GTK
wsec_key(idx=4, algo=AES_CCM, ea=00:00…,   flags=0, rsc=IPN)     # IGTK (BIP)
BRCMF_C_SET_SCB_AUTHORIZE(AP_MAC)                                 # dcmd 121
```

Fw distinguishes IGTK from GTK by key index (>= 4).  BIP-CMAC-128
integrity checking of protected mgmt frames runs entirely inside fw
once the IGTK is installed.

## Prerequisites

For IGTK install to reach the driver, net80211 must accept
`IOC_WPAKEY` with `kid >= 4`.  Stock FreeBSD 15.x rejects this — see
`docs/patches/net80211-igtk-support.diff`.
