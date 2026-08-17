# MFP join: the order of iovar steps

These are the steps to join a WPA2-PSK wifi with 802.11w turned on.
It uses a Broadcom FullMAC chip. We watched `brcmfmac` on Linux and
copied it in `brcm_join_wpa2_host_eapol` inside `brcm.c`.

The four steps marked `* NEW *` are all needed. If you skip any one,
the chip will say no (SET_SSID FAIL / status=1). Or it will drop the
link during the group key step.

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

Next, wpa_supplicant runs the 4-way handshake. The driver hands each
key to the chip using the `wsec_key` iovar (164 bytes):

```
wsec_key(idx=0, algo=AES_CCM, ea=AP_MAC,   flags=0)              # PTK
wsec_key(idx=1, algo=AES_CCM, ea=00:00…,   flags=PRIMARY_KEY)    # GTK
wsec_key(idx=4, algo=AES_CCM, ea=00:00…,   flags=0, rsc=IPN)     # IGTK (BIP)
BRCMF_C_SET_SCB_AUTHORIZE(AP_MAC)                                 # dcmd 121
```

The chip knows IGTK from GTK by the key index (4 or higher).
Once the IGTK is set, the chip itself checks BIP-CMAC-128 on
protected management frames.

## What you need first

For IGTK to reach the driver, net80211 must accept `IOC_WPAKEY`
with `kid >= 4`. Stock FreeBSD 15.x says no. See
`docs/patches/net80211-igtk-support.diff`.
