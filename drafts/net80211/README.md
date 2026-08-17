# FullMAC helper layer (draft)

This code lives in `drafts/net80211/` and not in
`/usr/src/sys/net80211/`. The API is still being shaped while one
driver moves onto it.

Once `brcm` swaps its fake beacon, link task, and `iv_newstate`
hook over to these calls, the diff will be small. Then
`ieee80211_fullmac.h` and `ieee80211_fullmac.c` can go upstream
as a patch to `sys/net80211/`.

## What net80211 needs from you

One new field in `struct ieee80211com`. This lets the framework
store its own state without stepping on other slots:

```c
/* sys/net80211/ieee80211_var.h, near the end of ieee80211com {} */
void			*ic_fmac;	/* FullMAC framework state */
```

That is the whole change. All the other bits
(`ic_scan_start`, `ic_scan_end`, `iv_newstate`, `iv_key_set`,
`iv_key_delete`) get rewired by the framework and put back on
detach. Old SoftMAC drivers are not touched.

## Plan for moving `brcm` over

About seven changes land:

1. Driver fills a `struct ieee80211_fullmac_ops` with helpers it
   already has (`brcm_scan_start_fw`, `brcm_assoc_now`, etc.).
2. `brcm_attach()` calls `ieee80211_fmac_attach(ic, &brcm_fmops, ...)`
   right before `ieee80211_ifattach()`.
3. `brcm_vap_create()` calls `ieee80211_fmac_vap_attach(vap)` after
   making the vap, before returning it.
4. The ~80 lines that build a fake beacon in `brcm_rx_frame()`
   shrink to one `ieee80211_fmac_scan_result()` call.
5. `brcm_link_task()` (~40 lines that fast-forward the state
   machine) becomes `ieee80211_fmac_link_up(ic, bssid)`.
6. The disassoc / link-loss handler becomes
   `ieee80211_fmac_link_down(ic, reason)`.
7. `brcm_eapol_rx_forward()` becomes `ieee80211_fmac_eapol_rx()`.

Rough size: about -400 / +60 lines in `brcm.c`. The old
`brcm_sta_join_from_cache`, `brcm_link_task`, and beacon-fake
helper all go away. The framework owns them.

## Open API questions while brcm moves

The RSN IE plumbing is the biggest one. `fmop_assoc` today takes
`(wpa_auth, wsec, ies)`. But the driver is the one that knows the
chip's wire format for those fields.

I do not know yet what is better. The framework could copy
net80211's RSN IE as-is and let the driver translate it. Or it
could pre-decode to `(auth, cipher)` pairs. brcm needs the raw IE
for its `wpaie` iovar, so I lean toward raw. But then chips with
a smaller IE grammar do more work than they should.

Channel set. Today net80211's regdomain pushes a channel list
into `ic_channels[]`. But FullMAC chips have their own idea of
which channels work (based on firmware).

I think `fmop_set_country` should return the firmware-approved
channel list so the framework can match them up. But I want to
see at least one non-brcm driver first before locking the ops
table into that shape.

Scan parameters. `fmop_scan_start` takes one SSID. net80211's
scan API can do multi-SSID and per-channel dwell. Wait until a
driver actually needs those.

Stats. Most FullMAC chips have rich stats (RSSI, TX retries) that
net80211 wants via `ieee80211_node_stats`. I will add a
`fmop_get_link_stats` op when there is a user for it.

The TX path stays in the driver. BCDC / IPC framing is
bus-specific. So `fmop_tx_eapol` for symmetry would also need
`fmop_tx_data`. At that point the framework would be redoing
net80211's TX queue. Not worth it.

## Test plan

The framework can only be tested by a real driver using it.
To ship:

1. `brcm` uses the framework, builds clean with no warnings.
2. Steps 4 and up from `STATUS.md` pass the same on patched and
   unpatched `brcm`.
3. Give `iwm` and `iwx` MVM-mode paths a look for the same
   refactor. No promise, just a look.

The header and core build cleanly against a made-up `ic_fmac`
slot in `ieee80211_var.h`. No in-tree user yet.
