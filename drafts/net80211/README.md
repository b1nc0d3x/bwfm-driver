# FullMAC adaptation layer (draft)

This lives in `drafts/net80211/` and not in `/usr/src/sys/net80211/`
because the API is open while at least one merged driver migrates
onto it.  Once `brcm` switches its synthesised beacon, link-task, and
`iv_newstate` intercept code over to these calls and the diff is
bounded, `ieee80211_fullmac.h` + `ieee80211_fullmac.c` become an
upstreamable patchset against `sys/net80211/`.

## What net80211 needs from you

One new field in `struct ieee80211com` so the framework can find its
per-com state without colliding with existing slots:

```c
/* sys/net80211/ieee80211_var.h, near the end of ieee80211com {} */
void			*ic_fmac;	/* FullMAC framework state */
```

That's the whole delta.  Everything else (`ic_scan_start`,
`ic_scan_end`, `iv_newstate`, `iv_key_set`, `iv_key_delete`) is
rewired in place by the framework and restored on detach, so existing
SoftMAC drivers are unaffected.

## Migration plan for `brcm`

Roughly seven hunks land:

1. Driver fills a `struct ieee80211_fullmac_ops` with existing
   helpers (`brcm_scan_start_fw`, `brcm_assoc_now`, etc.).
2. `brcm_attach()` calls `ieee80211_fmac_attach(ic, &brcm_fmops, ...)`
   immediately before `ieee80211_ifattach()`.
3. `brcm_vap_create()` calls `ieee80211_fmac_vap_attach(vap)` after
   the vap is created, before returning it.
4. The ~80 lines of synthesised-beacon building in `brcm_rx_frame()`
   collapse to one `ieee80211_fmac_scan_result()` call.
5. `brcm_link_task()` (~40 lines of state-machine fast-forwarding)
   becomes `ieee80211_fmac_link_up(ic, bssid)`.
6. The disassoc / link-loss event handler becomes
   `ieee80211_fmac_link_down(ic, reason)`.
7. `brcm_eapol_rx_forward()` becomes `ieee80211_fmac_eapol_rx()`.

Estimated diff: about -400 / +60 in `brcm.c`.  The custom
`brcm_sta_join_from_cache`, `brcm_link_task`, and beacon-synthesis
helper all disappear; the framework owns them.

## Open API questions while brcm migrates

The RSN IE plumbing is the biggest one.  `fmop_assoc` currently takes
`(wpa_auth, wsec, ies)`, but the driver is the one that knows the
chip's wire format for those fields.  I don't know yet whether the
framework should copy net80211's RSN IE verbatim and let the driver
translate, or pre-decode to `(auth, cipher)` pairs.  brcm needs the
verbatim IE for its `wpaie` iovar, so I'm leaning verbatim, but that
leaves anything with a smaller IE grammar doing more work than it
needs to.

Channel set: today net80211's regdomain pushes a channel list into
`ic_channels[]`, but FullMAC chips have their own idea of available
channels (firmware-dependent).  I think `fmop_set_country` should
return the firmware-validated channel list so the framework can
reconcile, but I want to see at least one non-brcm consumer first
before I commit the ops table to that shape.

Scan parameters: `fmop_scan_start` takes one SSID, and net80211's scan
API can do multi-SSID + per-channel dwell.  Defer until a driver
actually uses those.

Statistics: most FullMAC chips have rich stats (RSSI, TX retries) that
net80211 wants via `ieee80211_node_stats`.  I'll add a
`fmop_get_link_stats` op when there's a consumer.

The TX path stays with the driver.  BCDC / IPC framing is bus-specific,
so `fmop_tx_eapol` for symmetry would also need `fmop_tx_data`, and at
that point the framework is re-implementing net80211's TX queue.  Not
worth it.

## Test plan

The framework is unit-testable only insofar as a real driver exercises
it.  Acceptance:

1. `brcm` migrated to the framework, builds clean with no warnings.
2. Acceptance ladder from `STATUS.md` step 4+ passes identically on
   patched vs unpatched `brcm`.
3. `iwm` and `iwx`'s MVM-mode paths get an eyeball for the same
   refactor opportunity.  No commitment, just look.

The header and core compile cleanly against a hypothetical `ic_fmac`
slot in `ieee80211_var.h`.  No in-tree consumer yet.
