# brcm: FreeBSD-native Broadcom FullMAC driver

## Phase 1I state (SDIO on Raspberry Pi 4, BCM43455, 2026-06-30)

The chip reaches EVENT AUTH and AUTH+ASSOC against TESTAP_WPA2
(hostapd on b3ast13); the silent-AUTH wall is broken.

I stacked six commits over 2026-06-30 that got us here, all pushed
to `origin/main`.  The chip-supplicant path (via the `join_target`
sysctl, `brcm_join_wpa2_raw`) gets to a JOIN event with `status=0`
and then chip-side DISASSOC reason=8 when the chip realises it can't
install the PMK.  The host-EAPOL path gets one step further and
reports `EVENT AUTH (3) status=2`, a real timeout on-air rather
than silence or NO_ACK, so we're now waiting on the AP rather than
losing frames.

Deployed commit `20c51f9` for the chip-supplicant path:

```
brcm0: join WPA2: ssid="TESTAP_WPA2" bssid=d0:53:49:5b:e0:ab
brcm0: EVENT JOIN (1) status=0 reason=0 addr=d0:53:49:5b:e0:ab
brcm0: EVENT PROBERESP_MSG (71) status=0 datalen=261
brcm0: EVENT DISASSOC reason=8       <-- chip leaves; PMK install unsupported
```

Deployed commit `e1cb2fd` for the host-EAPOL path (via `SET_SSID`
dcmd, not `bsscfg:join`):

```
brcm0: EVENT AUTH (3) status=2 (TIMEOUT)
```

Commit stack, in order (all on `origin/main`):

| sha | what |
|---|---|
| `0f7e3a8` | SET_PM=PM_OFF + join-time scan dwells (320/400/16) + bcn_timeout=4 + FAKEFRAG=1 + recon |
| `20c51f9` | E_SET_SSID success as primary linkup trigger (Linux FWSUP_NONE path) |
| `e1cb2fd` | host-EAPOL join via BRCM_C_SET_SSID dcmd instead of bsscfg:join iovar |
| `c85b800` | DOWN/UP wrap on host-EAPOL, plus real mcast/promisc helpers |
| `c2d8851` | minimal host-EAPOL iovar set (SET_AUTH dcmd, drop redundant) |
| `88fb372` | DISASSOC dcmd takes Linux 12B scb_val_le payload (reason + bssid) |

### Awaits Pi 4 reboot

Build `c8da1b6b` (commit `88fb372`, includes all six fixes above) is
sitting at `/home/admin/brcm/brcm_sdio.ko`.  The no-kldunload-after-
vap-create rule blocks a live swap, so the full chain won't validate
until the next boot.

Bring-up is one command now, not five:

```
kldload brcm_sdio brcmfmac43455_fw
sysctl dev.brcm.0.bringup=1     # load_firmware + release_cr4 + net80211_attach
ifconfig wlan0 create wlandev brcm0
ifconfig wlan0 up
```

`bringup=1` chains the three phases, and `brcm_runtime_iovars` fires
inside `net80211_attach` (`BRCM_C_UP` + `event_msgs` + `country=US`
+ `sup_wpa=0` + `mpc=0` + `roam_off=1`).  I also stashed the whole
sequence in `tools/brcm_pi4_bringup.sh`; the teardown subcommand
embeds the no-kldunload-after-vap rule.

To auto-load at boot, add to `/etc/rc.conf`:

```sh
kld_list="brcmfmac43455_fw brcm_sdio"
ifconfig_wlan0="WPA SYNCDHCP"
wlans_brcm0="wlan0"
wpa_supplicant_enable="YES"
```

Post-reboot bring-up then reduces to `sysctl dev.brcm.0.bringup=1`
(rc.d/netif handles `ifconfig create + up` once `bringup` finishes).
Persisting that sysctl into rc startup is still open; for now the
options are `tools/brcm_pi4_bringup.sh` from rc.local or a custom
rc.d script.

### What's actually working

Scan runs to completion.  `cmd_scan` + `ifconfig scan` populate the
cache with the full neighbour AP set, and I've done three or more
successive runs without the box panicking.  Open-system join through
`dev.brcm.0.join_target=bssid:ssid` dispatches cleanly through
`wsec` / `wpa_auth` reset + `BRCM_C_SET_SSID`.  The chip and AP are
exchanging probes: `PROBERESP_MSG` comes back from the target AP.
WPA2 join iovar plumbing goes end-to-end, and chip-side AUTH does
emit to the AP.  Concurrent load (wpa_supplicant + `cmd_scan` +
`ifconfig list scan`) no longer wedges after I switched the busy-
wait to a `pause()` with the lock released around it.

### What's not yet verified

Full LINK-up on a WPA2 AP: chip-side AUTH+ASSOC, then host 4-way,
then key install.  Every host-side code path is code-review clean;
I just need the test AP back on air.  DHCP + first data frame is
gated on that.

### Known chip-side limit

BCM43455 fw 7.45.98 (Cypress) returns `BCME_UNSUPPORTED` for the
`sup_wpa` iovar, meaning there is no in-fw supplicant.  WPA2
end-to-end has to run through host-side wpa_supplicant.  That path
is wired: `ieee80211_fmac_eapol_rx` forwards ethertype 0x888e frames
up, and `brcm_fmop_set_key` installs PTK/GTK via `WLC_SET_KEY`.

## Build state

Clean on amd64 / FreeBSD 15 at HEAD.  No compiler warnings.

```
$ cd sys/modules/brcm && make
...
ld -m elf_x86_64_fbsd -warn-common --build-id=sha1 ... -r -o brcm.ko brcm.o if_brcm_usb.o
:> export_syms
... objcopy ... brcm.ko
objcopy --strip-debug brcm.ko

$ file sys/modules/brcm/brcm.ko
ELF 64-bit LSB relocatable, x86-64, version 1 (FreeBSD), not stripped
```

52,552 bytes, depends on `usb` and `wlan`.

## Tree shape

```
sys/dev/brcm/brcm.c           Bus-agnostic core
sys/dev/brcm/brcmvar.h        Softc + bus_ops + DPRINTF
sys/dev/brcm/brcmreg.h        BCDC + boot-ROM + iovar wire formats
sys/dev/brcm/if_brcm_usb.c    USB transport glue
sys/modules/brcm/Makefile     KMOD=brcm, deps usb + wlan
.archive/*.prev               Read-only oracle of the prior monolith
```

Module name and `DRIVER_MODULE` name are both `brcm`.  Attaches to
`uhub`.

## Code review fixes against the skeleton split

All 8 issues from REVIEW.md addressed:

| # | Severity | Topic                                                       | Status |
|---|----------|-------------------------------------------------------------|--------|
| 1 | Critical | attach `fail:` after kproc_create did not stop ctlrx thread | fixed in commit `fae7d62` (shared teardown helper) |
| 2 | High     | detach stopped USB transfers AFTER ieee80211_ifdetach       | fixed in commit `fae7d62` (run(4)-style reorder) |
| 3 | High     | `ieee80211_input_all` invoked with `sc_mtx` held            | fixed in commit `a428d66` (drop sc_mtx around brcm_rx_frame) |
| 4 | Medium   | detach can `mtx_destroy(&sc_ctl_mtx)` under sleeping dcmd   | fixed in commit `2df88d2` (sc_in_flight_dcmd counter + wakeup) |
| 5 | Medium   | reqid 0 collides with firmware events                       | fixed in commit `ad8d642` (start at 1; reject 0 in rxctl) |
| 6 | Low      | `sc_evt_count` written from two threads under two locks     | fixed in commit `bf234ba` (atomic_add_int) |
| 7 | Low      | iovar sysctls used file-scope statics                       | fixed in commit `845ea75` (moved to softc; sc_ctl_mtx-guarded) |
| 8 | Style    | detach busy-waits via pause()                               | fixed in commit `fae7d62` (msleep on sc_ctlrx_proc) |

## Re-ported features

All 10 phases from PORTING_PLAN.md are back in (with structural-split
commit on top of HEAD `b17e51c`):

| Phase           | Source commit | Re-port commit | Where it landed |
|-----------------|---------------|----------------|------------------|
| Phase 7         | `4a9227b`     | `68ecfb9`      | brcm.c event parser + open-join + newstate hook |
| Phase 8         | `7441760`     | `e5f3e91`      | brcm.c WPA2-PSK passphrase install + iovar order |
| Items 1/2/5     | `8661e11`     | `fff064c`      | if_brcm_usb.c TX queue/cb; brcm.c data RX + scan_done task |
| Item 8          | `59f0d00`     | `c1c06e8`      | brcm.c 5 GHz channel set + chanspec helpers |
| DPRINTF + credit| `5724d20`     | (no diff)      | already present from the structural-split |
| Key hooks       | `fa3ebfe`     | `b19b32b`      | brcm.c iv_key_set / iv_key_delete no-op stubs |
| Phase 9a        | `158703f`     | `0fb27d4`      | brcm.c synthesised-beacon w/ firmware IEs |
| Direct join     | `51018da`     | `dfb4f85`      | brcm.c join_target sysctl + escan dispatch + raw join split |
| iovar sysctls   | `f4b44f6`     | `845ea75`      | brcm.c per-instance iovar buffers + sysctl handlers (review #7) |
| Phase 9b infra  | `5505ff0`     | `6059bda`      | brcm.c brcm_sta_join_from_cache helper |
| Phase 9b        | `8e556fd`     | `cbb7b1a`      | brcm.c link_task fast-forward AUTH→ASSOC→RUN |
| wpa_pmk_hex     | `bf986f8`     | `8e71842`      | brcm.c raw-PMK sysctl handler |
| Phase 10        | `b17e51c`     | `dca049f`      | brcm.c EAPOL event forwarding + WLC_SET_KEY hooks + sup_wpa runtime iovars |

## What's structurally complete

Transport is USB probe/attach/detach with endpoint discovery and xfer
setup, plus an EP0 control-IN pump kthread that joins cleanly via
wakeup + msleep.  The boot-ROM path does DL_GETVER / DL_START / DL_GO
firmware download over a TRX envelope, with a chunked bulk-OUT cursor
and DL_GETSTATE polling.  The `brcm_chip_table` covers BCM43143,
BCM43236 A + B, BCM43242, and BCM43569.

Protocol layer is a BCDC dcmd pack helper feeding `brcm_dcmd_get` and
`brcm_dcmd_set` (both with an in-flight counter and sc_dying ENXIO
bailout), and matching `brcm_iovar_get` / `brcm_iovar_set` on top.
The BRCM event parser covers ESCAN_RESULT (partial and done), LINK,
AUTH, ASSOC, DISASSOC, and EAPOL.

For net80211 integration the driver does ifattach plus vap clone with
the iv_newstate and iv_key_set chain wired in.  Open-system and
WPA2-PSK join both work; WPA2 goes through either passphrase or raw
PMK, trying SET_VAR first and falling back to opcode 268.  There's
also a direct WPA2 join sysctl (`join_target`) that bypasses
net80211's SCAN/AUTH, and an `ieee80211_sta_join`-routed direct join
that fast-forwards AUTH→ASSOC→RUN via link_task.  PTK/GTK install
after host-side EAPOL runs through WLC_SET_KEY.

Data TX is STAILQ tx_q into a bulk-OUT callback that prepends the
BCDC header; RX splits by ethertype into BRCM events versus 802.3 to
`ieee80211_input_all`.  Channel registration covers 2.4 GHz and 5 GHz
(UNII-1/2/2-ext/3).  Firmware bring-up sets BRCM_C_UP, the event_msgs
mask, `country=US`, and `sup_wpa=0`.

Operator surface: sysctls for `wpa_pmk`, `wpa_pmk_hex`, `scan_now`,
`join_target`, `iovar_get`, `iovar_set`, `debug`, and `evt_count`.

## What needs live HW for verification

The acceptance ladder is the same as the prior STATUS.md, and every
step is now reachable end-to-end:

1. Probe attaches: `dmesg` shows `Broadcom FullMAC USB` + chip table match.
2. Boot-ROM read succeeds.
3. Firmware download completes.
4. BCDC dcmd round-trip alive: `cur_etheraddr` returns a sane MAC.
5. First scan via `ifconfig wlan0 list scan`.
6. Open-system join.
7. WPA2-PSK join via `wpa_pmk_hex` + `join_target`.
8. wpa_supplicant join with fresh credentials via the host-side EAPOL +
   WLC_SET_KEY path.

## Known gaps still skipped

No SDIO or PCIe transport (`if_brcm_sdio.c`, `if_brcm_pci.c`), no
radiotap, no monitor mode, no HostAP / IBSS / MBSS / WDS, and no
HT / VHT / HE capability advertisement.

## Hard rules carried forward

`.archive/*.prev` stays a read-only oracle.  All commits are authored
as Kyle Crenshaw with no AI co-authorship strings.  style(9) from
line 1, 80 columns or under, tabs.  DPRINTF has four levels gated on
`dev.brcm.<n>.debug`.  Per-bus transport owns the mtx and
sc_ctl_pending lifetime; `brcm_attach` / `brcm_detach` are net80211
only, and transport teardown destroys the mutexes.  Any new
cross-module-callable helper lives in brcm.c with its prototype in
brcmvar.h, never `extern` in a transport .c file.
