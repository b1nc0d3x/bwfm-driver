# What goes with what

bwfm is one driver with three parts, one for each way a Broadcom WiFi
chip can be connected: PCIe, USB and SDIO.  Each part is its own kernel
module.  This page says, for each one, what it needs from FreeBSD,
which patches (if any) go with it, and what has been tested.

Everything here was checked on 2026-11-04 and 2026-11-05.

## The short answer

| Bus  | Module      | Needs kernel patches?                   | Tested on                                  |
|------|-------------|-----------------------------------------|--------------------------------------------|
| PCIe | `bwfm_pci`  | No                                      | Stock FreeBSD 15.1, amd64 (BCM43602)       |
| USB  | `bwfm_usb`  | No                                      | Stock FreeBSD 15.1, amd64; FreeBSD 15.1, arm64, Raspberry Pi 4 (BCM43236) |
| SDIO | `bwfm_sdio` | Yes: `01-mmc-sdio-function-driver.diff` | FreeBSD 15.1 + patches, Raspberry Pi 4 (BCM43455) |

For 802.11w and WPA3, see "Extra features" below.  Those need one more
kernel patch on any bus.

## PCIe: `bwfm_pci`

- **Kernel:** stock FreeBSD 15.1.  No patches.
- **Firmware module:** `bwfm_pci_fw_43602` (BCM43602).
- **Tested:** a MacBook Pro (BCM43602) running the stock 15.1-RELEASE
  GENERIC kernel, amd64.
- **Works:** WPA2 station, open networks, access point mode with
  hostapd, and an 802.11w access point (with the extra patches below).
  802.11w as a station has not been tested on this chip.
- **Does not work:** WPA3.  The BCM43602 firmware has no SAE support.
- **arm64:** the module builds, but only probes the card.  It does not
  bring up WiFi there.

## USB: `bwfm_usb`

- **Kernel:** no patches.  The USB part uses only what stock FreeBSD
  already has.  None of the kernel patches in `docs/patches` are for
  USB.
- **Firmware module:** `brcmfmac43236b_fw` (BCM43236).
- **Tested:** a BCM43236 USB stick on two machines.  One is a MacBook
  Pro running the stock 15.1-RELEASE GENERIC kernel, amd64, with no
  patches at all.  The other is a Raspberry Pi 4, FreeBSD 15.1, arm64.
  That Pi's kernel carries the SDIO and net80211 patches for the
  built-in WiFi; the USB part does not use them.
- **Works:** WPA2 station, open networks, roaming done by the firmware.
- **Does not work:** 802.11w and WPA3.  The BCM43236 firmware has
  neither.

## SDIO: `bwfm_sdio`

- **Kernel:** needs `docs/patches/freebsd-15.1/01-mmc-sdio-function-driver.diff`.
  Stock FreeBSD has no way for a driver to talk to an SDIO WiFi chip.
  This patch adds that layer (`sdio_func`), the card interrupt, and the
  Raspberry Pi 4 SD controller changes.  Without it the module will
  not load.
- **Firmware module:** `brcmfmac43455_fw` (BCM43455).
- **Tested:** the built-in WiFi of a Raspberry Pi 4, FreeBSD 15.1,
  arm64, with patches 01 and 02.
- **Works:** WPA2 station, WPA3 station (SAE, with the extra patches
  below), 802.11w, access point mode.

## Extra features

These need patches on top of whatever the bus needs.

| Feature | Kernel patch | Userland patch | Which chips |
|---------|--------------|----------------|-------------|
| 802.11w station (protected management frames) | `freebsd-15.1/02-net80211.diff` | none | BCM43455 (tested) |
| 802.11w access point | `freebsd-15.1/02-net80211.diff` | `hostapd-rsn-mfp-explicit-group-mgmt.diff` | BCM43602 |
| WPA3 station (SAE) | `freebsd-15.1/02-net80211.diff` | `wpa_supplicant-driver_bsd-external-sae.diff` | BCM43455 only |

Why each one is needed:

- **`02-net80211.diff`:** 802.11w adds two new keys, in key slots 4 and
  5.  Stock net80211 only has room for slots 0 to 3, so the key can't
  be installed.  WPA3 always uses 802.11w, so it needs this too.
- **The wpa_supplicant patch:** for WPA3, the BCM43455 firmware asks
  the computer to do the password math (SAE).  This patch teaches
  wpa_supplicant's FreeBSD driver to answer.  The wpa_supplicant must
  also be built with `CONFIG_SAE` and `CONFIG_SME`.  FreeBSD 15.1's
  base wpa_supplicant has neither.
- **The hostapd patch:** the BCM43602 firmware writes one part of its
  security information (the RSN element) a little differently from
  hostapd.  Stations compare the two, see a mismatch, and disconnect.
  The patch makes hostapd write it the same way.

## One rule for building

A module must be built against the same net80211 headers as the
kernel it runs on.  `02-net80211.diff` changes the size of a kernel
structure (`struct ieee80211vap`).  So:

- Kernel with `02-net80211.diff`: build the modules with patched headers.
- Stock kernel: build the modules with stock headers.

If they don't match, the module loads but joins quietly fail.

## The FullMAC patch series

`docs/patches/net80211-fullmac-series/` is the FullMAC framework as a
patch series for FreeBSD main.  You don't need it to use the driver:
each module builds its own copy of the framework when the kernel
doesn't have one (`sys/modules/bwfm.fullmac.mk`).

## How a reviewer can try it

PCIe and USB: build the module and load it with `kldload`.  No new
kernel is needed.

SDIO: apply the kernel patches to FreeBSD 15.1 (the README in
`docs/patches/freebsd-15.1` lists the exact version and order), build a
kernel, and boot it once with `nextboot -k` so the normal kernel stays
safe.  A jail won't work: a jail shares the main kernel and can't run a
different one.  The test machine needs an SDIO WiFi chip; a Raspberry
Pi 4 is the easy choice.
