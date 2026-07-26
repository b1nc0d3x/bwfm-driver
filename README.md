# brcm — FreeBSD FullMAC driver for Broadcom wifi

Native FreeBSD driver supporting the three common bus attachments for
Broadcom FullMAC wifi silicon:

- **`brcm_pci`** — PCIe cards, notably BCM43602 (`14e4:43ba`)
- **`brcm_usb`** — USB dongles (BCM43143, 43236b, 43242a, 4329, 4330,
  4334, 4335 etc.)
- **`brcm_sdio`** — SDIO chips common on ARM SBCs (BCM43143, 43241,
  4329, 4330, 4334, 4335, 43362, 43430, 43455 etc.)

The three bus bindings share the net80211 glue, chip-backplane walk,
FullMAC shim, and register defs in a single `sys/dev/brcm/` tree; each
loadable module builds only what it needs.

## Status

- **`brcm_pci`** on BCM43602 — STA mode, WPA2-PSK, WPA2-PSK-SHA256,
  802.11w MFP (BIP-CMAC-128) all working end-to-end.  PTK/GTK/IGTK
  install, DHCP completes, on-air captures confirm MFP protection is
  active.
- **`brcm_usb`** / **`brcm_sdio`** — attach + firmware upload + basic
  net80211 registration.  Association paths reuse the same core but
  are less battle-tested than the PCIe port.

## Build

Each transport is an independent loadable module.  Build only what you
need:

```
# PCIe
cd sys/modules/brcm_pci  && SRCTOP=$(pwd)/../../.. make
# USB
cd sys/modules/brcm_usb  && SRCTOP=$(pwd)/../../.. make
# SDIO (needs a newer sdio_func.h than /usr/src ships on 15.x —
# point KERN_TREE at a CURRENT checkout)
cd sys/modules/brcm_sdio && SRCTOP=$(pwd)/../../.. KERN_TREE=/path/to/freebsd-src make
```

Install the resulting `.ko` under `/boot/modules/` and `kldload` the
one you need.

## Kernel prerequisites (802.11w / IGTK)

FreeBSD 15.x's stock `net80211` rejects `IOC_WPAKEY` with `kid >= 4`,
which blocks IGTK install and prevents MFP from completing.  Two
options:

1. Apply the WIP net80211 patch (D46668 by Adrian Chadd) that extends
   the per-VAP key table to include IGTK slots 4/5, rebuild the
   kernel + all wlan modules, and reboot.
2. Live without MFP — the driver still associates cleanly to non-MFP
   APs (`pmf=disable` on the AP or `pmf=0` in wpa_supplicant.conf).

## Layout

```
sys/dev/brcm/
    if_brcm_pci.c           PCIe bus attach, DMA, IRQ, PLL/PMU init
    if_brcm_usb.c           USB bus attach, bulk-URB fw upload
    if_brcm_sdio.c          SDIO bus attach
    if_brcm_sdio_cdev.h     SDIO character device iface
    brcm_pci_msgbuf.c/.h    msgbuf ring protocol (host <-> fw, PCIe)
    brcm_sdpcm.c/.h         SDPCM protocol framing (SDIO)
    brcm.c                  shared net80211 glue, join/roam, key install
    brcm_chip.c/.h          silicon backplane walk, core reset
    brcm_sdio_regs.h        SDIO core register defs
    ieee80211_fullmac.c/.h  FullMAC shim over net80211
    brcmreg.h               chip register defs, iovar constants
    brcmvar.h               softc, struct definitions
    brcm_srom_v11_table.h   SROM v11 layout
    brcm_stub_arm64.c       arm64 probe-only stub build
sys/modules/
    brcm_pci/Makefile       PCIe kmod
    brcm_usb/Makefile       USB kmod
    brcm_sdio/Makefile      SDIO kmod
```

## License

BSD-2-Clause.  See `LICENSE`.
