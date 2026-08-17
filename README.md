# brcm — FreeBSD FullMAC driver for Broadcom wifi

A native FreeBSD driver for Broadcom FullMAC wifi chips. It
supports the three common ways these chips plug in:

- **`brcm_pci`** — PCIe cards, mainly BCM43602 (`14e4:43ba`)
- **`brcm_usb`** — USB dongles (BCM43143, 43236b, 43242a, 4329,
  4330, 4334, 4335 etc.)
- **`brcm_sdio`** — SDIO chips found on ARM boards (BCM43143,
  43241, 4329, 4330, 4334, 4335, 43362, 43430, 43455 etc.)

The three bus bindings share the net80211 glue, the chip
backplane walk, the FullMAC shim, and register defs. All in one
`sys/dev/brcm/` tree. Each loadable module builds only the parts
it needs.

## Status

- **`brcm_pci`** on BCM43602 — STA mode, WPA2-PSK,
  WPA2-PSK-SHA256, and 802.11w MFP (BIP-CMAC-128) all work
  end-to-end. PTK, GTK, and IGTK install. DHCP finishes.
  Over-the-air captures show MFP is on.
- **`brcm_usb`** and **`brcm_sdio`** — attach, firmware upload,
  and basic net80211 registration all work. They use the same
  core join code but have had less testing than PCIe.

## What is known to work

- WPA2-PSK join + DHCP + real traffic
- WPA2-PSK-SHA256 + 802.11w MFP (BIP-CMAC-128) with IGTK
  install
- Rejoining across different SSIDs (both ways)
- Scanning while joined (no hang, link stays up)
- Over-the-air MFP check: an Atheros card in monitor mode saw
  protected Action frames from the AP that our chip accepted


## Build

Each transport is its own loadable module. Build only what you
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

Put the `.ko` file under `/boot/modules/` and `kldload` the one
you want.

## Kernel needs (802.11w / IGTK)

FreeBSD 15.x's stock `net80211` says no to `IOC_WPAKEY` with
`kid >= 4`. That stops the IGTK install and blocks MFP from
finishing. You have two choices:

1. Apply the net80211 IGTK-slots patch. It mirrors Adrian
   Chadd's WIP D46668 and adds IGTK slots 4/5 to the per-VAP
   key table. Then rebuild the kernel plus all wlan modules and
   reboot. The patch is queued for freebsd-wireless / Adrian
   upstream. Email us if you want an early copy.
2. Skip MFP. The driver still joins fine to non-MFP APs
   (`pmf=disable` on the AP or `pmf=0` in wpa_supplicant.conf).

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

BSD-2-Clause. See `LICENSE`.
