# brcm — FreeBSD driver for Broadcom FullMAC wifi

A native FreeBSD driver for Broadcom FullMAC wifi chips, the ones that run
their own firmware and leave the host to configure joins and install keys.
It comes as three loadable modules, one per bus, sharing one source tree in
`sys/dev/brcm/`:

- `brcm_pci` for PCIe cards
- `brcm_sdio` for SDIO chips on ARM boards such as the Raspberry Pi
- `brcm_usb` for USB dongles

Station mode with WPA2-PSK works on all three. net80211 and wpa_supplicant
drive the join and the 4-way handshake, and the driver installs the keys
in the firmware.

## Tested hardware

| Bus  | Chip                   | Where it was tested        |
|------|------------------------|----------------------------|
| PCIe | BCM43602 (`14e4:43ba`) | MacBook Pro, amd64         |
| SDIO | BCM43455               | Raspberry Pi 4, arm64      |
| USB  | BCM43236 rev B         | USB dongle on a Pi 4       |

Other chips are recognised by the driver's tables (PCIe BCM4350, 4360,
4364, 4365, 4366; SDIO BCM43430, 43456 and others; USB BCM43143, 43242,
43569), but they have not been tested, and most need firmware this
repository does not ship.

## Requirements

- FreeBSD 15.0 or later with kernel sources in `/usr/src`.  `brcm_usb` and
  `brcm_pci` build against the stock sources (tested on 15.0 and 15.1).
  `brcm_sdio` also needs the kernel's SDIO function layer
  (`sys/dev/mmc/sdio_func.[ch]` and the matching `mmc.c` changes), which
  stock FreeBSD does not have yet; it is on the `rkdev` branch of
  [FBSD_DEV](https://github.com/b1nc0d3x/FBSD_DEV).
- The net80211 cipher modules. The firmware does the encryption, but
  net80211 still needs `wlan_ccmp` (and `wlan_tkip` for TKIP group keys)
  loaded before keys can be installed, so load them first.
- Firmware. The modules under `sys/modules/*_fw` wrap the firmware images
  this repository ships (BCM43602, BCM43455, BCM43236) together with their
  licences. The BCM4360 module is only a slot: supply that image yourself.

## Build

Each module builds on its own. `SRCTOP` points at the top of this
repository:

```
cd sys/modules/brcm_sdio && make SRCTOP=$(pwd)/../../.. SYSDIR=/usr/src/sys
cd sys/modules/brcm_usb  && make SRCTOP=$(pwd)/../../.. SYSDIR=/usr/src/sys
cd sys/modules/brcm_pci  && make SRCTOP=$(pwd)/../../.. SYSDIR=/usr/src/sys
```

Build the matching firmware module the same way, for example
`sys/modules/brcmfmac43455_fw`.

## Install

Copy the modules and refresh the hints:

```
install -m 555 sys/modules/brcm_sdio/brcm_sdio.ko \
    sys/modules/brcmfmac43455_fw/brcmfmac43455_fw.ko /boot/modules/
kldxref /boot/modules
```

Install the devd rule, which creates the wlan interfaces once a device is
ready (its firmware can come up after the network has started, and USB
dongles can arrive at any time):

```
install -m 644 etc/devd/brcm.conf /usr/local/etc/devd/
service devd restart
```

Load the modules from `/etc/rc.conf`, cipher and firmware modules first:

```
kld_list="wlan_ccmp wlan_tkip brcmfmac43455_fw brcm_sdio"
```

For USB use `brcmfmac43236b_fw brcm_usb`, and for PCIe
`brcm_pci_fw_43602 brcm_pci`. Then name the interface and let rc run
wpa_supplicant and DHCP as usual (the PCIe device is `brcm_pci0`, so its
line is `wlans_brcm_pci0`):

```
wlans_brcm0="wlan0"
ifconfig_wlan0="WPA DHCP"
```

Each module brings its chip up from attach (firmware download, then
net80211), so there are no bring-up scripts.  `hw.brcm_sdio.autostart=0`
or `hw.brcm_pci.autostart=0` at the loader prompt turns that off.

`brcm_sdio` and `brcm_pci` cannot be unloaded while net80211 is
attached, so replacing them takes a reboot.  `brcm_usb` unloads once its
wlan interface is destroyed.

## Known issues

- With both an SDIO and a USB chip in one machine, list `brcm_sdio` before
  `brcm_usb` in `kld_list`.  If the USB device attaches first and the SDIO
  chip becomes `brcm1`, the SDIO chip associates but receives no data.

## Layout

```
sys/dev/brcm/
    brcm.c                  net80211 glue, joins, key install (shared)
    ieee80211_fullmac.c/.h  FullMAC layer over net80211 (shared)
    brcmreg.h, brcmvar.h    firmware interface definitions, softc
    brcm_chip.c/.h          chip backplane walk and core reset
    if_brcm_pci.c           PCIe attach, firmware download, rings
    brcm_pci_msgbuf.c/.h    msgbuf protocol (PCIe)
    if_brcm_sdio.c          SDIO attach and firmware bring-up
    brcm_sdpcm.c/.h         SDPCM framing (SDIO)
    brcm_sdio_regs.h        SDIO core registers
    if_brcm_usb.c           USB attach and firmware download
sys/modules/                one directory per module and firmware image
etc/devd/brcm.conf          creates wlan interfaces when a device is ready
```

## Credits

The driver was written for FreeBSD, but its firmware interface follows
Linux brcmfmac (Broadcom) and OpenBSD bwfm (Patrick Wildt). Files that
carry their definitions say so and keep their ISC notices.

## License

BSD-2-Clause, see `LICENSE`, except for the portions noted in individual
files, which are ISC. The firmware images are Broadcom's and come with
their own licences in `sys/modules/*_fw/`.
