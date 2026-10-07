# bwfm — FreeBSD driver for Broadcom FullMAC wifi

A native FreeBSD driver for Broadcom FullMAC wifi chips, the ones that run
their own firmware and leave the host to configure joins and install keys.
It comes as three loadable modules, one per bus, sharing one source tree in
`sys/dev/bwfm/`:

- `bwfm_pci` for PCIe cards
- `bwfm_sdio` for SDIO chips on ARM boards such as the Raspberry Pi
- `bwfm_usb` for USB dongles

Station mode with WPA2-PSK works on all three. net80211 and wpa_supplicant
drive the join and the 4-way handshake, and the driver installs the keys
in the firmware. Access point mode, open or WPA2 through hostapd(8), has
been tested on the SDIO BCM43455; USB runs the same code but is untested
as an access point, and PCIe does not offer it yet.

The net80211 side lives in a small FullMAC layer
(`ieee80211_fullmac.[ch]`) that any driver for firmware-run chips can use:
it carries scans, joins, keys, power save, regulatory changes, signal
reports and access point stations between net80211 and the driver, so the
driver only implements a table of operations.

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

- FreeBSD 15.0 or later with kernel sources in `/usr/src`.  `bwfm_usb` and
  `bwfm_pci` build against the stock sources (tested on 15.0 and 15.1).
  `bwfm_sdio` also needs the kernel's SDIO function layer
  (`sys/dev/mmc/sdio_func.[ch]` and the matching `mmc.c` changes), which
  stock FreeBSD does not have yet; it is on the `rkdev` branch of
  [FBSD_DEV](https://github.com/b1nc0d3x/FBSD_DEV). It now also needs SDIO
  card interrupt support in that layer (`sdio_enable_intr`,
  `sdio_intr_rearm` and the `mmcbr_sdio_intr` bridge method, implemented
  for the Raspberry Pi's `bcm2835_sdhci`), which is not published yet;
  without it the module does not load.
- The net80211 cipher modules. The firmware does the encryption, but
  net80211 still needs `wlan_ccmp` (and `wlan_tkip` for TKIP group keys)
  loaded before keys can be installed, so load them first.
- Firmware. The modules under `sys/modules/*_fw` wrap the firmware images
  this repository ships (BCM43602, BCM43455, BCM43236) together with their
  licences. The BCM4360 module is only a slot: supply that image yourself.
  The BCM43455 image is Cypress 7.45.265 from the Raspberry Pi
  distribution; Broadcom's 7.45.18 from linux-firmware stops transmitting
  unicast data within a minute of association.

## Build

Each module builds on its own. `SRCTOP` points at the top of this
repository:

```
cd sys/modules/bwfm_sdio && make SRCTOP=$(pwd)/../../.. SYSDIR=/usr/src/sys
cd sys/modules/bwfm_usb  && make SRCTOP=$(pwd)/../../.. SYSDIR=/usr/src/sys
cd sys/modules/bwfm_pci  && make SRCTOP=$(pwd)/../../.. SYSDIR=/usr/src/sys
```

Build the matching firmware module the same way, for example
`sys/modules/brcmfmac43455_fw`.

## Install

Copy the modules and refresh the hints:

```
install -m 555 sys/modules/bwfm_sdio/bwfm_sdio.ko \
    sys/modules/brcmfmac43455_fw/brcmfmac43455_fw.ko /boot/modules/
kldxref /boot/modules
```

Install the devd rule, which creates the wlan interfaces once a device is
ready (its firmware can come up after the network has started, and USB
dongles can arrive at any time):

```
install -m 644 etc/devd/bwfm.conf /usr/local/etc/devd/
service devd restart
```

Load the modules from `/etc/rc.conf`, cipher and firmware modules first:

```
kld_list="wlan_ccmp wlan_tkip brcmfmac43455_fw bwfm_sdio"
```

For USB use `brcmfmac43236b_fw bwfm_usb`, and for PCIe
`bwfm_pci_fw_43602 bwfm_pci`. Then name the interface and let rc run
wpa_supplicant and DHCP as usual (the PCIe device is `bwfm_pci0`, so its
line is `wlans_bwfm_pci0`):

```
wlans_bwfm0="wlan0"
ifconfig_wlan0="WPA DHCP"
```

Each module brings its chip up from attach (firmware download, then
net80211), so there are no bring-up scripts.  `hw.bwfm_sdio.autostart=0`
or `hw.bwfm_pci.autostart=0` at the loader prompt turns that off.

The SDIO bus runs 4 bits wide at 50 MHz high speed;
`hw.bwfm_sdio.bus_width` (1 or 4) and `hw.bwfm_sdio.bus_khz` set at the
loader prompt change that.

`bwfm_sdio` cannot be unloaded while net80211 is attached, so replacing
it takes a reboot.  `bwfm_pci` unloads after `ifconfig wlan0 destroy` and
`sysctl dev.bwfm_pci.0.net80211_detach=1`; `bwfm_usb` unloads once its
wlan interface is destroyed.

## Access point

Create a hostap interface and run hostapd on it, for example:

```
ifconfig wlan1 create wlandev bwfm0 wlanmode hostap
ifconfig wlan1 inet 10.0.0.1/24
hostapd -B /etc/hostapd.conf
```

with `driver=bsd`, the SSID and channel, and for WPA2 `wpa=2`,
`wpa_key_mgmt=WPA-PSK` and `rsn_pairwise=CCMP`. Two settings matter:

- Set `wmm_enabled=1`. The firmware writes its own RSN element into the
  beacon, advertising the replay counters WMM implies, and stations check
  hostapd's copy against it during the handshake; without the setting
  every station fails with reason 17. The driver warns at start.
- WPA and 802.1X need the `wlan_xauth` module. net80211 does not load it
  by itself, so load it first.

The firmware sends the beacons and runs authentication and association;
stations appear in `ifconfig wlan1 list sta` as usual.

## Known issues

- With both an SDIO and a USB chip in one machine, list `bwfm_sdio` before
  `bwfm_usb` in `kld_list`.  If the USB device attaches first and the SDIO
  chip becomes `bwfm1`, the SDIO chip associates but receives no data.

## Layout

```
sys/dev/bwfm/
    bwfm.c                  net80211 glue, joins, key install (shared)
    ieee80211_fullmac.c/.h  FullMAC layer over net80211 (shared)
    bwfmreg.h, bwfmvar.h    firmware interface definitions, softc
    bwfm_chip.c/.h          chip backplane walk and core reset
    if_bwfm_pci.c           PCIe attach, firmware download, rings
    bwfm_pci_msgbuf.c/.h    msgbuf protocol (PCIe)
    if_bwfm_sdio.c          SDIO attach and firmware bring-up
    bwfm_sdpcm.c/.h         SDPCM framing (SDIO)
    bwfm_sdio_regs.h        SDIO core registers
    if_bwfm_usb.c           USB attach and firmware download
sys/modules/                one directory per module and firmware image
etc/devd/bwfm.conf          creates wlan interfaces when a device is ready
```

## Credits

The driver was written for FreeBSD, but its firmware interface follows
Linux brcmfmac (Broadcom) and OpenBSD bwfm (Patrick Wildt). It takes its
name from the OpenBSD and NetBSD driver for the same chips. Files that
carry their definitions say so and keep their ISC notices.

## License

BSD-2-Clause, see `LICENSE`, except for the portions noted in individual
files, which are ISC. The firmware images are Broadcom's and come with
their own licences in `sys/modules/*_fw/`.
