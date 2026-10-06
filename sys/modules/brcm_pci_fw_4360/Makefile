# Firmware-only kld for the BCM4360 (14e4:43a0, 43a2) PCIe transport.
#
# brcm_pci(4) calls firmware_get("brcmfmac4360_pcie") to fetch the
# ARM-CR4 image during bring-up.  This module wraps whatever blob is
# placed in this directory as brcmfmac4360-pcie.bin.
#
# No firmware is shipped for this chip.  linux-firmware does not
# carry one: Linux drives the BCM4360 with the proprietary
# broadcom-wl driver, and brcmfmac's chip.c has no 4360 entry.
# Current macOS AirPortBrcmNIC.kext does not have one either; Apple
# dropped the BCM4360 after Big Sur, and the macOS 12 kext only
# carries blobs for the 4350, 43602 and 43602a2.
#
# Possible sources:
#
#   1. A macOS 11.x (Big Sur) image still ships
#      /System/Library/Extensions/AirPortBrcm4360.kext with its own
#      firmware.  Take the kext binary and run
#          tools/uefi-re/extract-airport-fw.py <kext-binary> <outdir>
#      The signature scan targets Apple v7.77; other versions may
#      need the signature adjusted in the script.
#
#   2. The broadcom-wl Linux driver is SoftMAC.  Its BCM4360 support
#      is D11 MAC ucode built into the binary, not an ARM-CR4 image,
#      so it gives brcm_pci nothing to load.
#
#   3. b43-fwcutter and similar tools extract D11 ucode for b43 from
#      the Windows Boot Camp driver, which likewise is not an image
#      brcm_pci can upload.  See
#      https://wireless.wiki.kernel.org/en/users/drivers/b43/firmware
#
# With a blob in hand, put it here as brcmfmac4360-pcie.bin and run
# make install.
#
# A missing .bin does not fail the build, so a plain make in
# sys/modules/ still works; the module then fails to register at
# kldload time.

.if !exists(${.CURDIR}/brcmfmac4360-pcie.bin)
.warning "brcmfmac4360-pcie.bin missing — see the sourcing notes at \
the top of ${.CURDIR}/Makefile for how to obtain it.  This module \
will build but fail at kldload."
# Create an empty placeholder so the build succeeds; loading it then
# fails in firmware_register().
.BEGIN: brcmfmac4360-pcie.bin
brcmfmac4360-pcie.bin:
	@echo "> creating empty brcmfmac4360-pcie.bin placeholder" >&2
	@:> ${.CURDIR}/brcmfmac4360-pcie.bin
.endif

KMOD=		brcm_pci_fw_4360
FIRMWS=		brcmfmac4360-pcie.bin:brcmfmac4360_pcie:1

.include <bsd.kmod.mk>
