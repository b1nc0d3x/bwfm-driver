# Firmware-only kld for the BCM43602 PCIe transport.
#
# bwfm_pci(4) calls firmware_get("brcmfmac43602_pcie") to fetch the
# ARM-CR4 image during bring-up.  This module wraps the unmodified
# brcmfmac43602-pcie.bin from Broadcom, as distributed in
# linux-firmware, and registers it under that name.
#
# Licence: Broadcom's BCM43xx Software License Agreement
# (LICENCE.broadcom_bcm43xx, included).

KMOD=		bwfm_pci_fw_43602
FIRMWS=		brcmfmac43602-pcie.bin:brcmfmac43602_pcie:1

.include <bsd.kmod.mk>
