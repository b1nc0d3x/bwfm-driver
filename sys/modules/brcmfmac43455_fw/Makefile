# Firmware module for BCM43455 / CYW43455 (Pi 4B, Pi 3B+).
#
# Wraps three blobs into one kld so bwfm_sdio can get them through
# firmware(9) without needing the root file system at attach time:
#
#   brcmfmac43455-sdio.bin       Cortex-R4 firmware, 7.45.18 (r538002)
#   brcmfmac43455-sdio.txt       NVRAM (board, antenna, coex)
#   brcmfmac43455-sdio.clm_blob  country-locale module
#
# Sources:
#   .bin       linux-firmware brcm/brcmfmac43455-sdio.bin as shipped in
#              its 2019 and 2020 releases (Broadcom's build, before the
#              Cypress one replaced it).  Licence: LICENCE.broadcom_bcm43xx.
#   .txt       RPi-Distro firmware-nonfree brcm/brcmfmac43455-sdio.txt.
#              Licence: LICENCE.broadcom_bcm43xx.
#   .clm_blob  RPi-Distro firmware-nonfree (bullseye)
#              cypress/cyfmac43455-sdio.clm_blob.  Licence: LICENCE.cypress.

KMOD=	brcmfmac43455_fw

# firmware(9) name : file on disk : version
FIRMWS=	brcmfmac43455-sdio.bin:brcmfmac43455-sdio.bin:1 \
	brcmfmac43455-sdio.txt:brcmfmac43455-sdio.txt:1 \
	brcmfmac43455-sdio.clm_blob:brcmfmac43455-sdio.clm_blob:1

.include <bsd.kmod.mk>
