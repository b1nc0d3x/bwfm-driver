# Standalone kld for the brcm SDIO transport.  It attaches under the
# sdio newbus parent (sys/dev/mmc/sdio_func.c) and probes Broadcom
# BCM43xxx WLAN functions.
#
# The SDIO headers (mmc_subr.h, sdio_func.h, sdioreg.h) are in base
# from 15.1.  On 14.x, add -I${KERN_TREE}/sys on the command line.

.PATH:	${SRCTOP}/sys/dev/brcm

KMOD=	brcm_sdio
SRCS=	if_brcm_sdio.c \
	brcm_chip.c \
	brcm_sdpcm.c \
	brcm.c \
	ieee80211_fullmac.c \
	bus_if.h device_if.h \
	opt_wlan.h

CFLAGS+=	-I${SRCTOP}/sys/dev/brcm \
		-I${SRCTOP}/sys

.include <bsd.kmod.mk>
