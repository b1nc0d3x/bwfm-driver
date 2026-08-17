# Kernel module for the brcm SDIO card path. It plugs into the
# `sdio` bus (sys/dev/mmc/sdio_func.c) and looks for Broadcom
# BCM43xxx Wi-Fi chips.
#
# All SDIO headers (mmc_subr.h, sdio_func.h, sdioreg.h) come with
# 15.1. No outside KERN_TREE needed. On older 14.x, you can add
# `-I${KERN_TREE}/sys` on the command line.

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
