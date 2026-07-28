# Standalone kld for brcm SDIO transport.  Attaches as a child of the
# `sdio` newbus parent (sys/dev/mmc/sdio_func.c) and probes Broadcom
# BCM43xxx WLAN function children.
#
# All SDIO headers (mmc_subr.h, sdio_func.h, sdioreg.h) ship in 15.1
# base; no external KERN_TREE required.  If you're building against an
# older 14.x host, `-I${KERN_TREE}/sys` can be re-added on the command
# line for the transitional case.

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
