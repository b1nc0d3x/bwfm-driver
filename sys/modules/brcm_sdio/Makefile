# Standalone kld for brcm SDIO transport.  Attaches as a child of the
# `sdio` newbus parent (sys/dev/mmc/sdio_func.c) and probes Broadcom
# BCM43xxx WLAN function children.
#
# Headers needed:
#  - brcmvar.h  : in ${SRCTOP}/sys/dev/brcm (this tree)
#  - sdio_func.h, sdioreg.h : in ${KERN_TREE}/sys/dev/mmc (our active
#                  FreeBSD source tree; default /usr/src).
#  Override KERN_TREE on the command line if your fbsd checkout lives
#  elsewhere.

KERN_TREE?=	/usr/src

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
		-I${KERN_TREE}/sys

.include <bsd.kmod.mk>
