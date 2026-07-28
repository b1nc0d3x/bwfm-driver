.PATH: ${SRCTOP}/sys/dev/brcm

KMOD=	brcm_usb

# Standalone module: pull in the shared core (brcm.c, ieee80211_fullmac.c)
# so brcm_usb.ko does not require a separately-loaded brcm.ko to resolve
# brcm_attach / ieee80211_fmac_attach / etc.  The monolithic `brcm`
# module in sys/modules/brcm/ is kept for the legacy USB-only build.
SRCS=	if_brcm_usb.c \
	brcm.c \
	ieee80211_fullmac.c \
	bus_if.h device_if.h usb_if.h \
	opt_usb.h opt_wlan.h

CFLAGS+=	-I${SRCTOP}/sys/dev/brcm \
		-I${SRCTOP}/sys

.include <bsd.kmod.mk>
