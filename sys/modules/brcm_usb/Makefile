.PATH: ${SRCTOP}/sys/dev/brcm

KMOD=	brcm_usb

# Standalone module.  It links in the shared core (brcm.c,
# ieee80211_fullmac.c) so that brcm_attach and ieee80211_fmac_attach
# resolve without a separate brcm.ko.  The monolithic brcm module in
# sys/modules/brcm/ remains for the USB-only build.
SRCS=	if_brcm_usb.c \
	brcm.c \
	ieee80211_fullmac.c \
	bus_if.h device_if.h usb_if.h \
	opt_usb.h opt_wlan.h

CFLAGS+=	-I${SRCTOP}/sys/dev/brcm \
		-I${SRCTOP}/sys

.include <bsd.kmod.mk>
