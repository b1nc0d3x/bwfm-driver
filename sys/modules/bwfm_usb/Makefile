.PATH: ${SRCTOP}/sys/dev/bwfm

KMOD=	bwfm_usb

# Standalone module.  It links in the shared core (bwfm.c,
# ieee80211_fullmac.c) so that bwfm_attach and ieee80211_fmac_attach
# resolve without a separate bwfm.ko.  The monolithic bwfm module in
# sys/modules/bwfm/ remains for the USB-only build.
SRCS=	if_bwfm_usb.c \
	bwfm.c \
	ieee80211_fullmac.c \
	bus_if.h device_if.h usb_if.h \
	opt_usb.h opt_wlan.h

CFLAGS+=	-I${SRCTOP}/sys/dev/bwfm \
		-I${SRCTOP}/sys

.include <bsd.kmod.mk>
