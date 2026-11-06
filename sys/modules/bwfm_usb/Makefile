.PATH: ${SRCTOP}/sys/dev/bwfm

KMOD=	bwfm_usb

# Needs no kernel patches.  See COMPATIBILITY.md.

# Standalone module.  It links in the shared core, bwfm.c and the
# FullMAC framework where the kernel lacks it, so that bwfm_attach and
# ieee80211_fmac_attach resolve without a separate bwfm.ko.  The
# monolithic bwfm module in sys/modules/bwfm/ remains for the USB-only
# build.
SRCS=	if_bwfm_usb.c \
	bwfm.c \
	bus_if.h device_if.h usb_if.h \
	opt_usb.h opt_wlan.h

CFLAGS+=	-I${SRCTOP}/sys/dev/bwfm

.include "../bwfm.fullmac.mk"
.include <bsd.kmod.mk>
.include "../bwfm.harden.mk"
