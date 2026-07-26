.PATH: ${SRCTOP}/sys/dev/brcm

KMOD=	brcm_usb

SRCS=	if_brcm_usb.c \
	bus_if.h device_if.h usb_if.h \
	opt_usb.h

CFLAGS+=	-I${SRCTOP}/sys/dev/brcm

.include <bsd.kmod.mk>
