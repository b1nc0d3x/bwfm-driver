# Standalone kld for the bwfm SDIO transport.  It attaches under the
# sdio newbus parent (sys/dev/mmc/sdio_func.c) and probes Broadcom
# BCM43xxx WLAN functions.
#
# Stock FreeBSD has no sdio_func layer.  The kernel needs
# docs/patches/freebsd-15.1/01-mmc-sdio-function-driver.diff, and this
# module must be built against that patched tree.  See COMPATIBILITY.md.

.PATH:	${SRCTOP}/sys/dev/bwfm

KMOD=	bwfm_sdio
SRCS=	if_bwfm_sdio.c \
	bwfm_chip.c \
	bwfm_sdpcm.c \
	bwfm.c \
	bus_if.h device_if.h mmcbr_if.h mmcbus_if.h \
	opt_wlan.h

CFLAGS+=	-I${SRCTOP}/sys/dev/bwfm

.include "../bwfm.fullmac.mk"
.include <bsd.kmod.mk>
.include "../bwfm.harden.mk"
