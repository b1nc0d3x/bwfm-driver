.PATH:	${SRCTOP}/sys/dev/bwfm

KMOD=	bwfm_pci

.if ${MACHINE_ARCH} == "aarch64"
# arm64 builds probe-only, without net80211: wlan.ko symbols did
# not resolve there.  bwfm_stub_arm64.c stands in for bwfm.c and
# ieee80211_fullmac.c.
SRCS=	if_bwfm_pci.c bwfm_pci_msgbuf.c bwfm_chip.c bwfm_stub_arm64.c \
	bus_if.h device_if.h pci_if.h acpi_if.h \
	opt_wlan.h opt_acpi.h
CFLAGS+= -DBWFM_PCI_PROBE_ONLY
.else
SRCS=	if_bwfm_pci.c bwfm_pci_msgbuf.c \
	bwfm.c bwfm_chip.c ieee80211_fullmac.c \
	bus_if.h device_if.h pci_if.h acpi_if.h \
	opt_wlan.h opt_acpi.h
.endif

CFLAGS+=	-I${SRCTOP}/sys/dev/bwfm

.include <bsd.kmod.mk>
