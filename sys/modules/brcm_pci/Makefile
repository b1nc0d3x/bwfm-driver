.PATH:	${SRCTOP}/sys/dev/brcm

KMOD=	brcm_pci

.if ${MACHINE_ARCH} == "aarch64"
# Arm64 build: only checks for the chip. No Wi-Fi stack here.
# wlan.ko had a symbol problem on RockPro64 (2026-07-05).
# Uses stub versions of brcm.c and ieee80211_fullmac.c.
SRCS=	if_brcm_pci.c brcm_pci_msgbuf.c brcm_chip.c brcm_stub_arm64.c \
	bus_if.h device_if.h pci_if.h acpi_if.h \
	opt_wlan.h opt_acpi.h
CFLAGS+= -DBRCM_PCI_PROBE_ONLY
.else
SRCS=	if_brcm_pci.c brcm_pci_msgbuf.c \
	brcm.c brcm_chip.c ieee80211_fullmac.c \
	bus_if.h device_if.h pci_if.h acpi_if.h \
	opt_wlan.h opt_acpi.h
.endif

CFLAGS+=	-I${SRCTOP}/sys/dev/brcm

.include <bsd.kmod.mk>
