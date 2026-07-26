.PATH:	${SRCTOP}/sys/dev/brcm

KMOD=	brcm_pci

.if ${MACHINE_ARCH} == "aarch64"
# Arm64 build: probe-only, no net80211 (wlan.ko symbol resolution issue
# 2026-07-05 on RockPro64 kernel).  Uses stub brcm.c/ieee80211_fullmac.c
# replacements.
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
