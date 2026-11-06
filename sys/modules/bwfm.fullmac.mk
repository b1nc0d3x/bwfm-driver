# The FullMAC framework (ieee80211_fullmac) is part of wlan(4) in
# kernels that carry it.  Against kernel sources without it, build this
# repository's copy into the module instead.

SYSDIR?=	/usr/src/sys

.if !exists(${SYSDIR}/net80211/ieee80211_fullmac.c)
.PATH:	${SRCTOP}/sys/net80211
SRCS+=	ieee80211_fullmac.c
CFLAGS+=	-I${SRCTOP}/sys
.endif
