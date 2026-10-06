/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Fake versions of some functions.
 *
 * These let brcm_pci.ko build when the target's wlan.ko lacks
 * some of the symbols we need, as on some arm64 kernels.
 *
 * With the stubs the driver attaches at the PCI level and the
 * chip sysctls work, but net80211 is disabled: setting
 * dev.brcm_pci.0.net80211_attach=1 returns ENOTSUP. That is
 * still enough for chip probe, warmup, the core walk and
 * firmware upload.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>

struct brcm_softc;

int brcm_attach(struct brcm_softc *sc);
void brcm_detach(struct brcm_softc *sc);
void brcm_handle_event(struct brcm_softc *sc, const uint8_t *p, size_t len,
    size_t evpos);
void brcm_rx_frame(struct brcm_softc *sc, struct mbuf *m);
void brcm_rxctl(struct brcm_softc *sc, const void *buf, size_t len);

/* fake attach: reports not supported */
int
brcm_attach(struct brcm_softc *sc __unused)
{
	printf("brcm_attach: stub (net80211 disabled in this build)\n");
	return (ENOTSUP);
}

/* fake detach: does nothing */
void
brcm_detach(struct brcm_softc *sc __unused)
{
}

/* fake event handler: does nothing */
void
brcm_handle_event(struct brcm_softc *sc __unused,
    const uint8_t *p __unused, size_t len __unused, size_t evpos __unused)
{
}

/* fake rx path: just frees the packet */
void
brcm_rx_frame(struct brcm_softc *sc __unused, struct mbuf *m)
{
	if (m != NULL)
		m_freem(m);
}

/* fake control rx: does nothing */
void
brcm_rxctl(struct brcm_softc *sc __unused, const void *buf __unused,
    size_t len __unused)
{
}
