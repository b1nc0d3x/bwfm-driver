/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Fake versions of some functions.
 *
 * These let bwfm_pci.ko build when the target's wlan.ko lacks
 * some of the symbols we need, as on some arm64 kernels.
 *
 * With the stubs the driver attaches at the PCI level and the
 * chip sysctls work, but net80211 is disabled: setting
 * dev.bwfm_pci.0.net80211_attach=1 returns ENOTSUP. That is
 * still enough for chip probe, warmup, the core walk and
 * firmware upload.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>

struct bwfm_softc;

int bwfm_attach(struct bwfm_softc *sc);
void bwfm_detach(struct bwfm_softc *sc);
void bwfm_handle_event(struct bwfm_softc *sc, const uint8_t *p, size_t len,
    size_t evpos);
void bwfm_rx_frame(struct bwfm_softc *sc, struct mbuf *m);
void bwfm_rxctl(struct bwfm_softc *sc, const void *buf, size_t len);

/* fake attach: reports not supported */
int
bwfm_attach(struct bwfm_softc *sc __unused)
{
	printf("bwfm_attach: stub (net80211 disabled in this build)\n");
	return (ENOTSUP);
}

/* fake detach: does nothing */
void
bwfm_detach(struct bwfm_softc *sc __unused)
{
}

/* fake event handler: does nothing */
void
bwfm_handle_event(struct bwfm_softc *sc __unused,
    const uint8_t *p __unused, size_t len __unused, size_t evpos __unused)
{
}

/* fake rx path: just frees the packet */
void
bwfm_rx_frame(struct bwfm_softc *sc __unused, struct mbuf *m)
{
	if (m != NULL)
		m_freem(m);
}

/* fake control rx: does nothing */
void
bwfm_rxctl(struct bwfm_softc *sc __unused, const void *buf __unused,
    size_t len __unused)
{
}
