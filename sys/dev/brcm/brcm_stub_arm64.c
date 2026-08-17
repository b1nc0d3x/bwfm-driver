/*
 * brcm_stub_arm64.c — Tiny fake versions so brcm_pci.ko can build
 * without brcm.c and ieee80211_fullmac.c. Used when wlan.ko has
 * missing symbols (seen on RockPro64 arm64 FreeBSD).
 *
 * With these stubs the driver still attaches at the PCI level and
 * all chip sysctls work. But Wi-Fi (net80211) is off. Setting
 * dev.brcm_pci.0.net80211_attach=1 gives ENOTSUP. Good enough
 * for chip probe, warmup, core walk, and firmware upload tests.
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

int
brcm_attach(struct brcm_softc *sc __unused)
{
	printf("brcm_attach: stub (net80211 disabled in this build)\n");
	return (ENOTSUP);
}

void
brcm_detach(struct brcm_softc *sc __unused)
{
}

void
brcm_handle_event(struct brcm_softc *sc __unused,
    const uint8_t *p __unused, size_t len __unused, size_t evpos __unused)
{
}

void
brcm_rx_frame(struct brcm_softc *sc __unused, struct mbuf *m)
{
	if (m != NULL)
		m_freem(m);
}

void
brcm_rxctl(struct brcm_softc *sc __unused, const void *buf __unused,
    size_t len __unused)
{
}
