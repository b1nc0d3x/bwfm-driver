/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom PCIe MSGBUF protocol implementation.  Native FreeBSD.
 *
 * First-light scope (DCMD round-trip only):
 *   - init_share_ram_info (read shared struct in TCM)
 *   - init_ringbuffers (5 common rings via bus_dma coherent alloc)
 *   - init_scratchbuffers (D2H scratch + ringupd)
 *   - post 1 IOCTLRESP_BUF into H2D_CONTROL_SUBMIT
 *   - DCMD tx: IOCTLPTR_REQ into H2D_CONTROL_SUBMIT + doorbell
 *   - ISR: read MAILBOXINT, drain D2H_CONTROL_COMPLETE, wake DCMD waiter
 *
 * Deferred (not in this file yet):
 *   - flowrings (TX path)
 *   - RXPOST_SUBMIT / RX_COMPLETE (data-plane RX)
 *   - Event dispatch (WL_EVENT)
 *   - Console log reader
 *   - DMA index optimization (using TCM indices for first light)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include <net/ethernet.h>

#include "brcm_pci_msgbuf.h"

/* Local shortcuts. */
#define	DEV(mb)		brcm_pci_msgbuf_dev((mb)->sc)
#define	DBG(mb)		brcm_pci_msgbuf_debug((mb)->sc)
#define	BAR0T(mb)	brcm_pci_msgbuf_bar0_tag((mb)->sc)
#define	BAR0H(mb)	brcm_pci_msgbuf_bar0_handle((mb)->sc)
#define	BAR2T(mb)	brcm_pci_msgbuf_bar2_tag((mb)->sc)
#define	BAR2H(mb)	brcm_pci_msgbuf_bar2_handle((mb)->sc)

/*
 * Silent-by-default trace print.  Gated on the shared sc_debug just
 * like DPRINTF() in brcmvar.h.  level==0 fires when sc_debug > 0.
 */
#define	MDPRINTF(mb, level, ...)	do {				\
	if (DBG(mb) > (level))						\
		device_printf(DEV(mb), __VA_ARGS__);			\
} while (0)

#define	MSGBUF_IOCTL_RESP_TIMEOUT_MS	2000

/* -----------------------------------------------------------------
 * TCM (BAR2) helpers — no window movement needed (BAR2 is direct).
 * ----------------------------------------------------------------- */
static inline uint8_t
tcm_read8(struct brcm_pci_msgbuf *mb, uint32_t off)
{
	return (bus_space_read_1(BAR2T(mb), BAR2H(mb), off));
}

static inline uint16_t
tcm_read16(struct brcm_pci_msgbuf *mb, uint32_t off)
{
	return (bus_space_read_2(BAR2T(mb), BAR2H(mb), off));
}

static inline uint32_t
tcm_read32(struct brcm_pci_msgbuf *mb, uint32_t off)
{
	return (bus_space_read_4(BAR2T(mb), BAR2H(mb), off));
}

static inline void
tcm_write16(struct brcm_pci_msgbuf *mb, uint32_t off, uint16_t val)
{
	bus_space_write_2(BAR2T(mb), BAR2H(mb), off, val);
}

static inline void
tcm_write32(struct brcm_pci_msgbuf *mb, uint32_t off, uint32_t val)
{
	bus_space_write_4(BAR2T(mb), BAR2H(mb), off, val);
}

/* -----------------------------------------------------------------
 * PCIe2 register helpers — window must be set to PCIe2 core base
 * first.  Callers hold the softc window lock (implicit today; if_brcm_pci
 * serializes via chip_probe/etc. and msgbuf is single-caller for now).
 * ----------------------------------------------------------------- */
static inline uint32_t
pcie2_read32(struct brcm_pci_msgbuf *mb, uint32_t off)
{
	brcm_pci_msgbuf_set_window(mb->sc, mb->pcie2_base);
	return (bus_space_read_4(BAR0T(mb), BAR0H(mb), off));
}

static inline void
pcie2_write32(struct brcm_pci_msgbuf *mb, uint32_t off, uint32_t val)
{
	brcm_pci_msgbuf_set_window(mb->sc, mb->pcie2_base);
	bus_space_write_4(BAR0T(mb), BAR0H(mb), off, val);
}

/* -----------------------------------------------------------------
 * bus_dma coherent buffer helpers.  Buffer is single-segment,
 * aligned, and both cpu-visible + dma-visible.
 * ----------------------------------------------------------------- */
static void
dma_buf_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	if (error != 0 || nseg != 1) {
		*(bus_addr_t *)arg = 0;
		return;
	}
	*(bus_addr_t *)arg = segs[0].ds_addr;
}

static int
brcm_pci_msgbuf_dma_alloc(struct brcm_pci_msgbuf *mb,
    struct brcm_pci_dma_buf *buf, size_t size, const char *tag)
{
	int error;

	buf->size = size;
	error = bus_dma_tag_create(bus_get_dma_tag(DEV(mb)),
	    /* alignment */ 8, /* boundary */ 0,
	    BUS_SPACE_MAXADDR_32BIT, /* fw is 32-bit-DMA-capable only per
					BCM43602 (host addr split lo/hi;
					hi is 0 unless we allocate above 4G) */
	    BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    size, 1, size,
	    BUS_DMA_ALLOCNOW,
	    NULL, NULL, &buf->tag);
	if (error != 0) {
		device_printf(DEV(mb),
		    "dma_alloc[%s]: tag_create failed %d\n", tag, error);
		return (error);
	}
	error = bus_dmamem_alloc(buf->tag, &buf->vaddr,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT | BUS_DMA_ZERO, &buf->map);
	if (error != 0) {
		device_printf(DEV(mb),
		    "dma_alloc[%s]: mem_alloc failed %d\n", tag, error);
		bus_dma_tag_destroy(buf->tag);
		buf->tag = NULL;
		return (error);
	}
	buf->paddr = 0;
	error = bus_dmamap_load(buf->tag, buf->map, buf->vaddr, size,
	    dma_buf_cb, &buf->paddr, BUS_DMA_NOWAIT);
	if (error != 0 || buf->paddr == 0) {
		device_printf(DEV(mb),
		    "dma_alloc[%s]: dmamap_load failed %d\n", tag, error);
		bus_dmamem_free(buf->tag, buf->vaddr, buf->map);
		bus_dma_tag_destroy(buf->tag);
		buf->tag = NULL;
		buf->vaddr = NULL;
		return (error != 0 ? error : ENOMEM);
	}
	return (0);
}

static void
brcm_pci_msgbuf_dma_free(struct brcm_pci_msgbuf *mb __unused,
    struct brcm_pci_dma_buf *buf)
{
	if (buf->tag == NULL)
		return;
	if (buf->paddr != 0) {
		bus_dmamap_unload(buf->tag, buf->map);
		buf->paddr = 0;
	}
	if (buf->vaddr != NULL) {
		bus_dmamem_free(buf->tag, buf->vaddr, buf->map);
		buf->vaddr = NULL;
	}
	bus_dma_tag_destroy(buf->tag);
	buf->tag = NULL;
}

/* -----------------------------------------------------------------
 * Common ring mechanics.  Uses per-ring spin mutex (mtx MTX_DEF for
 * simplicity; can move to MTX_SPIN once we settle interrupt context).
 * ----------------------------------------------------------------- */
static void
ring_config(struct brcm_pci_ring *ring, uint16_t depth, uint16_t item_len,
    struct brcm_pci_msgbuf *mb)
{
	if (!ring->inited) {
		mtx_init(&ring->lock, "brcm_pci_ring", NULL, MTX_DEF);
		ring->inited = true;
	}
	ring->depth = depth;
	ring->item_len = item_len;
	ring->mb = mb;
	ring->r_ptr = 0;
	ring->w_ptr = 0;
	ring->f_ptr = 0;
	ring->was_full = false;
}

/*
 * Push the last-written w_ptr (f_ptr) to fw via TCM index.
 * TCM index is a 16-bit value at ring->w_idx_addr.
 */
static void
ring_publish_wptr(struct brcm_pci_ring *ring)
{
	tcm_write16(ring->mb, ring->w_idx_addr, ring->w_ptr);
}

/* Publish our r_ptr (consumer) to fw via TCM index. */
static void
ring_publish_rptr(struct brcm_pci_ring *ring)
{
	tcm_write16(ring->mb, ring->r_idx_addr, ring->r_ptr);
}

/* Pull fw's current w_ptr for a D2H ring (fw is producer). */
static void
ring_pull_wptr_from_fw(struct brcm_pci_ring *ring)
{
	ring->w_ptr = tcm_read16(ring->mb, ring->w_idx_addr);
}

/* Pull fw's current r_ptr for an H2D ring (fw is consumer). */
static void
ring_pull_rptr_from_fw(struct brcm_pci_ring *ring)
{
	ring->r_ptr = tcm_read16(ring->mb, ring->r_idx_addr);
}

/* Ring the doorbell — H2D_MAILBOX_0 write kicks fw. */
static void
ring_bell(struct brcm_pci_ring *ring)
{
	pcie2_write32(ring->mb, BRCM_PCIE2REG_H2D_MAILBOX_0, 1);
}

static void *
ring_reserve_for_write(struct brcm_pci_ring *ring)
{
	uint16_t avail;
	void *ret;
	bool retried = false;

again:
	if (ring->r_ptr <= ring->w_ptr)
		avail = ring->depth - ring->w_ptr + ring->r_ptr;
	else
		avail = ring->r_ptr - ring->w_ptr;

	if (avail > 1) {
		ret = (uint8_t *)ring->buf.vaddr + ring->w_ptr * ring->item_len;
		ring->w_ptr++;
		if (ring->w_ptr == ring->depth)
			ring->w_ptr = 0;
		return (ret);
	}

	if (!retried) {
		ring_pull_rptr_from_fw(ring);
		retried = true;
		goto again;
	}
	ring->was_full = true;
	return (NULL);
}

static int
ring_write_complete(struct brcm_pci_ring *ring)
{
	if (ring->f_ptr > ring->w_ptr)
		ring->f_ptr = 0;
	ring->f_ptr = ring->w_ptr;
	ring_publish_wptr(ring);
	ring_bell(ring);
	return (0);
}

static void *
ring_get_read_ptr(struct brcm_pci_ring *ring, uint16_t *n_items)
{
	ring_pull_wptr_from_fw(ring);
	if (ring->w_ptr >= ring->r_ptr)
		*n_items = ring->w_ptr - ring->r_ptr;
	else
		*n_items = ring->depth - ring->r_ptr;
	if (*n_items == 0)
		return (NULL);
	return ((uint8_t *)ring->buf.vaddr + ring->r_ptr * ring->item_len);
}

static void
ring_read_complete(struct brcm_pci_ring *ring, uint16_t n_items)
{
	ring->r_ptr += n_items;
	if (ring->r_ptr == ring->depth)
		ring->r_ptr = 0;
	ring_publish_rptr(ring);
}

/* -----------------------------------------------------------------
 * Shared-info reader.
 *
 * Fw writes sharedram_addr at BAR2[rambase + ramsize - 4] after boot.
 * On BCM43602 v7.35.177.61, the address is a raw TCM offset,
 * expected to fall inside [rambase, rambase + ramsize).  We
 * tolerate values outside that range and log — helpful for
 * observing chip state on partially initialised fw.
 * ----------------------------------------------------------------- */
static int
msgbuf_read_shared_info(struct brcm_pci_msgbuf *mb)
{
	uint32_t rambase, ramsize, off, shared_addr, flags;

	rambase = brcm_pci_msgbuf_rambase(mb->sc);
	ramsize = brcm_pci_msgbuf_ramsize(mb->sc);
	off = rambase + ramsize - 4;

	shared_addr = tcm_read32(mb, off);
	MDPRINTF(mb, 0,
	    "msgbuf: sharedram_addr[BAR2+0x%x] = 0x%08x\n", off, shared_addr);

	if (shared_addr == 0) {
		device_printf(DEV(mb),
		    "msgbuf: fw hasn't written sharedram_addr yet\n");
		return (EAGAIN);
	}
	if (shared_addr < rambase ||
	    shared_addr >= (rambase + ramsize)) {
		uint32_t candidate = shared_addr & 0x00ffffff;

		device_printf(DEV(mb),
		    "msgbuf: sharedram_addr 0x%x outside [0x%x, 0x%x)\n",
		    shared_addr, rambase, rambase + ramsize);
		/*
		 * Some fw revisions (v7.35.177.61 on BCM43602) tag the
		 * sharedram pointer with high bits (0xc0 seen).  Try
		 * low-24-bit masking; validate by checking the version
		 * field falls in the supported range 5..7.
		 */
		if (candidate >= rambase && candidate < rambase + ramsize) {
			uint32_t f = tcm_read32(mb,
			    candidate + BRCM_SHARED_FLAGS_OFFSET);
			uint8_t v = f & BRCM_PCIE_SHARED_VERSION_MASK;

			MDPRINTF(mb, 0,
			    "msgbuf: try masked 0x%x — flags=0x%08x v=%u\n",
			    candidate, f, v);
			if (v >= BRCM_PCIE_MIN_SHARED_VERSION &&
			    v <= BRCM_PCIE_MAX_SHARED_VERSION) {
				MDPRINTF(mb, 0,
				    "msgbuf: masked address validates — "
				    "using 0x%x\n", candidate);
				shared_addr = candidate;
				goto validated;
			}
		}
		return (EINVAL);
	}
validated:

	mb->shared_addr = shared_addr;
	flags = tcm_read32(mb, shared_addr + BRCM_SHARED_FLAGS_OFFSET);
	mb->shared_flags = flags;
	mb->shared_version = flags & BRCM_PCIE_SHARED_VERSION_MASK;
	MDPRINTF(mb, 0,
	    "msgbuf: shared v=%u flags=0x%08x dma_idx=%d hostrdy_db1=%d\n",
	    mb->shared_version, flags,
	    !!(flags & BRCM_PCIE_SHARED_DMA_INDEX),
	    !!(flags & BRCM_PCIE_SHARED_HOSTRDY_DB1));

	if (mb->shared_version < BRCM_PCIE_MIN_SHARED_VERSION ||
	    mb->shared_version > BRCM_PCIE_MAX_SHARED_VERSION) {
		device_printf(DEV(mb),
		    "msgbuf: unsupported shared version %u\n",
		    mb->shared_version);
		return (EPROTONOSUPPORT);
	}

	mb->max_rxbufpost = tcm_read16(mb,
	    shared_addr + BRCM_SHARED_MAX_RXBUFPOST_OFFSET);
	mb->rx_dataoffset = tcm_read32(mb,
	    shared_addr + BRCM_SHARED_RX_DATAOFFSET_OFFSET);
	mb->htod_mb_data_addr = tcm_read32(mb,
	    shared_addr + BRCM_SHARED_HTOD_MB_DATA_ADDR_OFFSET);
	mb->dtoh_mb_data_addr = tcm_read32(mb,
	    shared_addr + BRCM_SHARED_DTOH_MB_DATA_ADDR_OFFSET);
	mb->ring_info_addr = tcm_read32(mb,
	    shared_addr + BRCM_SHARED_RING_INFO_ADDR_OFFSET);
	mb->console_addr = tcm_read32(mb,
	    shared_addr + BRCM_SHARED_CONSOLE_ADDR_OFFSET);

	MDPRINTF(mb, 0,
	    "msgbuf: max_rxbufpost=%u rx_dataoff=0x%x ringinfo=0x%x console=0x%x\n",
	    mb->max_rxbufpost, mb->rx_dataoffset, mb->ring_info_addr,
	    mb->console_addr);
	MDPRINTF(mb, 0,
	    "msgbuf: htod_mb_data=0x%x dtoh_mb_data=0x%x\n",
	    mb->htod_mb_data_addr, mb->dtoh_mb_data_addr);
	return (0);
}

/* -----------------------------------------------------------------
 * Ring buffer + index initialisation.
 *
 * For first light: TCM indices only (no DMA-idx optimisation).
 * Allocates 5 coherent ring buffers, publishes their DMA addresses
 * into the fw ringmem slots.
 * ----------------------------------------------------------------- */
static const uint32_t brcm_ring_max_item[BRCM_NROF_COMMON_MSGRINGS] = {
	BRCM_H2D_CONTROL_SUBMIT_MAX_ITEM,
	BRCM_H2D_RXPOST_SUBMIT_MAX_ITEM,
	BRCM_D2H_CONTROL_COMPLETE_MAX_ITEM,
	BRCM_D2H_TX_COMPLETE_MAX_ITEM,
	BRCM_D2H_RX_COMPLETE_MAX_ITEM,
};
static const uint32_t brcm_ring_itemsize_pre_v7[BRCM_NROF_COMMON_MSGRINGS] = {
	BRCM_H2D_CONTROL_SUBMIT_ITEMSIZE,
	BRCM_H2D_RXPOST_SUBMIT_ITEMSIZE,
	BRCM_D2H_CONTROL_COMPLETE_ITEMSIZE,
	BRCM_D2H_TX_COMPLETE_ITEMSIZE_PRE_V7,
	BRCM_D2H_RX_COMPLETE_ITEMSIZE_PRE_V7,
};
static const uint32_t brcm_ring_itemsize_v7[BRCM_NROF_COMMON_MSGRINGS] = {
	BRCM_H2D_CONTROL_SUBMIT_ITEMSIZE,
	BRCM_H2D_RXPOST_SUBMIT_ITEMSIZE,
	BRCM_D2H_CONTROL_COMPLETE_ITEMSIZE,
	BRCM_D2H_TX_COMPLETE_ITEMSIZE,
	BRCM_D2H_RX_COMPLETE_ITEMSIZE,
};

static int
msgbuf_init_rings(struct brcm_pci_msgbuf *mb)
{
	const uint32_t *itemsize;
	uint32_t ring_mem_ptr;
	uint32_t d2h_w, d2h_r, h2d_w, h2d_r;
	uint16_t max_flow, max_sub, max_cmp;
	uint32_t rinfo;
	int i, error;

	rinfo = mb->ring_info_addr;

	if (mb->shared_version >= 6) {
		max_sub = tcm_read16(mb, rinfo +
		    BRCM_RINGINFO_MAX_SUBMISSIONRINGS_OFFSET);
		max_flow = tcm_read16(mb, rinfo +
		    BRCM_RINGINFO_MAX_FLOWRINGS_OFFSET);
		max_cmp = tcm_read16(mb, rinfo +
		    BRCM_RINGINFO_MAX_COMPLETIONRINGS_OFFSET);
	} else {
		max_sub = tcm_read16(mb, rinfo +
		    BRCM_RINGINFO_MAX_FLOWRINGS_OFFSET);
		max_flow = max_sub - 2;	/* 2 H2D common rings */
		max_cmp = 3;		/* 3 D2H common rings */
	}
	if (max_flow > 512) {
		device_printf(DEV(mb),
		    "msgbuf: bogus max_flowrings=%u\n", max_flow);
		return (EIO);
	}

	mb->max_flowrings = max_flow;
	mb->max_submissionrings = max_sub;
	mb->max_completionrings = max_cmp;

	/* TCM-index mode: read ptrs, use 4-byte stride. */
	d2h_w = tcm_read32(mb, rinfo + BRCM_RINGINFO_D2H_W_IDX_PTR_OFFSET);
	d2h_r = tcm_read32(mb, rinfo + BRCM_RINGINFO_D2H_R_IDX_PTR_OFFSET);
	h2d_w = tcm_read32(mb, rinfo + BRCM_RINGINFO_H2D_W_IDX_PTR_OFFSET);
	h2d_r = tcm_read32(mb, rinfo + BRCM_RINGINFO_H2D_R_IDX_PTR_OFFSET);
	ring_mem_ptr = tcm_read32(mb, rinfo + BRCM_RINGINFO_RINGMEM_OFFSET);

	MDPRINTF(mb, 0,
	    "msgbuf: max_sub=%u max_flow=%u max_cmp=%u ringmem=0x%x\n",
	    max_sub, max_flow, max_cmp, ring_mem_ptr);
	MDPRINTF(mb, 0,
	    "msgbuf: h2d_w=0x%x h2d_r=0x%x d2h_w=0x%x d2h_r=0x%x\n",
	    h2d_w, h2d_r, d2h_w, d2h_r);

	itemsize = (mb->shared_version >= 7) ? brcm_ring_itemsize_v7 :
	    brcm_ring_itemsize_pre_v7;

	mb->ringmem_base = ring_mem_ptr;

	/* Two H2D rings first, then three D2H rings. */
	for (i = 0; i < BRCM_NROF_COMMON_MSGRINGS; i++) {
		struct brcm_pci_ring *ring = &mb->rings[i];
		size_t sz = brcm_ring_max_item[i] * itemsize[i];
		bus_addr_t pa;

		error = brcm_pci_msgbuf_dma_alloc(mb, &ring->buf, sz, "ring");
		if (error != 0)
			return (error);
		pa = ring->buf.paddr;

		/* Write ring DMA addr + item count + item size into fw's
		 * ringmem slot for this ring. */
		tcm_write32(mb, ring_mem_ptr + BRCM_RING_MEM_BASE_ADDR_OFFSET,
		    (uint32_t)(pa & 0xffffffff));
		tcm_write32(mb,
		    ring_mem_ptr + BRCM_RING_MEM_BASE_ADDR_OFFSET + 4,
		    (uint32_t)((uint64_t)pa >> 32));
		tcm_write16(mb, ring_mem_ptr + BRCM_RING_MAX_ITEM_OFFSET,
		    brcm_ring_max_item[i]);
		tcm_write16(mb, ring_mem_ptr + BRCM_RING_LEN_ITEMS_OFFSET,
		    itemsize[i]);

		ring_config(ring, brcm_ring_max_item[i], itemsize[i], mb);
		ring->id = i;
		if (i < 2) {
			ring->w_idx_addr = h2d_w;
			ring->r_idx_addr = h2d_r;
			h2d_w += sizeof(uint32_t);
			h2d_r += sizeof(uint32_t);
		} else {
			ring->w_idx_addr = d2h_w;
			ring->r_idx_addr = d2h_r;
			d2h_w += sizeof(uint32_t);
			d2h_r += sizeof(uint32_t);
		}
		ring_mem_ptr += BRCM_RING_MEM_SZ;

		/* Zero out the indices in TCM (fw already zeros on boot,
		 * but be safe). */
		tcm_write16(mb, ring->w_idx_addr, 0);
		tcm_write16(mb, ring->r_idx_addr, 0);

		MDPRINTF(mb, 0,
		    "msgbuf: ring[%d] items=%u itemsize=%u pa=0x%jx "
		    "w_idx=0x%x r_idx=0x%x\n", i,
		    brcm_ring_max_item[i], itemsize[i], (uintmax_t)pa,
		    ring->w_idx_addr, ring->r_idx_addr);
	}

	/*
	 * Cursors: h2d_w/h2d_r now point to the FIRST H2D slot after
	 * the 2 common H2D rings, i.e. the flowring[0] slot.  Same for
	 * ring_mem_ptr (5 slots consumed).
	 */
	mb->flow_h2d_w_next = h2d_w;
	mb->flow_h2d_r_next = h2d_r;
	mb->flow_ringmem_next = ring_mem_ptr;

	return (0);
}

/* -----------------------------------------------------------------
 * Scratch + ringupd — small coherent buffers fw uses for D2H
 * scratch space and ring update deltas.  Not strictly required for
 * a synchronous DCMD, but fw firmware asserts on missing scratch on
 * some versions.  Cheap; allocate.
 * ----------------------------------------------------------------- */
#define	BRCM_D2H_SCRATCH_BUF_LEN	8
#define	BRCM_D2H_RINGUPD_BUF_LEN	1024

static int
msgbuf_init_scratch(struct brcm_pci_msgbuf *mb)
{
	uint32_t base, addr;
	int error;

	base = mb->shared_addr;

	error = brcm_pci_msgbuf_dma_alloc(mb, &mb->scratch,
	    BRCM_D2H_SCRATCH_BUF_LEN, "scratch");
	if (error != 0)
		return (error);
	addr = base + BRCM_SHARED_DMA_SCRATCH_ADDR_OFFSET;
	tcm_write32(mb, addr,
	    (uint32_t)(mb->scratch.paddr & 0xffffffff));
	tcm_write32(mb, addr + 4,
	    (uint32_t)((uint64_t)mb->scratch.paddr >> 32));
	tcm_write32(mb, base + BRCM_SHARED_DMA_SCRATCH_LEN_OFFSET,
	    BRCM_D2H_SCRATCH_BUF_LEN);

	error = brcm_pci_msgbuf_dma_alloc(mb, &mb->ringupd,
	    BRCM_D2H_RINGUPD_BUF_LEN, "ringupd");
	if (error != 0)
		return (error);
	addr = base + BRCM_SHARED_DMA_RINGUPD_ADDR_OFFSET;
	tcm_write32(mb, addr,
	    (uint32_t)(mb->ringupd.paddr & 0xffffffff));
	tcm_write32(mb, addr + 4,
	    (uint32_t)((uint64_t)mb->ringupd.paddr >> 32));
	tcm_write32(mb, base + BRCM_SHARED_DMA_RINGUPD_LEN_OFFSET,
	    BRCM_D2H_RINGUPD_BUF_LEN);

	MDPRINTF(mb, 0,
	    "msgbuf: scratch pa=0x%jx ringupd pa=0x%jx (published)\n",
	    (uintmax_t)mb->scratch.paddr, (uintmax_t)mb->ringupd.paddr);
	return (0);
}

/* -----------------------------------------------------------------
 * Post one IOCTLRESP_BUF into the H2D control ring so fw has
 * somewhere to write the DCMD reply.  Uses mb->ioctbuf as the
 * response staging buffer for first light (single outstanding
 * DCMD, we reuse the same 8KB coherent slot).
 * ----------------------------------------------------------------- */
static int
msgbuf_post_ioctlresp(struct brcm_pci_msgbuf *mb)
{
	struct brcm_pci_ring *ring;
	struct msgbuf_rx_ioctl_resp_or_event *post;
	uint64_t paddr;

	ring = &mb->rings[BRCM_H2D_MSGRING_CONTROL_SUBMIT];
	mtx_lock(&ring->lock);
	post = ring_reserve_for_write(ring);
	if (post == NULL) {
		static struct timeval _last;
		static int _cnt;
		mtx_unlock(&ring->lock);
		if (ppsratecheck(&_last, &_cnt, 1))
			device_printf(DEV(mb),
			    "msgbuf: post_ioctlresp: ring full\n");
		return (ENOSPC);
	}

	memset(post, 0, sizeof(*post));
	post->msg.msgtype = BRCM_MSGBUF_TYPE_IOCTLRESP_BUF_POST;
	post->msg.ifidx = 0;
	post->msg.flags = 0;
	post->msg.request_id = htole32(BRCM_IOCTL_REQ_PKTID);
	post->host_buf_len = htole16(BRCM_MSGBUF_MAX_CTL_PKT_SIZE);
	paddr = (uint64_t)mb->ioctbuf.paddr;
	post->host_buf_addr.low_addr = htole32((uint32_t)(paddr & 0xffffffff));
	post->host_buf_addr.high_addr = htole32((uint32_t)(paddr >> 32));

	ring_write_complete(ring);
	mtx_unlock(&ring->lock);
	return (0);
}

/* -----------------------------------------------------------------
 * pktid table: track outstanding TX mbufs so we can free them when
 * fw acks via TX_STATUS.  Simple linear scan starting from a hint;
 * O(N) worst case but N=1024 and TX rate is bounded by fw.
 * Slot 0 is reserved (request_id 0 == "no id").
 * ----------------------------------------------------------------- */
static int
pktid_alloc(struct brcm_pci_msgbuf *mb, struct mbuf *m, uint16_t flowid,
    uint32_t *idx_out)
{
	uint32_t i, start;

	mtx_lock(&mb->pktid_mtx);
	start = mb->pktid_next_hint;
	if (start == 0)
		start = 1;
	for (i = 0; i < BRCM_MSGBUF_MAX_PKTID; i++) {
		uint32_t j = start + i;
		if (j >= BRCM_MSGBUF_MAX_PKTID)
			j -= (BRCM_MSGBUF_MAX_PKTID - 1);
		if (j == 0)
			j = 1;
		if (!mb->pktids[j].inuse) {
			mb->pktids[j].inuse = true;
			mb->pktids[j].m = m;
			mb->pktids[j].flowid = flowid;
			mb->pktid_next_hint = j + 1;
			if (mb->pktid_next_hint >= BRCM_MSGBUF_MAX_PKTID)
				mb->pktid_next_hint = 1;
			mtx_unlock(&mb->pktid_mtx);
			*idx_out = j;
			return (0);
		}
	}
	mtx_unlock(&mb->pktid_mtx);
	return (ENOSPC);
}

static struct mbuf *
pktid_release(struct brcm_pci_msgbuf *mb, uint32_t idx,
    bus_dmamap_t *map_out)
{
	struct mbuf *m;

	if (idx == 0 || idx >= BRCM_MSGBUF_MAX_PKTID)
		return (NULL);
	mtx_lock(&mb->pktid_mtx);
	if (!mb->pktids[idx].inuse) {
		mtx_unlock(&mb->pktid_mtx);
		return (NULL);
	}
	m = mb->pktids[idx].m;
	if (map_out != NULL)
		*map_out = mb->pktids[idx].map;
	mb->pktids[idx].m = NULL;
	mb->pktids[idx].map = NULL;
	mb->pktids[idx].pa = 0;
	mb->pktids[idx].datalen = 0;
	mb->pktids[idx].flowid = 0;
	mb->pktids[idx].inuse = false;
	mtx_unlock(&mb->pktid_mtx);
	return (m);
}

/* -----------------------------------------------------------------
 * RXPOST table: analogous to pktid table but for host mbufs POSTED
 * to fw as RX/event/ioctl-response landing zones.  Fw echoes the
 * pktid back in the RX_CMPLT / WL_EVENT descriptor so we can find
 * the buffer.
 * ----------------------------------------------------------------- */
static int
rxpost_alloc(struct brcm_pci_msgbuf *mb, struct mbuf *m, uint8_t type,
    uint32_t *idx_out)
{
	uint32_t i, start;

	mtx_lock(&mb->rxpost_mtx);
	start = mb->rxpost_next_hint;
	if (start == 0)
		start = 1;
	for (i = 0; i < BRCM_MSGBUF_MAX_RXPOST; i++) {
		uint32_t j = start + i;
		if (j >= BRCM_MSGBUF_MAX_RXPOST)
			j -= (BRCM_MSGBUF_MAX_RXPOST - 1);
		if (j == 0)
			j = 1;
		if (mb->rxposts[j].type == BRCM_RXPOST_UNUSED) {
			mb->rxposts[j].type = type;
			mb->rxposts[j].m = m;
			mb->rxpost_next_hint = j + 1;
			if (mb->rxpost_next_hint >= BRCM_MSGBUF_MAX_RXPOST)
				mb->rxpost_next_hint = 1;
			mtx_unlock(&mb->rxpost_mtx);
			*idx_out = j;
			return (0);
		}
	}
	mtx_unlock(&mb->rxpost_mtx);
	return (ENOSPC);
}

static struct mbuf *
rxpost_release(struct brcm_pci_msgbuf *mb, uint32_t idx,
    bus_dmamap_t *map_out, uint8_t *type_out)
{
	struct mbuf *m;

	if (idx == 0 || idx >= BRCM_MSGBUF_MAX_RXPOST)
		return (NULL);
	mtx_lock(&mb->rxpost_mtx);
	if (mb->rxposts[idx].type == BRCM_RXPOST_UNUSED) {
		mtx_unlock(&mb->rxpost_mtx);
		return (NULL);
	}
	m = mb->rxposts[idx].m;
	if (map_out != NULL)
		*map_out = mb->rxposts[idx].map;
	if (type_out != NULL)
		*type_out = mb->rxposts[idx].type;
	mb->rxposts[idx].m = NULL;
	mb->rxposts[idx].map = NULL;
	mb->rxposts[idx].pa = 0;
	mb->rxposts[idx].buflen = 0;
	mb->rxposts[idx].type = BRCM_RXPOST_UNUSED;
	mtx_unlock(&mb->rxpost_mtx);
	return (m);
}

static void
rxbuf_load_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	uint64_t *pa = arg;

	if (error != 0 || nseg < 1) {
		*pa = 0;
		return;
	}
	*pa = (uint64_t)segs[0].ds_addr;
}

/*
 * Post ONE host mbuf as a receive landing zone.  Depending on `type`:
 *  BRCM_RXPOST_EVENT → msgtype EVENT_BUF_POST on H2D_CTRL_SUBMIT
 *  BRCM_RXPOST_DATA  → msgtype RXBUF_POST on H2D_RXPOST_SUBMIT
 * Returns 0 on success.  Caller responsible for doorbell burst if
 * posting many (we doorbell per-post here — simple, low-perf).
 */
/*
 * Event-buf pktid: fw returns this in WL_EVENT.request_id so we can
 * find the source buffer.  Event bufs use a dedicated pktid range
 * that never overlaps with data rxpost pktids (data starts from 1
 * via rxpost_alloc's hint).  We encode the eventbuf slot index as
 * a high-bit tag so lookup is O(1).
 */
#define	BRCM_EVENTBUF_PKTID_BASE	0xE0000000u
#define	BRCM_EVENTBUF_PKTID(slot)	(BRCM_EVENTBUF_PKTID_BASE | (slot))
#define	BRCM_EVENTBUF_IS_EVENT(pktid)	\
	(((pktid) & 0xFFFFFF00u) == BRCM_EVENTBUF_PKTID_BASE)
#define	BRCM_EVENTBUF_PKTID_SLOT(pktid)	((pktid) & 0xFFu)

/*
 * Post ONE pre-allocated coherent event buffer to the H2D CTRL SUBMIT
 * ring.  Called at attach and after each WL_EVENT processing to refill
 * the slot.  Uses mb->eventbufs[slot] — no mbuf, no rxpost table.
 * Physaddr is guaranteed sub-4GB by the dma tag's lowaddr constraint.
 */
static int
msgbuf_post_event_slot(struct brcm_pci_msgbuf *mb, uint32_t slot)
{
	struct brcm_pci_ring *ring;
	struct brcm_pci_dma_buf *evb;
	struct msgbuf_rx_ioctl_resp_or_event *post;

	if (slot >= mb->max_eventbuf)
		return (EINVAL);
	evb = &mb->eventbufs[slot];
	if (evb->vaddr == NULL || evb->paddr == 0)
		return (ENOMEM);

	ring = &mb->rings[BRCM_H2D_MSGRING_CONTROL_SUBMIT];

	/* Zero the buffer so fw sees clean state; sync PREREAD after. */
	memset(evb->vaddr, 0, evb->size);
	bus_dmamap_sync(evb->tag, evb->map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	mtx_lock(&ring->lock);
	post = ring_reserve_for_write(ring);
	if (post == NULL) {
		mtx_unlock(&ring->lock);
		return (ENOSPC);
	}
	memset(post, 0, sizeof(*post));
	post->msg.msgtype = BRCM_MSGBUF_TYPE_EVENT_BUF_POST;
	post->msg.ifidx = 0;
	post->msg.request_id = htole32(BRCM_EVENTBUF_PKTID(slot));
	post->host_buf_len = htole16((uint16_t)evb->size);
	post->host_buf_addr.low_addr = htole32((uint32_t)(evb->paddr & 0xffffffff));
	post->host_buf_addr.high_addr = htole32((uint32_t)((uint64_t)evb->paddr >> 32));
	ring_write_complete(ring);
	mtx_unlock(&ring->lock);
	return (0);
}

static int
msgbuf_post_one_rxbuf(struct brcm_pci_msgbuf *mb, uint8_t type)
{
	struct mbuf *m;
	struct brcm_pci_ring *ring;
	bus_dmamap_t map = NULL;
	uint64_t pa;
	uint32_t pktid;
	size_t bufsize;
	uint8_t msgtype;
	int error;

	if (type == BRCM_RXPOST_EVENT) {
		/*
		 * Events use the coherent pool via msgbuf_post_event_slot.
		 * Reject the mbuf path so no one silently posts an mbuf
		 * with an above-4GB physaddr and gives fw a bad pointer.
		 */
		return (EINVAL);
	} else if (type == BRCM_RXPOST_DATA) {
		bufsize = BRCM_MSGBUF_MAX_PKT_SIZE;
		msgtype = BRCM_MSGBUF_TYPE_RXBUF_POST;
		ring = &mb->rings[BRCM_H2D_MSGRING_RXPOST_SUBMIT];
	} else {
		return (EINVAL);
	}

	/*
	 * m_getjcl's `size` arg must be one of the exact cluster sizes:
	 * MCLBYTES (2K), MJUMPAGESIZE (PAGE_SIZE, 4K on amd64), MJUM9BYTES
	 * (9K), or MJUM16BYTES (16K).  Round bufsize up to the smallest
	 * cluster that fits; otherwise the returned mbuf is short and the
	 * subsequent bus_dmamap_load walks past the allocation.  This was
	 * the "posted 0/8 event buffers" symptom — event bufs are 8K, we
	 * asked for a 4K cluster to hold them.
	 */
	{
		int cluster_size;
		if (bufsize <= MCLBYTES)
			cluster_size = MCLBYTES;
		else if (bufsize <= MJUMPAGESIZE)
			cluster_size = MJUMPAGESIZE;
		else if (bufsize <= MJUM9BYTES)
			cluster_size = MJUM9BYTES;
		else
			cluster_size = MJUM16BYTES;
		m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, cluster_size);
	}
	if (m == NULL) {
		device_printf(DEV(mb),
		    "msgbuf: post_one_rxbuf(type=%u): m_getjcl(%zu) failed\n",
		    type, bufsize);
		return (ENOMEM);
	}
	m->m_len = m->m_pkthdr.len = bufsize;

	error = bus_dmamap_create(mb->rx_mbuf_tag, 0, &map);
	if (error != 0) {
		device_printf(DEV(mb),
		    "msgbuf: post_one_rxbuf(type=%u): dmamap_create failed %d\n",
		    type, error);
		m_freem(m);
		return (error);
	}
	pa = 0;
	error = bus_dmamap_load(mb->rx_mbuf_tag, map, mtod(m, void *), bufsize,
	    rxbuf_load_cb, &pa, BUS_DMA_NOWAIT);
	if (error != 0 || pa == 0) {
		device_printf(DEV(mb),
		    "msgbuf: post_one_rxbuf(type=%u): dmamap_load err=%d pa=0x%llx bufsize=%zu\n",
		    type, error, (unsigned long long)pa, bufsize);
		bus_dmamap_destroy(mb->rx_mbuf_tag, map);
		m_freem(m);
		return (error != 0 ? error : EIO);
	}

	error = rxpost_alloc(mb, m, type, &pktid);
	if (error != 0) {
		device_printf(DEV(mb),
		    "msgbuf: post_one_rxbuf(type=%u): rxpost_alloc failed %d\n",
		    type, error);
		bus_dmamap_unload(mb->rx_mbuf_tag, map);
		bus_dmamap_destroy(mb->rx_mbuf_tag, map);
		m_freem(m);
		return (error);
	}
	mb->rxposts[pktid].map = map;
	mb->rxposts[pktid].pa = pa;
	mb->rxposts[pktid].buflen = (uint16_t)bufsize;

	/* Sync so fw reads whatever host wrote (mostly zeros — fine). */
	bus_dmamap_sync(mb->rx_mbuf_tag, map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	mtx_lock(&ring->lock);
	if (type == BRCM_RXPOST_DATA) {
		struct msgbuf_rx_bufpost *post;

		post = ring_reserve_for_write(ring);
		if (post == NULL)
			goto ring_full;
		memset(post, 0, sizeof(*post));
		post->msg.msgtype = msgtype;
		post->msg.ifidx = 0;
		post->msg.request_id = htole32(pktid);
		post->data_buf_len = htole16((uint16_t)bufsize);
		post->data_buf_addr.low_addr =
		    htole32((uint32_t)(pa & 0xffffffff));
		post->data_buf_addr.high_addr = htole32((uint32_t)(pa >> 32));
		post->metadata_buf_len = 0;
		post->metadata_buf_addr.low_addr = 0;
		post->metadata_buf_addr.high_addr = 0;
	} else {
		struct msgbuf_rx_ioctl_resp_or_event *post;

		post = ring_reserve_for_write(ring);
		if (post == NULL)
			goto ring_full;
		memset(post, 0, sizeof(*post));
		post->msg.msgtype = msgtype;
		post->msg.ifidx = 0;
		post->msg.request_id = htole32(pktid);
		post->host_buf_len = htole16((uint16_t)bufsize);
		post->host_buf_addr.low_addr =
		    htole32((uint32_t)(pa & 0xffffffff));
		post->host_buf_addr.high_addr = htole32((uint32_t)(pa >> 32));
	}
	ring_write_complete(ring);
	mtx_unlock(&ring->lock);

	if (type == BRCM_RXPOST_EVENT)
		mb->cur_eventbuf++;
	else
		mb->cur_rxbufpost++;
	return (0);

ring_full:
	{
		static struct timeval _last;
		static int _cnt;
		if (ppsratecheck(&_last, &_cnt, 1))
			device_printf(DEV(mb),
			    "msgbuf: post_one_rxbuf(type=%u): ring reserve failed (ring full or unpublished)\n",
			    type);
	}
	mtx_unlock(&ring->lock);
	/* Roll back the rxpost slot + dmamap + mbuf. */
	(void)rxpost_release(mb, pktid, NULL, NULL);
	bus_dmamap_unload(mb->rx_mbuf_tag, map);
	bus_dmamap_destroy(mb->rx_mbuf_tag, map);
	m_freem(m);
	return (ENOSPC);
}

/*
 * Post up to `count` event buffers from the coherent pool.  Slots
 * post/refill idempotently — a "refill" just re-posts the same slot
 * with fresh content.  Returns number successfully posted.
 */
static uint32_t
msgbuf_post_event_bufs(struct brcm_pci_msgbuf *mb, uint32_t count)
{
	uint32_t posted = 0;
	uint32_t i;
	uint32_t slot_start = mb->cur_eventbuf;

	if (count > (uint32_t)(mb->max_eventbuf - slot_start))
		count = mb->max_eventbuf - slot_start;
	for (i = 0; i < count; i++) {
		if (msgbuf_post_event_slot(mb, slot_start + i) != 0)
			break;
		mb->cur_eventbuf++;
		posted++;
	}
	return (posted);
}

/*
 * Deferred WL_EVENT dispatch task.  Runs on taskqueue_thread outside
 * any ISR / ring lock, so its downstream calls into net80211
 * (ieee80211_add_scan_result etc.) can safely take IEEE80211_LOCK.
 * See the queue-and-defer comment in msgbuf_process_wl_event.
 */
static void
msgbuf_event_task(void *arg, int pending __unused)
{
	struct brcm_pci_msgbuf *mb = arg;
	struct brcm_pci_event *ep;

	for (;;) {
		mtx_lock(&mb->event_q_mtx);
		ep = STAILQ_FIRST(&mb->event_q);
		if (ep != NULL)
			STAILQ_REMOVE_HEAD(&mb->event_q, link);
		mtx_unlock(&mb->event_q_mtx);
		if (ep == NULL)
			return;
		brcm_pci_msgbuf_event_up(mb->sc, ep->data, ep->datalen);
		free(ep, M_DEVBUF);
	}
}

/* Post up to `count` RX data buffers. */
static uint32_t
msgbuf_post_rx_bufs(struct brcm_pci_msgbuf *mb, uint32_t count)
{
	uint32_t i;

	for (i = 0; i < count; i++)
		if (msgbuf_post_one_rxbuf(mb, BRCM_RXPOST_DATA) != 0)
			break;
	return (i);
}

/* Refill the event/rxbuf pools up to their maxes.  Called from ISR
 * after consuming a slot. */
static void
msgbuf_rxpost_refill(struct brcm_pci_msgbuf *mb)
{
	uint32_t need, got;

	if (mb->cur_eventbuf < mb->max_eventbuf) {
		need = mb->max_eventbuf - mb->cur_eventbuf;
		got = msgbuf_post_event_bufs(mb, need);
		if (got > 0)
			mb->stat_rxpost_refills++;
	}
	if (mb->cur_rxbufpost < mb->max_rxbufpost) {
		need = mb->max_rxbufpost - mb->cur_rxbufpost;
		got = msgbuf_post_rx_bufs(mb, need);
		if (got > 0)
			mb->stat_rxpost_refills++;
	}
}

/* -----------------------------------------------------------------
 * Flowring create: allocate coherent buffer, send FLOW_RING_CREATE
 * via H2D_CTRL, wait cv up to 2s.  Idempotent: subsequent create for
 * the same flowid returns 0 immediately if already OPEN.
 *
 * Local flowid semantics: caller passes back a small integer 0-based
 * into mb->flowrings[].  The fw sees `flowid + IDSTART`.  For first
 * light we serialize on flow_mtx (no concurrent creates).
 * ----------------------------------------------------------------- */
#define	FLOW_CREATE_TIMEOUT_MS	2000

/* Map priority (0..7) → 802.1D TID.  Identity map for first light
 * since the AC<->TID mapping is 1:1 for prio 0..7. */
static inline uint8_t
prio_to_tid(uint8_t prio)
{
	return (prio & 0x07);
}

static int
find_free_local_flowid(struct brcm_pci_msgbuf *mb, uint16_t *out)
{
	uint16_t i;

	for (i = 0; i < mb->max_flowrings; i++) {
		if (mb->flowrings[i].status == BRCM_FLOW_CLOSED) {
			*out = i;
			return (0);
		}
	}
	return (ENOSPC);
}

uint16_t
brcm_pci_msgbuf_flowring_lookup(struct brcm_pci_softc *sc,
    const uint8_t da[6], uint8_t prio)
{
	struct brcm_pci_msgbuf *mb = brcm_pci_msgbuf_state(sc);
	uint16_t i;

	if (mb == NULL || mb->flowrings == NULL)
		return ((uint16_t)-1);
	mtx_lock(&mb->flow_mtx);
	for (i = 0; i < mb->max_flowrings; i++) {
		struct brcm_pci_flowring *fr = &mb->flowrings[i];
		if (fr->status != BRCM_FLOW_OPEN)
			continue;
		if (fr->prio != prio)
			continue;
		if (memcmp(fr->da, da, 6) != 0)
			continue;
		mtx_unlock(&mb->flow_mtx);
		return (i);
	}
	mtx_unlock(&mb->flow_mtx);
	return ((uint16_t)-1);
}

int
brcm_pci_msgbuf_flowring_create(struct brcm_pci_softc *sc,
    const uint8_t sa[6], const uint8_t da[6], uint8_t prio, uint8_t ifidx,
    uint16_t *flowid_out)
{
	struct brcm_pci_msgbuf *mb = brcm_pci_msgbuf_state(sc);
	struct brcm_pci_flowring *fr;
	struct brcm_pci_ring *ctl_ring;
	struct msgbuf_tx_flowring_create_req *req;
	uint32_t ringmem_addr;
	uint16_t local_id, fw_id;
	uint64_t paddr;
	int error;

	if (mb == NULL || !mb->attached)
		return (ENXIO);
	if (mb->flowrings == NULL)
		return (ENXIO);

	mtx_lock(&mb->flow_mtx);
	error = find_free_local_flowid(mb, &local_id);
	if (error != 0) {
		mtx_unlock(&mb->flow_mtx);
		return (error);
	}
	fr = &mb->flowrings[local_id];
	fr->status = BRCM_FLOW_PENDING;
	memcpy(fr->da, da, 6);
	memcpy(fr->sa, sa, 6);
	fr->prio = prio;
	fr->tid = prio_to_tid(prio);
	fr->ifidx = ifidx;
	mtx_unlock(&mb->flow_mtx);

	/* Allocate the flowring's DMA-coherent circular buffer.  Assigned
	 * TCM index-slot addrs derived from cursor set in msgbuf_init_rings. */
	if (fr->ring.buf.tag == NULL) {
		error = brcm_pci_msgbuf_dma_alloc(mb, &fr->ring.buf,
		    BRCM_H2D_TXFLOWRING_MAX_ITEM * BRCM_H2D_TXFLOWRING_ITEMSIZE,
		    "flowring");
		if (error != 0)
			goto fail;
	}
	ring_config(&fr->ring, BRCM_H2D_TXFLOWRING_MAX_ITEM,
	    BRCM_H2D_TXFLOWRING_ITEMSIZE, mb);
	fr->ring.id = local_id + BRCM_H2D_MSGRING_FLOWRING_IDSTART;
	fr->ring.w_idx_addr = mb->flow_h2d_w_next + local_id * sizeof(uint32_t);
	fr->ring.r_idx_addr = mb->flow_h2d_r_next + local_id * sizeof(uint32_t);

	/* Publish per-ring metadata into fw's ringmem slot for this flow. */
	ringmem_addr = mb->flow_ringmem_next + local_id * BRCM_RING_MEM_SZ;
	paddr = (uint64_t)fr->ring.buf.paddr;
	tcm_write32(mb, ringmem_addr + BRCM_RING_MEM_BASE_ADDR_OFFSET,
	    (uint32_t)(paddr & 0xffffffff));
	tcm_write32(mb, ringmem_addr + BRCM_RING_MEM_BASE_ADDR_OFFSET + 4,
	    (uint32_t)(paddr >> 32));
	tcm_write16(mb, ringmem_addr + BRCM_RING_MAX_ITEM_OFFSET,
	    BRCM_H2D_TXFLOWRING_MAX_ITEM);
	tcm_write16(mb, ringmem_addr + BRCM_RING_LEN_ITEMS_OFFSET,
	    BRCM_H2D_TXFLOWRING_ITEMSIZE);
	tcm_write16(mb, fr->ring.w_idx_addr, 0);
	tcm_write16(mb, fr->ring.r_idx_addr, 0);

	/* Send FLOW_RING_CREATE onto H2D_CTRL_SUBMIT. */
	fw_id = local_id + BRCM_H2D_MSGRING_FLOWRING_IDSTART;
	ctl_ring = &mb->rings[BRCM_H2D_MSGRING_CONTROL_SUBMIT];
	mtx_lock(&ctl_ring->lock);
	req = ring_reserve_for_write(ctl_ring);
	if (req == NULL) {
		mtx_unlock(&ctl_ring->lock);
		error = ENOSPC;
		goto fail;
	}
	memset(req, 0, sizeof(*req));
	req->msg.msgtype = BRCM_MSGBUF_TYPE_FLOW_RING_CREATE;
	req->msg.ifidx = ifidx;
	req->msg.request_id = 0;
	memcpy(req->da, da, 6);
	memcpy(req->sa, sa, 6);
	req->tid = fr->tid;
	req->if_flags = 0;
	req->flow_ring_id = htole16(fw_id);
	req->tc = 0;
	req->priority = prio;
	req->int_vector = 0;
	req->max_items = htole16(BRCM_H2D_TXFLOWRING_MAX_ITEM);
	req->len_item = htole16(BRCM_H2D_TXFLOWRING_ITEMSIZE);
	req->flow_ring_addr.low_addr = htole32((uint32_t)(paddr & 0xffffffff));
	req->flow_ring_addr.high_addr = htole32((uint32_t)(paddr >> 32));

	ring_write_complete(ctl_ring);
	mtx_unlock(&ctl_ring->lock);

	mb->stat_flow_create_tx++;

	MDPRINTF(mb, 0,
	    "msgbuf: FLOW_CREATE flow=%u prio=%u tid=%u da=%02x:%02x:%02x:%02x:%02x:%02x\n",
	    fw_id, prio, fr->tid,
	    da[0], da[1], da[2], da[3], da[4], da[5]);

	/* Wait for CREATE_CMPLT on the D2H control ring. */
	mtx_lock(&mb->flow_mtx);
	while (fr->status == BRCM_FLOW_PENDING) {
		error = cv_timedwait_sig(&mb->flow_cv, &mb->flow_mtx,
		    hz * FLOW_CREATE_TIMEOUT_MS / 1000);
		if (error == EWOULDBLOCK) {
			fr->status = BRCM_FLOW_FAILED;
			mtx_unlock(&mb->flow_mtx);
			device_printf(DEV(mb),
			    "msgbuf: FLOW_CREATE flow=%u timeout\n", fw_id);
			return (ETIMEDOUT);
		}
		if (error != 0) {
			mtx_unlock(&mb->flow_mtx);
			return (error);
		}
	}
	if (fr->status != BRCM_FLOW_OPEN) {
		mtx_unlock(&mb->flow_mtx);
		mb->stat_flow_create_fail++;
		device_printf(DEV(mb),
		    "msgbuf: FLOW_CREATE flow=%u rejected (fw status=%d)\n",
		    fw_id, fr->last_create_status);
		return (EIO);
	}
	mtx_unlock(&mb->flow_mtx);

	mb->stat_flow_create_ok++;
	*flowid_out = local_id;
	return (0);

fail:
	mtx_lock(&mb->flow_mtx);
	fr->status = BRCM_FLOW_CLOSED;
	mtx_unlock(&mb->flow_mtx);
	brcm_pci_msgbuf_dma_free(mb, &fr->ring.buf);
	return (error);
}

/* -----------------------------------------------------------------
 * TX submission — takes an mbuf with an Ethernet header, maps it,
 * writes TX_POST into the flowring, doorbells.  Ownership of `m`
 * passes to us on success (freed on TX_STATUS ack).
 * ----------------------------------------------------------------- */
static void
tx_load_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	uint64_t *pa = arg;

	if (error != 0 || nseg < 1) {
		*pa = 0;
		return;
	}
	*pa = (uint64_t)segs[0].ds_addr;
}

int
brcm_pci_msgbuf_txmbuf(struct brcm_pci_softc *sc, uint16_t flowid,
    struct mbuf *m, uint8_t ifidx)
{
	struct brcm_pci_msgbuf *mb = brcm_pci_msgbuf_state(sc);
	struct brcm_pci_flowring *fr;
	struct brcm_pci_ring *ring;
	struct msgbuf_tx_msghdr *tx;
	bus_dmamap_t map = NULL;
	uint64_t data_pa;
	uint32_t pktid;
	int error;
	uint16_t datalen;

	if (mb == NULL || !mb->attached || flowid >= mb->max_flowrings)
		return (ENXIO);
	fr = &mb->flowrings[flowid];
	if (fr->status != BRCM_FLOW_OPEN)
		return (ENOTCONN);
	if (m->m_pkthdr.len < ETHER_HDR_LEN)
		return (EINVAL);

	/* Ensure single mbuf — first-light TX is unfragmented. */
	if (m->m_next != NULL) {
		struct mbuf *m2 = m_defrag(m, M_NOWAIT);
		if (m2 == NULL)
			return (ENOMEM);
		m = m2;
	}

	/* bus_dmamap for this packet. */
	error = bus_dmamap_create(mb->tx_mbuf_tag, 0, &map);
	if (error != 0)
		return (error);
	data_pa = 0;
	error = bus_dmamap_load(mb->tx_mbuf_tag, map, mtod(m, void *),
	    m->m_pkthdr.len, tx_load_cb, &data_pa, BUS_DMA_NOWAIT);
	if (error != 0 || data_pa == 0) {
		bus_dmamap_destroy(mb->tx_mbuf_tag, map);
		return (error != 0 ? error : EIO);
	}

	error = pktid_alloc(mb, m, flowid, &pktid);
	if (error != 0) {
		bus_dmamap_unload(mb->tx_mbuf_tag, map);
		bus_dmamap_destroy(mb->tx_mbuf_tag, map);
		mb->stat_tx_no_pktid++;
		return (error);
	}
	mb->pktids[pktid].map = map;
	mb->pktids[pktid].pa = data_pa;
	mb->pktids[pktid].datalen = m->m_pkthdr.len;

	ring = &fr->ring;
	mtx_lock(&ring->lock);
	tx = ring_reserve_for_write(ring);
	if (tx == NULL) {
		mtx_unlock(&ring->lock);
		(void)pktid_release(mb, pktid, NULL);
		bus_dmamap_unload(mb->tx_mbuf_tag, map);
		bus_dmamap_destroy(mb->tx_mbuf_tag, map);
		mb->stat_tx_ring_full++;
		return (ENOSPC);
	}

	datalen = m->m_pkthdr.len;
	memset(tx, 0, sizeof(*tx));
	tx->msg.msgtype = BRCM_MSGBUF_TYPE_TX_POST;
	tx->msg.ifidx = ifidx;
	tx->msg.flags = 0;
	tx->msg.request_id = htole32(pktid + 1);
	memcpy(tx->txhdr, mtod(m, uint8_t *), 14);
	tx->flags = BRCM_MSGBUF_PKT_FLAGS_FRAME_802_3 |
	    ((fr->prio & 0x07) << BRCM_MSGBUF_PKT_FLAGS_PRIO_SHIFT);
	tx->seg_cnt = 1;
	tx->data_len = htole16(datalen - 14);
	/*
	 * data_buf points to the payload AFTER the 14-byte Ethernet
	 * header (which is copied into tx->txhdr).  Previously we set
	 * data_buf = mbuf start + data_len = mbuf_len - 14, which made
	 * fw read the first 14 bytes of the Ethernet header twice and
	 * truncated the last 14 bytes of the payload — bad EAPOL M2.
	 */
	tx->data_buf_addr.low_addr = htole32((uint32_t)((data_pa + 14) & 0xffffffff));
	tx->data_buf_addr.high_addr = htole32((uint32_t)((data_pa + 14) >> 32));
	tx->metadata_buf_len = 0;
	tx->metadata_buf_addr.low_addr = 0;
	tx->metadata_buf_addr.high_addr = 0;

	/* Sync CPU-writes into the packet buffer visible to fw. */
	bus_dmamap_sync(mb->tx_mbuf_tag, map, BUS_DMASYNC_PREWRITE);

	ring_write_complete(ring);
	mtx_unlock(&ring->lock);

	mb->stat_tx_post++;
	return (0);
}

/* -----------------------------------------------------------------
 * Fw → host ctrl-ring processing for FLOW_RING_CREATE_CMPLT and
 * TX_STATUS.  Called from msgbuf_process_ctrl_msg dispatch.
 * ----------------------------------------------------------------- */
static void
msgbuf_process_flowring_create_cmplt(struct brcm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_flowring_create_resp *resp = item;
	uint16_t fw_id, local_id;
	int16_t status;

	fw_id = le16toh(resp->compl_hdr.flow_ring_id);
	status = (int16_t)le16toh(resp->compl_hdr.status);

	if (fw_id < BRCM_H2D_MSGRING_FLOWRING_IDSTART) {
		device_printf(DEV(mb),
		    "msgbuf: FLOW_CREATE_CMPLT weird fw_id=%u status=%d\n",
		    fw_id, status);
		return;
	}
	local_id = fw_id - BRCM_H2D_MSGRING_FLOWRING_IDSTART;
	if (local_id >= mb->max_flowrings) {
		device_printf(DEV(mb),
		    "msgbuf: FLOW_CREATE_CMPLT local_id=%u out of range\n",
		    local_id);
		return;
	}

	mtx_lock(&mb->flow_mtx);
	mb->flowrings[local_id].last_create_status = status;
	mb->flowrings[local_id].status = (status == 0) ?
	    BRCM_FLOW_OPEN : BRCM_FLOW_FAILED;
	cv_broadcast(&mb->flow_cv);
	mtx_unlock(&mb->flow_mtx);

	MDPRINTF(mb, 0,
	    "msgbuf: FLOW_CREATE_CMPLT fw_id=%u local=%u status=%d\n",
	    fw_id, local_id, status);
}

static void
msgbuf_process_txstatus(struct brcm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_tx_status *ts = item;
	uint32_t pktid;
	struct mbuf *m;
	bus_dmamap_t map = NULL;
	uint16_t tx_status;

	pktid = le32toh(ts->msg.request_id);
	if (pktid == 0) {
		device_printf(DEV(mb),
		    "msgbuf: TX_STATUS with request_id=0 (unexpected)\n");
		return;
	}
	pktid--;	/* TX_POST convention: request_id = idx + 1 */

	tx_status = le16toh(ts->tx_status);
	m = pktid_release(mb, pktid, &map);
	if (m == NULL) {
		device_printf(DEV(mb),
		    "msgbuf: TX_STATUS pktid=%u unknown\n", pktid);
		return;
	}
	{
		uint16_t etype = 0;
		if (m->m_pkthdr.len >= 14 && m->m_len >= 14) {
			const uint8_t *p = mtod(m, const uint8_t *);
			etype = (uint16_t)p[12] << 8 | p[13];
		}
		MDPRINTF(mb, 0,
		    "msgbuf: TX_STATUS pktid=%u status=0x%04x len=%d etype=0x%04x\n",
		    pktid, tx_status, m->m_pkthdr.len, etype);
	}
	if (map != NULL) {
		bus_dmamap_sync(mb->tx_mbuf_tag, map, BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(mb->tx_mbuf_tag, map);
		bus_dmamap_destroy(mb->tx_mbuf_tag, map);
	}
	m_freem(m);

	if (tx_status == 0)
		mb->stat_tx_status_ok++;
	else
		mb->stat_tx_status_err++;
}

/* -----------------------------------------------------------------
 * DCMD wrappers.  All synchronous via brcm_pci_msgbuf_dcmd (which
 * owns dcmd_sx for serialization).
 * ----------------------------------------------------------------- */
#define	BRCM_IOVAR_BUF_MAX	1024

int
brcm_pci_msgbuf_dcmd_set_int(struct brcm_pci_softc *sc, uint32_t cmd,
    uint32_t val)
{
	uint32_t le = htole32(val);
	size_t rlen = 0;
	int32_t fwerr = 0;
	int error;

	error = brcm_pci_msgbuf_dcmd(sc, cmd, true, &le, sizeof(le),
	    NULL, &rlen, &fwerr);
	if (error == 0 && fwerr != 0)
		error = EIO;
	return (error);
}

int
brcm_pci_msgbuf_dcmd_get_int(struct brcm_pci_softc *sc, uint32_t cmd,
    uint32_t *val)
{
	uint32_t buf = 0;
	size_t rlen = sizeof(buf);
	int32_t fwerr = 0;
	int error;

	error = brcm_pci_msgbuf_dcmd(sc, cmd, false, &buf, sizeof(buf),
	    &buf, &rlen, &fwerr);
	if (error != 0)
		return (error);
	if (fwerr != 0)
		return (EIO);
	if (rlen < sizeof(uint32_t))
		return (EIO);
	*val = le32toh(buf);
	return (0);
}

int
brcm_pci_msgbuf_dcmd_set_var(struct brcm_pci_softc *sc, const char *name,
    const void *data, size_t datalen)
{
	uint8_t buf[BRCM_IOVAR_BUF_MAX];
	size_t namelen, buflen, rlen = 0;
	int32_t fwerr = 0;
	int error;

	namelen = strlen(name) + 1;
	if (namelen + datalen > sizeof(buf))
		return (E2BIG);
	memcpy(buf, name, namelen);
	if (data != NULL && datalen != 0)
		memcpy(buf + namelen, data, datalen);
	buflen = namelen + datalen;

	error = brcm_pci_msgbuf_dcmd(sc, BRCM_C_SET_VAR, true, buf, buflen,
	    NULL, &rlen, &fwerr);
	if (error == 0 && fwerr != 0)
		error = EIO;
	return (error);
}

int
brcm_pci_msgbuf_dcmd_get_var(struct brcm_pci_softc *sc, const char *name,
    void *data, size_t *datalenp)
{
	uint8_t buf[BRCM_IOVAR_BUF_MAX];
	size_t namelen, buflen, rlen;
	int32_t fwerr = 0;
	int error;

	if (datalenp == NULL)
		return (EINVAL);
	namelen = strlen(name) + 1;
	if (namelen + *datalenp > sizeof(buf))
		return (E2BIG);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, name, namelen);
	buflen = namelen + *datalenp;
	rlen = *datalenp;

	error = brcm_pci_msgbuf_dcmd(sc, BRCM_C_GET_VAR, false, buf, buflen,
	    buf, &rlen, &fwerr);
	if (error != 0)
		return (error);
	if (fwerr != 0)
		return (EIO);
	if (data != NULL && rlen > 0)
		memcpy(data, buf, rlen);
	*datalenp = rlen;
	return (0);
}

/* -----------------------------------------------------------------
 * DCMD round-trip.
 *
 * (a) Post 1 IOCTLRESP buffer.
 * (b) Enqueue IOCTLPTR_REQ into H2D_CONTROL_SUBMIT with:
 *     - cmd, ifidx=0, request_id=BRCM_IOCTL_REQ_PKTID
 *     - trans_id = ++dcmd_reqid
 *     - input_buf_len = params_len
 *     - output_buf_len = *resp_lenp
 *     - req_buf_addr = mb->ioctbuf physical address
 *     - copy params into mb->ioctbuf host memory
 * (c) Doorbell + wait on dcmd_cv up to 2s.
 * (d) On completion, copy mb->ioctbuf (fw wrote response there)
 *     into caller's resp.  Set *fwerr = dcmd_resp_status.
 * ----------------------------------------------------------------- */
int
brcm_pci_msgbuf_dcmd(struct brcm_pci_softc *sc, uint32_t cmd, bool is_set,
    const void *params, size_t params_len, void *resp, size_t *resp_lenp,
    int32_t *fwerr)
{
	struct brcm_pci_msgbuf *mb = brcm_pci_msgbuf_state(sc);
	struct brcm_pci_ring *ring;
	struct msgbuf_ioctl_req_hdr *req;
	uint16_t buf_len, out_len;
	uint64_t paddr;
	int error;

	if (mb == NULL || !mb->attached)
		return (ENXIO);
	if (params_len > BRCM_MSGBUF_MAX_CTL_PKT_SIZE ||
	    (resp_lenp != NULL && *resp_lenp > BRCM_MSGBUF_MAX_CTL_PKT_SIZE))
		return (E2BIG);

	MDPRINTF(mb, 0,
	    "SCAN_DBG: dcmd cmd=0x%x is_set=%d plen=%zu enter\n",
	    cmd, is_set, params_len);
	sx_xlock(&mb->dcmd_sx);
	MDPRINTF(mb, 0,
	    "SCAN_DBG: dcmd sx_xlock acquired\n");

	/* Fresh IOCTLRESP buffer for fw to write reply into. */
	error = msgbuf_post_ioctlresp(mb);
	if (error != 0) {
		sx_xunlock(&mb->dcmd_sx);
		return (error);
	}

	/* Stage request payload. */
	buf_len = (uint16_t)MIN(params_len, BRCM_MSGBUF_MAX_CTL_PKT_SIZE);
	if (params != NULL && buf_len > 0)
		memcpy(mb->ioctbuf.vaddr, params, buf_len);
	else
		memset(mb->ioctbuf.vaddr, 0, buf_len);

	/*
	 * Fw writes the response into the same ioctbuf slot the request
	 * lives in.  output_buf_len must be the FULL caller buffer size,
	 * not just the expected response length.  If we set
	 * output_buf_len < input_buf_len, fw returns BCME_BUFTOOSHORT
	 * (-14) even when the actual response is small.
	 */
	out_len = (uint16_t)MAX(buf_len,
	    resp_lenp != NULL ? *resp_lenp : 0);

	ring = &mb->rings[BRCM_H2D_MSGRING_CONTROL_SUBMIT];
	mtx_lock(&ring->lock);
	req = ring_reserve_for_write(ring);
	if (req == NULL) {
		static struct timeval _last;
		static int _cnt;
		mtx_unlock(&ring->lock);
		sx_xunlock(&mb->dcmd_sx);
		if (ppsratecheck(&_last, &_cnt, 1))
			device_printf(DEV(mb),
			    "msgbuf: dcmd: h2d ctrl ring full\n");
		return (ENOSPC);
	}
	mb->dcmd_reqid++;

	memset(req, 0, sizeof(*req));
	req->msg.msgtype = BRCM_MSGBUF_TYPE_IOCTLPTR_REQ;
	req->msg.ifidx = 0;
	req->msg.flags = 0;
	req->msg.request_id = htole32(BRCM_IOCTL_REQ_PKTID);
	req->cmd = htole32(cmd);
	req->trans_id = htole16(mb->dcmd_reqid);
	req->input_buf_len = htole16(buf_len);
	req->output_buf_len = htole16(out_len);
	paddr = (uint64_t)mb->ioctbuf.paddr;
	req->req_buf_addr.low_addr = htole32((uint32_t)(paddr & 0xffffffff));
	req->req_buf_addr.high_addr = htole32((uint32_t)(paddr >> 32));

	mtx_lock(&mb->dcmd_mtx);
	mb->dcmd_completed = false;
	mtx_unlock(&mb->dcmd_mtx);

	ring_write_complete(ring);
	mtx_unlock(&ring->lock);

	mb->stat_dcmd_tx++;
	MDPRINTF(mb, 0,
	    "SCAN_DBG: dcmd cmd=0x%x submitted, waiting for cv\n", cmd);

	/* Wait for ISR to signal completion. */
	mtx_lock(&mb->dcmd_mtx);
	while (!mb->dcmd_completed) {
		error = cv_timedwait_sig(&mb->dcmd_cv, &mb->dcmd_mtx,
		    hz * MSGBUF_IOCTL_RESP_TIMEOUT_MS / 1000);
		if (error == EWOULDBLOCK) {
			static struct timeval _last;
			static int _cnt;
			mb->stat_dcmd_timeout++;
			mtx_unlock(&mb->dcmd_mtx);
			if (ppsratecheck(&_last, &_cnt, 1))
				device_printf(DEV(mb),
				    "msgbuf: dcmd cmd=0x%x timeout\n", cmd);
			sx_xunlock(&mb->dcmd_sx);
			return (ETIMEDOUT);
		}
		if (error != 0) {
			mtx_unlock(&mb->dcmd_mtx);
			sx_xunlock(&mb->dcmd_sx);
			return (error);
		}
	}
	mtx_unlock(&mb->dcmd_mtx);

	/* Copy response out from ioctbuf. */
	if (resp != NULL && resp_lenp != NULL) {
		size_t rlen = MIN(*resp_lenp, mb->dcmd_resp_len);
		memcpy(resp, mb->ioctbuf.vaddr, rlen);
		*resp_lenp = rlen;
	}
	if (fwerr != NULL)
		*fwerr = mb->dcmd_resp_status;

	sx_xunlock(&mb->dcmd_sx);
	return (0);
}

/* -----------------------------------------------------------------
 * ISR filter.  Runs in interrupt context.  If a bit is set in
 * MAILBOXINT, mask the chip's interrupt source (MAILBOXMASK=0) and
 * schedule the ithread; the ithread will read, ACK, drain, and
 * re-enable.  This avoids re-entering the filter while the thread
 * processes.
 * ----------------------------------------------------------------- */
int
brcm_pci_msgbuf_isr_filter(void *arg)
{
	struct brcm_pci_msgbuf *mb = arg;
	uint32_t status;

	status = pcie2_read32(mb, BRCM_PCIE2REG_MAILBOXINT);
	if (status == 0 || status == 0xffffffff)
		return (FILTER_STRAY);

	/* Mask off — thread will re-enable after draining. */
	pcie2_write32(mb, BRCM_PCIE2REG_MAILBOXMASK, 0);
	mb->stat_isr_hits++;
	return (FILTER_SCHEDULE_THREAD);
}

/* -----------------------------------------------------------------
 * WL_EVENT payload processing.  Fw hands us a `msgbuf_rx_event`
 * descriptor whose request_id names an event-buffer pktid.  The
 * actual event payload lives in the host mbuf pinned by that pktid
 * (fw DMA'd it there).  For first-light we decode a minimal
 * bcmevent header for logging; full fweh-style dispatch is deferred.
 * ----------------------------------------------------------------- */
/* Human-readable event-code lookup. */
static const char *
bcmevent_name(uint32_t code)
{
	switch (code) {
	case BRCM_PCI_E_SET_SSID:		return "SET_SSID";
	case BRCM_PCI_E_JOIN:		return "JOIN";
	case BRCM_PCI_E_START:		return "START";
	case BRCM_PCI_E_AUTH:		return "AUTH";
	case BRCM_PCI_E_AUTH_IND:		return "AUTH_IND";
	case BRCM_PCI_E_DEAUTH:		return "DEAUTH";
	case BRCM_PCI_E_DEAUTH_IND:		return "DEAUTH_IND";
	case BRCM_PCI_E_ASSOC:		return "ASSOC";
	case BRCM_PCI_E_ASSOC_IND:		return "ASSOC_IND";
	case BRCM_PCI_E_REASSOC:		return "REASSOC";
	case BRCM_PCI_E_REASSOC_IND:	return "REASSOC_IND";
	case BRCM_PCI_E_DISASSOC:		return "DISASSOC";
	case BRCM_PCI_E_DISASSOC_IND:	return "DISASSOC_IND";
	case BRCM_PCI_E_LINK:		return "LINK";
	case BRCM_PCI_E_MIC_ERROR:		return "MIC_ERROR";
	case BRCM_PCI_E_ROAM:		return "ROAM";
	case BRCM_PCI_E_PMKID_CACHE:	return "PMKID_CACHE";
	case BRCM_PCI_E_EAPOL_MSG:		return "EAPOL_MSG";
	case BRCM_PCI_E_SCAN_COMPLETE:	return "SCAN_COMPLETE";
	case BRCM_PCI_E_JOIN_START:		return "JOIN_START";
	case BRCM_PCI_E_ROAM_START:		return "ROAM_START";
	case BRCM_PCI_E_ASSOC_START:	return "ASSOC_START";
	case BRCM_PCI_E_PSK_SUP:		return "PSK_SUP";
	case BRCM_PCI_E_COUNTRY_CODE_CHANGED: return "COUNTRY_CODE_CHANGED";
	case BRCM_PCI_E_ACTION_FRAME:	return "ACTION_FRAME";
	case BRCM_PCI_E_ESCAN_RESULT:	return "ESCAN_RESULT";
	case BRCM_PCI_E_PROBERESP_MSG:	return "PROBERESP_MSG";
	case BRCM_PCI_E_FIFO_CREDIT_MAP:	return "FIFO_CREDIT_MAP";
	case BRCM_PCI_E_IF:		return "IF";
	case BRCM_PCI_E_RSSI:		return "RSSI";
	case BRCM_PCI_E_TRACE:		return "TRACE";
	case BRCM_PCI_E_BEACON_RX:	return "BEACON_RX";
	case BRCM_PCI_E_TXFAIL:		return "TXFAIL";
	case BRCM_PCI_E_RADIO:		return "RADIO";
	case BRCM_PCI_E_PSM_WATCHDOG:	return "PSM_WATCHDOG";
	default:			return "?";
	}
}

static const char *
bcmevent_status_name(uint32_t status)
{
	switch (status) {
	case BRCM_PCI_E_STATUS_SUCCESS:	return "SUCCESS";
	case BRCM_PCI_E_STATUS_FAIL:	return "FAIL";
	case BRCM_PCI_E_STATUS_TIMEOUT:	return "TIMEOUT";
	case BRCM_PCI_E_STATUS_NO_NETWORKS:	return "NO_NETWORKS";
	case BRCM_PCI_E_STATUS_ABORT:	return "ABORT";
	case BRCM_PCI_E_STATUS_NO_ACK:	return "NO_ACK";
	case BRCM_PCI_E_STATUS_UNSOLICITED:	return "UNSOLICITED";
	case BRCM_PCI_E_STATUS_ATTEMPT:	return "ATTEMPT";
	case BRCM_PCI_E_STATUS_PARTIAL:	return "PARTIAL";
	case BRCM_PCI_E_STATUS_NEWSCAN:	return "NEWSCAN";
	case BRCM_PCI_E_STATUS_NEWASSOC:	return "NEWASSOC";
	case BRCM_PCI_E_STATUS_ERROR:	return "ERROR";
	default:			return "?";
	}
}

static void
msgbuf_process_wl_event(struct brcm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_rx_event *ev = item;
	struct brcm_pci_dma_buf *evb;
	uint32_t pktid, slot;
	uint16_t datalen;
	uint8_t *payload;

	pktid = le32toh(ev->msg.request_id);
	datalen = le16toh(ev->event_data_len);

	mb->stat_event_rx++;

	if (!BRCM_EVENTBUF_IS_EVENT(pktid)) {
		device_printf(DEV(mb),
		    "msgbuf: WL_EVENT pktid=0x%x not in eventbuf range\n",
		    pktid);
		return;
	}
	slot = BRCM_EVENTBUF_PKTID_SLOT(pktid);
	if (slot >= mb->max_eventbuf) {
		device_printf(DEV(mb),
		    "msgbuf: WL_EVENT slot %u out of range (max %u)\n",
		    slot, mb->max_eventbuf);
		return;
	}
	evb = &mb->eventbufs[slot];
	if (evb->vaddr == NULL) {
		device_printf(DEV(mb),
		    "msgbuf: WL_EVENT slot %u vaddr NULL\n", slot);
		return;
	}

	bus_dmamap_sync(evb->tag, evb->map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	if (datalen > evb->size)
		datalen = evb->size;

	if (datalen < BRCM_EVT_OFFSET_DATA) {
		device_printf(DEV(mb),
		    "msgbuf: WL_EVENT ifidx=%u short (datalen=%u < %u)\n",
		    ev->msg.ifidx, datalen, BRCM_EVT_OFFSET_DATA);
		goto refill;
	}
	payload = evb->vaddr;
	{
		uint16_t etype;
		struct brcm_bcm_ethhdr *eh;
		struct brcm_bcm_event_msg *em;
		uint32_t event_code, status, reason, data_len_field;
		uint16_t version, flags;
		const uint8_t *addr;

		etype = be16dec(payload + 12);
		if (etype != BRCM_ETH_TYPE_EVENT) {
			device_printf(DEV(mb),
			    "msgbuf: WL_EVENT unexpected etype=0x%04x "
			    "(want 0x886c)\n", etype);
			goto refill;
		}
		eh = (struct brcm_bcm_ethhdr *)(payload + BRCM_EVT_OFFSET_BCM_ETHHDR);
		em = (struct brcm_bcm_event_msg *)(payload + BRCM_EVT_OFFSET_MSG);

		version = be16dec(&em->version);
		flags = be16dec(&em->flags);
		event_code = be32dec(&em->event_type);
		status = be32dec(&em->status);
		reason = be32dec(&em->reason);
		data_len_field = be32dec(&em->datalen);
		addr = em->addr;

		MDPRINTF(mb, 0,
		    "msgbuf: EVT %s(%u) status=%s(%u) reason=%u "
		    "flags=0x%x ifidx=%u addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "datalen=%u/%u v=%u eh_subtype=0x%04x usr_subtype=%u\n",
		    bcmevent_name(event_code), event_code,
		    bcmevent_status_name(status), status,
		    reason, flags, em->ifidx,
		    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
		    data_len_field, datalen - BRCM_EVT_OFFSET_DATA,
		    version, be16dec(&eh->subtype),
		    be16dec(&eh->usr_subtype));
	}
	/*
	 * Queue payload for deferred dispatch on taskqueue_thread.
	 * Direct dispatch here would deadlock: ISR holds ring->lock,
	 * brcm_pci_msgbuf_event_up -> brcm_handle_event ->
	 * ieee80211_add_scan_result acquires IEEE80211_LOCK, and the
	 * scan-trigger path (fmac_scan_start_shim -> DCMD) holds
	 * IEEE80211_LOCK across cv_wait for IOCTL_CMPLT.  If any
	 * WL_EVENT lands between the DCMD dispatch and cv_signal, the
	 * ISR takes ring->lock, waits for IEEE80211_LOCK held by the
	 * scan thread — scan thread cv_wait's for IOCTL_CMPLT which
	 * this same ISR is meant to deliver.  Textbook AB-BA deadlock.
	 *
	 * Deferring dispatch runs it AFTER the DCMD thread releases
	 * IEEE80211_LOCK, so no lock ordering issue.  Cost: one malloc
	 * + memcpy per event.
	 */
	{
		struct brcm_pci_event *ep;

		ep = malloc(sizeof(*ep), M_DEVBUF, M_NOWAIT);
		if (ep == NULL) {
			device_printf(DEV(mb),
			    "msgbuf: WL_EVENT malloc failed — dropping event\n");
			goto refill;
		}
		if (datalen > sizeof(ep->data))
			datalen = sizeof(ep->data);
		ep->datalen = datalen;
		memcpy(ep->data, payload, datalen);
		mtx_lock(&mb->event_q_mtx);
		STAILQ_INSERT_TAIL(&mb->event_q, ep, link);
		mtx_unlock(&mb->event_q_mtx);
		(void)taskqueue_enqueue(taskqueue_thread, &mb->event_task);
	}

refill:
	/* Re-post the same slot; buf lifetime = driver lifetime. */
	mb->cur_eventbuf--;
	(void)msgbuf_post_event_slot(mb, slot);
	mb->cur_eventbuf++;
}

/* -----------------------------------------------------------------
 * RX_CMPLT: fw completed a receive into one of our data buffers.
 * For first-light we log length + first bytes + release the mbuf.
 * Wiring to a net80211 rx sink is deferred.
 * ----------------------------------------------------------------- */
static void
msgbuf_process_rx_complete(struct brcm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_rx_complete *rc = item;
	struct mbuf *m;
	bus_dmamap_t map = NULL;
	uint8_t type = 0;
	uint32_t pktid;
	uint16_t datalen;

	pktid = le32toh(rc->msg.request_id);
	datalen = le16toh(rc->data_len);
	mb->stat_rx_data++;

	m = rxpost_release(mb, pktid, &map, &type);
	if (m == NULL || type != BRCM_RXPOST_DATA) {
		device_printf(DEV(mb),
		    "msgbuf: RX_CMPLT pktid=%u unknown (m=%p type=%u)\n",
		    pktid, m, type);
		mb->cur_rxbufpost--;
		if (m != NULL)
			m_freem(m);
		return;
	}
	if (map != NULL) {
		bus_dmamap_sync(mb->rx_mbuf_tag, map,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(mb->rx_mbuf_tag, map);
		bus_dmamap_destroy(mb->rx_mbuf_tag, map);
	}

	{
		uint16_t data_off = le16toh(rc->data_offset);
		uint16_t flags = le16toh(rc->flags);

		/*
		 * Strip fw-provided rx metadata offset if any, trim to
		 * datalen, and hand the mbuf to net80211 via the shared
		 * brcm.c core.  For first light we ignore monitor-mode
		 * 802.11 frames — chip is fullmac-STA, all frames come
		 * as 802.3.
		 */
		if (data_off > 0 && data_off <= m->m_len)
			m_adj(m, data_off);
		if (datalen < m->m_len) {
			m->m_len = datalen;
			m->m_pkthdr.len = datalen;
		}
		if ((flags & BRCM_MSGBUF_PKT_FLAGS_FRAME_MASK) ==
		    BRCM_MSGBUF_PKT_FLAGS_FRAME_802_11) {
			/* Monitor-mode 802.11 frame — not yet handled. */
			m_freem(m);
		} else {
			brcm_pci_msgbuf_rx_up(mb->sc, m, -50);
		}
	}
	mb->cur_rxbufpost--;
	msgbuf_rxpost_refill(mb);
}

/* -----------------------------------------------------------------
 * ithread — drains D2H_CONTROL_COMPLETE, wakes DCMD waiter on
 * MSGBUF_TYPE_IOCTL_CMPLT.  Other message types (WL_EVENT,
 * RING_STATUS, GEN_STATUS) are logged and dropped for first light.
 * ----------------------------------------------------------------- */
static void
msgbuf_process_ctrl_msg(struct brcm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_common_hdr *hdr = item;
	struct msgbuf_ioctl_resp_hdr *ioctl;

	mb->stat_ctl_msgs++;

	switch (hdr->msgtype) {
	case BRCM_MSGBUF_TYPE_IOCTL_CMPLT:
		ioctl = item;
		mtx_lock(&mb->dcmd_mtx);
		mb->dcmd_resp_status = (int16_t)le16toh(ioctl->compl_hdr.status);
		mb->dcmd_resp_len = le16toh(ioctl->resp_len);
		mb->dcmd_completed = true;
		cv_broadcast(&mb->dcmd_cv);
		mtx_unlock(&mb->dcmd_mtx);
		mb->stat_dcmd_rx++;
		MDPRINTF(mb, 0,
		    "msgbuf: IOCTL_CMPLT trans=%u status=%d resp_len=%u\n",
		    le16toh(ioctl->trans_id),
		    (int)mb->dcmd_resp_status, mb->dcmd_resp_len);
		break;
	case BRCM_MSGBUF_TYPE_FLOW_RING_CREATE_CMPLT:
		msgbuf_process_flowring_create_cmplt(mb, item);
		break;
	case BRCM_MSGBUF_TYPE_TX_STATUS:
		msgbuf_process_txstatus(mb, item);
		break;
	case BRCM_MSGBUF_TYPE_GEN_STATUS:
	case BRCM_MSGBUF_TYPE_RING_STATUS:
	case BRCM_MSGBUF_TYPE_IOCTLPTR_REQ_ACK:
		MDPRINTF(mb, 0,
		    "msgbuf: ctrl msg type 0x%02x (ignored, first-light)\n",
		    hdr->msgtype);
		break;
	case BRCM_MSGBUF_TYPE_WL_EVENT:
		msgbuf_process_wl_event(mb, item);
		break;
	case BRCM_MSGBUF_TYPE_RX_CMPLT:
		msgbuf_process_rx_complete(mb, item);
		break;
	default:
		device_printf(DEV(mb),
		    "msgbuf: unknown ctrl msgtype 0x%02x\n", hdr->msgtype);
		break;
	}
}

static void
drain_d2h_ring(struct brcm_pci_msgbuf *mb, uint32_t ring_idx)
{
	struct brcm_pci_ring *ring = &mb->rings[ring_idx];
	void *base;
	uint16_t n, i;

	mtx_lock(&ring->lock);
	base = ring_get_read_ptr(ring, &n);
	while (base != NULL && n != 0) {
		for (i = 0; i < n; i++) {
			void *item = (uint8_t *)base + i * ring->item_len;
			msgbuf_process_ctrl_msg(mb, item);
		}
		ring_read_complete(ring, n);
		base = ring_get_read_ptr(ring, &n);
	}
	mtx_unlock(&ring->lock);
}

void
brcm_pci_msgbuf_isr_thread(void *arg)
{
	struct brcm_pci_msgbuf *mb = arg;
	uint32_t status;

	/* Read + ACK chip-side status.  Done in thread context. */
	status = pcie2_read32(mb, BRCM_PCIE2REG_MAILBOXINT);
	if (status != 0 && status != 0xffffffff)
		pcie2_write32(mb, BRCM_PCIE2REG_MAILBOXINT, status);

	/* Drain BOTH D2H rings we care about.  D2H_CTRL carries IOCTL
	 * completions + FLOW_RING_CREATE_CMPLT + async events; D2H_TX
	 * carries TX_STATUS.  Fw signals via D2H_DB0/1 bits but for
	 * first-light we poll both rings regardless of which bit set. */
	drain_d2h_ring(mb, BRCM_D2H_MSGRING_CONTROL_COMPLETE);
	drain_d2h_ring(mb, BRCM_D2H_MSGRING_TX_COMPLETE);
	drain_d2h_ring(mb, BRCM_D2H_MSGRING_RX_COMPLETE);

	/* Re-arm chip interrupt (unless we're tearing down). */
	if (mb->attached)
		pcie2_write32(mb, BRCM_PCIE2REG_MAILBOXMASK,
		    BRCM_PCIE_MB_INT_D2H_DB | BRCM_PCIE_MB_INT_FN0);
}

/* -----------------------------------------------------------------
 * Public attach — must be called after fw has been released
 * (armcr4_release succeeded, fw is running).  This function is
 * idempotent for double-attach requests.
 * ----------------------------------------------------------------- */
int
brcm_pci_msgbuf_attach(struct brcm_pci_softc *sc)
{
	struct brcm_pci_msgbuf *mb = brcm_pci_msgbuf_state(sc);
	uint32_t pcie2;
	int error;

	if (mb == NULL)
		return (ENXIO);
	if (mb->attached)
		return (0);

	memset(mb, 0, sizeof(*mb));
	mb->sc = sc;

	pcie2 = brcm_pci_msgbuf_pcie2_base(sc);
	if (pcie2 == 0) {
		device_printf(brcm_pci_msgbuf_dev(sc),
		    "msgbuf: PCIe2 core not found in EROM\n");
		return (ENOENT);
	}
	mb->pcie2_base = pcie2;
	mb->intmask = BRCM_PCIE2REG_INTMASK;
	mb->mailboxint = BRCM_PCIE2REG_MAILBOXINT;
	mb->mailboxmask = BRCM_PCIE2REG_MAILBOXMASK;
	mb->h2d_mailbox_0 = BRCM_PCIE2REG_H2D_MAILBOX_0;

	sx_init(&mb->dcmd_sx, "brcm_pci_dcmd_sx");
	mtx_init(&mb->dcmd_mtx, "brcm_pci_dcmd_mtx", NULL, MTX_DEF);
	cv_init(&mb->dcmd_cv, "brcm_pci_dcmd_cv");
	mtx_init(&mb->flow_mtx, "brcm_pci_flow_mtx", NULL, MTX_DEF);
	cv_init(&mb->flow_cv, "brcm_pci_flow_cv");
	mtx_init(&mb->pktid_mtx, "brcm_pci_pktid_mtx", NULL, MTX_DEF);
	mtx_init(&mb->rxpost_mtx, "brcm_pci_rxpost_mtx", NULL, MTX_DEF);

	error = msgbuf_read_shared_info(mb);
	if (error != 0)
		goto fail;

	error = msgbuf_init_rings(mb);
	if (error != 0)
		goto fail;

	error = msgbuf_init_scratch(mb);
	if (error != 0)
		goto fail;

	/* IOCTL request buffer — host memory fw reads request payload from. */
	error = brcm_pci_msgbuf_dma_alloc(mb, &mb->ioctbuf,
	    BRCM_MSGBUF_MAX_CTL_PKT_SIZE, "ioctbuf");
	if (error != 0)
		goto fail;

	/*
	 * Event-buf coherent pool.  Sub-4GB physaddr guaranteed by the
	 * dma tag inside dma_alloc.  Persist for driver lifetime; fw
	 * writes here, we process, we re-post the same slot.
	 *
	 * Uses BRCM_MSGBUF_MAX_EVENTBUF_POST literal (not mb->max_eventbuf)
	 * because mb->max_eventbuf is set much later in this function.
	 * Allocating 0 bufs here silently made post_event_slot return
	 * ENOMEM for every slot → "posted 0/8" wall.
	 */
	{
		uint32_t i;
		for (i = 0; i < BRCM_MSGBUF_MAX_EVENTBUF_POST; i++) {
			error = brcm_pci_msgbuf_dma_alloc(mb,
			    &mb->eventbufs[i], BRCM_MSGBUF_MAX_CTL_PKT_SIZE,
			    "evtbuf");
			if (error != 0) {
				device_printf(DEV(mb),
				    "msgbuf: evtbuf[%u] alloc failed %d\n",
				    i, error);
				goto fail;
			}
		}
	}

	/* Deferred WL_EVENT dispatch queue. */
	mtx_init(&mb->event_q_mtx, "brcm_pci_evtq", NULL, MTX_DEF);
	STAILQ_INIT(&mb->event_q);
	TASK_INIT(&mb->event_task, 0, msgbuf_event_task, mb);

	/* Flowring array + pktid table. */
	mb->flowrings = malloc(mb->max_flowrings * sizeof(*mb->flowrings),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (mb->flowrings == NULL) {
		error = ENOMEM;
		goto fail;
	}
	mb->pktids = malloc(BRCM_MSGBUF_MAX_PKTID * sizeof(*mb->pktids),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (mb->pktids == NULL) {
		error = ENOMEM;
		goto fail;
	}
	mb->pktid_next_hint = 1;

	/*
	 * TX-mbuf DMA tag: maps single-frag Ethernet frames, host memory,
	 * 32-bit DMA (BCM43602 is 32-bit-only).  4 bytes alignment; max
	 * one segment for first-light (m_defrag before load).
	 */
	error = bus_dma_tag_create(bus_get_dma_tag(DEV(mb)),
	    /* alignment */ 4, /* boundary */ 0,
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    /* maxsize */ MCLBYTES, /* nsegments */ 1, /* maxsegsize */ MCLBYTES,
	    0, NULL, NULL, &mb->tx_mbuf_tag);
	if (error != 0) {
		device_printf(DEV(mb),
		    "msgbuf: tx_mbuf_tag create failed %d\n", error);
		goto fail;
	}

	/* RX-mbuf DMA tag: same constraints but max size = ctl pkt (8K). */
	error = bus_dma_tag_create(bus_get_dma_tag(DEV(mb)),
	    /* alignment */ 4, /* boundary */ 0,
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    /* maxsize */ BRCM_MSGBUF_MAX_CTL_PKT_SIZE, /* nsegments */ 1,
	    /* maxsegsize */ BRCM_MSGBUF_MAX_CTL_PKT_SIZE,
	    0, NULL, NULL, &mb->rx_mbuf_tag);
	if (error != 0) {
		device_printf(DEV(mb),
		    "msgbuf: rx_mbuf_tag create failed %d\n", error);
		goto fail;
	}

	/* RXPOST tracking table. */
	mb->rxposts = malloc(BRCM_MSGBUF_MAX_RXPOST * sizeof(*mb->rxposts),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (mb->rxposts == NULL) {
		error = ENOMEM;
		goto fail;
	}
	mb->rxpost_next_hint = 1;
	mb->max_eventbuf = BRCM_MSGBUF_MAX_EVENTBUF_POST;
	/* max_rxbufpost was already read from shared info; clamp to a
	 * reasonable working value for first light. */
	if (mb->max_rxbufpost > 128)
		mb->max_rxbufpost = 128;

	/*
	 * Mark attached BEFORE binding ISR — the ithread's re-arm branch
	 * checks mb->attached and skips if false (detach path).
	 */
	mb->attached = true;

	/*
	 * Clear stale MAILBOXINT bits from earlier boot.  W1C: write back
	 * only bits that are currently set.  Writing all-ones (0xffffffff)
	 * risks setting reserved bits on chips that aren't strict W1C
	 * -- suspected root cause of non-deterministic msgbuf_attach
	 * wedge.  Match the ISR's read-then-write pattern.
	 */
	pcie2_write32(mb, BRCM_PCIE2REG_MAILBOXMASK, 0);
	{
		uint32_t stale = pcie2_read32(mb, BRCM_PCIE2REG_MAILBOXINT);
		if (stale != 0 && stale != 0xffffffff)
			pcie2_write32(mb, BRCM_PCIE2REG_MAILBOXINT, stale);
	}

	error = brcm_pci_msgbuf_bind_intr(sc, brcm_pci_msgbuf_isr_filter,
	    brcm_pci_msgbuf_isr_thread, mb);
	if (error != 0) {
		mb->attached = false;
		goto fail;
	}

	/* Chip-side interrupt unmask. */
	pcie2_write32(mb, BRCM_PCIE2REG_MAILBOXMASK,
	    BRCM_PCIE_MB_INT_D2H_DB | BRCM_PCIE_MB_INT_FN0);

	/*
	 * Now that the ISR is armed, prime the RX pools.  Event bufs go
	 * on the ctrl ring (fw picks one per WL_EVENT); rxbufs go on the
	 * rxpost ring (fw picks one per incoming data frame).  Fw needs
	 * these to be posted BEFORE any event/data DMA can occur.
	 */
	{
		uint32_t posted;
		posted = msgbuf_post_event_bufs(mb, mb->max_eventbuf);
		MDPRINTF(mb, 0,
		    "msgbuf: posted %u/%u event buffers\n",
		    posted, mb->max_eventbuf);
		if (posted == 0) {
			/*
			 * Fw needs at least one WL_EVENT landing zone.  If
			 * we have zero, the FIRST DCMD trip triggers a
			 * hard-wedge (fw sends a spontaneous event, has
			 * nowhere to write it, host wedges on next MMIO).
			 * Fail cleanly rather than let caller fire DCMD.
			 */
			device_printf(DEV(mb),
			    "msgbuf: refusing attach: event-buf pool "
			    "empty.  Likely 8KB MJUM9BYTES cluster above "
			    "4GB with no bounce pages.  Retry (mbufs may "
			    "come from below-4GB pool), or fix by using "
			    "bus_dmamem_alloc for event bufs.\n");
			mb->attached = false;
			error = ENOMEM;
			goto fail;
		}
		posted = msgbuf_post_rx_bufs(mb, mb->max_rxbufpost);
		MDPRINTF(mb, 0,
		    "msgbuf: posted %u/%u rx data buffers\n",
		    posted, mb->max_rxbufpost);
	}

	device_printf(brcm_pci_msgbuf_dev(sc),
	    "msgbuf: attach OK — rings + scratch + ioctbuf + ISR bound\n");
	return (0);

fail:
	brcm_pci_msgbuf_detach(sc);
	return (error);
}

void
brcm_pci_msgbuf_detach(struct brcm_pci_softc *sc)
{
	struct brcm_pci_msgbuf *mb = brcm_pci_msgbuf_state(sc);
	bool was_attached;
	int i;

	if (mb == NULL)
		return;

	was_attached = mb->attached;

	/* Mask chip interrupt + tear down before touching softc DMA. */
	if (was_attached) {
		pcie2_write32(mb, BRCM_PCIE2REG_MAILBOXMASK, 0);
		mb->attached = false;
	}
	brcm_pci_msgbuf_unbind_intr(sc);

	/* Reclaim posted RX/event mbufs before killing rx_mbuf_tag. */
	if (mb->rxposts != NULL) {
		uint32_t k;
		for (k = 1; k < BRCM_MSGBUF_MAX_RXPOST; k++) {
			bus_dmamap_t map = NULL;
			uint8_t type = 0;
			struct mbuf *m = rxpost_release(mb, k, &map, &type);
			if (m != NULL) {
				if (map != NULL) {
					bus_dmamap_unload(mb->rx_mbuf_tag, map);
					bus_dmamap_destroy(mb->rx_mbuf_tag, map);
				}
				m_freem(m);
			}
		}
		free(mb->rxposts, M_DEVBUF);
		mb->rxposts = NULL;
	}
	if (mb->rx_mbuf_tag != NULL) {
		bus_dma_tag_destroy(mb->rx_mbuf_tag);
		mb->rx_mbuf_tag = NULL;
	}

	/* Reclaim in-flight TX mbufs first (before killing tx_mbuf_tag). */
	if (mb->pktids != NULL) {
		uint32_t k;
		for (k = 1; k < BRCM_MSGBUF_MAX_PKTID; k++) {
			bus_dmamap_t map = NULL;
			struct mbuf *m = pktid_release(mb, k, &map);
			if (m != NULL) {
				if (map != NULL) {
					bus_dmamap_unload(mb->tx_mbuf_tag, map);
					bus_dmamap_destroy(mb->tx_mbuf_tag, map);
				}
				m_freem(m);
			}
		}
		free(mb->pktids, M_DEVBUF);
		mb->pktids = NULL;
	}
	if (mb->tx_mbuf_tag != NULL) {
		bus_dma_tag_destroy(mb->tx_mbuf_tag);
		mb->tx_mbuf_tag = NULL;
	}

	/* Flowrings: free coherent buffers.  Fw retains ring state on
	 * chip until a FLOW_RING_DELETE, but for host teardown we just
	 * unpublish (tag=NULL) — chip will fault if it tries to DMA.
	 * Real teardown path (future): send DELETE_REQ before free. */
	if (mb->flowrings != NULL) {
		uint32_t k;
		for (k = 0; k < mb->max_flowrings; k++) {
			struct brcm_pci_ring *fring = &mb->flowrings[k].ring;
			if (fring->inited) {
				mtx_destroy(&fring->lock);
				fring->inited = false;
			}
			brcm_pci_msgbuf_dma_free(mb, &fring->buf);
		}
		free(mb->flowrings, M_DEVBUF);
		mb->flowrings = NULL;
	}

	for (i = 0; i < BRCM_NROF_COMMON_MSGRINGS; i++) {
		struct brcm_pci_ring *ring = &mb->rings[i];
		if (ring->inited) {
			mtx_destroy(&ring->lock);
			ring->inited = false;
		}
		brcm_pci_msgbuf_dma_free(mb, &ring->buf);
	}
	brcm_pci_msgbuf_dma_free(mb, &mb->scratch);
	brcm_pci_msgbuf_dma_free(mb, &mb->ringupd);
	brcm_pci_msgbuf_dma_free(mb, &mb->ioctbuf);
	{
		uint32_t i;
		for (i = 0; i < 8; i++)
			brcm_pci_msgbuf_dma_free(mb, &mb->eventbufs[i]);
	}

	if (was_attached) {
		struct brcm_pci_event *ep;

		/* Drain the event task first — it may hold event_q_mtx. */
		taskqueue_drain(taskqueue_thread, &mb->event_task);
		while ((ep = STAILQ_FIRST(&mb->event_q)) != NULL) {
			STAILQ_REMOVE_HEAD(&mb->event_q, link);
			free(ep, M_DEVBUF);
		}
		mtx_destroy(&mb->event_q_mtx);

		cv_destroy(&mb->flow_cv);
		mtx_destroy(&mb->flow_mtx);
		mtx_destroy(&mb->pktid_mtx);
		mtx_destroy(&mb->rxpost_mtx);
		cv_destroy(&mb->dcmd_cv);
		mtx_destroy(&mb->dcmd_mtx);
		sx_destroy(&mb->dcmd_sx);
	}
	mb->attached = false;
}
