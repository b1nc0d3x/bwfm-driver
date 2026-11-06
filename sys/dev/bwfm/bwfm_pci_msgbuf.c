/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom PCIe MSGBUF protocol implementation.  Native FreeBSD.
 *
 * Reads the shared structure the firmware leaves in chip RAM, sets up
 * the five common rings and the per-peer TX flowrings in coherent DMA
 * memory, and runs dcmds and iovars through IOCTLPTR requests on the
 * control-submit ring.  The interrupt path drains the control, TX and
 * RX completion rings, hands received frames and firmware events to
 * bwfm.c, and wakes waiting dcmds.  Ring indices are kept in chip RAM.
 *
 * The protocol follows Linux brcmfmac msgbuf.c and commonring.c
 * (Broadcom); the code was written for this driver.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/condvar.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/sbuf.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include <net/ethernet.h>

#include "bwfm_pci_msgbuf.h"

/* Set to keep packet buffers below 4 GB, bouncing as before. */
static int bwfm_pci_dma32 = 0;
TUNABLE_INT("hw.bwfm_pci.dma32", &bwfm_pci_dma32);
/* Host rx buffers kept posted to the firmware (at most 511). */
static int bwfm_pci_rxbufpost = 255;
TUNABLE_INT("hw.bwfm_pci.rxbufpost", &bwfm_pci_rxbufpost);
/* Rx buffers refilled per doorbell from the completion path. */
static int bwfm_pci_rxpost_batch = BWFM_MSGBUF_RXBUFPOST_THRESHOLD;
TUNABLE_INT("hw.bwfm_pci.rxpost_batch", &bwfm_pci_rxpost_batch);

/* Local shortcuts. */
#define	DEV(mb)		bwfm_pci_msgbuf_dev((mb)->sc)
/* Flowring status is read by transmit without flow_mtx. */
#define	FLOW_STATUS(fr)		((int)atomic_load_int((volatile u_int *)&(fr)->status))
#define	FLOW_STATUS_SET(fr, v)	\
	atomic_store_int((volatile u_int *)&(fr)->status, (v))
#define	MB_ATTACHED(mb)		atomic_load_bool(&(mb)->attached)
#define	DBG(mb)		bwfm_pci_msgbuf_debug((mb)->sc)
#define	BAR0T(mb)	bwfm_pci_msgbuf_bar0_tag((mb)->sc)
#define	BAR0H(mb)	bwfm_pci_msgbuf_bar0_handle((mb)->sc)
#define	BAR2T(mb)	bwfm_pci_msgbuf_bar2_tag((mb)->sc)
#define	BAR2H(mb)	bwfm_pci_msgbuf_bar2_handle((mb)->sc)

/*
 * Debug print, silent by default.  Gated on the shared sc_debug like
 * DPRINTF() in bwfmvar.h; level 0 fires when sc_debug > 0.
 */
#define	MDPRINTF(mb, level, ...)	do {				\
	if (DBG(mb) > (level))						\
		device_printf(DEV(mb), __VA_ARGS__);			\
} while (0)

#define	MSGBUF_IOCTL_RESP_TIMEOUT_MS	2000

/*
 * TCM (BAR2) accessors.  BAR2 maps TCM directly, so no window is needed.
 */
static inline uint16_t
tcm_read16(struct bwfm_pci_msgbuf *mb, uint32_t off)
{
	return (bus_space_read_2(BAR2T(mb), BAR2H(mb), off));
}

static inline uint32_t
tcm_read32(struct bwfm_pci_msgbuf *mb, uint32_t off)
{
	return (bus_space_read_4(BAR2T(mb), BAR2H(mb), off));
}

static inline void
tcm_write16(struct bwfm_pci_msgbuf *mb, uint32_t off, uint16_t val)
{
	bus_space_write_2(BAR2T(mb), BAR2H(mb), off, val);
}

static inline void
tcm_write32(struct bwfm_pci_msgbuf *mb, uint32_t off, uint32_t val)
{
	bus_space_write_4(BAR2T(mb), BAR2H(mb), off, val);
}

/*
 * PCIe2 core register accessors.  These point the BAR0 window at the
 * PCIe2 core first.  There is no explicit window lock: if_bwfm_pci
 * serializes its own window users, and msgbuf has a single caller.
 */
static inline uint32_t
pcie2_read32(struct bwfm_pci_msgbuf *mb, uint32_t off)
{
	bwfm_pci_msgbuf_set_window(mb->sc, mb->pcie2_base);
	return (bus_space_read_4(BAR0T(mb), BAR0H(mb), off));
}

static inline void
pcie2_write32(struct bwfm_pci_msgbuf *mb, uint32_t off, uint32_t val)
{
	bwfm_pci_msgbuf_set_window(mb->sc, mb->pcie2_base);
	bus_space_write_4(BAR0T(mb), BAR0H(mb), off, val);
}

/*
 * Coherent DMA buffer helpers.  Each buffer is a single aligned segment
 * visible to both the CPU and the device.
 */
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
bwfm_pci_msgbuf_dma_alloc(struct bwfm_pci_msgbuf *mb,
    struct bwfm_pci_dma_buf *buf, size_t size, const char *tag)
{
	int error;

	buf->size = size;
	error = bus_dma_tag_create(bus_get_dma_tag(DEV(mb)),
	    /* alignment */ 8, /* boundary */ 0,
	    BUS_SPACE_MAXADDR_32BIT, /* keep host addresses below 4G, so
					the hi word fw sees is always 0 */
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
bwfm_pci_msgbuf_dma_free(struct bwfm_pci_msgbuf *mb __unused,
    struct bwfm_pci_dma_buf *buf)
{
	if (buf->tag == NULL)
		return;
	if (buf->paddr != 0) {
		bus_dmamap_unload(buf->tag, buf->map);
		buf->paddr = 0;
	}
	if (buf->vaddr != NULL) {
		/*
		 * ioctbuf and the rings can hold keys.  Callers stop bus
		 * mastering first, so the firmware cannot write it again.
		 */
		explicit_bzero(buf->vaddr, buf->size);
		bus_dmamem_free(buf->tag, buf->vaddr, buf->map);
		buf->vaddr = NULL;
	}
	bus_dma_tag_destroy(buf->tag);
	buf->tag = NULL;
}

/*
 * Common ring mechanics.  Each ring has its own MTX_DEF mutex.
 */
static void
ring_config(struct bwfm_pci_ring *ring, uint16_t depth, uint16_t item_len,
    struct bwfm_pci_msgbuf *mb, const char *name)
{
	if (!ring->inited) {
		mtx_init(&ring->lock, name, NULL, MTX_DEF);
		ring->inited = true;
	}
	/* A reused flowring can have a sender in ring_reserve_for_write. */
	mtx_lock(&ring->lock);
	ring->depth = depth;
	ring->item_len = item_len;
	ring->mb = mb;
	ring->r_ptr = 0;
	ring->w_ptr = 0;
	ring->f_ptr = 0;
	ring->was_full = false;
	mtx_unlock(&ring->lock);
}

/* Publish our w_ptr (producer) to fw via the 16-bit TCM index. */
static void
ring_publish_wptr(struct bwfm_pci_ring *ring)
{
	tcm_write16(ring->mb, ring->w_idx_addr, ring->w_ptr);
}

/* Publish our r_ptr (consumer) to fw via TCM index. */
static void
ring_publish_rptr(struct bwfm_pci_ring *ring)
{
	tcm_write16(ring->mb, ring->r_idx_addr, ring->r_ptr);
}

/* Ignore a firmware ring index that is out of range. */
static void
ring_bad_index(struct bwfm_pci_ring *ring, const char *which, uint16_t v)
{
	if (ppsratecheck(&ring->mb->bad_idx_last, &ring->mb->bad_idx_pps, 1))
		device_printf(DEV(ring->mb),
		    "msgbuf: ring %u: firmware %s index %u >= depth %u\n",
		    ring->id, which, v, ring->depth);
}

/* Pull fw's current w_ptr for a D2H ring (fw is producer). */
static void
ring_pull_wptr_from_fw(struct bwfm_pci_ring *ring)
{
	uint16_t v = tcm_read16(ring->mb, ring->w_idx_addr);

	if (v >= ring->depth) {
		ring_bad_index(ring, "write", v);
		return;
	}
	ring->w_ptr = v;
}

/* Pull fw's current r_ptr for an H2D ring (fw is consumer). */
static void
ring_pull_rptr_from_fw(struct bwfm_pci_ring *ring)
{
	uint16_t v = tcm_read16(ring->mb, ring->r_idx_addr);

	if (v >= ring->depth) {
		ring_bad_index(ring, "read", v);
		return;
	}
	ring->r_ptr = v;
}

/* Ring indices for the rings sysctl; no ring lock, so a stuck lock can't hang it. */
static void
ring_dump_one(struct bwfm_pci_ring *ring, struct sbuf *sb, const char *name)
{
	sbuf_printf(sb, "%-10s id=%-3u depth=%-4u host r=%-4u w=%-4u f=%-4u "
	    "fw r=%-4u w=%-4u%s\n", name, ring->id, ring->depth, ring->r_ptr,
	    ring->w_ptr, ring->f_ptr, tcm_read16(ring->mb, ring->r_idx_addr),
	    tcm_read16(ring->mb, ring->w_idx_addr),
	    ring->was_full ? " was_full" : "");
}

void
bwfm_pci_msgbuf_ring_dump(struct bwfm_pci_msgbuf *mb, struct sbuf *sb)
{
	static const char *names[BWFM_NROF_COMMON_MSGRINGS] = {
		"ctrl_sub", "rxpost", "ctrl_cmpl", "tx_cmpl", "rx_cmpl" };
	struct bwfm_pci_flowring *fr;
	u_int i;

	if (!MB_ATTACHED(mb)) {
		sbuf_printf(sb, "msgbuf not attached\n");
		return;
	}
	sbuf_printf(sb, "rxbufpost %u/%u eventbuf %u/%u\n", mb->cur_rxbufpost,
	    mb->max_rxbufpost, mb->cur_eventbuf, mb->max_eventbuf);
	for (i = 0; i < BWFM_NROF_COMMON_MSGRINGS; i++)
		ring_dump_one(&mb->rings[i], sb, names[i]);
	for (i = 0; mb->flowrings != NULL && i < mb->max_flowrings; i++) {
		fr = &mb->flowrings[i];
		if (FLOW_STATUS(fr) == BWFM_FLOW_CLOSED)
			continue;
		sbuf_printf(sb, "flow %-5u status=%d prio=%u ", i, FLOW_STATUS(fr),
		    fr->prio);
		ring_dump_one(&fr->ring, sb, "");
	}
}

/* Ring the doorbell: a write to H2D_MAILBOX_0 kicks fw. */
static void
ring_bell(struct bwfm_pci_ring *ring)
{
	pcie2_write32(ring->mb, BWFM_PCIE2REG_H2D_MAILBOX_0, 1);
}

static void *
ring_reserve_for_write(struct bwfm_pci_ring *ring)
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
		ret = (uint8_t *)ring->buf.vaddr +
		    (size_t)ring->w_ptr * ring->item_len;
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
ring_write_complete(struct bwfm_pci_ring *ring)
{
	if (ring->f_ptr > ring->w_ptr)
		ring->f_ptr = 0;
	ring->f_ptr = ring->w_ptr;
	ring_publish_wptr(ring);
	ring_bell(ring);
	return (0);
}

static void *
ring_get_read_ptr(struct bwfm_pci_ring *ring, uint16_t *n_items)
{
	ring_pull_wptr_from_fw(ring);
	if (ring->w_ptr >= ring->r_ptr)
		*n_items = ring->w_ptr - ring->r_ptr;
	else
		*n_items = ring->depth - ring->r_ptr;
	if (*n_items == 0)
		return (NULL);
	return ((uint8_t *)ring->buf.vaddr +
	    (size_t)ring->r_ptr * ring->item_len);
}

static void
ring_read_complete(struct bwfm_pci_ring *ring, uint16_t n_items)
{
	ring->r_ptr += n_items;
	if (ring->r_ptr == ring->depth)
		ring->r_ptr = 0;
	ring_publish_rptr(ring);
}

/*
 * Shared-info reader.
 *
 * After boot, fw writes sharedram_addr at BAR2[rambase + ramsize - 4].
 * It is a raw TCM offset and should fall inside [rambase,
 * rambase + ramsize).  A value outside that range is logged rather
 * than silently rejected, which helps diagnose half-booted fw.
 */
/* True when [addr, addr + len) lies inside the chip's RAM in TCM. */
bool
bwfm_pci_msgbuf_tcm_ok(struct bwfm_pci_msgbuf *mb, uint32_t addr,
    uint32_t len)
{
	uint64_t base, end;

	base = bwfm_pci_msgbuf_rambase(mb->sc);
	end = base + bwfm_pci_msgbuf_ramsize(mb->sc);
	return (addr >= base && (uint64_t)addr + len <= end);
}

static int
msgbuf_read_shared_info(struct bwfm_pci_msgbuf *mb)
{
	uint32_t rambase, ramsize, off, shared_addr, flags;

	rambase = bwfm_pci_msgbuf_rambase(mb->sc);
	ramsize = bwfm_pci_msgbuf_ramsize(mb->sc);
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
		 * sharedram pointer with high bits (e.g. 0xc0).  Try the
		 * low 24 bits, and accept them only if the version field
		 * there is in the supported range 5..7.
		 */
		if (candidate >= rambase && candidate < rambase + ramsize) {
			uint32_t f = tcm_read32(mb,
			    candidate + BWFM_SHARED_FLAGS_OFFSET);
			uint8_t v = f & BWFM_PCIE_SHARED_VERSION_MASK;

			MDPRINTF(mb, 0,
			    "msgbuf: try masked 0x%x — flags=0x%08x v=%u\n",
			    candidate, f, v);
			if (v >= BWFM_PCIE_MIN_SHARED_VERSION &&
			    v <= BWFM_PCIE_MAX_SHARED_VERSION) {
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
	if (!bwfm_pci_msgbuf_tcm_ok(mb, shared_addr,
	    BWFM_SHARED_DMA_RINGUPD_ADDR_OFFSET + 8)) {
		device_printf(DEV(mb),
		    "msgbuf: shared area at 0x%x runs past RAM\n",
		    shared_addr);
		return (EINVAL);
	}

	mb->shared_addr = shared_addr;
	flags = tcm_read32(mb, shared_addr + BWFM_SHARED_FLAGS_OFFSET);
	mb->shared_flags = flags;
	mb->shared_version = flags & BWFM_PCIE_SHARED_VERSION_MASK;
	MDPRINTF(mb, 0,
	    "msgbuf: shared v=%u flags=0x%08x dma_idx=%d hostrdy_db1=%d\n",
	    mb->shared_version, flags,
	    !!(flags & BWFM_PCIE_SHARED_DMA_INDEX),
	    !!(flags & BWFM_PCIE_SHARED_HOSTRDY_DB1));

	if (mb->shared_version < BWFM_PCIE_MIN_SHARED_VERSION ||
	    mb->shared_version > BWFM_PCIE_MAX_SHARED_VERSION) {
		device_printf(DEV(mb),
		    "msgbuf: unsupported shared version %u\n",
		    mb->shared_version);
		return (EPROTONOSUPPORT);
	}

	mb->max_rxbufpost = tcm_read16(mb,
	    shared_addr + BWFM_SHARED_MAX_RXBUFPOST_OFFSET);
	mb->rx_dataoffset = tcm_read32(mb,
	    shared_addr + BWFM_SHARED_RX_DATAOFFSET_OFFSET);
	mb->htod_mb_data_addr = tcm_read32(mb,
	    shared_addr + BWFM_SHARED_HTOD_MB_DATA_ADDR_OFFSET);
	mb->dtoh_mb_data_addr = tcm_read32(mb,
	    shared_addr + BWFM_SHARED_DTOH_MB_DATA_ADDR_OFFSET);
	mb->ring_info_addr = tcm_read32(mb,
	    shared_addr + BWFM_SHARED_RING_INFO_ADDR_OFFSET);
	mb->console_addr = tcm_read32(mb,
	    shared_addr + BWFM_SHARED_CONSOLE_ADDR_OFFSET);

	if (!bwfm_pci_msgbuf_tcm_ok(mb, mb->ring_info_addr,
	    BWFM_RINGINFO_MAX_COMPLETIONRINGS_OFFSET + 2) ||
	    (mb->htod_mb_data_addr != 0 &&
	    !bwfm_pci_msgbuf_tcm_ok(mb, mb->htod_mb_data_addr, 4)) ||
	    (mb->dtoh_mb_data_addr != 0 &&
	    !bwfm_pci_msgbuf_tcm_ok(mb, mb->dtoh_mb_data_addr, 4))) {
		device_printf(DEV(mb),
		    "msgbuf: shared area points outside RAM (ringinfo 0x%x "
		    "htod 0x%x dtoh 0x%x)\n", mb->ring_info_addr,
		    mb->htod_mb_data_addr, mb->dtoh_mb_data_addr);
		return (EINVAL);
	}
	/* The console is only for debugging; lose it rather than fail. */
	if (mb->console_addr != 0 &&
	    !bwfm_pci_msgbuf_tcm_ok(mb, mb->console_addr, 20))
		mb->console_addr = 0;

	MDPRINTF(mb, 0,
	    "msgbuf: max_rxbufpost=%u rx_dataoff=0x%x ringinfo=0x%x console=0x%x\n",
	    mb->max_rxbufpost, mb->rx_dataoffset, mb->ring_info_addr,
	    mb->console_addr);
	MDPRINTF(mb, 0,
	    "msgbuf: htod_mb_data=0x%x dtoh_mb_data=0x%x\n",
	    mb->htod_mb_data_addr, mb->dtoh_mb_data_addr);
	return (0);
}

/*
 * Ring buffer and index setup.
 *
 * Allocates the five common rings as coherent buffers and publishes
 * their DMA addresses into fw's ringmem slots.
 */
static const uint32_t bwfm_ring_max_item[BWFM_NROF_COMMON_MSGRINGS] = {
	BWFM_H2D_CONTROL_SUBMIT_MAX_ITEM,
	BWFM_H2D_RXPOST_SUBMIT_MAX_ITEM,
	BWFM_D2H_CONTROL_COMPLETE_MAX_ITEM,
	BWFM_D2H_TX_COMPLETE_MAX_ITEM,
	BWFM_D2H_RX_COMPLETE_MAX_ITEM,
};
static const uint32_t bwfm_ring_itemsize_pre_v7[BWFM_NROF_COMMON_MSGRINGS] = {
	BWFM_H2D_CONTROL_SUBMIT_ITEMSIZE,
	BWFM_H2D_RXPOST_SUBMIT_ITEMSIZE,
	BWFM_D2H_CONTROL_COMPLETE_ITEMSIZE,
	BWFM_D2H_TX_COMPLETE_ITEMSIZE_PRE_V7,
	BWFM_D2H_RX_COMPLETE_ITEMSIZE_PRE_V7,
};
static const uint32_t bwfm_ring_itemsize_v7[BWFM_NROF_COMMON_MSGRINGS] = {
	BWFM_H2D_CONTROL_SUBMIT_ITEMSIZE,
	BWFM_H2D_RXPOST_SUBMIT_ITEMSIZE,
	BWFM_D2H_CONTROL_COMPLETE_ITEMSIZE,
	BWFM_D2H_TX_COMPLETE_ITEMSIZE,
	BWFM_D2H_RX_COMPLETE_ITEMSIZE,
};

static int
msgbuf_init_rings(struct bwfm_pci_msgbuf *mb)
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
		    BWFM_RINGINFO_MAX_SUBMISSIONRINGS_OFFSET);
		max_flow = tcm_read16(mb, rinfo +
		    BWFM_RINGINFO_MAX_FLOWRINGS_OFFSET);
		max_cmp = tcm_read16(mb, rinfo +
		    BWFM_RINGINFO_MAX_COMPLETIONRINGS_OFFSET);
	} else {
		max_sub = tcm_read16(mb, rinfo +
		    BWFM_RINGINFO_MAX_FLOWRINGS_OFFSET);
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
	d2h_w = tcm_read32(mb, rinfo + BWFM_RINGINFO_D2H_W_IDX_PTR_OFFSET);
	d2h_r = tcm_read32(mb, rinfo + BWFM_RINGINFO_D2H_R_IDX_PTR_OFFSET);
	h2d_w = tcm_read32(mb, rinfo + BWFM_RINGINFO_H2D_W_IDX_PTR_OFFSET);
	h2d_r = tcm_read32(mb, rinfo + BWFM_RINGINFO_H2D_R_IDX_PTR_OFFSET);
	ring_mem_ptr = tcm_read32(mb, rinfo + BWFM_RINGINFO_RINGMEM_OFFSET);

	MDPRINTF(mb, 0,
	    "msgbuf: max_sub=%u max_flow=%u max_cmp=%u ringmem=0x%x\n",
	    max_sub, max_flow, max_cmp, ring_mem_ptr);

	/*
	 * Every index slot and ringmem slot we will touch, common rings
	 * and flowrings both, has to sit in RAM.
	 */
	if (!bwfm_pci_msgbuf_tcm_ok(mb, h2d_w, (2 + max_flow) * 4) ||
	    !bwfm_pci_msgbuf_tcm_ok(mb, h2d_r, (2 + max_flow) * 4) ||
	    !bwfm_pci_msgbuf_tcm_ok(mb, d2h_w, 3 * 4) ||
	    !bwfm_pci_msgbuf_tcm_ok(mb, d2h_r, 3 * 4) ||
	    !bwfm_pci_msgbuf_tcm_ok(mb, ring_mem_ptr,
	    (BWFM_NROF_COMMON_MSGRINGS + max_flow) * BWFM_RING_MEM_SZ)) {
		device_printf(DEV(mb),
		    "msgbuf: ring info points outside RAM (h2d_w 0x%x "
		    "h2d_r 0x%x d2h_w 0x%x d2h_r 0x%x ringmem 0x%x)\n",
		    h2d_w, h2d_r, d2h_w, d2h_r, ring_mem_ptr);
		return (EIO);
	}
	MDPRINTF(mb, 0,
	    "msgbuf: h2d_w=0x%x h2d_r=0x%x d2h_w=0x%x d2h_r=0x%x\n",
	    h2d_w, h2d_r, d2h_w, d2h_r);

	itemsize = (mb->shared_version >= 7) ? bwfm_ring_itemsize_v7 :
	    bwfm_ring_itemsize_pre_v7;

	mb->ringmem_base = ring_mem_ptr;

	/* Two H2D rings first, then three D2H rings. */
	for (i = 0; i < BWFM_NROF_COMMON_MSGRINGS; i++) {
		struct bwfm_pci_ring *ring = &mb->rings[i];
		size_t sz = (size_t)bwfm_ring_max_item[i] * itemsize[i];
		bus_addr_t pa;

		error = bwfm_pci_msgbuf_dma_alloc(mb, &ring->buf, sz, "ring");
		if (error != 0)
			return (error);
		pa = ring->buf.paddr;

		/*
		 * Write the ring's DMA address, item count and item size
		 * into its ringmem slot.
		 */
		tcm_write32(mb, ring_mem_ptr + BWFM_RING_MEM_BASE_ADDR_OFFSET,
		    (uint32_t)(pa & 0xffffffff));
		tcm_write32(mb,
		    ring_mem_ptr + BWFM_RING_MEM_BASE_ADDR_OFFSET + 4,
		    (uint32_t)((uint64_t)pa >> 32));
		tcm_write16(mb, ring_mem_ptr + BWFM_RING_MAX_ITEM_OFFSET,
		    bwfm_ring_max_item[i]);
		tcm_write16(mb, ring_mem_ptr + BWFM_RING_LEN_ITEMS_OFFSET,
		    itemsize[i]);

		/* One WITNESS class per direction, since d2h nests over h2d. */
		ring_config(ring, bwfm_ring_max_item[i], itemsize[i], mb,
		    i < 2 ? "bwfm_pci_h2d" : "bwfm_pci_d2h");
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
		ring_mem_ptr += BWFM_RING_MEM_SZ;

		/* Zero the TCM indices; fw does this at boot, but be safe. */
		tcm_write16(mb, ring->w_idx_addr, 0);
		tcm_write16(mb, ring->r_idx_addr, 0);

		MDPRINTF(mb, 0,
		    "msgbuf: ring[%d] items=%u itemsize=%u pa=0x%jx "
		    "w_idx=0x%x r_idx=0x%x\n", i,
		    bwfm_ring_max_item[i], itemsize[i], (uintmax_t)pa,
		    ring->w_idx_addr, ring->r_idx_addr);
	}

	/*
	 * h2d_w/h2d_r now point at the first H2D index slot after the two
	 * common H2D rings, i.e. flowring 0.  ring_mem_ptr likewise points
	 * past the five common ring slots.
	 */
	mb->flow_h2d_w_next = h2d_w;
	mb->flow_h2d_r_next = h2d_r;
	mb->flow_ringmem_next = ring_mem_ptr;

	return (0);
}

/*
 * Scratch and ringupd: small coherent buffers fw uses for D2H scratch
 * space and ring update deltas.  A synchronous DCMD does not strictly
 * need them, but some fw versions assert if scratch is missing, and
 * they are cheap.
 */
#define	BWFM_D2H_SCRATCH_BUF_LEN	8
#define	BWFM_D2H_RINGUPD_BUF_LEN	1024

static int
msgbuf_init_scratch(struct bwfm_pci_msgbuf *mb)
{
	uint32_t base, addr;
	int error;

	base = mb->shared_addr;

	error = bwfm_pci_msgbuf_dma_alloc(mb, &mb->scratch,
	    BWFM_D2H_SCRATCH_BUF_LEN, "scratch");
	if (error != 0)
		return (error);
	addr = base + BWFM_SHARED_DMA_SCRATCH_ADDR_OFFSET;
	tcm_write32(mb, addr,
	    (uint32_t)(mb->scratch.paddr & 0xffffffff));
	tcm_write32(mb, addr + 4,
	    (uint32_t)((uint64_t)mb->scratch.paddr >> 32));
	tcm_write32(mb, base + BWFM_SHARED_DMA_SCRATCH_LEN_OFFSET,
	    BWFM_D2H_SCRATCH_BUF_LEN);

	error = bwfm_pci_msgbuf_dma_alloc(mb, &mb->ringupd,
	    BWFM_D2H_RINGUPD_BUF_LEN, "ringupd");
	if (error != 0)
		return (error);
	addr = base + BWFM_SHARED_DMA_RINGUPD_ADDR_OFFSET;
	tcm_write32(mb, addr,
	    (uint32_t)(mb->ringupd.paddr & 0xffffffff));
	tcm_write32(mb, addr + 4,
	    (uint32_t)((uint64_t)mb->ringupd.paddr >> 32));
	tcm_write32(mb, base + BWFM_SHARED_DMA_RINGUPD_LEN_OFFSET,
	    BWFM_D2H_RINGUPD_BUF_LEN);

	MDPRINTF(mb, 0,
	    "msgbuf: scratch pa=0x%jx ringupd pa=0x%jx (published)\n",
	    (uintmax_t)mb->scratch.paddr, (uintmax_t)mb->ringupd.paddr);
	return (0);
}

/*
 * Post one IOCTLRESP_BUF into the H2D control ring so fw has somewhere
 * to write the DCMD reply.  mb->ioctbuf is the response buffer; only
 * one DCMD is outstanding at a time, so the same 8KB coherent slot is
 * reused.
 */
static int
msgbuf_post_ioctlresp(struct bwfm_pci_msgbuf *mb)
{
	struct bwfm_pci_ring *ring;
	struct msgbuf_rx_ioctl_resp_or_event *post;
	uint64_t paddr;

	ring = &mb->rings[BWFM_H2D_MSGRING_CONTROL_SUBMIT];
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
	post->msg.msgtype = BWFM_MSGBUF_TYPE_IOCTLRESP_BUF_POST;
	post->msg.ifidx = 0;
	post->msg.flags = 0;
	post->msg.request_id = htole32(BWFM_IOCTL_REQ_PKTID);
	post->host_buf_len = htole16(BWFM_MSGBUF_MAX_CTL_PKT_SIZE);
	paddr = (uint64_t)mb->ioctbuf.paddr;
	post->host_buf_addr.low_addr = htole32((uint32_t)(paddr & 0xffffffff));
	post->host_buf_addr.high_addr = htole32((uint32_t)(paddr >> 32));

	ring_write_complete(ring);
	mtx_unlock(&ring->lock);
	return (0);
}

/*
 * pktid table: tracks outstanding TX mbufs so they can be freed when fw
 * acks them with TX_STATUS.  A linear scan from a hint is O(N) worst
 * case, but N is 1024 and fw bounds the TX rate.  Slot 0 is reserved
 * (request_id 0 means "no id").
 */
static int
pktid_alloc(struct bwfm_pci_msgbuf *mb, struct mbuf *m, uint16_t flowid,
    bool is_eapol, uint16_t datalen, uint32_t *idx_out)
{
	uint32_t i, start;

	mtx_lock(&mb->pktid_mtx);
	start = mb->pktid_next_hint;
	if (start == 0)
		start = 1;
	for (i = 0; i < BWFM_MSGBUF_MAX_PKTID; i++) {
		uint32_t j = start + i;
		if (j >= BWFM_MSGBUF_MAX_PKTID)
			j -= (BWFM_MSGBUF_MAX_PKTID - 1);
		if (j == 0)
			j = 1;
		if (!mb->pktids[j].inuse) {
			/* Fill the whole slot before dropping the lock. */
			mb->pktids[j].inuse = true;
			mb->pktids[j].posted = false;
			mb->pktids[j].m = m;
			mb->pktids[j].datalen = datalen;
			mb->pktids[j].flowid = flowid;
			mb->pktids[j].is_eapol = is_eapol;
			if (is_eapol)
				mb->pending_eapol++;
			mb->pktid_next_hint = j + 1;
			if (mb->pktid_next_hint >= BWFM_MSGBUF_MAX_PKTID)
				mb->pktid_next_hint = 1;
			mtx_unlock(&mb->pktid_mtx);
			*idx_out = j;
			return (0);
		}
	}
	mtx_unlock(&mb->pktid_mtx);
	return (ENOSPC);
}

/* The firmware owns the slot from here; TX_STATUS may release it. */
static void
pktid_mark_posted(struct bwfm_pci_msgbuf *mb, uint32_t idx)
{
	mtx_lock(&mb->pktid_mtx);
	mb->pktids[idx].posted = true;
	mtx_unlock(&mb->pktid_mtx);
}

/* Release a slot.  With fw_done, only a slot the firmware holds. */
static struct mbuf *
pktid_release(struct bwfm_pci_msgbuf *mb, uint32_t idx,
    bus_dmamap_t *map_out, bool fw_done)
{
	struct mbuf *m;
	bool was_eapol;

	if (idx == 0 || idx >= BWFM_MSGBUF_MAX_PKTID)
		return (NULL);
	mtx_lock(&mb->pktid_mtx);
	if (!mb->pktids[idx].inuse ||
	    (fw_done && !mb->pktids[idx].posted)) {
		mtx_unlock(&mb->pktid_mtx);
		return (NULL);
	}
	m = mb->pktids[idx].m;
	if (map_out != NULL)
		*map_out = mb->pktids[idx].map;
	was_eapol = mb->pktids[idx].is_eapol;
	mb->pktids[idx].m = NULL;
	mb->pktids[idx].datalen = 0;
	mb->pktids[idx].flowid = 0;
	mb->pktids[idx].is_eapol = false;
	mb->pktids[idx].posted = false;
	mb->pktids[idx].inuse = false;
	if (was_eapol) {
		if (mb->pending_eapol > 0)
			mb->pending_eapol--;
		if (mb->pending_eapol == 0)
			cv_broadcast(&mb->pending_eapol_cv);
	}
	mtx_unlock(&mb->pktid_mtx);
	return (m);
}

/*
 * RXPOST table: like the pktid table, but for host mbufs posted to fw
 * as RX, event or ioctl-response buffers.  Fw echoes the pktid in the
 * RX_CMPLT or WL_EVENT descriptor so the buffer can be found.
 */
static int
rxpost_alloc(struct bwfm_pci_msgbuf *mb, struct mbuf *m, uint8_t type,
    uint32_t *idx_out)
{
	uint32_t i, start;

	mtx_lock(&mb->rxpost_mtx);
	start = mb->rxpost_next_hint;
	if (start == 0)
		start = 1;
	for (i = 0; i < BWFM_MSGBUF_MAX_RXPOST; i++) {
		uint32_t j = start + i;
		if (j >= BWFM_MSGBUF_MAX_RXPOST)
			j -= (BWFM_MSGBUF_MAX_RXPOST - 1);
		if (j == 0)
			j = 1;
		if (mb->rxposts[j].type == BWFM_RXPOST_UNUSED) {
			mb->rxposts[j].type = type;
			mb->rxposts[j].m = m;
			mb->rxpost_next_hint = j + 1;
			if (mb->rxpost_next_hint >= BWFM_MSGBUF_MAX_RXPOST)
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
rxpost_release(struct bwfm_pci_msgbuf *mb, uint32_t idx,
    bus_dmamap_t *map_out, uint8_t *type_out)
{
	struct mbuf *m;

	if (idx == 0 || idx >= BWFM_MSGBUF_MAX_RXPOST)
		return (NULL);
	mtx_lock(&mb->rxpost_mtx);
	if (mb->rxposts[idx].type == BWFM_RXPOST_UNUSED) {
		mtx_unlock(&mb->rxpost_mtx);
		return (NULL);
	}
	m = mb->rxposts[idx].m;
	if (map_out != NULL)
		*map_out = mb->rxposts[idx].map;
	if (type_out != NULL)
		*type_out = mb->rxposts[idx].type;
	mb->rxposts[idx].m = NULL;
	mb->rxposts[idx].buflen = 0;
	mb->rxposts[idx].type = BWFM_RXPOST_UNUSED;
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
 * Event buffer pktids.  Fw returns the pktid in WL_EVENT.request_id so
 * the source buffer can be found.  Event buffers use their own pktid
 * range, tagged in the high bits with the slot index in the low byte,
 * so it never overlaps the small data rxpost pktids and lookup is O(1).
 */
#define	BWFM_EVENTBUF_PKTID_BASE	0xE0000000u
#define	BWFM_EVENTBUF_PKTID(slot)	(BWFM_EVENTBUF_PKTID_BASE | (slot))
#define	BWFM_EVENTBUF_IS_EVENT(pktid)	\
	(((pktid) & 0xFFFFFF00u) == BWFM_EVENTBUF_PKTID_BASE)
#define	BWFM_EVENTBUF_PKTID_SLOT(pktid)	((pktid) & 0xFFu)

/*
 * Post one preallocated coherent event buffer, mb->eventbufs[slot], to
 * the H2D control ring.  Called at attach and after each WL_EVENT to
 * refill the slot.  No mbuf or rxpost entry is involved, and the DMA
 * tag's lowaddr keeps the buffer below 4GB.
 */
static int
msgbuf_post_event_slot(struct bwfm_pci_msgbuf *mb, uint32_t slot)
{
	struct bwfm_pci_ring *ring;
	struct bwfm_pci_dma_buf *evb;
	struct msgbuf_rx_ioctl_resp_or_event *post;

	if (slot >= mb->max_eventbuf)
		return (EINVAL);
	evb = &mb->eventbufs[slot];
	if (evb->vaddr == NULL || evb->paddr == 0)
		return (ENOMEM);

	ring = &mb->rings[BWFM_H2D_MSGRING_CONTROL_SUBMIT];

	/* Zero the buffer so fw sees clean state, then sync. */
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
	post->msg.msgtype = BWFM_MSGBUF_TYPE_EVENT_BUF_POST;
	post->msg.ifidx = 0;
	post->msg.request_id = htole32(BWFM_EVENTBUF_PKTID(slot));
	post->host_buf_len = htole16((uint16_t)evb->size);
	post->host_buf_addr.low_addr = htole32((uint32_t)(evb->paddr & 0xffffffff));
	post->host_buf_addr.high_addr = htole32((uint32_t)((uint64_t)evb->paddr >> 32));
	ring_write_complete(ring);
	mtx_unlock(&ring->lock);
	return (0);
}

/*
 * Post one host mbuf as an RX data buffer (RXBUF_POST on
 * H2D_RXPOST_SUBMIT).  Event buffers go through msgbuf_post_event_slot
 * instead.  The doorbell is rung for every post.  Returns 0 on success.
 */
static int
msgbuf_post_one_rxbuf(struct bwfm_pci_msgbuf *mb, uint8_t type)
{
	struct mbuf *m;
	struct bwfm_pci_ring *ring;
	bus_dmamap_t map = NULL;
	uint64_t pa;
	uint32_t pktid;
	size_t bufsize;
	uint8_t msgtype;
	int error;

	if (type == BWFM_RXPOST_EVENT) {
		/*
		 * Events use the coherent pool via msgbuf_post_event_slot.
		 * Refuse the mbuf path so an mbuf above 4GB can never be
		 * handed to fw as a bad pointer.
		 */
		return (EINVAL);
	} else if (type == BWFM_RXPOST_DATA) {
		bufsize = BWFM_MSGBUF_MAX_PKT_SIZE;
		msgtype = BWFM_MSGBUF_TYPE_RXBUF_POST;
		ring = &mb->rings[BWFM_H2D_MSGRING_RXPOST_SUBMIT];
	} else {
		return (EINVAL);
	}

	/*
	 * m_getjcl's size must be one of the exact cluster sizes:
	 * MCLBYTES (2K), MJUMPAGESIZE (PAGE_SIZE), MJUM9BYTES (9K) or
	 * MJUM16BYTES (16K).  Round bufsize up to the smallest cluster
	 * that fits; otherwise the mbuf is short and bus_dmamap_load
	 * walks past the allocation.
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
		/* Out of mbufs; the refill retry callout tries again. */
		return (ENOMEM);
	}
	m->m_len = m->m_pkthdr.len = bufsize;

	error = rxpost_alloc(mb, m, type, &pktid);
	if (error != 0) {
		if (ppsratecheck(&mb->rxpost_err_last, &mb->rxpost_err_pps, 1))
			device_printf(DEV(mb),
			    "msgbuf: post_one_rxbuf(type=%u): rxpost_alloc failed %d\n",
			    type, error);
		m_freem(m);
		return (error);
	}
	/* The slot owns its map for life; only the owner loads it. */
	map = mb->rxposts[pktid].map;
	pa = 0;
	error = bus_dmamap_load(mb->rx_mbuf_tag, map, mtod(m, void *), bufsize,
	    rxbuf_load_cb, &pa, BUS_DMA_NOWAIT);
	if (error != 0 || pa == 0) {
		if (ppsratecheck(&mb->rxpost_err_last, &mb->rxpost_err_pps, 1))
			device_printf(DEV(mb),
			    "msgbuf: post_one_rxbuf(type=%u): dmamap_load err=%d pa=0x%llx bufsize=%zu\n",
			    type, error, (unsigned long long)pa, bufsize);
		if (error == 0)
			bus_dmamap_unload(mb->rx_mbuf_tag, map);
		(void)rxpost_release(mb, pktid, NULL, NULL);
		m_freem(m);
		return (error != 0 ? error : EIO);
	}
	mb->rxposts[pktid].buflen = (uint16_t)bufsize;
	if ((pa >> 32) != 0)
		atomic_add_64(&mb->stat_rx_high, 1);

	/* Sync before handing the buffer to fw. */
	bus_dmamap_sync(mb->rx_mbuf_tag, map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	mtx_lock(&ring->lock);
	if (type == BWFM_RXPOST_DATA) {
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
	mtx_unlock(&ring->lock);

	if (type == BWFM_RXPOST_EVENT)
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
	/* Roll back the rxpost slot, dmamap and mbuf. */
	bus_dmamap_unload(mb->rx_mbuf_tag, map);
	(void)rxpost_release(mb, pktid, NULL, NULL);
	m_freem(m);
	return (ENOSPC);
}

/*
 * Post up to `count` event buffers from the coherent pool.  Posting is
 * idempotent: a refill just re-posts the same slot with fresh content.
 * Returns the number posted.
 */
static bool
msgbuf_event_refill(struct bwfm_pci_msgbuf *mb)
{
	uint32_t slot;
	bool short_ = false;

	CTASSERT(BWFM_MSGBUF_MAX_EVENTBUF_POST <= 32);
	mtx_lock(&mb->eventbuf_mtx);
	for (slot = 0; slot < mb->max_eventbuf; slot++) {
		if ((mb->eventbuf_posted & (1u << slot)) != 0)
			continue;
		if (msgbuf_post_event_slot(mb, slot) != 0) {
			short_ = true;
			break;
		}
		mb->eventbuf_posted |= 1u << slot;
		mb->cur_eventbuf++;
	}
	mtx_unlock(&mb->eventbuf_mtx);
	return (short_);
}

/*
 * Deferred WL_EVENT dispatch.  Runs on taskqueue_thread outside any
 * ISR or ring lock, so the net80211 calls it leads to (e.g.
 * ieee80211_add_scan_result) can take IEEE80211_LOCK.  See
 * msgbuf_process_wl_event.
 */
static void
msgbuf_event_task(void *arg, int pending __unused)
{
	struct bwfm_pci_msgbuf *mb = arg;
	struct bwfm_pci_event *ep;

	for (;;) {
		mtx_lock(&mb->event_q_mtx);
		ep = STAILQ_FIRST(&mb->event_q);
		if (ep != NULL) {
			STAILQ_REMOVE_HEAD(&mb->event_q, link);
			mb->event_q_len--;
		}
		mtx_unlock(&mb->event_q_mtx);
		if (ep == NULL)
			return;
		bwfm_pci_msgbuf_event_up(mb->sc, ep->data, ep->datalen);
		free(ep, M_DEVBUF);
	}
}

/* Post up to `count` RX data buffers. */
static uint32_t
msgbuf_post_rx_bufs(struct bwfm_pci_msgbuf *mb, uint32_t count)
{
	struct bwfm_pci_ring *ring = &mb->rings[BWFM_H2D_MSGRING_RXPOST_SUBMIT];
	uint32_t i;

	for (i = 0; i < count; i++)
		if (msgbuf_post_one_rxbuf(mb, BWFM_RXPOST_DATA) != 0)
			break;
	/* One index update and doorbell for the whole batch. */
	if (i > 0) {
		mtx_lock(&ring->lock);
		ring_write_complete(ring);
		mtx_unlock(&ring->lock);
	}
	return (i);
}

/* Deficit that triggers a refill from the rx completion path. */
#define	BWFM_RXPOST_BATCH(mb)	((mb)->rxpost_batch)

static void	msgbuf_rx_refill(struct bwfm_pci_msgbuf *mb);

/* Note fw running under half its rx buffers; tell the core when they return. */
static void
msgbuf_rx_short_check(struct bwfm_pci_msgbuf *mb, uint32_t pending)
{
	uint32_t fwfree;

	fwfree = mb->cur_rxbufpost > pending ? mb->cur_rxbufpost - pending : 0;
	if (fwfree < mb->max_rxbufpost / 2) {
		if (!mb->rx_short)
			atomic_add_64(&mb->stat_rx_short, 1);
		mb->rx_short = true;
	} else if (mb->rx_short && pending == 0 &&
	    mb->max_rxbufpost - mb->cur_rxbufpost < BWFM_RXPOST_BATCH(mb)) {
		mb->rx_short = false;
		bwfm_pci_msgbuf_rx_starved(mb->sc);
	}
}
static void	msgbuf_rxfill_retry(void *arg);

/*
 * Refill the event and RX buffer pools up to their maxima.  Called from
 * the ISR after a slot is consumed.
 */
static void
msgbuf_rxpost_refill(struct bwfm_pci_msgbuf *mb)
{
	/* Refill in batches, as brcmfmac does, not one buffer per frame. */
	if (mb->max_rxbufpost - mb->cur_rxbufpost < BWFM_RXPOST_BATCH(mb))
		return;
	msgbuf_rx_refill(mb);
}

#define	BWFM_RXFILL_RETRY_TICKS	MAX(1, hz / 10)

/*
 * Refill the RX data pool; caller holds the RX_COMPLETE ring lock.
 * If the pool stays short, arm the retry callout.
 */
static void
msgbuf_rx_refill(struct bwfm_pci_msgbuf *mb)
{
	uint32_t need, got;

	bool ev_short;

	mtx_assert(&mb->rings[BWFM_D2H_MSGRING_RX_COMPLETE].lock, MA_OWNED);
	ev_short = msgbuf_event_refill(mb);
	need = got = 0;
	if (mb->cur_rxbufpost < mb->max_rxbufpost) {
		need = mb->max_rxbufpost - mb->cur_rxbufpost;
		got = msgbuf_post_rx_bufs(mb, need);
		if (got > 0)
			mb->stat_rxpost_refills++;
	}
	if ((got < need || ev_short) && mb->rxfill_inited && MB_ATTACHED(mb) &&
	    !callout_pending(&mb->rxfill_callout))
		callout_reset(&mb->rxfill_callout, BWFM_RXFILL_RETRY_TICKS,
		    msgbuf_rxfill_retry, mb);
	msgbuf_rx_short_check(mb, 0);
}

/* Callout: runs with the D2H RX_COMPLETE ring lock held. */
static void
msgbuf_rxfill_retry(void *arg)
{
	struct bwfm_pci_msgbuf *mb = arg;

	if (!MB_ATTACHED(mb))
		return;
	msgbuf_rx_refill(mb);
}

/*
 * Flowring create: allocate a coherent buffer, send FLOW_RING_CREATE on
 * the H2D control ring, and wait up to 2s for the completion.
 *
 * The local flowid handed back to the caller is a 0-based index into
 * mb->flowrings[]; fw sees flowid + IDSTART.  Slot allocation is
 * serialized on flow_mtx.
 */
#define	FLOW_CREATE_TIMEOUT_MS	2000

/*
 * Map priority (0..7) to 802.1D TID.  This is the identity, since
 * priorities 0..7 map 1:1 onto TIDs.
 */
static inline uint8_t
prio_to_tid(uint8_t prio)
{
	return (prio & 0x07);
}

static int
find_free_local_flowid(struct bwfm_pci_msgbuf *mb, uint16_t *out)
{
	uint16_t i;

	for (i = 0; i < mb->max_flowrings; i++) {
		if (mb->flowrings[i].status == BWFM_FLOW_CLOSED) {
			*out = i;
			return (0);
		}
	}
	return (ENOSPC);
}

/*
 * D3/D0 mailbox helpers; see bwfm_pci_msgbuf.h.
 */
static int
msgbuf_send_mb_data(struct bwfm_pci_softc *sc, uint32_t htod_val)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	device_t dev = bwfm_pci_msgbuf_dev(sc);
	uint32_t cur;
	int i;

	if (mb == NULL || !MB_ATTACHED(mb) || mb->htod_mb_data_addr == 0)
		return (ENXIO);
	cur = tcm_read32(mb, mb->htod_mb_data_addr);
	for (i = 0; cur != 0 && i < 100; i++) {
		DELAY(10000);
		cur = tcm_read32(mb, mb->htod_mb_data_addr);
	}
	if (cur != 0) {
		device_printf(dev,
		    "mb_send: htod slot still 0x%x after 1 s\n", cur);
		return (EBUSY);
	}
	tcm_write32(mb, mb->htod_mb_data_addr, htod_val);
	pci_write_config(dev, BWFM_PCI_REG_SBMBX, 1, 4);
	/*
	 * PCIe2 core rev <= 13 needs the doorbell written twice.  Doing
	 * it on every core is harmless.
	 */
	pci_write_config(dev, BWFM_PCI_REG_SBMBX, 1, 4);
	return (0);
}

static int
msgbuf_wait_mb_ack(struct bwfm_pci_softc *sc, uint32_t expect,
    int timeout_ms)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	uint32_t val;
	int elapsed;

	if (mb == NULL || !MB_ATTACHED(mb) || mb->dtoh_mb_data_addr == 0)
		return (ENXIO);
	for (elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
		val = tcm_read32(mb, mb->dtoh_mb_data_addr);
		if ((val & expect) == expect) {
			/* Clear it so the next exchange sees a fresh slot. */
			tcm_write32(mb, mb->dtoh_mb_data_addr, 0);
			return (0);
		}
		DELAY(10000);
	}
	return (ETIMEDOUT);
}

int
bwfm_pci_msgbuf_send_mb_data(struct bwfm_pci_softc *sc, uint32_t htod_val)
{
	int error;

	/* cold_reattach may be freeing the msgbuf. */
	if (!bwfm_pci_gate_enter(sc))
		return (ENXIO);
	error = msgbuf_send_mb_data(sc, htod_val);
	bwfm_pci_gate_exit(sc);
	return (error);
}

int
bwfm_pci_msgbuf_wait_mb_ack(struct bwfm_pci_softc *sc, uint32_t expect,
    int timeout_ms)
{
	int error;

	/* cold_reattach may be freeing the msgbuf. */
	if (!bwfm_pci_gate_enter(sc))
		return (ENXIO);
	error = msgbuf_wait_mb_ack(sc, expect, timeout_ms);
	bwfm_pci_gate_exit(sc);
	return (error);
}

/*
 * Wait up to timeout_ms for every outstanding EAPOL TX pktid to get its
 * TX_STATUS.  bwfm_fmop_set_key calls this when installing the PTK.
 * wpa_supplicant writes M4 and then issues SIOCS80211(WPAKEY) back to
 * back; if the WPAKEY DCMD reaches fw before M4 has drained from the
 * TID-7 flowring, fw may encrypt M4 with the new PTK.  The AP cannot
 * check that MIC (it installs its own PTK only after accepting M4) and
 * deauths with reason 6.  The drain normally takes well under a
 * millisecond; the timeout only guards against misbehaving fw.
 */
int
bwfm_pci_msgbuf_wait_eapol_drain(struct bwfm_pci_softc *sc, int timeout_ms)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	sbintime_t deadline;
	int error = 0;

	if (mb == NULL || !MB_ATTACHED(mb))
		return (ENXIO);
	deadline = sbinuptime() + SBT_1MS * timeout_ms;
	mtx_lock(&mb->pktid_mtx);
	while (mb->pending_eapol > 0) {
		if (sbinuptime() >= deadline) {
			error = ETIMEDOUT;
			break;
		}
		error = cv_timedwait_sbt(&mb->pending_eapol_cv,
		    &mb->pktid_mtx, deadline, 0, C_ABSOLUTE);
		if (error == EWOULDBLOCK) {
			error = ETIMEDOUT;
			break;
		}
	}
	mtx_unlock(&mb->pktid_mtx);
	return (error);
}

uint16_t
bwfm_pci_msgbuf_flowring_lookup(struct bwfm_pci_softc *sc,
    const uint8_t da[6], uint8_t prio)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	uint16_t i;

	if (mb == NULL || mb->flowrings == NULL)
		return ((uint16_t)-1);
	mtx_lock(&mb->flow_mtx);
	for (i = 0; i < mb->max_flowrings; i++) {
		struct bwfm_pci_flowring *fr = &mb->flowrings[i];
		if (fr->status != BWFM_FLOW_OPEN)
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
bwfm_pci_msgbuf_flowring_create(struct bwfm_pci_softc *sc,
    const uint8_t sa[6], const uint8_t da[6], uint8_t prio, uint8_t ifidx,
    uint16_t *flowid_out)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	struct bwfm_pci_flowring *fr;
	struct bwfm_pci_ring *ctl_ring;
	struct msgbuf_tx_flowring_create_req *req;
	uint32_t ringmem_addr;
	uint16_t local_id, fw_id;
	uint64_t paddr;
	int error;

	if (mb == NULL || !MB_ATTACHED(mb))
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
	FLOW_STATUS_SET(fr, BWFM_FLOW_PENDING);
	memcpy(fr->da, da, 6);
	memcpy(fr->sa, sa, 6);
	fr->prio = prio;
	fr->tid = prio_to_tid(prio);
	fr->ifidx = ifidx;
	mtx_unlock(&mb->flow_mtx);

	/*
	 * Allocate the flowring's coherent ring buffer.  Its TCM index
	 * slots follow the cursors set up in msgbuf_init_rings.
	 */
	if (fr->ring.buf.tag == NULL) {
		error = bwfm_pci_msgbuf_dma_alloc(mb, &fr->ring.buf,
		    BWFM_H2D_TXFLOWRING_MAX_ITEM * BWFM_H2D_TXFLOWRING_ITEMSIZE,
		    "flowring");
		if (error != 0)
			goto fail;
	}
	ring_config(&fr->ring, BWFM_H2D_TXFLOWRING_MAX_ITEM,
	    BWFM_H2D_TXFLOWRING_ITEMSIZE, mb, "bwfm_pci_flowring");
	fr->ring.id = local_id + BWFM_H2D_MSGRING_FLOWRING_IDSTART;
	fr->ring.w_idx_addr = mb->flow_h2d_w_next + local_id * sizeof(uint32_t);
	fr->ring.r_idx_addr = mb->flow_h2d_r_next + local_id * sizeof(uint32_t);

	/* Publish per-ring metadata into fw's ringmem slot for this flow. */
	ringmem_addr = mb->flow_ringmem_next + local_id * BWFM_RING_MEM_SZ;
	paddr = (uint64_t)fr->ring.buf.paddr;
	tcm_write32(mb, ringmem_addr + BWFM_RING_MEM_BASE_ADDR_OFFSET,
	    (uint32_t)(paddr & 0xffffffff));
	tcm_write32(mb, ringmem_addr + BWFM_RING_MEM_BASE_ADDR_OFFSET + 4,
	    (uint32_t)(paddr >> 32));
	tcm_write16(mb, ringmem_addr + BWFM_RING_MAX_ITEM_OFFSET,
	    BWFM_H2D_TXFLOWRING_MAX_ITEM);
	tcm_write16(mb, ringmem_addr + BWFM_RING_LEN_ITEMS_OFFSET,
	    BWFM_H2D_TXFLOWRING_ITEMSIZE);
	tcm_write16(mb, fr->ring.w_idx_addr, 0);
	tcm_write16(mb, fr->ring.r_idx_addr, 0);

	/* Send FLOW_RING_CREATE onto H2D_CTRL_SUBMIT. */
	fw_id = local_id + BWFM_H2D_MSGRING_FLOWRING_IDSTART;
	ctl_ring = &mb->rings[BWFM_H2D_MSGRING_CONTROL_SUBMIT];
	mtx_lock(&ctl_ring->lock);
	req = ring_reserve_for_write(ctl_ring);
	if (req == NULL) {
		mtx_unlock(&ctl_ring->lock);
		error = ENOSPC;
		goto fail;
	}
	memset(req, 0, sizeof(*req));
	req->msg.msgtype = BWFM_MSGBUF_TYPE_FLOW_RING_CREATE;
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
	req->max_items = htole16(BWFM_H2D_TXFLOWRING_MAX_ITEM);
	req->len_item = htole16(BWFM_H2D_TXFLOWRING_ITEMSIZE);
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
	while (fr->status == BWFM_FLOW_PENDING) {
		error = cv_timedwait_sig(&mb->flow_cv, &mb->flow_mtx,
		    hz * FLOW_CREATE_TIMEOUT_MS / 1000);
		if (error == EWOULDBLOCK) {
			/* Still PENDING: a late completion settles it. */
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
	if (FLOW_STATUS(fr) != BWFM_FLOW_OPEN) {
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
	FLOW_STATUS_SET(fr, BWFM_FLOW_CLOSED);
	mtx_unlock(&mb->flow_mtx);
	bwfm_pci_msgbuf_dma_free(mb, &fr->ring.buf);
	return (error);
}

/*
 * TX submission: map an mbuf that starts with an Ethernet header, write
 * a TX_POST into the flowring and ring the doorbell.  The mbuf is ours
 * from here on: on success it is freed when fw acks it with TX_STATUS,
 * and on error it is freed here.  ENOSPC (ring or pktid table full) is
 * the exception: *mp is handed back, possibly defragmented, to retry.
 */
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
bwfm_pci_msgbuf_txmbuf(struct bwfm_pci_softc *sc, uint16_t flowid,
    struct mbuf **mp, uint8_t ifidx)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	struct mbuf *m = *mp;
	struct bwfm_pci_flowring *fr;
	struct bwfm_pci_ring *ring;
	struct msgbuf_tx_msghdr *tx;
	bus_dmamap_t map = NULL;
	uint64_t data_pa;
	uint32_t pktid;
	int error;
	uint16_t datalen;

	if (mb == NULL || !MB_ATTACHED(mb) || flowid >= mb->max_flowrings) {
		error = ENXIO;
		goto drop;
	}
	fr = &mb->flowrings[flowid];
	if (FLOW_STATUS(fr) != BWFM_FLOW_OPEN) {
		error = ENOTCONN;
		goto drop;
	}
	if (m->m_pkthdr.len < ETHER_HDR_LEN) {
		error = EINVAL;
		goto drop;
	}

	/* TX_POST carries a single segment, so defragment the chain. */
	if (m->m_next != NULL) {
		struct mbuf *m2 = m_defrag(m, M_NOWAIT);
		if (m2 == NULL) {
			error = ENOMEM;
			goto drop;
		}
		m = m2;
		*mp = m;
	}

	{
		bool is_eapol = false;
		if (m->m_pkthdr.len >= 14 && m->m_len >= 14) {
			const uint8_t *_p = mtod(m, const uint8_t *);
			uint16_t _et = ((uint16_t)_p[12] << 8) | _p[13];
			is_eapol = (_et == 0x888e);
		}
		datalen = m->m_pkthdr.len;
		error = pktid_alloc(mb, m, flowid, is_eapol, datalen, &pktid);
	}
	if (error != 0) {
		atomic_add_64(&mb->stat_tx_no_pktid, 1);
		if (error == ENOSPC)
			return (ENOSPC);
		goto drop;
	}

	/* The slot owns its map for life; only the owner loads it. */
	map = mb->pktids[pktid].map;
	data_pa = 0;
	error = bus_dmamap_load(mb->tx_mbuf_tag, map, mtod(m, void *),
	    m->m_pkthdr.len, tx_load_cb, &data_pa, BUS_DMA_NOWAIT);
	if (error != 0 || data_pa == 0) {
		if (error == 0) {
			bus_dmamap_unload(mb->tx_mbuf_tag, map);
			error = EIO;
		}
		(void)pktid_release(mb, pktid, NULL, false);
		goto drop;
	}
	ring = &fr->ring;
	mtx_lock(&ring->lock);
	/* The ring may have been deleted; check again under its lock. */
	tx = FLOW_STATUS(fr) == BWFM_FLOW_OPEN ? ring_reserve_for_write(ring) :
	    NULL;
	if (tx == NULL) {
		error = FLOW_STATUS(fr) == BWFM_FLOW_OPEN ? ENOSPC : ENOTCONN;
		mtx_unlock(&ring->lock);
		bus_dmamap_unload(mb->tx_mbuf_tag, map);
		(void)pktid_release(mb, pktid, NULL, false);
		if (error == ENOSPC) {
			atomic_add_64(&mb->stat_tx_ring_full, 1);
			return (ENOSPC);
		}
		goto drop;
	}

	memset(tx, 0, sizeof(*tx));
	tx->msg.msgtype = BWFM_MSGBUF_TYPE_TX_POST;
	tx->msg.ifidx = ifidx;
	tx->msg.flags = 0;
	tx->msg.request_id = htole32(pktid + 1);
	memcpy(tx->txhdr, mtod(m, uint8_t *), 14);
	tx->flags = BWFM_MSGBUF_PKT_FLAGS_FRAME_802_3 |
	    ((fr->prio & 0x07) << BWFM_MSGBUF_PKT_FLAGS_PRIO_SHIFT);
	tx->seg_cnt = 1;
	tx->data_len = htole16(datalen - 14);
	/*
	 * The 14-byte Ethernet header travels in tx->txhdr, so data_buf
	 * must point past it, at the payload.  Pointing it at the start of
	 * the mbuf would make fw send the header twice and drop the last
	 * 14 bytes of payload.
	 */
	tx->data_buf_addr.low_addr = htole32((uint32_t)((data_pa + 14) & 0xffffffff));
	tx->data_buf_addr.high_addr = htole32((uint32_t)((data_pa + 14) >> 32));
	tx->metadata_buf_len = 0;
	tx->metadata_buf_addr.low_addr = 0;
	tx->metadata_buf_addr.high_addr = 0;

	if ((data_pa >> 32) != 0)
		atomic_add_64(&mb->stat_tx_high, 1);

	/* Make CPU writes to the packet buffer visible to fw. */
	bus_dmamap_sync(mb->tx_mbuf_tag, map, BUS_DMASYNC_PREWRITE);

	/* Before the doorbell: fw cannot complete it until then. */
	pktid_mark_posted(mb, pktid);
	ring_write_complete(ring);
	mtx_unlock(&ring->lock);

	atomic_add_64(&mb->stat_tx_post, 1);
	*mp = NULL;
	return (0);

drop:
	m_freem(m);
	*mp = NULL;
	return (error);
}

/*
 * D2H handling of FLOW_RING_CREATE_CMPLT and TX_STATUS, dispatched from
 * msgbuf_process_ctrl_msg.
 */
static void
msgbuf_process_flowring_create_cmplt(struct bwfm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_flowring_create_resp *resp = item;
	uint16_t fw_id, local_id;
	int16_t status;

	fw_id = le16toh(resp->compl_hdr.flow_ring_id);
	status = (int16_t)le16toh(resp->compl_hdr.status);

	if (fw_id < BWFM_H2D_MSGRING_FLOWRING_IDSTART) {
		device_printf(DEV(mb),
		    "msgbuf: FLOW_CREATE_CMPLT weird fw_id=%u status=%d\n",
		    fw_id, status);
		return;
	}
	local_id = fw_id - BWFM_H2D_MSGRING_FLOWRING_IDSTART;
	if (local_id >= mb->max_flowrings) {
		device_printf(DEV(mb),
		    "msgbuf: FLOW_CREATE_CMPLT local_id=%u out of range\n",
		    local_id);
		return;
	}

	/*
	 * Only a slot waiting on a create takes the answer.
	 * A refused create frees the slot.
	 */
	mtx_lock(&mb->flow_mtx);
	if (mb->flowrings[local_id].status == BWFM_FLOW_PENDING) {
		mb->flowrings[local_id].last_create_status = status;
		FLOW_STATUS_SET(&mb->flowrings[local_id], (status == 0) ?
		    BWFM_FLOW_OPEN : BWFM_FLOW_CLOSED);
		cv_broadcast(&mb->flow_cv);
	}
	mtx_unlock(&mb->flow_mtx);

	MDPRINTF(mb, 0,
	    "msgbuf: FLOW_CREATE_CMPLT fw_id=%u local=%u status=%d\n",
	    fw_id, local_id, status);
}

/*
 * FLOW_RING_DELETE_CMPLT: fw acknowledges a FLOW_RING_DELETE.  Mark the
 * local slot CLOSED so a later create can reuse it.
 */
static void
msgbuf_process_flowring_delete_cmplt(struct bwfm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_flowring_delete_resp *resp = item;
	uint16_t fw_id, local_id;
	int16_t status;

	fw_id = le16toh(resp->compl_hdr.flow_ring_id);
	status = (int16_t)le16toh(resp->compl_hdr.status);
	if (fw_id < BWFM_H2D_MSGRING_FLOWRING_IDSTART) {
		device_printf(DEV(mb),
		    "msgbuf: FLOW_DELETE_CMPLT weird fw_id=%u status=%d\n",
		    fw_id, status);
		return;
	}
	local_id = fw_id - BWFM_H2D_MSGRING_FLOWRING_IDSTART;
	if (local_id >= mb->max_flowrings) {
		device_printf(DEV(mb),
		    "msgbuf: FLOW_DELETE_CMPLT local_id=%u out of range\n",
		    local_id);
		return;
	}
	mtx_lock(&mb->flow_mtx);
	FLOW_STATUS_SET(&mb->flowrings[local_id], BWFM_FLOW_CLOSED);
	memset(mb->flowrings[local_id].da, 0, 6);
	memset(mb->flowrings[local_id].sa, 0, 6);
	cv_broadcast(&mb->flow_cv);
	mtx_unlock(&mb->flow_mtx);
	MDPRINTF(mb, 0,
	    "msgbuf: FLOW_DELETE_CMPLT fw_id=%u local=%u status=%d\n",
	    fw_id, local_id, status);
}

/*
 * Synchronously delete a flowring: send FLOW_RING_DELETE on the H2D
 * control ring and wait up to 2s for fw's completion, which marks the
 * slot CLOSED for reuse.  Callers must not hold any lock the msgbuf ISR
 * path needs.
 */
int
bwfm_pci_msgbuf_flowring_delete(struct bwfm_pci_softc *sc, uint16_t local_id)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	struct bwfm_pci_ring *ctl_ring;
	struct msgbuf_tx_flowring_delete_req *req;
	struct bwfm_pci_flowring *fr;
	uint16_t fw_id;
	int error;

	if (mb == NULL || !MB_ATTACHED(mb) || mb->flowrings == NULL)
		return (ENXIO);
	if (local_id >= mb->max_flowrings)
		return (EINVAL);
	fr = &mb->flowrings[local_id];

	mtx_lock(&mb->flow_mtx);
	if (FLOW_STATUS(fr) != BWFM_FLOW_OPEN) {
		mtx_unlock(&mb->flow_mtx);
		return (0);	/* nothing to delete */
	}
	mtx_unlock(&mb->flow_mtx);

	fw_id = local_id + BWFM_H2D_MSGRING_FLOWRING_IDSTART;
	ctl_ring = &mb->rings[BWFM_H2D_MSGRING_CONTROL_SUBMIT];
	mtx_lock(&ctl_ring->lock);
	req = ring_reserve_for_write(ctl_ring);
	if (req == NULL) {
		mtx_unlock(&ctl_ring->lock);
		return (ENOSPC);
	}
	memset(req, 0, sizeof(*req));
	req->msg.msgtype = BWFM_MSGBUF_TYPE_FLOW_RING_DELETE;
	req->msg.ifidx = fr->ifidx;
	req->msg.request_id = 0;
	req->flow_ring_id = htole16(fw_id);
	req->reason = 0;
	ring_write_complete(ctl_ring);
	mtx_unlock(&ctl_ring->lock);

	MDPRINTF(mb, 0, "msgbuf: FLOW_DELETE flow=%u sent\n", fw_id);

	mtx_lock(&mb->flow_mtx);
	while (fr->status == BWFM_FLOW_OPEN) {
		error = cv_timedwait_sig(&mb->flow_cv, &mb->flow_mtx,
		    hz * 2);
		if (error == EWOULDBLOCK) {
			mtx_unlock(&mb->flow_mtx);
			device_printf(DEV(mb),
			    "msgbuf: FLOW_DELETE flow=%u timeout\n", fw_id);
			return (ETIMEDOUT);
		}
		if (error != 0) {
			mtx_unlock(&mb->flow_mtx);
			return (error);
		}
	}
	mtx_unlock(&mb->flow_mtx);
	return (0);
}

/*
 * Delete every flow ring whose destination is `da`: an access point's
 * rings for a station that has left, one per priority.  The firmware
 * frees the station's state, so a ring left behind would carry the
 * station's next association's frames nowhere.
 */
void
bwfm_pci_msgbuf_flowring_delete_peer(struct bwfm_pci_softc *sc,
    const uint8_t da[6])
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	uint16_t i;
	bool match;

	if (mb == NULL || !MB_ATTACHED(mb) || mb->flowrings == NULL)
		return;
	for (i = 0; i < mb->max_flowrings; i++) {
		mtx_lock(&mb->flow_mtx);
		match = mb->flowrings[i].status == BWFM_FLOW_OPEN &&
		    memcmp(mb->flowrings[i].da, da, 6) == 0;
		mtx_unlock(&mb->flow_mtx);
		if (match && bwfm_pci_msgbuf_flowring_delete(sc, i) == 0)
			MDPRINTF(mb, 1, "msgbuf: deleted flow ring %u of "
			    "%6D\n", i, da, ":");
	}
}

void
bwfm_pci_msgbuf_flowring_delete_all(struct bwfm_pci_softc *sc)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	uint16_t i;
	int rc, ok = 0, fail = 0;

	if (mb == NULL || !MB_ATTACHED(mb) || mb->flowrings == NULL)
		return;
	for (i = 0; i < mb->max_flowrings; i++) {
		if (mb->flowrings[i].status != BWFM_FLOW_OPEN)
			continue;
		rc = bwfm_pci_msgbuf_flowring_delete(sc, i);
		if (rc == 0)
			ok++;
		else
			fail++;
	}
	if (ok != 0 || fail != 0)
		MDPRINTF(mb, 0,
		    "msgbuf: flowring_delete_all: %d deleted, %d failed\n",
		    ok, fail);
}

static void
msgbuf_process_txstatus(struct bwfm_pci_msgbuf *mb, void *item)
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
	m = pktid_release(mb, pktid, &map, true);
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
	}
	m_freem(m);

	if (tx_status == 0)
		mb->stat_tx_status_ok++;
	else
		mb->stat_tx_status_err++;
	bwfm_pci_tx_resume(mb->sc);
}

/*
 * DCMD wrappers.  All are synchronous through bwfm_pci_msgbuf_dcmd,
 * which serializes on dcmd_sx.
 */
#define	BWFM_IOVAR_BUF_MAX	1024

int
bwfm_pci_msgbuf_dcmd_set_int(struct bwfm_pci_softc *sc, uint32_t cmd,
    uint32_t val)
{
	uint32_t le = htole32(val);
	size_t rlen = 0;
	int32_t fwerr = 0;
	int error;

	error = bwfm_pci_msgbuf_dcmd(sc, cmd, true, &le, sizeof(le),
	    NULL, &rlen, &fwerr);
	if (error == 0 && fwerr != 0)
		error = EIO;
	return (error);
}

int
bwfm_pci_msgbuf_dcmd_get_int(struct bwfm_pci_softc *sc, uint32_t cmd,
    uint32_t *val)
{
	uint32_t buf = 0;
	size_t rlen = sizeof(buf);
	int32_t fwerr = 0;
	int error;

	error = bwfm_pci_msgbuf_dcmd(sc, cmd, false, &buf, sizeof(buf),
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
bwfm_pci_msgbuf_dcmd_set_var(struct bwfm_pci_softc *sc, const char *name,
    const void *data, size_t datalen)
{
	uint8_t buf[BWFM_IOVAR_BUF_MAX];
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

	error = bwfm_pci_msgbuf_dcmd(sc, BWFM_C_SET_VAR, true, buf, buflen,
	    NULL, &rlen, &fwerr);
	explicit_bzero(buf, buflen);	/* may hold key material */
	if (error == 0 && fwerr != 0)
		error = EIO;
	return (error);
}

int
bwfm_pci_msgbuf_dcmd_get_var(struct bwfm_pci_softc *sc, const char *name,
    void *data, size_t *datalenp)
{
	uint8_t buf[BWFM_IOVAR_BUF_MAX];
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

	error = bwfm_pci_msgbuf_dcmd(sc, BWFM_C_GET_VAR, false, buf, buflen,
	    buf, &rlen, &fwerr);
	if (error == 0 && fwerr != 0)
		error = EIO;
	if (error == 0) {
		if (data != NULL && rlen > 0)
			memcpy(data, buf, rlen);
		*datalenp = rlen;
	}
	explicit_bzero(buf, sizeof(buf));
	return (error);
}

/*
 * DCMD round trip:
 *
 * 1. Post one IOCTLRESP buffer.
 * 2. Copy params into mb->ioctbuf and enqueue an IOCTLPTR_REQ on
 *    H2D_CONTROL_SUBMIT with request_id BWFM_IOCTL_REQ_PKTID, a new
 *    trans_id, and req_buf_addr pointing at mb->ioctbuf.
 * 3. Ring the doorbell and wait on dcmd_cv for up to 2s.
 * 4. On completion, copy the response fw wrote into mb->ioctbuf out to
 *    the caller and return fw's status in *fwerr.
 */
static int
msgbuf_dcmd(struct bwfm_pci_softc *sc, uint32_t cmd, bool is_set,
    const void *params, size_t params_len, void *resp, size_t *resp_lenp,
    int32_t *fwerr)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	struct bwfm_pci_ring *ring;
	struct msgbuf_ioctl_req_hdr *req;
	uint16_t buf_len, out_len;
	uint64_t paddr;
	int error;

	if (mb == NULL || !MB_ATTACHED(mb))
		return (ENXIO);
	if (params_len > BWFM_MSGBUF_MAX_CTL_PKT_SIZE ||
	    (resp_lenp != NULL && *resp_lenp > BWFM_MSGBUF_MAX_CTL_PKT_SIZE))
		return (E2BIG);

	sx_xlock(&mb->dcmd_sx);

	/*
	 * After a timeout, give the old reply up to 1 s to land
	 * before staging a new request.
	 */
	mtx_lock(&mb->dcmd_mtx);
	if (mb->dcmd_stale) {
		(void)cv_timedwait(&mb->dcmd_cv, &mb->dcmd_mtx, hz);
		mb->dcmd_stale = false;
	}
	mtx_unlock(&mb->dcmd_mtx);

	/* Give fw a fresh IOCTLRESP buffer for the reply. */
	error = msgbuf_post_ioctlresp(mb);
	if (error != 0) {
		sx_xunlock(&mb->dcmd_sx);
		return (error);
	}

	/* Stage request payload. */
	buf_len = (uint16_t)MIN(params_len, BWFM_MSGBUF_MAX_CTL_PKT_SIZE);
	if (params != NULL && buf_len > 0)
		memcpy(mb->ioctbuf.vaddr, params, buf_len);
	else
		memset(mb->ioctbuf.vaddr, 0, buf_len);

	/*
	 * Fw writes the response into the same ioctbuf slot as the
	 * request, so output_buf_len must be the full buffer size, not
	 * just the expected response length.  If output_buf_len is less
	 * than input_buf_len, fw returns BCME_BUFTOOSHORT (-14) even when
	 * the response is small.
	 */
	out_len = (uint16_t)MAX(buf_len,
	    resp_lenp != NULL ? *resp_lenp : 0);

	ring = &mb->rings[BWFM_H2D_MSGRING_CONTROL_SUBMIT];
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
	req->msg.msgtype = BWFM_MSGBUF_TYPE_IOCTLPTR_REQ;
	req->msg.ifidx = 0;
	req->msg.flags = 0;
	req->msg.request_id = htole32(BWFM_IOCTL_REQ_PKTID);
	req->cmd = htole32(cmd);
	req->trans_id = htole16(mb->dcmd_reqid);
	/* Fw drops a request whose input is over one frame; brcmfmac caps it too. */
	req->input_buf_len = htole16(MIN(buf_len, BWFM_MSGBUF_TX_IOCTL_MAX_MSG_SIZE));
	req->output_buf_len = htole16(out_len);
	paddr = (uint64_t)mb->ioctbuf.paddr;
	req->req_buf_addr.low_addr = htole32((uint32_t)(paddr & 0xffffffff));
	req->req_buf_addr.high_addr = htole32((uint32_t)(paddr >> 32));

	mtx_lock(&mb->dcmd_mtx);
	mb->dcmd_completed = false;
	mb->dcmd_waiting = true;
	mtx_unlock(&mb->dcmd_mtx);

	ring_write_complete(ring);
	mtx_unlock(&ring->lock);

	mb->stat_dcmd_tx++;

	/* Wait for ISR to signal completion. */
	mtx_lock(&mb->dcmd_mtx);
	while (!mb->dcmd_completed) {
		/* Not interruptible; the timeout bounds the wait. */
		error = cv_timedwait(&mb->dcmd_cv, &mb->dcmd_mtx,
		    hz * MSGBUF_IOCTL_RESP_TIMEOUT_MS / 1000);
		if (error == EWOULDBLOCK) {
			static struct timeval _last;
			static int _cnt;
			mb->stat_dcmd_timeout++;
			mb->stat_dcmd_timeout_consec++;
			mb->dcmd_waiting = false;
			mb->dcmd_stale = true;
			mtx_unlock(&mb->dcmd_mtx);
			if (ppsratecheck(&_last, &_cnt, 1))
				device_printf(DEV(mb),
				    "msgbuf: dcmd cmd=0x%x timeout "
				    "(consec=%u)\n", cmd,
				    mb->stat_dcmd_timeout_consec);
			/*
			 * Fw crash recovery.  The threshold check lives in
			 * if_bwfm_pci.c, where struct bwfm_pci_softc is
			 * fully defined; this file only sees a forward
			 * declaration.
			 */
			bwfm_pci_maybe_queue_crash_recover(sc);
			sx_xunlock(&mb->dcmd_sx);
			return (ETIMEDOUT);
		}
		if (error != 0) {
			mb->dcmd_waiting = false;
			mtx_unlock(&mb->dcmd_mtx);
			sx_xunlock(&mb->dcmd_sx);
			return (error);
		}
	}
	mb->dcmd_waiting = false;
	mtx_unlock(&mb->dcmd_mtx);

	/* Copy response out from ioctbuf. */
	if (resp != NULL && resp_lenp != NULL) {
		size_t rlen = MIN(*resp_lenp, mb->dcmd_resp_len);
		memcpy(resp, mb->ioctbuf.vaddr, rlen);
		*resp_lenp = rlen;
	}
	/* Requests and replies can carry keys; leave none behind. */
	explicit_bzero(mb->ioctbuf.vaddr, MAX(buf_len, out_len));
	if (fwerr != NULL)
		*fwerr = mb->dcmd_resp_status;

	/* Fw responded, so reset the consecutive-timeout count. */
	mb->stat_dcmd_timeout_consec = 0;

	sx_xunlock(&mb->dcmd_sx);
	return (0);
}

int
bwfm_pci_msgbuf_dcmd(struct bwfm_pci_softc *sc, uint32_t cmd, bool is_set,
    const void *params, size_t params_len, void *resp, size_t *resp_lenp,
    int32_t *fwerr)
{
	int error;

	/* cold_reattach may be freeing the dcmd locks and buffers. */
	if (!bwfm_pci_gate_enter(sc))
		return (ENXIO);
	error = msgbuf_dcmd(sc, cmd, is_set, params, params_len, resp,
	    resp_lenp, fwerr);
	bwfm_pci_gate_exit(sc);
	return (error);
}

/*
 * Interrupt filter.  If MAILBOXINT has a bit set, mask the chip's
 * interrupt source (MAILBOXMASK = 0) and schedule the ithread, which
 * reads, acks, drains and re-enables.  This keeps the filter from
 * re-entering while the thread is working.
 */
int
bwfm_pci_msgbuf_isr_filter(void *arg)
{
	struct bwfm_pci_msgbuf *mb = arg;
	uint32_t status;

	status = pcie2_read32(mb, BWFM_PCIE2REG_MAILBOXINT);
	if (status == 0 || status == 0xffffffff)
		return (FILTER_STRAY);

	/* Mask; the thread re-enables after draining. */
	pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXMASK, 0);
	mb->stat_isr_hits++;
	return (FILTER_SCHEDULE_THREAD);
}

/*
 * WL_EVENT processing.  Fw hands us a msgbuf_rx_event descriptor whose
 * request_id names an event buffer pktid; fw has DMA'd the event
 * payload into that coherent event buffer.  The bcmevent header is
 * decoded for debug logging and the payload is queued for
 * msgbuf_event_task.
 */
/* Human-readable event-code lookup. */
static const char *
bcmevent_name(uint32_t code)
{
	switch (code) {
	case BWFM_PCI_E_SET_SSID:		return "SET_SSID";
	case BWFM_PCI_E_JOIN:		return "JOIN";
	case BWFM_PCI_E_START:		return "START";
	case BWFM_PCI_E_AUTH:		return "AUTH";
	case BWFM_PCI_E_AUTH_IND:		return "AUTH_IND";
	case BWFM_PCI_E_DEAUTH:		return "DEAUTH";
	case BWFM_PCI_E_DEAUTH_IND:		return "DEAUTH_IND";
	case BWFM_PCI_E_ASSOC:		return "ASSOC";
	case BWFM_PCI_E_ASSOC_IND:		return "ASSOC_IND";
	case BWFM_PCI_E_REASSOC:		return "REASSOC";
	case BWFM_PCI_E_REASSOC_IND:	return "REASSOC_IND";
	case BWFM_PCI_E_DISASSOC:		return "DISASSOC";
	case BWFM_PCI_E_DISASSOC_IND:	return "DISASSOC_IND";
	case BWFM_PCI_E_LINK:		return "LINK";
	case BWFM_PCI_E_MIC_ERROR:		return "MIC_ERROR";
	case BWFM_PCI_E_ROAM:		return "ROAM";
	case BWFM_PCI_E_PMKID_CACHE:	return "PMKID_CACHE";
	case BWFM_PCI_E_EAPOL_MSG:		return "EAPOL_MSG";
	case BWFM_PCI_E_SCAN_COMPLETE:	return "SCAN_COMPLETE";
	case BWFM_PCI_E_JOIN_START:		return "JOIN_START";
	case BWFM_PCI_E_ROAM_START:		return "ROAM_START";
	case BWFM_PCI_E_ASSOC_START:	return "ASSOC_START";
	case BWFM_PCI_E_PSK_SUP:		return "PSK_SUP";
	case BWFM_PCI_E_COUNTRY_CODE_CHANGED: return "COUNTRY_CODE_CHANGED";
	case BWFM_PCI_E_ACTION_FRAME:	return "ACTION_FRAME";
	case BWFM_PCI_E_ESCAN_RESULT:	return "ESCAN_RESULT";
	case BWFM_PCI_E_PROBERESP_MSG:	return "PROBERESP_MSG";
	case BWFM_PCI_E_FIFO_CREDIT_MAP:	return "FIFO_CREDIT_MAP";
	case BWFM_PCI_E_IF:		return "IF";
	case BWFM_PCI_E_RSSI:		return "RSSI";
	case BWFM_PCI_E_TRACE:		return "TRACE";
	case BWFM_PCI_E_BEACON_RX:	return "BEACON_RX";
	case BWFM_PCI_E_TXFAIL:		return "TXFAIL";
	case BWFM_PCI_E_RADIO:		return "RADIO";
	case BWFM_PCI_E_PSM_WATCHDOG:	return "PSM_WATCHDOG";
	default:			return "?";
	}
}

static const char *
bcmevent_status_name(uint32_t status)
{
	switch (status) {
	case BWFM_PCI_E_STATUS_SUCCESS:	return "SUCCESS";
	case BWFM_PCI_E_STATUS_FAIL:	return "FAIL";
	case BWFM_PCI_E_STATUS_TIMEOUT:	return "TIMEOUT";
	case BWFM_PCI_E_STATUS_NO_NETWORKS:	return "NO_NETWORKS";
	case BWFM_PCI_E_STATUS_ABORT:	return "ABORT";
	case BWFM_PCI_E_STATUS_NO_ACK:	return "NO_ACK";
	case BWFM_PCI_E_STATUS_UNSOLICITED:	return "UNSOLICITED";
	case BWFM_PCI_E_STATUS_ATTEMPT:	return "ATTEMPT";
	case BWFM_PCI_E_STATUS_PARTIAL:	return "PARTIAL";
	case BWFM_PCI_E_STATUS_NEWSCAN:	return "NEWSCAN";
	case BWFM_PCI_E_STATUS_NEWASSOC:	return "NEWASSOC";
	case BWFM_PCI_E_STATUS_ERROR:	return "ERROR";
	default:			return "?";
	}
}

static void
msgbuf_process_wl_event(struct bwfm_pci_msgbuf *mb, void *item)
{
	struct msgbuf_rx_event *ev = item;
	struct bwfm_pci_dma_buf *evb;
	uint32_t pktid, slot;
	uint16_t datalen;
	uint8_t *payload;

	pktid = le32toh(ev->msg.request_id);
	datalen = le16toh(ev->event_data_len);

	mb->stat_event_rx++;

	if (!BWFM_EVENTBUF_IS_EVENT(pktid)) {
		device_printf(DEV(mb),
		    "msgbuf: WL_EVENT pktid=0x%x not in eventbuf range\n",
		    pktid);
		return;
	}
	slot = BWFM_EVENTBUF_PKTID_SLOT(pktid);
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

	if (datalen < BWFM_EVT_OFFSET_DATA) {
		device_printf(DEV(mb),
		    "msgbuf: WL_EVENT ifidx=%u short (datalen=%u < %u)\n",
		    ev->msg.ifidx, datalen, BWFM_EVT_OFFSET_DATA);
		goto refill;
	}
	payload = evb->vaddr;
	{
		uint16_t etype;
		struct bwfm_bcm_ethhdr *eh;
		struct bwfm_bcm_event_msg *em;
		uint32_t event_code, status, reason, data_len_field;
		uint16_t evver, evflags;
		const uint8_t *addr;

		etype = be16dec(payload + 12);
		if (etype != BWFM_ETH_TYPE_EVENT) {
			device_printf(DEV(mb),
			    "msgbuf: WL_EVENT unexpected etype=0x%04x "
			    "(want 0x886c)\n", etype);
			goto refill;
		}
		eh = (struct bwfm_bcm_ethhdr *)(payload + BWFM_EVT_OFFSET_BCM_ETHHDR);
		em = (struct bwfm_bcm_event_msg *)(payload + BWFM_EVT_OFFSET_MSG);

		evver = be16dec(&em->version);
		evflags = be16dec(&em->flags);
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
		    reason, evflags, em->ifidx,
		    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
		    data_len_field, datalen - BWFM_EVT_OFFSET_DATA,
		    evver, be16dec(&eh->subtype),
		    be16dec(&eh->usr_subtype));
	}
	/*
	 * Queue the payload for dispatch on taskqueue_thread.  Direct
	 * dispatch here would deadlock: the ISR holds ring->lock, and
	 * bwfm_pci_msgbuf_event_up -> bwfm_handle_event ->
	 * ieee80211_add_scan_result takes IEEE80211_LOCK.  Meanwhile the
	 * scan path (fmac_scan_start_shim -> DCMD) holds IEEE80211_LOCK
	 * while it waits for the IOCTL_CMPLT that this same ISR has to
	 * deliver.  Deferring runs dispatch after the DCMD thread drops
	 * IEEE80211_LOCK, at the cost of one malloc and memcpy per event.
	 */
	{
		struct bwfm_pci_event *ep;

		ep = malloc(sizeof(*ep), M_DEVBUF, M_NOWAIT | M_ZERO);
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
		/* Bound the scan result backlog. */
		if (mb->event_q_len >= BWFM_PCI_EVENT_Q_MAX) {
			mb->stat_event_drops++;
			mtx_unlock(&mb->event_q_mtx);
			free(ep, M_DEVBUF);
			goto refill;
		}
		STAILQ_INSERT_TAIL(&mb->event_q, ep, link);
		mb->event_q_len++;
		mtx_unlock(&mb->event_q_mtx);
		(void)taskqueue_enqueue(taskqueue_thread, &mb->event_task);
	}

refill:
	/*
	 * The firmware has handed this slot back; post it again.  If that
	 * fails (control ring full), the rxfill callout retries it.
	 */
	mtx_lock(&mb->eventbuf_mtx);
	if ((mb->eventbuf_posted & (1u << slot)) != 0) {
		mb->eventbuf_posted &= ~(1u << slot);
		mb->cur_eventbuf--;
	}
	mtx_unlock(&mb->eventbuf_mtx);
	if (msgbuf_event_refill(mb)) {
		struct bwfm_pci_ring *rx =
		    &mb->rings[BWFM_D2H_MSGRING_RX_COMPLETE];

		mtx_lock(&rx->lock);
		if (mb->rxfill_inited && MB_ATTACHED(mb) &&
		    !callout_pending(&mb->rxfill_callout))
			callout_reset(&mb->rxfill_callout,
			    BWFM_RXFILL_RETRY_TICKS, msgbuf_rxfill_retry, mb);
		mtx_unlock(&rx->lock);
	}
}

/*
 * RX_CMPLT: fw completed a receive into one of our data buffers.  Trim
 * the mbuf, pass it up, and refill the RX pool.
 */
static void
msgbuf_process_rx_complete(struct bwfm_pci_msgbuf *mb, void *item)
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
	if (m == NULL || type != BWFM_RXPOST_DATA) {
		static struct timeval last;
		static int pps;

		if (ppsratecheck(&last, &pps, 1))
			device_printf(DEV(mb),
			    "msgbuf: RX_CMPLT pktid=%u unknown (m=%p type=%u)\n",
			    pktid, m, type);
		/* Only a buffer we posted counts against cur_rxbufpost. */
		if (m != NULL) {
			if (map != NULL)
				bus_dmamap_unload(mb->rx_mbuf_tag, map);
			m_freem(m);
			msgbuf_rxpost_refill(mb);
		}
		return;
	}
	if (map != NULL) {
		bus_dmamap_sync(mb->rx_mbuf_tag, map,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(mb->rx_mbuf_tag, map);
	}

	{
		uint16_t data_off = le16toh(rc->data_offset);
		uint16_t flags = le16toh(rc->flags);

		/*
		 * Strip fw's RX data offset, if any, trim to datalen and
		 * pass the mbuf to net80211 through the shared bwfm.c
		 * core.  As a fullmac STA, fw delivers 802.3 frames;
		 * monitor-mode 802.11 frames are dropped.
		 */
		if (data_off > 0 && data_off <= m->m_len)
			m_adj(m, data_off);
		if (datalen < m->m_len) {
			m->m_len = datalen;
			m->m_pkthdr.len = datalen;
		}
		if ((flags & BWFM_MSGBUF_PKT_FLAGS_FRAME_MASK) ==
		    BWFM_MSGBUF_PKT_FLAGS_FRAME_802_11) {
			/* Monitor-mode 802.11 frames are not handled. */
			m_freem(m);
		} else if (mbufq_enqueue(&mb->rx_upq, m) != 0)
			m_freem(m);
	}
	if (mb->cur_rxbufpost > 0)
		mb->cur_rxbufpost--;
	msgbuf_rxpost_refill(mb);
}

/*
 * D2H message dispatch for the ithread.  IOCTL_CMPLT wakes the DCMD
 * waiter; GEN_STATUS, RING_STATUS and IOCTLPTR_REQ_ACK are only logged.
 */
static void
msgbuf_process_ctrl_msg(struct bwfm_pci_msgbuf *mb, uint32_t ring_idx,
    void *item)
{
	struct msgbuf_common_hdr *hdr = item;
	struct msgbuf_ioctl_resp_hdr *ioctl;

	mb->stat_ctl_msgs++;

	switch (hdr->msgtype) {
	case BWFM_MSGBUF_TYPE_IOCTL_CMPLT:
		ioctl = item;
		mtx_lock(&mb->dcmd_mtx);
		/* Only the reply to the waiting request completes it. */
		if (!mb->dcmd_waiting ||
		    le16toh(ioctl->trans_id) != mb->dcmd_reqid) {
			mb->stat_dcmd_stale++;
			/* The late reply is in; ioctbuf is free again. */
			if (mb->dcmd_stale) {
				mb->dcmd_stale = false;
				cv_broadcast(&mb->dcmd_cv);
			}
			mtx_unlock(&mb->dcmd_mtx);
			MDPRINTF(mb, 0, "msgbuf: stale IOCTL_CMPLT trans=%u "
			    "(want %u)\n", le16toh(ioctl->trans_id),
			    mb->dcmd_reqid);
			break;
		}
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
	case BWFM_MSGBUF_TYPE_FLOW_RING_CREATE_CMPLT:
		msgbuf_process_flowring_create_cmplt(mb, item);
		break;
	case BWFM_MSGBUF_TYPE_FLOW_RING_DELETE_CMPLT:
		msgbuf_process_flowring_delete_cmplt(mb, item);
		break;
	case BWFM_MSGBUF_TYPE_TX_STATUS:
		msgbuf_process_txstatus(mb, item);
		break;
	case BWFM_MSGBUF_TYPE_GEN_STATUS:
	case BWFM_MSGBUF_TYPE_RING_STATUS:
	case BWFM_MSGBUF_TYPE_IOCTLPTR_REQ_ACK:
		MDPRINTF(mb, 0,
		    "msgbuf: ctrl msg type 0x%02x (ignored, first-light)\n",
		    hdr->msgtype);
		break;
	case BWFM_MSGBUF_TYPE_WL_EVENT:
		msgbuf_process_wl_event(mb, item);
		break;
	case BWFM_MSGBUF_TYPE_RX_CMPLT:
		/*
		 * Receive completions refill the RX pool, which needs the
		 * RX_COMPLETE ring lock; one on any other ring is bogus.
		 */
		if (ring_idx != BWFM_D2H_MSGRING_RX_COMPLETE) {
			static struct timeval last;
			static int pps;

			if (ppsratecheck(&last, &pps, 1))
				device_printf(DEV(mb),
				    "msgbuf: RX_CMPLT on ring %u ignored\n",
				    ring_idx);
			break;
		}
		msgbuf_process_rx_complete(mb, item);
		break;
	default:
		device_printf(DEV(mb),
		    "msgbuf: unknown ctrl msgtype 0x%02x\n", hdr->msgtype);
		break;
	}
}

static void
drain_d2h_ring(struct bwfm_pci_msgbuf *mb, uint32_t ring_idx)
{
	struct bwfm_pci_ring *ring = &mb->rings[ring_idx];
	struct mbufq upq;
	struct mbuf *m;
	void *base;
	uint16_t n, i;

	mtx_lock(&ring->lock);
	base = ring_get_read_ptr(ring, &n);
	if (ring_idx == BWFM_D2H_MSGRING_RX_COMPLETE && base != NULL)
		msgbuf_rx_short_check(mb, (ring->w_ptr + ring->depth -
		    ring->r_ptr) % ring->depth);
	while (base != NULL && n != 0) {
		for (i = 0; i < n; i++) {
			void *item = (uint8_t *)base +
			    (size_t)i * ring->item_len;
			msgbuf_process_ctrl_msg(mb, ring_idx, item);
		}
		ring_read_complete(ring, n);
		base = ring_get_read_ptr(ring, &n);
	}
	mbufq_init(&upq, INT_MAX);
	mbufq_concat(&upq, &mb->rx_upq);
	mtx_unlock(&ring->lock);

	/* The stack may transmit from here, so no driver lock is held. */
	while ((m = mbufq_dequeue(&upq)) != NULL)
		bwfm_pci_msgbuf_rx_up(mb->sc, m, -50);
}

void
bwfm_pci_msgbuf_isr_thread(void *arg)
{
	struct bwfm_pci_msgbuf *mb = arg;
	uint32_t status;

	/* Read and ack the chip's interrupt status. */
	status = pcie2_read32(mb, BWFM_PCIE2REG_MAILBOXINT);
	if (status != 0 && status != 0xffffffff)
		pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXINT, status);

	/*
	 * Drain all three D2H rings.  D2H_CTRL carries IOCTL completions,
	 * FLOW_RING_CREATE_CMPLT and async events, D2H_TX carries
	 * TX_STATUS, and D2H_RX carries RX_CMPLT.  Fw indicates which ring
	 * with the D2H_DB bits, but every ring is polled regardless.
	 */
	drain_d2h_ring(mb, BWFM_D2H_MSGRING_CONTROL_COMPLETE);
	drain_d2h_ring(mb, BWFM_D2H_MSGRING_TX_COMPLETE);
	drain_d2h_ring(mb, BWFM_D2H_MSGRING_RX_COMPLETE);

	/* Re-arm the chip interrupt unless we are tearing down. */
	if (MB_ATTACHED(mb))
		pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXMASK,
		    BWFM_PCIE_MB_INT_D2H_DB | BWFM_PCIE_MB_INT_FN0);
}

/*
 * Attach.  Must be called after fw has been released and is running
 * (armcr4_release succeeded).  A second attach is a no-op.
 */
int
bwfm_pci_msgbuf_attach(struct bwfm_pci_softc *sc)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	uint32_t pcie2;
	int error;

	if (mb == NULL)
		return (ENXIO);
	if (MB_ATTACHED(mb))
		return (0);

	memset(mb, 0, sizeof(*mb));
	mb->sc = sc;
	mbufq_init(&mb->rx_upq, INT_MAX);

	pcie2 = bwfm_pci_msgbuf_pcie2_base(sc);
	if (pcie2 == 0) {
		device_printf(bwfm_pci_msgbuf_dev(sc),
		    "msgbuf: PCIe2 core not found in EROM\n");
		return (ENOENT);
	}
	mb->pcie2_base = pcie2;
	mb->intmask = BWFM_PCIE2REG_INTMASK;
	mb->mailboxint = BWFM_PCIE2REG_MAILBOXINT;
	mb->mailboxmask = BWFM_PCIE2REG_MAILBOXMASK;
	mb->h2d_mailbox_0 = BWFM_PCIE2REG_H2D_MAILBOX_0;

	sx_init(&mb->dcmd_sx, "bwfm_pci_dcmd_sx");
	mtx_init(&mb->dcmd_mtx, "bwfm_pci_dcmd_mtx", NULL, MTX_DEF);
	cv_init(&mb->dcmd_cv, "bwfm_pci_dcmd_cv");
	mtx_init(&mb->flow_mtx, "bwfm_pci_flow_mtx", NULL, MTX_DEF);
	cv_init(&mb->flow_cv, "bwfm_pci_flow_cv");
	mtx_init(&mb->pktid_mtx, "bwfm_pci_pktid_mtx", NULL, MTX_DEF);
	cv_init(&mb->pending_eapol_cv, "bwfm_pci_eapol_cv");
	mtx_init(&mb->rxpost_mtx, "bwfm_pci_rxpost_mtx", NULL, MTX_DEF);
	mtx_init(&mb->eventbuf_mtx, "bwfm_pci_eventbuf_mtx", NULL, MTX_DEF);
	mb->locks_inited = true;

	error = msgbuf_read_shared_info(mb);
	if (error != 0)
		goto fail;

	error = msgbuf_init_rings(mb);
	if (error != 0)
		goto fail;
	callout_init_mtx(&mb->rxfill_callout,
	    &mb->rings[BWFM_D2H_MSGRING_RX_COMPLETE].lock, 0);
	mb->rxfill_inited = true;

	error = msgbuf_init_scratch(mb);
	if (error != 0)
		goto fail;

	/* IOCTL request buffer: host memory fw reads the request from. */
	error = bwfm_pci_msgbuf_dma_alloc(mb, &mb->ioctbuf,
	    BWFM_MSGBUF_MAX_CTL_PKT_SIZE, "ioctbuf");
	if (error != 0)
		goto fail;

	/*
	 * Coherent event buffer pool, kept below 4GB by the DMA tag in
	 * dma_alloc.  The buffers live as long as the driver: fw writes
	 * one, we process it and re-post the same slot.
	 *
	 * Use BWFM_MSGBUF_MAX_EVENTBUF_POST rather than mb->max_eventbuf,
	 * which is not set until later in this function.
	 */
	{
		uint32_t i;
		for (i = 0; i < BWFM_MSGBUF_MAX_EVENTBUF_POST; i++) {
			error = bwfm_pci_msgbuf_dma_alloc(mb,
			    &mb->eventbufs[i], BWFM_MSGBUF_MAX_CTL_PKT_SIZE,
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
	mtx_init(&mb->event_q_mtx, "bwfm_pci_evtq", NULL, MTX_DEF);
	STAILQ_INIT(&mb->event_q);
	mb->event_q_len = 0;
	TASK_INIT(&mb->event_task, 0, msgbuf_event_task, mb);
	mb->event_q_inited = true;

	/* Flowring array + pktid table. */
	mb->flowrings = mallocarray(mb->max_flowrings,
	    sizeof(*mb->flowrings), M_DEVBUF, M_WAITOK | M_ZERO);
	if (mb->flowrings == NULL) {
		error = ENOMEM;
		goto fail;
	}
	mb->pktids = mallocarray(BWFM_MSGBUF_MAX_PKTID,
	    sizeof(*mb->pktids), M_DEVBUF, M_WAITOK | M_ZERO);
	if (mb->pktids == NULL) {
		error = ENOMEM;
		goto fail;
	}
	mb->pktid_next_hint = 1;

	/*
	 * TX mbuf DMA tag: single-segment Ethernet frames (txmbuf
	 * defragments first), 4-byte aligned, 64-bit DMA addresses.
	 */
	error = bus_dma_tag_create(bus_get_dma_tag(DEV(mb)),
	    /* alignment */ 4, /* boundary */ 0,
	    bwfm_pci_dma32 ? BUS_SPACE_MAXADDR_32BIT : BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR, NULL, NULL,
	    /* maxsize */ MCLBYTES, /* nsegments */ 1, /* maxsegsize */ MCLBYTES,
	    0, NULL, NULL, &mb->tx_mbuf_tag);
	if (error != 0) {
		device_printf(DEV(mb),
		    "msgbuf: tx_mbuf_tag create failed %d\n", error);
		goto fail;
	}

	/* RX mbuf DMA tag: same constraints, up to the 8K ctl pkt size. */
	error = bus_dma_tag_create(bus_get_dma_tag(DEV(mb)),
	    /* alignment */ 4, /* boundary */ 0,
	    bwfm_pci_dma32 ? BUS_SPACE_MAXADDR_32BIT : BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR, NULL, NULL,
	    /* maxsize */ BWFM_MSGBUF_MAX_CTL_PKT_SIZE, /* nsegments */ 1,
	    /* maxsegsize */ BWFM_MSGBUF_MAX_CTL_PKT_SIZE,
	    0, NULL, NULL, &mb->rx_mbuf_tag);
	if (error != 0) {
		device_printf(DEV(mb),
		    "msgbuf: rx_mbuf_tag create failed %d\n", error);
		goto fail;
	}

	/* RXPOST tracking table. */
	mb->rxposts = mallocarray(BWFM_MSGBUF_MAX_RXPOST,
	    sizeof(*mb->rxposts), M_DEVBUF, M_WAITOK | M_ZERO);
	if (mb->rxposts == NULL) {
		error = ENOMEM;
		goto fail;
	}
	mb->rxpost_next_hint = 1;

	/* One DMA map per slot, made here once rather than per packet. */
	{
		uint32_t k;

		for (k = 1; k < BWFM_MSGBUF_MAX_PKTID; k++) {
			error = bus_dmamap_create(mb->tx_mbuf_tag, 0,
			    &mb->pktids[k].map);
			if (error != 0)
				goto fail;
			mb->pktid_maps = k;
		}
		for (k = 1; k < BWFM_MSGBUF_MAX_RXPOST; k++) {
			error = bus_dmamap_create(mb->rx_mbuf_tag, 0,
			    &mb->rxposts[k].map);
			if (error != 0)
				goto fail;
			mb->rxpost_maps = k;
		}
	}
	mb->max_eventbuf = BWFM_MSGBUF_MAX_EVENTBUF_POST;
	/* Clamp the max_rxbufpost fw advertised to the tunable. */
	if (bwfm_pci_rxbufpost > BWFM_MSGBUF_MAX_RXPOST - 1)
		bwfm_pci_rxbufpost = BWFM_MSGBUF_MAX_RXPOST - 1;
	if (bwfm_pci_rxbufpost < BWFM_MSGBUF_RXBUFPOST_THRESHOLD)
		bwfm_pci_rxbufpost = BWFM_MSGBUF_RXBUFPOST_THRESHOLD;
	device_printf(DEV(mb), "msgbuf: fw max_rxbufpost %u, using %d\n",
	    mb->max_rxbufpost, bwfm_pci_rxbufpost);
	if (mb->max_rxbufpost == 0 || mb->max_rxbufpost > bwfm_pci_rxbufpost)
		mb->max_rxbufpost = bwfm_pci_rxbufpost;
	mb->rxpost_batch = MAX(1, MIN(bwfm_pci_rxpost_batch,
	    (int)mb->max_rxbufpost / 8));

	/*
	 * Mark attached before binding the interrupt: the ithread only
	 * re-arms when mb->attached is set, which is how detach stops it.
	 */
	atomic_store_bool(&mb->attached, true);

	/*
	 * Clear stale MAILBOXINT bits left from an earlier boot.  The
	 * register is W1C, so write back only the bits that are set, as
	 * the ISR does.  Writing all-ones risks setting reserved bits on
	 * chips that are not strictly W1C, and is suspected of wedging
	 * attach.
	 */
	pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXMASK, 0);
	{
		uint32_t stale = pcie2_read32(mb, BWFM_PCIE2REG_MAILBOXINT);
		if (stale != 0 && stale != 0xffffffff)
			pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXINT, stale);
	}

	error = bwfm_pci_msgbuf_bind_intr(sc, bwfm_pci_msgbuf_isr_filter,
	    bwfm_pci_msgbuf_isr_thread, mb);
	if (error != 0) {
		atomic_store_bool(&mb->attached, false);
		goto fail;
	}

	/* Unmask the chip's interrupts. */
	pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXMASK,
	    BWFM_PCIE_MB_INT_D2H_DB | BWFM_PCIE_MB_INT_FN0);

	/*
	 * With the interrupt armed, prime the RX pools.  Event buffers go
	 * on the control ring (fw uses one per WL_EVENT) and data buffers
	 * on the rxpost ring (one per received frame).  They must be
	 * posted before fw can DMA any event or data.
	 */
	{
		uint32_t posted;
		(void)msgbuf_event_refill(mb);
		posted = mb->cur_eventbuf;
		MDPRINTF(mb, 0,
		    "msgbuf: posted %u/%u event buffers\n",
		    posted, mb->max_eventbuf);
		if (posted == 0) {
			/*
			 * Fw needs at least one WL_EVENT buffer.  With none,
			 * the first DCMD hard-wedges the host: fw sends an
			 * unsolicited event, has nowhere to write it, and
			 * the next MMIO hangs.  Fail attach instead.
			 */
			device_printf(DEV(mb),
			    "msgbuf: refusing attach: event-buf pool "
			    "empty.  Likely 8KB MJUM9BYTES cluster above "
			    "4GB with no bounce pages.  Retry (mbufs may "
			    "come from below-4GB pool), or fix by using "
			    "bus_dmamem_alloc for event bufs.\n");
			atomic_store_bool(&mb->attached, false);
			error = ENOMEM;
			goto fail;
		}
		mtx_lock(&mb->rings[BWFM_D2H_MSGRING_RX_COMPLETE].lock);
		posted = mb->cur_rxbufpost;
		msgbuf_rx_refill(mb);
		posted = mb->cur_rxbufpost - posted;
		mtx_unlock(&mb->rings[BWFM_D2H_MSGRING_RX_COMPLETE].lock);
		MDPRINTF(mb, 0,
		    "msgbuf: posted %u/%u rx data buffers\n",
		    posted, mb->max_rxbufpost);
	}

	device_printf(bwfm_pci_msgbuf_dev(sc),
	    "msgbuf: attach OK — rings + scratch + ioctbuf + ISR bound\n");
	return (0);

fail:
	/* Stop bus mastering before freeing memory the firmware may write. */
	pci_disable_busmaster(bwfm_pci_msgbuf_dev(sc));
	bwfm_pci_msgbuf_detach(sc);
	return (error);
}

void
bwfm_pci_msgbuf_detach(struct bwfm_pci_softc *sc)
{
	struct bwfm_pci_msgbuf *mb = bwfm_pci_msgbuf_state(sc);
	bool was_attached;
	int i;

	if (mb == NULL)
		return;

	was_attached = MB_ATTACHED(mb);

	/* Mask the chip interrupt and unbind before freeing DMA memory. */
	if (was_attached) {
		pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXMASK, 0);
		atomic_store_bool(&mb->attached, false);
	}
	bwfm_pci_msgbuf_unbind_intr(sc);
	/* Mask again now that no handler can run. */
	if (mb->pcie2_base != 0)
		pcie2_write32(mb, BWFM_PCIE2REG_MAILBOXMASK, 0);
	if (mb->rxfill_inited) {
		callout_drain(&mb->rxfill_callout);
		mb->rxfill_inited = false;
	}

	mbufq_drain(&mb->rx_upq);

	/* Reclaim posted RX/event mbufs before killing rx_mbuf_tag. */
	if (mb->rxposts != NULL) {
		uint32_t k;
		for (k = 1; k < BWFM_MSGBUF_MAX_RXPOST; k++) {
			bus_dmamap_t map = NULL;
			uint8_t type = 0;
			struct mbuf *m = rxpost_release(mb, k, &map, &type);
			if (m != NULL) {
				if (map != NULL)
					bus_dmamap_unload(mb->rx_mbuf_tag, map);
				m_freem(m);
			}
			/* a NULL map is valid too; destroy each one made */
			if (k <= mb->rxpost_maps)
				bus_dmamap_destroy(mb->rx_mbuf_tag,
				    mb->rxposts[k].map);
			mb->rxposts[k].map = NULL;
		}
		mb->rxpost_maps = 0;
		free(mb->rxposts, M_DEVBUF);
		mb->rxposts = NULL;
	}
	if (mb->rx_mbuf_tag != NULL) {
		bus_dma_tag_destroy(mb->rx_mbuf_tag);
		mb->rx_mbuf_tag = NULL;
	}

	/* Reclaim in-flight TX mbufs before destroying tx_mbuf_tag. */
	if (mb->pktids != NULL) {
		uint32_t k;
		for (k = 1; k < BWFM_MSGBUF_MAX_PKTID; k++) {
			bus_dmamap_t map = NULL;
			struct mbuf *m = pktid_release(mb, k, &map, false);
			if (m != NULL) {
				if (map != NULL)
					bus_dmamap_unload(mb->tx_mbuf_tag, map);
				m_freem(m);
			}
			/* a NULL map is valid too; destroy each one made */
			if (k <= mb->pktid_maps)
				bus_dmamap_destroy(mb->tx_mbuf_tag,
				    mb->pktids[k].map);
			mb->pktids[k].map = NULL;
		}
		mb->pktid_maps = 0;
		free(mb->pktids, M_DEVBUF);
		mb->pktids = NULL;
	}
	if (mb->tx_mbuf_tag != NULL) {
		bus_dma_tag_destroy(mb->tx_mbuf_tag);
		mb->tx_mbuf_tag = NULL;
	}

	/*
	 * Free the flowring buffers.  Fw keeps ring state until it sees
	 * FLOW_RING_DELETE (bwfm_pci_msgbuf_flowring_delete_all); detach
	 * only frees the host side, and the chip faults if it DMAs to a
	 * freed ring.
	 */
	if (mb->flowrings != NULL) {
		uint32_t k;
		for (k = 0; k < mb->max_flowrings; k++) {
			struct bwfm_pci_ring *fring = &mb->flowrings[k].ring;
			if (fring->inited) {
				mtx_destroy(&fring->lock);
				fring->inited = false;
			}
			bwfm_pci_msgbuf_dma_free(mb, &fring->buf);
		}
		free(mb->flowrings, M_DEVBUF);
		mb->flowrings = NULL;
	}

	for (i = 0; i < BWFM_NROF_COMMON_MSGRINGS; i++) {
		struct bwfm_pci_ring *ring = &mb->rings[i];
		if (ring->inited) {
			mtx_destroy(&ring->lock);
			ring->inited = false;
		}
		bwfm_pci_msgbuf_dma_free(mb, &ring->buf);
	}
	bwfm_pci_msgbuf_dma_free(mb, &mb->scratch);
	bwfm_pci_msgbuf_dma_free(mb, &mb->ringupd);
	bwfm_pci_msgbuf_dma_free(mb, &mb->ioctbuf);
	for (i = 0; i < BWFM_MSGBUF_MAX_EVENTBUF_POST; i++)
		bwfm_pci_msgbuf_dma_free(mb, &mb->eventbufs[i]);

	/* A failed attach gets here with attached false; free what it made. */
	if (mb->event_q_inited) {
		struct bwfm_pci_event *ep;

		/* Drain the event task first — it may hold event_q_mtx. */
		taskqueue_drain(taskqueue_thread, &mb->event_task);
		while ((ep = STAILQ_FIRST(&mb->event_q)) != NULL) {
			STAILQ_REMOVE_HEAD(&mb->event_q, link);
			free(ep, M_DEVBUF);
		}
		mb->event_q_len = 0;
		mtx_destroy(&mb->event_q_mtx);
		mb->event_q_inited = false;
	}
	if (mb->locks_inited) {
		cv_destroy(&mb->flow_cv);
		mtx_destroy(&mb->flow_mtx);
		cv_destroy(&mb->pending_eapol_cv);
		mtx_destroy(&mb->pktid_mtx);
		mtx_destroy(&mb->rxpost_mtx);
		mtx_destroy(&mb->eventbuf_mtx);
		cv_destroy(&mb->dcmd_cv);
		mtx_destroy(&mb->dcmd_mtx);
		sx_destroy(&mb->dcmd_sx);
		mb->locks_inited = false;
	}
	atomic_store_bool(&mb->attached, false);
}
