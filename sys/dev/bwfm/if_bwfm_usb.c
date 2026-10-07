/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC USB transport glue for bwfm.
 *
 * Lifecycle (BCM43236 example):
 *   1. uhub matches us via STRUCT_USB_HOST_ID; probe accepts iface 0.
 *   2. attach() discovers bulk-IN / bulk-OUT endpoints, sets up the
 *      usb_xfer slots, then issues DL_GETVER to read the boot ROM.
 *   3. If the chip reports BWFM_POSTBOOT_ID, firmware already runs and
 *      we jump straight to bwfm_attach() to wire net80211.
 *   4. Otherwise we look up the chip in bwfm_chip_table, fetch the
 *      firmware(9) blob, push it through DL_START / chunked bulk-OUT /
 *      DL_GO, then poll DL_GETVER until BWFM_POSTBOOT_ID appears.
 *      Finally we call bwfm_attach().
 *
 * Bus ops:
 *   bs_txctl   USB vendor-class control OUT (bmReq 0x21, bReq 0)
 *   bs_rxctl   Drained by the dedicated EP0-pump kthread; the core
 *              owns the wakeup/match logic via bwfm_rxctl().
 *   bs_txdata  Bulk-OUT pipe (post-boot data path).
 *   bs_stop    Wakes the kthread, then unsets transfers.
 *
 * The download protocol and the control-pipe requests follow OpenBSD's
 * sys/dev/usb/if_bwfm_usb.c (Patrick Wildt) and Linux brcmfmac usb.c
 * (Broadcom); the code was written for this driver.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/firmware.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>

#include "bwfmvar.h"
#include "bwfmreg.h"

#define	BWFM_USB_DESC	"Broadcom FullMAC USB"

/*
 * USB transfer slots.
 *
 * BWFM_BULK_DL_OUT is used during the firmware download phase only;
 * once the chip is running it's effectively idle.  BWFM_BULK_TX_OUT
 * carries post-boot data frames.  BWFM_BULK_RX_IN feeds events +
 * data frames into bwfm_rx_frame().  BWFM_INT_IN is informational
 * dongle status (8 bytes); we count + ignore.
 */
enum {
	BWFM_BULK_DL_OUT,
	BWFM_BULK_TX_OUT,
	BWFM_BULK_RX_IN,
	BWFM_INT_IN,
	BWFM_N_XFER,
};

#define	BWFM_TX_BUFSZ		2048
#define	BWFM_CTL_REPLY_MAX	4096

/*
 * Per-mbuf TX queue node.  Caller-provided mbufs are wrapped into one
 * of these so the bulk-OUT callback can dequeue + ship + free in its
 * own context without referencing the original net80211 caller.
 */
struct bwfm_tx_pending {
	STAILQ_ENTRY(bwfm_tx_pending)	link;	/* queue linkage */
	struct mbuf			*m;	/* the frame to send */
};
STAILQ_HEAD(bwfm_tx_queue, bwfm_tx_pending);

/*
 * Per-USB-attach state.  Embeds a bwfm_softc as its first member so
 * the core can recover us via container_of-style casts (the core
 * itself only sees a struct bwfm_softc *).
 */
struct bwfm_usb_softc {
	struct bwfm_softc	 bus_sc;	/* shared core state (first member) */
	struct usb_device	*sc_udev;	/* USB device handle */
	struct usb_xfer		*sc_xfer[BWFM_N_XFER];	/* USB transfer slots */
	struct proc		*sc_ctlrx_proc;	/* control-read thread */
	u_int			 sc_ctl_want;	/* sent, reply not yet read */
	uint8_t			 sc_iface_index;	/* USB interface number */
	uint8_t			 sc_rx_ep;	/* bulk-in endpoint */
	uint8_t			 sc_tx_ep;	/* bulk-out endpoint */

	struct bwfm_tx_queue	 sc_tx_q;	/* frames waiting to send */
	bool			 sc_tx_running;	/* true while the tx pipe is busy */

	/* Firmware download cursor (DL phase only). */
	const uint8_t		*sc_dl_buf;
	size_t			 sc_dl_len;
	size_t			 sc_dl_sent;
	int			 sc_dl_err;
	int			 sc_dl_done;
};

#define	SC_TO_USB(sc)	__containerof((sc), struct bwfm_usb_softc, bus_sc)

static const STRUCT_USB_HOST_ID bwfm_usb_devs[] = {
	{ USB_VPI(BWFM_USB_VENDOR_BROADCOM,
	    BWFM_USB_PRODUCT_BCM43143, 0) },
	{ USB_VPI(BWFM_USB_VENDOR_BROADCOM,
	    BWFM_USB_PRODUCT_BCM43236, 0) },
	{ USB_VPI(BWFM_USB_VENDOR_BROADCOM,
	    BWFM_USB_PRODUCT_BCM43242, 0) },
	{ USB_VPI(BWFM_USB_VENDOR_BROADCOM,
	    BWFM_USB_PRODUCT_BCM43569, 0) },
	{ USB_VPI(BWFM_USB_VENDOR_BROADCOM,
	    BWFM_USB_PRODUCT_BCMFW,    0) },
};

static usb_callback_t	bwfm_usb_dl_cb;
static usb_callback_t	bwfm_usb_bulk_rx_cb;
static usb_callback_t	bwfm_usb_bulk_tx_cb;
static usb_callback_t	bwfm_usb_int_in_cb;

static void	bwfm_usb_ctlrx_thread(void *);

static int	bwfm_usb_dl_cmd(struct bwfm_usb_softc *, uint8_t,
		    void *, int);
static int	bwfm_usb_load_firmware(struct bwfm_usb_softc *,
		    const uint8_t *, size_t);
static int	bwfm_usb_read_bootrom(struct bwfm_usb_softc *);
static int	bwfm_usb_enumerate_endpoints(struct bwfm_usb_softc *,
		    struct usb_attach_arg *);

/* Bus ops, forward-declared so the const table can refer to them. */
static int	bwfm_usb_bs_txctl(struct bwfm_softc *, const void *, size_t);
static int	bwfm_usb_bs_rxctl(struct bwfm_softc *, void *, size_t *, int);
static int	bwfm_usb_bs_txdata(struct bwfm_softc *, struct mbuf *);
static void	bwfm_usb_bs_stop(struct bwfm_softc *);

static const struct bwfm_bus_ops bwfm_usb_bus_ops = {
	.bs_txctl = bwfm_usb_bs_txctl,
	.bs_rxctl = bwfm_usb_bs_rxctl,
	.bs_txdata = bwfm_usb_bs_txdata,
	.bs_stop = bwfm_usb_bs_stop,
};

static const struct usb_config bwfm_usb_config[BWFM_N_XFER] = {
	[BWFM_BULK_DL_OUT] = {
		.type = UE_BULK,
		.endpoint = UE_ADDR_ANY,
		.direction = UE_DIR_OUT,
		.bufsize = BWFM_TRX_RDL_CHUNK,
		.flags = { .pipe_bof = 1, .force_short_xfer = 1, },
		.callback = bwfm_usb_dl_cb,
		.timeout = 5000,
	},
	[BWFM_BULK_TX_OUT] = {
		.type = UE_BULK,
		.endpoint = UE_ADDR_ANY,
		.direction = UE_DIR_OUT,
		.bufsize = BWFM_TX_BUFSZ,
		.flags = { .pipe_bof = 1, .force_short_xfer = 1, },
		.callback = bwfm_usb_bulk_tx_cb,
		.timeout = 5000,
	},
	[BWFM_BULK_RX_IN] = {
		.type = UE_BULK,
		.endpoint = UE_ADDR_ANY,
		.direction = UE_DIR_IN,
		.bufsize = 2048,
		.flags = { .pipe_bof = 1, .short_xfer_ok = 1, },
		.callback = bwfm_usb_bulk_rx_cb,
		.timeout = 0,
	},
	[BWFM_INT_IN] = {
		.type = UE_INTERRUPT,
		.endpoint = UE_ADDR_ANY,
		.direction = UE_DIR_IN,
		.bufsize = 64,
		.flags = { .pipe_bof = 1, .short_xfer_ok = 1, },
		.callback = bwfm_usb_int_in_cb,
		.timeout = 0,
	},
};

/*
 * Endpoint discovery.  The boot-ROM-mode interface has 2 bulk
 * endpoints (one IN, one OUT); after firmware boot the same two
 * endpoints carry post-boot data.  Some images expose 4 endpoints
 * (separate RX/TX for data vs. firmware download); we treat the
 * first matching pair as the canonical bulk pipes.
 */
static int
bwfm_usb_enumerate_endpoints(struct bwfm_usb_softc *sc,
    struct usb_attach_arg *uaa)
{
	struct usb_endpoint_descriptor *ed;

	/*
	 * Walk every endpoint descriptor in the interface and record
	 * the first bulk-IN and bulk-OUT addresses.
	 *
	 * usbd_find_descriptor's subtype filter compares offset-2 of
	 * the descriptor — for endpoint descriptors that byte is
	 * bEndpointAddress, not bmAttributes — so we cannot filter
	 * by transfer type via the subtype mask.  Skip the filter
	 * and check bmAttributes ourselves.
	 */
	ed = NULL;
	while ((ed = usbd_find_descriptor(uaa->device, ed,
	    sc->sc_iface_index, UDESC_ENDPOINT, 0xff, 0, 0)) != NULL) {
		if ((ed->bmAttributes & UE_XFERTYPE) != UE_BULK)
			continue;
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN) {
			if (sc->sc_rx_ep == 0)
				sc->sc_rx_ep = ed->bEndpointAddress;
		} else {
			if (sc->sc_tx_ep == 0)
				sc->sc_tx_ep = ed->bEndpointAddress;
		}
	}
	if (sc->sc_rx_ep == 0 || sc->sc_tx_ep == 0) {
		device_printf(sc->bus_sc.sc_dev,
		    "missing bulk endpoints: rx=0x%02x tx=0x%02x\n",
		    sc->sc_rx_ep, sc->sc_tx_ep);
		return (ENXIO);
	}
	return (0);
}

/*
 * Vendor-defined boot-ROM control request.  All boot-ROM commands
 * share this shape: bmRequestType = 0xc0 (device->host vendor iface),
 * bRequest = cmd, payload of `len` bytes.  Synchronous.
 */
static int
bwfm_usb_dl_cmd(struct bwfm_usb_softc *sc, uint8_t cmd, void *buf, int len)
{
	struct usb_device_request req;
	usb_error_t err;
	uint16_t alen;

	req.bmRequestType = UT_READ_VENDOR_INTERFACE;
	req.bRequest = cmd;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_iface_index);
	USETW(req.wLength, len);

	err = usbd_do_request_flags(sc->sc_udev, NULL, &req, buf,
	    USB_SHORT_XFER_OK, &alen, USB_DEFAULT_TIMEOUT);
	if (err != USB_ERR_NORMAL_COMPLETION) {
		device_printf(sc->bus_sc.sc_dev,
		    "boot-ROM cmd 0x%02x failed: %s (got %u bytes)\n",
		    cmd, usbd_errstr(err), alen);
		return (EIO);
	}
	return (0);
}

/*
 * DL bulk-OUT callback.  Drives the firmware download cursor: each
 * SETUP transition pulls the next chunk from sc->sc_dl_buf; when the
 * last chunk has been sent we set sc_dl_done and wake the loader.
 */
static void
bwfm_usb_dl_cb(struct usb_xfer *xfer, usb_error_t error)
{
	struct bwfm_usb_softc *sc = usbd_xfer_softc(xfer);
	struct usb_page_cache *pc;
	size_t chunk;

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		sc->sc_dl_sent += usbd_xfer_frame_len(xfer, 0);
		if (sc->sc_dl_sent >= sc->sc_dl_len) {
			sc->sc_dl_done = 1;
			wakeup(&sc->sc_dl_done);
			break;
		}
		/* FALLTHROUGH */
	case USB_ST_SETUP:
		chunk = sc->sc_dl_len - sc->sc_dl_sent;
		if (chunk > BWFM_TRX_RDL_CHUNK)
			chunk = BWFM_TRX_RDL_CHUNK;
		if (chunk == 0)
			break;
		pc = usbd_xfer_get_frame(xfer, 0);
		usbd_copy_in(pc, 0, sc->sc_dl_buf + sc->sc_dl_sent, chunk);
		usbd_xfer_set_frame_len(xfer, 0, chunk);
		usbd_transfer_submit(xfer);
		break;
	default:
		if (error != USB_ERR_CANCELLED) {
			sc->sc_dl_err = EIO;
			wakeup(&sc->sc_dl_done);
		}
		break;
	}
}

/*
 * Push a TRX-wrapped firmware image into the boot ROM:
 *   1. DL_START -> chip enters DL_WAITING
 *   2. chunked bulk-OUT writes until image is in
 *   3. DL_GETSTATE confirms DL_RUNNABLE
 *   4. DL_GO transfers control to the loaded image
 */
static int
bwfm_usb_load_firmware(struct bwfm_usb_softc *sc, const uint8_t *ucode,
    size_t size)
{
	const struct bwfm_trx_header *trx;
	struct bwfm_rdl_state state;
	int error;

	if (size < sizeof(*trx))
		return (EINVAL);
	trx = (const struct bwfm_trx_header *)ucode;
	if (le32toh(trx->magic) != BWFM_TRX_MAGIC ||
	    (le32toh(trx->flag_version) & BWFM_TRX_UNCOMP_IMAGE) == 0) {
		device_printf(sc->bus_sc.sc_dev, "invalid TRX header\n");
		return (EINVAL);
	}

	memset(&state, 0, sizeof(state));
	error = bwfm_usb_dl_cmd(sc, BWFM_DL_START, &state, sizeof(state));
	if (error != 0)
		return (error);
	if (le32toh(state.state) != BWFM_DL_WAITING) {
		device_printf(sc->bus_sc.sc_dev,
		    "DL_START refused (state=%u)\n", le32toh(state.state));
		return (EIO);
	}

	sc->sc_dl_buf = ucode;
	sc->sc_dl_len = size;
	sc->sc_dl_sent = 0;
	sc->sc_dl_err = 0;
	sc->sc_dl_done = 0;

	mtx_lock(&sc->bus_sc.sc_mtx);
	usbd_transfer_start(sc->sc_xfer[BWFM_BULK_DL_OUT]);
	while (sc->sc_dl_done == 0 && sc->sc_dl_err == 0 &&
	    !sc->bus_sc.sc_dying) {
		(void)mtx_sleep(&sc->sc_dl_done, &sc->bus_sc.sc_mtx, 0,
		    "bwfmdl", hz * 5);
	}
	usbd_transfer_stop(sc->sc_xfer[BWFM_BULK_DL_OUT]);
	mtx_unlock(&sc->bus_sc.sc_mtx);

	if (sc->sc_dl_err != 0)
		return (sc->sc_dl_err);

	memset(&state, 0, sizeof(state));
	error = bwfm_usb_dl_cmd(sc, BWFM_DL_GETSTATE, &state, sizeof(state));
	if (error != 0)
		return (error);
	if (le32toh(state.state) != BWFM_DL_RUNNABLE) {
		device_printf(sc->bus_sc.sc_dev,
		    "chip not runnable after upload (state=%u)\n",
		    le32toh(state.state));
		return (EIO);
	}
	return (bwfm_usb_dl_cmd(sc, BWFM_DL_GO, &state, sizeof(state)));
}

/* read the boot ROM version from the chip */
static int
bwfm_usb_read_bootrom(struct bwfm_usb_softc *sc)
{
	memset(&sc->bus_sc.sc_brom, 0, sizeof(sc->bus_sc.sc_brom));
	return (bwfm_usb_dl_cmd(sc, BWFM_DL_GETVER, &sc->bus_sc.sc_brom,
	    sizeof(sc->bus_sc.sc_brom)));
}

/*
 * Bulk-IN callback.  Pulls full frames out of the pipe and hands them
 * to the bwfm core via bwfm_rx_frame().  Resubmits unconditionally so
 * the pipe keeps draining.
 *
 * The USB framework invokes us with sc_mtx held; bwfm_rx_frame may
 * call ieee80211_input_all which takes net80211 locks and can
 * re-enter the driver.  Drop sc_mtx for the duration of the input
 * call (run(4) pattern) and re-acquire before falling through to
 * usbd_transfer_submit.
 */
static void
bwfm_usb_bulk_rx_cb(struct usb_xfer *xfer, usb_error_t error)
{
	struct bwfm_usb_softc *sc = usbd_xfer_softc(xfer);
	struct usb_page_cache *pc;
	struct mbuf *m;
	int actlen;

	usbd_xfer_status(xfer, &actlen, NULL, NULL, NULL);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		if (actlen <= 0)
			goto resubmit;
		m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
		if (m == NULL)
			goto resubmit;
		pc = usbd_xfer_get_frame(xfer, 0);
		usbd_copy_out(pc, 0, mtod(m, void *), actlen);
		m->m_len = m->m_pkthdr.len = actlen;
		mtx_unlock(&sc->bus_sc.sc_mtx);
		bwfm_rx_frame(&sc->bus_sc, m);
		mtx_lock(&sc->bus_sc.sc_mtx);
		/* FALLTHROUGH */
	case USB_ST_SETUP:
resubmit:
		usbd_xfer_set_frame_len(xfer, 0, usbd_xfer_max_len(xfer));
		usbd_transfer_submit(xfer);
		break;
	default:
		if (error != USB_ERR_CANCELLED) {
			usbd_xfer_set_stall(xfer);
			goto resubmit;
		}
		break;
	}
}

/*
 * Bulk-OUT data callback.  bs_txdata enqueues mbufs onto sc_tx_q and
 * kicks the xfer; on each callback we dequeue one mbuf, prepend the
 * 4-byte BCDC data header, copy the mbuf payload in, submit, and
 * free the mbuf.  Synchronisation is via sc_mtx, which the USB
 * framework holds when the callback fires.
 */
static void
bwfm_usb_bulk_tx_cb(struct usb_xfer *xfer, usb_error_t error)
{
	struct bwfm_usb_softc *sc = usbd_xfer_softc(xfer);
	struct usb_page_cache *pc;
	struct bwfm_tx_pending *p;
	struct bwfm_bcdc_hdr hdr;
	struct mbuf *m;
	int actlen, payload_len;

	usbd_xfer_status(xfer, &actlen, NULL, NULL, NULL);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		/* FALLTHROUGH */
	case USB_ST_SETUP:
tr_setup_tx:
		p = STAILQ_FIRST(&sc->sc_tx_q);
		if (p == NULL) {
			sc->sc_tx_running = false;
			return;
		}
		STAILQ_REMOVE_HEAD(&sc->sc_tx_q, link);
		m = p->m;
		free(p, M_BWFM);

		payload_len = m->m_pkthdr.len;
		if (payload_len + (int)sizeof(hdr) > BWFM_TX_BUFSZ) {
			m_freem(m);
			goto tr_setup_tx;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.flags = BWFM_BCDC_FLAG_VER(BWFM_BCDC_FLAG_PROTO_VER);
		pc = usbd_xfer_get_frame(xfer, 0);
		usbd_copy_in(pc, 0, &hdr, sizeof(hdr));
		usbd_m_copy_in(pc, sizeof(hdr), m, 0, payload_len);
		usbd_xfer_set_frame_len(xfer, 0,
		    sizeof(hdr) + payload_len);
		m_freem(m);
		usbd_transfer_submit(xfer);
		sc->sc_tx_running = true;
		return;
	default:
		if (error == USB_ERR_CANCELLED) {
			sc->sc_tx_running = false;
			return;
		}
		device_printf(sc->bus_sc.sc_dev, "TX error: %s\n",
		    usbd_errstr(error));
		if (error != USB_ERR_STALLED)
			goto tr_setup_tx;
		sc->sc_tx_running = false;
		return;
	}
}

/* keep the interrupt endpoint's status transfer running */
static void
bwfm_usb_int_in_cb(struct usb_xfer *xfer, usb_error_t error)
{
	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		/* FALLTHROUGH */
	case USB_ST_SETUP:
		usbd_xfer_set_frame_len(xfer, 0, usbd_xfer_max_len(xfer));
		usbd_transfer_submit(xfer);
		break;
	default:
		if (error != USB_ERR_CANCELLED)
			usbd_xfer_set_stall(xfer);
		break;
	}
}

/*
 * EP0 control-IN pump.  Loops on UT_READ_CLASS_INTERFACE bRequest 1
 * pulls (the way the chip emits BCDC replies on USB) and shuttles
 * each response into bwfm_rxctl() for reqid demultiplex.  Exits on
 * sc_dying; clears sc_ctlrx_proc and wakes anyone waiting for the
 * thread to exit (the detach / fail teardown path).
 */
static void
bwfm_usb_ctlrx_thread(void *arg)
{
	struct bwfm_usb_softc *sc = arg;
	uint8_t buf[BWFM_CTL_REPLY_MAX];
	struct usb_device_request req;
	uint16_t actlen;
	usb_error_t err;

	while (!sc->bus_sc.sc_dying) {
		/*
		 * Read only while a sent command is waiting for its reply.
		 * A read kept pending on the control pipe holds the
		 * device's control lock, so each command's control write
		 * queues behind it, often for several rounds.  That makes
		 * a dcmd take seconds and the join sequence long enough
		 * for wpa_supplicant's 10 s authentication timeout to
		 * expire before the firmware joins.
		 */
		mtx_lock(&sc->bus_sc.sc_ctl_mtx);
		while (sc->sc_ctl_want == 0 && !sc->bus_sc.sc_dying)
			mtx_sleep(&sc->sc_ctl_want, &sc->bus_sc.sc_ctl_mtx,
			    0, "bwfmcti", hz / 2);
		if (TAILQ_EMPTY(&sc->bus_sc.sc_ctl_pending))
			sc->sc_ctl_want = 0;	/* waiter gave up */
		mtx_unlock(&sc->bus_sc.sc_ctl_mtx);
		if (sc->bus_sc.sc_dying)
			break;
		if (sc->sc_ctl_want == 0)
			continue;

		req.bmRequestType = UT_READ_CLASS_INTERFACE;
		req.bRequest = 1;
		USETW(req.wValue, 0);
		USETW(req.wIndex, sc->sc_iface_index);
		USETW(req.wLength, sizeof(buf));
		actlen = 0;
		err = usbd_do_request_flags(sc->sc_udev, NULL, &req, buf,
		    USB_SHORT_XFER_OK, &actlen, 100);
		if (sc->bus_sc.sc_dying)
			break;
		if (err == USB_ERR_TIMEOUT)
			continue;
		if (err != USB_ERR_NORMAL_COMPLETION) {
			pause("bwfmctl", hz / 10);
			continue;
		}
		if (actlen >= sizeof(struct bwfm_bcdc_dcmd)) {
			bwfm_rxctl(&sc->bus_sc, buf, actlen);
			mtx_lock(&sc->bus_sc.sc_ctl_mtx);
			if (sc->sc_ctl_want > 0)
				sc->sc_ctl_want--;
			mtx_unlock(&sc->bus_sc.sc_ctl_mtx);
		}
	}

	mtx_lock(&sc->bus_sc.sc_mtx);
	sc->sc_ctlrx_proc = NULL;
	wakeup(&sc->sc_ctlrx_proc);
	mtx_unlock(&sc->bus_sc.sc_mtx);
	kproc_exit(0);
}

/* ----------------- bwfm_bus_ops implementations ---------------- */

static int
bwfm_usb_bs_txctl(struct bwfm_softc *bsc, const void *buf, size_t len)
{
	struct bwfm_usb_softc *sc = SC_TO_USB(bsc);
	struct usb_device_request req;
	usb_error_t err;

	req.bmRequestType = UT_WRITE_CLASS_INTERFACE;
	req.bRequest = 0;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_iface_index);
	USETW(req.wLength, len);

	err = usbd_do_request(sc->sc_udev, NULL, &req,
	    __DECONST(void *, buf));
	if (err != USB_ERR_NORMAL_COMPLETION) {
		DPRINTF(bsc, 0, "txctl failed: %s\n", usbd_errstr(err));
		return (EIO);
	}
	mtx_lock(&bsc->sc_ctl_mtx);
	sc->sc_ctl_want++;
	wakeup(&sc->sc_ctl_want);
	mtx_unlock(&bsc->sc_ctl_mtx);
	return (0);
}

/* unused: replies arrive via the control-read thread */
static int
bwfm_usb_bs_rxctl(struct bwfm_softc *bsc, void *buf, size_t *lenp,
    int timeout_ms)
{
	/*
	 * Not used by the core: the ctlrx kthread
	 * (bwfm_usb_ctlrx_thread) calls bwfm_rxctl() directly with each
	 * incoming reply, and bwfm_dcmd_get() waits on the per-request
	 * sleep channel.  The stub keeps the vtable shape the same for
	 * transports that prefer a caller-pulled rxctl.
	 */
	(void)bsc;
	(void)buf;
	(void)lenp;
	(void)timeout_ms;
	return (ENOTSUP);
}

/* queue a data frame to send */
static int
bwfm_usb_bs_txdata(struct bwfm_softc *bsc, struct mbuf *m)
{
	struct bwfm_usb_softc *sc = SC_TO_USB(bsc);
	struct bwfm_tx_pending *p;
	int err;

	/* 802.11 from net80211 -> 802.3 for the firmware; see bwfm.c. */
	if ((err = bwfm_deencap_80211(&m)) != 0) {
		if (m != NULL)
			m_freem(m);
		return (err == EAGAIN ? 0 : err);	/* EAGAIN: mgmt, dropped */
	}
	p = malloc(sizeof(*p), M_BWFM, M_NOWAIT);
	if (p == NULL) {
		m_freem(m);
		return (ENOMEM);
	}
	p->m = m;

	mtx_lock(&bsc->sc_mtx);
	if (bsc->sc_dying) {
		mtx_unlock(&bsc->sc_mtx);
		m_freem(m);
		free(p, M_BWFM);
		return (ENXIO);
	}
	STAILQ_INSERT_TAIL(&sc->sc_tx_q, p, link);
	if (!sc->sc_tx_running)
		usbd_transfer_start(sc->sc_xfer[BWFM_BULK_TX_OUT]);
	mtx_unlock(&bsc->sc_mtx);
	return (0);
}

/*
 * Shared teardown.  Called from the attach `fail:` label after
 * kproc_create has succeeded and from device_detach.  Both paths see
 * the same partially-initialised state on entry, so the same unwind
 * sequence walks them safely:
 *
 *   1. Set sc_dying so the ctlrx thread breaks out of its read loop
 *      and so dcmd callers stop arming new requests.
 *   2. Wake every sleeper on sc_ctl_pending so dcmd waiters exit with
 *      a benign error instead of dangling on a mutex we're about to
 *      destroy.
 *   3. Wait (msleep, not pause-poll) for the ctlrx thread to set
 *      sc_ctlrx_proc = NULL and wake us.
 *   4. usbd_transfer_unsetup drains bulk-RX / bulk-TX / INT callbacks
 *      — once it returns, no more callbacks will fire so it is safe
 *      to drain any tasks they enqueued.
 *   5. taskqueue_drain scan_done + link.
 *   6. ieee80211_ifdetach after callbacks + tasks are quiesced; this
 *      mirrors run(4) / rsu(4): kill the wire first, then net80211.
 *   7. mtx_destroy after all sleepers are gone.
 */
static void
bwfm_usb_teardown(struct bwfm_usb_softc *sc)
{
	struct bwfm_softc *bsc = &sc->bus_sc;

	/*
	 * Common prologue, shared with SDIO and PCIe in bwfm.c: set
	 * sc_dying, wake ctl_pending waiters, drain in_flight_dcmd,
	 * drain the scan_done and link tasks, ieee80211_ifdetach.
	 */
	bwfm_transport_teardown(bsc);

	/*
	 * USB-specific: drain the control-RX ithread proc that owns
	 * the bulk-in xfer.  Must run before usbd_transfer_unsetup so
	 * we don't tear the xfer out from under an in-flight callback.
	 */
	if (mtx_initialized(&bsc->sc_mtx)) {
		mtx_lock(&bsc->sc_mtx);
		while (sc->sc_ctlrx_proc != NULL)
			(void)mtx_sleep(&sc->sc_ctlrx_proc, &bsc->sc_mtx, 0,
			    "bwfmctlx", hz);
		mtx_unlock(&bsc->sc_mtx);
	}

	if (sc->sc_xfer[0] != NULL)
		usbd_transfer_unsetup(sc->sc_xfer, BWFM_N_XFER);

	/* Drain any TX mbufs still queued; xfer is already shut down. */
	while (!STAILQ_EMPTY(&sc->sc_tx_q)) {
		struct bwfm_tx_pending *p = STAILQ_FIRST(&sc->sc_tx_q);

		STAILQ_REMOVE_HEAD(&sc->sc_tx_q, link);
		m_freem(p->m);
		free(p, M_BWFM);
	}

	if (mtx_initialized(&bsc->sc_ctl_mtx))
		mtx_destroy(&bsc->sc_ctl_mtx);
	if (mtx_initialized(&bsc->sc_mtx))
		mtx_destroy(&bsc->sc_mtx);
}

/* stop the device */
static void
bwfm_usb_bs_stop(struct bwfm_softc *bsc)
{

	bwfm_usb_teardown(SC_TO_USB(bsc));
}

/* ------------------- newbus probe / attach / detach ---------------- */

static int
bwfm_usb_probe(device_t dev)
{
	struct usb_attach_arg *uaa = device_get_ivars(dev);

	if (uaa->usb_mode != USB_MODE_HOST)
		return (ENXIO);
	if (uaa->info.bConfigIndex != 0)
		return (ENXIO);
	if (uaa->info.bIfaceIndex != 0)
		return (ENXIO);
	return (usbd_lookup_id_by_uaa(bwfm_usb_devs,
	    sizeof(bwfm_usb_devs), uaa));
}

/* set up the USB device and load firmware */
static int
bwfm_usb_attach(device_t dev)
{
	struct bwfm_usb_softc *sc = device_get_softc(dev);
	struct bwfm_softc *bsc = &sc->bus_sc;
	struct usb_attach_arg *uaa = device_get_ivars(dev);
	const struct firmware *fw;
	uint32_t chip, chiprev;
	int error;

	bsc->sc_dev = dev;
	bsc->sc_bus_ops = &bwfm_usb_bus_ops;
	sc->sc_udev = uaa->device;
	sc->sc_iface_index = uaa->info.bIfaceIndex;

	mtx_init(&bsc->sc_mtx, device_get_nameunit(dev), NULL, MTX_DEF);
	mtx_init(&bsc->sc_ctl_mtx, "bwfm ctl", NULL, MTX_DEF);
	TAILQ_INIT(&bsc->sc_ctl_pending);
	STAILQ_INIT(&sc->sc_tx_q);
	/*
	 * Start reqid at 1 so a freshly-arrived event frame with id 0
	 * cannot be matched against our first outstanding dcmd.  Broadcom
	 * async events on EP0 generally carry id 0; a reqid-0 dcmd reply
	 * would otherwise be indistinguishable from an event.
	 */
	bsc->sc_bcdc_reqid = 1;

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)), OID_AUTO,
	    "debug", CTLFLAG_RWTUN, &bsc->sc_debug, 0,
	    "Verbosity: 0=milestones, 1=protocol, 2=per-frame, "
	    "3=hex dumps");

	device_set_usb_desc(dev);

	error = bwfm_usb_enumerate_endpoints(sc, uaa);
	if (error != 0) {
		device_printf(dev, "endpoint discovery failed: %d\n", error);
		goto fail;
	}

	error = usbd_transfer_setup(uaa->device, &sc->sc_iface_index,
	    sc->sc_xfer, bwfm_usb_config, BWFM_N_XFER, sc, &bsc->sc_mtx);
	if (error != 0) {
		device_printf(dev, "USB xfer setup failed: %s\n",
		    usbd_errstr(error));
		error = ENXIO;
		goto fail;
	}

	error = bwfm_usb_read_bootrom(sc);
	if (error != 0)
		goto fail;

	chip = le32toh(bsc->sc_brom.chip);
	chiprev = le32toh(bsc->sc_brom.chiprev);

	if (chip != BWFM_POSTBOOT_ID) {
		bsc->sc_chip = bwfm_chip_lookup(chip, chiprev);
		if (bsc->sc_chip == NULL) {
			device_printf(dev,
			    "unsupported chip 0x%04x rev %u\n", chip, chiprev);
			error = ENXIO;
			goto fail;
		}
		device_printf(dev, "%s (chip 0x%04x rev %u)\n",
		    bsc->sc_chip->desc, chip, chiprev);

		/*
		 * Record the firmware basename so bwfm_runtime_iovars
		 * can look up the matching CLM.
		 */
		strlcpy(bsc->sc_fw_basename, bsc->sc_chip->fwname,
		    sizeof(bsc->sc_fw_basename));

		fw = firmware_get(bsc->sc_chip->fwname);
		if (fw == NULL) {
			device_printf(dev,
			    "firmware \"%s\" not registered; install via "
			    "firmware(9)\n", bsc->sc_chip->fwname);
			error = ENOENT;
			goto fail;
		}
		error = bwfm_usb_load_firmware(sc, fw->data, fw->datasize);
		firmware_put(fw, FIRMWARE_UNLOAD);
		if (error != 0)
			goto fail;

		/* Poll for the post-boot sentinel. */
		for (int i = 0; i < 20; i++) {
			pause_sbt("bwfmpb", SBT_1MS * 50, 0, 0);
			memset(&bsc->sc_brom, 0, sizeof(bsc->sc_brom));
			if (bwfm_usb_dl_cmd(sc, BWFM_DL_GETVER, &bsc->sc_brom,
			    sizeof(bsc->sc_brom)) != 0)
				continue;
			if (le32toh(bsc->sc_brom.chip) == BWFM_POSTBOOT_ID)
				break;
		}
		if (le32toh(bsc->sc_brom.chip) != BWFM_POSTBOOT_ID) {
			device_printf(dev,
			    "firmware did not boot (chip=0x%08x)\n",
			    le32toh(bsc->sc_brom.chip));
			error = EIO;
			goto fail;
		}
		device_printf(dev,
		    "firmware running; arming BCDC + net80211\n");
	} else {
		device_printf(dev,
		    "chip already in firmware mode\n");
	}

	error = kproc_create(bwfm_usb_ctlrx_thread, sc, &sc->sc_ctlrx_proc,
	    0, 0, "bwfm_ctlrx");
	if (error != 0) {
		device_printf(dev, "ctlrx thread spawn failed: %d\n", error);
		goto fail;
	}

	mtx_lock(&bsc->sc_mtx);
	usbd_transfer_start(sc->sc_xfer[BWFM_BULK_RX_IN]);
	usbd_transfer_start(sc->sc_xfer[BWFM_INT_IN]);
	mtx_unlock(&bsc->sc_mtx);

	/*
	 * Read MAC out of the firmware before bwfm_attach() consumes it
	 * for ieee80211_ifattach().  iovar failure leaves bsc_macaddr as
	 * zeros, which ieee80211_ifattach will treat as "device didn't
	 * report" — acceptable degradation.
	 */
	{
		size_t maclen = sizeof(bsc->sc_macaddr);
		(void)bwfm_iovar_get(bsc, "cur_etheraddr", bsc->sc_macaddr,
		    &maclen);
	}

	/*
	 * A chip that was already running firmware (the module reloaded
	 * without a power cycle) skipped the bootrom lookup above, which
	 * left sc_chip NULL and made the join encode chanspecs as D11AC.
	 * The BCM43236 rejects those with BCME_BADCHAN.  Ask the
	 * running firmware which chip it is: in brcmf_rev_info_le,
	 * chiprev is word 3 and chipnum word 11.
	 */
	if (bsc->sc_chip == NULL) {
		uint32_t rev[17];
		size_t rlen = sizeof(rev);

		memset(rev, 0, sizeof(rev));
		if (bwfm_dcmd_get(bsc, BWFM_C_GET_REVINFO, rev, &rlen) == 0 &&
		    rlen >= 12 * sizeof(uint32_t)) {
			chip = le32toh(rev[11]);
			chiprev = le32toh(rev[3]);
			bsc->sc_chip = bwfm_chip_lookup(chip, chiprev);
		}
		device_printf(dev, "running firmware reports chip 0x%04x "
		    "rev %u: %s\n", chip, chiprev,
		    bsc->sc_chip != NULL ? bsc->sc_chip->desc : "unknown");
		if (bsc->sc_chip != NULL)
			strlcpy(bsc->sc_fw_basename, bsc->sc_chip->fwname,
			    sizeof(bsc->sc_fw_basename));
	}

	error = bwfm_attach(bsc);
	if (error != 0)
		goto fail;
	bwfm_runtime_iovars(bsc);

	return (0);

fail:
	bwfm_usb_teardown(sc);
	return (error);
}

/* tear down the USB device */
static int
bwfm_usb_detach(device_t dev)
{
	struct bwfm_usb_softc *sc = device_get_softc(dev);

	bwfm_usb_teardown(sc);
	return (0);
}

static device_method_t bwfm_usb_methods[] = {
	DEVMETHOD(device_probe, bwfm_usb_probe),
	DEVMETHOD(device_attach, bwfm_usb_attach),
	DEVMETHOD(device_detach, bwfm_usb_detach),
	DEVMETHOD_END
};

static driver_t bwfm_usb_driver = {
	"bwfm",
	bwfm_usb_methods,
	sizeof(struct bwfm_usb_softc),
};

DRIVER_MODULE(bwfm, uhub, bwfm_usb_driver, NULL, NULL);
MODULE_DEPEND(bwfm, usb, 1, 1, 1);
MODULE_DEPEND(bwfm, wlan, 1, 1, 1);
MODULE_VERSION(bwfm, 1);
USB_PNP_HOST_INFO(bwfm_usb_devs);
