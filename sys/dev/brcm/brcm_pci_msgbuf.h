/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom PCIe MSGBUF protocol — native FreeBSD port from
 * Linux upstream brcmfmac.  No linuxkpi.
 *
 * Reference: drivers/net/wireless/broadcom/brcm80211/brcmfmac/
 *   {msgbuf.h, msgbuf.c, commonring.c, commonring.h, pcie.c}
 * in linux-6.6.  Layout constants and structure fields are
 * fw-visible and must match byte-for-byte.
 */

#ifndef _DEV_BRCM_BRCM_PCI_MSGBUF_H_
#define _DEV_BRCM_BRCM_PCI_MSGBUF_H_

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/sx.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/_task.h>

#include <machine/bus.h>

struct mbuf;

/*
 * Deferred WL_EVENT payload — populated by drain_d2h_ring (ISR
 * context, holds ring->lock), drained by msgbuf_event_task on
 * taskqueue_thread outside any ISR lock.
 *
 * Necessary because msgbuf_process_wl_event's downstream path
 * (brcm_handle_event -> ieee80211_add_scan_result) takes
 * IEEE80211_LOCK, and net80211's ic_scan_start (which triggers the
 * scan iovar DCMD) holds IEEE80211_LOCK across the cv_wait for the
 * DCMD's IOCTL_CMPLT.  ISR-inline WL_EVENT dispatch would
 * self-deadlock.
 */
struct brcm_pci_event {
	STAILQ_ENTRY(brcm_pci_event) link;
	uint16_t datalen;
	uint8_t  data[8192];	/* BRCM_MSGBUF_MAX_CTL_PKT_SIZE — max event */
};

/* -----------------------------------------------------------------
 * Common ring constants (matches Linux msgbuf.h:10-24).
 * ----------------------------------------------------------------- */
#define	BRCM_H2D_CONTROL_SUBMIT_MAX_ITEM	64
#define	BRCM_H2D_RXPOST_SUBMIT_MAX_ITEM		1024
#define	BRCM_D2H_CONTROL_COMPLETE_MAX_ITEM	64
#define	BRCM_D2H_TX_COMPLETE_MAX_ITEM		1024
#define	BRCM_D2H_RX_COMPLETE_MAX_ITEM		1024
#define	BRCM_H2D_TXFLOWRING_MAX_ITEM		512

#define	BRCM_H2D_CONTROL_SUBMIT_ITEMSIZE	40
#define	BRCM_H2D_RXPOST_SUBMIT_ITEMSIZE		32
#define	BRCM_D2H_CONTROL_COMPLETE_ITEMSIZE	24
#define	BRCM_D2H_TX_COMPLETE_ITEMSIZE_PRE_V7	16
#define	BRCM_D2H_TX_COMPLETE_ITEMSIZE		24
#define	BRCM_D2H_RX_COMPLETE_ITEMSIZE_PRE_V7	32
#define	BRCM_D2H_RX_COMPLETE_ITEMSIZE		40
#define	BRCM_H2D_TXFLOWRING_ITEMSIZE		48

/* Ring IDs — index into commonrings[] (pcie.c:408-430). */
#define	BRCM_H2D_MSGRING_CONTROL_SUBMIT		0
#define	BRCM_H2D_MSGRING_RXPOST_SUBMIT		1
#define	BRCM_D2H_MSGRING_CONTROL_COMPLETE	2
#define	BRCM_D2H_MSGRING_TX_COMPLETE		3
#define	BRCM_D2H_MSGRING_RX_COMPLETE		4
#define	BRCM_NROF_COMMON_MSGRINGS		5

/* -----------------------------------------------------------------
 * Shared-info struct offsets (Linux pcie.c:223-233).
 * Read via BAR2[sharedram_addr + N].
 * ----------------------------------------------------------------- */
#define	BRCM_SHARED_FLAGS_OFFSET		0	/* u32 */
#define	BRCM_SHARED_CONSOLE_ADDR_OFFSET		20	/* u32 */
#define	BRCM_SHARED_MAX_RXBUFPOST_OFFSET	34	/* u16 */
#define	BRCM_SHARED_RX_DATAOFFSET_OFFSET	36	/* u32 */
#define	BRCM_SHARED_HTOD_MB_DATA_ADDR_OFFSET	40	/* u32 */
#define	BRCM_SHARED_DTOH_MB_DATA_ADDR_OFFSET	44	/* u32 */
#define	BRCM_SHARED_RING_INFO_ADDR_OFFSET	48	/* u32 */
#define	BRCM_SHARED_DMA_SCRATCH_LEN_OFFSET	52	/* u32 */
#define	BRCM_SHARED_DMA_SCRATCH_ADDR_OFFSET	56	/* u64 (lo,hi) */
#define	BRCM_SHARED_DMA_RINGUPD_LEN_OFFSET	64	/* u32 */
#define	BRCM_SHARED_DMA_RINGUPD_ADDR_OFFSET	68	/* u64 (lo,hi) */

#define	BRCM_PCIE_SHARED_VERSION_MASK		0x000000FF
#define	BRCM_PCIE_MIN_SHARED_VERSION		5
#define	BRCM_PCIE_MAX_SHARED_VERSION		7
#define	BRCM_PCIE_SHARED_DMA_INDEX		0x00010000
#define	BRCM_PCIE_SHARED_DMA_2B_IDX		0x00100000
#define	BRCM_PCIE_SHARED_HOSTRDY_DB1		0x10000000

/*
 * D3 / D0 mailbox values written to htod_mb_data_addr in TCM and read
 * from dtoh_mb_data_addr for fw ack.  Fires the SBMBX config-space
 * doorbell (offset 0x98 in PCI config space) to notify fw.  Reference:
 * brcmfmac pcie.c BRCMF_H2D_HOST_D3_INFORM / BRCMF_D2H_DEV_D3_ACK.
 */
#define	BRCM_H2D_HOST_D3_INFORM			0x00000001
#define	BRCM_D2H_DEV_D3_ACK			0x00000001
#define	BRCM_H2D_HOST_D0_INFORM_IN_USE		0x00000008
#define	BRCM_H2D_HOST_D0_INFORM			0x00000010
#define	BRCM_PCI_REG_SBMBX			0x98

/* Ring-info struct offsets within the ringinfo TCM block. */
#define	BRCM_RINGINFO_RINGMEM_OFFSET		0	/* u32 */
#define	BRCM_RINGINFO_H2D_W_IDX_PTR_OFFSET	4	/* u32 */
#define	BRCM_RINGINFO_H2D_R_IDX_PTR_OFFSET	8	/* u32 */
#define	BRCM_RINGINFO_D2H_W_IDX_PTR_OFFSET	12	/* u32 */
#define	BRCM_RINGINFO_D2H_R_IDX_PTR_OFFSET	16	/* u32 */
#define	BRCM_RINGINFO_H2D_W_IDX_HOST_OFFSET	20	/* u64 */
#define	BRCM_RINGINFO_H2D_R_IDX_HOST_OFFSET	28	/* u64 */
#define	BRCM_RINGINFO_D2H_W_IDX_HOST_OFFSET	36	/* u64 */
#define	BRCM_RINGINFO_D2H_R_IDX_HOST_OFFSET	44	/* u64 */
#define	BRCM_RINGINFO_MAX_FLOWRINGS_OFFSET	52	/* u16 */
#define	BRCM_RINGINFO_MAX_SUBMISSIONRINGS_OFFSET 54	/* u16 */
#define	BRCM_RINGINFO_MAX_COMPLETIONRINGS_OFFSET 56	/* u16 */

/* Per-ring "ringmem" entry — 16 bytes each (pcie.c:240-244). */
#define	BRCM_RING_MAX_ITEM_OFFSET		4	/* u16 */
#define	BRCM_RING_LEN_ITEMS_OFFSET		6	/* u16 */
#define	BRCM_RING_MEM_BASE_ADDR_OFFSET		8	/* u64 (lo,hi) */
#define	BRCM_RING_MEM_SZ			16
#define	BRCM_RING_STATE_SZ			8

/* -----------------------------------------------------------------
 * PCIe2 core register offsets (Linux pcie.c:134-149,
 * brcmf_reginfo_default — 32-bit PCIe2 core, applies to BCM43602).
 * All relative to PCIe2 core base (found via EROM walk).
 * ----------------------------------------------------------------- */
#define	BRCM_PCIE2REG_INTMASK			0x24
#define	BRCM_PCIE2REG_MAILBOXINT		0x48
#define	BRCM_PCIE2REG_MAILBOXMASK		0x4C
#define	BRCM_PCIE2REG_H2D_MAILBOX_0		0x140
#define	BRCM_PCIE2REG_H2D_MAILBOX_1		0x144

#define	BRCM_PCIE_MB_INT_FN0_0			0x0100
#define	BRCM_PCIE_MB_INT_FN0_1			0x0200
#define	BRCM_PCIE_MB_INT_FN0			(BRCM_PCIE_MB_INT_FN0_0 | \
						 BRCM_PCIE_MB_INT_FN0_1)
#define	BRCM_PCIE_MB_INT_D2H0_DB0		0x00010000
#define	BRCM_PCIE_MB_INT_D2H0_DB1		0x00020000
#define	BRCM_PCIE_MB_INT_D2H1_DB0		0x00040000
#define	BRCM_PCIE_MB_INT_D2H1_DB1		0x00080000
#define	BRCM_PCIE_MB_INT_D2H2_DB0		0x00100000
#define	BRCM_PCIE_MB_INT_D2H2_DB1		0x00200000
#define	BRCM_PCIE_MB_INT_D2H3_DB0		0x00400000
#define	BRCM_PCIE_MB_INT_D2H3_DB1		0x00800000
#define	BRCM_PCIE_MB_INT_D2H_DB			(BRCM_PCIE_MB_INT_D2H0_DB0 | \
						 BRCM_PCIE_MB_INT_D2H0_DB1 | \
						 BRCM_PCIE_MB_INT_D2H1_DB0 | \
						 BRCM_PCIE_MB_INT_D2H1_DB1 | \
						 BRCM_PCIE_MB_INT_D2H2_DB0 | \
						 BRCM_PCIE_MB_INT_D2H2_DB1 | \
						 BRCM_PCIE_MB_INT_D2H3_DB0 | \
						 BRCM_PCIE_MB_INT_D2H3_DB1)

/* -----------------------------------------------------------------
 * MSGBUF packet layouts.  All __le32 in Linux — since we run only
 * on little-endian hosts (x86), fields are raw uint32_t/uint16_t
 * and we htole/le64toh at use sites where portability matters.
 * ----------------------------------------------------------------- */

#define	BRCM_MSGBUF_TYPE_GEN_STATUS		0x1
#define	BRCM_MSGBUF_TYPE_RING_STATUS		0x2
#define	BRCM_MSGBUF_TYPE_FLOW_RING_CREATE	0x3
#define	BRCM_MSGBUF_TYPE_FLOW_RING_CREATE_CMPLT	0x4
#define	BRCM_MSGBUF_TYPE_FLOW_RING_DELETE	0x5
#define	BRCM_MSGBUF_TYPE_FLOW_RING_DELETE_CMPLT	0x6
#define	BRCM_MSGBUF_TYPE_IOCTLPTR_REQ		0x9
#define	BRCM_MSGBUF_TYPE_IOCTLPTR_REQ_ACK	0xA
#define	BRCM_MSGBUF_TYPE_IOCTLRESP_BUF_POST	0xB
#define	BRCM_MSGBUF_TYPE_IOCTL_CMPLT		0xC
#define	BRCM_MSGBUF_TYPE_EVENT_BUF_POST		0xD
#define	BRCM_MSGBUF_TYPE_WL_EVENT		0xE
#define	BRCM_MSGBUF_TYPE_TX_POST		0xF
#define	BRCM_MSGBUF_TYPE_TX_STATUS		0x10
#define	BRCM_MSGBUF_TYPE_RXBUF_POST		0x11
#define	BRCM_MSGBUF_TYPE_RX_CMPLT		0x12

#define	BRCM_IOCTL_REQ_PKTID			0xFFFE
#define	BRCM_MSGBUF_MAX_CTL_PKT_SIZE		8192

struct msgbuf_buf_addr {
	uint32_t	low_addr;
	uint32_t	high_addr;
} __packed;

struct msgbuf_common_hdr {
	uint8_t		msgtype;
	uint8_t		ifidx;
	uint8_t		flags;
	uint8_t		rsvd0;
	uint32_t	request_id;
} __packed;

struct msgbuf_ioctl_req_hdr {
	struct msgbuf_common_hdr	msg;
	uint32_t			cmd;
	uint16_t			trans_id;
	uint16_t			input_buf_len;
	uint16_t			output_buf_len;
	uint16_t			rsvd0[3];
	struct msgbuf_buf_addr		req_buf_addr;
	uint32_t			rsvd1[2];
} __packed;

struct msgbuf_completion_hdr {
	uint16_t	status;
	uint16_t	flow_ring_id;
} __packed;

struct msgbuf_ioctl_resp_hdr {
	struct msgbuf_common_hdr	msg;
	struct msgbuf_completion_hdr	compl_hdr;
	uint16_t			resp_len;
	uint16_t			trans_id;
	uint32_t			cmd;
	uint32_t			rsvd0;
} __packed;

struct msgbuf_rx_ioctl_resp_or_event {
	struct msgbuf_common_hdr	msg;
	uint16_t			host_buf_len;
	uint16_t			rsvd0[3];
	struct msgbuf_buf_addr		host_buf_addr;
	uint32_t			rsvd1[4];
} __packed;

/* TX descriptor into a flowring (48 bytes; Linux msgbuf.c:95). */
struct msgbuf_tx_msghdr {
	struct msgbuf_common_hdr	msg;
	uint8_t				txhdr[14];	/* ETH_HLEN */
	uint8_t				flags;
	uint8_t				seg_cnt;
	struct msgbuf_buf_addr		metadata_buf_addr;
	struct msgbuf_buf_addr		data_buf_addr;
	uint16_t			metadata_buf_len;
	uint16_t			data_len;
	uint32_t			rsvd0;
} __packed;

/* Fw's ack of a TX_POST (48 bytes on H2D ctrl completion ring). */
struct msgbuf_tx_status {
	struct msgbuf_common_hdr	msg;
	struct msgbuf_completion_hdr	compl_hdr;
	uint16_t			metadata_len;
	uint16_t			tx_status;
} __packed;

/* Host → fw: create a flowring for a peer (48 bytes). */
struct msgbuf_tx_flowring_create_req {
	struct msgbuf_common_hdr	msg;
	uint8_t				da[6];
	uint8_t				sa[6];
	uint8_t				tid;
	uint8_t				if_flags;
	uint16_t			flow_ring_id;
	uint8_t				tc;
	uint8_t				priority;
	uint16_t			int_vector;
	uint16_t			max_items;
	uint16_t			len_item;
	struct msgbuf_buf_addr		flow_ring_addr;
} __packed;

/* Fw's ack of a create request (48 bytes on H2D ctrl completion ring). */
struct msgbuf_flowring_create_resp {
	struct msgbuf_common_hdr	msg;
	struct msgbuf_completion_hdr	compl_hdr;
	uint32_t			rsvd0[3];
} __packed;

/*
 * FLOW_RING_DELETE request — sent on H2D_CTRL_SUBMIT.  Symmetric to
 * FLOW_RING_CREATE but only carries flow_ring_id + reason.
 */
struct msgbuf_tx_flowring_delete_req {
	struct msgbuf_common_hdr	msg;
	uint16_t			flow_ring_id;
	uint16_t			reason;
	uint32_t			rsvd0[7];
} __packed;

/* Fw's ack of a delete request (D2H ctrl completion ring). */
struct msgbuf_flowring_delete_resp {
	struct msgbuf_common_hdr	msg;
	struct msgbuf_completion_hdr	compl_hdr;
	uint32_t			rsvd0[3];
} __packed;

/* Fw → host async event descriptor (Linux msgbuf.c:145). */
struct msgbuf_rx_event {
	struct msgbuf_common_hdr	msg;
	struct msgbuf_completion_hdr	compl_hdr;
	uint16_t			event_data_len;
	uint16_t			seqnum;
	uint16_t			rsvd0[4];
} __packed;

/* Fw → host RX packet descriptor (Linux msgbuf.c:169; 40 bytes v7). */
struct msgbuf_rx_complete {
	struct msgbuf_common_hdr	msg;
	struct msgbuf_completion_hdr	compl_hdr;
	uint16_t			metadata_len;
	uint16_t			data_len;
	uint16_t			data_offset;
	uint16_t			flags;
	uint32_t			rx_status_0;
	uint32_t			rx_status_1;
	uint32_t			rsvd0;
} __packed;

/* Host → fw RXBUF_POST descriptor (Linux msgbuf.c:107; 32 bytes). */
struct msgbuf_rx_bufpost {
	struct msgbuf_common_hdr	msg;
	uint16_t			metadata_buf_len;
	uint16_t			data_buf_len;
	uint32_t			rsvd0;
	struct msgbuf_buf_addr		metadata_buf_addr;
	struct msgbuf_buf_addr		data_buf_addr;
} __packed;

/* RXPOST/EVENT/IOCTLRESP constants (Linux msgbuf.c:56-60). */
#define	BRCM_MSGBUF_MAX_PKT_SIZE		2048	/* rx data buf */
#define	BRCM_MSGBUF_RXBUFPOST_THRESHOLD		32
#define	BRCM_MSGBUF_MAX_EVENTBUF_POST		8
#define	BRCM_MSGBUF_MAX_IOCTLRESPBUF_POST	8
#define	BRCM_MSGBUF_MAX_RXPOST			256	/* our tunable */

/* Flags in msgbuf_rx_complete indicating packet framing. */
#define	BRCM_MSGBUF_PKT_FLAGS_FRAME_MASK	0x07
#define	BRCM_MSGBUF_PKT_FLAGS_FRAME_802_11	0x02

/* -----------------------------------------------------------------
 * bcmevent packet layout inside a WL_EVENT buffer (Linux fweh.h).
 *   [ethhdr] [brcm_ethhdr] [brcmf_event_msg_be] [event data...]
 * All be-fields big-endian (fw is BE-normalised on the wire).
 * ----------------------------------------------------------------- */
#define	BRCM_ETH_TYPE_EVENT		0x886c
#define	BRCM_BCMILCP_SUBTYPE_VENDOR_LONG	32769
#define	BRCM_BCM_OUI0			0x00
#define	BRCM_BCM_OUI1			0x10
#define	BRCM_BCM_OUI2			0x18

/* brcm_ethhdr (8 B, all BE). */
struct brcm_bcm_ethhdr {
	uint16_t	subtype;
	uint16_t	length;
	uint8_t		version;
	uint8_t		oui[3];
	uint16_t	usr_subtype;
} __packed;

/* brcmf_event_msg_be (48 B, all BE). */
struct brcm_bcm_event_msg {
	uint16_t	version;
	uint16_t	flags;
	uint32_t	event_type;
	uint32_t	status;
	uint32_t	reason;
	int32_t		auth_type;
	uint32_t	datalen;
	uint8_t		addr[6];
	char		ifname[16];
	uint8_t		ifidx;
	uint8_t		bsscfgidx;
} __packed;

/* Event codes we care about (Linux fweh.h BRCMF_E_*). */
#define	BRCM_PCI_E_SET_SSID			0
#define	BRCM_PCI_E_JOIN			1
#define	BRCM_PCI_E_START			2
#define	BRCM_PCI_E_AUTH			3
#define	BRCM_PCI_E_AUTH_IND			4
#define	BRCM_PCI_E_DEAUTH			5
#define	BRCM_PCI_E_DEAUTH_IND		6
#define	BRCM_PCI_E_ASSOC			7
#define	BRCM_PCI_E_ASSOC_IND		8
#define	BRCM_PCI_E_REASSOC			9
#define	BRCM_PCI_E_REASSOC_IND		10
#define	BRCM_PCI_E_DISASSOC			11
#define	BRCM_PCI_E_DISASSOC_IND		12
#define	BRCM_PCI_E_LINK			16
#define	BRCM_PCI_E_MIC_ERROR		17
#define	BRCM_PCI_E_ROAM			19
#define	BRCM_PCI_E_PMKID_CACHE		21
#define	BRCM_PCI_E_EAPOL_MSG		25
#define	BRCM_PCI_E_SCAN_COMPLETE		26
#define	BRCM_PCI_E_JOIN_START		36
#define	BRCM_PCI_E_ROAM_START		37
#define	BRCM_PCI_E_ASSOC_START		38
#define	BRCM_PCI_E_PSK_SUP			46
#define	BRCM_PCI_E_COUNTRY_CODE_CHANGED	47
#define	BRCM_PCI_E_ACTION_FRAME		59
#define	BRCM_PCI_E_ESCAN_RESULT		69
#define	BRCM_PCI_E_PROBERESP_MSG		71
#define	BRCM_PCI_E_FIFO_CREDIT_MAP		74
#define	BRCM_PCI_E_IF			54
#define	BRCM_PCI_E_RSSI			56
#define	BRCM_PCI_E_TRACE		52
#define	BRCM_PCI_E_BEACON_RX		15
#define	BRCM_PCI_E_TXFAIL		20
#define	BRCM_PCI_E_RADIO		40
#define	BRCM_PCI_E_PSM_WATCHDOG	41
#define	BRCM_PCI_E_LAST			139

/* Status codes (subset). */
#define	BRCM_PCI_E_STATUS_SUCCESS		0
#define	BRCM_PCI_E_STATUS_FAIL		1
#define	BRCM_PCI_E_STATUS_TIMEOUT		2
#define	BRCM_PCI_E_STATUS_NO_NETWORKS	3
#define	BRCM_PCI_E_STATUS_ABORT		4
#define	BRCM_PCI_E_STATUS_NO_ACK		5
#define	BRCM_PCI_E_STATUS_UNSOLICITED	6
#define	BRCM_PCI_E_STATUS_ATTEMPT		7
#define	BRCM_PCI_E_STATUS_PARTIAL		8
#define	BRCM_PCI_E_STATUS_NEWSCAN		9
#define	BRCM_PCI_E_STATUS_NEWASSOC		10
#define	BRCM_PCI_E_STATUS_ERROR		16

/* Flags in event_msg->flags. */
#define	BRCM_EVENT_MSG_LINK		0x01
#define	BRCM_EVENT_MSG_FLUSHTXQ		0x02
#define	BRCM_EVENT_MSG_GROUP		0x04

/* Offsets inside the raw payload buffer we posted to fw. */
#define	BRCM_EVT_OFFSET_ETHHDR		0
#define	BRCM_EVT_OFFSET_BCM_ETHHDR	14	/* eth hdr size */
#define	BRCM_EVT_OFFSET_MSG		24	/* +brcm_ethhdr (10) */
#define	BRCM_EVT_OFFSET_DATA		72	/* +brcm_event_msg (48) */

/* Flowring IDs — fw sees `local_id + IDSTART`. */
#define	BRCM_H2D_MSGRING_FLOWRING_IDSTART	2

/* TX_POST flags (Linux msgbuf.c:62-65). */
#define	BRCM_MSGBUF_PKT_FLAGS_FRAME_802_3	0x01
#define	BRCM_MSGBUF_PKT_FLAGS_PRIO_SHIFT	5

/* Max concurrent outstanding TX packets — pktid table depth. */
#define	BRCM_MSGBUF_MAX_PKTID			1024

/* -----------------------------------------------------------------
 * Ring buffer + msgbuf softc state (native FreeBSD).
 *
 * Coherent DMA buffers use bus_dma(9).  Each ring wraps a coherent
 * allocation (mapaddr = physical DMA address given to fw; vaddr =
 * host CPU pointer for enqueue/dequeue).
 * ----------------------------------------------------------------- */
struct brcm_pci_dma_buf {
	bus_dma_tag_t	tag;
	bus_dmamap_t	map;
	void		*vaddr;
	bus_addr_t	paddr;
	size_t		size;
};

struct brcm_pci_ring {
	/* Layout state, in items (protected by lock). */
	uint16_t	depth;
	uint16_t	item_len;
	uint16_t	r_ptr;		/* consumer, incremented by us on read */
	uint16_t	w_ptr;		/* producer, incremented by us on write */
	uint16_t	f_ptr;		/* last fw-visible w_ptr */

	uint8_t		id;
	bool		inited;
	bool		was_full;

	struct brcm_pci_dma_buf	buf;

	/* TCM addresses of ring's r/w indices (fw-side). */
	uint32_t	w_idx_addr;
	uint32_t	r_idx_addr;

	struct mtx	lock;

	/* Back pointer for callback context. */
	struct brcm_pci_msgbuf	*mb;
};

/*
 * A flow ring holds TX descriptors for a single (peer, prio, ifidx)
 * tuple.  Fw allocates a numeric ring id on CREATE ack.  Native
 * struct: ring buf + state; no skb queue (net80211 queues at ifnet).
 */
enum brcm_pci_flowring_status {
	BRCM_FLOW_CLOSED = 0,
	BRCM_FLOW_PENDING = 1,	/* CREATE sent, awaiting CMPLT */
	BRCM_FLOW_OPEN = 2,
	BRCM_FLOW_FAILED = 3,	/* fw rejected create */
};
struct brcm_pci_flowring {
	struct brcm_pci_ring	ring;		/* commonring mechanics */
	uint8_t			da[6];
	uint8_t			sa[6];
	uint8_t			prio;
	uint8_t			tid;
	uint8_t			ifidx;
	uint8_t			pad;
	int			status;		/* enum brcm_pci_flowring_status */
	int16_t			last_create_status;
};

/*
 * pktid slot: tracks one outstanding TX mbuf so we can free it when
 * fw acks via TX_STATUS.  request_id in TX_POST is (idx + 1) so 0 =
 * "unused" (Linux msgbuf convention).
 */
struct brcm_pci_pktid {
	struct mbuf	*m;
	bus_dmamap_t	 map;
	uint64_t	 pa;
	uint16_t	 datalen;
	uint16_t	 flowid;	/* local id */
	bool		 inuse;
};

/*
 * RXPOST slot: tracks one host mbuf posted to fw for either an
 * incoming data frame (via H2D_RXPOST_SUBMIT) or an async event
 * payload / ioctl response (via H2D_CTRL_SUBMIT).  Fw returns the
 * pktid in the RX_CMPLT / WL_EVENT / IOCTL_CMPLT descriptor so we
 * can look up the mbuf.
 */
enum brcm_pci_rxpost_type {
	BRCM_RXPOST_UNUSED = 0,
	BRCM_RXPOST_DATA,	/* fw incoming 802.3 / 802.11 frame */
	BRCM_RXPOST_EVENT,	/* WL_EVENT payload */
	BRCM_RXPOST_IOCTL,	/* IOCTL response (deferred — future) */
};
struct brcm_pci_rxpost {
	struct mbuf	*m;
	bus_dmamap_t	 map;
	uint64_t	 pa;
	uint16_t	 buflen;
	uint8_t		 type;		/* enum brcm_pci_rxpost_type */
};

struct brcm_pci_msgbuf {
	struct brcm_pci_softc	*sc;
	bool			 attached;

	/* Shared-memory state read from TCM after fw boot. */
	uint32_t		 shared_addr;	/* TCM offset of shared struct */
	uint32_t		 shared_flags;
	uint8_t			 shared_version;
	uint32_t		 htod_mb_data_addr;
	uint32_t		 dtoh_mb_data_addr;
	uint32_t		 ring_info_addr;
	uint32_t		 console_addr;
	uint16_t		 max_rxbufpost;
	uint32_t		 rx_dataoffset;

	uint16_t		 max_flowrings;
	uint16_t		 max_submissionrings;
	uint16_t		 max_completionrings;

	uint32_t		 ringmem_base;

	/* PCIe2 core BAR0 window base — cached at attach. */
	uint32_t		 pcie2_base;

	/* Doorbell + interrupt regs (offsets into PCIe2 window). */
	uint32_t		 intmask;
	uint32_t		 mailboxint;
	uint32_t		 mailboxmask;
	uint32_t		 h2d_mailbox_0;

	/* The 5 fixed common rings. */
	struct brcm_pci_ring	 rings[BRCM_NROF_COMMON_MSGRINGS];

	/* Coherent scratch + ringupd (Linux init_scratchbuffers). */
	struct brcm_pci_dma_buf	 scratch;
	struct brcm_pci_dma_buf	 ringupd;

	/* Coherent IOCTL request buffer (single-outstanding, msgbuf.c). */
	struct brcm_pci_dma_buf	 ioctbuf;

	/* IOCTL round-trip completion (single outstanding). */
	struct sx		 dcmd_sx;
	struct mtx		 dcmd_mtx;
	struct cv		 dcmd_cv;
	bool			 dcmd_completed;
	uint16_t		 dcmd_reqid;
	int16_t			 dcmd_resp_status;
	uint16_t		 dcmd_resp_len;

	/* Flowring index-slot cursor — set at commonring init to first free
	 * H2D w/r index slot after the two H2D common rings. */
	uint32_t		 flow_h2d_w_next;
	uint32_t		 flow_h2d_r_next;
	uint32_t		 flow_ringmem_next;	/* per-ring 16B slot */

	/* Flowring array, size = max_flowrings.  Alloc'd at attach. */
	struct brcm_pci_flowring *flowrings;
	struct mtx		 flow_mtx;	/* protects create/status */
	struct cv		 flow_cv;

	/* Pktid table for TX (dyn-alloc size BRCM_MSGBUF_MAX_PKTID). */
	struct brcm_pci_pktid	*pktids;
	struct mtx		 pktid_mtx;
	uint32_t		 pktid_next_hint;
	bus_dma_tag_t		 tx_mbuf_tag;

	/*
	 * RXPOST slots + counters.  Pktid space for rxposts is disjoint
	 * from tx_pktids — separate table + separate hint.  Slot 0 is
	 * reserved (fw treats request_id 0 as "no id").
	 */
	struct brcm_pci_rxpost	*rxposts;
	struct mtx		 rxpost_mtx;
	uint32_t		 rxpost_next_hint;
	bus_dma_tag_t		 rx_mbuf_tag;

	uint16_t		 cur_eventbuf;
	uint16_t		 max_eventbuf;
	uint16_t		 cur_rxbufpost;

	/*
	 * Coherent event-buf pool.  Fixed-count (BRCM_MSGBUF_MAX_
	 * EVENTBUF_POST=8), pre-allocated via bus_dmamem_alloc so
	 * physaddr is guaranteed to fit the 32-bit tag constraint
	 * (mbuf-based m_getjcl for 8KB MJUM9BYTES clusters could
	 * return above-4GB clusters with no bounce, giving pa=0 →
	 * 0/8 posted → fw wedge on first DCMD).  Slots are reused
	 * for the driver's lifetime; pktid == slot_index + 1.
	 * See project_brcm_pci_dcmd_hard_wedge_2026_07_20 memory.
	 */
	struct brcm_pci_dma_buf	 eventbufs[8];

	/*
	 * Deferred WL_EVENT dispatch queue.  See brcm_pci_event comment
	 * above the type definition.  ISR queues here; event_task drains.
	 */
	struct mtx		 event_q_mtx;
	STAILQ_HEAD(, brcm_pci_event) event_q;
	struct task		 event_task;

	/* Statistics. */
	uint64_t		 stat_dcmd_tx;
	uint64_t		 stat_dcmd_rx;
	uint64_t		 stat_dcmd_timeout;
	uint64_t		 stat_isr_hits;
	uint64_t		 stat_ctl_msgs;
	uint64_t		 stat_flow_create_tx;
	uint64_t		 stat_flow_create_ok;
	uint64_t		 stat_flow_create_fail;
	uint64_t		 stat_tx_post;
	uint64_t		 stat_tx_status_ok;
	uint64_t		 stat_tx_status_err;
	uint64_t		 stat_tx_no_pktid;
	uint64_t		 stat_tx_ring_full;
	uint64_t		 stat_event_rx;
	uint64_t		 stat_rx_data;
	uint64_t		 stat_rxpost_refills;
};

/* -----------------------------------------------------------------
 * Public entry points (implemented in brcm_pci_msgbuf.c).
 * ----------------------------------------------------------------- */

/*
 * Attach: fw must be running (armcr4_release must have fired,
 * BAR2[rambase+ramsize-4] must be non-zero).  Reads shared info,
 * allocates ring buffers, installs ISR, publishes rings to fw.
 * Idempotent — returns 0 if already attached.
 */
int	brcm_pci_msgbuf_attach(struct brcm_pci_softc *);

/*
 * Detach: free all coherent buffers, remove ISR.  Must be called
 * before device_detach.  Safe to call unattached.
 */
void	brcm_pci_msgbuf_detach(struct brcm_pci_softc *);

/*
 * DCMD round-trip: send `cmd` with `params_len` bytes, wait up to
 * 2s for reply, copy up to `*resp_lenp` bytes into `resp`.  On
 * return, *resp_lenp is set to actual reply length and fwerr is
 * set to the fw-reported status.  Returns 0 on success, ETIMEDOUT
 * on no reply, ENXIO if msgbuf not attached.
 */
int	brcm_pci_msgbuf_dcmd(struct brcm_pci_softc *, uint32_t cmd,
	    bool is_set, const void *params, size_t params_len,
	    void *resp, size_t *resp_lenp, int32_t *fwerr);

/*
 * Create a flowring for (sa,da,prio) on ifidx.  Synchronous: sends
 * FLOW_RING_CREATE, waits up to 2 s for FLOW_RING_CREATE_CMPLT.
 * On success sets *flowid_out to the local flowring id (0-based).
 * Fw's ring id = flowid_out + BRCM_H2D_MSGRING_FLOWRING_IDSTART.
 * TID inferred from prio (Linux brcmf_flowring_prio_to_tid).
 */
int	brcm_pci_msgbuf_flowring_create(struct brcm_pci_softc *,
	    const uint8_t sa[6], const uint8_t da[6], uint8_t prio,
	    uint8_t ifidx, uint16_t *flowid_out);

/*
 * Submit an mbuf into an OPEN flowring.  Takes ownership of `m` on
 * success (freed when fw acks via TX_STATUS); caller must m_freem
 * on error return.  ifidx is written into the TX_POST header.
 * Frame must be 802.3 with a 14-byte Ethernet header at m_data.
 */
int	brcm_pci_msgbuf_txmbuf(struct brcm_pci_softc *, uint16_t flowid,
	    struct mbuf *m, uint8_t ifidx);

/*
 * DCMD wrappers — Linux fwil.c equivalents.  All are synchronous
 * (dcmd waits up to 2s for reply).  Use for chip-supplicant control
 * (WLC_UP, SET_INFRA, SET_SSID, iovars, etc).
 */
int	brcm_pci_msgbuf_dcmd_set_int(struct brcm_pci_softc *, uint32_t cmd,
	    uint32_t val);
int	brcm_pci_msgbuf_dcmd_get_int(struct brcm_pci_softc *, uint32_t cmd,
	    uint32_t *val);
int	brcm_pci_msgbuf_dcmd_set_var(struct brcm_pci_softc *, const char *name,
	    const void *data, size_t datalen);
int	brcm_pci_msgbuf_dcmd_get_var(struct brcm_pci_softc *, const char *name,
	    void *data, size_t *datalenp);

/* Well-known DCMD command numbers (Linux fwil.h). */
#define	BRCM_C_GET_VERSION	1
#define	BRCM_C_UP		2
#define	BRCM_C_DOWN		3
#define	BRCM_C_GET_INFRA	19
#define	BRCM_C_SET_INFRA	20
#define	BRCM_C_GET_SSID		25
#define	BRCM_C_SET_SSID		26
#define	BRCM_C_DISASSOC		52
#define	BRCM_C_SET_COUNTRY	84
#define	BRCM_C_SET_PM		86
#define	BRCM_C_GET_WSEC		133
#define	BRCM_C_SET_WSEC		134
#define	BRCM_C_GET_BSS_INFO	136
#define	BRCM_C_GET_VAR		262
#define	BRCM_C_SET_VAR		263

/*
 * ISR filter — installed via bus_setup_intr with a filter+ithread
 * pair.  Reads MAILBOXINT, acknowledges D2H bits, wakes ithread.
 */
int	brcm_pci_msgbuf_isr_filter(void *arg);

/* ithread handler: drain D2H_CONTROL_COMPLETE ring. */
void	brcm_pci_msgbuf_isr_thread(void *arg);

/* -----------------------------------------------------------------
 * Bridge functions provided by if_brcm_pci.c and consumed by
 * brcm_pci_msgbuf.c.  Keeps the msgbuf layer free of any dependency
 * on the transport softc definition.
 * ----------------------------------------------------------------- */
struct brcm_pci_softc;
uint32_t	brcm_pci_msgbuf_pcie2_base(struct brcm_pci_softc *);
void		brcm_pci_msgbuf_set_window(struct brcm_pci_softc *, uint32_t);
struct resource *brcm_pci_msgbuf_bar0(struct brcm_pci_softc *);
struct resource *brcm_pci_msgbuf_bar2(struct brcm_pci_softc *);
bus_space_tag_t	brcm_pci_msgbuf_bar0_tag(struct brcm_pci_softc *);
bus_space_handle_t brcm_pci_msgbuf_bar0_handle(struct brcm_pci_softc *);
bus_space_tag_t	brcm_pci_msgbuf_bar2_tag(struct brcm_pci_softc *);
bus_space_handle_t brcm_pci_msgbuf_bar2_handle(struct brcm_pci_softc *);
device_t	brcm_pci_msgbuf_dev(struct brcm_pci_softc *);
int		brcm_pci_msgbuf_debug(struct brcm_pci_softc *);

/*
 * D3 / D0 mailbox helpers.  send_mb_data writes htod_val into the TCM
 * htod slot and rings the SBMBX config-space doorbell; returns 0 if
 * the fw's mailbox was clear (or cleared within 1 s).  wait_mb_ack
 * polls the dtoh slot for `expect` for up to `timeout_ms` ms and
 * returns 0 on match, ETIMEDOUT otherwise.
 */
int	brcm_pci_msgbuf_send_mb_data(struct brcm_pci_softc *,
	    uint32_t htod_val);
int	brcm_pci_msgbuf_wait_mb_ack(struct brcm_pci_softc *,
	    uint32_t expect, int timeout_ms);

/*
 * Synchronously send FLOW_RING_DELETE for a given local flowid and
 * wait up to 2 s for the CMPLT.  On success the slot is marked
 * CLOSED so it can be reallocated on a subsequent create.  Returns
 * ETIMEDOUT if fw doesn't ack, ENXIO if msgbuf is down.
 */
int	brcm_pci_msgbuf_flowring_delete(struct brcm_pci_softc *,
	    uint16_t local_id);

/*
 * Iterate every host-side flowring in status BRCM_FLOW_OPEN and
 * synchronously delete each one (see brcm_pci_msgbuf_flowring_delete).
 * Slots are marked CLOSED on success; failures are logged and skipped
 * so partial success is possible.
 */
void	brcm_pci_msgbuf_flowring_delete_all(struct brcm_pci_softc *);
uint32_t	brcm_pci_msgbuf_rambase(struct brcm_pci_softc *);
uint32_t	brcm_pci_msgbuf_ramsize(struct brcm_pci_softc *);
struct brcm_pci_msgbuf	*brcm_pci_msgbuf_state(struct brcm_pci_softc *);
/* Wire ISR to sc_irq — filter + thread pair, arg = &sc->sc_msgbuf. */
int	brcm_pci_msgbuf_bind_intr(struct brcm_pci_softc *,
	    driver_filter_t *filter, driver_intr_t *thread, void *arg);
void	brcm_pci_msgbuf_unbind_intr(struct brcm_pci_softc *);
/* Deliver an already-decoded WL_EVENT payload to the brcm.c FullMAC
 * core.  Bridge implemented in if_brcm_pci.c so this header can stay
 * independent of brcmvar.h. */
void	brcm_pci_msgbuf_event_up(struct brcm_pci_softc *,
	    const uint8_t *payload, size_t len);

/*
 * Find an OPEN flowring matching dst MAC + prio, or return
 * (uint16_t)-1 if none.  Used by the txdata path to skip the
 * create-then-fail cycle when the flow already exists.
 */
uint16_t	brcm_pci_msgbuf_flowring_lookup(struct brcm_pci_softc *,
		    const uint8_t da[6], uint8_t prio);

/*
 * Hand an RX data mbuf to net80211.  Bridge in if_brcm_pci.c pulls
 * up the shared brcm_softc and calls ieee80211_input_all.  Consumes
 * `m` on both success and failure paths.
 */
void	brcm_pci_msgbuf_rx_up(struct brcm_pci_softc *, struct mbuf *m,
	    int rssi_dbm);

#endif /* _DEV_BRCM_BRCM_PCI_MSGBUF_H_ */
