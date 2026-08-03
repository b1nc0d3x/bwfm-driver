/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 *
 * Broadcom FullMAC (brcm) wire-protocol register and structure
 * definitions.  This file covers:
 *
 *   - The BCM43xxx boot-ROM download protocol (DL_* opcodes, TRX
 *     envelope) used to push firmware to a chip that just enumerated.
 *   - The BCDC (Broadcom Common Driver Code) dcmd / event / data
 *     framing the firmware speaks once it is running.
 *   - The firmware-side iovar payload structs (scan params, join
 *     params, wsec keys, BSS info, etc.) needed for IOVAR get/set.
 *
 * Field offsets, opcode numbers and byte order trace back to OpenBSD's
 * brcm driver (Patrick Wildt et al.); re-expressed in FreeBSD style.
 * Layouts are __packed because the chip parses them by raw byte offset.
 */

#ifndef _DEV_BRCM_BRCMREG_H_
#define _DEV_BRCM_BRCMREG_H_

#include <sys/types.h>
#include <sys/cdefs.h>

/*
 * USB vendor + product IDs that ship a Broadcom boot ROM.  Kept here
 * (rather than in if_brcm_usb.c) so a future SDIO / PCIe attach can
 * still consume the chip table without dragging in USB headers.
 */
#define	BRCM_USB_VENDOR_BROADCOM	0x0a5c
#define	BRCM_USB_PRODUCT_BCM43143	0xbd1e
#define	BRCM_USB_PRODUCT_BCM43236	0xbd17
#define	BRCM_USB_PRODUCT_BCM43242	0xbd1f
#define	BRCM_USB_PRODUCT_BCM43569	0xbd27
#define	BRCM_USB_PRODUCT_BCMFW		0x0bdc	/* post-download enumeration */

/*
 * Vendor-defined bRequest values the boot ROM accepts on EP0
 * (bmRequestType 0x40 for host->device, 0xc0 for device->host).
 * Borrowed from the Broadcom SDIO/USB shared bootloader.
 */
#define	BRCM_DL_GETSTATE	0
#define	BRCM_DL_CHECK_CRC	1
#define	BRCM_DL_GO		2
#define	BRCM_DL_START		3
#define	BRCM_DL_REBOOT		4
#define	BRCM_DL_GETVER		5
#define	BRCM_DL_GO_PROTECTED	6
#define	BRCM_DL_EXEC		7
#define	BRCM_DL_RESETCFG	8
#define	BRCM_DL_DEFER_RESP_OK	9

/* DL_GETSTATE response state values. */
#define	BRCM_DL_WAITING		0
#define	BRCM_DL_READY		1
#define	BRCM_DL_BAD_HDR		2
#define	BRCM_DL_BAD_CRC		3
#define	BRCM_DL_RUNNABLE	4
#define	BRCM_DL_START_FAIL	5
#define	BRCM_DL_NVRAM_TOOBIG	6
#define	BRCM_DL_IMAGE_TOOBIG	7

/*
 * struct bootrom_id — what DL_GETVER hands back.  Little-endian over
 * the wire; chip + chiprev together pin down the silicon revision for
 * firmware selection.  Once firmware boots, DL_GETVER returns
 * BRCM_POSTBOOT_ID in the chip field to signal "out of boot ROM."
 */
#define	BRCM_POSTBOOT_ID	0xa123

struct brcm_bootrom_id {
	uint32_t	chip;
	uint32_t	chiprev;
	uint32_t	ramsize;
	uint32_t	remapbase;
	uint32_t	boardtype;
	uint32_t	boardrev;
} __packed;

/*
 * TRX firmware envelope.  Boot ROM consumes a TRX-wrapped image:
 * 28-byte header (magic / total length / CRC32 / flag-version /
 * offsets[3]) followed by the payload.  Pushed verbatim via chunked
 * bulk OUT; the boot ROM parses header + offsets[] itself.
 */
#define	BRCM_TRX_MAGIC		0x30524448	/* "HDR0" */
#define	BRCM_TRX_UNCOMP_IMAGE	0x20		/* flag bit: uncompressed */
#define	BRCM_TRX_RDL_CHUNK	1500		/* bulk OUT chunk cap */

struct brcm_trx_header {
	uint32_t	magic;
	uint32_t	len;
	uint32_t	crc32;
	uint32_t	flag_version;
	uint32_t	offsets[3];
} __packed;

/*
 * Reply to DL_START / DL_GETSTATE.  state is one of BRCM_DL_*; bytes
 * is how many of our payload bytes the chip has accepted so far.
 */
struct brcm_rdl_state {
	uint32_t	state;
	uint32_t	bytes;
} __packed;

/*
 * Chip-info dispatch table.  Lookup is keyed on (chip, chiprev) read
 * from the boot ROM via DL_GETVER.  Resolves once at attach into the
 * firmware blob name + a human-readable description so callers never
 * have to inspect raw silicon IDs.  Reused by SDIO / PCIe attaches.
 */
struct brcm_chip_info {
	uint32_t	chip;
	uint32_t	chiprev_min;
	uint32_t	chiprev_max;
	const char	*fwname;
	const char	*desc;
};

/*
 * BCDC (Broadcom Common Driver Code) — wire protocol between host and
 * running firmware.  Two flavours of message:
 *
 *   1. Control (dcmd) — get/set firmware variables ("iovars") and
 *      structured commands.  Travels over the USB control endpoint
 *      with vendor-class interface requests:
 *        TX = bmRequestType 0x21, bRequest 0
 *        RX = bmRequestType 0xa1, bRequest 1
 *   2. Data — 802.11 frames.  Travels over bulk endpoints with a
 *      4-byte BCDC header prefix.
 */

/* Selected BCDC dcmd opcodes. */
#define	BRCM_C_UP			2	/* bring data plane up */
#define	BRCM_C_DOWN			3	/* tear data plane down */
#define	BRCM_C_SCAN			50	/* start scan (legacy) */
#define	BRCM_C_DISASSOC			52	/* leave current BSS */
#define	BRCM_C_REASSOC			53	/* trigger (re)assoc to last BSS */
#define	BRCM_C_SET_BSSID		54	/* set target BSSID + auto-join */
#define	BRCM_C_SET_ROAM_TRIGGER		55	/* {dBm, band} */
#define	BRCM_C_SET_ROAM_DELTA		57	/* {dBm, band} */
#define	BRCM_C_GET_PM			85
#define	BRCM_C_SET_PM			86	/* PM_OFF/MAX/FAST */
#define	BRCM_C_GET_REVINFO		98
#define	BRCM_C_SET_SCB_AUTHORIZE	121	/* 6-byte MAC payload */
#define	BRCM_C_GET_BSS_INFO		136
#define	BRCM_C_SET_SCAN_CHANNEL_TIME	185
#define	BRCM_C_SET_SCAN_UNASSOC_TIME	187
#define	BRCM_C_SET_ASSOC_PREFER		205
#define	BRCM_C_SET_FAKEFRAG		219	/* frameburst */
#define	BRCM_C_SET_SCAN_PASSIVE_TIME	258
#define	BRCM_C_GET_VAR			262
#define	BRCM_C_SET_VAR			263

/* SET_PM values */
#define	BRCM_PM_OFF			0	/* always awake */
#define	BRCM_PM_MAX			1	/* max power save */
#define	BRCM_PM_FAST			2	/* fast power save */

/*
 * Payload for DISASSOC dcmd.  Wire layout: {val=4, bssid[6], pad[2]} =
 * 12 bytes.  Explicit tail pad matches the on-wire alignment expected
 * by firmware.
 */
struct brcm_scb_val_le {
	uint32_t	val;		/* reason code (LE) */
	uint8_t		ea[6];		/* BSSID */
	uint8_t		pad[2];		/* align to 12 bytes */
} __packed;
_Static_assert(sizeof(struct brcm_scb_val_le) == 12,
    "brcm_scb_val_le must be 12 bytes");

/* Roaming defaults. */
#define	BRCM_ROAM_TRIGGER_LEVEL		(-75)	/* dBm */
#define	BRCM_ROAM_DELTA			20	/* dBm gain to actually roam */
#define	BRCM_BAND_ALL			3

/*
 * "escan" iovar request payload (v0 format used by older Broadcom
 * firmware images such as the 43236 blob).  Sent via SET_VAR with
 * the name "escan"; the firmware emits ESCAN_RESULT events as it
 * walks the channel list.
 */
#define	BRCM_MAX_SSID_LEN		32
#define	BRCM_DOT11_BSSTYPE_ANY		2
#define	BRCM_SCANTYPE_ACTIVE		0
#define	BRCM_SCANTYPE_PASSIVE		1
#define	BRCM_ESCAN_REQ_VERSION		1
#define	BRCM_WL_ESCAN_ACTION_START	1

struct brcm_ssid {
	uint32_t	len;
	uint8_t		ssid[BRCM_MAX_SSID_LEN];
} __packed;

struct brcm_scan_params_v0 {
	struct brcm_ssid	ssid;
	uint8_t			bssid[6];
	uint8_t			bss_type;
	uint8_t			scan_type;
	uint32_t		nprobes;
	uint32_t		active_time;
	uint32_t		passive_time;
	uint32_t		home_time;
	uint32_t		channel_num;
} __packed;

struct brcm_escan_params_v0 {
	uint32_t			version;
	uint16_t			action;
	uint16_t			sync_id;
	struct brcm_scan_params_v0	scan_params;
} __packed;

/*
 * 4-byte BCDC data header prepended to every TX frame and present on
 * every RX frame.  Distinct from the dcmd header used on the control
 * endpoint; data frames travel over bulk, dcmd over EP0.
 */
struct brcm_bcdc_hdr {
	uint8_t		flags;
#define	BRCM_BCDC_FLAG_PROTO_VER	2
#define	BRCM_BCDC_FLAG_VER(x)		(((x) & 0xf) << 4)
#define	BRCM_BCDC_FLAG_SUM_GOOD		(1u << 2)	/* rx */
#define	BRCM_BCDC_FLAG_SUM_NEEDED	(1u << 3)	/* tx */
	uint8_t		priority;
#define	BRCM_BCDC_PRIORITY_MASK		0x7u
	uint8_t		flags2;
#define	BRCM_BCDC_FLAG2_IF_MASK		0xfu
	uint8_t		data_offset;	/* extra header words after BCDC */
} __packed;

/*
 * Broadcom-proprietary event encapsulation.  After the BCDC header
 * (+ optional data_offset padding) comes a synthetic Ethernet frame
 * whose ethertype is 0x886c — that signals to the host that the
 * remaining bytes are a BCM "BRCM" event message, not a real data
 * frame.  A real data frame has its own ethertype (0x0800 etc.) and
 * gets handed to net80211 instead.
 */
#define	BRCM_ETHERTYPE_BRCM	0x886c

struct brcm_brcm_ethhdr {
	uint16_t	subtype;
	uint16_t	length;
	uint8_t		version;
	uint8_t		oui[3];		/* "\x00\x10\x18" */
	uint16_t	usr_subtype;
#define	BRCM_BRCM_SUBTYPE_EVENT	1
} __packed;

struct brcm_event_msg {
	uint16_t	version;
	uint16_t	flags;
	uint32_t	event_type;
	uint32_t	status;
	uint32_t	reason;
	uint32_t	auth_type;
	uint32_t	datalen;
	uint8_t		addr[6];
	char		ifname[16];
	uint8_t		ifidx;
	uint8_t		bsscfgidx;
} __packed;

/* Event types. */
#define	BRCM_E_TYPE_SET_SSID		0
#define	BRCM_E_TYPE_JOIN		1
#define	BRCM_E_TYPE_AUTH		3
#define	BRCM_E_DEAUTH			5
#define	BRCM_E_TYPE_ASSOC		7
#define	BRCM_E_TYPE_DISASSOC		11
#define	BRCM_E_TYPE_LINK		16
#define	BRCM_E_EAPOL_MSG		25
#define	BRCM_E_IF			54
#define	BRCM_E_TYPE_ESCAN_RESULT	69
#define	BRCM_E_TYPE_PSK_SUP		46
#define	BRCM_E_LAST			128

#define	BRCM_EVENT_MASK_LEN		(BRCM_E_LAST / 8)

/* Event statuses. */
#define	BRCM_E_STATUS_SUCCESS		0
#define	BRCM_E_STATUS_FAIL		1
#define	BRCM_E_STATUS_TIMEOUT		2
#define	BRCM_E_STATUS_PARTIAL		8

/* Event flags. */
#define	BRCM_E_FLAG_LINK_UP		(1 << 0)

/* BRCM_C_SET_SSID join params (legacy non-extended form). */
#define	BRCM_C_SET_INFRA		20
#define	BRCM_C_SET_AUTH			22
#define	BRCM_C_SET_SSID			26
#define	BRCM_C_SET_KEY			45
#define	BRCM_C_SET_ASSOC_PREFER		205	/* WLC_BAND_AUTO */
#define	BRCM_C_SET_WSEC_PMK		268

/* BRCMF_C_SET_ASSOC_PREFER band values. */
#define	BRCM_WLC_BAND_AUTO		0
#define	BRCM_WLC_BAND_5G		1
#define	BRCM_WLC_BAND_2G		2

/*
 * Broadcom WLC key install (BRCM_C_SET_KEY = opcode 45).
 *
 * struct brcm_wsec_key matches the legacy `wl_wsec_key_t` layout.
 * Total = 164 bytes; padding fields exist to preserve the historical
 * offsets the chip's BCDC dispatcher expects.
 *
 *   index   0           pairwise (PTK) slot
 *           1, 2, 3     group (GTK) slots
 *   len     0           clear the key
 *           16, 32      AES-CCM PTK / GTK material
 *   algo    BRCM_CRYPTO_ALGO_AES_CCM = 4 (WPA2 CCMP)
 *           BRCM_CRYPTO_ALGO_TKIP = 2   (WPA1 / GTK)
 *           BRCM_CRYPTO_ALGO_OFF = 0    (delete)
 *   flags   BRCM_WSEC_PRIMARY_KEY  for the active PTK
 *   ea      peer BSSID for pairwise, broadcast for group
 */
#define	BRCM_CRYPTO_ALGO_OFF		0
#define	BRCM_CRYPTO_ALGO_WEP1		1
#define	BRCM_CRYPTO_ALGO_TKIP		2
#define	BRCM_CRYPTO_ALGO_WEP128		3
#define	BRCM_CRYPTO_ALGO_AES_CCM	4

#define	BRCM_WSEC_PRIMARY_KEY		(1u << 1)

struct brcm_wsec_key {
	uint32_t	index;
	uint32_t	len;
	uint8_t		data[32];
	uint32_t	pad1[18];
	uint32_t	algo;
	uint32_t	flags;
	uint32_t	pad2[3];
	uint32_t	iv_initialized;
	uint32_t	pad3;
	uint32_t	rxiv_hi;
	uint16_t	rxiv_lo;
	uint16_t	pad_align;
	uint32_t	pad4[2];
	uint8_t		ea[6];
	uint16_t	pad_end;
} __packed;

#define	BRCM_AUTH_OPEN			0

#define	BRCM_WSEC_NONE			(0u << 0)
#define	BRCM_WSEC_WEP			(1u << 0)
#define	BRCM_WSEC_TKIP			(1u << 1)
#define	BRCM_WSEC_AES			(1u << 2)

#define	BRCM_WPA_AUTH_DISABLED		(0u << 0)
#define	BRCM_WPA_AUTH_WPA_PSK		(1u << 2)	/* WPA-PSK */
#define	BRCM_WPA_AUTH_WPA2_UNSPEC	(1u << 6)	/* WPA2/802.1X */
#define	BRCM_WPA_AUTH_WPA2_PSK		(1u << 7)	/* WPA2-PSK */
#define	BRCM_WPA_AUTH_WPA2_1X_SHA256	0x1000		/* 802.1X SHA-256 */
#define	BRCM_WPA_AUTH_WPA2_FT		0x4000		/* Fast BSS Transition */
#define	BRCM_WPA_AUTH_WPA2_PSK_SHA256	(1u << 15)	/* WPA2-PSK-SHA256 (MFP) */
#define	BRCM_WPA_AUTH_WPA3_SAE_PSK	0x40000		/* WPA3-SAE PSK */
/*
 * WPA3-OWE (Opportunistic Wireless Encryption, RFC 8110).  Speculative
 * bit — no BCM43602 fw has ever implemented it (fw v7.35.177.61 is
 * from Nov 2015, two years before RFC 8110).  Value chosen to sit in
 * the wpa3-family band alongside SAE_PSK.  Real chip families that
 * support OWE will publish their own constant; the sysctl probe
 * brcm.brcm_owe_probe reports whether the currently-loaded fw accepts
 * it.
 */
#define	BRCM_WPA_AUTH_WPA3_OWE		0x100000	/* WPA3-OWE (speculative) */

#define	BRCM_WSEC_MAX_PSK_LEN		32
#define	BRCM_WSEC_PASSPHRASE		(1u << 0)

/*
 * "mfp" iovar values for Management Frame Protection negotiation.
 * When set to CAPABLE, fw includes MFPC in RSN caps and negotiates BIP
 * with MFPC-advertising APs; REQUIRED refuses to associate without MFP.
 * Linux brcmfmac sets this per-connection from the M2 RSN cap bits.
 */
#define	BRCM_MFP_NONE			0
#define	BRCM_MFP_CAPABLE		1
#define	BRCM_MFP_REQUIRED		2

/*
 * CLM (Country Locale Matrix) blob upload via "clmload" iovar.
 * Without it the chip's regulatory data restricts TX: PROBERESP
 * frames come back from the AP but the chip never transmits AUTH
 * because the operation is forbidden on that channel.
 */
#define	BRCM_DL_BEGIN			0x0002
#define	BRCM_DL_END			0x0004
#define	BRCM_DL_TYPE_CLM		2
#define	BRCM_DLOAD_HANDLER_VER		1
#define	BRCM_DLOAD_FLAG_VER_SHIFT	12
#define	BRCM_DLOAD_MAX_CHUNK_LEN	1400u

struct brcm_dload_data {
	uint16_t	flag;
	uint16_t	dload_type;
	uint32_t	len;
	uint32_t	crc;
	uint8_t		data[];
} __packed;

/*
 * Wire-format key install via "wsec_key" iovar (164 bytes).  Used in
 * place of BRCM_C_SET_KEY=45 dcmd, which BCM43455 fw 7.45.x rejects
 * with the 37-byte legacy struct.  Fires for both PTK (index=0,
 * ea=AP MAC, PRIMARY_KEY flag) and GTK (index=1+, ea=bcast) after
 * the 4-way handshake completes.
 */
#define	BRCM_WLAN_MAX_KEY_LEN	32

struct brcm_wsec_key_le {
	uint32_t	index;			/* key index */
	uint32_t	len;			/* key length */
	uint8_t		data[BRCM_WLAN_MAX_KEY_LEN];
	uint32_t	pad_1[18];
	uint32_t	algo;			/* CRYPTO_ALGO_* */
	uint32_t	flags;			/* BRCM_WSEC_PRIMARY_KEY etc. */
	uint32_t	pad_2[3];
	uint32_t	iv_initialized;
	uint32_t	pad_3;
	struct {
		uint32_t hi;
		uint16_t lo;
	} rxiv;					/* compiler pads lo→4 (8 B) */
	uint32_t	pad_4[2];
	uint8_t		ea[6];			/* compiler pads to align (8 B) */
};

/* sizeof(brcm_wsec_key_le) MUST equal 164 to match the wire format. */
_Static_assert(sizeof(struct brcm_wsec_key_le) == 164,
    "brcm_wsec_key_le wire size != 164");

/*
 * 37 bytes total (2 + 2 + 33).  This is the wire layout that
 * BCM43455 fw 7.45.x actually accepts: passing the larger 132-byte
 * SAE-capable form makes the fw return BCME_BADARG (-2) on opcode
 * 268.  With the 37-byte shape + flags=BRCM_WSEC_PASSPHRASE the
 * chip's on-chip PBKDF2 derives the PMK and tries the 4-way
 * handshake.
 */
struct brcm_wsec_pmk {
	uint16_t	key_len;
	uint16_t	flags;
	uint8_t		key[BRCM_WSEC_MAX_PSK_LEN + 1];
} __packed;

/*
 * 132-byte SAE-capable form of the wsec_pmk struct.  Required by
 * BCM43602 fw v7.35.x when performing MFP-negotiated associations:
 * even in host-EAPOL mode the fw needs the raw PMK / passphrase to
 * derive MFP key material for management-frame protection.  Layout
 * matches Linux brcmfmac's `brcmf_wsec_pmk_le` in fwil_types.h.
 */
#define	BRCM_WSEC_MAX_SAE_PASSWORD_LEN	128
struct brcm_wsec_pmk_le {
	uint16_t	key_len;
	uint16_t	flags;
	uint8_t		key[BRCM_WSEC_MAX_SAE_PASSWORD_LEN];
} __packed;
_Static_assert(sizeof(struct brcm_wsec_pmk_le) == 132,
    "brcm_wsec_pmk_le wire size != 132");

/*
 * join_pref iovar entry.  Fixed 4 bytes; typically 2 entries are sent
 * (RSSI + optional band boost).  Mirrors Linux brcmfmac's
 * `struct brcmf_join_pref_params`.
 */
#define	BRCM_JOIN_PREF_RSSI		1
#define	BRCM_JOIN_PREF_WPA		2
#define	BRCM_JOIN_PREF_BAND		3
#define	BRCM_JOIN_PREF_RSSI_DELTA	4

#define	BRCM_JOIN_PREF_RSSI_BOOST	8	/* default 5GHz RSSI gain */

struct brcm_join_pref_params {
	uint8_t		type;
	uint8_t		len;
	uint8_t		rssi_gain;
	uint8_t		band;
} __packed;

struct brcm_assoc_params {
	uint8_t		bssid[6];
	uint16_t	pad;
	uint32_t	chanspec_num;
	uint16_t	chanspec_list[1];	/* optional, send len conditional */
} __packed;

struct brcm_join_params {
	struct brcm_ssid		ssid;
	struct brcm_assoc_params	assoc;
} __packed;

/*
 * Send length when caller has 0 chanspecs (chip auto-scans for SSID):
 *   sizeof(ssid) + offsetof(assoc, chanspec_list)
 * vs when caller passes 1 chanspec (chip parks on that channel):
 *   sizeof(ssid) + offsetof(assoc, chanspec_list) + sizeof(u16)
 */
#define	BRCM_JOIN_PARAMS_FIXED_SIZE \
	(sizeof(struct brcm_ssid) + \
	 offsetof(struct brcm_assoc_params, chanspec_list))

/*
 * Extended join (bsscfg:join) -- preferred over BRCM_C_SET_SSID on
 * recent firmware because it bundles the scan params + chanspec_list
 * in one shot so the chip can park the radio on the target channel
 * before issuing AUTH.
 */
struct brcm_join_scan_params {
	uint8_t		scan_type;	/* 0 = use default */
	uint8_t		pad[3];
	uint32_t	nprobes;	/* -1 = use default */
	uint32_t	active_time;	/* -1 = use default */
	uint32_t	passive_time;	/* -1 = use default */
	uint32_t	home_time;	/* -1 = use default */
} __packed;

struct brcm_ext_assoc_params {
	uint8_t		bssid[6];
	uint8_t		pad[2];		/* align chanspec_num to 4 */
	uint32_t	chanspec_num;
	uint16_t	chanspec_list[1];
} __packed;

struct brcm_ext_join_params {
	struct brcm_ssid		ssid;
	struct brcm_join_scan_params	scan;
	struct brcm_ext_assoc_params	assoc;
} __packed;

/*
 * BSS info payload that follows the event_msg inside an
 * ESCAN_RESULT event.  Outer wrapper carries the BSS count.
 */
#define	BRCM_MCSSET_LEN			16

struct brcm_bss_info {
	uint32_t	version;
	uint32_t	length;
	uint8_t		bssid[6];
	uint16_t	beacon_period;
	uint16_t	capability;
	uint8_t		ssid_len;
	uint8_t		ssid[BRCM_MAX_SSID_LEN];
	uint8_t		pad0;
	uint32_t	nrates;
	uint8_t		rates[16];
	uint16_t	chanspec;
	uint16_t	atim_window;
	uint8_t		dtim_period;
	uint8_t		pad1;
	int16_t		rssi;
	int8_t		phy_noise;
	uint8_t		n_cap;
	uint16_t	pad2;
	uint32_t	nbss_cap;
	uint8_t		ctl_ch;
	uint8_t		pad3[3];
	uint32_t	reserved32[1];
	uint8_t		flags;
	uint8_t		reserved[3];
	uint8_t		basic_mcs[BRCM_MCSSET_LEN];
	uint16_t	ie_offset;
	uint16_t	pad4;
	uint32_t	ie_length;
	int16_t		snr;
} __packed;

struct brcm_escan_results {
	uint32_t			buflen;
	uint32_t			version;
	uint16_t			sync_id;
	uint16_t			bss_count;
	/* followed by bss_info[bss_count] */
} __packed;

/* dcmd flags bits */
#define	BRCM_BCDC_DCMD_ERROR		(1u << 0)
#define	BRCM_BCDC_DCMD_GET		(0u << 1)
#define	BRCM_BCDC_DCMD_SET		(1u << 1)
#define	BRCM_BCDC_DCMD_IF_SHIFT		12
#define	BRCM_BCDC_DCMD_IF_MASK		0xfu
#define	BRCM_BCDC_DCMD_ID_SHIFT		16
#define	BRCM_BCDC_DCMD_ID_MASK		0xffffu

/*
 * BCDC dcmd header — 16 bytes on the wire, little-endian.  Variable-
 * length payload follows.  When sending an iovar GET, the payload is
 * the NUL-terminated iovar name followed by the response output area.
 */
struct brcm_bcdc_dcmd {
	uint32_t	cmd;
	uint32_t	len;
	uint32_t	flags;
	uint32_t	status;
} __packed;

#endif /* _DEV_BRCM_BRCMREG_H_ */
