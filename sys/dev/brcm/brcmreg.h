/*-
 * SPDX-License-Identifier: BSD-2-Clause AND ISC
 *
 * Copyright (c) 2026 Kyle Crenshaw <b1nc0d3x@gmail.com>
 * Copyright (c) 2010-2016 Broadcom Corporation
 * Copyright (c) 2016,2017 Patrick Wildt <patrick@blueri.se>
 *
 * Wire-protocol registers and structs for the brcm
 * (Broadcom FullMAC) driver.
 *
 * This file covers:
 *   - The BCM43xxx boot-ROM download protocol (DL_* opcodes,
 *     TRX envelope) used to push firmware to a chip that
 *     just enumerated.
 *   - The BCDC (Broadcom Common Driver Code) dcmd / event /
 *     data framing the firmware speaks once running.
 *   - The firmware-side iovar payload structs (scan params,
 *     join params, wsec keys, BSS info, etc.) needed for
 *     IOVAR get/set.
 *
 * Field offsets, opcode numbers and byte order come from
 * OpenBSD's bwfm driver (Patrick Wildt et al.), rewritten
 * in FreeBSD style. Layouts are __packed because the chip
 * parses them by raw byte offset.
 *
 * Portions derived from OpenBSD sys/dev/ic/bwfmreg.h are covered by the
 * following notice:
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _DEV_BRCM_BRCMREG_H_
#define _DEV_BRCM_BRCMREG_H_

#include <sys/types.h>
#include <sys/cdefs.h>

/*
 * USB vendor + product IDs that ship a Broadcom boot ROM.
 *
 * Kept here (not in if_brcm_usb.c) so the SDIO and PCIe
 * attachments can use the chip table without pulling in
 * USB headers.
 */
#define	BRCM_USB_VENDOR_BROADCOM	0x0a5c
#define	BRCM_USB_PRODUCT_BCM43143	0xbd1e
#define	BRCM_USB_PRODUCT_BCM43236	0xbd17
#define	BRCM_USB_PRODUCT_BCM43242	0xbd1f
#define	BRCM_USB_PRODUCT_BCM43569	0xbd27
#define	BRCM_USB_PRODUCT_BCMFW		0x0bdc	/* post-download enumeration */

/*
 * Vendor bRequest values the boot ROM accepts on EP0.
 * bmRequestType 0x40 for host->device, 0xc0 for device->host.
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
 * struct bootrom_id: what DL_GETVER hands back.
 *
 * Little-endian on the wire. chip + chiprev together pin
 * down the silicon revision so we can pick firmware.
 * After firmware boots, DL_GETVER returns BRCM_POSTBOOT_ID
 * in the chip field to signal "out of boot ROM".
 */
#define	BRCM_POSTBOOT_ID	0xa123

struct brcm_bootrom_id {
	uint32_t	chip;	/* chip silicon id */
	uint32_t	chiprev;	/* chip revision */
	uint32_t	ramsize;	/* on-chip RAM size */
	uint32_t	remapbase;	/* RAM remap base */
	uint32_t	boardtype;	/* board type id */
	uint32_t	boardrev;	/* board revision */
} __packed;

/*
 * TRX firmware envelope.
 *
 * The boot ROM expects a TRX-wrapped image: a 28-byte
 * header (magic, total length, CRC32, flag-version,
 * offsets[3]) followed by the payload. Pushed as-is via
 * chunked bulk OUT. The boot ROM parses header + offsets[]
 * itself.
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
 * Reply to DL_START / DL_GETSTATE.
 *
 * `state` is one of BRCM_DL_*. `bytes` is how many of our
 * payload bytes the chip has accepted so far.
 */
struct brcm_rdl_state {
	uint32_t	state;
	uint32_t	bytes;
} __packed;

/*
 * Chip-info dispatch table.
 *
 * Looked up by (chip, chiprev) read from the boot ROM via
 * DL_GETVER. Resolves once at attach into a firmware blob
 * name plus a human-readable description, so callers never
 * have to look at raw silicon IDs. Reused by SDIO / PCIe
 * attaches.
 */
struct brcm_chip_info {
	uint32_t	chip;	/* chip silicon id */
	uint32_t	chiprev_min;	/* lowest matching revision */
	uint32_t	chiprev_max;	/* highest matching revision */
	const char	*fwname;	/* firmware blob name */
	const char	*desc;	/* human-readable name */
	/*
	 * D11 chanspec encoding used by this chip's firmware.
	 * true  = D11N  (pre-2014 blobs: BCM43143/43236/43242).
	 * false = D11AC (2014+ blobs: BCM43455, BCM43569, ...).
	 * Selects which brcm_chan_to_chanspec_* helper is used
	 * when building SET_SSID / bsscfg:join payloads.
	 */
	bool		d11n;
};

/*
 * BCDC (Broadcom Common Driver Code) — the wire protocol
 * between host and running firmware.
 *
 * Two message kinds:
 *   1. Control (dcmd): get/set firmware variables ("iovars")
 *      and structured commands. Goes over the USB control
 *      endpoint with vendor-class interface requests:
 *        TX = bmRequestType 0x21, bRequest 0
 *        RX = bmRequestType 0xa1, bRequest 1
 *   2. Data: 802.11 frames. Goes over bulk endpoints with a
 *      4-byte BCDC header at the start.
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
 * Payload for the DISASSOC dcmd.
 *
 * Wire layout: {val=4, bssid[6], pad[2]} = 12 bytes. The
 * tail pad matches the wire alignment the firmware expects.
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
 * "escan" iovar request payload (v0 format used by older
 * Broadcom firmware such as the 43236 blob).
 *
 * Sent via SET_VAR with the name "escan". The firmware
 * emits ESCAN_RESULT events as it walks the channel list.
 */
#define	BRCM_MAX_SSID_LEN		32
#define	BRCM_DOT11_BSSTYPE_ANY		2
#define	BRCM_SCANTYPE_ACTIVE		0
#define	BRCM_SCANTYPE_PASSIVE		1
#define	BRCM_ESCAN_REQ_VERSION		1
#define	BRCM_WL_ESCAN_ACTION_START	1

struct brcm_ssid {
	uint32_t	len;	/* length of ssid */
	uint8_t		ssid[BRCM_MAX_SSID_LEN];	/* ssid bytes */
} __packed;

struct brcm_scan_params_v0 {
	struct brcm_ssid	ssid;	/* target ssid (empty = any) */
	uint8_t			bssid[6];	/* target bssid (broadcast = any) */
	uint8_t			bss_type;	/* infrastructure or any */
	uint8_t			scan_type;	/* active or passive */
	uint32_t		nprobes;	/* probe requests per channel */
	uint32_t		active_time;	/* dwell on an active channel */
	uint32_t		passive_time;	/* dwell on a passive channel */
	uint32_t		home_time;	/* time back on home channel */
	uint32_t		channel_num;	/* channel count (0 = all) */
} __packed;

struct brcm_escan_params_v0 {
	uint32_t			version;	/* escan request version */
	uint16_t			action;	/* start or abort */
	uint16_t			sync_id;	/* tag echoed back in results */
	struct brcm_scan_params_v0	scan_params;	/* the scan settings */
} __packed;

/*
 * 4-byte BCDC data header added to every TX frame and
 * present on every RX frame.
 *
 * Different from the dcmd header used on the control
 * endpoint. Data frames go over bulk; dcmd over EP0.
 */
struct brcm_bcdc_hdr {
	uint8_t		flags;	/* protocol version and flags */
#define	BRCM_BCDC_FLAG_PROTO_VER	2
#define	BRCM_BCDC_FLAG_VER(x)		(((x) & 0xf) << 4)
#define	BRCM_BCDC_FLAG_SUM_GOOD		(1u << 2)	/* rx */
#define	BRCM_BCDC_FLAG_SUM_NEEDED	(1u << 3)	/* tx */
	uint8_t		priority;	/* traffic priority */
#define	BRCM_BCDC_PRIORITY_MASK		0x7u
	uint8_t		flags2;	/* interface index bits */
#define	BRCM_BCDC_FLAG2_IF_MASK		0xfu
	uint8_t		data_offset;	/* extra header words after BCDC */
} __packed;

/*
 * Broadcom event wrapper.
 *
 * After the BCDC header (plus optional data_offset padding),
 * a fake Ethernet frame with ethertype 0x886c tells the
 * host the rest is a BRCM event message, not real data.
 * Real data has its own ethertype (0x0800 etc.) and goes to
 * net80211 instead.
 */
#define	BRCM_ETHERTYPE_BRCM	0x886c

struct brcm_brcm_ethhdr {
	uint16_t	subtype;	/* event subtype */
	uint16_t	length;	/* payload length */
	uint8_t		version;	/* header version */
	uint8_t		oui[3];		/* "\x00\x10\x18" */
	uint16_t	usr_subtype;	/* vendor subtype (event) */
#define	BRCM_BRCM_SUBTYPE_EVENT	1
} __packed;

struct brcm_event_msg {
	uint16_t	version;	/* message version */
	uint16_t	flags;	/* event flags */
	uint32_t	event_type;	/* which event */
	uint32_t	status;	/* event status */
	uint32_t	reason;	/* reason code */
	uint32_t	auth_type;	/* auth type */
	uint32_t	datalen;	/* length of trailing data */
	uint8_t		addr[6];	/* peer MAC address */
	char		ifname[16];	/* interface name */
	uint8_t		ifidx;	/* interface index */
	uint8_t		bsscfgidx;	/* bss config index */
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
 * struct brcm_wsec_key matches the old `wl_wsec_key_t`
 * layout. Total is 164 bytes. The padding fields exist to
 * keep the offsets the chip's BCDC dispatcher expects.
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
 * WPA3-OWE (Opportunistic Wireless Encryption, RFC 8110).
 *
 * Speculative value. The BCM43602 firmware (v7.35.177.61,
 * Nov 2015) predates RFC 8110 and has no OWE, so the value
 * is chosen to sit in the WPA3 family next to SAE_PSK.
 * Chip families that add OWE will publish their own
 * constant. The sysctl probe brcm.brcm_owe_probe says
 * whether the loaded fw accepts this value.
 */
#define	BRCM_WPA_AUTH_WPA3_OWE		0x100000	/* WPA3-OWE (speculative) */

#define	BRCM_WSEC_MAX_PSK_LEN		32
/*
 * Modern brcmfmac firmware (BCM43602/43455 v7.x) expects the full
 * 132-byte wsec_pmk struct (key buffer sized for a SAE password),
 * regardless of how many bytes key_len marks valid.  Sending the
 * old short 37-byte struct is rejected with BCME_BADARG.
 */
#define	BRCM_WSEC_MAX_SAE_PASSWORD_LEN	128
#define	BRCM_WSEC_PASSPHRASE		(1u << 0)

/*
 * "mfp" iovar values for Management Frame Protection.
 *
 * CAPABLE: fw adds MFPC to RSN caps and negotiates BIP with
 * APs that advertise MFPC. REQUIRED: refuses to associate
 * without MFP. Linux brcmfmac sets this per connection from
 * the MFPR/MFPC bits of the RSN IE in the connect request,
 * before the join (cfg80211.c, brcmf_set_key_mgmt).
 */
#define	BRCM_MFP_NONE			0
#define	BRCM_MFP_CAPABLE		1
#define	BRCM_MFP_REQUIRED		2

/*
 * CLM (Country Locale Matrix) blob upload via the "clmload"
 * iovar.
 *
 * Without it, the chip's regulatory data blocks TX. The AP
 * sends PROBERESP but the chip never sends AUTH because the
 * op is not allowed on that channel.
 */
#define	BRCM_DL_BEGIN			0x0002
#define	BRCM_DL_END			0x0004
#define	BRCM_DL_TYPE_CLM		2
#define	BRCM_DLOAD_HANDLER_VER		1
#define	BRCM_DLOAD_FLAG_VER_SHIFT	12
#define	BRCM_DLOAD_MAX_CHUNK_LEN	1400u

struct brcm_dload_data {
	uint16_t	flag;	/* begin/end and version bits */
	uint16_t	dload_type;	/* download type */
	uint32_t	len;	/* chunk length */
	uint32_t	crc;	/* chunk checksum */
	uint8_t		data[];	/* chunk bytes */
} __packed;

/*
 * Wire-format key install via the "wsec_key" iovar (164 bytes).
 *
 * Used in place of the BRCM_C_SET_KEY=45 dcmd, which
 * BCM43455 fw 7.45.x rejects with the 37-byte legacy struct.
 *
 * Fires for both PTK (index=0, ea=AP MAC, PRIMARY_KEY flag)
 * and GTK (index=1+, ea=bcast) after the 4-way handshake.
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

/* sizeof(brcm_wsec_key_le) MUST equal 164 for the wire format. */
_Static_assert(sizeof(struct brcm_wsec_key_le) == 164,
    "brcm_wsec_key_le wire size != 164");

/*
 * wsec_pmk payload.  As declared here the struct is 132 bytes
 * (2 + 2 + 128), the same size as brcm_wsec_pmk_le below.
 *
 * BCM43455 fw 7.45.x accepts a shorter 37-byte (2 + 2 + 33)
 * shape and returns BCME_BADARG (-2) on opcode 268 for the
 * larger 132-byte SAE-capable form.  With the 37-byte shape
 * and flags=BRCM_WSEC_PASSPHRASE, the chip's on-chip PBKDF2
 * derives the PMK and runs the 4-way handshake.
 */
struct brcm_wsec_pmk {
	uint16_t	key_len;	/* passphrase length */
	uint16_t	flags;	/* passphrase flag */
	uint8_t		key[BRCM_WSEC_MAX_SAE_PASSWORD_LEN];	/* key material (132-byte struct) */
} __packed;

/*
 * 132-byte SAE-capable form of the wsec_pmk struct.
 *
 * Needed by BCM43602 fw v7.35.x for MFP-negotiated joins.
 * Even in host-EAPOL mode the fw needs the raw PMK or
 * passphrase to derive MFP key material for management-
 * frame protection.
 *
 * Layout matches Linux brcmfmac's `brcmf_wsec_pmk_le` in
 * fwil_types.h.
 */
#define	BRCM_WSEC_MAX_SAE_PASSWORD_LEN	128
struct brcm_wsec_pmk_le {
	uint16_t	key_len;	/* key/passphrase length */
	uint16_t	flags;	/* mode flags */
	uint8_t		key[BRCM_WSEC_MAX_SAE_PASSWORD_LEN];	/* key or passphrase bytes */
} __packed;
_Static_assert(sizeof(struct brcm_wsec_pmk_le) == 132,
    "brcm_wsec_pmk_le wire size != 132");

/*
 * join_pref iovar entry.
 *
 * Fixed 4 bytes each. Usually 2 entries are sent: RSSI plus
 * an optional band boost. Matches Linux brcmfmac's
 * `struct brcmf_join_pref_params`.
 */
#define	BRCM_JOIN_PREF_RSSI		1
#define	BRCM_JOIN_PREF_WPA		2
#define	BRCM_JOIN_PREF_BAND		3
#define	BRCM_JOIN_PREF_RSSI_DELTA	4

#define	BRCM_JOIN_PREF_RSSI_BOOST	8	/* default 5GHz RSSI gain */

struct brcm_join_pref_params {
	uint8_t		type;	/* preference type */
	uint8_t		len;	/* entry length */
	uint8_t		rssi_gain;	/* signal boost */
	uint8_t		band;	/* which band */
} __packed;

struct brcm_assoc_params {
	uint8_t		bssid[6];	/* target bssid */
	uint16_t	pad;
	uint32_t	chanspec_num;	/* channel count */
	uint16_t	chanspec_list[1];	/* optional, send len conditional */
} __packed;

struct brcm_join_params {
	struct brcm_ssid		ssid;	/* network name */
	struct brcm_assoc_params	assoc;	/* association parameters */
} __packed;

/*
 * Send length rules:
 * 0 chanspecs (chip auto-scans for SSID):
 *   sizeof(ssid) + offsetof(assoc, chanspec_list)
 * 1 chanspec (chip parks on that channel):
 *   sizeof(ssid) + offsetof(assoc, chanspec_list) + sizeof(u16)
 */
#define	BRCM_JOIN_PARAMS_FIXED_SIZE \
	(sizeof(struct brcm_ssid) + \
	 offsetof(struct brcm_assoc_params, chanspec_list))

/*
 * Extended join (bsscfg:join).
 *
 * Preferred over BRCM_C_SET_SSID on recent firmware. It
 * bundles scan params + chanspec_list in one shot so the
 * chip can park the radio on the target channel before it
 * sends AUTH.
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
	uint8_t		bssid[6];	/* target bssid */
	uint8_t		pad[2];		/* align chanspec_num to 4 */
	uint32_t	chanspec_num;	/* channel count */
	uint16_t	chanspec_list[1];	/* channel list */
} __packed;

struct brcm_ext_join_params {
	struct brcm_ssid		ssid;	/* network name */
	struct brcm_join_scan_params	scan;	/* join-scan settings */
	struct brcm_ext_assoc_params	assoc;	/* association parameters */
} __packed;

/*
 * BSS info payload that follows event_msg inside an
 * ESCAN_RESULT event. The outer wrapper carries the BSS count.
 */
#define	BRCM_MCSSET_LEN			16

struct brcm_bss_info {
	uint32_t	version;	/* struct version */
	uint32_t	length;	/* total length */
	uint8_t		bssid[6];	/* AP MAC address */
	uint16_t	beacon_period;	/* beacon interval */
	uint16_t	capability;	/* capability bits */
	uint8_t		ssid_len;	/* length of ssid */
	uint8_t		ssid[BRCM_MAX_SSID_LEN];	/* network name */
	uint8_t		pad0;
	uint32_t	nrates;	/* number of rates */
	uint8_t		rates[16];	/* supported rates */
	uint16_t	chanspec;	/* channel */
	uint16_t	atim_window;	/* ATIM window */
	uint8_t		dtim_period;	/* DTIM period */
	uint8_t		pad1;
	int16_t		rssi;	/* signal strength */
	int8_t		phy_noise;	/* noise floor */
	uint8_t		n_cap;	/* 11n capable */
	uint16_t	pad2;
	uint32_t	nbss_cap;	/* HT capabilities */
	uint8_t		ctl_ch;	/* control channel */
	uint8_t		pad3[3];
	uint32_t	reserved32[1];
	uint8_t		flags;	/* misc flags */
	uint8_t		reserved[3];
	uint8_t		basic_mcs[BRCM_MCSSET_LEN];	/* basic MCS set */
	uint16_t	ie_offset;	/* offset to IEs */
	uint16_t	pad4;
	uint32_t	ie_length;	/* length of IEs */
	int16_t		snr;	/* signal-to-noise ratio */
} __packed;

struct brcm_escan_results {
	uint32_t			buflen;	/* buffer length */
	uint32_t			version;	/* results version */
	uint16_t			sync_id;	/* tag from the request */
	uint16_t			bss_count;	/* number of BSS entries */
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
 * BCDC dcmd header. 16 bytes on the wire, little-endian.
 *
 * A variable-length payload follows. For an iovar GET, the
 * payload is the NUL-terminated iovar name followed by the
 * area where the response goes.
 */
struct brcm_bcdc_dcmd {
	uint32_t	cmd;	/* command opcode */
	uint32_t	len;	/* payload length */
	uint32_t	flags;	/* request flags */
	uint32_t	status;	/* firmware status */
} __packed;

#endif /* _DEV_BRCM_BRCMREG_H_ */
