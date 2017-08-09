/*
 * Copyright (c) 2011-2014, 2016 The Linux Foundation. All rights reserved.
 *
 * Previously licensed under the ISC license by Qualcomm Atheros, Inc.
 *
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */

/**
 * @file ol_txrx_api.h
 * @brief Definitions used in multiple external interfaces to the txrx SW.
 */
#ifndef _OL_TXRX_API__H_
#define _OL_TXRX_API__H_

/**
 * @brief ADDBA negotiation status, used both during requests and confirmations
 */
enum ol_addba_status {
	/* status: negotiation started or completed successfully */
	ol_addba_success,

	/* reject: aggregation is not applicable - don't try again */
	ol_addba_reject,

	/* busy: ADDBA negotiation couldn't be performed - try again later */
	ol_addba_busy,
};

enum ol_sec_type {
	ol_sec_type_none,
	ol_sec_type_wep128,
	ol_sec_type_wep104,
	ol_sec_type_wep40,
	ol_sec_type_tkip,
	ol_sec_type_tkip_nomic,
	ol_sec_type_aes_ccmp,
	ol_sec_type_wapi,

	/* keep this last! */
	ol_sec_type_types
};

typedef void (*tp_ol_packetdump_cb)(qdf_nbuf_t netbuf,
		uint8_t status, uint8_t vdev_id, uint8_t type);
void ol_register_packetdump_callback(tp_ol_packetdump_cb ol_tx_packetdump_cb,
			tp_ol_packetdump_cb ol_rx_packetdump_cb);
void ol_deregister_packetdump_callback(void);

#endif /* _OL_TXRX_API__H_ */
