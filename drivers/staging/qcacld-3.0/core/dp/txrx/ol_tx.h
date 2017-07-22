/*
 * Copyright (c) 2011-2017 The Linux Foundation. All rights reserved.
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
 * @file ol_tx.h
 * @brief Internal definitions for the high-level tx module.
 */
#ifndef _OL_TX__H_
#define _OL_TX__H_

#include <qdf_nbuf.h>           /* qdf_nbuf_t */
#include <qdf_lock.h>
#include <cdp_txrx_cmn.h>       /* ol_txrx_vdev_t, etc. */
#include <cdp_txrx_misc.h>      /* ol_tx_spec */

#include <ol_txrx_types.h>      /* ol_tx_desc_t, ol_txrx_msdu_info_t */

qdf_nbuf_t ol_tx_ll(ol_txrx_vdev_handle vdev, qdf_nbuf_t msdu_list);
qdf_nbuf_t ol_tx_ll_wrapper(ol_txrx_vdev_handle vdev, qdf_nbuf_t msdu_list);
#ifdef WLAN_FEATURE_FASTPATH
qdf_nbuf_t ol_tx_ll_fast(ol_txrx_vdev_handle vdev, qdf_nbuf_t msdu_list);
#endif

qdf_nbuf_t ol_tx_ll_queue(ol_txrx_vdev_handle vdev, qdf_nbuf_t msdu_list);

#ifdef CONFIG_HL_SUPPORT
#define OL_TX_SEND ol_tx_hl
#else
#define OL_TX_SEND OL_TX_LL
#endif

#ifdef QCA_LL_LEGACY_TX_FLOW_CONTROL
#define OL_TX_LL ol_tx_ll_queue
#else
#define OL_TX_LL ol_tx_ll_wrapper
#endif

#ifdef QCA_LL_LEGACY_TX_FLOW_CONTROL
void ol_tx_vdev_ll_pause_queue_send(void *context);
void ol_tx_pdev_ll_pause_queue_send_all(struct ol_txrx_pdev_t *pdev);
#else
static inline void ol_tx_vdev_ll_pause_queue_send(void *context)
{
	return;
}
static inline
void ol_tx_pdev_ll_pause_queue_send_all(struct ol_txrx_pdev_t *pdev)
{
	return;
}
#endif

/**
 * ol_tx_non_std_hl() - send non std tx frame.
 * @vdev: the virtual device sending the data
 * @tx_spec: indicate what non-standard transmission actions to apply
 * @msdu_list: the tx frames to send
 *
 * Return: NULL if all MSDUs are accepted
 */
qdf_nbuf_t
ol_tx_non_std_hl(ol_txrx_vdev_handle data_vdev,
		 enum ol_tx_spec tx_spec, qdf_nbuf_t msdu_list);

/**
 * ol_tx_hl() - transmit tx frames for a HL system.
 * @vdev: the virtual device transmit the data
 * @msdu_list: the tx frames to send
 *
 * Return: NULL if all MSDUs are accepted
 */
qdf_nbuf_t
ol_tx_hl(ol_txrx_vdev_handle vdev, qdf_nbuf_t msdu_list);

qdf_nbuf_t
ol_tx_non_std_ll(ol_txrx_vdev_handle data_vdev,
		 enum ol_tx_spec tx_spec, qdf_nbuf_t msdu_list);

qdf_nbuf_t
ol_tx_reinject(struct ol_txrx_vdev_t *vdev, qdf_nbuf_t msdu, uint16_t peer_id);

void ol_txrx_mgmt_tx_complete(void *ctxt, qdf_nbuf_t netbuf, int err);


#if defined(FEATURE_TSO)
void ol_tso_seg_list_init(struct ol_txrx_pdev_t *pdev, uint32_t num_seg);
void ol_tso_seg_list_deinit(struct ol_txrx_pdev_t *pdev);
void ol_tso_num_seg_list_init(struct ol_txrx_pdev_t *pdev, uint32_t num_seg);
void ol_tso_num_seg_list_deinit(struct ol_txrx_pdev_t *pdev);
#else
static inline void ol_tso_seg_list_init(struct ol_txrx_pdev_t *pdev,
	uint32_t num_seg)
{
	return;
}
static inline void ol_tso_seg_list_deinit(struct ol_txrx_pdev_t *pdev)
{
	return;
}
static inline void ol_tso_num_seg_list_init(struct ol_txrx_pdev_t *pdev,
	uint32_t num_seg)
{
}
static inline void ol_tso_num_seg_list_deinit(struct ol_txrx_pdev_t *pdev)
{
}
#endif

#if defined(HELIUMPLUS)
void ol_txrx_dump_frag_desc(char *msg, struct ol_tx_desc_t *tx_desc);
#else
static inline
void ol_txrx_dump_frag_desc(char *msg, struct ol_tx_desc_t *tx_desc)
{
}
#endif

#endif /* _OL_TX__H_ */
