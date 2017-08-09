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

#include <qdf_nbuf.h>               /* qdf_nbuf_t, etc. */
#include <qdf_util.h>               /* qdf_cpu_to_le64 */
#include <qdf_types.h>              /* bool */
#include <cds_ieee80211_common.h>   /* ieee80211_frame */

/* external API header files */
#include <ol_ctrl_txrx_api.h>   /* ol_rx_notify */
#include <ol_txrx_api.h>        /* ol_txrx_pdev_handle */
#include <ol_txrx_htt_api.h>    /* ol_rx_indication_handler */
#include <ol_htt_rx_api.h>      /* htt_rx_peer_id, etc. */

/* internal API header files */
#include <ol_txrx_peer_find.h>  /* ol_txrx_peer_find_by_id */
#include <ol_rx_reorder.h>      /* ol_rx_reorder_store, etc. */
#include <ol_rx_reorder_timeout.h>      /* OL_RX_REORDER_TIMEOUT_UPDATE */
#include <ol_rx_defrag.h>       /* ol_rx_defrag_waitlist_flush */
#include <ol_txrx_internal.h>
#include <wdi_event.h>
#ifdef QCA_SUPPORT_SW_TXRX_ENCAP
#include <ol_txrx_encap.h>      /* ol_rx_decap_info_t, etc */
#endif
#include <ol_rx.h>

/* FIX THIS: txrx should not include private header files of other modules */
#include <htt_types.h>
#include <ol_if_athvar.h>
#include <enet.h>               /* ethernet + SNAP/LLC header defs and
				   ethertype values */
#include <ip_prot.h>            /* IP protocol values */
#include <ipv4.h>               /* IPv4 header defs */
#include <ipv6_defs.h>          /* IPv6 header defs */
#include <ol_vowext_dbg_defs.h>
#include <wma.h>
#include <cds_concurrency.h>
#include "pktlog_ac_fmt.h"

#include <pld_common.h>


#define OL_RX_INDICATION_MAX_RECORDS 2048

/**
 * enum ol_rx_ind_record_type - OL rx indication events
 * @OL_RX_INDICATION_POP_START: event recorded before netbuf pop
 * @OL_RX_INDICATION_POP_END: event recorded after netbuf pop
 * @OL_RX_INDICATION_BUF_REPLENISH: event recorded after buffer replenishment
 */
enum ol_rx_ind_record_type {
	OL_RX_INDICATION_POP_START,
	OL_RX_INDICATION_POP_END,
	OL_RX_INDICATION_BUF_REPLENISH,
};

/**
 * struct ol_rx_ind_record - structure for detailing ol txrx rx ind. event
 * @value: info corresponding to rx indication event
 * @type: what the event was
 * @time: when it happened
 */
struct ol_rx_ind_record {
	uint16_t value;
	enum ol_rx_ind_record_type type;
	uint64_t time;
};

#ifdef OL_RX_INDICATION_RECORD
static uint32_t ol_rx_ind_record_index;
static struct ol_rx_ind_record
	      ol_rx_indication_record_history[OL_RX_INDICATION_MAX_RECORDS];

/**
 * ol_rx_ind_record_event() - record ol rx indication events
 * @value: contains rx ind. event related info
 * @type: ol rx indication message type
 *
 * This API record the ol rx indiation event in a rx indication
 * record buffer.
 *
 * Return: None
 */
static void ol_rx_ind_record_event(uint32_t value,
				    enum ol_rx_ind_record_type type)
{
	ol_rx_indication_record_history[ol_rx_ind_record_index].value = value;
	ol_rx_indication_record_history[ol_rx_ind_record_index].type = type;
	ol_rx_indication_record_history[ol_rx_ind_record_index].time =
							qdf_get_log_timestamp();

	ol_rx_ind_record_index++;
	if (ol_rx_ind_record_index >= OL_RX_INDICATION_MAX_RECORDS)
		ol_rx_ind_record_index = 0;
}
#else
static inline
void ol_rx_ind_record_event(uint32_t value, enum ol_rx_ind_record_type type)
{
}

#endif /* OL_RX_INDICATION_RECORD */

void ol_rx_data_process(struct ol_txrx_peer_t *peer,
			qdf_nbuf_t rx_buf_list);

/**
 * ol_rx_send_pktlog_event() - send rx packetlog event
 * @pdev: pdev handle
 * @peer: peer handle
 * @msdu: skb list
 * @pktlog_bit: packetlog bit from firmware
 *
 * Return: none
 */
#ifdef HELIUMPLUS
void ol_rx_send_pktlog_event(struct ol_txrx_pdev_t *pdev,
	struct ol_txrx_peer_t *peer, qdf_nbuf_t msdu, uint8_t pktlog_bit)
{
	struct ol_rx_remote_data data;

	if (!pktlog_bit)
		return;

	data.msdu = msdu;
	if (peer)
		data.mac_id = peer->vdev->mac_id;
	else
		data.mac_id = 0;

	wdi_event_handler(WDI_EVENT_RX_DESC_REMOTE, pdev, &data);
}
#else
void ol_rx_send_pktlog_event(struct ol_txrx_pdev_t *pdev,
	struct ol_txrx_peer_t *peer, qdf_nbuf_t msdu, uint8_t pktlog_bit)
{
	struct ol_rx_remote_data data;

	data.msdu = msdu;
	if (peer)
		data.mac_id = peer->vdev->mac_id;
	else
		data.mac_id = 0;

	wdi_event_handler(WDI_EVENT_RX_DESC_REMOTE, pdev, &data);
}
#endif

#ifdef HTT_RX_RESTORE

static void ol_rx_restore_handler(struct work_struct *htt_rx)
{
	qdf_device_t qdf_ctx = cds_get_context(QDF_MODULE_ID_QDF_DEVICE);

	QDF_TRACE(QDF_MODULE_ID_TXRX, QDF_TRACE_LEVEL_INFO,
		  "Enter: %s", __func__);
	pld_device_self_recovery(qdf_ctx->dev);
	QDF_TRACE(QDF_MODULE_ID_TXRX, QDF_TRACE_LEVEL_INFO,
		  "Exit: %s", __func__);
}

static DECLARE_WORK(ol_rx_restore_work, ol_rx_restore_handler);

void ol_rx_trigger_restore(htt_pdev_handle htt_pdev, qdf_nbuf_t head_msdu,
			   qdf_nbuf_t tail_msdu)
{
	qdf_nbuf_t next;

	while (head_msdu) {
		next = qdf_nbuf_next(head_msdu);
		QDF_TRACE(QDF_MODULE_ID_TXRX, QDF_TRACE_LEVEL_INFO,
			  "freeing %p\n", head_msdu);
		qdf_nbuf_free(head_msdu);
		head_msdu = next;
	}

	if (!htt_pdev->rx_ring.htt_rx_restore) {
		cds_set_recovery_in_progress(true);
		htt_pdev->rx_ring.htt_rx_restore = 1;
		schedule_work(&ol_rx_restore_work);
	}
}
#endif

/**
 * ol_rx_update_histogram_stats() - update rx histogram statistics
 * @msdu_count: msdu count
 * @frag_ind: fragment indication set
 * @offload_ind: offload indication set
 *
 * Return: none
 */
void ol_rx_update_histogram_stats(uint32_t msdu_count, uint8_t frag_ind,
		 uint8_t offload_ind)
{
	struct ol_txrx_pdev_t *pdev = cds_get_context(QDF_MODULE_ID_TXRX);

	if (!pdev) {
		TXRX_PRINT(TXRX_PRINT_LEVEL_ERR,
			"%s pdev is NULL\n", __func__);
		return;
	}

	if (msdu_count > 60) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_61_plus, 1);
	} else if (msdu_count > 50) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_51_60, 1);
	} else if (msdu_count > 40) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_41_50, 1);
	} else if (msdu_count > 30) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_31_40, 1);
	} else if (msdu_count > 20) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_21_30, 1);
	} else if (msdu_count > 10) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_11_20, 1);
	} else if (msdu_count > 1) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_2_10, 1);
	} else if (msdu_count == 1) {
		TXRX_STATS_ADD(pdev, pub.rx.rx_ind_histogram.pkts_1, 1);
	}

	if (frag_ind)
		TXRX_STATS_ADD(pdev, pub.rx.msdus_with_frag_ind, msdu_count);

	if (offload_ind)
		TXRX_STATS_ADD(pdev, pub.rx.msdus_with_offload_ind, msdu_count);

}

static void ol_rx_process_inv_peer(ol_txrx_pdev_handle pdev,
				   void *rx_mpdu_desc, qdf_nbuf_t msdu)
{
	uint8_t a1[IEEE80211_ADDR_LEN];
	htt_pdev_handle htt_pdev = pdev->htt_pdev;
	struct ol_txrx_vdev_t *vdev = NULL;
	struct ieee80211_frame *wh;
	struct wdi_event_rx_peer_invalid_msg msg;

	wh = (struct ieee80211_frame *)
	     htt_rx_mpdu_wifi_hdr_retrieve(htt_pdev, rx_mpdu_desc);
	/*
	 * Klocwork issue #6152
	 *  All targets that send a "INVALID_PEER" rx status provide a
	 *  802.11 header for each rx MPDU, so it is certain that
	 *  htt_rx_mpdu_wifi_hdr_retrieve will succeed.
	 *  However, both for robustness, e.g. if this function is given a
	 *  MSDU descriptor rather than a MPDU descriptor, and to make it
	 *  clear to static analysis that this code is safe, add an explicit
	 *  check that htt_rx_mpdu_wifi_hdr_retrieve provides a non-NULL value.
	 */
	if (wh == NULL || !IEEE80211_IS_DATA(wh))
		return;

	/* ignore frames for non-existent bssids */
	qdf_mem_copy(a1, wh->i_addr1, IEEE80211_ADDR_LEN);
	TAILQ_FOREACH(vdev, &pdev->vdev_list, vdev_list_elem) {
		if (qdf_mem_cmp(a1, vdev->mac_addr.raw, IEEE80211_ADDR_LEN))
			break;
	}
	if (!vdev)
		return;

	msg.wh = wh;
	msg.msdu = msdu;
	msg.vdev_id = vdev->vdev_id;
#ifdef WDI_EVENT_ENABLE
	wdi_event_handler(WDI_EVENT_RX_PEER_INVALID, pdev, &msg);
#endif
}

#ifdef QCA_SUPPORT_PEER_DATA_RX_RSSI
static inline int16_t
ol_rx_rssi_avg(struct ol_txrx_pdev_t *pdev, int16_t rssi_old, int16_t rssi_new)
{
	int rssi_old_weight;

	if (rssi_new == HTT_RSSI_INVALID)
		return rssi_old;
	if (rssi_old == HTT_RSSI_INVALID)
		return rssi_new;

	rssi_old_weight =
		(1 << pdev->rssi_update_shift) - pdev->rssi_new_weight;
	return (rssi_new * pdev->rssi_new_weight +
		rssi_old * rssi_old_weight) >> pdev->rssi_update_shift;
}

static void
ol_rx_ind_rssi_update(struct ol_txrx_peer_t *peer, qdf_nbuf_t rx_ind_msg)
{
	struct ol_txrx_pdev_t *pdev = peer->vdev->pdev;
	peer->rssi_dbm = ol_rx_rssi_avg(pdev, peer->rssi_dbm,
					htt_rx_ind_rssi_dbm(pdev->htt_pdev,
							    rx_ind_msg));
}

static void
ol_rx_mpdu_rssi_update(struct ol_txrx_peer_t *peer, void *rx_mpdu_desc)
{
	struct ol_txrx_pdev_t *pdev = peer->vdev->pdev;
	if (!peer)
		return;
	peer->rssi_dbm = ol_rx_rssi_avg(pdev, peer->rssi_dbm,
					htt_rx_mpdu_desc_rssi_dbm(
						pdev->htt_pdev,
						rx_mpdu_desc));
}

#else
#define ol_rx_ind_rssi_update(peer, rx_ind_msg) /* no-op */
#define ol_rx_mpdu_rssi_update(peer, rx_mpdu_desc)      /* no-op */
#endif /* QCA_SUPPORT_PEER_DATA_RX_RSSI */

static void discard_msdus(htt_pdev_handle htt_pdev,
			  qdf_nbuf_t head_msdu,
			  qdf_nbuf_t tail_msdu)
{
	while (1) {
		qdf_nbuf_t next;
		next = qdf_nbuf_next(
			head_msdu);
		htt_rx_desc_frame_free
			(htt_pdev,
			 head_msdu);
		if (head_msdu ==
		    tail_msdu) {
			break;
		}
		head_msdu = next;
	}
	return;
}

static void chain_msdus(htt_pdev_handle htt_pdev,
			qdf_nbuf_t head_msdu,
			qdf_nbuf_t tail_msdu)
{
	while (1) {
		qdf_nbuf_t next;
		next = qdf_nbuf_next(head_msdu);
		htt_rx_desc_frame_free(
			htt_pdev,
			head_msdu);
		if (head_msdu == tail_msdu)
			break;
		head_msdu = next;
	}
	return;
}

static void process_reorder(ol_txrx_pdev_handle pdev,
			    void *rx_mpdu_desc,
			    uint8_t tid,
			    struct ol_txrx_peer_t *peer,
			    qdf_nbuf_t head_msdu,
			    qdf_nbuf_t tail_msdu,
			    int num_mpdu_ranges,
			    int num_pdus,
			    bool rx_ind_release)
{
	htt_pdev_handle htt_pdev = pdev->htt_pdev;
	enum htt_rx_status mpdu_status;
	int reorder_idx;
	reorder_idx = htt_rx_mpdu_desc_reorder_idx(htt_pdev, rx_mpdu_desc);
	OL_RX_REORDER_TRACE_ADD(pdev, tid,
				reorder_idx,
				htt_rx_mpdu_desc_seq_num(htt_pdev,
							 rx_mpdu_desc),
				1);
	ol_rx_mpdu_rssi_update(peer, rx_mpdu_desc);
	/*
	 * In most cases, out-of-bounds and duplicate sequence number detection
	 * is performed by the target, but in some cases it is done by the host.
	 * Specifically, the host does rx out-of-bounds sequence number
	 * detection for:
	 * 1.  Peregrine or Rome target
	 *     for peer-TIDs that do not have aggregation enabled, if the
	 *     RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK flag
	 *     is set during the driver build.
	 * 2.  Riva-family targets, which have rx reorder timeouts handled by
	 *     the host rather than the target.
	 *     (The target already does duplicate detection, but the host
	 *     may have given up waiting for a particular sequence number before
	 *     it arrives.  In this case, the out-of-bounds sequence number
	 *     of the late frame allows the host to discard it, rather than
	 *     sending it out of order.
	 */
	mpdu_status = OL_RX_SEQ_NUM_CHECK(pdev,
						  peer,
						  tid,
						  rx_mpdu_desc);
	if (mpdu_status != htt_rx_status_ok) {
		/*
		 * If the sequence number was out of bounds, the MPDU needs
		 * to be discarded.
		 */
		discard_msdus(htt_pdev, head_msdu, tail_msdu);
		/*
		 * For Peregrine and Rome,
		 * OL_RX_REORDER_SEQ_NUM_CHECK should only fail for the case
		 * of (duplicate) non-aggregates.
		 *
		 * For Riva, Pronto and Northstar,
		 * there should be only one MPDU delivered at a time.
		 * Thus, there are no further MPDUs that need to be
		 * processed here.
		 * Just to be sure this is true, check the assumption
		 * that this was the only MPDU referenced by the rx
		 * indication.
		 */
		TXRX_ASSERT2((num_mpdu_ranges == 1) && num_mpdus == 1);

		/*
		 * The MPDU was not stored in the rx reorder array, so
		 * there's nothing to release.
		 */
		rx_ind_release = false;
	} else {
		ol_rx_reorder_store(pdev, peer, tid,
				    reorder_idx, head_msdu, tail_msdu);
		if (peer->tids_rx_reorder[tid].win_sz_mask == 0) {
			peer->tids_last_seq[tid] = htt_rx_mpdu_desc_seq_num(
				htt_pdev,
				rx_mpdu_desc);
		}
	}
	return;
} /* process_reorder */

void
ol_rx_indication_handler(ol_txrx_pdev_handle pdev,
			 qdf_nbuf_t rx_ind_msg,
			 uint16_t peer_id, uint8_t tid, int num_mpdu_ranges)
{
	int mpdu_range, i;
	unsigned seq_num_start = 0, seq_num_end = 0;
	bool rx_ind_release = false;
	struct ol_txrx_vdev_t *vdev = NULL;
	struct ol_txrx_peer_t *peer;
	htt_pdev_handle htt_pdev;
	uint16_t center_freq;
	uint16_t chan1;
	uint16_t chan2;
	uint8_t phymode;
	bool ret;

	htt_pdev = pdev->htt_pdev;
	peer = ol_txrx_peer_find_by_id(pdev, peer_id);
	if (!peer) {
		/*
		 * If we can't find a peer send this packet to OCB interface
		 * using OCB self peer
		 */
		if (!ol_txrx_get_ocb_peer(pdev, &peer))
			peer = NULL;
	}

	if (peer) {
		vdev = peer->vdev;
		ol_rx_ind_rssi_update(peer, rx_ind_msg);

		if (vdev->opmode == wlan_op_mode_ocb) {
			htt_rx_ind_legacy_rate(pdev->htt_pdev, rx_ind_msg,
				       &peer->last_pkt_legacy_rate,
				       &peer->last_pkt_legacy_rate_sel);
			peer->last_pkt_rssi_cmb = htt_rx_ind_rssi_dbm(
				pdev->htt_pdev, rx_ind_msg);
			for (i = 0; i < 4; i++)
				peer->last_pkt_rssi[i] =
					htt_rx_ind_rssi_dbm_chain(
					pdev->htt_pdev, rx_ind_msg, i);
			htt_rx_ind_timestamp(pdev->htt_pdev, rx_ind_msg,
					&peer->last_pkt_timestamp_microsec,
					&peer->last_pkt_timestamp_submicrosec);
			peer->last_pkt_tsf = htt_rx_ind_tsf32(pdev->htt_pdev,
							      rx_ind_msg);
			peer->last_pkt_tid = htt_rx_ind_ext_tid(pdev->htt_pdev,
								rx_ind_msg);
		}
	}

	TXRX_STATS_INCR(pdev, priv.rx.normal.ppdus);

	OL_RX_REORDER_TIMEOUT_MUTEX_LOCK(pdev);

	if (htt_rx_ind_flush(pdev->htt_pdev, rx_ind_msg) && peer) {
		htt_rx_ind_flush_seq_num_range(pdev->htt_pdev, rx_ind_msg,
					       &seq_num_start, &seq_num_end);
		if (tid == HTT_INVALID_TID) {
			/*
			 * host/FW reorder state went out-of sync
			 * for a while because FW ran out of Rx indication
			 * buffer. We have to discard all the buffers in
			 * reorder queue.
			 */
			ol_rx_reorder_peer_cleanup(vdev, peer);
		} else {
			ol_rx_reorder_flush(vdev, peer, tid, seq_num_start,
					    seq_num_end, htt_rx_flush_release);
		}
	}

	if (htt_rx_ind_release(pdev->htt_pdev, rx_ind_msg)) {
		/* the ind info of release is saved here and do release at the
		 * end. This is for the reason of in HL case, the qdf_nbuf_t
		 * for msg and payload are the same buf. And the buf will be
		 * changed during processing */
		rx_ind_release = true;
		htt_rx_ind_release_seq_num_range(pdev->htt_pdev, rx_ind_msg,
						 &seq_num_start, &seq_num_end);
	}
#ifdef DEBUG_DMA_DONE
	pdev->htt_pdev->rx_ring.dbg_initial_msdu_payld =
		pdev->htt_pdev->rx_ring.sw_rd_idx.msdu_payld;
#endif

	for (mpdu_range = 0; mpdu_range < num_mpdu_ranges; mpdu_range++) {
		enum htt_rx_status status;
		int i, num_mpdus;
		qdf_nbuf_t head_msdu, tail_msdu, msdu;
		void *rx_mpdu_desc;

#ifdef DEBUG_DMA_DONE
		pdev->htt_pdev->rx_ring.dbg_mpdu_range = mpdu_range;
#endif

		htt_rx_ind_mpdu_range_info(pdev->htt_pdev, rx_ind_msg,
					   mpdu_range, &status, &num_mpdus);
		if ((status == htt_rx_status_ok) && peer) {
			TXRX_STATS_ADD(pdev, priv.rx.normal.mpdus, num_mpdus);
			/* valid frame - deposit it into rx reordering buffer */
			for (i = 0; i < num_mpdus; i++) {
				int msdu_chaining;
				/*
				 * Get a linked list of the MSDUs that comprise
				 * this MPDU.
				 * This also attaches each rx MSDU descriptor to
				 * the corresponding rx MSDU network buffer.
				 * (In some systems, the rx MSDU desc is already
				 * in the same buffer as the MSDU payload; in
				 * other systems they are separate, so a pointer
				 * needs to be set in the netbuf to locate the
				 * corresponding rx descriptor.)
				 *
				 * It is neccessary to call htt_rx_amsdu_pop
				 * before htt_rx_mpdu_desc_list_next, because
				 * the (MPDU) rx descriptor has DMA unmapping
				 * done during the htt_rx_amsdu_pop call.
				 * The rx desc should not be accessed until this
				 * DMA unmapping has been done, since the DMA
				 * unmapping involves making sure the cache area
				 * for the mapped buffer is flushed, so the data
				 * written by the MAC DMA into memory will be
				 * fetched, rather than garbage from the cache.
				 */

#ifdef DEBUG_DMA_DONE
				pdev->htt_pdev->rx_ring.dbg_mpdu_count = i;
#endif

				msdu_chaining =
					htt_rx_amsdu_pop(htt_pdev,
							 rx_ind_msg,
							 &head_msdu,
							 &tail_msdu);
#ifdef HTT_RX_RESTORE
				if (htt_pdev->rx_ring.rx_reset) {
					ol_rx_trigger_restore(htt_pdev,
							      head_msdu,
							      tail_msdu);
					return;
				}
#endif
				rx_mpdu_desc =
					htt_rx_mpdu_desc_list_next(htt_pdev,
								   rx_ind_msg);
				ret = htt_rx_msdu_center_freq(htt_pdev, peer,
					rx_mpdu_desc, &center_freq, &chan1,
					&chan2, &phymode);
				if (ret == true) {
					peer->last_pkt_center_freq =
						center_freq;
				} else {
					peer->last_pkt_center_freq = 0;
				}

				/* Pktlog */
#ifdef WDI_EVENT_ENABLE
		ol_rx_send_pktlog_event(pdev, peer, head_msdu, 1);
#endif

				if (msdu_chaining) {
					/*
					 * TBDXXX - to deliver SDU with
					 * chaining, we need to stitch those
					 * scattered buffers into one single
					 * buffer.
					 * Just discard it now.
					 */
					chain_msdus(htt_pdev,
						    head_msdu,
						    tail_msdu);
				} else {
					process_reorder(pdev, rx_mpdu_desc,
							tid, peer,
							head_msdu, tail_msdu,
							num_mpdu_ranges,
							num_mpdus,
							rx_ind_release);
				}

			}
		} else {
			/* invalid frames - discard them */
			OL_RX_REORDER_TRACE_ADD(pdev, tid,
						TXRX_SEQ_NUM_ERR(status),
						TXRX_SEQ_NUM_ERR(status),
						num_mpdus);
			TXRX_STATS_ADD(pdev, priv.rx.err.mpdu_bad, num_mpdus);
			for (i = 0; i < num_mpdus; i++) {
				/* pull the MPDU's MSDUs off the buffer queue */
				htt_rx_amsdu_pop(htt_pdev, rx_ind_msg, &msdu,
						 &tail_msdu);
#ifdef HTT_RX_RESTORE
				if (htt_pdev->rx_ring.rx_reset) {
					ol_rx_trigger_restore(htt_pdev, msdu,
							      tail_msdu);
					return;
				}
#endif
				/* pull the MPDU desc off the desc queue */
				rx_mpdu_desc =
					htt_rx_mpdu_desc_list_next(htt_pdev,
								   rx_ind_msg);
				OL_RX_ERR_STATISTICS_2(pdev, vdev, peer,
						       rx_mpdu_desc, msdu,
						       status);

				if (status == htt_rx_status_tkip_mic_err &&
				    vdev != NULL && peer != NULL) {
					union htt_rx_pn_t pn;
					uint8_t key_id;
					htt_rx_mpdu_desc_pn(
						pdev->htt_pdev,
						htt_rx_msdu_desc_retrieve(
							pdev->htt_pdev,
							msdu), &pn, 48);
					if (htt_rx_msdu_desc_key_id(
						    pdev->htt_pdev,
						    htt_rx_msdu_desc_retrieve(
							    pdev->htt_pdev,
							    msdu),
						    &key_id) == true) {
						ol_rx_err(pdev->ctrl_pdev,
							  vdev->vdev_id,
							  peer->mac_addr.raw,
							  tid, 0,
							  OL_RX_ERR_TKIP_MIC,
							  msdu, &pn.pn48,
							  key_id);
					}
				}
#ifdef WDI_EVENT_ENABLE
				if (status != htt_rx_status_ctrl_mgmt_null) {
					/* Pktlog */
					ol_rx_send_pktlog_event(pdev,
						 peer, msdu, 1);
				}
#endif
				if (status == htt_rx_status_err_inv_peer) {
					/* once per mpdu */
					ol_rx_process_inv_peer(pdev,
							       rx_mpdu_desc,
							       msdu);
				}
				while (1) {
					/* Free the nbuf */
					qdf_nbuf_t next;
					next = qdf_nbuf_next(msdu);
					htt_rx_desc_frame_free(htt_pdev, msdu);
					if (msdu == tail_msdu)
						break;
					msdu = next;
				}
			}
		}
	}
	/*
	 * Now that a whole batch of MSDUs have been pulled out of HTT
	 * and put into the rx reorder array, it is an appropriate time
	 * to request HTT to provide new rx MSDU buffers for the target
	 * to fill.
	 * This could be done after the end of this function, but it's
	 * better to do it now, rather than waiting until after the driver
	 * and OS finish processing the batch of rx MSDUs.
	 */
	htt_rx_msdu_buff_replenish(htt_pdev);

	if ((true == rx_ind_release) && peer && vdev) {
		ol_rx_reorder_release(vdev, peer, tid, seq_num_start,
				      seq_num_end);
	}
	OL_RX_REORDER_TIMEOUT_UPDATE(peer, tid);
	OL_RX_REORDER_TIMEOUT_MUTEX_UNLOCK(pdev);

	if (pdev->rx.flags.defrag_timeout_check)
		ol_rx_defrag_waitlist_flush(pdev);
}

void
ol_rx_sec_ind_handler(ol_txrx_pdev_handle pdev,
		      uint16_t peer_id,
		      enum htt_sec_type sec_type,
		      int is_unicast, uint32_t *michael_key, uint32_t *rx_pn)
{
	struct ol_txrx_peer_t *peer;
	int sec_index, i;

	peer = ol_txrx_peer_find_by_id(pdev, peer_id);
	if (!peer) {
		TXRX_PRINT(TXRX_PRINT_LEVEL_ERR,
			   "Couldn't find peer from ID %d - skipping security inits\n",
			   peer_id);
		return;
	}
	TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
		   "sec spec for peer %p (%02x:%02x:%02x:%02x:%02x:%02x): "
		   "%s key of type %d\n",
		   peer,
		   peer->mac_addr.raw[0], peer->mac_addr.raw[1],
		   peer->mac_addr.raw[2], peer->mac_addr.raw[3],
		   peer->mac_addr.raw[4], peer->mac_addr.raw[5],
		   is_unicast ? "ucast" : "mcast", sec_type);
	sec_index = is_unicast ? txrx_sec_ucast : txrx_sec_mcast;
	peer->security[sec_index].sec_type = sec_type;
	/* michael key only valid for TKIP
	   but for simplicity, copy it anyway */
	qdf_mem_copy(&peer->security[sec_index].michael_key[0],
		     michael_key,
		     sizeof(peer->security[sec_index].michael_key));

	if (sec_type != htt_sec_type_wapi) {
		qdf_mem_set(peer->tids_last_pn_valid,
			    OL_TXRX_NUM_EXT_TIDS, 0x00);
	} else if (sec_index == txrx_sec_mcast || peer->tids_last_pn_valid[0]) {
		for (i = 0; i < OL_TXRX_NUM_EXT_TIDS; i++) {
			/*
			 * Setting PN valid bit for WAPI sec_type,
			 * since WAPI PN has to be started with predefined value
			 */
			peer->tids_last_pn_valid[i] = 1;
			qdf_mem_copy((uint8_t *) &peer->tids_last_pn[i],
				     (uint8_t *) rx_pn,
				     sizeof(union htt_rx_pn_t));
			peer->tids_last_pn[i].pn128[1] =
				qdf_cpu_to_le64(
					peer->tids_last_pn[i].pn128[1]);
			peer->tids_last_pn[i].pn128[0] =
				qdf_cpu_to_le64(
					peer->tids_last_pn[i].pn128[0]);
		}
	}
}

#if defined(PERE_IP_HDR_ALIGNMENT_WAR)

#include <cds_ieee80211_common.h>

static void transcap_nwifi_to_8023(qdf_nbuf_t msdu)
{
	struct ieee80211_frame *wh;
	uint32_t hdrsize;
	struct llc *llchdr;
	struct ether_header *eth_hdr;
	uint16_t ether_type = 0;
	uint8_t a1[IEEE80211_ADDR_LEN];
	uint8_t a2[IEEE80211_ADDR_LEN];
	uint8_t a3[IEEE80211_ADDR_LEN];
	uint8_t fc1;

	wh = (struct ieee80211_frame *)qdf_nbuf_data(msdu);
	qdf_mem_copy(a1, wh->i_addr1, IEEE80211_ADDR_LEN);
	qdf_mem_copy(a2, wh->i_addr2, IEEE80211_ADDR_LEN);
	qdf_mem_copy(a3, wh->i_addr3, IEEE80211_ADDR_LEN);
	fc1 = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
	/* Native Wifi header is 80211 non-QoS header */
	hdrsize = sizeof(struct ieee80211_frame);

	llchdr = (struct llc *)(((uint8_t *) qdf_nbuf_data(msdu)) + hdrsize);
	ether_type = llchdr->llc_un.type_snap.ether_type;

	/*
	 * Now move the data pointer to the beginning of the mac header :
	 * new-header = old-hdr + (wifhdrsize + llchdrsize - ethhdrsize)
	 */
	qdf_nbuf_pull_head(msdu,
			   (hdrsize + sizeof(struct llc) -
			    sizeof(struct ether_header)));
	eth_hdr = (struct ether_header *)(qdf_nbuf_data(msdu));
	switch (fc1) {
	case IEEE80211_FC1_DIR_NODS:
		qdf_mem_copy(eth_hdr->ether_dhost, a1, IEEE80211_ADDR_LEN);
		qdf_mem_copy(eth_hdr->ether_shost, a2, IEEE80211_ADDR_LEN);
		break;
	case IEEE80211_FC1_DIR_TODS:
		qdf_mem_copy(eth_hdr->ether_dhost, a3, IEEE80211_ADDR_LEN);
		qdf_mem_copy(eth_hdr->ether_shost, a2, IEEE80211_ADDR_LEN);
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		qdf_mem_copy(eth_hdr->ether_dhost, a1, IEEE80211_ADDR_LEN);
		qdf_mem_copy(eth_hdr->ether_shost, a3, IEEE80211_ADDR_LEN);
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		break;
	}
	eth_hdr->ether_type = ether_type;
}
#endif

void ol_rx_notify(ol_pdev_handle pdev,
		  uint8_t vdev_id,
		  uint8_t *peer_mac_addr,
		  int tid,
		  uint32_t tsf32,
		  enum ol_rx_notify_type notify_type, qdf_nbuf_t rx_frame)
{
	/*
	 * NOTE: This is used in qca_main for AP mode to handle IGMP
	 * packets specially. Umac has a corresponding handler for this
	 * not sure if we need to have this for CLD as well.
	 */
}

/**
 * @brief Look into a rx MSDU to see what kind of special handling it requires
 * @details
 *      This function is called when the host rx SW sees that the target
 *      rx FW has marked a rx MSDU as needing inspection.
 *      Based on the results of the inspection, the host rx SW will infer
 *      what special handling to perform on the rx frame.
 *      Currently, the only type of frames that require special handling
 *      are IGMP frames.  The rx data-path SW checks if the frame is IGMP
 *      (it should be, since the target would not have set the inspect flag
 *      otherwise), and then calls the ol_rx_notify function so the
 *      control-path SW can perform multicast group membership learning
 *      by sniffing the IGMP frame.
 */
#define SIZEOF_80211_HDR (sizeof(struct ieee80211_frame))
static void
ol_rx_inspect(struct ol_txrx_vdev_t *vdev,
	      struct ol_txrx_peer_t *peer,
	      unsigned tid, qdf_nbuf_t msdu, void *rx_desc)
{
	ol_txrx_pdev_handle pdev = vdev->pdev;
	uint8_t *data, *l3_hdr;
	uint16_t ethertype;
	int offset;

	data = qdf_nbuf_data(msdu);
	if (pdev->frame_format == wlan_frm_fmt_native_wifi) {
		offset = SIZEOF_80211_HDR + LLC_SNAP_HDR_OFFSET_ETHERTYPE;
		l3_hdr = data + SIZEOF_80211_HDR + LLC_SNAP_HDR_LEN;
	} else {
		offset = ETHERNET_ADDR_LEN * 2;
		l3_hdr = data + ETHERNET_HDR_LEN;
	}
	ethertype = (data[offset] << 8) | data[offset + 1];
	if (ethertype == ETHERTYPE_IPV4) {
		offset = IPV4_HDR_OFFSET_PROTOCOL;
		if (l3_hdr[offset] == IP_PROTOCOL_IGMP) {
			ol_rx_notify(pdev->ctrl_pdev,
				     vdev->vdev_id,
				     peer->mac_addr.raw,
				     tid,
				     htt_rx_mpdu_desc_tsf32(pdev->htt_pdev,
							    rx_desc),
				     OL_RX_NOTIFY_IPV4_IGMP, msdu);
		}
	}
}

void
ol_rx_offload_deliver_ind_handler(ol_txrx_pdev_handle pdev,
				  qdf_nbuf_t msg, int msdu_cnt)
{
	int vdev_id, peer_id, tid;
	qdf_nbuf_t head_buf, tail_buf, buf;
	struct ol_txrx_peer_t *peer;
	uint8_t fw_desc;
	htt_pdev_handle htt_pdev = pdev->htt_pdev;

	while (msdu_cnt) {
		if (!htt_rx_offload_msdu_pop(htt_pdev, msg, &vdev_id, &peer_id,
					&tid, &fw_desc, &head_buf, &tail_buf)) {
			peer = ol_txrx_peer_find_by_id(pdev, peer_id);
			if (peer) {
				ol_rx_data_process(peer, head_buf);
			} else {
				buf = head_buf;
				while (1) {
					qdf_nbuf_t next;
					next = qdf_nbuf_next(buf);
					htt_rx_desc_frame_free(htt_pdev, buf);
					if (buf == tail_buf)
						break;
					buf = next;
				}
			}
		}
		msdu_cnt--;
	}
	htt_rx_msdu_buff_replenish(htt_pdev);
}

#ifdef WDI_EVENT_ENABLE
static inline
void ol_rx_mic_error_send_pktlog_event(struct ol_txrx_pdev_t *pdev,
	struct ol_txrx_peer_t *peer, qdf_nbuf_t msdu, uint8_t pktlog_bit)
{
	ol_rx_send_pktlog_event(pdev, peer, msdu, pktlog_bit);
}

#else
static inline
void ol_rx_mic_error_send_pktlog_event(struct ol_txrx_pdev_t *pdev,
	struct ol_txrx_peer_t *peer, qdf_nbuf_t msdu, uint8_t pktlog_bit)
{
}

#endif


void
ol_rx_mic_error_handler(
	ol_txrx_pdev_handle pdev,
	u_int8_t tid,
	u_int16_t peer_id,
	void *msdu_desc,
	qdf_nbuf_t msdu)
{
	union htt_rx_pn_t pn = {0};
	u_int8_t key_id = 0;

	struct ol_txrx_peer_t *peer = NULL;
	struct ol_txrx_vdev_t *vdev = NULL;

	if (pdev) {
		TXRX_STATS_MSDU_INCR(pdev, rx.dropped_mic_err, msdu);
		peer = ol_txrx_peer_find_by_id(pdev, peer_id);
		if (peer) {
			vdev = peer->vdev;
			if (vdev) {
				htt_rx_mpdu_desc_pn(vdev->pdev->htt_pdev,
						    msdu_desc, &pn, 48);

				if (htt_rx_msdu_desc_key_id(
					vdev->pdev->htt_pdev, msdu_desc,
					&key_id) == true) {
					ol_rx_err(vdev->pdev->ctrl_pdev,
						  vdev->vdev_id,
						  peer->mac_addr.raw, tid, 0,
						  OL_RX_ERR_TKIP_MIC, msdu,
						  &pn.pn48, key_id);
				}
			}
		}
		/* Pktlog */
		ol_rx_mic_error_send_pktlog_event(pdev, peer, msdu, 1);
	}
}

/**
 * @brief Check the first msdu to decide whether the a-msdu should be accepted.
 */
static bool
ol_rx_filter(struct ol_txrx_vdev_t *vdev,
	     struct ol_txrx_peer_t *peer, qdf_nbuf_t msdu, void *rx_desc)
{
#define FILTER_STATUS_REJECT 1
#define FILTER_STATUS_ACCEPT 0
	uint8_t *wh;
	uint32_t offset = 0;
	uint16_t ether_type = 0;
	bool is_encrypted = false, is_mcast = false;
	uint8_t i;
	enum privacy_filter_packet_type packet_type =
		PRIVACY_FILTER_PACKET_UNICAST;
	ol_txrx_pdev_handle pdev = vdev->pdev;
	htt_pdev_handle htt_pdev = pdev->htt_pdev;
	int sec_idx;

	/*
	 * Safemode must avoid the PrivacyExemptionList and
	 * ExcludeUnencrypted checking
	 */
	if (vdev->safemode)
		return FILTER_STATUS_ACCEPT;

	is_mcast = htt_rx_msdu_is_wlan_mcast(htt_pdev, rx_desc);
	if (vdev->num_filters > 0) {
		if (pdev->frame_format == wlan_frm_fmt_native_wifi) {
			offset = SIZEOF_80211_HDR +
				LLC_SNAP_HDR_OFFSET_ETHERTYPE;
		} else {
			offset = ETHERNET_ADDR_LEN * 2;
		}
		/* get header info from msdu */
		wh = qdf_nbuf_data(msdu);

		/* get ether type */
		ether_type = (wh[offset] << 8) | wh[offset + 1];
		/* get packet type */
		if (true == is_mcast)
			packet_type = PRIVACY_FILTER_PACKET_MULTICAST;
		else
			packet_type = PRIVACY_FILTER_PACKET_UNICAST;
	}
	/* get encrypt info */
	is_encrypted = htt_rx_mpdu_is_encrypted(htt_pdev, rx_desc);
#ifdef ATH_SUPPORT_WAPI
	if ((true == is_encrypted) && (ETHERTYPE_WAI == ether_type)) {
		/* We expect the WAI frames to be always unencrypted when
		   the UMAC gets it.*/
		return FILTER_STATUS_REJECT;
	}
#endif /* ATH_SUPPORT_WAPI */

	for (i = 0; i < vdev->num_filters; i++) {
		enum privacy_filter filter_type;
		enum privacy_filter_packet_type filter_packet_type;

		/* skip if the ether type does not match */
		if (vdev->privacy_filters[i].ether_type != ether_type)
			continue;

		/* skip if the packet type does not match */
		filter_packet_type = vdev->privacy_filters[i].packet_type;
		if (filter_packet_type != packet_type &&
		    filter_packet_type != PRIVACY_FILTER_PACKET_BOTH) {
			continue;
		}

		filter_type = vdev->privacy_filters[i].filter_type;
		if (filter_type == PRIVACY_FILTER_ALWAYS) {
			/*
			 * In this case, we accept the frame if and only if
			 * it was originally NOT encrypted.
			 */
			if (true == is_encrypted)
				return FILTER_STATUS_REJECT;
			else
				return FILTER_STATUS_ACCEPT;

		} else if (filter_type == PRIVACY_FILTER_KEY_UNAVAILABLE) {
			/*
			 * In this case, we reject the frame if it was
			 * originally NOT encrypted but we have the key mapping
			 * key for this frame.
			 */
			if (!is_encrypted &&
			    !is_mcast &&
			    (peer->security[txrx_sec_ucast].sec_type !=
			     htt_sec_type_none) &&
			    (peer->keyinstalled || !ETHERTYPE_IS_EAPOL_WAPI(
				    ether_type))) {
				return FILTER_STATUS_REJECT;
			} else {
				return FILTER_STATUS_ACCEPT;
			}
		} else {
			/*
			 * The privacy exemption does not apply to this frame.
			 */
			break;
		}
	}

	/*
	 * If the privacy exemption list does not apply to the frame,
	 * check ExcludeUnencrypted.
	 * If ExcludeUnencrypted is not set, or if this was oringially
	 * an encrypted frame, it will be accepted.
	 */
	if (!vdev->drop_unenc || (true == is_encrypted))
		return FILTER_STATUS_ACCEPT;

	/*
	 *  If this is a open connection, it will be accepted.
	 */
	sec_idx = (true == is_mcast) ? txrx_sec_mcast : txrx_sec_ucast;
	if (peer->security[sec_idx].sec_type == htt_sec_type_none)
		return FILTER_STATUS_ACCEPT;

	if ((false == is_encrypted) && vdev->drop_unenc) {
		OL_RX_ERR_STATISTICS(pdev, vdev, OL_RX_ERR_PRIVACY,
				     pdev->sec_types[htt_sec_type_none],
				     is_mcast);
	}
	return FILTER_STATUS_REJECT;
}

void
ol_rx_deliver(struct ol_txrx_vdev_t *vdev,
	      struct ol_txrx_peer_t *peer, unsigned tid, qdf_nbuf_t msdu_list)
{
	ol_txrx_pdev_handle pdev = vdev->pdev;
	htt_pdev_handle htt_pdev = pdev->htt_pdev;
	qdf_nbuf_t deliver_list_head = NULL;
	qdf_nbuf_t deliver_list_tail = NULL;
	qdf_nbuf_t msdu;
	bool filter = false;
#ifdef QCA_SUPPORT_SW_TXRX_ENCAP
	struct ol_rx_decap_info_t info;
	qdf_mem_set(&info, sizeof(info), 0);
#endif

	msdu = msdu_list;
	/*
	 * Check each MSDU to see whether it requires special handling,
	 * and free each MSDU's rx descriptor
	 */
	while (msdu) {
		void *rx_desc;
		int discard, inspect, dummy_fwd;
		qdf_nbuf_t next = qdf_nbuf_next(msdu);

		rx_desc = htt_rx_msdu_desc_retrieve(pdev->htt_pdev, msdu);
		/* for HL, point to payload right now*/
		if (pdev->cfg.is_high_latency)
			qdf_nbuf_pull_head(msdu,
				htt_rx_msdu_rx_desc_size_hl(htt_pdev, rx_desc));

#ifdef QCA_SUPPORT_SW_TXRX_ENCAP
		info.is_msdu_cmpl_mpdu =
			htt_rx_msdu_desc_completes_mpdu(htt_pdev, rx_desc);
		info.is_first_subfrm =
			htt_rx_msdu_first_msdu_flag(htt_pdev, rx_desc);
		if (OL_RX_DECAP(vdev, peer, msdu, &info) != A_OK) {
			discard = 1;
			TXRX_PRINT(TXRX_PRINT_LEVEL_WARN,
				   "decap error %p from peer %p "
				   "(%02x:%02x:%02x:%02x:%02x:%02x) len %d\n",
				   msdu, peer,
				   peer->mac_addr.raw[0], peer->mac_addr.raw[1],
				   peer->mac_addr.raw[2], peer->mac_addr.raw[3],
				   peer->mac_addr.raw[4], peer->mac_addr.raw[5],
				   qdf_nbuf_len(msdu));
			goto DONE;
		}
#endif
		htt_rx_msdu_actions(pdev->htt_pdev, rx_desc, &discard,
				    &dummy_fwd, &inspect);
		if (inspect)
			ol_rx_inspect(vdev, peer, tid, msdu, rx_desc);

		/*
		 * Check the first msdu in the mpdu, if it will be filtered out,
		 * then discard the entire mpdu.
		 */
		if (htt_rx_msdu_first_msdu_flag(htt_pdev, rx_desc))
			filter = ol_rx_filter(vdev, peer, msdu, rx_desc);

#ifdef QCA_SUPPORT_SW_TXRX_ENCAP
DONE:
#endif
		htt_rx_msdu_desc_free(htt_pdev, msdu);
		if (discard || (true == filter)) {
			ol_txrx_frms_dump("rx discarding:",
					  pdev, deliver_list_head,
					  ol_txrx_frm_dump_tcp_seq |
					  ol_txrx_frm_dump_contents,
					  0 /* don't print contents */);
			qdf_nbuf_free(msdu);
			/* If discarding packet is last packet of the delivery
			   list, NULL terminator should be added
			   for delivery list. */
			if (next == NULL && deliver_list_head) {
				/* add NULL terminator */
				qdf_nbuf_set_next(deliver_list_tail, NULL);
			}
		} else {
			/*
			 *  If this is for OCB,
			 *  then prepend the RX stats header.
			 */
			if (vdev->opmode == wlan_op_mode_ocb) {
				int i;
				struct ol_txrx_ocb_chan_info *chan_info = 0;
				int packet_freq = peer->last_pkt_center_freq;
				for (i = 0; i < vdev->ocb_channel_count; i++) {
					if (vdev->ocb_channel_info[i].
						chan_freq == packet_freq) {
						chan_info = &vdev->
							ocb_channel_info[i];
						break;
					}
				}
				if (!chan_info || !chan_info->
					disable_rx_stats_hdr) {
					struct ether_header eth_header = {
						{0} };
					struct ocb_rx_stats_hdr_t rx_header = {
						0};

					/*
					 * Construct the RX stats header and
					 * push that to the frontof the packet.
					 */
					rx_header.version = 1;
					rx_header.length = sizeof(rx_header);
					rx_header.channel_freq =
						peer->last_pkt_center_freq;
					rx_header.rssi_cmb =
						peer->last_pkt_rssi_cmb;
					qdf_mem_copy(rx_header.rssi,
							peer->last_pkt_rssi,
							sizeof(rx_header.rssi));
					if (peer->last_pkt_legacy_rate_sel ==
					    0) {
						switch (peer->
							last_pkt_legacy_rate) {
						case 0x8:
							rx_header.datarate = 6;
							break;
						case 0x9:
							rx_header.datarate = 4;
							break;
						case 0xA:
							rx_header.datarate = 2;
							break;
						case 0xB:
							rx_header.datarate = 0;
							break;
						case 0xC:
							rx_header.datarate = 7;
							break;
						case 0xD:
							rx_header.datarate = 5;
							break;
						case 0xE:
							rx_header.datarate = 3;
							break;
						case 0xF:
							rx_header.datarate = 1;
							break;
						default:
							rx_header.datarate =
								0xFF;
							break;
						}
					} else {
						rx_header.datarate = 0xFF;
					}

					rx_header.timestamp_microsec = peer->
						last_pkt_timestamp_microsec;
					rx_header.timestamp_submicrosec = peer->
						last_pkt_timestamp_submicrosec;
					rx_header.tsf32 = peer->last_pkt_tsf;
					rx_header.ext_tid = peer->last_pkt_tid;

					qdf_nbuf_push_head(msdu,
						sizeof(rx_header));
					qdf_mem_copy(qdf_nbuf_data(msdu),
						&rx_header, sizeof(rx_header));

					/* Construct the ethernet header with
					   type 0x8152 and push that to the
					   front of the packet to indicate the
					   RX stats header. */
					eth_header.ether_type = QDF_SWAP_U16(
						ETHERTYPE_OCB_RX);
					qdf_nbuf_push_head(msdu,
							   sizeof(eth_header));
					qdf_mem_copy(qdf_nbuf_data(msdu),
							&eth_header,
							 sizeof(eth_header));
				}
			}
			OL_RX_PEER_STATS_UPDATE(peer, msdu);
			OL_RX_ERR_STATISTICS_1(pdev, vdev, peer, rx_desc,
					       OL_RX_ERR_NONE);
			TXRX_STATS_MSDU_INCR(vdev->pdev, rx.delivered, msdu);
			OL_TXRX_LIST_APPEND(deliver_list_head,
					    deliver_list_tail, msdu);
		}
		msdu = next;
	}
	/* sanity check - are there any frames left to give to the OS shim? */
	if (!deliver_list_head)
		return;

#if defined(PERE_IP_HDR_ALIGNMENT_WAR)
	if (pdev->host_80211_enable)
		for (msdu = deliver_list_head; msdu; msdu = qdf_nbuf_next(msdu))
			transcap_nwifi_to_8023(msdu);
#endif

	ol_txrx_frms_dump("rx delivering:",
			  pdev, deliver_list_head,
			  ol_txrx_frm_dump_tcp_seq | ol_txrx_frm_dump_contents,
			  0 /* don't print contents */);

	ol_rx_data_process(peer, deliver_list_head);
}

void
ol_rx_discard(struct ol_txrx_vdev_t *vdev,
	      struct ol_txrx_peer_t *peer, unsigned tid, qdf_nbuf_t msdu_list)
{
	ol_txrx_pdev_handle pdev = vdev->pdev;
	htt_pdev_handle htt_pdev = pdev->htt_pdev;

	while (msdu_list) {
		qdf_nbuf_t msdu = msdu_list;

		msdu_list = qdf_nbuf_next(msdu_list);
		TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
			   "discard rx %p from partly-deleted peer %p "
			   "(%02x:%02x:%02x:%02x:%02x:%02x)\n",
			   msdu, peer,
			   peer->mac_addr.raw[0], peer->mac_addr.raw[1],
			   peer->mac_addr.raw[2], peer->mac_addr.raw[3],
			   peer->mac_addr.raw[4], peer->mac_addr.raw[5]);
		htt_rx_desc_frame_free(htt_pdev, msdu);
	}
}

void ol_rx_peer_init(struct ol_txrx_pdev_t *pdev, struct ol_txrx_peer_t *peer)
{
	uint8_t tid;
	for (tid = 0; tid < OL_TXRX_NUM_EXT_TIDS; tid++) {
		ol_rx_reorder_init(&peer->tids_rx_reorder[tid], tid);

		/* invalid sequence number */
		peer->tids_last_seq[tid] = IEEE80211_SEQ_MAX;
	}
	/*
	 * Set security defaults: no PN check, no security.
	 * The target may send a HTT SEC_IND message to overwrite
	 * these defaults.
	 */
	peer->security[txrx_sec_ucast].sec_type =
		peer->security[txrx_sec_mcast].sec_type = htt_sec_type_none;
	peer->keyinstalled = 0;

	peer->last_assoc_rcvd = 0;
	peer->last_disassoc_rcvd = 0;
	peer->last_deauth_rcvd = 0;

	qdf_atomic_init(&peer->fw_pn_check);
}

void
ol_rx_peer_cleanup(struct ol_txrx_vdev_t *vdev, struct ol_txrx_peer_t *peer)
{
	peer->keyinstalled = 0;
	peer->last_assoc_rcvd = 0;
	peer->last_disassoc_rcvd = 0;
	peer->last_deauth_rcvd = 0;
	ol_rx_reorder_peer_cleanup(vdev, peer);
}

/*
 * Free frames including both rx descriptors and buffers
 */
void ol_rx_frames_free(htt_pdev_handle htt_pdev, qdf_nbuf_t frames)
{
	qdf_nbuf_t next, frag = frames;

	while (frag) {
		next = qdf_nbuf_next(frag);
		htt_rx_desc_frame_free(htt_pdev, frag);
		frag = next;
	}
}

#ifndef CONFIG_HL_SUPPORT
void
ol_rx_in_order_indication_handler(ol_txrx_pdev_handle pdev,
				  qdf_nbuf_t rx_ind_msg,
				  uint16_t peer_id,
				  uint8_t tid, uint8_t is_offload)
{
	struct ol_txrx_vdev_t *vdev = NULL;
	struct ol_txrx_peer_t *peer = NULL;
	htt_pdev_handle htt_pdev = NULL;
	int status;
	qdf_nbuf_t head_msdu, tail_msdu = NULL;
	uint8_t *rx_ind_data;
	uint32_t *msg_word;
	uint32_t msdu_count;
#ifdef WDI_EVENT_ENABLE
	uint8_t pktlog_bit;
#endif
	uint32_t filled = 0;

	if (pdev) {
		if (qdf_unlikely(QDF_GLOBAL_MONITOR_MODE == cds_get_conparam()))
			peer = pdev->self_peer;
		else
			peer = ol_txrx_peer_find_by_id(pdev, peer_id);
		htt_pdev = pdev->htt_pdev;
	} else {
		TXRX_PRINT(TXRX_PRINT_LEVEL_ERR,
			   "%s: Invalid pdev passed!\n", __func__);
		qdf_assert_always(pdev);
		return;
	}

#if defined(HELIUMPLUS_DEBUG)
	qdf_print("%s %d: rx_ind_msg 0x%p peer_id %d tid %d is_offload %d\n",
		  __func__, __LINE__, rx_ind_msg, peer_id, tid, is_offload);
#endif

#ifdef WDI_EVENT_ENABLE
	pktlog_bit = (htt_rx_amsdu_rx_in_order_get_pktlog(rx_ind_msg) == 0x01);
#endif

	rx_ind_data = qdf_nbuf_data(rx_ind_msg);
	msg_word = (uint32_t *)rx_ind_data;
	/* Get the total number of MSDUs */
	msdu_count = HTT_RX_IN_ORD_PADDR_IND_MSDU_CNT_GET(*(msg_word + 1));

	ol_rx_ind_record_event(msdu_count, OL_RX_INDICATION_POP_START);

	/*
	 * Get a linked list of the MSDUs in the rx in order indication.
	 * This also attaches each rx MSDU descriptor to the
	 * corresponding rx MSDU network buffer.
	 */
	status = htt_rx_amsdu_pop(htt_pdev, rx_ind_msg, &head_msdu, &tail_msdu);
	ol_rx_ind_record_event(status, OL_RX_INDICATION_POP_END);

	if (qdf_unlikely(0 == status)) {
		TXRX_PRINT(TXRX_PRINT_LEVEL_WARN,
			   "%s: Pop status is 0, returning here\n", __func__);
		return;
	}

	/* Replenish the rx buffer ring first to provide buffers to the target
	   rather than waiting for the indeterminate time taken by the OS
	   to consume the rx frames */
	filled = htt_rx_msdu_buff_in_order_replenish(htt_pdev, msdu_count);
	ol_rx_ind_record_event(filled, OL_RX_INDICATION_BUF_REPLENISH);

	/* Send the chain of MSDUs to the OS */
	/* rx_opt_proc takes a NULL-terminated list of msdu netbufs */
	qdf_nbuf_set_next(tail_msdu, NULL);

	/* Pktlog */
#ifdef WDI_EVENT_ENABLE
	ol_rx_send_pktlog_event(pdev, peer, head_msdu, pktlog_bit);
#endif

	/* if this is an offload indication, peer id is carried in the
	   rx buffer */
	if (peer) {
		vdev = peer->vdev;
	} else {
		TXRX_PRINT(TXRX_PRINT_LEVEL_INFO2,
			   "%s: Couldn't find peer from ID 0x%x\n",
			   __func__, peer_id);
		while (head_msdu) {
			qdf_nbuf_t msdu = head_msdu;
			head_msdu = qdf_nbuf_next(head_msdu);
			TXRX_STATS_MSDU_INCR(pdev,
				 rx.dropped_peer_invalid, msdu);
			htt_rx_desc_frame_free(htt_pdev, msdu);
		}
		return;
	}

	peer->rx_opt_proc(vdev, peer, tid, head_msdu);
}
#endif

/**
 * ol_rx_pkt_dump_call() - updates status and
 * calls packetdump callback to log rx packet
 *
 * @msdu: rx packet
 * @peer_id: peer id
 * @status: status of rx packet
 *
 * This function is used to update the status of rx packet
 * and then calls packetdump callback to log that packet.
 *
 * Return: None
 *
 */
void ol_rx_pkt_dump_call(
	qdf_nbuf_t msdu,
	uint8_t peer_id,
	uint8_t status)
{
	v_CONTEXT_t vos_context;
	ol_txrx_pdev_handle pdev;
	struct ol_txrx_peer_t *peer = NULL;
	tp_ol_packetdump_cb packetdump_cb;

	vos_context = cds_get_global_context();
	pdev = cds_get_context(QDF_MODULE_ID_TXRX);

	if (!pdev) {
		TXRX_PRINT(TXRX_PRINT_LEVEL_ERR,
			"%s: pdev is NULL", __func__);
		return;
	}

	peer = ol_txrx_peer_find_by_id(pdev, peer_id);
	if (!peer) {
		TXRX_PRINT(TXRX_PRINT_LEVEL_INFO1,
			"%s: peer with peer id %d is NULL", __func__,
			peer_id);
		return;
	}

	packetdump_cb = pdev->ol_rx_packetdump_cb;
	if (packetdump_cb)
		packetdump_cb(msdu, status, peer->vdev->vdev_id, RX_DATA_PKT);
}

/* the msdu_list passed here must be NULL terminated */
void
ol_rx_in_order_deliver(struct ol_txrx_vdev_t *vdev,
		       struct ol_txrx_peer_t *peer,
		       unsigned tid, qdf_nbuf_t msdu_list)
{
	qdf_nbuf_t msdu;

	msdu = msdu_list;
	/*
	 * Currently, this does not check each MSDU to see whether it requires
	 * special handling. MSDUs that need special handling (example: IGMP
	 * frames) should be sent via a seperate HTT message. Also, this does
	 * not do rx->tx forwarding or filtering.
	 */

	while (msdu) {
		qdf_nbuf_t next = qdf_nbuf_next(msdu);

		DPTRACE(qdf_dp_trace(msdu,
			QDF_DP_TRACE_RX_TXRX_PACKET_PTR_RECORD,
			qdf_nbuf_data_addr(msdu),
			sizeof(qdf_nbuf_data(msdu)), QDF_RX));

		OL_RX_PEER_STATS_UPDATE(peer, msdu);
		OL_RX_ERR_STATISTICS_1(vdev->pdev, vdev, peer, rx_desc,
				       OL_RX_ERR_NONE);
		TXRX_STATS_MSDU_INCR(vdev->pdev, rx.delivered, msdu);

		msdu = next;
	}

	ol_txrx_frms_dump("rx delivering:",
			  pdev, deliver_list_head,
			  ol_txrx_frm_dump_tcp_seq | ol_txrx_frm_dump_contents,
			  0 /* don't print contents */);

	ol_rx_data_process(peer, msdu_list);
}

void ol_rx_log_packet(htt_pdev_handle htt_pdev,
		uint8_t peer_id, qdf_nbuf_t msdu)
{
	struct ol_txrx_peer_t *peer;

	peer = ol_txrx_peer_find_by_id(htt_pdev->txrx_pdev, peer_id);
	if (peer)
		qdf_dp_trace_log_pkt(peer->vdev->vdev_id, msdu, QDF_RX);
}

#ifndef CONFIG_HL_SUPPORT
void
ol_rx_offload_paddr_deliver_ind_handler(htt_pdev_handle htt_pdev,
					uint32_t msdu_count,
					uint32_t *msg_word)
{
	int vdev_id, peer_id, tid;
	qdf_nbuf_t head_buf, tail_buf, buf;
	struct ol_txrx_peer_t *peer;
	uint8_t fw_desc;
	int msdu_iter = 0;

	while (msdu_count) {
		htt_rx_offload_paddr_msdu_pop_ll(htt_pdev, msg_word, msdu_iter,
						 &vdev_id, &peer_id, &tid,
						 &fw_desc, &head_buf,
						 &tail_buf);

		peer = ol_txrx_peer_find_by_id(htt_pdev->txrx_pdev, peer_id);
		if (peer) {
			QDF_NBUF_CB_DP_TRACE_PRINT(head_buf) = false;
			qdf_dp_trace_set_track(head_buf, QDF_RX);
			QDF_NBUF_CB_TX_PACKET_TRACK(head_buf) =
						QDF_NBUF_TX_PKT_DATA_TRACK;
			qdf_dp_trace_log_pkt(peer->vdev->vdev_id,
				head_buf, QDF_RX);
			DPTRACE(qdf_dp_trace(head_buf,
				QDF_DP_TRACE_RX_OFFLOAD_HTT_PACKET_PTR_RECORD,
				qdf_nbuf_data_addr(head_buf),
				sizeof(qdf_nbuf_data(head_buf)), QDF_RX));
			ol_rx_data_process(peer, head_buf);
		} else {
			buf = head_buf;
			while (1) {
				qdf_nbuf_t next;
				next = qdf_nbuf_next(buf);
				htt_rx_desc_frame_free(htt_pdev, buf);
				if (buf == tail_buf)
					break;
				buf = next;
			}
		}
		msdu_iter++;
		msdu_count--;
	}
	htt_rx_msdu_buff_replenish(htt_pdev);
}
#endif

/**
 * ol_htt_mon_note_chan() - Update monitor channel information
 * @pdev:  handle to the physical device
 * @mon_ch: Monitor channel
 *
 * Return: None
 */
void ol_htt_mon_note_chan(ol_txrx_pdev_handle pdev, int mon_ch)
{
	htt_rx_mon_note_capture_channel(pdev->htt_pdev, mon_ch);
}

#ifdef NEVERDEFINED
/**
 * @brief populates vow ext stats in given network buffer.
 * @param msdu - network buffer handle
 * @param pdev - handle to htt dev.
 */
void ol_ath_add_vow_extstats(htt_pdev_handle pdev, qdf_nbuf_t msdu)
{
	/* FIX THIS:
	 * txrx should not be directly using data types (scn)
	 * that are internal to other modules.
	 */
	struct ol_ath_softc_net80211 *scn =
		(struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;

	if (scn->vow_extstats == 0) {
		return;
	} else {
		uint8_t *data, *l3_hdr, *bp;
		uint16_t ethertype;
		int offset;
		struct vow_extstats vowstats;

		data = qdf_nbuf_data(msdu);

		offset = ETHERNET_ADDR_LEN * 2;
		l3_hdr = data + ETHERNET_HDR_LEN;
		ethertype = (data[offset] << 8) | data[offset + 1];
		if (ethertype == ETHERTYPE_IPV4) {
			offset = IPV4_HDR_OFFSET_PROTOCOL;
			if ((l3_hdr[offset] == IP_PROTOCOL_UDP) &&
			    (l3_hdr[0] == IP_VER4_N_NO_EXTRA_HEADERS)) {
				bp = data + EXT_HDR_OFFSET;

				if ((data[RTP_HDR_OFFSET] == UDP_PDU_RTP_EXT) &&
				    (bp[0] == 0x12) &&
				    (bp[1] == 0x34) &&
				    (bp[2] == 0x00) && (bp[3] == 0x08)) {
					/*
					 * Clear UDP checksum so we do not have
					 * to recalculate it
					 * after filling in status fields.
					 */
					data[UDP_CKSUM_OFFSET] = 0;
					data[(UDP_CKSUM_OFFSET + 1)] = 0;

					bp += IPERF3_DATA_OFFSET;

					htt_rx_get_vowext_stats(msdu,
								&vowstats);

					/* control channel RSSI */
					*bp++ = vowstats.rx_rssi_ctl0;
					*bp++ = vowstats.rx_rssi_ctl1;
					*bp++ = vowstats.rx_rssi_ctl2;

					/* rx rate info */
					*bp++ = vowstats.rx_bw;
					*bp++ = vowstats.rx_sgi;
					*bp++ = vowstats.rx_nss;

					*bp++ = vowstats.rx_rssi_comb;
					/* rsflags */
					*bp++ = vowstats.rx_rs_flags;

					/* Time stamp Lo */
					*bp++ = (uint8_t)
						((vowstats.
						  rx_macTs & 0x0000ff00) >> 8);
					*bp++ = (uint8_t)
						(vowstats.rx_macTs & 0x0000ff);
					/* rx phy errors */
					*bp++ = (uint8_t)
						((scn->chan_stats.
						  phy_err_cnt >> 8) & 0xff);
					*bp++ =
						(uint8_t) (scn->chan_stats.
							   phy_err_cnt & 0xff);
					/* rx clear count */
					*bp++ = (uint8_t)
						((scn->mib_cycle_cnts.
						  rx_clear_count >> 24) & 0xff);
					*bp++ = (uint8_t)
						((scn->mib_cycle_cnts.
						  rx_clear_count >> 16) & 0xff);
					*bp++ = (uint8_t)
						((scn->mib_cycle_cnts.
						  rx_clear_count >> 8) & 0xff);
					*bp++ = (uint8_t)
						(scn->mib_cycle_cnts.
						 rx_clear_count & 0xff);
					/* rx cycle count */
					*bp++ = (uint8_t)
						((scn->mib_cycle_cnts.
						  cycle_count >> 24) & 0xff);
					*bp++ = (uint8_t)
						((scn->mib_cycle_cnts.
						  cycle_count >> 16) & 0xff);
					*bp++ = (uint8_t)
						((scn->mib_cycle_cnts.
						  cycle_count >> 8) & 0xff);
					*bp++ = (uint8_t)
						(scn->mib_cycle_cnts.
						 cycle_count & 0xff);

					*bp++ = vowstats.rx_ratecode;
					*bp++ = vowstats.rx_moreaggr;

					/* sequence number */
					*bp++ = (uint8_t)
						((vowstats.rx_seqno >> 8) &
						 0xff);
					*bp++ = (uint8_t)
						(vowstats.rx_seqno & 0xff);
				}
			}
		}
	}
}

#endif
