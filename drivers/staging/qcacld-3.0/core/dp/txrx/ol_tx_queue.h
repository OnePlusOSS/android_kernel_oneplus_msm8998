/*
 * Copyright (c) 2012-2016 The Linux Foundation. All rights reserved.
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
 * @file ol_tx_queue.h
 * @brief API definitions for the tx frame queue module within the data SW.
 */
#ifndef _OL_TX_QUEUE__H_
#define _OL_TX_QUEUE__H_

#include <qdf_nbuf.h>           /* qdf_nbuf_t */
#include <cdp_txrx_cmn.h>       /* ol_txrx_vdev_t, etc. */
#include <qdf_types.h>          /* bool */

/*--- function prototypes for optional queue log feature --------------------*/
#if defined(ENABLE_TX_QUEUE_LOG) || \
	(defined(DEBUG_HL_LOGGING) && defined(CONFIG_HL_SUPPORT))

/**
 * ol_tx_queue_log_enqueue() - enqueue tx queue logs
 * @pdev: physical device object
 * @msdu_info: tx msdu meta data
 * @frms: number of frames for which logs need to be enqueued
 * @bytes: number of bytes
 *
 *
 * Return: None
 */
void
ol_tx_queue_log_enqueue(struct ol_txrx_pdev_t *pdev,
			struct ol_txrx_msdu_info_t *msdu_info,
			int frms, int bytes);

/**
 * ol_tx_queue_log_dequeue() - dequeue tx queue logs
 * @pdev: physical device object
 * @txq: tx queue
 * @frms: number of frames for which logs need to be dequeued
 * @bytes: number of bytes
 *
 *
 * Return: None
 */
void
ol_tx_queue_log_dequeue(struct ol_txrx_pdev_t *pdev,
			struct ol_tx_frms_queue_t *txq, int frms, int bytes);

/**
 * ol_tx_queue_log_free() - free tx queue logs
 * @pdev: physical device object
 * @txq: tx queue
 * @tid: tid value
 * @frms: number of frames for which logs need to be freed
 * @bytes: number of bytes
 * @is_peer_txq - peer queue or not
 *
 *
 * Return: None
 */
void
ol_tx_queue_log_free(struct ol_txrx_pdev_t *pdev,
		     struct ol_tx_frms_queue_t *txq,
		     int tid, int frms, int bytes, bool is_peer_txq);

#else

static inline void
ol_tx_queue_log_enqueue(struct ol_txrx_pdev_t *pdev,
			struct ol_txrx_msdu_info_t *msdu_info,
			int frms, int bytes)
{
	return;
}

static inline void
ol_tx_queue_log_dequeue(struct ol_txrx_pdev_t *pdev,
			struct ol_tx_frms_queue_t *txq, int frms, int bytes)
{
	return;
}

static inline void
ol_tx_queue_log_free(struct ol_txrx_pdev_t *pdev,
		     struct ol_tx_frms_queue_t *txq,
		     int tid, int frms, int bytes, bool is_peer_txq)
{
	return;
}

#endif

#if defined(CONFIG_HL_SUPPORT)

/**
 * @brief Queue a tx frame to the tid queue.
 *
 * @param pdev - the data virtual device sending the data
 *      (for storing the tx desc in the virtual dev's tx_target_list,
 *      and for accessing the phy dev)
 * @param txq - which queue the tx frame gets stored in
 * @param tx_desc - tx meta-data, including prev and next ptrs
 * @param tx_msdu_info - characteristics of the tx frame
 */
void
ol_tx_enqueue(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		struct ol_tx_desc_t *tx_desc,
		struct ol_txrx_msdu_info_t *tx_msdu_info);

/**
 * @brief - remove the specified number of frames from the head of a tx queue
 * @details
 *  This function removes frames from the head of a tx queue,
 *  and returns them as a NULL-terminated linked list.
 *  The function will remove frames until one of the following happens:
 *  1.  The tx queue is empty
 *  2.  The specified number of frames have been removed
 *  3.  Removal of more frames would exceed the specified credit limit
 *
 * @param pdev - the physical device object
 * @param txq - which tx queue to remove frames from
 * @param head - which contains return linked-list of tx frames (descriptors)
 * @param num_frames - maximum number of frames to remove
 * @param[in/out] credit -
 *     input:  max credit the dequeued frames can consume
 *     output: how much credit the dequeued frames consume
 * @param[out] bytes - the sum of the sizes of the dequeued frames
 * @return number of frames dequeued
*/
u_int16_t
ol_tx_dequeue(
	struct ol_txrx_pdev_t *pdev,
	struct ol_tx_frms_queue_t *txq,
	ol_tx_desc_list *head,
	u_int16_t num_frames,
	u_int32_t *credit,
	int *bytes);

/**
 * @brief - free all of frames from the tx queue while deletion
 * @details
 *  This function frees all of frames from the tx queue.
 *  This function is called during peer or vdev deletion.
 *  This function notifies the scheduler, so the scheduler can update
 *  its state to account for the absence of the queue.
 *
 * @param pdev - the physical device object, which stores the txqs
 * @param txq - which tx queue to free frames from
 * @param tid - the extended TID that the queue belongs to
 * @param is_peer_txq - peer queue or not
 */
void
ol_tx_queue_free(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		int tid, bool is_peer_txq);

/**
 * @brief - discard pending tx frames from the tx queue
 * @details
 *  This function is called if there are too many queues in tx scheduler.
 *  This function is called if we wants to flush all pending tx
 *  queues in tx scheduler.
 *
 * @param pdev - the physical device object, which stores the txqs
 * @param flush_all - flush all pending tx queues if set to true
 * @param tx_descs - List Of tx_descs to be discarded will be returned by this function
 */

void
ol_tx_queue_discard(
		struct ol_txrx_pdev_t *pdev,
		bool flush_all,
		ol_tx_desc_list *tx_descs);

#else

static inline void
ol_tx_enqueue(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		struct ol_tx_desc_t *tx_desc,
		struct ol_txrx_msdu_info_t *tx_msdu_info)
{
	return;
}

static inline u_int16_t
ol_tx_dequeue(
	struct ol_txrx_pdev_t *pdev,
	struct ol_tx_frms_queue_t *txq,
	ol_tx_desc_list *head,
	u_int16_t num_frames,
	u_int32_t *credit,
	int *bytes)
{
	return 0;
}

static inline void
ol_tx_queue_free(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		int tid, bool is_peer_txq)
{
	return;
}

static inline void
ol_tx_queue_discard(
		struct ol_txrx_pdev_t *pdev,
		bool flush_all,
		ol_tx_desc_list *tx_descs)
{
	return;
}
#endif /* defined(CONFIG_HL_SUPPORT) */

#if defined(CONFIG_HL_SUPPORT) && defined(QCA_BAD_PEER_TX_FLOW_CL)

void
ol_txrx_peer_bal_add_limit_peer(
		struct ol_txrx_pdev_t *pdev,
		u_int16_t peer_id,
		u_int16_t peer_limit);

void
ol_txrx_peer_bal_remove_limit_peer(
		struct ol_txrx_pdev_t *pdev,
		u_int16_t peer_id);

/**
 * ol_txrx_peer_pause_but_no_mgmt_q() - suspend/pause all txqs except
 *					management queue for a given peer
 * @peer: peer device object
 *
 * Return: None
 */
void
ol_txrx_peer_pause_but_no_mgmt_q(ol_txrx_peer_handle peer);

/**
 * ol_txrx_peer_unpause_but_no_mgmt_q() - unpause all txqs except management
 *					  queue for a given peer
 * @peer: peer device object
 *
 * Return: None
 */
void
ol_txrx_peer_unpause_but_no_mgmt_q(ol_txrx_peer_handle peer);

/**
 * ol_tx_bad_peer_dequeue_check() - retrieve the send limit
 *				    of the tx queue category
 * @txq: tx queue of the head of the category list
 * @max_frames: send limit of the txq category
 * @tx_limit_flag: set true is tx limit is reached
 *
 * Return: send limit
 */
u_int16_t
ol_tx_bad_peer_dequeue_check(struct ol_tx_frms_queue_t *txq,
			     u_int16_t max_frames,
			     u_int16_t *tx_limit_flag);

/**
 * ol_tx_bad_peer_update_tx_limit() - update the send limit of the
 *				      tx queue category
 * @pdev: the physical device object
 * @txq: tx queue of the head of the category list
 * @frames: frames that has been dequeued
 * @tx_limit_flag: tx limit reached flag
 *
 * Return: None
 */
void
ol_tx_bad_peer_update_tx_limit(struct ol_txrx_pdev_t *pdev,
			       struct ol_tx_frms_queue_t *txq,
			       u_int16_t frames,
			       u_int16_t tx_limit_flag);

/**
 * ol_txrx_set_txq_peer() - set peer to the tx queue's peer
 * @txq: tx queue for a given tid
 * @peer: the peer device object
 *
 * Return: None
 */
void
ol_txrx_set_txq_peer(
	struct ol_tx_frms_queue_t *txq,
	struct ol_txrx_peer_t *peer);

/**
 * @brief - initialize the peer balance context
 * @param pdev - the physical device object, which stores the txqs
 */
void ol_tx_badpeer_flow_cl_init(struct ol_txrx_pdev_t *pdev);

/**
 * @brief - deinitialize the peer balance context
 * @param pdev - the physical device object, which stores the txqs
 */
void ol_tx_badpeer_flow_cl_deinit(struct ol_txrx_pdev_t *pdev);

#else

static inline void ol_txrx_peer_bal_add_limit_peer(
		struct ol_txrx_pdev_t *pdev,
		u_int16_t peer_id,
		u_int16_t peer_limit)
{
	return;
}

static inline void ol_txrx_peer_bal_remove_limit_peer(
		struct ol_txrx_pdev_t *pdev,
		u_int16_t peer_id)
{
	return;
}

static inline void ol_txrx_peer_pause_but_no_mgmt_q(ol_txrx_peer_handle peer)
{
	return;
}

static inline void ol_txrx_peer_unpause_but_no_mgmt_q(ol_txrx_peer_handle peer)
{
	return;
}

static inline u_int16_t
ol_tx_bad_peer_dequeue_check(struct ol_tx_frms_queue_t *txq,
			     u_int16_t max_frames,
			     u_int16_t *tx_limit_flag)
{
	/* just return max_frames */
	return max_frames;
}

static inline void
ol_tx_bad_peer_update_tx_limit(struct ol_txrx_pdev_t *pdev,
			       struct ol_tx_frms_queue_t *txq,
			       u_int16_t frames,
			       u_int16_t tx_limit_flag)
{
	return;
}

static inline void
ol_txrx_set_txq_peer(
		struct ol_tx_frms_queue_t *txq,
		struct ol_txrx_peer_t *peer)
{
	return;
}

static inline void ol_tx_badpeer_flow_cl_init(struct ol_txrx_pdev_t *pdev)
{
	return;
}

static inline void ol_tx_badpeer_flow_cl_deinit(struct ol_txrx_pdev_t *pdev)
{
	return;
}

#endif /* defined(CONFIG_HL_SUPPORT) && defined(QCA_BAD_PEER_TX_FLOW_CL) */

#if defined(CONFIG_HL_SUPPORT) && defined(DEBUG_HL_LOGGING)

/**
 * ol_tx_queue_log_sched() - start logging of tx queues for HL
 * @pdev: physical device object
 * @credit: number of credits
 * @num_active_tids: number of active tids for which logging needs to be done
 * @active_bitmap:bitmap
 * @data: buffer
 *
 * Return: None
 */
void
ol_tx_queue_log_sched(struct ol_txrx_pdev_t *pdev,
		      int credit,
		      int *num_active_tids,
		      uint32_t **active_bitmap, uint8_t **data);
#else

static inline void
ol_tx_queue_log_sched(struct ol_txrx_pdev_t *pdev,
		      int credit,
		      int *num_active_tids,
		      uint32_t **active_bitmap, uint8_t **data)
{
	return;
}
#endif /* defined(CONFIG_HL_SUPPORT) && defined(DEBUG_HL_LOGGING) */

#if defined(CONFIG_HL_SUPPORT) && TXRX_DEBUG_LEVEL > 5
/**
 * @brief - show current state of all tx queues
 * @param pdev - the physical device object, which stores the txqs
 */
void
ol_tx_queues_display(struct ol_txrx_pdev_t *pdev);

#else

static inline void
ol_tx_queues_display(struct ol_txrx_pdev_t *pdev)
{
	return;
}
#endif

#define ol_tx_queue_decs_reinit(peer, peer_id)  /* no-op */

#ifdef QCA_SUPPORT_TX_THROTTLE
/**
 * @brief - initialize the throttle context
 * @param pdev - the physical device object, which stores the txqs
 */
void ol_tx_throttle_init(struct ol_txrx_pdev_t *pdev);
#else
#define ol_tx_throttle_init(pdev)       /*no op */
#endif

#ifdef FEATURE_HL_GROUP_CREDIT_FLOW_CONTROL

static inline bool
ol_tx_is_txq_last_serviced_queue(struct ol_txrx_pdev_t *pdev,
				 struct ol_tx_frms_queue_t *txq)
{
	return txq == pdev->tx_sched.last_used_txq;
}

/**
 * ol_tx_txq_group_credit_limit() - check for credit limit of a given tx queue
 * @pdev: physical device object
 * @txq: tx queue for which credit limit needs be to checked
 * @credit: number of credits of the selected category
 *
 * Return: updated credits
 */
u_int32_t ol_tx_txq_group_credit_limit(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		u_int32_t credit);

/**
 * ol_tx_txq_group_credit_update() - update group credits of the
 *				     selected catoegory
 * @pdev: physical device object
 * @txq: tx queue for which credit needs to be updated
 * @credit: number of credits by which selected category needs to be updated
 * @absolute: TXQ group absolute value
 *
 * Return: None
 */
void ol_tx_txq_group_credit_update(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		int32_t credit,
		u_int8_t absolute);

/**
 * ol_tx_set_vdev_group_ptr() - update vdev queues group pointer
 * @pdev: physical device object
 * @vdev_id: vdev id for which group pointer needs to update
 * @grp_ptr: pointer to ol tx queue group which needs to be set for vdev queues
 *
 * Return: None
 */
void
ol_tx_set_vdev_group_ptr(
		ol_txrx_pdev_handle pdev,
		u_int8_t vdev_id,
		struct ol_tx_queue_group_t *grp_ptr);

/**
 * ol_tx_txq_set_group_ptr() - update tx queue group pointer
 * @txq: tx queue of which group pointer needs to update
 * @grp_ptr: pointer to ol tx queue group which needs to be
 *	     set for given tx queue
 *
 *
 * Return: None
 */
void
ol_tx_txq_set_group_ptr(
		struct ol_tx_frms_queue_t *txq,
		struct ol_tx_queue_group_t *grp_ptr);

/**
 * ol_tx_set_peer_group_ptr() - update peer tx queues group pointer
 *				for a given tid
 * @pdev: physical device object
 * @peer: peer device object
 * @vdev_id: vdev id
 * @tid: tid for which group pointer needs to update
 *
 *
 * Return: None
 */
void
ol_tx_set_peer_group_ptr(
		ol_txrx_pdev_handle pdev,
		struct ol_txrx_peer_t *peer,
		u_int8_t vdev_id,
		u_int8_t tid);
#else

static inline bool
ol_tx_is_txq_last_serviced_queue(struct ol_txrx_pdev_t *pdev,
				 struct ol_tx_frms_queue_t *txq)
{
	return 0;
}

static inline
u_int32_t ol_tx_txq_group_credit_limit(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		u_int32_t credit)
{
	return credit;
}

static inline void ol_tx_txq_group_credit_update(
		struct ol_txrx_pdev_t *pdev,
		struct ol_tx_frms_queue_t *txq,
		int32_t credit,
		u_int8_t absolute)
{
	return;
}

static inline void
ol_tx_txq_set_group_ptr(
		struct ol_tx_frms_queue_t *txq,
		struct ol_tx_queue_group_t *grp_ptr)
{
	return;
}

static inline void
ol_tx_set_peer_group_ptr(
		ol_txrx_pdev_handle pdev,
		struct ol_txrx_peer_t *peer,
		u_int8_t vdev_id,
		u_int8_t tid)
{
	return;
}
#endif

#endif /* _OL_TX_QUEUE__H_ */
