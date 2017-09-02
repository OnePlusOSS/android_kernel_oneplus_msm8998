/*
 * Copyright (c) 2012-2017 The Linux Foundation. All rights reserved.
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

/*
 * This file lim_link_monitoring_algo.cc contains the code for
 * Link monitoring algorithm on AP and heart beat failure
 * handling on STA.
 * Author:        Chandra Modumudi
 * Date:          03/01/02
 * History:-
 * Date           Modified by    Modification Information
 * --------------------------------------------------------------------
 *
 */

#include "ani_global.h"
#include "wni_cfg.h"
#include "cfg_api.h"

#include "sch_api.h"
#include "utils_api.h"
#include "lim_assoc_utils.h"
#include "lim_types.h"
#include "lim_utils.h"
#include "lim_prop_exts_utils.h"

#ifdef FEATURE_WLAN_DIAG_SUPPORT_LIM    /* FEATURE_WLAN_DIAG_SUPPORT */
#include "host_diag_core_log.h"
#endif /* FEATURE_WLAN_DIAG_SUPPORT */
#include "lim_ft_defs.h"
#include "lim_session.h"
#include "lim_ser_des_utils.h"

/**
 * lim_delete_sta_util - utility function for deleting station context
 *
 * @mac_ctx: global MAC context
 * @msg: pointer to delte station context
 * @session_entry: PE session entry
 *
 * utility function called to clear up station context.
 *
 * Return: None.
 */
static void lim_delete_sta_util(tpAniSirGlobal mac_ctx, tpDeleteStaContext msg,
				tpPESession session_entry)
{
	tpDphHashNode stads;

	lim_log(mac_ctx, LOGE,
		FL("Deleting station: staId = %d, reasonCode = %d"),
		msg->staId, msg->reasonCode);

	if (LIM_IS_IBSS_ROLE(session_entry)) {
		return;
	}

	stads = dph_lookup_assoc_id(mac_ctx, msg->staId, &msg->assocId,
				    &session_entry->dph.dphHashTable);

	if (!stads) {
		lim_log(mac_ctx, LOGE,
			FL("Invalid STA limSystemRole=%d"),
			GET_LIM_SYSTEM_ROLE(session_entry));
		return;
	}
	stads->del_sta_ctx_rssi = msg->rssi;

	/* check and see if same staId. This is to avoid the scenario
	 * where we're trying to delete a staId we just added.
	 */
	if (stads->staIndex != msg->staId) {
		lim_log(mac_ctx, LOGE, FL("staid mismatch: %d vs %d "),
			stads->staIndex, msg->staId);
		return;
	}

	if (LIM_IS_AP_ROLE(session_entry)) {
		lim_log(mac_ctx, LOG1,
			FL("Delete Station staId: %d, assocId: %d"),
			msg->staId, msg->assocId);
		/*
		 * Check if Deauth/Disassoc is triggered from Host.
		 * If mlmState is in some transient state then
		 * don't trigger STA deletion to avoid the race
		 * condition.
		 */
		 if ((stads &&
		     ((stads->mlmStaContext.mlmState !=
			eLIM_MLM_LINK_ESTABLISHED_STATE) &&
		      (stads->mlmStaContext.mlmState !=
			eLIM_MLM_WT_ASSOC_CNF_STATE) &&
		      (stads->mlmStaContext.mlmState !=
			eLIM_MLM_ASSOCIATED_STATE)))) {
			lim_log(mac_ctx, LOGE,
				FL("Inv Del STA staId:%d, assocId:%d"),
				msg->staId, msg->assocId);
			return;
		} else {
			lim_send_disassoc_mgmt_frame(mac_ctx,
				eSIR_MAC_DISASSOC_DUE_TO_INACTIVITY_REASON,
				stads->staAddr, session_entry, false);
			lim_trigger_sta_deletion(mac_ctx, stads, session_entry);
		}
	} else {
#ifdef FEATURE_WLAN_TDLS
		if (LIM_IS_STA_ROLE(session_entry) &&
		    STA_ENTRY_TDLS_PEER == stads->staType) {
			/*
			 * TeardownLink with PEER reason code
			 * HAL_DEL_STA_REASON_CODE_KEEP_ALIVE means
			 * eSIR_MAC_TDLS_TEARDOWN_PEER_UNREACHABLE
			 */
			lim_send_sme_tdls_del_sta_ind(mac_ctx, stads,
			    session_entry,
			    eSIR_MAC_TDLS_TEARDOWN_PEER_UNREACHABLE);
		} else {
#endif
		/* TearDownLink with AP */
		tLimMlmDeauthInd mlm_deauth_ind;
		lim_log(mac_ctx, LOGW,
			FL("Delete Station (staId: %d, assocId: %d) "),
			msg->staId, msg->assocId);

		if ((stads &&
			((stads->mlmStaContext.mlmState !=
					eLIM_MLM_LINK_ESTABLISHED_STATE) &&
			(stads->mlmStaContext.mlmState !=
					eLIM_MLM_WT_ASSOC_CNF_STATE) &&
			(stads->mlmStaContext.mlmState !=
					eLIM_MLM_ASSOCIATED_STATE)))) {

			/*
			 * Received SIR_LIM_DELETE_STA_CONTEXT_IND for STA that
			 * does not have context or in some transit state.
			 * Log error
			 */
			lim_log(mac_ctx, LOGE,
				FL("Received SIR_LIM_DELETE_STA_CONTEXT_IND for "
					"STA that either has no context or "
					"in some transit state, Addr = "
					MAC_ADDRESS_STR),
					MAC_ADDR_ARRAY(msg->bssId));
			return;
		}

		stads->mlmStaContext.disassocReason =
			eSIR_MAC_DISASSOC_DUE_TO_INACTIVITY_REASON;
		stads->mlmStaContext.cleanupTrigger =
			eLIM_LINK_MONITORING_DEAUTH;

		/* Issue Deauth Indication to SME. */
		qdf_mem_copy((uint8_t *) &mlm_deauth_ind.peerMacAddr,
			     stads->staAddr, sizeof(tSirMacAddr));
		mlm_deauth_ind.reasonCode =
			(uint8_t) stads->mlmStaContext.disassocReason;
		mlm_deauth_ind.deauthTrigger =
			stads->mlmStaContext.cleanupTrigger;

#ifdef FEATURE_WLAN_TDLS
		/* Delete all TDLS peers connected before leaving BSS */
		lim_delete_tdls_peers(mac_ctx, session_entry);
#endif
		if (LIM_IS_STA_ROLE(session_entry))
			lim_post_sme_message(mac_ctx, LIM_MLM_DEAUTH_IND,
				     (uint32_t *) &mlm_deauth_ind);

		lim_send_sme_deauth_ind(mac_ctx, stads,	session_entry);
#ifdef FEATURE_WLAN_TDLS
	}
#endif
	}
}

/**
 * lim_delete_sta_context() - delete sta context.
 *
 * @mac_ctx: global mac_ctx context
 * @lim_msg: lim message.
 *
 * This function handles the message from HAL: WMA_DELETE_STA_CONTEXT_IND.
 * This function validates that the given station id exist, and if so,
 * deletes the station by calling lim_trigger_sta_deletion.
 *
 * Return: none
 */
void lim_delete_sta_context(tpAniSirGlobal mac_ctx, tpSirMsgQ lim_msg)
{
	tpDeleteStaContext msg = (tpDeleteStaContext) lim_msg->bodyptr;
	tpPESession session_entry;
	tpDphHashNode sta_ds;

	if (NULL == msg) {
		lim_log(mac_ctx, LOGE, FL("Invalid body pointer in message"));
		return;
	}
	session_entry = pe_find_session_by_sme_session_id(mac_ctx, msg->vdev_id);
	if (NULL == session_entry) {
		lim_log(mac_ctx, LOGE,
			FL("session not found for given sme session"));
		qdf_mem_free(msg);
		return;
	}

	switch (msg->reasonCode) {
	case HAL_DEL_STA_REASON_CODE_KEEP_ALIVE:
		if (LIM_IS_STA_ROLE(session_entry) && !msg->is_tdls) {
			if (!((session_entry->limMlmState ==
			    eLIM_MLM_LINK_ESTABLISHED_STATE) &&
			    (session_entry->limSmeState !=
			    eLIM_SME_WT_DISASSOC_STATE) &&
			    (session_entry->limSmeState !=
			    eLIM_SME_WT_DEAUTH_STATE))) {
				lim_log(mac_ctx, LOGE,
				  FL("Do not process in limMlmState %s(%x) limSmeState %s(%x)"),
				  lim_mlm_state_str(session_entry->limMlmState),
				  session_entry->limMlmState,
				  lim_mlm_state_str(session_entry->limSmeState),
				  session_entry->limSmeState);
				qdf_mem_free(msg);
				return;
			}
			sta_ds = dph_get_hash_entry(mac_ctx,
					DPH_STA_HASH_INDEX_PEER,
					&session_entry->dph.dphHashTable);
			if (NULL == sta_ds) {
				lim_log(mac_ctx, LOGE,
					FL("Dph entry not found."));
				qdf_mem_free(msg);
				return;
			}
			lim_send_deauth_mgmt_frame(mac_ctx,
				eSIR_MAC_DISASSOC_DUE_TO_INACTIVITY_REASON,
				msg->addr2, session_entry, false);
			lim_tear_down_link_with_ap(mac_ctx,
						session_entry->peSessionId,
						eSIR_MAC_UNSPEC_FAILURE_REASON);
			/* only break for STA role (non TDLS) */
			break;
		}
		lim_delete_sta_util(mac_ctx, msg, session_entry);
		break;

	case HAL_DEL_STA_REASON_CODE_UNKNOWN_A2:
		lim_log(mac_ctx, LOGE, FL("Deleting Unknown station "));
		lim_print_mac_addr(mac_ctx, msg->addr2, LOGE);
		lim_send_deauth_mgmt_frame(mac_ctx,
			eSIR_MAC_CLASS3_FRAME_FROM_NON_ASSOC_STA_REASON,
			msg->addr2, session_entry, false);
		break;

	default:
		lim_log(mac_ctx, LOGE, FL(" Unknown reason code "));
		break;
	}
	qdf_mem_free(msg);
	lim_msg->bodyptr = NULL;
	return;
}

/**
 * lim_trigger_sta_deletion() -
 *          This function is called to trigger STA context deletion.
 *
 * @param  mac_ctx   - Pointer to global MAC structure
 * @param  sta_ds - Pointer to internal STA Datastructure
 * @session_entry: PE session entry

 * @return None
 */
void
lim_trigger_sta_deletion(tpAniSirGlobal mac_ctx, tpDphHashNode sta_ds,
			 tpPESession session_entry)
{
	tLimMlmDisassocInd mlm_disassoc_ind;

	if (!sta_ds) {
		lim_log(mac_ctx, LOGW, FL("Skip STA deletion (invalid STA)"));
		return;
	}

	if ((sta_ds->mlmStaContext.mlmState == eLIM_MLM_WT_DEL_STA_RSP_STATE) ||
		(sta_ds->mlmStaContext.mlmState ==
			eLIM_MLM_WT_DEL_BSS_RSP_STATE) ||
		sta_ds->sta_deletion_in_progress) {
		/* Already in the process of deleting context for the peer */
		lim_log(mac_ctx, LOG1,
			FL("Deletion is in progress (%d) for peer:%p in mlmState %d"),
			sta_ds->sta_deletion_in_progress, sta_ds->staAddr,
			sta_ds->mlmStaContext.mlmState);
		return;
	}
	sta_ds->sta_deletion_in_progress = true;

	sta_ds->mlmStaContext.disassocReason =
		eSIR_MAC_DISASSOC_DUE_TO_INACTIVITY_REASON;
	sta_ds->mlmStaContext.cleanupTrigger = eLIM_LINK_MONITORING_DISASSOC;
	qdf_mem_copy(&mlm_disassoc_ind.peerMacAddr, sta_ds->staAddr,
		sizeof(tSirMacAddr));
	mlm_disassoc_ind.reasonCode =
		eSIR_MAC_DISASSOC_DUE_TO_INACTIVITY_REASON;
	mlm_disassoc_ind.disassocTrigger = eLIM_LINK_MONITORING_DISASSOC;

	/* Update PE session Id */
	mlm_disassoc_ind.sessionId = session_entry->peSessionId;
	lim_post_sme_message(mac_ctx, LIM_MLM_DISASSOC_IND,
			(uint32_t *) &mlm_disassoc_ind);
	if (mac_ctx->roam.configParam.enable_fatal_event)
		cds_flush_logs(WLAN_LOG_TYPE_FATAL,
				WLAN_LOG_INDICATOR_HOST_DRIVER,
				WLAN_LOG_REASON_HB_FAILURE,
				false, false);
	/* Issue Disassoc Indication to SME */
	lim_send_sme_disassoc_ind(mac_ctx, sta_ds, session_entry);
} /*** end lim_trigger_st_adeletion() ***/

/**
 * lim_tear_down_link_with_ap()
 *
 ***FUNCTION:
 * This function is called when heartbeat (beacon reception)
 * fails on STA
 *
 ***LOGIC:
 *
 ***ASSUMPTIONS:
 *
 ***NOTE:
 *
 * @param  pMac - Pointer to Global MAC structure
 * @return None
 */

void
lim_tear_down_link_with_ap(tpAniSirGlobal pMac, uint8_t sessionId,
			   tSirMacReasonCodes reasonCode)
{
	tpDphHashNode pStaDs = NULL;

	/* tear down the following sessionEntry */
	tpPESession psessionEntry;

	psessionEntry = pe_find_session_by_session_id(pMac, sessionId);
	if (psessionEntry == NULL) {
		lim_log(pMac, LOGP,
			FL("Session Does not exist for given sessionID"));
		return;
	}
	/**
	 * Heart beat failed for upto threshold value
	 * and AP did not respond for Probe request.
	 * Trigger link tear down.
	 */
	psessionEntry->pmmOffloadInfo.bcnmiss = false;

	lim_log(pMac, LOGW,
		FL("No ProbeRsp from AP after HB failure. Tearing down link"));

	/* Announce loss of link to Roaming algorithm */
	/* and cleanup by sending SME_DISASSOC_REQ to SME */

	pStaDs =
		dph_get_hash_entry(pMac, DPH_STA_HASH_INDEX_PEER,
				   &psessionEntry->dph.dphHashTable);

	if (pStaDs != NULL) {
		tLimMlmDeauthInd mlmDeauthInd;

#ifdef FEATURE_WLAN_TDLS
		/* Delete all TDLS peers connected before leaving BSS */
		lim_delete_tdls_peers(pMac, psessionEntry);
#endif

		pStaDs->mlmStaContext.disassocReason = reasonCode;
		pStaDs->mlmStaContext.cleanupTrigger =
			eLIM_LINK_MONITORING_DEAUTH;
		/* / Issue Deauth Indication to SME. */
		qdf_mem_copy((uint8_t *) &mlmDeauthInd.peerMacAddr,
			     pStaDs->staAddr, sizeof(tSirMacAddr));

	/*
	* if sendDeauthBeforeCon is enabled and reasoncode is
	* Beacon Missed Store the MAC of AP in the flip flop
	* buffer. This MAC will be used to send Deauth before
	* connection, if we connect to same AP after HB failure.
	*/
	if (pMac->roam.configParam.sendDeauthBeforeCon &&
		eSIR_BEACON_MISSED == reasonCode) {
		int apCount = pMac->lim.gLimHeartBeatApMacIndex;

		if (pMac->lim.gLimHeartBeatApMacIndex)
			pMac->lim.gLimHeartBeatApMacIndex = 0;
		else
			pMac->lim.gLimHeartBeatApMacIndex = 1;

		lim_log(pMac, LOGE, FL("HB Failure on MAC "
			MAC_ADDRESS_STR" Store it on Index %d"),
			MAC_ADDR_ARRAY(pStaDs->staAddr), apCount);

		sir_copy_mac_addr(pMac->lim.gLimHeartBeatApMac[apCount],
							pStaDs->staAddr);
	}

		mlmDeauthInd.reasonCode =
			(uint8_t) pStaDs->mlmStaContext.disassocReason;
		mlmDeauthInd.deauthTrigger =
			pStaDs->mlmStaContext.cleanupTrigger;

		if (LIM_IS_STA_ROLE(psessionEntry))
			lim_post_sme_message(pMac, LIM_MLM_DEAUTH_IND,
				     (uint32_t *) &mlmDeauthInd);
		if (pMac->roam.configParam.enable_fatal_event)
			cds_flush_logs(WLAN_LOG_TYPE_FATAL,
					WLAN_LOG_INDICATOR_HOST_DRIVER,
					WLAN_LOG_REASON_HB_FAILURE,
					false, false);

		lim_send_sme_deauth_ind(pMac, pStaDs, psessionEntry);
	}
} /*** lim_tear_down_link_with_ap() ***/

/**
 * lim_handle_heart_beat_failure() - handle hear beat failure in STA
 *
 * @mac_ctx: global MAC context
 * @session: PE session entry
 *
 * This function is called when heartbeat (beacon reception)
 * fails on STA
 *
 * Return: None
 */

void lim_handle_heart_beat_failure(tpAniSirGlobal mac_ctx,
				   tpPESession session)
{
	uint8_t curr_chan;
	tpSirAddie scan_ie = NULL;

#ifdef FEATURE_WLAN_DIAG_SUPPORT_LIM    /* FEATURE_WLAN_DIAG_SUPPORT */
	host_log_beacon_update_pkt_type *log_ptr = NULL;
#endif /* FEATURE_WLAN_DIAG_SUPPORT */

#ifdef FEATURE_WLAN_DIAG_SUPPORT_LIM    /* FEATURE_WLAN_DIAG_SUPPORT */
	WLAN_HOST_DIAG_LOG_ALLOC(log_ptr, host_log_beacon_update_pkt_type,
				 LOG_WLAN_BEACON_UPDATE_C);
	if (log_ptr)
		log_ptr->bcn_rx_cnt = session->LimRxedBeaconCntDuringHB;
	WLAN_HOST_DIAG_LOG_REPORT(log_ptr);
#endif /* FEATURE_WLAN_DIAG_SUPPORT */

	/* Ensure HB Status for the session has been reseted */
	session->LimHBFailureStatus = false;

	if (LIM_IS_STA_ROLE(session) &&
	    (session->limMlmState == eLIM_MLM_LINK_ESTABLISHED_STATE) &&
	    (session->limSmeState != eLIM_SME_WT_DISASSOC_STATE) &&
	    (session->limSmeState != eLIM_SME_WT_DEAUTH_STATE)) {
		if (!mac_ctx->sys.gSysEnableLinkMonitorMode)
			return;

		/* Ignore HB if channel switch is in progress */
		if (session->gLimSpecMgmt.dot11hChanSwState ==
		   eLIM_11H_CHANSW_RUNNING) {
			lim_log(mac_ctx, LOGE,
				FL("Ignore Heartbeat failure as Channel switch is in progress"));
			session->pmmOffloadInfo.bcnmiss = false;
			return;
		}
		/* Beacon frame not received within heartbeat timeout. */
		lim_log(mac_ctx, LOGW, FL("Heartbeat Failure"));
		mac_ctx->lim.gLimHBfailureCntInLinkEstState++;

		/*
		 * Check if connected on the DFS channel, if not connected on
		 * DFS channel then only send the probe request otherwise tear
		 * down the link
		 */
		curr_chan = session->currentOperChannel;
		if (!lim_isconnected_on_dfs_channel(curr_chan)) {
			/* Detected continuous Beacon Misses */
			session->LimHBFailureStatus = true;

			/*Reset the HB packet count before sending probe*/
			limResetHBPktCount(session);
			/**
			 * Send Probe Request frame to AP to see if
			 * it is still around. Wait until certain
			 * timeout for Probe Response from AP.
			 */
			lim_log(mac_ctx, LOGW,
				FL("HB missed from AP. Sending Probe Req"));
			/* for searching AP, we don't include any more IE */
			if (session->pLimJoinReq != NULL) {
				scan_ie = &session->pLimJoinReq->addIEScan;
				lim_send_probe_req_mgmt_frame(mac_ctx,
					&session->ssId,
					session->bssId, curr_chan,
					session->selfMacAddr,
					session->dot11mode,
					scan_ie->length, scan_ie->addIEdata);
			} else {
				lim_send_probe_req_mgmt_frame(mac_ctx,
					&session->ssId,
					session->bssId, curr_chan,
					session->selfMacAddr,
					session->dot11mode, 0, NULL);
			}
		} else {
			lim_log(mac_ctx, LOGW,
			    FL("HB missed from AP on DFS chanel moving to passive"));
			if (curr_chan < SIR_MAX_24G_5G_CHANNEL_RANGE) {
				lim_covert_channel_scan_type(mac_ctx, curr_chan,
					false);
				mac_ctx->lim.dfschannelList.
					timeStamp[curr_chan] = 0;
			}
			/*
			 * Connected on DFS channel so should not send the
			 * probe request tear down the link directly
			 */
			lim_tear_down_link_with_ap(mac_ctx,
				session->peSessionId,
				eSIR_BEACON_MISSED);
		}
	} else {
		/**
		 * Heartbeat timer may have timed out
		 * while we're doing background scanning/learning
		 * or in states other than link-established state.
		 * Log error.
		 */
		lim_log(mac_ctx, LOG1,
			FL("received heartbeat timeout in state %X"),
			session->limMlmState);
		lim_print_mlm_state(mac_ctx, LOG1, session->limMlmState);
		mac_ctx->lim.gLimHBfailureCntInOtherStates++;
	}
}
