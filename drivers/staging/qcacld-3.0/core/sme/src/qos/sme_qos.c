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

/**=========================================================================

   \file  sme_qos.c

   \brief implementation for SME QoS APIs

   ========================================================================*/
/* $Header$ */
/*--------------------------------------------------------------------------
   Include Files
   ------------------------------------------------------------------------*/

#include "ani_global.h"

#include "sme_inside.h"
#include "host_diag_core_event.h"
#include "host_diag_core_log.h"

#include "sms_debug.h"
#include "utils_parser.h"
#include "sme_power_save_api.h"

#ifndef WLAN_MDM_CODE_REDUCTION_OPT
/* TODO : 6Mbps as Cisco APs seem to like only this value; analysis req.   */
#define SME_QOS_MIN_PHY_RATE         0x5B8D80
#define SME_QOS_SURPLUS_BW_ALLOWANCE  0x2000    /* Ratio of 1.0           */
/*---------------------------------------------------------------------------
   Max values to bound tspec params against and avoid rollover
   ---------------------------------------------------------------------------*/
#define SME_QOS_32BIT_MAX  0xFFFFFFFF
#define SME_QOS_16BIT_MAX  0xFFFF
#define SME_QOS_16BIT_MSB  0x8000
/*---------------------------------------------------------------------------
   Adds y to x, but saturates at 32-bit max to avoid rollover
   ---------------------------------------------------------------------------*/
#define SME_QOS_BOUNDED_U32_ADD_Y_TO_X(_x, _y) \
	do { \
		(_x) = ((SME_QOS_32BIT_MAX - (_x)) < (_y)) ? \
		       (SME_QOS_32BIT_MAX) : (_x) + (_y); \
	} while (0)

/*---------------------------------------------------------------------------
   As per WMM spec there could be max 2 TSPEC running on the same AC with
   different direction. We will refer each TSPEC with an index
   ---------------------------------------------------------------------------*/
#define SME_QOS_TSPEC_INDEX_0            0
#define SME_QOS_TSPEC_INDEX_1            1
#define SME_QOS_TSPEC_INDEX_MAX          2
#define SME_QOS_TSPEC_MASK_BIT_1_SET     1
#define SME_QOS_TSPEC_MASK_BIT_2_SET     2
#define SME_QOS_TSPEC_MASK_BIT_1_2_SET   3
#define SME_QOS_TSPEC_MASK_CLEAR         0

/* which key to search on, in the flowlist (1 = flowID, 2 = AC, 4 = reason) */
#define SME_QOS_SEARCH_KEY_INDEX_1       1
#define SME_QOS_SEARCH_KEY_INDEX_2       2
#define SME_QOS_SEARCH_KEY_INDEX_3       4
#define SME_QOS_SEARCH_KEY_INDEX_4       8      /* ac + direction */
#define SME_QOS_SEARCH_KEY_INDEX_5       0x10   /* ac + tspec_mask */
/* special value for searching any Session Id */
#define SME_QOS_SEARCH_SESSION_ID_ANY    CSR_ROAM_SESSION_MAX
#define SME_QOS_ACCESS_POLICY_EDCA       1
#define SME_QOS_MAX_TID                  255
#define SME_QOS_TSPEC_IE_LENGTH          61
#define SME_QOS_TSPEC_IE_TYPE            2
#define SME_QOS_MIN_FLOW_ID              1
#define SME_QOS_MAX_FLOW_ID              0xFFFFFFFE
#define SME_QOS_INVALID_FLOW_ID          0xFFFFFFFF
/* per the WMM Specification v1.2 Section 2.2.10 */
/* The Dialog Token field shall be set [...] to a non-zero value */
#define SME_QOS_MIN_DIALOG_TOKEN         1
#define SME_QOS_MAX_DIALOG_TOKEN         0xFF
/*--------------------------------------------------------------------------
   Type declarations
   ------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------
   Enumeration of the various states in the QoS state m/c
   ---------------------------------------------------------------------------*/
typedef enum {
	SME_QOS_CLOSED = 0,
	SME_QOS_INIT,
	SME_QOS_LINK_UP,
	SME_QOS_REQUESTED,
	SME_QOS_QOS_ON,
	SME_QOS_HANDOFF,

} sme_QosStates;
/*---------------------------------------------------------------------------
   Enumeration of the various Release QoS trigger
   ---------------------------------------------------------------------------*/
typedef enum {
	SME_QOS_RELEASE_DEFAULT = 0,
	SME_QOS_RELEASE_BY_AP,
} sme_QosRelTriggers;
/*---------------------------------------------------------------------------
   Enumeration of the various QoS cmds
   ---------------------------------------------------------------------------*/
typedef enum {
	SME_QOS_SETUP_REQ = 0,
	SME_QOS_RELEASE_REQ,
	SME_QOS_MODIFY_REQ,
	SME_QOS_RESEND_REQ,
	SME_QOS_CMD_MAX
} sme_QosCmdType;
/*---------------------------------------------------------------------------
   Enumeration of the various QoS reason codes to be used in the Flow list
   ---------------------------------------------------------------------------*/
typedef enum {
	SME_QOS_REASON_SETUP = 0,
	SME_QOS_REASON_RELEASE,
	SME_QOS_REASON_MODIFY,
	SME_QOS_REASON_MODIFY_PENDING,
	SME_QOS_REASON_REQ_SUCCESS,
	SME_QOS_REASON_MAX
} sme_QosReasonType;

/*---------------------------------------------------------------------------
   Table to map user priority passed in as an argument to appropriate Access
   Category as specified in 802.11e/WMM
   ---------------------------------------------------------------------------*/
sme_QosEdcaAcType sme_qos_u_pto_ac_map[SME_QOS_WMM_UP_MAX] = {
	SME_QOS_EDCA_AC_BE,     /* User Priority 0 */
	SME_QOS_EDCA_AC_BK,     /* User Priority 1 */
	SME_QOS_EDCA_AC_BK,     /* User Priority 2 */
	SME_QOS_EDCA_AC_BE,     /* User Priority 3 */
	SME_QOS_EDCA_AC_VI,     /* User Priority 4 */
	SME_QOS_EDCA_AC_VI,     /* User Priority 5 */
	SME_QOS_EDCA_AC_VO,     /* User Priority 6 */
	SME_QOS_EDCA_AC_VO      /* User Priority 7 */
};

/*---------------------------------------------------------------------------
   Table to map access category (AC) to appropriate user priority as specified
   in 802.11e/WMM
   Note: there is a quantization loss here because 4 ACs are mapped to 8 UPs
   Mapping is done for consistency
   ---------------------------------------------------------------------------*/
sme_QosWmmUpType sme_qos_a_cto_up_map[SME_QOS_EDCA_AC_MAX] = {
	SME_QOS_WMM_UP_BE,      /* AC BE */
	SME_QOS_WMM_UP_BK,      /* AC BK */
	SME_QOS_WMM_UP_VI,      /* AC VI */
	SME_QOS_WMM_UP_VO       /* AC VO */
};

/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's FLOW Link List structure. This list can hold information per
   flow/request, like TSPEC params requested, which AC it is running on
   ---------------------------------------------------------------------------*/
typedef struct sme_QosFlowInfoEntry_s {
	tListElem link;         /* list links */
	uint8_t sessionId;
	uint8_t tspec_mask;
	sme_QosReasonType reason;
	uint32_t QosFlowID;
	sme_QosEdcaAcType ac_type;
	sme_QosWmmTspecInfo QoSInfo;
	void *HDDcontext;
	sme_QosCallback QoSCallback;
	bool hoRenewal;         /* set to true while re-negotiating flows after */
	/* handoff, will set to false once done with */
	/* the process. Helps SME to decide if at all */
	/* to notify HDD/LIS for flow renewal after HO */
} sme_QosFlowInfoEntry;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's setup request cmd related information structure.
   ---------------------------------------------------------------------------*/
typedef struct sme_qos_setupCmdInfo_s {
	uint32_t QosFlowID;
	sme_QosWmmTspecInfo QoSInfo;
	void *HDDcontext;
	sme_QosCallback QoSCallback;
	sme_QosWmmUpType UPType;
	bool hoRenewal;         /* set to true while re-negotiating flows after */
	/* handoff, will set to false once done with */
	/* the process. Helps SME to decide if at all */
	/* to notify HDD/LIS for flow renewal after HO */
} sme_qos_setupCmdInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's modify cmd related information structure.
   ---------------------------------------------------------------------------*/
typedef struct sme_QosModifyCmdInfo_s {
	uint32_t QosFlowID;
	sme_QosEdcaAcType ac;
	sme_QosWmmTspecInfo QoSInfo;
} sme_QosModifyCmdInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's resend cmd related information structure.
   ---------------------------------------------------------------------------*/
typedef struct sme_QosResendCmdInfo_s {
	uint8_t tspecMask;
	sme_QosEdcaAcType ac;
	sme_QosWmmTspecInfo QoSInfo;
} sme_QosResendCmdInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's release cmd related information structure.
   ---------------------------------------------------------------------------*/
typedef struct sme_QosReleaseCmdInfo_s {
	uint32_t QosFlowID;
} sme_QosReleaseCmdInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's buffered cmd related information structure.
   ---------------------------------------------------------------------------*/
typedef struct sme_QosCmdInfo_s {
	sme_QosCmdType command;
	tpAniSirGlobal pMac;
	uint8_t sessionId;
	union {
		sme_qos_setupCmdInfo setupCmdInfo;
		sme_QosModifyCmdInfo modifyCmdInfo;
		sme_QosResendCmdInfo resendCmdInfo;
		sme_QosReleaseCmdInfo releaseCmdInfo;
	} u;
} sme_QosCmdInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's buffered cmd List structure. This list can hold information
   related to any pending cmd from HDD
   ---------------------------------------------------------------------------*/
typedef struct sme_QosCmdInfoEntry_s {
	tListElem link;         /* list links */
	sme_QosCmdInfo cmdInfo;
} sme_QosCmdInfoEntry;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's Per AC information structure. This can hold information on
   how many flows running on the AC, the current, previous states the AC is in
   ---------------------------------------------------------------------------*/
typedef struct sme_QosACInfo_s {
	uint8_t num_flows[SME_QOS_TSPEC_INDEX_MAX];
	sme_QosStates curr_state;
	sme_QosStates prev_state;
	sme_QosWmmTspecInfo curr_QoSInfo[SME_QOS_TSPEC_INDEX_MAX];
	sme_QosWmmTspecInfo requested_QoSInfo[SME_QOS_TSPEC_INDEX_MAX];
	/* reassoc requested for APSD */
	bool reassoc_pending;
	/*
	 * As per WMM spec there could be max 2 TSPEC running on the same
	 * AC with different direction. We will refer each TSPEC with an index
	 */
	/* status showing if both the indices are in use */
	uint8_t tspec_mask_status;
	/* tspec negotiation going on for which index */
	uint8_t tspec_pending;
	/* set to true while re-negotiating flows after */
	bool hoRenewal;
	/*
	 * handoff, will set to false once done with the process. Helps SME to
	 * decide if at all to notify HDD/LIS for flow renewal after HO
	 */
	uint8_t ricIdentifier[SME_QOS_TSPEC_INDEX_MAX];
	/*
	 * stores the ADD TS response for each AC. The ADD TS response is
	 * formed by parsing the RIC received in the the reassoc response
	 */
	tSirAddtsRsp addTsRsp[SME_QOS_TSPEC_INDEX_MAX];
	sme_QosRelTriggers relTrig;

} sme_QosACInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's Per session information structure. This can hold information
   on the state of the session
   ---------------------------------------------------------------------------*/
typedef struct sme_QosSessionInfo_s {
	/* what is this entry's session id */
	uint8_t sessionId;
	/* is the session currently active */
	bool sessionActive;
	/* All AC info for this session */
	sme_QosACInfo ac_info[SME_QOS_EDCA_AC_MAX];
	/* Bitmask of the ACs with APSD on */
	/* Bit0:VO; Bit1:VI; Bit2:BK; Bit3:BE all other bits are ignored */
	uint8_t apsdMask;
	/* association information for this session */
	sme_QosAssocInfo assocInfo;
	/* ID assigned to our reassoc request */
	uint32_t roamID;
	/* maintaining a powersave status in QoS module, to be fed back to PMC at */
	/* times through the sme_qos_pmc_check_routine */
	bool readyForPowerSave;
	/* are we in the process of handing off to a different AP */
	bool handoffRequested;
	/* following reassoc or AddTS has UAPSD already been requested from PMC */
	bool uapsdAlreadyRequested;
	/* commands that are being buffered for this session */
	tDblLinkList bufferedCommandList;

	bool ftHandoffInProgress;

} sme_QosSessionInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   Search key union. We can use the flowID, ac type, or reason to find an entry
   in the flow list
   ---------------------------------------------------------------------------*/
typedef union sme_QosSearchKey_s {
	uint32_t QosFlowID;
	sme_QosEdcaAcType ac_type;
	sme_QosReasonType reason;
} sme_QosSearchKey;
/*---------------------------------------------------------------------------
   DESCRIPTION
   We can either use the flowID or the ac type to find an entry in the flow list.
   The index is a bitmap telling us which key to use. Starting from LSB,
   bit 0 - Flow ID
   bit 1 - AC type
   ---------------------------------------------------------------------------*/
typedef struct sme_QosSearchInfo_s {
	uint8_t sessionId;
	uint8_t index;
	sme_QosSearchKey key;
	sme_QosWmmDirType direction;
	uint8_t tspec_mask;
} sme_QosSearchInfo;
/*---------------------------------------------------------------------------
   DESCRIPTION
   SME QoS module's internal control block.
   ---------------------------------------------------------------------------*/
struct sme_qos_cb_s {
	/* global Mac pointer */
	tpAniSirGlobal pMac;
	/* All Session Info */
	sme_QosSessionInfo sessionInfo[CSR_ROAM_SESSION_MAX];
	/* All FLOW info */
	tDblLinkList flow_list;
	/* default TSPEC params */
	sme_QosWmmTspecInfo def_QoSInfo[SME_QOS_EDCA_AC_MAX];
	/* counter for assigning Flow IDs */
	uint32_t nextFlowId;
	/* counter for assigning Dialog Tokens */
	uint8_t nextDialogToken;
} sme_qos_cb;
typedef QDF_STATUS (*sme_QosProcessSearchEntry)(tpAniSirGlobal pMac,
						tListElem *pEntry);

sme_QosStatusType sme_qos_internal_setup_req(tpAniSirGlobal pMac,
					     uint8_t sessionId,
					     sme_QosWmmTspecInfo *pQoSInfo,
					     sme_QosCallback QoSCallback,
					     void *HDDcontext,
					     sme_QosWmmUpType UPType,
					     uint32_t QosFlowID,
					     bool buffered_cmd, bool hoRenewal);
sme_QosStatusType sme_qos_internal_modify_req(tpAniSirGlobal pMac,
					      sme_QosWmmTspecInfo *pQoSInfo,
					      uint32_t QosFlowID,
					      bool buffered_cmd);
sme_QosStatusType sme_qos_internal_release_req(tpAniSirGlobal pMac,
					       uint8_t session_id,
					       uint32_t QosFlowID,
					       bool buffered_cmd);
sme_QosStatusType sme_qos_setup(tpAniSirGlobal pMac,
				uint8_t sessionId,
				sme_QosWmmTspecInfo *pTspec_Info,
				sme_QosEdcaAcType ac);
QDF_STATUS sme_qos_add_ts_req(tpAniSirGlobal pMac,
			      uint8_t sessionId,
			      sme_QosWmmTspecInfo *pTspec_Info,
			      sme_QosEdcaAcType ac);
QDF_STATUS sme_qos_del_ts_req(tpAniSirGlobal pMac,
			      uint8_t sessionId,
			      sme_QosEdcaAcType ac, uint8_t tspec_mask);
QDF_STATUS sme_qos_process_add_ts_rsp(tpAniSirGlobal pMac, void *pMsgBuf);
QDF_STATUS sme_qos_process_del_ts_ind(tpAniSirGlobal pMac, void *pMsgBuf);
QDF_STATUS sme_qos_process_del_ts_rsp(tpAniSirGlobal pMac, void *pMsgBuf);
QDF_STATUS sme_qos_process_assoc_complete_ev(tpAniSirGlobal pMac, uint8_t sessionId,
					     void *pEvent_info);
QDF_STATUS sme_qos_process_reassoc_req_ev(tpAniSirGlobal pMac, uint8_t sessionId,
					  void *pEvent_info);
QDF_STATUS sme_qos_process_reassoc_success_ev(tpAniSirGlobal pMac,
					      uint8_t sessionId, void *pEvent_info);
QDF_STATUS sme_qos_process_reassoc_failure_ev(tpAniSirGlobal pMac,
					      uint8_t sessionId, void *pEvent_info);
QDF_STATUS sme_qos_process_disconnect_ev(tpAniSirGlobal pMac, uint8_t sessionId,
					 void *pEvent_info);
QDF_STATUS sme_qos_process_join_req_ev(tpAniSirGlobal pMac, uint8_t sessionId,
				       void *pEvent_info);
QDF_STATUS sme_qos_process_handoff_assoc_req_ev(tpAniSirGlobal pMac,
						uint8_t sessionId,
						void *pEvent_info);
QDF_STATUS sme_qos_process_handoff_success_ev(tpAniSirGlobal pMac,
					      uint8_t sessionId, void *pEvent_info);
QDF_STATUS sme_qos_process_handoff_failure_ev(tpAniSirGlobal pMac,
					      uint8_t sessionId, void *pEvent_info);
QDF_STATUS sme_qos_process_preauth_success_ind(tpAniSirGlobal pMac,
					       uint8_t sessionId,
					       void *pEvent_info);
QDF_STATUS sme_qos_process_set_key_success_ind(tpAniSirGlobal pMac,
					       uint8_t sessionId, void *pEvent_info);
QDF_STATUS sme_qos_process_aggr_qos_rsp(tpAniSirGlobal pMac, void *pMsgBuf);
QDF_STATUS sme_qos_ft_aggr_qos_req(tpAniSirGlobal pMac, uint8_t sessionId);
QDF_STATUS sme_qos_process_add_ts_success_rsp(tpAniSirGlobal pMac,
					      uint8_t sessionId,
					      tSirAddtsRspInfo *pRsp);
QDF_STATUS sme_qos_process_add_ts_failure_rsp(tpAniSirGlobal pMac,
					      uint8_t sessionId,
					      tSirAddtsRspInfo *pRsp);
QDF_STATUS sme_qos_aggregate_params(sme_QosWmmTspecInfo *pInput_Tspec_Info,
				    sme_QosWmmTspecInfo *pCurrent_Tspec_Info,
				    sme_QosWmmTspecInfo *pUpdated_Tspec_Info);
static QDF_STATUS sme_qos_update_params(uint8_t sessionId,
					sme_QosEdcaAcType ac,
					uint8_t tspec_mask,
					sme_QosWmmTspecInfo *pTspec_Info);
sme_QosWmmUpType sme_qos_ac_to_up(sme_QosEdcaAcType ac);
sme_QosEdcaAcType sme_qos_up_to_ac(sme_QosWmmUpType up);
bool sme_qos_is_acm(tpAniSirGlobal pMac, tSirBssDescription *pSirBssDesc,
		    sme_QosEdcaAcType ac, tDot11fBeaconIEs *pIes);
tListElem *sme_qos_find_in_flow_list(sme_QosSearchInfo search_key);
QDF_STATUS sme_qos_find_all_in_flow_list(tpAniSirGlobal pMac,
					 sme_QosSearchInfo search_key,
					 sme_QosProcessSearchEntry fnp);
static void sme_qos_state_transition(uint8_t sessionId,
				     sme_QosEdcaAcType ac,
				     sme_QosStates new_state);
QDF_STATUS sme_qos_buffer_cmd(sme_QosCmdInfo *pcmd, bool insert_head);
static QDF_STATUS sme_qos_process_buffered_cmd(uint8_t sessionId);
QDF_STATUS sme_qos_save_assoc_info(sme_QosSessionInfo *pSession,
				   sme_QosAssocInfo *pAssoc_info);
QDF_STATUS sme_qos_setup_fnp(tpAniSirGlobal pMac, tListElem *pEntry);
QDF_STATUS sme_qos_modification_notify_fnp(tpAniSirGlobal pMac,
					   tListElem *pEntry);
QDF_STATUS sme_qos_modify_fnp(tpAniSirGlobal pMac, tListElem *pEntry);
QDF_STATUS sme_qos_del_ts_ind_fnp(tpAniSirGlobal pMac, tListElem *pEntry);
QDF_STATUS sme_qos_reassoc_success_ev_fnp(tpAniSirGlobal pMac, tListElem *pEntry);
QDF_STATUS sme_qos_add_ts_failure_fnp(tpAniSirGlobal pMac, tListElem *pEntry);
QDF_STATUS sme_qos_add_ts_success_fnp(tpAniSirGlobal pMac, tListElem *pEntry);
static bool sme_qos_is_rsp_pending(uint8_t sessionId, sme_QosEdcaAcType ac);
static bool sme_qos_is_uapsd_active(void);

void sme_qos_pmc_offload_start_uapsd_callback(void *callbackContext,
					      uint32_t sessionId, QDF_STATUS status);
bool sme_qos_pmc_offload_check_routine(void *callbackContext, uint32_t sessionId);

static QDF_STATUS sme_qos_buffer_existing_flows(tpAniSirGlobal pMac,
						uint8_t sessionId);
static QDF_STATUS sme_qos_delete_existing_flows(tpAniSirGlobal pMac,
						uint8_t sessionId);
static void sme_qos_cleanup_ctrl_blk_for_handoff(tpAniSirGlobal pMac,
						 uint8_t sessionId);
static QDF_STATUS sme_qos_delete_buffered_requests(tpAniSirGlobal pMac,
						   uint8_t sessionId);
bool sme_qos_validate_requested_params(tpAniSirGlobal pMac,
				       sme_QosWmmTspecInfo *pQoSInfo,
				       uint8_t sessionId);

extern QDF_STATUS sme_acquire_global_lock(tSmeStruct *psSme);
extern QDF_STATUS sme_release_global_lock(tSmeStruct *psSme);
static QDF_STATUS qos_issue_command(tpAniSirGlobal pMac, uint8_t sessionId,
				    eSmeCommandType cmdType,
				    sme_QosWmmTspecInfo *pQoSInfo,
				    sme_QosEdcaAcType ac, uint8_t tspec_mask);
/*
    sme_qos_re_request_add_ts to re-send AddTS for the combined QoS request
 */
static sme_QosStatusType sme_qos_re_request_add_ts(tpAniSirGlobal pMac,
						   uint8_t sessionId,
						   sme_QosWmmTspecInfo *pQoSInfo,
						   sme_QosEdcaAcType ac,
						   uint8_t tspecMask);
static void sme_qos_init_a_cs(tpAniSirGlobal pMac, uint8_t sessionId);
static QDF_STATUS sme_qos_request_reassoc(tpAniSirGlobal pMac, uint8_t sessionId,
					  tCsrRoamModifyProfileFields *
					  pModFields, bool fForce);
static uint32_t sme_qos_assign_flow_id(void);
static uint8_t sme_qos_assign_dialog_token(void);
static QDF_STATUS sme_qos_update_tspec_mask(uint8_t sessionId,
					    sme_QosSearchInfo search_key,
					    uint8_t new_tspec_mask);

/* External APIs definitions */

/**
 * sme_qos_open() - called to initialize SME QoS module.
 * @pMac: global MAC context
 *
 * This function must be called before any API call to
 * SME QoS module.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_open(tpAniSirGlobal pMac)
{
	sme_QosSessionInfo *pSession;
	uint8_t sessionId;
	QDF_STATUS status;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: initializing SME-QoS module", __func__, __LINE__);
	/* init the control block */
	/* (note that this will make all sessions invalid) */
	qdf_mem_zero(&sme_qos_cb, sizeof(sme_qos_cb));
	sme_qos_cb.pMac = pMac;
	sme_qos_cb.nextFlowId = SME_QOS_MIN_FLOW_ID;
	sme_qos_cb.nextDialogToken = SME_QOS_MIN_DIALOG_TOKEN;
	/* init flow list */
	status = csr_ll_open(pMac->hHdd, &sme_qos_cb.flow_list);
	if (!QDF_IS_STATUS_SUCCESS(status)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_FATAL,
			  "%s: %d: cannot initialize Flow List",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}

	for (sessionId = 0; sessionId < CSR_ROAM_SESSION_MAX; ++sessionId) {
		pSession = &sme_qos_cb.sessionInfo[sessionId];
		pSession->sessionId = sessionId;
		/* initialize the session's per-AC information */
		sme_qos_init_a_cs(pMac, sessionId);
		/* initialize the session's buffered command list */
		status = csr_ll_open(pMac->hHdd, &pSession->bufferedCommandList);
		if (!QDF_IS_STATUS_SUCCESS(status)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_FATAL,
				  "%s: %d: cannot initialize cmd list for session %d",
				  __func__, __LINE__, sessionId);
			return QDF_STATUS_E_FAILURE;
		}
		pSession->readyForPowerSave = true;
	}

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: done initializing SME-QoS module",
		  __func__, __LINE__);
	return QDF_STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
    \brief sme_qos_close() - To close down SME QoS module. There should not be
    any API call into this module after calling this function until another
    call of sme_qos_open.
    \param pMac - Pointer to the global MAC parameter structure.

    \return QDF_STATUS
   ----------------------------------------------------------------------------*/
QDF_STATUS sme_qos_close(tpAniSirGlobal pMac)
{
	sme_QosSessionInfo *pSession;
	sme_QosEdcaAcType ac;
	uint8_t sessionId;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: closing down SME-QoS", __func__, __LINE__);

	/* cleanup control block */
	/* close the flow list */
	csr_ll_close(&sme_qos_cb.flow_list);
	/* shut down all of the sessions */
	for (sessionId = 0; sessionId < CSR_ROAM_SESSION_MAX; ++sessionId) {
		pSession = &sme_qos_cb.sessionInfo[sessionId];
		if (pSession == NULL)
			continue;

		sme_qos_init_a_cs(pMac, sessionId);
		/* this session doesn't require UAPSD */
		pSession->apsdMask = 0;

		pSession->uapsdAlreadyRequested = false;
		pSession->handoffRequested = false;
		pSession->readyForPowerSave = true;
		pSession->roamID = 0;
		/* need to clean up buffered req */
		sme_qos_delete_buffered_requests(pMac, sessionId);
		/* need to clean up flows */
		sme_qos_delete_existing_flows(pMac, sessionId);

		/* Clean up the assoc info if already allocated */
		if (pSession->assocInfo.pBssDesc) {
			qdf_mem_free(pSession->assocInfo.pBssDesc);
			pSession->assocInfo.pBssDesc = NULL;
		}
		/* close the session's buffered command list */
		csr_ll_close(&pSession->bufferedCommandList);
		for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
			sme_qos_state_transition(sessionId, ac, SME_QOS_CLOSED);
		}
		pSession->sessionActive = false;
		pSession->readyForPowerSave = true;
	}
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: closed down QoS", __func__, __LINE__);
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_setup_req() - The SME QoS API exposed to HDD to request for QoS
 *                       on a particular AC.
 * @hHal: The handle returned by mac_open.
 * @sessionId: sessionId returned by sme_open_session.
 * @pQoSInfo: Pointer to sme_QosWmmTspecInfo which contains the WMM TSPEC
 *            related info as defined above, provided by HDD
 * @QoSCallback: The callback which is registered per flow while
 *               requesting for QoS. Used for any notification for the
 *               flow (i.e. setup success/failure/release) which needs to
 *               be sent to HDD
 * @HDDcontext: A cookie passed by HDD to be used by SME during any QoS
 *              notification (through the callabck) to HDD
 * @UPType: Useful only if HDD or any other upper layer module (BAP etc.)
 *          looking for implicit QoS setup, in that
 *          case, the pQoSInfo will be NULL & SME will know about the AC
 *          (from the UP provided in this param) QoS is requested on
 * @pQosFlowID: Identification per flow running on each AC generated by
 *              SME. It is only meaningful if the QoS setup for the flow is
 *              successful
 * This function should be called after a link has been
 * established, i.e. STA is associated with an AP etc. If the request involves
 * admission control on the requested AC, HDD needs to provide the necessary
 * Traffic Specification (TSPEC) parameters otherwise SME is going to use the
 * default params.
 * Return: QDF_STATUS_SUCCESS - Setup is successful.
 *          Other status means Setup request failed
 */
sme_QosStatusType sme_qos_setup_req(tHalHandle hHal, uint32_t sessionId,
				    sme_QosWmmTspecInfo *pQoSInfo,
				    sme_QosCallback QoSCallback,
				    void *HDDcontext,
				    sme_QosWmmUpType UPType,
				    uint32_t *pQosFlowID)
{
	sme_QosSessionInfo *pSession;
	QDF_STATUS lock_status = QDF_STATUS_E_FAILURE;
	tpAniSirGlobal pMac = PMAC_STRUCT(hHal);
	sme_QosStatusType status;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: QoS Setup requested by client on session %d",
		  __func__, __LINE__, sessionId);
	lock_status = sme_acquire_global_lock(&pMac->sme);
	if (!QDF_IS_STATUS_SUCCESS(lock_status)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Unable to obtain lock", __func__, __LINE__);
		return SME_QOS_STATUS_SETUP_FAILURE_RSP;
	}
	/* Make sure the session is valid */
	if (!CSR_IS_SESSION_VALID(pMac, sessionId)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Supplied Session ID %d is invalid",
			  __func__, __LINE__, sessionId);
		status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
	} else {
		/* Make sure the session is active */
		pSession = &sme_qos_cb.sessionInfo[sessionId];
		if (!pSession->sessionActive) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: Supplied Session ID %d is inactive",
				  __func__, __LINE__, sessionId);
			status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
		} else {
			/* Assign a Flow ID */
			*pQosFlowID = sme_qos_assign_flow_id();
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: QoS request on session %d assigned Flow ID %d",
				  __func__, __LINE__, sessionId, *pQosFlowID);
			/* Call the internal function for QoS setup, */
			/* adding a layer of abstraction */
			status =
				sme_qos_internal_setup_req(pMac, (uint8_t) sessionId,
							   pQoSInfo, QoSCallback,
							   HDDcontext, UPType,
							   *pQosFlowID, false,
							   false);
		}
	}
	sme_release_global_lock(&pMac->sme);
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: QoS setup return status on session %d is %d",
		  __func__, __LINE__, sessionId, status);
	return status;
}

/**
 * sme_qos_modify_req() - The SME QoS API exposed to HDD to request for
 *  modification of certain QoS params on a flow running on a particular AC.
 * @hHal: The handle returned by mac_open.
 * @pQoSInfo: Pointer to sme_QosWmmTspecInfo which contains the WMM TSPEC
 *            related info as defined above, provided by HDD
 * @QosFlowID: Identification per flow running on each AC generated by
 *             SME. It is only meaningful if the QoS setup for the flow has
 *             been successful already
 *
 * This function should be called after a link has been established,
 * i.e. STA is associated with an AP etc. & a QoS setup has been succesful for
 * that flow. If the request involves admission control on the requested AC,
 * HDD needs to provide the necessary Traffic Specification (TSPEC) parameters &
 * SME might start the renegotiation process through ADDTS.
 *
 * Return: SME_QOS_STATUS_SETUP_SUCCESS_RSP - Modification is successful.
 *         Other status means request failed
 */
sme_QosStatusType sme_qos_modify_req(tHalHandle hHal,
				     sme_QosWmmTspecInfo *pQoSInfo,
				     uint32_t QosFlowID)
{
	QDF_STATUS lock_status = QDF_STATUS_E_FAILURE;
	tpAniSirGlobal pMac = PMAC_STRUCT(hHal);
	sme_QosStatusType status;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: QoS Modify requested by client for Flow %d",
		  __func__, __LINE__, QosFlowID);
	lock_status = sme_acquire_global_lock(&pMac->sme);
	if (!QDF_IS_STATUS_SUCCESS(lock_status)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Unable to obtain lock", __func__, __LINE__);
		return SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
	}
	/* Call the internal function for QoS modify, adding a layer of abstraction */
	status = sme_qos_internal_modify_req(pMac, pQoSInfo, QosFlowID, false);
	sme_release_global_lock(&pMac->sme);
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: QoS Modify return status on Flow %d is %d",
		  __func__, __LINE__, QosFlowID, status);
	return status;
}

/**
 * sme_qos_release_req() - The SME QoS API exposed to HDD to request for
 *                         releasing a QoS flow running on a particular AC.
 *
 * @hHal: The handle returned by mac_open.
 * @session_id: session_id returned by sme_open_session.
 * @QosFlowID: Identification per flow running on each AC generated by SME
 *             It is only meaningful if the QoS setup for the flow is successful
 *
 * This function should be called only if a QoS is set up with a valid FlowID.
 * HDD sould invoke this API only if an explicit request for QoS release has
 * come from Application
 *
 * Return: QDF_STATUS_SUCCESS - Release is successful.
 */
sme_QosStatusType sme_qos_release_req(tHalHandle hHal, uint8_t session_id,
				      uint32_t QosFlowID)
{
	QDF_STATUS lock_status = QDF_STATUS_E_FAILURE;
	tpAniSirGlobal pMac = PMAC_STRUCT(hHal);
	sme_QosStatusType status;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: QoS Release requested by client for Flow %d",
		  __func__, __LINE__, QosFlowID);
	lock_status = sme_acquire_global_lock(&pMac->sme);
	if (!QDF_IS_STATUS_SUCCESS(lock_status)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Unable to obtain lock", __func__, __LINE__);
		return SME_QOS_STATUS_RELEASE_FAILURE_RSP;
	}
	/* Call the internal function for QoS release, adding a layer of abstraction */
	status = sme_qos_internal_release_req(pMac, session_id, QosFlowID,
					      false);
	sme_release_global_lock(&pMac->sme);
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: QoS Release return status on Flow %d is %d",
		  __func__, __LINE__, QosFlowID, status);
	return status;
}

void qos_release_command(tpAniSirGlobal pMac, tSmeCmd *pCommand)
{
	qdf_mem_zero(&pCommand->u.qosCmd, sizeof(tGenericQosCmd));
	sme_release_command(pMac, pCommand);
}

/**
 * sme_qos_msg_processor() - Processes QOS messages
 * @mac_ctx: Pointer to the global MAC parameter structure.
 * @msg_type: the type of msg passed by PE as defined in wni_api.h
 * @msg: a pointer to a buffer that maps to various structures bases.
 *
 * sme_process_msg() calls this function for the messages that
 * are handled by SME QoS module.
 *
 * Return: QDF_STATUS enumeration.
 */
QDF_STATUS sme_qos_msg_processor(tpAniSirGlobal mac_ctx,
	uint16_t msg_type, void *msg)
{
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	tListElem *entry = NULL;
	tSmeCmd *command;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		FL(" msg = %d for QoS"), msg_type);
	/* switch on the msg type & make the state transition accordingly */
	switch (msg_type) {
	case eWNI_SME_ADDTS_RSP:
		entry = csr_ll_peek_head(&mac_ctx->sme.smeCmdActiveList,
				LL_ACCESS_LOCK);
		if (NULL == entry)
			break;
		command = GET_BASE_ADDR(entry, tSmeCmd, Link);
		if (eSmeCommandAddTs == command->command) {
			status = sme_qos_process_add_ts_rsp(mac_ctx, msg);
			if (csr_ll_remove_entry
				(&mac_ctx->sme.smeCmdActiveList, entry,
				LL_ACCESS_LOCK)) {
				qos_release_command(mac_ctx, command);
			}
			sme_process_pending_queue(mac_ctx);
		}
		break;
	case eWNI_SME_DELTS_RSP:
		entry =
			csr_ll_peek_head(&mac_ctx->sme.smeCmdActiveList,
				LL_ACCESS_LOCK);
		if (NULL == entry)
			break;
		command = GET_BASE_ADDR(entry, tSmeCmd, Link);
		if (eSmeCommandDelTs == command->command) {
			status = sme_qos_process_del_ts_rsp(mac_ctx, msg);
			if (csr_ll_remove_entry
				(&mac_ctx->sme.smeCmdActiveList, entry,
				LL_ACCESS_LOCK)) {
				qos_release_command(mac_ctx, command);
			}
			sme_process_pending_queue(mac_ctx);
		}
		break;
	case eWNI_SME_DELTS_IND:
		status = sme_qos_process_del_ts_ind(mac_ctx, msg);
		break;
	case eWNI_SME_FT_AGGR_QOS_RSP:
		status = sme_qos_process_aggr_qos_rsp(mac_ctx, msg);
		break;
	default:
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			FL("unknown msg type = %d"),
			msg_type);
		break;
	}
	return status;
}

/**
 * sme_qos_validate_params() - validate SME QOS parameters.
 * @pMac: Pointer to the global MAC parameter structure.
 * @pBssDesc: Pointer to the BSS Descriptor information passed down by
 *            CSR to PE while issuing the Join request
 *
 * The SME QoS API exposed to CSR to validate AP
 * capabilities regarding QoS support & any other QoS parameter validation.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_validate_params(tpAniSirGlobal pMac,
				   tSirBssDescription *pBssDesc)
{
	tDot11fBeaconIEs *pIes = NULL;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: validation for QAP & APSD", __func__, __LINE__);
	do {
		if (!QDF_IS_STATUS_SUCCESS(
			csr_get_parsed_bss_description_ies(
				pMac, pBssDesc,	&pIes))) {
			/* err msg */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: csr_get_parsed_bss_description_ies() failed",
				  __func__, __LINE__);
			break;
		}
		/* check if the AP is QAP & it supports APSD */
		if (!CSR_IS_QOS_BSS(pIes)) {
			/* err msg */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: AP doesn't support QoS",
				  __func__, __LINE__);

			break;
		}
		if (!(pIes->WMMParams.qosInfo & SME_QOS_AP_SUPPORTS_APSD) &&
		    !(pIes->WMMInfoAp.uapsd)) {
			/* err msg */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: AP doesn't support APSD",
				  __func__, __LINE__);
			break;
		}
		status = QDF_STATUS_SUCCESS;
	} while (0);
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: validated with status = %d",
		  __func__, __LINE__, status);
	if (pIes) {
		qdf_mem_free(pIes);
	}
	return status;
}

void sme_qos_remove_addts_delts_cmd(tpAniSirGlobal mac_ctx, uint8_t session_id)
{
	tListElem *entry;
	tSmeCmd *command;

	entry = csr_ll_peek_head(&mac_ctx->sme.smeCmdActiveList,
				 LL_ACCESS_LOCK);
	if (NULL == entry)
		return;
	command = GET_BASE_ADDR(entry, tSmeCmd, Link);
	if ((eSmeCommandAddTs   == command->command ||
	    eSmeCommandDelTs == command->command) &&
	    command->sessionId == session_id) {
		if (csr_ll_remove_entry(&mac_ctx->sme.smeCmdActiveList, entry,
		    LL_ACCESS_LOCK)) {
		    QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
			      "%s: removed addts/delts command", __func__);
			qos_release_command(mac_ctx, command);
		}
	}
}

/*--------------------------------------------------------------------------
   \brief sme_qos_csr_event_ind() - The QoS sub-module in SME expects notifications
   from CSR when certain events occur as mentioned in sme_qos_csr_event_indType.
   \param pMac - Pointer to the global MAC parameter structure.
   \param ind - The event occurred of type sme_qos_csr_event_indType.
   \param pEvent_info - Information related to the event

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_csr_event_ind(tpAniSirGlobal pMac,
				 uint8_t sessionId,
				 sme_qos_csr_event_indType ind, void *pEvent_info)
{
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: On Session %d Event %d received from CSR",
		  __func__, __LINE__, sessionId, ind);
	switch (ind) {
	case SME_QOS_CSR_ASSOC_COMPLETE:
		/* expecting assoc info in pEvent_info */
		status =
			sme_qos_process_assoc_complete_ev(pMac, sessionId, pEvent_info);
		break;
	case SME_QOS_CSR_REASSOC_REQ:
		/* nothing expected in pEvent_info */
		status =
			sme_qos_process_reassoc_req_ev(pMac, sessionId, pEvent_info);
		break;
	case SME_QOS_CSR_REASSOC_COMPLETE:
		/* expecting assoc info in pEvent_info */
		status =
			sme_qos_process_reassoc_success_ev(pMac, sessionId,
							   pEvent_info);
		break;
	case SME_QOS_CSR_REASSOC_FAILURE:
		/* nothing expected in pEvent_info */
		status =
			sme_qos_process_reassoc_failure_ev(pMac, sessionId,
							   pEvent_info);
		break;
	case SME_QOS_CSR_DISCONNECT_REQ:
	case SME_QOS_CSR_DISCONNECT_IND:
		/* nothing expected in pEvent_info */
		status =
			sme_qos_process_disconnect_ev(pMac, sessionId, pEvent_info);
		break;
	case SME_QOS_CSR_JOIN_REQ:
		/* nothing expected in pEvent_info */
		status = sme_qos_process_join_req_ev(pMac, sessionId, pEvent_info);
		break;
	case SME_QOS_CSR_HANDOFF_ASSOC_REQ:
		/* nothing expected in pEvent_info */
		status =
			sme_qos_process_handoff_assoc_req_ev(pMac, sessionId,
							     pEvent_info);
		break;
	case SME_QOS_CSR_HANDOFF_COMPLETE:
		/* nothing expected in pEvent_info */
		status =
			sme_qos_process_handoff_success_ev(pMac, sessionId,
							   pEvent_info);
		break;
	case SME_QOS_CSR_HANDOFF_FAILURE:
		/* nothing expected in pEvent_info */
		status =
			sme_qos_process_handoff_failure_ev(pMac, sessionId,
							   pEvent_info);
		break;
	case SME_QOS_CSR_PREAUTH_SUCCESS_IND:
		status =
			sme_qos_process_preauth_success_ind(pMac, sessionId,
							    pEvent_info);
		break;
	case SME_QOS_CSR_SET_KEY_SUCCESS_IND:
		status =
			sme_qos_process_set_key_success_ind(pMac, sessionId,
							    pEvent_info);
		break;
	default:
		/* Err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On Session %d Unknown Event %d received from CSR",
			  __func__, __LINE__, sessionId, ind);
		break;
	}
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: On Session %d processed Event %d with status %d",
		  __func__, __LINE__, sessionId, ind, status);
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_get_acm_mask() - The QoS sub-module API to find out on which ACs
   AP mandates Admission Control (ACM = 1)
   (Bit0:VO; Bit1:VI; Bit2:BK; Bit3:BE all other bits are ignored)
   \param pMac - Pointer to the global MAC parameter structure.
   \param pSirBssDesc - The event occurred of type sme_qos_csr_event_indType.

   \return a bit mask indicating for which ACs AP has ACM set to 1

   \sa

   --------------------------------------------------------------------------*/
uint8_t sme_qos_get_acm_mask(tpAniSirGlobal pMac, tSirBssDescription *pSirBssDesc,
			     tDot11fBeaconIEs *pIes)
{
	sme_QosEdcaAcType ac;
	uint8_t acm_mask = 0;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked", __func__, __LINE__);
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		if (sme_qos_is_acm(pMac, pSirBssDesc, ac, pIes)) {
			acm_mask = acm_mask | (1 << (SME_QOS_EDCA_AC_VO - ac));
		}

	}
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: mask is %d", __func__, __LINE__, acm_mask);
	return acm_mask;
}

/* Internal function definitions */

/**
 *  sme_qos_internal_setup_req() - The SME QoS internal setup request handling
 *                                 function.
 *
 *  @pMac: Pointer to the global MAC parameter structure.
 *  @pQoSInfo: Pointer to sme_QosWmmTspecInfo which contains the WMM TSPEC
 *             related info as defined above, provided by HDD
 *  @QoSCallback: The callback which is registered per flow while
 *                requesting for QoS. Used for any notification for the
 *                flow (i.e. setup success/failure/release) which needs to
 *                be sent to HDD
 *  @HDDcontext: A cookie passed by HDD to be used by SME during any QoS
 *               notification (through the callabck) to HDD
 *  @UPType: Useful only if HDD or any other upper layer module (BAP etc.)
 *           looking for implicit QoS setup, in that
 *           case, the pQoSInfo will be NULL & SME will know about the AC
 *           (from the UP provided in this param) QoS is requested on
 *  @QosFlowID: Identification per flow running on each AC generated by
 *              SME. It is only meaningful if the QoS setup for the flow is
 *              successful
 *  @buffered_cmd: tells us if the cmd was a buffered one or fresh from
 *                 client
 *
 *  If the request involves admission control on the requested AC, HDD needs to
 *  provide the necessary Traffic Specification (TSPEC) parameters otherwise SME
 *  is going to use the default params.
 *
 *  Return: QDF_STATUS_SUCCESS - Setup is successful.
 *          Other status means Setup request failed
 */
sme_QosStatusType sme_qos_internal_setup_req(tpAniSirGlobal pMac,
					     uint8_t sessionId,
					     sme_QosWmmTspecInfo *pQoSInfo,
					     sme_QosCallback QoSCallback,
					     void *HDDcontext,
					     sme_QosWmmUpType UPType,
					     uint32_t QosFlowID,
					     bool buffered_cmd, bool hoRenewal)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType ac;
	sme_QosWmmTspecInfo Tspec_Info;
	sme_QosStates new_state = SME_QOS_CLOSED;
	sme_QosFlowInfoEntry *pentry = NULL;
	sme_QosCmdInfo cmd;
	sme_QosStatusType status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
	uint8_t tmask = 0;
	uint8_t new_tmask = 0;
	sme_QosSearchInfo search_key;
	QDF_STATUS hstatus;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d for flow %d",
		  __func__, __LINE__, sessionId, QosFlowID);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	/* if caller sent an empty TSPEC, fill up with the default one */
	if (!pQoSInfo) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
			  "%s: %d: caller sent an empty QoS param list, using defaults",
			  __func__, __LINE__);
		/* find the AC with UPType passed in */
		ac = sme_qos_up_to_ac(UPType);
		if (SME_QOS_EDCA_AC_MAX == ac) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: invalid AC %d from UP %d",
				  __func__, __LINE__, ac, UPType);

			return SME_QOS_STATUS_SETUP_INVALID_PARAMS_RSP;
		}
		Tspec_Info = sme_qos_cb.def_QoSInfo[ac];
	} else {
		/* find the AC */
		ac = sme_qos_up_to_ac(pQoSInfo->ts_info.up);
		if (SME_QOS_EDCA_AC_MAX == ac) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: invalid AC %d from UP %d",
				  __func__, __LINE__, ac, pQoSInfo->ts_info.up);

			return SME_QOS_STATUS_SETUP_INVALID_PARAMS_RSP;
		}
		/* validate QoS params */
		if (!sme_qos_validate_requested_params(pMac, pQoSInfo, sessionId)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: invalid params", __func__, __LINE__);
			return SME_QOS_STATUS_SETUP_INVALID_PARAMS_RSP;
		}
		Tspec_Info = *pQoSInfo;
	}
	pACInfo = &pSession->ac_info[ac];
	/* need to vote off powersave for the duration of this request */
	pSession->readyForPowerSave = false;
	/* check to consider the following flowing scenario.
	 * Addts request is pending on one AC, while APSD requested on another
	 * which needs a reassoc. Will buffer a request if Addts is pending
	 * on any AC, which will safegaurd the above scenario, & also won't
	 * confuse PE with back to back Addts or Addts followed by Reassoc
	 */
	if (sme_qos_is_rsp_pending(sessionId, ac)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
			  "%s: %d: buffering the setup request for flow %d in state %d "
			  "since another request is pending",
			  __func__, __LINE__, QosFlowID, pACInfo->curr_state);
		/* we need to buffer the command */
		cmd.command = SME_QOS_SETUP_REQ;
		cmd.pMac = pMac;
		cmd.sessionId = sessionId;
		cmd.u.setupCmdInfo.HDDcontext = HDDcontext;
		cmd.u.setupCmdInfo.QoSInfo = Tspec_Info;
		cmd.u.setupCmdInfo.QoSCallback = QoSCallback;
		cmd.u.setupCmdInfo.UPType = UPType;
		cmd.u.setupCmdInfo.hoRenewal = hoRenewal;
		cmd.u.setupCmdInfo.QosFlowID = QosFlowID;
		hstatus = sme_qos_buffer_cmd(&cmd, buffered_cmd);
		if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: couldn't buffer the setup request in state = %d",
				  __func__, __LINE__, pACInfo->curr_state);
			/* unable to buffer the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return SME_QOS_STATUS_SETUP_FAILURE_RSP;
		}
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Buffered setup request for flow = %d",
			  __func__, __LINE__, QosFlowID);
		return SME_QOS_STATUS_SETUP_REQ_PENDING_RSP;
	}
	/* get into the state m/c to see if the request can be granted */
	switch (pACInfo->curr_state) {
	case SME_QOS_LINK_UP:
		/* call the internal qos setup logic to decide on if the */
		/* request is NOP, or need reassoc for APSD and/or need to send out ADDTS */
		status = sme_qos_setup(pMac, sessionId, &Tspec_Info, ac);
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: On session %d with AC %d in state SME_QOS_LINK_UP "
			  "sme_qos_setup returned with status %d",
			  __func__, __LINE__, sessionId, ac, status);
		if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP != status) {
			/* we aren't waiting for a response from the AP */
			/* so vote powersave back on */
			pSession->readyForPowerSave = true;
		}
		if ((SME_QOS_STATUS_SETUP_REQ_PENDING_RSP == status) ||
		    (SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP == status)
		    || (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY ==
			status)) {
			/* we received an expected "good" status */
			/* create an entry in the flow list */
			pentry = qdf_mem_malloc(sizeof(*pentry));
			if (!pentry) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: couldn't allocate memory for the new "
					  "entry in the Flow List", __func__,
					  __LINE__);
				return SME_QOS_STATUS_SETUP_FAILURE_RSP;
			}
			pentry->ac_type = ac;
			pentry->HDDcontext = HDDcontext;
			pentry->QoSCallback = QoSCallback;
			pentry->hoRenewal = hoRenewal;
			pentry->QosFlowID = QosFlowID;
			pentry->sessionId = sessionId;
			/* since we are in state SME_QOS_LINK_UP this must be the */
			/* first TSPEC on this AC, so use index 0 (mask bit 1) */
			pACInfo->requested_QoSInfo[SME_QOS_TSPEC_INDEX_0] =
				Tspec_Info;
			if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP == status) {
				if (pACInfo->tspec_mask_status &&
				    !pACInfo->reassoc_pending) {
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: %d: On session %d with AC %d in state "
						  "SME_QOS_LINK_UP tspec_mask_status is %d "
						  "but should not be set yet",
						  __func__, __LINE__, sessionId,
						  ac,
						  pACInfo->tspec_mask_status);
					QDF_ASSERT(0);
					qdf_mem_free(pentry);
					return SME_QOS_STATUS_SETUP_FAILURE_RSP;
				}
				pACInfo->tspec_mask_status =
					SME_QOS_TSPEC_MASK_BIT_1_SET;
				if (!pACInfo->reassoc_pending) {
					/* we didn't request for reassoc, it must be a tspec negotiation */
					pACInfo->tspec_pending = 1;
				}

				pentry->reason = SME_QOS_REASON_SETUP;
				new_state = SME_QOS_REQUESTED;
			} else {
				/* SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP or */
				/* SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY */
				pentry->reason = SME_QOS_REASON_REQ_SUCCESS;
				new_state = SME_QOS_QOS_ON;
				pACInfo->tspec_mask_status =
					SME_QOS_TSPEC_MASK_BIT_1_SET;
				pACInfo->curr_QoSInfo[SME_QOS_TSPEC_INDEX_0] =
					Tspec_Info;
				if (buffered_cmd && !pentry->hoRenewal) {
					QoSCallback(pMac, HDDcontext,
						    &pACInfo->
						    curr_QoSInfo
						    [SME_QOS_TSPEC_INDEX_0],
						    status, pentry->QosFlowID);
				}
				pentry->hoRenewal = false;
			}
			pACInfo->num_flows[SME_QOS_TSPEC_INDEX_0]++;

			/* indicate on which index the flow entry belongs to & add it to the */
			/* Flow List at the end */
			pentry->tspec_mask = pACInfo->tspec_mask_status;
			pentry->QoSInfo = Tspec_Info;
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: Creating entry on session %d at %p with flowID %d",
				  __func__, __LINE__,
				  sessionId, pentry, QosFlowID);
			csr_ll_insert_tail(&sme_qos_cb.flow_list, &pentry->link,
					   true);
		} else {
			/* unexpected status returned by sme_qos_setup() */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d unexpected status %d "
				  "returned by sme_qos_setup",
				  __func__, __LINE__, sessionId, status);
			new_state = pACInfo->curr_state;
			if (buffered_cmd && hoRenewal) {
				QoSCallback(pMac, HDDcontext,
					    &pACInfo->
					    curr_QoSInfo[SME_QOS_TSPEC_INDEX_0],
					    SME_QOS_STATUS_RELEASE_QOS_LOST_IND,
					    QosFlowID);
			}
		}
		break;
	case SME_QOS_HANDOFF:
	case SME_QOS_REQUESTED:
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
			  "%s: %d: Buffering setup request for flow %d in state = %d",
			  __func__, __LINE__, QosFlowID, pACInfo->curr_state);
		/* buffer cmd */
		cmd.command = SME_QOS_SETUP_REQ;
		cmd.pMac = pMac;
		cmd.sessionId = sessionId;
		cmd.u.setupCmdInfo.HDDcontext = HDDcontext;
		cmd.u.setupCmdInfo.QoSInfo = Tspec_Info;
		cmd.u.setupCmdInfo.QoSCallback = QoSCallback;
		cmd.u.setupCmdInfo.UPType = UPType;
		cmd.u.setupCmdInfo.hoRenewal = hoRenewal;
		cmd.u.setupCmdInfo.QosFlowID = QosFlowID;
		hstatus = sme_qos_buffer_cmd(&cmd, buffered_cmd);
		if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d couldn't buffer the setup "
				  "request for flow %d in state = %d",
				  __func__, __LINE__,
				  sessionId, QosFlowID, pACInfo->curr_state);
			/* unable to buffer the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return SME_QOS_STATUS_SETUP_FAILURE_RSP;
		}
		status = SME_QOS_STATUS_SETUP_REQ_PENDING_RSP;
		new_state = pACInfo->curr_state;
		break;
	case SME_QOS_QOS_ON:

		/* check if multiple flows running on the ac */
		if ((pACInfo->num_flows[SME_QOS_TSPEC_INDEX_0] > 0) ||
		    (pACInfo->num_flows[SME_QOS_TSPEC_INDEX_1] > 0)) {
			/* do we need to care about the case where APSD needed on ACM = 0 below? */
			if (CSR_IS_ADDTS_WHEN_ACMOFF_SUPPORTED(pMac) ||
			    sme_qos_is_acm(pMac, pSession->assocInfo.pBssDesc, ac,
					   NULL)) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_MED,
					  "%s: %d: tspec_mask_status = %d for AC = %d",
					  __func__, __LINE__,
					  pACInfo->tspec_mask_status, ac);
				if (!pACInfo->tspec_mask_status) {
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: %d: tspec_mask_status can't be 0 for ac = %d in "
						  "state = %d", __func__,
						  __LINE__, ac,
						  pACInfo->curr_state);
					QDF_ASSERT(0);
					/* unable to service the request */
					/* nothing is pending so vote powersave back on */
					pSession->readyForPowerSave = true;
					return status;
				}
				/* Flow aggregation */
				if (((pACInfo->tspec_mask_status > 0) &&
				     (pACInfo->tspec_mask_status <=
				      SME_QOS_TSPEC_INDEX_MAX))) {
					/* Either of upstream, downstream or bidirectional flows are present */
					/* If either of new stream or current stream is for bidirecional, aggregate
					 * the new stream with the current streams present and send out aggregated Tspec.*/
					if ((Tspec_Info.ts_info.direction ==
					     SME_QOS_WMM_TS_DIR_BOTH)
					    || (pACInfo->
						curr_QoSInfo[pACInfo->
							     tspec_mask_status -
							     1].ts_info.
						direction ==
						SME_QOS_WMM_TS_DIR_BOTH)) {
						/* Aggregate the new stream with the current stream(s). */
						tmask =
							pACInfo->tspec_mask_status;
					}
					/* None of new stream or current (aggregated) streams are for bidirectional.
					* Check if the new stream direction matches the current stream direction. */
					else if (pACInfo->
						 curr_QoSInfo[pACInfo->
							      tspec_mask_status
							      -
							      1].ts_info.
						 direction ==
						 Tspec_Info.ts_info.direction) {
						/* Aggregate the new stream with the current stream(s). */
						tmask =
							pACInfo->tspec_mask_status;
					}
					/* New stream is in different direction. */
					else {
						/* No Aggregation. Mark the 2nd tpsec index also as active. */
						tmask =
							SME_QOS_TSPEC_MASK_CLEAR;
						new_tmask =
							SME_QOS_TSPEC_MASK_BIT_1_2_SET
							& ~pACInfo->
							tspec_mask_status;
						pACInfo->tspec_mask_status =
							SME_QOS_TSPEC_MASK_BIT_1_2_SET;
					}
				} else if (SME_QOS_TSPEC_MASK_BIT_1_2_SET ==
					   pACInfo->tspec_mask_status) {
					/* Both uplink and downlink streams are present. */
					/* If new stream is bidirectional, aggregate new stream with all existing
					 * upstreams and downstreams. Send out new aggregated tpsec. */
					if (Tspec_Info.ts_info.direction ==
					    SME_QOS_WMM_TS_DIR_BOTH) {
						/* Only one tspec index (0) will be in use after this aggregation. */
						tmask =
							SME_QOS_TSPEC_MASK_BIT_1_2_SET;
						pACInfo->tspec_mask_status =
							SME_QOS_TSPEC_MASK_BIT_1_SET;
					}
					/* New stream is also uni-directional
					 * Find out the tsepc index with which it needs to be aggregated */
					else if (pACInfo->
						 curr_QoSInfo
						 [SME_QOS_TSPEC_INDEX_0].
						 ts_info.direction !=
						 Tspec_Info.ts_info.direction) {
						/* Aggregate with 2nd tspec index */
						tmask =
							SME_QOS_TSPEC_MASK_BIT_2_SET;
					} else {
						/* Aggregate with 1st tspec index */
						tmask =
							SME_QOS_TSPEC_MASK_BIT_1_SET;
					}
				} else {
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_INFO_MED,
						  "%s: %d: wrong tmask = %d",
						  __func__, __LINE__,
						  pACInfo->tspec_mask_status);
				}
			} else {
				/* ACM = 0 */
				/* We won't be sending a TSPEC to the AP but we still need */
				/* to aggregate to calculate trigger frame parameters */
				tmask = SME_QOS_TSPEC_MASK_BIT_1_SET;
			}
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
				  "%s: %d: tmask = %d, new_tmask = %d in state = %d",
				  __func__, __LINE__,
				  tmask, new_tmask, pACInfo->curr_state);
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
				  "%s: %d: tspec_mask_status = %d for AC = %d",
				  __func__, __LINE__,
				  pACInfo->tspec_mask_status, ac);
			if (tmask) {
				/* create the aggregate TSPEC */
				if (tmask != SME_QOS_TSPEC_MASK_BIT_1_2_SET) {
					hstatus =
						sme_qos_aggregate_params(&Tspec_Info,
									 &pACInfo->
									 curr_QoSInfo
									 [tmask - 1],
									 &pACInfo->
									 requested_QoSInfo
									 [tmask - 1]);
				} else {
					/* Aggregate the new bidirectional stream with the existing upstreams and
					 * downstreams in tspec indices 0 and 1. */
					tmask = SME_QOS_TSPEC_MASK_BIT_1_SET;

					hstatus = sme_qos_aggregate_params(
							&Tspec_Info, &pACInfo->
							curr_QoSInfo
							[SME_QOS_TSPEC_INDEX_0],
							&pACInfo->
							requested_QoSInfo
							[tmask - 1]);
					if (hstatus == QDF_STATUS_SUCCESS) {
						hstatus =
							sme_qos_aggregate_params
								(&pACInfo->
								curr_QoSInfo
								[SME_QOS_TSPEC_INDEX_1],
								&pACInfo->
								requested_QoSInfo[tmask -
										  1],
								NULL);
					}
				}

				if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
					/* err msg */
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: %d: failed to aggregate params",
						  __func__, __LINE__);
					/* unable to service the request */
					/* nothing is pending so vote powersave back on */
					pSession->readyForPowerSave = true;
					return SME_QOS_STATUS_SETUP_FAILURE_RSP;
				}
			} else {
				if (!
				    (new_tmask > 0
				     && new_tmask <= SME_QOS_TSPEC_INDEX_MAX)) {
					return SME_QOS_STATUS_SETUP_FAILURE_RSP;
				}
				tmask = new_tmask;
				pACInfo->requested_QoSInfo[tmask - 1] =
					Tspec_Info;
			}
		} else {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: no flows running for ac = %d while in state = %d",
				  __func__, __LINE__, ac, pACInfo->curr_state);
			QDF_ASSERT(0);
			/* unable to service the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return status;
		}
		/* although aggregating, make sure to request on the correct UP,TID,PSB and direction */
		pACInfo->requested_QoSInfo[tmask - 1].ts_info.up =
			Tspec_Info.ts_info.up;
		pACInfo->requested_QoSInfo[tmask - 1].ts_info.tid =
			Tspec_Info.ts_info.tid;
		pACInfo->requested_QoSInfo[tmask - 1].ts_info.direction =
			Tspec_Info.ts_info.direction;
		pACInfo->requested_QoSInfo[tmask - 1].ts_info.psb =
			Tspec_Info.ts_info.psb;
		status =
			sme_qos_setup(pMac, sessionId,
				      &pACInfo->requested_QoSInfo[tmask - 1], ac);
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: On session %d with AC %d in state SME_QOS_QOS_ON "
			  "sme_qos_setup returned with status %d", __func__,
			  __LINE__, sessionId, ac, status);
		if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP != status) {
			/* we aren't waiting for a response from the AP */
			/* so vote powersave back on */
			pSession->readyForPowerSave = true;
		}
		if ((SME_QOS_STATUS_SETUP_REQ_PENDING_RSP == status) ||
		    (SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP == status)
		    || (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY ==
			status)) {
			/* we received an expected "good" status */
			/* create an entry in the flow list */
			pentry =
				(sme_QosFlowInfoEntry *)
				qdf_mem_malloc(sizeof(*pentry));
			if (!pentry) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: couldn't allocate memory for the new "
					  "entry in the Flow List", __func__,
					  __LINE__);
				return SME_QOS_STATUS_SETUP_FAILURE_RSP;
			}
			pentry->ac_type = ac;
			pentry->HDDcontext = HDDcontext;
			pentry->QoSCallback = QoSCallback;
			pentry->hoRenewal = hoRenewal;
			pentry->QosFlowID = QosFlowID;
			pentry->sessionId = sessionId;
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: Creating flow %d",
				  __func__, __LINE__, QosFlowID);
			if ((SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP ==
			     status)
			    || (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY ==
				status)) {
				new_state = pACInfo->curr_state;
				pentry->reason = SME_QOS_REASON_REQ_SUCCESS;
				pACInfo->curr_QoSInfo[SME_QOS_TSPEC_INDEX_0] =
					pACInfo->
					requested_QoSInfo[SME_QOS_TSPEC_INDEX_0];
				if (buffered_cmd && !pentry->hoRenewal) {
					QoSCallback(pMac, HDDcontext,
						    &pACInfo->
						    curr_QoSInfo
						    [SME_QOS_TSPEC_INDEX_0],
						    status, pentry->QosFlowID);
				}
				if (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY == status) {
					/* if we are not in handoff, then notify all flows on */
					/* this AC that the aggregate TSPEC may have changed */
					if (!pentry->hoRenewal) {
						qdf_mem_zero(&search_key,
							     sizeof
							     (sme_QosSearchInfo));
						search_key.key.ac_type = ac;
						search_key.index =
							SME_QOS_SEARCH_KEY_INDEX_2;
						search_key.sessionId =
							sessionId;
						hstatus =
							sme_qos_find_all_in_flow_list
								(pMac, search_key,
								sme_qos_setup_fnp);
						if (!QDF_IS_STATUS_SUCCESS
							    (hstatus)) {
							QDF_TRACE
								(QDF_MODULE_ID_SME,
								QDF_TRACE_LEVEL_ERROR,
								"%s: %d: couldn't notify other "
								"entries on this AC =%d",
								__func__, __LINE__,
								ac);
						}
					}
				}
				pentry->hoRenewal = false;
			} else {
				/* SME_QOS_STATUS_SETUP_REQ_PENDING_RSP */
				new_state = SME_QOS_REQUESTED;
				pentry->reason = SME_QOS_REASON_SETUP;
				/* Need this info when addts comes back from PE to know on */
				/* which index of the AC the request was from */
				pACInfo->tspec_pending = tmask;
			}
			pACInfo->num_flows[tmask - 1]++;
			/* indicate on which index the flow entry belongs to & add it to the */
			/* Flow List at the end */
			pentry->tspec_mask = tmask;
			pentry->QoSInfo = Tspec_Info;
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: On session %d creating entry at %p with flowID %d",
				  __func__, __LINE__,
				  sessionId, pentry, QosFlowID);
			csr_ll_insert_tail(&sme_qos_cb.flow_list, &pentry->link,
					   true);
		} else {
			/* unexpected status returned by sme_qos_setup() */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d unexpected status %d "
				  "returned by sme_qos_setup",
				  __func__, __LINE__, sessionId, status);
			new_state = pACInfo->curr_state;
		}
		break;
	case SME_QOS_CLOSED:
	case SME_QOS_INIT:
	default:
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: setup requested in unexpected state = %d",
			  __func__, __LINE__, pACInfo->curr_state);
		/* unable to service the request */
		/* nothing is pending so vote powersave back on */
		pSession->readyForPowerSave = true;
		QDF_ASSERT(0);
		new_state = pACInfo->curr_state;
	}
	/* if current state is same as previous no need for transistion,
	   if we are doing reassoc & we are already in handoff state, no need to move
	   to requested state. But make sure to set the previous state as requested
	   state
	 */
	if ((new_state != pACInfo->curr_state) &&
	    (!(pACInfo->reassoc_pending &&
	       (SME_QOS_HANDOFF == pACInfo->curr_state)))) {
		sme_qos_state_transition(sessionId, ac, new_state);
	}

	if (pACInfo->reassoc_pending &&
	    (SME_QOS_HANDOFF == pACInfo->curr_state)) {
		pACInfo->prev_state = SME_QOS_REQUESTED;
	}
	if ((SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP == status) ||
	    (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY == status)) {
		(void)sme_qos_process_buffered_cmd(sessionId);
	}
	return status;
}

/**
 * sme_qos_internal_modify_req() - The SME QoS internal function to request
 *  for modification of certain QoS params on a flow running on a particular AC.
 * @pMac: Pointer to the global MAC parameter structure.
 * @pQoSInfo: Pointer to sme_QosWmmTspecInfo which contains the WMM TSPEC
 *            related info as defined above, provided by HDD
 * @QosFlowID: Identification per flow running on each AC generated by
 *             SME. It is only meaningful if the QoS setup for the flow has
 *             been successful already
 *
 * If the request involves admission control on the requested AC, HDD needs to
 * provide the necessary Traffic Specification (TSPEC) parameters & SME might
 * start the renegotiation process through ADDTS.
 *
 * Return: SME_QOS_STATUS_SETUP_SUCCESS_RSP - Modification is successful.
 *         Other status means request failed
 */
sme_QosStatusType sme_qos_internal_modify_req(tpAniSirGlobal pMac,
					      sme_QosWmmTspecInfo *pQoSInfo,
					      uint32_t QosFlowID,
					      bool buffered_cmd)
{
	tListElem *pEntry = NULL;
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosFlowInfoEntry *pNewEntry = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosEdcaAcType ac;
	sme_QosStates new_state = SME_QOS_CLOSED;
	sme_QosStatusType status = SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
	sme_QosWmmTspecInfo Aggr_Tspec_Info;
	sme_QosSearchInfo search_key;
	sme_QosCmdInfo cmd;
	uint8_t sessionId;
	QDF_STATUS hstatus;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked for flow %d", __func__, __LINE__, QosFlowID);

	qdf_mem_zero(&search_key, sizeof(sme_QosSearchInfo));
	/* set the key type & the key to be searched in the Flow List */
	search_key.key.QosFlowID = QosFlowID;
	search_key.index = SME_QOS_SEARCH_KEY_INDEX_1;
	search_key.sessionId = SME_QOS_SEARCH_SESSION_ID_ANY;
	/* go through the link list to find out the details on the flow */
	pEntry = sme_qos_find_in_flow_list(search_key);
	if (!pEntry) {
		/* Err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: no match found for flowID = %d",
			  __func__, __LINE__, QosFlowID);
		return SME_QOS_STATUS_MODIFY_SETUP_INVALID_PARAMS_RSP;
	}
	/* find the AC */
	flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;

	sessionId = flow_info->sessionId;
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pACInfo = &pSession->ac_info[ac];

	/* validate QoS params */
	if (!sme_qos_validate_requested_params(pMac, pQoSInfo, sessionId)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: invalid params", __func__, __LINE__);
		return SME_QOS_STATUS_MODIFY_SETUP_INVALID_PARAMS_RSP;
	}
	/* For modify, make sure that direction, TID and UP are not being altered */
	if ((pQoSInfo->ts_info.direction !=
	     flow_info->QoSInfo.ts_info.direction)
	    || (pQoSInfo->ts_info.up != flow_info->QoSInfo.ts_info.up)
	    || (pQoSInfo->ts_info.tid != flow_info->QoSInfo.ts_info.tid)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Modification of direction/tid/up is not allowed",
			  __func__, __LINE__);

		return SME_QOS_STATUS_MODIFY_SETUP_INVALID_PARAMS_RSP;
	}

	/* should not be same as previous ioctl parameters */
	if ((pQoSInfo->nominal_msdu_size ==
		flow_info->QoSInfo.nominal_msdu_size) &&
	    (pQoSInfo->maximum_msdu_size ==
		flow_info->QoSInfo.maximum_msdu_size) &&
	    (pQoSInfo->min_data_rate ==
		flow_info->QoSInfo.min_data_rate) &&
	    (pQoSInfo->mean_data_rate ==
		flow_info->QoSInfo.mean_data_rate) &&
	    (pQoSInfo->peak_data_rate ==
		flow_info->QoSInfo.peak_data_rate) &&
	    (pQoSInfo->min_service_interval ==
		flow_info->QoSInfo.min_service_interval) &&
	    (pQoSInfo->max_service_interval ==
		flow_info->QoSInfo.max_service_interval) &&
	    (pQoSInfo->inactivity_interval ==
		flow_info->QoSInfo.inactivity_interval) &&
	    (pQoSInfo->suspension_interval ==
		flow_info->QoSInfo.suspension_interval) &&
	    (pQoSInfo->surplus_bw_allowance ==
		flow_info->QoSInfo.surplus_bw_allowance)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			"%s: %d: the addts parameters are same as last request,"
			"dropping the current request", __func__, __LINE__);

		return SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
	}

	/* need to vote off powersave for the duration of this request */
	pSession->readyForPowerSave = false;
	/* check to consider the following flowing scenario.
	 * Addts request is pending on one AC, while APSD requested on another
	 * which needs a reassoc. Will buffer a request if Addts is pending on
	 * any AC, which will safegaurd the above scenario, & also won't
	 * confuse PE with back to back Addts or Addts followed by Reassoc
	 */
	if (sme_qos_is_rsp_pending(sessionId, ac)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
			  "%s: %d: buffering the modify request for flow %d in state %d "
			  "since another request is pending",
			  __func__, __LINE__, QosFlowID, pACInfo->curr_state);
		/* we need to buffer the command */
		cmd.command = SME_QOS_MODIFY_REQ;
		cmd.pMac = pMac;
		cmd.sessionId = sessionId;
		cmd.u.modifyCmdInfo.QosFlowID = QosFlowID;
		cmd.u.modifyCmdInfo.QoSInfo = *pQoSInfo;
		hstatus = sme_qos_buffer_cmd(&cmd, buffered_cmd);
		if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: couldn't buffer the modify request in state = %d",
				  __func__, __LINE__, pACInfo->curr_state);
			/* unable to buffer the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
		}
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Buffered modify request for flow = %d",
			  __func__, __LINE__, QosFlowID);
		return SME_QOS_STATUS_MODIFY_SETUP_PENDING_RSP;
	}
	/* get into the stat m/c to see if the request can be granted */
	switch (pACInfo->curr_state) {
	case SME_QOS_QOS_ON:
		/* save the new params adding a new (duplicate) entry in the Flow List */
		/* Once we have decided on OTA exchange needed or not we can delete the */
		/* original one from the List */
		pNewEntry =
			(sme_QosFlowInfoEntry *) qdf_mem_malloc(sizeof(*pNewEntry));
		if (!pNewEntry) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: couldn't allocate memory for the new "
				  "entry in the Flow List", __func__, __LINE__);
			/* unable to service the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
		}
		pNewEntry->ac_type = ac;
		pNewEntry->sessionId = sessionId;
		pNewEntry->HDDcontext = flow_info->HDDcontext;
		pNewEntry->QoSCallback = flow_info->QoSCallback;
		pNewEntry->QosFlowID = flow_info->QosFlowID;
		pNewEntry->reason = SME_QOS_REASON_MODIFY_PENDING;
		/* since it is a modify request, use the same index on which the flow */
		/* entry originally was running & add it to the Flow List at the end */
		pNewEntry->tspec_mask = flow_info->tspec_mask;
		pNewEntry->QoSInfo = *pQoSInfo;
		/* update the entry from Flow List which needed to be modified */
		flow_info->reason = SME_QOS_REASON_MODIFY;
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: On session %d creating modified "
			  "entry at %p with flowID %d",
			  __func__, __LINE__,
			  sessionId, pNewEntry, pNewEntry->QosFlowID);
		/* add the new entry under construction to the Flow List */
		csr_ll_insert_tail(&sme_qos_cb.flow_list, &pNewEntry->link,
				   true);
		/* update TSPEC with the new param set */
		hstatus = sme_qos_update_params(sessionId,
						ac, pNewEntry->tspec_mask,
						&Aggr_Tspec_Info);
		if (QDF_IS_STATUS_SUCCESS(hstatus)) {
			pACInfo->requested_QoSInfo[pNewEntry->tspec_mask - 1] =
				Aggr_Tspec_Info;
			/* if ACM, send out a new ADDTS */
			status = sme_qos_setup(pMac, sessionId,
					       &pACInfo->
					       requested_QoSInfo[pNewEntry->
								 tspec_mask - 1],
					       ac);
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: On session %d with AC %d in state SME_QOS_QOS_ON "
				  "sme_qos_setup returned with status %d",
				  __func__, __LINE__, sessionId, ac, status);
			if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP != status) {
				/* we aren't waiting for a response from the AP */
				/* so vote powersave back on */
				pSession->readyForPowerSave = true;
			}
			if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP == status) {
				new_state = SME_QOS_REQUESTED;
				status =
					SME_QOS_STATUS_MODIFY_SETUP_PENDING_RSP;
				pACInfo->tspec_pending = pNewEntry->tspec_mask;
			} else
			if ((SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP
			     == status)
			    ||
			    (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY
			     == status)) {
				new_state = SME_QOS_QOS_ON;

				qdf_mem_zero(&search_key,
					     sizeof(sme_QosSearchInfo));
				/* delete the original entry in FLOW list which got modified */
				search_key.key.ac_type = ac;
				search_key.index = SME_QOS_SEARCH_KEY_INDEX_2;
				search_key.sessionId = sessionId;
				hstatus =
					sme_qos_find_all_in_flow_list(pMac, search_key,
								      sme_qos_modify_fnp);
				if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
					status =
						SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
				}
				if (SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP !=
				    status) {
					pACInfo->curr_QoSInfo[pNewEntry->
							      tspec_mask - 1] =
						pACInfo->
						requested_QoSInfo[pNewEntry->
								  tspec_mask - 1];
					if (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY == status) {
						status =
							SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_APSD_SET_ALREADY;
						qdf_mem_zero(&search_key,
							     sizeof
							     (sme_QosSearchInfo));
						search_key.key.ac_type = ac;
						search_key.index =
							SME_QOS_SEARCH_KEY_INDEX_2;
						search_key.sessionId =
							sessionId;
						hstatus =
							sme_qos_find_all_in_flow_list
								(pMac, search_key,
								sme_qos_modification_notify_fnp);
						if (!QDF_IS_STATUS_SUCCESS
							    (hstatus)) {
							QDF_TRACE
								(QDF_MODULE_ID_SME,
								QDF_TRACE_LEVEL_ERROR,
								"%s: %d: couldn't notify other "
								"entries on this AC =%d",
								__func__, __LINE__,
								ac);
						}
					} else
					if
					(SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP
					 == status) {
						status =
							SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP;
					}
				}
				if (buffered_cmd) {
					flow_info->QoSCallback(pMac,
							       flow_info->
							       HDDcontext,
							       &pACInfo->
							       curr_QoSInfo
							       [pNewEntry->
								tspec_mask - 1],
							       status,
							       flow_info->
							       QosFlowID);
				}

			} else {
				/* unexpected status returned by sme_qos_setup() */
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: On session %d unexpected status %d "
					  "returned by sme_qos_setup", __func__,
					  __LINE__, sessionId, status);
				new_state = SME_QOS_QOS_ON;
			}
		} else {
			/* err msg */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: sme_qos_update_params() failed",
				  __func__, __LINE__);
			/* unable to service the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			new_state = SME_QOS_LINK_UP;
		}
		/* if we are doing reassoc & we are already in handoff state, no need
		   to move to requested state. But make sure to set the previous state
		   as requested state
		 */
		if (!(pACInfo->reassoc_pending &&
		      (SME_QOS_HANDOFF == pACInfo->curr_state))) {
			sme_qos_state_transition(sessionId, ac, new_state);
		} else {
			pACInfo->prev_state = SME_QOS_REQUESTED;
		}
		break;
	case SME_QOS_HANDOFF:
	case SME_QOS_REQUESTED:
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
			  "%s: %d: Buffering modify request for flow %d in state = %d",
			  __func__, __LINE__, QosFlowID, pACInfo->curr_state);
		/* buffer cmd */
		cmd.command = SME_QOS_MODIFY_REQ;
		cmd.pMac = pMac;
		cmd.sessionId = sessionId;
		cmd.u.modifyCmdInfo.QosFlowID = QosFlowID;
		cmd.u.modifyCmdInfo.QoSInfo = *pQoSInfo;
		hstatus = sme_qos_buffer_cmd(&cmd, buffered_cmd);
		if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: couldn't buffer the modify request in state = %d",
				  __func__, __LINE__, pACInfo->curr_state);
			/* unable to buffer the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
		}
		status = SME_QOS_STATUS_MODIFY_SETUP_PENDING_RSP;
		break;
	case SME_QOS_CLOSED:
	case SME_QOS_INIT:
	case SME_QOS_LINK_UP:
	default:
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: modify requested in unexpected state = %d",
			  __func__, __LINE__, pACInfo->curr_state);
		/* unable to service the request */
		/* nothing is pending so vote powersave back on */
		pSession->readyForPowerSave = true;
		break;
	}
	if ((SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP == status)
	    || (SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_APSD_SET_ALREADY ==
		status)) {
		(void)sme_qos_process_buffered_cmd(sessionId);
	}
	return status;
}

/**
 * sme_qos_internal_release_req() - release QOS flow on a particular AC
 * @pMac: Pointer to the global MAC parameter structure.
 * @sessionId: sessionId returned by sme_open_session.
 * @QosFlowID: Identification per flow running on each AC generated by SME
 *             It is only meaningful if the QoS setup for the flow is successful
 *
 * The SME QoS internal function to request
 * for releasing a QoS flow running on a particular AC.

 * Return: QDF_STATUS_SUCCESS - Release is successful.
 */
sme_QosStatusType sme_qos_internal_release_req(tpAniSirGlobal pMac,
					       uint8_t sessionId,
					       uint32_t QosFlowID,
					       bool buffered_cmd)
{
	tListElem *pEntry = NULL;
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosFlowInfoEntry *pDeletedFlow = NULL;
	sme_QosEdcaAcType ac;
	sme_QosStates new_state = SME_QOS_CLOSED;
	sme_QosStatusType status = SME_QOS_STATUS_RELEASE_FAILURE_RSP;
	sme_QosWmmTspecInfo Aggr_Tspec_Info;
	sme_QosSearchInfo search_key;
	sme_QosCmdInfo cmd;
	tCsrRoamModifyProfileFields modifyProfileFields;
	bool deltsIssued = false;
	QDF_STATUS hstatus;
	bool biDirectionalFlowsPresent = false;
	bool uplinkFlowsPresent = false;
	bool downlinkFlowsPresent = false;
	tListElem *pResult = NULL;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked for flow %d", __func__, __LINE__, QosFlowID);

	qdf_mem_zero(&search_key, sizeof(sme_QosSearchInfo));
	/* set the key type & the key to be searched in the Flow List */
	search_key.key.QosFlowID = QosFlowID;
	search_key.index = SME_QOS_SEARCH_KEY_INDEX_1;
	search_key.sessionId = SME_QOS_SEARCH_SESSION_ID_ANY;
	/* go through the link list to find out the details on the flow */
	pEntry = sme_qos_find_in_flow_list(search_key);

	if (!pEntry) {
		/* Err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: no match found for flowID = %d",
			  __func__, __LINE__, QosFlowID);

		pSession = &sme_qos_cb.sessionInfo[sessionId];
		if (!buffered_cmd &&
		    !csr_ll_is_list_empty(&pSession->bufferedCommandList,
					  false)) {
			cmd.command = SME_QOS_RELEASE_REQ;
			cmd.pMac = pMac;
			cmd.sessionId = sessionId;
			cmd.u.releaseCmdInfo.QosFlowID = QosFlowID;
			hstatus = sme_qos_buffer_cmd(&cmd, buffered_cmd);
			if (QDF_IS_STATUS_SUCCESS(hstatus)) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s:%d: Buffered release request for flow = %d",
					  __func__, __LINE__, QosFlowID);
			}
		}
		return SME_QOS_STATUS_RELEASE_INVALID_PARAMS_RSP;
	}
	/* find the AC */
	flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;
	sessionId = flow_info->sessionId;

	if (!CSR_IS_SESSION_VALID(pMac, sessionId)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			"%s: %d: Session Id: %d is invalid",
			__func__, __LINE__, sessionId);
		return status;
	}

	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pACInfo = &pSession->ac_info[ac];
	/* need to vote off powersave for the duration of this request */
	pSession->readyForPowerSave = false;
	/* check to consider the following flowing scenario.
	 * Addts request is pending on one AC, while APSD requested on another
	 * which needs a reassoc. Will buffer a request if Addts is pending on
	 * any AC, which will safegaurd the above scenario, & also won't
	 * confuse PE with back to back Addts or Addts followed by Reassoc
	 */
	if (sme_qos_is_rsp_pending(sessionId, ac)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
			  "%s: %d: buffering the release request for flow %d in state %d "
			  "since another request is pending",
			  __func__, __LINE__, QosFlowID, pACInfo->curr_state);
		/* we need to buffer the command */
		cmd.command = SME_QOS_RELEASE_REQ;
		cmd.pMac = pMac;
		cmd.sessionId = sessionId;
		cmd.u.releaseCmdInfo.QosFlowID = QosFlowID;
		hstatus = sme_qos_buffer_cmd(&cmd, buffered_cmd);
		if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: couldn't buffer the release request in state = %d",
				  __func__, __LINE__, pACInfo->curr_state);
			/* unable to buffer the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return SME_QOS_STATUS_RELEASE_FAILURE_RSP;
		}
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Buffered release request for flow = %d",
			  __func__, __LINE__, QosFlowID);
		return SME_QOS_STATUS_RELEASE_REQ_PENDING_RSP;
	}
	/* get into the stat m/c to see if the request can be granted */
	switch (pACInfo->curr_state) {
	case SME_QOS_QOS_ON:
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
			  "%s: %d: tspec_mask_status = %d for AC = %d with "
			  "entry tspec_mask = %d",
			  __func__, __LINE__,
			  pACInfo->tspec_mask_status, ac,
			  flow_info->tspec_mask);

		/* check if multiple flows running on the ac */
		if (pACInfo->num_flows[flow_info->tspec_mask - 1] > 1) {
			/* don't want to include the flow in the new TSPEC on which release */
			/* is requested */
			flow_info->reason = SME_QOS_REASON_RELEASE;

			/* Check if the flow being released is for bi-diretional.
			 * Following flows may present in the system.
			 * a) bi-directional flows
			 * b) uplink flows
			 * c) downlink flows.
			 * If the flow being released is for bidirectional, splitting of existing
			 * streams into two tspec indices is required in case ff (b), (c) are present
			 * and not (a).
			 * In case if split occurs, all upstreams are aggregated into tspec index 0,
			 * downstreams are aggregaed into tspec index 1 and two tspec requests for
			 * (aggregated) upstream(s) followed by (aggregated) downstream(s) is sent
			 * to AP. */
			if (flow_info->QoSInfo.ts_info.direction ==
			    SME_QOS_WMM_TS_DIR_BOTH) {
				qdf_mem_zero(&search_key,
					     sizeof(sme_QosSearchInfo));
				/* set the key type & the key to be searched in the Flow List */
				search_key.key.ac_type = ac;
				search_key.index = SME_QOS_SEARCH_KEY_INDEX_4;
				search_key.sessionId = sessionId;
				search_key.direction = SME_QOS_WMM_TS_DIR_BOTH;
				pResult = sme_qos_find_in_flow_list(search_key);
				if (pResult)
					biDirectionalFlowsPresent = true;

				if (!biDirectionalFlowsPresent) {
					/* The only existing bidirectional flow is being released */

					/* Check if uplink flows exist */
					search_key.direction =
						SME_QOS_WMM_TS_DIR_UPLINK;
					pResult =
						sme_qos_find_in_flow_list(search_key);
					if (pResult)
						uplinkFlowsPresent = true;

					/* Check if downlink flows exist */
					search_key.direction =
						SME_QOS_WMM_TS_DIR_DOWNLINK;
					pResult =
						sme_qos_find_in_flow_list(search_key);
					if (pResult)
						downlinkFlowsPresent = true;

					if (uplinkFlowsPresent
					    && downlinkFlowsPresent) {
						/* Need to split the uni-directional flows into SME_QOS_TSPEC_INDEX_0 and SME_QOS_TSPEC_INDEX_1 */

						qdf_mem_zero(&search_key,
							     sizeof
							     (sme_QosSearchInfo));
						/* Mark all downstream flows as using tspec index 1 */
						search_key.key.ac_type = ac;
						search_key.index =
							SME_QOS_SEARCH_KEY_INDEX_4;
						search_key.sessionId =
							sessionId;
						search_key.direction =
							SME_QOS_WMM_TS_DIR_DOWNLINK;
						sme_qos_update_tspec_mask
							(sessionId, search_key,
							SME_QOS_TSPEC_MASK_BIT_2_SET);

						/* Aggregate all downstream flows */
						hstatus =
							sme_qos_update_params
								(sessionId, ac,
								SME_QOS_TSPEC_MASK_BIT_2_SET,
								&Aggr_Tspec_Info);

						QDF_TRACE(QDF_MODULE_ID_SME,
							  QDF_TRACE_LEVEL_ERROR,
							  "%s: %d: On session %d buffering the AddTS request "
							  "for AC %d in state %d as Addts is pending "
							  "on other Tspec index of this AC",
							  __func__, __LINE__,
							  sessionId, ac,
							  pACInfo->curr_state);

						/* Buffer the (aggregated) tspec request for downstream flows. */
						/* Please note that the (aggregated) tspec for upstream flows is sent */
						/* out by the susequent logic. */
						cmd.command =
							SME_QOS_RESEND_REQ;
						cmd.pMac = pMac;
						cmd.sessionId = sessionId;
						cmd.u.resendCmdInfo.ac = ac;
						cmd.u.resendCmdInfo.tspecMask =
							SME_QOS_TSPEC_MASK_BIT_2_SET;
						cmd.u.resendCmdInfo.QoSInfo =
							Aggr_Tspec_Info;
						pACInfo->
						requested_QoSInfo
						[SME_QOS_TSPEC_MASK_BIT_2_SET
						 - 1] = Aggr_Tspec_Info;
						if (!QDF_IS_STATUS_SUCCESS
							    (sme_qos_buffer_cmd
								    (&cmd, false))) {
							QDF_TRACE
								(QDF_MODULE_ID_SME,
								QDF_TRACE_LEVEL_ERROR,
								"%s: %d: On session %d unable to buffer the AddTS "
								"request for AC %d TSPEC %d in state %d",
								__func__, __LINE__,
								sessionId, ac,
								SME_QOS_TSPEC_MASK_BIT_2_SET,
								pACInfo->
								curr_state);

							/* unable to buffer the request */
							/* nothing is pending so vote powersave back on */
							pSession->
							readyForPowerSave =
								true;

							return
								SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
						}
						pACInfo->tspec_mask_status =
							SME_QOS_TSPEC_MASK_BIT_1_2_SET;

					}
				}
			}

			/* In case of splitting of existing streams,
			 * tspec_mask will be pointing to tspec index 0 and
			 * aggregated tspec for upstream(s) is sent out here. */
			hstatus = sme_qos_update_params(sessionId,
							ac, flow_info->tspec_mask,
							&Aggr_Tspec_Info);
			if (QDF_IS_STATUS_SUCCESS(hstatus)) {
				pACInfo->requested_QoSInfo[flow_info->
							   tspec_mask - 1] =
					Aggr_Tspec_Info;
				/* if ACM, send out a new ADDTS */
				status = sme_qos_setup(pMac, sessionId,
						       &pACInfo->
						       requested_QoSInfo
						       [flow_info->tspec_mask -
							1], ac);
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s: %d: On session %d with AC %d in state SME_QOS_QOS_ON "
					  "sme_qos_setup returned with status %d",
					  __func__, __LINE__, sessionId, ac,
					  status);
				if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP !=
				    status) {
					/* we aren't waiting for a response from the AP */
					/* so vote powersave back on */
					pSession->readyForPowerSave = true;
				}
				if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP ==
				    status) {
					new_state = SME_QOS_REQUESTED;
					status =
						SME_QOS_STATUS_RELEASE_REQ_PENDING_RSP;
					pACInfo->tspec_pending =
						flow_info->tspec_mask;
				} else
				if ((SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP == status) || (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY == status)) {
					new_state = SME_QOS_QOS_ON;
					pACInfo->num_flows[flow_info->
							   tspec_mask - 1]--;
					pACInfo->curr_QoSInfo[flow_info->
							      tspec_mask - 1] =
						pACInfo->
						requested_QoSInfo[flow_info->
								  tspec_mask - 1];
					/* delete the entry from Flow List */
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_INFO_HIGH,
						  "%s: %d: Deleting entry at %p with flowID %d",
						  __func__, __LINE__, flow_info,
						  QosFlowID);
					csr_ll_remove_entry(&sme_qos_cb.flow_list,
							    pEntry, true);
					pDeletedFlow = flow_info;
					if (SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY == status) {
						qdf_mem_zero(&search_key,
							     sizeof
							     (sme_QosSearchInfo));
						search_key.key.ac_type = ac;
						search_key.index =
							SME_QOS_SEARCH_KEY_INDEX_2;
						search_key.sessionId =
							sessionId;
						hstatus =
							sme_qos_find_all_in_flow_list
								(pMac, search_key,
								sme_qos_setup_fnp);
						if (!QDF_IS_STATUS_SUCCESS
							    (hstatus)) {
							QDF_TRACE
								(QDF_MODULE_ID_SME,
								QDF_TRACE_LEVEL_ERROR,
								"%s: %d: couldn't notify other "
								"entries on this AC =%d",
								__func__, __LINE__,
								ac);
						}
					}
					status =
						SME_QOS_STATUS_RELEASE_SUCCESS_RSP;
					if (buffered_cmd) {
						flow_info->QoSCallback(pMac,
								       flow_info->
								       HDDcontext,
								       &pACInfo->
								       curr_QoSInfo
								       [flow_info->
									tspec_mask
									- 1],
								       status,
								       flow_info->
								       QosFlowID);
					}
				} else {
					/* unexpected status returned by sme_qos_setup() */
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: %d: On session %d unexpected status %d "
						  "returned by sme_qos_setup",
						  __func__, __LINE__, sessionId,
						  status);
					new_state = SME_QOS_LINK_UP;
					pACInfo->num_flows[flow_info->
							   tspec_mask - 1]--;
					pACInfo->curr_QoSInfo[flow_info->
							      tspec_mask - 1] =
						pACInfo->
						requested_QoSInfo[flow_info->
								  tspec_mask - 1];
					/* delete the entry from Flow List */
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_INFO_HIGH,
						  "%s: %d: On session %d deleting entry at "
						  "%p with flowID %d", __func__,
						  __LINE__, sessionId,
						  flow_info, QosFlowID);
					csr_ll_remove_entry(&sme_qos_cb.flow_list,
							    pEntry, true);
					pDeletedFlow = flow_info;
					if (buffered_cmd) {
						flow_info->QoSCallback(pMac,
								       flow_info->
								       HDDcontext,
								       &pACInfo->
								       curr_QoSInfo
								       [flow_info->
									tspec_mask
									- 1],
								       status,
								       flow_info->
								       QosFlowID);
					}
				}
			} else {
				/* err msg */
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: sme_qos_update_params() failed",
					  __func__, __LINE__);
				/* unable to service the request */
				/* nothing is pending so vote powersave back on */
				pSession->readyForPowerSave = true;
				new_state = SME_QOS_LINK_UP;
				if (buffered_cmd) {
					flow_info->QoSCallback(pMac,
							       flow_info->
							       HDDcontext,
							       &pACInfo->
							       curr_QoSInfo
							       [flow_info->
								tspec_mask - 1],
							       status,
							       flow_info->
							       QosFlowID);
				}
			}
		} else {
			/* this is the only flow aggregated in this TSPEC */
			status = SME_QOS_STATUS_RELEASE_SUCCESS_RSP;
			/* check if delts needs to be sent */
			if (CSR_IS_ADDTS_WHEN_ACMOFF_SUPPORTED(pMac) ||
			    sme_qos_is_acm(pMac, pSession->assocInfo.pBssDesc, ac,
					   NULL)) {
				/* check if other TSPEC for this AC is also in use */
				if (SME_QOS_TSPEC_MASK_BIT_1_2_SET !=
				    pACInfo->tspec_mask_status) {
					/* this is the only TSPEC active on this AC */
					/* so indicate that we no longer require APSD */
					pSession->apsdMask &=
						~(1 << (SME_QOS_EDCA_AC_VO - ac));
					/* Also update modifyProfileFields.uapsd_mask in CSR for consistency */
					csr_get_modify_profile_fields(pMac,
								      flow_info->
								      sessionId,
								      &modifyProfileFields);
					modifyProfileFields.uapsd_mask =
						pSession->apsdMask;
					csr_set_modify_profile_fields(pMac,
								      flow_info->
								      sessionId,
								      &modifyProfileFields);
					if (!pSession->apsdMask) {
						/* this session no longer needs UAPSD */
						/* do any sessions still require UAPSD? */
						if (!sme_qos_is_uapsd_active()) {
							/* No sessions require UAPSD so turn it off */
							/* (really don't care when PMC stops it) */
							sme_ps_uapsd_disable(
							      pMac, sessionId);
						}
					}
				}
				if (SME_QOS_RELEASE_DEFAULT == pACInfo->relTrig) {
					/* send delts */
					hstatus =
						qos_issue_command(pMac, sessionId,
								  eSmeCommandDelTs,
								  NULL, ac,
								  flow_info->
								  tspec_mask);
					if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
						/* err msg */
						QDF_TRACE(QDF_MODULE_ID_SME,
							  QDF_TRACE_LEVEL_ERROR,
							  "%s: %d: sme_qos_del_ts_req() failed",
							  __func__, __LINE__);
						status =
							SME_QOS_STATUS_RELEASE_FAILURE_RSP;
						/* we won't be waiting for a response from the AP */
						/* so vote powersave back on */
						pSession->readyForPowerSave =
							true;
					} else {
						pACInfo->tspec_mask_status &=
							SME_QOS_TSPEC_MASK_BIT_1_2_SET
							& (~flow_info->tspec_mask);
						deltsIssued = true;
					}
				} else {
					pSession->readyForPowerSave = true;
					pACInfo->tspec_mask_status &=
						SME_QOS_TSPEC_MASK_BIT_1_2_SET &
						(~flow_info->tspec_mask);
					deltsIssued = true;
				}
			} else if (pSession->apsdMask &
				(1 << (SME_QOS_EDCA_AC_VO - ac))) {
				/* reassoc logic */
				csr_get_modify_profile_fields(pMac, sessionId,
							      &modifyProfileFields);
				modifyProfileFields.uapsd_mask |=
					pSession->apsdMask;
				modifyProfileFields.uapsd_mask &=
					~(1 << (SME_QOS_EDCA_AC_VO - ac));
				pSession->apsdMask &=
					~(1 << (SME_QOS_EDCA_AC_VO - ac));
				if (!pSession->apsdMask) {
					/* this session no longer needs UAPSD */
					/* do any sessions still require UAPSD? */
					if (!sme_qos_is_uapsd_active()) {
						/* No sessions require UAPSD so turn it off */
						/* (really don't care when PMC stops it) */
						sme_ps_uapsd_disable(
							pMac, sessionId);
					}
				}
				hstatus = sme_qos_request_reassoc(pMac, sessionId,
								  &modifyProfileFields,
								  false);
				if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
					/* err msg */
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: %d: Reassoc failed",
						  __func__, __LINE__);
					status =
						SME_QOS_STATUS_RELEASE_FAILURE_RSP;
					/* we won't be waiting for a response from the AP */
					/* so vote powersave back on */
					pSession->readyForPowerSave = true;
				} else {
					pACInfo->reassoc_pending = false;   /* no need to wait */
					pACInfo->prev_state = SME_QOS_LINK_UP;
					pACInfo->tspec_pending = 0;
				}
			} else {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s: %d: nothing to do for AC = %d",
					  __func__, __LINE__, ac);
				/* we won't be waiting for a response from the AP */
				/* so vote powersave back on */
				pSession->readyForPowerSave = true;
			}

			if (SME_QOS_RELEASE_BY_AP == pACInfo->relTrig) {
				flow_info->QoSCallback(pMac,
						       flow_info->HDDcontext,
						       &pACInfo->
						       curr_QoSInfo[flow_info->
								    tspec_mask -
								    1],
						       SME_QOS_STATUS_RELEASE_QOS_LOST_IND,
						       flow_info->QosFlowID);

				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s: %d: Deleting entry at %p with flowID %d",
					  __func__, __LINE__, flow_info,
					  flow_info->QosFlowID);
			} else if (buffered_cmd) {
				flow_info->QoSCallback(pMac,
						       flow_info->HDDcontext,
						       NULL, status,
						       flow_info->QosFlowID);
			}

			if (SME_QOS_STATUS_RELEASE_FAILURE_RSP == status) {
				break;
			}

			if (((SME_QOS_TSPEC_MASK_BIT_1_2_SET & ~flow_info->
			      tspec_mask) > 0)
			    &&
			    ((SME_QOS_TSPEC_MASK_BIT_1_2_SET & ~flow_info->
			      tspec_mask) <= SME_QOS_TSPEC_INDEX_MAX)) {
				if (pACInfo->
				    num_flows[(SME_QOS_TSPEC_MASK_BIT_1_2_SET &
					       ~flow_info->tspec_mask) - 1] >
				    0) {
					new_state = SME_QOS_QOS_ON;
				} else {
					new_state = SME_QOS_LINK_UP;
				}
			} else {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s: %d: Exceeded the array bounds of pACInfo->num_flows",
					  __func__, __LINE__);
				QDF_ASSERT(0);
				return
					SME_QOS_STATUS_RELEASE_INVALID_PARAMS_RSP;
			}

			if (false == deltsIssued) {
				qdf_mem_zero(&pACInfo->
					     curr_QoSInfo[flow_info->
							  tspec_mask - 1],
					     sizeof(sme_QosWmmTspecInfo));
			}
			qdf_mem_zero(&pACInfo->
				     requested_QoSInfo[flow_info->tspec_mask -
						       1],
				     sizeof(sme_QosWmmTspecInfo));
			pACInfo->num_flows[flow_info->tspec_mask - 1]--;
			/* delete the entry from Flow List */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: On session %d deleting entry at %p with flowID %d",
				  __func__, __LINE__,
				  sessionId, flow_info, QosFlowID);
			csr_ll_remove_entry(&sme_qos_cb.flow_list, pEntry,
					    true);
			pDeletedFlow = flow_info;
			pACInfo->relTrig = SME_QOS_RELEASE_DEFAULT;
		}
		/* if we are doing reassoc & we are already in handoff state, no need
		   to move to requested state. But make sure to set the previous state
		   as requested state
		 */
		if (SME_QOS_HANDOFF != pACInfo->curr_state) {
			sme_qos_state_transition(sessionId, ac, new_state);
		}
		if (pACInfo->reassoc_pending) {
			pACInfo->prev_state = SME_QOS_REQUESTED;
		}
		break;
	case SME_QOS_HANDOFF:
	case SME_QOS_REQUESTED:
		/* buffer cmd */
		cmd.command = SME_QOS_RELEASE_REQ;
		cmd.pMac = pMac;
		cmd.sessionId = sessionId;
		cmd.u.releaseCmdInfo.QosFlowID = QosFlowID;
		hstatus = sme_qos_buffer_cmd(&cmd, buffered_cmd);
		if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: couldn't buffer the release request in state = %d",
				  __func__, __LINE__, pACInfo->curr_state);
			/* unable to service the request */
			/* nothing is pending so vote powersave back on */
			pSession->readyForPowerSave = true;
			return SME_QOS_STATUS_RELEASE_FAILURE_RSP;
		}
		status = SME_QOS_STATUS_RELEASE_REQ_PENDING_RSP;
		break;
	case SME_QOS_CLOSED:
	case SME_QOS_INIT:
	case SME_QOS_LINK_UP:
	default:
		/* print error msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: release request in unexpected state = %d",
			  __func__, __LINE__, pACInfo->curr_state);
		QDF_ASSERT(0);
		/* unable to service the request */
		/* nothing is pending so vote powersave back on */
		pSession->readyForPowerSave = true;
		break;
	}
	/* if we deleted a flow, reclaim the memory */
	if (pDeletedFlow) {
		qdf_mem_free(pDeletedFlow);
	}
	if ((SME_QOS_STATUS_RELEASE_SUCCESS_RSP == status)) {
		(void)sme_qos_process_buffered_cmd(sessionId);
	}
	return status;
}

/**
 * sme_qos_setup() - internal SME QOS setup function.
 * @pMac: Pointer to the global MAC parameter structure.
 * @sessionId: Session upon which setup is being performed
 * @pTspec_Info: Pointer to sme_QosWmmTspecInfo which contains the WMM
 *               TSPEC related info as defined above
 * @ac: Enumeration of the various EDCA Access Categories.
 *
 * The internal qos setup function which has the intelligence
 * if the request is NOP, or for APSD and/or need to send out ADDTS.
 * It also does the sanity check for QAP, AP supports APSD etc.
 * The logic used in the code might be confusing.
 *
 * Trying to cover all the cases here.
 *    AP supports  App wants   ACM = 1  Already set APSD   Result
 * |    0     |    0     |     0   |       0          |  NO ACM NO APSD
 * |    0     |    0     |     0   |       1          |  NO ACM NO APSD/INVALID
 * |    0     |    0     |     1   |       0          |  ADDTS
 * |    0     |    0     |     1   |       1          |  ADDTS
 * |    0     |    1     |     0   |       0          |  FAILURE
 * |    0     |    1     |     0   |       1          |  INVALID
 * |    0     |    1     |     1   |       0          |  ADDTS
 * |    0     |    1     |     1   |       1          |  ADDTS
 * |    1     |    0     |     0   |       0          |  NO ACM NO APSD
 * |    1     |    0     |     0   |       1          |  NO ACM NO APSD
 * |    1     |    0     |     1   |       0          |  ADDTS
 * |    1     |    0     |     1   |       1          |  ADDTS
 * |    1     |    1     |     0   |       0          |  REASSOC
 * |    1     |    1     |     0   |       1          |  NOP: APSD SET ALREADY
 * |    1     |    1     |     1   |       0          |  ADDTS
 * |    1     |    1     |     1   |       1          |  ADDTS
 *
 * Return: SME_QOS_STATUS_SETUP_SUCCESS_RSP if the setup is successful'
 */
sme_QosStatusType sme_qos_setup(tpAniSirGlobal pMac,
				uint8_t sessionId,
				sme_QosWmmTspecInfo *pTspec_Info,
				sme_QosEdcaAcType ac)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosStatusType status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
	tDot11fBeaconIEs *pIes = NULL;
	tCsrRoamModifyProfileFields modifyProfileFields;
	QDF_STATUS hstatus;
	if (!CSR_IS_SESSION_VALID(pMac, sessionId)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Session Id %d is invalid",
			  __func__, __LINE__, sessionId);
		return status;
	}
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	if (!pSession->sessionActive) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Session %d is inactive",
			  __func__, __LINE__, sessionId);
		return status;
	}
	if (!pSession->assocInfo.pBssDesc) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Session %d has an Invalid BSS Descriptor",
			  __func__, __LINE__, sessionId);
		return status;
	}
	hstatus = csr_get_parsed_bss_description_ies(pMac,
						      pSession->assocInfo.pBssDesc,
						      &pIes);
	if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d unable to parse BSS IEs",
			  __func__, __LINE__, sessionId);
		return status;
	}

	/* success so pIes was allocated */

	if (!CSR_IS_QOS_BSS(pIes)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d AP doesn't support QoS",
			  __func__, __LINE__, sessionId);
		qdf_mem_free(pIes);
		/* notify HDD through the synchronous status msg */
		return SME_QOS_STATUS_SETUP_NOT_QOS_AP_RSP;
	}

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_DEBUG,
		  "%s: %d: UAPSD/PSB set %d: ", __func__, __LINE__,
		  pTspec_Info->ts_info.psb);

	pACInfo = &pSession->ac_info[ac];
	do {
		/* is ACM enabled for this AC? */
		if (CSR_IS_ADDTS_WHEN_ACMOFF_SUPPORTED(pMac) ||
		    sme_qos_is_acm(pMac, pSession->assocInfo.pBssDesc,
				   ac, NULL)) {
			/* ACM is enabled for this AC so we must send an AddTS */
			if (pTspec_Info->ts_info.psb &&
			    !(pIes->WMMParams.
			      qosInfo & SME_QOS_AP_SUPPORTS_APSD)
			    && !(pIes->WMMInfoAp.uapsd)) {
				/* application is looking for APSD but AP doesn't support it */
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: On session %d AP doesn't support APSD",
					  __func__, __LINE__, sessionId);
				break;
			}

			if (SME_QOS_MAX_TID == pTspec_Info->ts_info.tid) {
				/* App didn't set TID, generate one */
				pTspec_Info->ts_info.tid =
					(uint8_t) (SME_QOS_WMM_UP_NC -
						   pTspec_Info->ts_info.up);
			}
			/* addts logic */
			hstatus =
				qos_issue_command(pMac, sessionId, eSmeCommandAddTs,
						  pTspec_Info, ac, 0);
			if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: sme_qos_add_ts_req() failed",
					  __func__, __LINE__);
				break;
			}
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: On session %d AddTS on AC %d is pending",
				  __func__, __LINE__, sessionId, ac);
			status = SME_QOS_STATUS_SETUP_REQ_PENDING_RSP;
			break;
		}
		/* ACM is not enabled for this AC */
		/* Is the application looking for APSD? */
		if (0 == pTspec_Info->ts_info.psb) {
			/* no, we don't need APSD */
			/* but check the case, if the setup is called as a result of a release */
			/* or modify which boils down to the fact that APSD was set on this AC */
			/* but no longer needed - so we need a reassoc for the above case to */
			/* let the AP know */
			if (pSession->
			    apsdMask & (1 << (SME_QOS_EDCA_AC_VO - ac))) {
				/* APSD was formerly enabled on this AC but is no longer required */
				/* so we must reassociate */
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s: %d: On session %d reassoc needed "
					  "to disable APSD on AC %d", __func__,
					  __LINE__, sessionId, ac);
				csr_get_modify_profile_fields(pMac, sessionId,
							      &modifyProfileFields);
				modifyProfileFields.uapsd_mask |=
					pSession->apsdMask;
				modifyProfileFields.uapsd_mask &=
					~(1 << (SME_QOS_EDCA_AC_VO - ac));
				hstatus =
					sme_qos_request_reassoc(pMac, sessionId,
								&modifyProfileFields,
								false);
				if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
					/* err msg */
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: %d: Unable to request reassociation",
						  __func__, __LINE__);
					break;
				} else {
					QDF_TRACE(QDF_MODULE_ID_SME,
						  QDF_TRACE_LEVEL_INFO_HIGH,
						  "%s: %d: On session %d reassociation to enable "
						  "APSD on AC %d is pending",
						  __func__, __LINE__, sessionId,
						  ac);
					status =
						SME_QOS_STATUS_SETUP_REQ_PENDING_RSP;
					pACInfo->reassoc_pending = true;
				}
			} else {
				/* we don't need APSD on this AC */
				/* and we don't currently have APSD on this AC */
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s: %d: Request is not looking for APSD & Admission "
					  "Control isn't mandatory for the AC",
					  __func__, __LINE__);
				/* return success right away */
				status =
					SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP;
			}
			break;
		} else if (!(pIes->WMMParams.qosInfo & SME_QOS_AP_SUPPORTS_APSD)
			   && !(pIes->WMMInfoAp.uapsd)) {
			/* application is looking for APSD but AP doesn't support it */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d AP doesn't support APSD",
				  __func__, __LINE__, sessionId);
			break;
		} else if (pSession->
			   apsdMask & (1 << (SME_QOS_EDCA_AC_VO - ac))) {
			/* application is looking for APSD */
			/* and it is already enabled on this AC */
			status = SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY;
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: Request is looking for APSD and it is already "
				  "set for the AC", __func__, __LINE__);
			break;
		} else {
			/* application is looking for APSD */
			/* but it is not enabled on this AC */
			/* so we need to reassociate */
			QDF_TRACE(QDF_MODULE_ID_SME,
				QDF_TRACE_LEVEL_INFO_HIGH,
				FL("On session %d reassoc needed to enable APSD on AC %d"),
				sessionId, ac);
			/* reassoc logic */
			/* update the UAPSD mask to include the new */
			/* AC on which APSD is requested */
			csr_get_modify_profile_fields(pMac, sessionId,
					&modifyProfileFields);
			modifyProfileFields.uapsd_mask |=
				pSession->apsdMask;
			modifyProfileFields.uapsd_mask |=
				1 << (SME_QOS_EDCA_AC_VO - ac);
			hstatus =
				sme_qos_request_reassoc(pMac, sessionId,
						&modifyProfileFields,
						false);
			if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
				/* err msg */
				QDF_TRACE(QDF_MODULE_ID_SME,
						QDF_TRACE_LEVEL_ERROR,
						"%s: %d: Unable to request reassociation",
						__func__, __LINE__);
				break;
			} else {
				QDF_TRACE(QDF_MODULE_ID_SME,
					QDF_TRACE_LEVEL_INFO_HIGH,
					FL("On session %d reassociation to enable APSD on AC %d is pending"),
					sessionId, ac);
				status =
					SME_QOS_STATUS_SETUP_REQ_PENDING_RSP;
				pACInfo->reassoc_pending = true;
			}
		}
	} while (0);

	qdf_mem_free(pIes);
	return status;
}

/* This is a dummy function now. But the purpose of me adding this was to
 * delay the TSPEC processing till SET_KEY completes. This function can be
 * used to do any SME_QOS processing after the SET_KEY. As of now, it is
 * not required as we are ok with tspec getting programmed before set_key
 * as the roam timings are measured without tspec in reassoc!
 */
QDF_STATUS sme_qos_process_set_key_success_ind(tpAniSirGlobal pMac,
					       uint8_t sessionId, void *pEvent_info)
{
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
		  "########### Set Key Complete #############");
	(void)sme_qos_process_buffered_cmd(sessionId);
	return QDF_STATUS_SUCCESS;
}

#ifdef FEATURE_WLAN_ESE
/**
 * sme_qos_ese_save_tspec_response() - save TSPEC parameters.
 * @pMac: Pointer to the global MAC parameter structure.
 * @sessionId: SME session ID
 * @pTspec: Pointer to the TSPEC IE from the reassoc rsp
 * @ac:  Access Category for which this TSPEC rsp is received
 * @tspecIndex: flow/direction
 *
 * This function saves the TSPEC parameters that came along in the TSPEC IE
 * in the reassoc response
 *
 * Return: QDF_STATUS_SUCCESS - Release is successful.
 */
static QDF_STATUS
sme_qos_ese_save_tspec_response(tpAniSirGlobal pMac, uint8_t sessionId,
				tDot11fIEWMMTSPEC *pTspec, uint8_t ac,
				uint8_t tspecIndex)
{
	tpSirAddtsRsp pAddtsRsp =
		&sme_qos_cb.sessionInfo[sessionId].ac_info[ac].addTsRsp[tspecIndex];

	ac = sme_qos_u_pto_ac_map[pTspec->user_priority];

	qdf_mem_zero(pAddtsRsp, sizeof(tSirAddtsRsp));

	pAddtsRsp->messageType = eWNI_SME_ADDTS_RSP;
	pAddtsRsp->length = sizeof(tSirAddtsRsp);
	pAddtsRsp->rc = eSIR_SUCCESS;
	pAddtsRsp->sessionId = sessionId;
	pAddtsRsp->rsp.dialogToken = 0;
	pAddtsRsp->rsp.status = eSIR_SUCCESS;
	pAddtsRsp->rsp.wmeTspecPresent = pTspec->present;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
		  "%s: Copy Tspec to local data structure ac=%d, tspecIdx=%d",
		  __func__, ac, tspecIndex);

	if (pAddtsRsp->rsp.wmeTspecPresent) {
		/* Copy TSPEC params received in assoc response to addts response */
		convert_wmmtspec(pMac, &pAddtsRsp->rsp.tspec, pTspec);
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_ese_process_reassoc_tspec_rsp() - process ese reassoc tspec response
 * @pMac: Pointer to the global MAC parameter structure.
 * @sessionId: SME session ID
 * @pEven_info: Pointer to the smeJoinRsp structure
 *
 * This function processes the WMM TSPEC IE in the reassoc response.
 * Reassoc triggered as part of ESE roaming to another ESE capable AP.
 * If the TSPEC was added before reassoc, as part of Call Admission Control,
 * the reasso req from the STA would carry the TSPEC parameters which were
 * already negotiated with the older AP.
 *
 * Return: QDF_STATUS_SUCCESS - Release is successful.
 */
static
QDF_STATUS sme_qos_ese_process_reassoc_tspec_rsp(tpAniSirGlobal pMac,
						 uint8_t sessionId,
						 void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	tDot11fIEWMMTSPEC *pTspecIE = NULL;
	tCsrRoamSession *pCsrSession = NULL;
	tCsrRoamConnectedInfo *pCsrConnectedInfo = NULL;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	uint8_t ac, numTspec, cnt;
	uint8_t tspec_flow_index, tspec_mask_status;
	uint32_t tspecIeLen;

	pCsrSession = CSR_GET_SESSION(pMac, sessionId);
	if (NULL == pCsrSession) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("session %d not found"), sessionId);
		return QDF_STATUS_E_FAILURE;
	}
	pCsrConnectedInfo = &pCsrSession->connectedInfo;
	pSession = &sme_qos_cb.sessionInfo[sessionId];

	/* Get the TSPEC IEs which came along with the reassoc response */
	/* from the pbFrames pointer */
	pTspecIE =
		(tDot11fIEWMMTSPEC *) (pCsrConnectedInfo->pbFrames +
				       pCsrConnectedInfo->nBeaconLength +
				       pCsrConnectedInfo->nAssocReqLength +
				       pCsrConnectedInfo->nAssocRspLength +
				       pCsrConnectedInfo->nRICRspLength);

	/* Get the number of tspecs Ies in the frame, the min length */
	/* should be atleast equal to the one TSPEC IE */
	tspecIeLen = pCsrConnectedInfo->nTspecIeLength;
	if (tspecIeLen < sizeof(tDot11fIEWMMTSPEC)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("ESE Tspec IE len %d less than min %zu"),
			  tspecIeLen, sizeof(tDot11fIEWMMTSPEC));
		return QDF_STATUS_E_FAILURE;
	}

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
		  "TspecLen = %d, pbFrames = %p, pTspecIE = %p",
		  tspecIeLen, pCsrConnectedInfo->pbFrames, pTspecIE);

	numTspec = (tspecIeLen) / sizeof(tDot11fIEWMMTSPEC);
	for (cnt = 0; cnt < numTspec; cnt++) {
		ac = sme_qos_up_to_ac(pTspecIE->user_priority);
		if (ac >= SME_QOS_EDCA_AC_MAX) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  FL("ac %d more than it`s max value"), ac);
			return QDF_STATUS_E_FAILURE;
		}
		pACInfo = &pSession->ac_info[ac];
		tspec_mask_status = pACInfo->tspec_mask_status;
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
			  FL("UP=%d, ac=%d, tspec_mask_status=%x"),
			  pTspecIE->user_priority, ac, tspec_mask_status);

		for (tspec_flow_index = 0;
		     tspec_flow_index < SME_QOS_TSPEC_INDEX_MAX;
		     tspec_flow_index++) {
			if (tspec_mask_status & (1 << tspec_flow_index)) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_WARN,
					  FL
						  ("Found Tspec entry flow = %d AC = %d"),
					  tspec_flow_index, ac);
				sme_qos_ese_save_tspec_response(pMac, sessionId,
								pTspecIE, ac,
								tspec_flow_index);
			} else {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_WARN,
					  FL
						  ("Not found Tspec entry flow = %d AC = %d"),
					  tspec_flow_index, ac);
			}
		}
		/* Increment the pointer to point it to the next TSPEC IE */
		pTspecIE++;
	}

	/* Send the Aggregated QoS request to HAL */
	status = sme_qos_ft_aggr_qos_req(pMac, sessionId);

	return status;
}

/**
 * sme_qos_copy_tspec_info() - copy tspec info.
 * @pMac: Pointer to the global MAC parameter structure.
 * @pTspec_Info: source structure
 * @pTspec: destination structure
 *
 * This function copies the existing TSPEC parameters from the source structure
 * to the destination structure.
 *
 * Return: None
 */
static void sme_qos_copy_tspec_info(tpAniSirGlobal pMac,
				    sme_QosWmmTspecInfo *pTspec_Info,
				    tSirMacTspecIE *pTspec)
{
	/* As per WMM_AC_testplan_v0.39 Minimum Service Interval, Maximum Service
	 * Interval, Service Start Time, Suspension Interval and Delay Bound are
	 * all intended for HCCA operation and therefore must be set to zero*/
	pTspec->delayBound = pTspec_Info->delay_bound;
	pTspec->inactInterval = pTspec_Info->inactivity_interval;
	pTspec->length = SME_QOS_TSPEC_IE_LENGTH;
	pTspec->maxBurstSz = pTspec_Info->max_burst_size;
	pTspec->maxMsduSz = pTspec_Info->maximum_msdu_size;
	pTspec->maxSvcInterval = pTspec_Info->max_service_interval;
	pTspec->meanDataRate = pTspec_Info->mean_data_rate;
	pTspec->mediumTime = pTspec_Info->medium_time;
	pTspec->minDataRate = pTspec_Info->min_data_rate;
	pTspec->minPhyRate = pTspec_Info->min_phy_rate;
	pTspec->minSvcInterval = pTspec_Info->min_service_interval;
	pTspec->nomMsduSz = pTspec_Info->nominal_msdu_size;
	pTspec->peakDataRate = pTspec_Info->peak_data_rate;
	pTspec->surplusBw = pTspec_Info->surplus_bw_allowance;
	pTspec->suspendInterval = pTspec_Info->suspension_interval;
	pTspec->svcStartTime = pTspec_Info->svc_start_time;
	pTspec->tsinfo.traffic.direction = pTspec_Info->ts_info.direction;

	/* Make sure UAPSD is allowed */
	if (pTspec_Info->ts_info.psb) {
		pTspec->tsinfo.traffic.psb = pTspec_Info->ts_info.psb;
	} else {
		pTspec->tsinfo.traffic.psb = 0;
		pTspec_Info->ts_info.psb = 0;
	}
	pTspec->tsinfo.traffic.tsid = pTspec_Info->ts_info.tid;
	pTspec->tsinfo.traffic.userPrio = pTspec_Info->ts_info.up;
	pTspec->tsinfo.traffic.accessPolicy = SME_QOS_ACCESS_POLICY_EDCA;
	pTspec->tsinfo.traffic.burstSizeDefn =
		pTspec_Info->ts_info.burst_size_defn;
	pTspec->tsinfo.traffic.ackPolicy = pTspec_Info->ts_info.ack_policy;
	pTspec->type = SME_QOS_TSPEC_IE_TYPE;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: up = %d, tid = %d",
		  __func__, __LINE__,
		  pTspec_Info->ts_info.up, pTspec_Info->ts_info.tid);
}

/**
 * sme_qos_ese_retrieve_tspec_info() - retrieve tspec info.
 * @pMac: Pointer to the global MAC parameter structure.
 * @sessionId: SME session ID
 * @pTspecInfo: Pointer to the structure to carry back the TSPEC parameters
 *
 * This function is called by CSR when try to create reassoc request message to
 * PE - csrSendSmeReassocReqMsg. This functions get the existing tspec
 * parameters to be included in the reassoc request.
 *
 * Return: uint8_t - number of existing negotiated TSPECs
 */
uint8_t sme_qos_ese_retrieve_tspec_info(tpAniSirGlobal mac_ctx,
	 uint8_t session_id, tTspecInfo *tspec_info)
{
	sme_QosSessionInfo *session;
	sme_QosACInfo *ac_info;
	uint8_t ac, num_tspec = 0;
	tTspecInfo *dst_tspec = tspec_info;
	uint8_t tspec_mask;
	uint8_t tspec_pending;

	/*
	 * TODO: Check if TSPEC has already been established
	 * if not return
	 */
	session = &sme_qos_cb.sessionInfo[session_id];
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		volatile uint8_t index = 0;
		ac_info = &session->ac_info[ac];
		tspec_pending = ac_info->tspec_pending;
		tspec_mask = ac_info->tspec_mask_status;
		do {
			/*
			 * If a tspec status is pending, take
			 * requested_QoSInfo for RIC request,
			 * else use curr_QoSInfo for the
			 * RIC request
			 */
			if ((tspec_mask & SME_QOS_TSPEC_MASK_BIT_1_SET)
				&& (tspec_pending &
				SME_QOS_TSPEC_MASK_BIT_1_SET)){
				sme_qos_copy_tspec_info(mac_ctx,
					&ac_info->requested_QoSInfo[index],
					&dst_tspec->tspec);
				dst_tspec->valid = true;
				num_tspec++;
				dst_tspec++;
			} else if ((tspec_mask & SME_QOS_TSPEC_MASK_BIT_1_SET)
				&& !(tspec_pending &
				SME_QOS_TSPEC_MASK_BIT_1_SET)){
				sme_qos_copy_tspec_info(mac_ctx,
					&ac_info->curr_QoSInfo[index],
					&dst_tspec->tspec);
				dst_tspec->valid = true;
				num_tspec++;
				dst_tspec++;
			}
			tspec_mask >>= 1;
			tspec_pending >>= 1;
			index++;
		} while (tspec_mask);
	}
	return num_tspec;
}

#endif

static
QDF_STATUS sme_qos_create_tspec_ricie(tpAniSirGlobal pMac,
				      sme_QosWmmTspecInfo *pTspec_Info,
				      uint8_t *pRICBuffer, uint32_t *pRICLength,
				      uint8_t *pRICIdentifier)
{
	tDot11fIERICDataDesc ricIE;
	uint32_t nStatus;

	if (pRICBuffer == NULL || pRICIdentifier == NULL || pRICLength == NULL) {
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}

	qdf_mem_zero(&ricIE, sizeof(tDot11fIERICDataDesc));

	ricIE.present = 1;
	ricIE.RICData.present = 1;
	ricIE.RICData.resourceDescCount = 1;
	ricIE.RICData.statusCode = 0;
	ricIE.RICData.Identifier = sme_qos_assign_dialog_token();
#ifndef USE_80211_WMMTSPEC_FOR_RIC
	ricIE.TSPEC.present = 1;
	ricIE.TSPEC.delay_bound = pTspec_Info->delay_bound;
	ricIE.TSPEC.inactivity_int = pTspec_Info->inactivity_interval;
	ricIE.TSPEC.burst_size = pTspec_Info->max_burst_size;
	ricIE.TSPEC.max_msdu_size = pTspec_Info->maximum_msdu_size;
	ricIE.TSPEC.max_service_int = pTspec_Info->max_service_interval;
	ricIE.TSPEC.mean_data_rate = pTspec_Info->mean_data_rate;
	ricIE.TSPEC.medium_time = 0;
	ricIE.TSPEC.min_data_rate = pTspec_Info->min_data_rate;
	ricIE.TSPEC.min_phy_rate = pTspec_Info->min_phy_rate;
	ricIE.TSPEC.min_service_int = pTspec_Info->min_service_interval;
	ricIE.TSPEC.size = pTspec_Info->nominal_msdu_size;
	ricIE.TSPEC.peak_data_rate = pTspec_Info->peak_data_rate;
	ricIE.TSPEC.surplus_bw_allowance = pTspec_Info->surplus_bw_allowance;
	ricIE.TSPEC.suspension_int = pTspec_Info->suspension_interval;
	ricIE.TSPEC.service_start_time = pTspec_Info->svc_start_time;
	ricIE.TSPEC.direction = pTspec_Info->ts_info.direction;
	/* Make sure UAPSD is allowed */
	if (pTspec_Info->ts_info.psb) {
		ricIE.TSPEC.psb = pTspec_Info->ts_info.psb;
	} else {
		ricIE.TSPEC.psb = 0;
	}
	ricIE.TSPEC.tsid = pTspec_Info->ts_info.tid;
	ricIE.TSPEC.user_priority = pTspec_Info->ts_info.up;
	ricIE.TSPEC.access_policy = SME_QOS_ACCESS_POLICY_EDCA;

	*pRICIdentifier = ricIE.RICData.Identifier;

	nStatus =
		dot11f_pack_ie_ric_data_desc(pMac, &ricIE, pRICBuffer, sizeof(ricIE),
					     pRICLength);
	if (DOT11F_FAILED(nStatus)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL
				  ("Packing of RIC Data of length %d failed with status %d"),
			  *pRICLength, nStatus);
	}
#else                           /* WMM TSPEC */
	/*As per WMM_AC_testplan_v0.39 Minimum Service Interval, Maximum Service
	   Interval, Service Start Time, Suspension Interval and Delay Bound are
	   all intended for HCCA operation and therefore must be set to zero */
	ricIE.WMMTSPEC.present = 1;
	ricIE.WMMTSPEC.version = 1;
	ricIE.WMMTSPEC.delay_bound = pTspec_Info->delay_bound;
	ricIE.WMMTSPEC.inactivity_int = pTspec_Info->inactivity_interval;
	ricIE.WMMTSPEC.burst_size = pTspec_Info->max_burst_size;
	ricIE.WMMTSPEC.max_msdu_size = pTspec_Info->maximum_msdu_size;
	ricIE.WMMTSPEC.max_service_int = pTspec_Info->max_service_interval;
	ricIE.WMMTSPEC.mean_data_rate = pTspec_Info->mean_data_rate;
	ricIE.WMMTSPEC.medium_time = 0;
	ricIE.WMMTSPEC.min_data_rate = pTspec_Info->min_data_rate;
	ricIE.WMMTSPEC.min_phy_rate = pTspec_Info->min_phy_rate;
	ricIE.WMMTSPEC.min_service_int = pTspec_Info->min_service_interval;
	ricIE.WMMTSPEC.size = pTspec_Info->nominal_msdu_size;
	ricIE.WMMTSPEC.peak_data_rate = pTspec_Info->peak_data_rate;
	ricIE.WMMTSPEC.surplus_bw_allowance = pTspec_Info->surplus_bw_allowance;
	ricIE.WMMTSPEC.suspension_int = pTspec_Info->suspension_interval;
	ricIE.WMMTSPEC.service_start_time = pTspec_Info->svc_start_time;
	ricIE.WMMTSPEC.direction = pTspec_Info->ts_info.direction;
	/* Make sure UAPSD is allowed */
	if (pTspec_Info->ts_info.psb) {
		ricIE.WMMTSPEC.psb = pTspec_Info->ts_info.psb;
	} else {
		ricIE.WMMTSPEC.psb = 0;
	}
	ricIE.WMMTSPEC.tsid = pTspec_Info->ts_info.tid;
	ricIE.WMMTSPEC.user_priority = pTspec_Info->ts_info.up;
	ricIE.WMMTSPEC.access_policy = SME_QOS_ACCESS_POLICY_EDCA;

	nStatus =
		dot11f_pack_ie_ric_data_desc(pMac, &ricIE, pRICBuffer, sizeof(ricIE),
					     pRICLength);
	if (DOT11F_FAILED(nStatus)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL
				  ("Packing of RIC Data of length %d failed with status %d"),
			  *pRICLength, nStatus);
	}
#endif /* 80211_TSPEC */
	*pRICIdentifier = ricIE.RICData.Identifier;
	return nStatus;
}
/**
 * sme_qos_process_ft_reassoc_req_ev()- processes reassoc request
 *
 * @session_id: SME Session Id
 *
 * This function Process reassoc request related to QOS
 *
 * Return: QDF_STATUS enumeration value.
 */
static QDF_STATUS sme_qos_process_ft_reassoc_req_ev(
	uint8_t sessionId)
{
	sme_QosSessionInfo *session;
	sme_QosACInfo *ac_info;
	uint8_t ac, qos_requested = false;
	uint8_t tspec_index;
	sme_QosFlowInfoEntry *flow_info = NULL;
	tListElem *entry = NULL;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		FL("Invoked on session %d"), sessionId);

	session = &sme_qos_cb.sessionInfo[sessionId];

	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		ac_info = &session->ac_info[ac];
		qos_requested = false;

		for (tspec_index = 0;
			tspec_index < SME_QOS_TSPEC_INDEX_MAX;
			tspec_index++) {
			/*
			 * Only in the below case, copy the AC's curr
			 * QoS Info to requested QoS info
			 */
			if ((ac_info->ricIdentifier[tspec_index]
				&& !ac_info->tspec_pending)
				|| (ac_info->
				tspec_mask_status & (1 << tspec_index))) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					QDF_TRACE_LEVEL_INFO,
					FL("Copying the currentQos to "
					"requestedQos for AC=%d, flow=%d"),
					ac, tspec_index);

				ac_info->requested_QoSInfo[tspec_index] =
					ac_info->curr_QoSInfo[tspec_index];
				qdf_mem_zero(
					&ac_info->curr_QoSInfo[tspec_index],
					sizeof(sme_QosWmmTspecInfo));
				qos_requested = true;
			}
		}

		/*
		 * Only if the tspec is required, transition the state to
		 * SME_QOS_REQUESTED for this AC
		 */
		if (qos_requested) {
			switch (ac_info->curr_state) {
			case SME_QOS_HANDOFF:
				sme_qos_state_transition(sessionId, ac,
					SME_QOS_REQUESTED);
				break;
			default:
				QDF_TRACE(QDF_MODULE_ID_SME,
					QDF_TRACE_LEVEL_ERROR,
					FL("FT Reassoc req event in"
					" unexpected state %d"),
					ac_info->curr_state);
				QDF_ASSERT(0);
			}
		}
	}

	/*
	 * At this point of time, we are
	 * disconnected from the old AP, so it is safe
	 * to reset all these session variables
	 */
	session->apsdMask = 0;
	session->uapsdAlreadyRequested = 0;
	session->readyForPowerSave = 0;

	/*
	 * Now change reason and HO renewal of
	 * all the flow in this session only
	 */
	entry = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!entry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
			FL("Flow List empty, nothing to update"));
		return QDF_STATUS_E_FAILURE;
	}

	do {
		flow_info = GET_BASE_ADDR(entry, sme_QosFlowInfoEntry, link);
		if (sessionId == flow_info->sessionId) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				FL("Changing FlowID %d reason to SETUP"
				"and HO renewal to false"),
				flow_info->QosFlowID);
			flow_info->reason = SME_QOS_REASON_SETUP;
			flow_info->hoRenewal = true;
		}
		entry = csr_ll_next(&sme_qos_cb.flow_list, entry, false);
	} while (entry);

	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_fill_aggr_info - fill QOS Aggregation info
 *
 * @ac_id - index to the AC
 * @ts_id - index to TS for a given AC
 * @direction - traffic direction
 * @msg - QOS message
 * @session - sme session information
 *
 * this is a helper function to populate aggregation information
 * for QOS message.
 *
 * Return: None
 */
static void sme_qos_fill_aggr_info(int ac_id, int ts_id,
				   sme_QosWmmDirType direction,
				   tSirAggrQosReq *msg,
				   sme_QosSessionInfo *session)
{
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
		  FL("Found tspec entry AC=%d, flow=%d, direction = %d"),
		  ac_id, ts_id, direction);

	msg->aggrInfo.aggrAddTsInfo[ac_id].dialogToken =
			sme_qos_assign_dialog_token();
	msg->aggrInfo.aggrAddTsInfo[ac_id].lleTspecPresent =
		session->ac_info[ac_id].addTsRsp[ts_id].rsp.lleTspecPresent;
	msg->aggrInfo.aggrAddTsInfo[ac_id].numTclas =
		session->ac_info[ac_id].addTsRsp[ts_id].rsp.numTclas;
	qdf_mem_copy(msg->aggrInfo.aggrAddTsInfo[ac_id].tclasInfo,
		     session->ac_info[ac_id].addTsRsp[ts_id].rsp.tclasInfo,
		     SIR_MAC_TCLASIE_MAXNUM);
	msg->aggrInfo.aggrAddTsInfo[ac_id].tclasProc =
		session->ac_info[ac_id].addTsRsp[ts_id].rsp.tclasProc;
	msg->aggrInfo.aggrAddTsInfo[ac_id].tclasProcPresent =
		session->ac_info[ac_id].addTsRsp[ts_id].rsp.tclasProcPresent;
	msg->aggrInfo.aggrAddTsInfo[ac_id].tspec =
		session->ac_info[ac_id].addTsRsp[ts_id].rsp.tspec;
	msg->aggrInfo.aggrAddTsInfo[ac_id].wmeTspecPresent =
		session->ac_info[ac_id].addTsRsp[ts_id].rsp.wmeTspecPresent;
	msg->aggrInfo.aggrAddTsInfo[ac_id].wsmTspecPresent =
		session->ac_info[ac_id].addTsRsp[ts_id].rsp.wsmTspecPresent;
	msg->aggrInfo.tspecIdx |= (1 << ac_id);

	/* Mark the index for this AC as pending for response, which would be */
	/* used to validate the AddTS response from HAL->PE->SME */
	session->ac_info[ac_id].tspec_pending = (1 << ts_id);

	return;
}

/**
 * sme_qos_ft_aggr_qos_req - send aggregated QOS request
 *
 * @mac_ctx - global MAC context
 * @session_id - sme session Id
 *
 * This function is used to send aggregated QOS request to HAL.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_ft_aggr_qos_req(tpAniSirGlobal mac_ctx, uint8_t session_id)
{
	tSirAggrQosReq *aggr_req = NULL;
	sme_QosSessionInfo *session;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	int i, j = 0;
	uint8_t direction;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  FL("invoked on session %d"), session_id);

	session = &sme_qos_cb.sessionInfo[session_id];

	aggr_req = (tSirAggrQosReq *) qdf_mem_malloc(sizeof(tSirAggrQosReq));

	if (!aggr_req) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("couldn't allocate memory for the msg buffer"));
		return QDF_STATUS_E_NOMEM;
	}

	aggr_req->messageType = eWNI_SME_FT_AGGR_QOS_REQ;
	aggr_req->length = sizeof(tSirAggrQosReq);
	aggr_req->sessionId = session_id;
	aggr_req->timeout = 0;
	aggr_req->rspReqd = true;
	qdf_mem_copy(&aggr_req->bssid.bytes[0],
		     &session->assocInfo.pBssDesc->bssId[0],
		     sizeof(struct qdf_mac_addr));

	for (i = 0; i < SME_QOS_EDCA_AC_MAX; i++) {
		for (j = 0; j < SME_QOS_TSPEC_INDEX_MAX; j++) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
				  FL("ac=%d, tspec_mask_staus=%x, tspec_index=%d"),
				  i, session->ac_info[i].tspec_mask_status, j);
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
				  FL("direction = %d"),
				  session->ac_info[i].addTsRsp[j].rsp.tspec.
				  tsinfo.traffic.direction);
			/* Check if any flow is active on this AC */
			if (!((session->ac_info[i].tspec_mask_status) &
			     (1 << j)))
				continue;

			direction = session->ac_info[i].addTsRsp[j].rsp.tspec.
					tsinfo.traffic.direction;

			if ((direction == SME_QOS_WMM_TS_DIR_UPLINK) ||
			    (direction == SME_QOS_WMM_TS_DIR_BOTH)) {
					sme_qos_fill_aggr_info(i, j, direction,
						aggr_req, session);
			}
		}
	}

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
		  FL("Sending aggregated message to HAL 0x%x"),
		  aggr_req->aggrInfo.tspecIdx);

	if (QDF_IS_STATUS_SUCCESS(cds_send_mb_message_to_mac(aggr_req))) {
		status = QDF_STATUS_SUCCESS;
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  FL("sent down a AGGR QoS req to PE"));
	}

	return status;
}

static
QDF_STATUS sme_qos_process_ftric_response(tpAniSirGlobal pMac,
					  uint8_t sessionId,
					  tDot11fIERICDataDesc *pRicDataDesc,
					  uint8_t ac, uint8_t tspecIndex)
{
	uint8_t i = 0;
	tpSirAddtsRsp pAddtsRsp
		=
			&sme_qos_cb.sessionInfo[sessionId].ac_info[ac].addTsRsp[tspecIndex];

	qdf_mem_zero(pAddtsRsp, sizeof(tSirAddtsRsp));

	pAddtsRsp->messageType = eWNI_SME_ADDTS_RSP;
	pAddtsRsp->length = sizeof(tSirAddtsRsp);
	pAddtsRsp->rc = pRicDataDesc->RICData.statusCode;
	pAddtsRsp->sessionId = sessionId;
	pAddtsRsp->rsp.dialogToken = pRicDataDesc->RICData.Identifier;
	pAddtsRsp->rsp.status = pRicDataDesc->RICData.statusCode;
	pAddtsRsp->rsp.wmeTspecPresent = pRicDataDesc->TSPEC.present;
	if (pAddtsRsp->rsp.wmeTspecPresent) {
		/* Copy TSPEC params received in RIC response to addts response */
		convert_tspec(pMac, &pAddtsRsp->rsp.tspec, &pRicDataDesc->TSPEC);
	}

	pAddtsRsp->rsp.numTclas = pRicDataDesc->num_TCLAS;
	if (pAddtsRsp->rsp.numTclas) {
		for (i = 0; i < pAddtsRsp->rsp.numTclas; i++) {
			/* Copy TCLAS info per index to the addts response */
			convert_tclas(pMac, &pAddtsRsp->rsp.tclasInfo[i],
				      &pRicDataDesc->TCLAS[i]);
		}
	}

	pAddtsRsp->rsp.tclasProcPresent = pRicDataDesc->TCLASSPROC.present;
	if (pAddtsRsp->rsp.tclasProcPresent)
		pAddtsRsp->rsp.tclasProc = pRicDataDesc->TCLASSPROC.processing;

	pAddtsRsp->rsp.schedulePresent = pRicDataDesc->Schedule.present;
	if (pAddtsRsp->rsp.schedulePresent) {
		/* Copy Schedule IE params to addts response */
		convert_schedule(pMac, &pAddtsRsp->rsp.schedule,
				 &pRicDataDesc->Schedule);
	}
	/* Need to check the below portion is a part of WMM TSPEC */
	/* Process Delay element */
	if (pRicDataDesc->TSDelay.present)
		convert_ts_delay(pMac, &pAddtsRsp->rsp.delay,
				 &pRicDataDesc->TSDelay);

	/* Need to call for WMMTSPEC */
	if (pRicDataDesc->WMMTSPEC.present) {
		convert_wmmtspec(pMac, &pAddtsRsp->rsp.tspec,
				 &pRicDataDesc->WMMTSPEC);
	}
	/* return sme_qos_process_add_ts_rsp(pMac, &addtsRsp); */
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_process_aggr_qos_rsp - process qos aggregation response
 *
 * @mac_ctx - global mac context
 * @msgbuf - SME message buffer
 *
 * this function process the QOS aggregation response received.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_process_aggr_qos_rsp(tpAniSirGlobal mac_ctx, void *msgbuf)
{
	tpSirAggrQosRsp rsp = (tpSirAggrQosRsp) msgbuf;
	tSirAddtsRsp addtsrsp;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	int i, j = 0;
	uint8_t sessionid = rsp->sessionId;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
		  FL("Received AGGR_QOS resp from LIM"));

	/* Copy the updated response information for TSPEC of all the ACs */
	for (i = 0; i < SIR_QOS_NUM_AC_MAX; i++) {
		uint8_t tspec_mask_status =
			sme_qos_cb.sessionInfo[sessionid].ac_info[i].
			tspec_mask_status;
		for (j = 0; j < SME_QOS_TSPEC_INDEX_MAX; j++) {
			uint8_t direction =
				sme_qos_cb.sessionInfo[sessionid].
				ac_info[i].addTsRsp[j].rsp.tspec.tsinfo.traffic.
				direction;

			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
				  FL("Addts rsp from LIM AC=%d, flow=%d dir=%d, tspecIdx=%x"),
				  i, j, direction, rsp->aggrInfo.tspecIdx);

			/* Check if the direction is Uplink or bi-directional */
			if (!(((1 << i) & rsp->aggrInfo.tspecIdx) &&
			    ((tspec_mask_status) & (1 << j)) &&
			    ((direction == SME_QOS_WMM_TS_DIR_UPLINK) ||
			     (direction == SME_QOS_WMM_TS_DIR_BOTH)))) {
				continue;
			}
			addtsrsp =
				sme_qos_cb.sessionInfo[sessionid].ac_info[i].
				addTsRsp[j];
			addtsrsp.rc = rsp->aggrInfo.aggrRsp[i].status;
			addtsrsp.rsp.status = rsp->aggrInfo.aggrRsp[i].status;
			addtsrsp.rsp.tspec = rsp->aggrInfo.aggrRsp[i].tspec;

			QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_INFO,
				  FL("Processing Addts rsp from LIM AC=%d, flow=%d"),
				  i, j);
			/* post ADD TS response for each */
			if (sme_qos_process_add_ts_rsp(mac_ctx, &addtsrsp) !=
			    QDF_STATUS_SUCCESS)
				status = QDF_STATUS_E_FAILURE;
		}
	}
	return status;
}

/**
 * sme_qos_find_matching_tspec() - utility function to find matching tspec
 * @mac_ctx: global MAC context
 * @sessionid: session ID
 * @ac: AC index
 * @ac_info: Current AC info
 * @ric_data_desc: pointer to ric data
 * @ric_rsplen: pointer to ric response length
 *
 * This utility function is called by sme_qos_process_ft_reassoc_rsp_ev
 * to find the matching tspec
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sme_qos_find_matching_tspec(tpAniSirGlobal mac_ctx,
		uint8_t sessionid, uint8_t ac, sme_QosACInfo *ac_info,
		tDot11fIERICDataDesc *ric_data_desc, uint32_t *ric_rsplen)
{
	uint8_t tspec_flow_index;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
			FL("invoked on session %d"), sessionid);

	for (tspec_flow_index = 0;
	     tspec_flow_index < SME_QOS_TSPEC_INDEX_MAX; tspec_flow_index++) {
		/*
		 * Only in the below case, copy the AC's curr QoS Info
		 * to requested QoS info
		 */
		if (!ac_info->ricIdentifier[tspec_flow_index])
			continue;

		if (!*ric_rsplen) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("RIC Response not received for AC %d on "
			  "TSPEC Index %d, RIC Req Identifier = %d"),
			  ac, tspec_flow_index,
			  ac_info->ricIdentifier[tspec_flow_index]);
			QDF_ASSERT(0);
			continue;
		}
		/* Now we got response for this identifier. Process it. */
		if (!ric_data_desc->present)
			continue;
		if (!ric_data_desc->RICData.present)
			continue;

		if (ric_data_desc->RICData.Identifier !=
			ac_info->ricIdentifier[tspec_flow_index]) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("RIC response order not same as request sent. "
			  "Request ID = %d, Response ID = %d"),
			  ac_info->ricIdentifier[tspec_flow_index],
			  ric_data_desc->RICData.Identifier);
			QDF_ASSERT(0);
		} else {
			QDF_TRACE(QDF_MODULE_ID_SME,
			  QDF_TRACE_LEVEL_INFO,
			  FL("Processing RIC Response for AC %d, "
			  "TSPEC Flow index %d with RIC ID %d "),
			  ac, tspec_flow_index,
			  ric_data_desc->RICData.Identifier);
			status = sme_qos_process_ftric_response(mac_ctx,
					sessionid, ric_data_desc, ac,
					tspec_flow_index);
			if (QDF_STATUS_SUCCESS != status) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_ERROR,
				  FL("Failed with status %d for AC %d in "
				  "TSPEC Flow index = %d"),
				  status, ac, tspec_flow_index);
			}
		}
		ric_data_desc++;
		*ric_rsplen -= sizeof(tDot11fIERICDataDesc);
	}
	return status;
}

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
/**
 * sme_qos_find_matching_tspec_lfr3() - utility function to find matching tspec
 * @mac_ctx: global MAC context
 * @sessionid: session ID
 * @ac: AC index
 * @qos_session: QOS session
 * @ric_data_desc: pointer to ric data
 * @ric_rsplen: ric response length
 *
 * This utility function is called by sme_qos_process_ft_reassoc_rsp_ev
 * to find the matching tspec while LFR3 is enabled.
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sme_qos_find_matching_tspec_lfr3(tpAniSirGlobal mac_ctx,
		uint8_t sessionid, uint8_t ac, sme_QosSessionInfo *qos_session,
		tDot11fIERICDataDesc *ric_data_desc, uint32_t ric_rsplen)
{
	sme_QosACInfo *ac_info;
	uint8_t tspec_flow_idx;
	bool found = false;
	sme_QosWmmDirType direction, qos_dir;
	uint8_t ac1;
	tDot11fIERICDataDesc *ric_data = NULL;
	uint32_t ric_len;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
			FL("invoked on session %d"), sessionid);

	ric_data = ric_data_desc;
	ric_len = ric_rsplen;
	ac_info = &qos_session->ac_info[ac];
	for (tspec_flow_idx = 0; tspec_flow_idx < SME_QOS_TSPEC_INDEX_MAX;
	     tspec_flow_idx++) {
		if (!((qos_session->ac_info[ac].tspec_mask_status) &
		    (1 << tspec_flow_idx)))
			goto sme_qos_next_ric;
		qos_dir =
		  ac_info->requested_QoSInfo[tspec_flow_idx].ts_info.direction;
		do {
			ac1 = sme_qos_up_to_ac(
				ric_data->WMMTSPEC.user_priority);
			if (ac == SME_QOS_EDCA_AC_MAX) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_ERROR,
				  FL("Invalid AC %d UP %d"), ac,
				  ric_data->WMMTSPEC.user_priority);
				break;
			}
			direction = ric_data->WMMTSPEC.direction;
			if (ac == ac1 && direction == qos_dir) {
				found = true;
				status = sme_qos_process_ftric_response(mac_ctx,
						sessionid, ric_data, ac,
						tspec_flow_idx);
				if (QDF_STATUS_SUCCESS != status) {
					QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("Failed with status %d for AC %d "
					  "in TSPEC Flow index = %d"),
					  status, ac, tspec_flow_idx);
				}
				break;
			}
			ric_data++;
			ric_len -= sizeof(tDot11fIERICDataDesc);
		} while (ric_len);
sme_qos_next_ric:
		ric_data = ric_data_desc;
		ric_len = ric_rsplen;
		found = false;
	}

	return status;
}
#endif /* WLAN_FEATURE_ROAM_OFFLOAD */

static
QDF_STATUS sme_qos_process_ft_reassoc_rsp_ev(tpAniSirGlobal mac_ctx,
				uint8_t sessionid, void *event_info)
{
	sme_QosSessionInfo *qos_session;
	sme_QosACInfo *ac_info;
	uint8_t ac;
	tDot11fIERICDataDesc *ric_data_desc = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	tCsrRoamSession *csr_session = CSR_GET_SESSION(mac_ctx, sessionid);
	tCsrRoamConnectedInfo *csr_conn_info = NULL;
	uint32_t ric_rsplen;
#ifdef WLAN_FEATURE_ROAM_OFFLOAD
	tDot11fIERICDataDesc *ric_data = NULL;
	uint32_t ric_len;
#endif

	if (NULL == csr_session) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("The Session pointer is NULL"));
		return QDF_STATUS_E_FAILURE;
	}
	csr_conn_info = &csr_session->connectedInfo;
	ric_rsplen = csr_conn_info->nRICRspLength;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  FL("invoked on session %d"), sessionid);

	qos_session = &sme_qos_cb.sessionInfo[sessionid];

	ric_data_desc = (tDot11fIERICDataDesc *) ((csr_conn_info->pbFrames) +
				(csr_conn_info->nBeaconLength +
				 csr_conn_info->nAssocReqLength +
				 csr_conn_info->nAssocRspLength));

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
	if (!csr_session->roam_synch_in_progress) {
#endif
		for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
			ac_info = &qos_session->ac_info[ac];
			sme_qos_find_matching_tspec(mac_ctx, sessionid, ac,
					ac_info, ric_data_desc, &ric_rsplen);
		}

		if (ric_rsplen) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				FL("RIC Resp still follows . Rem len = %d"),
				ric_rsplen);
			QDF_ASSERT(0);
		}
#ifdef WLAN_FEATURE_ROAM_OFFLOAD
	} else {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
			  FL("LFR3-11r Compare RIC in Reassoc Resp to find"
			     " matching tspec in host."));
		ric_data = ric_data_desc;
		ric_len = ric_rsplen;
		if (ric_rsplen && ric_data_desc->present &&
		    ric_data_desc->WMMTSPEC.present) {
			for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX;
			     ac++) {
				sme_qos_find_matching_tspec_lfr3(mac_ctx,
					sessionid, ac, qos_session, ric_data,
					ric_len);
			}
		} else {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
			  FL("LFR3-11r ric_rsplen is zero or ric_data_desc is"
			  " not present or wmmtspec is not present"));
		}
	}
#endif

	/* Send the Aggregated QoS request to HAL */
	status = sme_qos_ft_aggr_qos_req(mac_ctx, sessionid);

	return status;
}

/**
 * sme_qos_add_ts_req() - send ADDTS request.
 * @pMac: Pointer to the global MAC parameter structure.
 * @sessionId: Session upon which the TSPEC should be added
 * @pTspec_Info: Pointer to sme_QosWmmTspecInfo which contains the WMM
 *               TSPEC related info as defined above
 * @ac: Enumeration of the various EDCA Access Categories.
 *
 * This function is used to send down the ADDTS request with TSPEC params to PE
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_add_ts_req(tpAniSirGlobal pMac,
			      uint8_t sessionId,
			      sme_QosWmmTspecInfo *pTspec_Info,
			      sme_QosEdcaAcType ac)
{
	tSirAddtsReq *pMsg = NULL;
	sme_QosSessionInfo *pSession;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
#ifdef FEATURE_WLAN_ESE
	tCsrRoamSession *pCsrSession = CSR_GET_SESSION(pMac, sessionId);
#endif
#ifdef FEATURE_WLAN_DIAG_SUPPORT
	WLAN_HOST_DIAG_EVENT_DEF(qos, host_event_wlan_qos_payload_type);
#endif
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d for AC %d",
		  __func__, __LINE__, sessionId, ac);
	if (sessionId >= CSR_ROAM_SESSION_MAX) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: sessionId(%d) is invalid",
			  __func__, __LINE__, sessionId);
		return QDF_STATUS_E_FAILURE;
	}

	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pMsg = (tSirAddtsReq *) qdf_mem_malloc(sizeof(tSirAddtsReq));
	if (!pMsg) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: couldn't allocate memory for the msg buffer",
			  __func__, __LINE__);
		return QDF_STATUS_E_NOMEM;
	}
	pMsg->messageType = eWNI_SME_ADDTS_REQ;
	pMsg->length = sizeof(tSirAddtsReq);
	pMsg->sessionId = sessionId;
	pMsg->timeout = 0;
	pMsg->rspReqd = true;
	pMsg->req.dialogToken = sme_qos_assign_dialog_token();
	/*As per WMM_AC_testplan_v0.39 Minimum Service Interval, Maximum Service
	   Interval, Service Start Time, Suspension Interval and Delay Bound are
	   all intended for HCCA operation and therefore must be set to zero */
	pMsg->req.tspec.delayBound = 0;
	pMsg->req.tspec.inactInterval = pTspec_Info->inactivity_interval;
	pMsg->req.tspec.length = SME_QOS_TSPEC_IE_LENGTH;
	pMsg->req.tspec.maxBurstSz = pTspec_Info->max_burst_size;
	pMsg->req.tspec.maxMsduSz = pTspec_Info->maximum_msdu_size;
	pMsg->req.tspec.maxSvcInterval = pTspec_Info->max_service_interval;
	pMsg->req.tspec.meanDataRate = pTspec_Info->mean_data_rate;
	pMsg->req.tspec.mediumTime = pTspec_Info->medium_time;
	pMsg->req.tspec.minDataRate = pTspec_Info->min_data_rate;
	pMsg->req.tspec.minPhyRate = pTspec_Info->min_phy_rate;
	pMsg->req.tspec.minSvcInterval = pTspec_Info->min_service_interval;
	pMsg->req.tspec.nomMsduSz = pTspec_Info->nominal_msdu_size;
	pMsg->req.tspec.peakDataRate = pTspec_Info->peak_data_rate;
	pMsg->req.tspec.surplusBw = pTspec_Info->surplus_bw_allowance;
	pMsg->req.tspec.suspendInterval = pTspec_Info->suspension_interval;
	pMsg->req.tspec.svcStartTime = 0;
	pMsg->req.tspec.tsinfo.traffic.direction =
		pTspec_Info->ts_info.direction;
	/* Make sure UAPSD is allowed */
	if (pTspec_Info->ts_info.psb) {
		pMsg->req.tspec.tsinfo.traffic.psb = pTspec_Info->ts_info.psb;
	} else {
		pMsg->req.tspec.tsinfo.traffic.psb = 0;
		pTspec_Info->ts_info.psb = 0;
	}
	pMsg->req.tspec.tsinfo.traffic.tsid = pTspec_Info->ts_info.tid;
	pMsg->req.tspec.tsinfo.traffic.userPrio = pTspec_Info->ts_info.up;
	pMsg->req.tspec.tsinfo.traffic.accessPolicy =
		SME_QOS_ACCESS_POLICY_EDCA;
	pMsg->req.tspec.tsinfo.traffic.burstSizeDefn =
		pTspec_Info->ts_info.burst_size_defn;
	pMsg->req.tspec.tsinfo.traffic.ackPolicy =
		pTspec_Info->ts_info.ack_policy;
	pMsg->req.tspec.type = SME_QOS_TSPEC_IE_TYPE;
	/*Fill the BSSID pMsg->req.bssId */
	if (NULL == pSession->assocInfo.pBssDesc) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: BSS descriptor is NULL so we don't send request to PE",
			  __func__, __LINE__);
		qdf_mem_free(pMsg);
		return QDF_STATUS_E_FAILURE;
	}
	qdf_mem_copy(&pMsg->bssid.bytes[0],
		     &pSession->assocInfo.pBssDesc->bssId[0],
		     sizeof(struct qdf_mac_addr));
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: up = %d, tid = %d",
		  __func__, __LINE__,
		  pTspec_Info->ts_info.up, pTspec_Info->ts_info.tid);
#ifdef FEATURE_WLAN_ESE
	if (pCsrSession->connectedProfile.isESEAssoc) {
		pMsg->req.tsrsIE.tsid = pTspec_Info->ts_info.up;
		pMsg->req.tsrsPresent = 1;
	}
#endif
	if (QDF_IS_STATUS_SUCCESS(cds_send_mb_message_to_mac(pMsg))) {
		status = QDF_STATUS_SUCCESS;
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: sent down a ADDTS req to PE",
			  __func__, __LINE__);
		/* event: EVENT_WLAN_QOS */
#ifdef FEATURE_WLAN_DIAG_SUPPORT
		qos.eventId = SME_QOS_DIAG_ADDTS_REQ;
		qos.reasonCode = SME_QOS_DIAG_USER_REQUESTED;
		WLAN_HOST_DIAG_EVENT_REPORT(&qos, EVENT_WLAN_QOS);
#endif /* FEATURE_WLAN_DIAG_SUPPORT */
	}
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_del_ts_req() - To send down the DELTS request with TSPEC params
   to PE

   \param pMac - Pointer to the global MAC parameter structure.
   \param sessionId - Session from which the TSPEC should be deleted
   \param ac - Enumeration of the various EDCA Access Categories.
   \param tspec_mask - on which tspec per AC, the delts is requested

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_del_ts_req(tpAniSirGlobal pMac,
			      uint8_t sessionId,
			      sme_QosEdcaAcType ac, uint8_t tspec_mask)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	tSirDeltsReq *pMsg;
	sme_QosWmmTspecInfo *pTspecInfo;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
#ifdef FEATURE_WLAN_DIAG_SUPPORT
	WLAN_HOST_DIAG_EVENT_DEF(qos, host_event_wlan_qos_payload_type);
#endif
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d for AC %d",
		  __func__, __LINE__, sessionId, ac);
	pMsg = (tSirDeltsReq *) qdf_mem_malloc(sizeof(tSirDeltsReq));
	if (!pMsg) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: couldn't allocate memory for the msg buffer",
			  __func__, __LINE__);
		return QDF_STATUS_E_NOMEM;
	}
	/* get pointer to the TSPEC being deleted */
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pACInfo = &pSession->ac_info[ac];
	pTspecInfo = &pACInfo->curr_QoSInfo[tspec_mask - 1];
	pMsg->messageType = eWNI_SME_DELTS_REQ;
	pMsg->length = sizeof(tSirDeltsReq);
	pMsg->sessionId = sessionId;
	pMsg->rspReqd = true;
	pMsg->req.tspec.delayBound = pTspecInfo->delay_bound;
	pMsg->req.tspec.inactInterval = pTspecInfo->inactivity_interval;
	pMsg->req.tspec.length = SME_QOS_TSPEC_IE_LENGTH;
	pMsg->req.tspec.maxBurstSz = pTspecInfo->max_burst_size;
	pMsg->req.tspec.maxMsduSz = pTspecInfo->maximum_msdu_size;
	pMsg->req.tspec.maxSvcInterval = pTspecInfo->max_service_interval;
	pMsg->req.tspec.meanDataRate = pTspecInfo->mean_data_rate;
	pMsg->req.tspec.mediumTime = pTspecInfo->medium_time;
	pMsg->req.tspec.minDataRate = pTspecInfo->min_data_rate;
	pMsg->req.tspec.minPhyRate = pTspecInfo->min_phy_rate;
	pMsg->req.tspec.minSvcInterval = pTspecInfo->min_service_interval;
	pMsg->req.tspec.nomMsduSz = pTspecInfo->nominal_msdu_size;
	pMsg->req.tspec.peakDataRate = pTspecInfo->peak_data_rate;
	pMsg->req.tspec.surplusBw = pTspecInfo->surplus_bw_allowance;
	pMsg->req.tspec.suspendInterval = pTspecInfo->suspension_interval;
	pMsg->req.tspec.svcStartTime = pTspecInfo->svc_start_time;
	pMsg->req.tspec.tsinfo.traffic.direction =
		pTspecInfo->ts_info.direction;
	pMsg->req.tspec.tsinfo.traffic.psb = pTspecInfo->ts_info.psb;
	pMsg->req.tspec.tsinfo.traffic.tsid = pTspecInfo->ts_info.tid;
	pMsg->req.tspec.tsinfo.traffic.userPrio = pTspecInfo->ts_info.up;
	pMsg->req.tspec.tsinfo.traffic.accessPolicy =
		SME_QOS_ACCESS_POLICY_EDCA;
	pMsg->req.tspec.tsinfo.traffic.burstSizeDefn =
		pTspecInfo->ts_info.burst_size_defn;
	pMsg->req.tspec.tsinfo.traffic.ackPolicy =
		pTspecInfo->ts_info.ack_policy;
	pMsg->req.tspec.type = SME_QOS_TSPEC_IE_TYPE;
	/*Fill the BSSID pMsg->req.bssId */
	if (NULL == pSession->assocInfo.pBssDesc) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: BSS descriptor is NULL so we don't send request to PE",
			  __func__, __LINE__);
		qdf_mem_free(pMsg);
		return QDF_STATUS_E_FAILURE;
	}
	qdf_mem_copy(&pMsg->bssid.bytes[0],
		     &pSession->assocInfo.pBssDesc->bssId[0],
		     sizeof(struct qdf_mac_addr));

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: up = %d, tid = %d",
		  __func__, __LINE__,
		  pTspecInfo->ts_info.up, pTspecInfo->ts_info.tid);
	qdf_mem_zero(&pACInfo->curr_QoSInfo[tspec_mask - 1],
		     sizeof(sme_QosWmmTspecInfo));
	if (QDF_IS_STATUS_SUCCESS(cds_send_mb_message_to_mac(pMsg))) {
		status = QDF_STATUS_SUCCESS;
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: sme_qos_del_ts_req:Test: sent down a DELTS req to PE",
			  __func__, __LINE__);
		/* event: EVENT_WLAN_QOS */
#ifdef FEATURE_WLAN_DIAG_SUPPORT
		qos.eventId = SME_QOS_DIAG_DELTS;
		qos.reasonCode = SME_QOS_DIAG_USER_REQUESTED;
		WLAN_HOST_DIAG_EVENT_REPORT(&qos, EVENT_WLAN_QOS);
#endif /* FEATURE_WLAN_DIAG_SUPPORT */
	}
	sme_set_tspec_uapsd_mask_per_session(pMac,
			&pMsg->req.tspec.tsinfo,
			sessionId);

	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_add_ts_rsp() - Function to process the
   eWNI_SME_ADDTS_RSP came from PE

   \param pMac - Pointer to the global MAC parameter structure.
   \param pMsgBuf - Pointer to the msg buffer came from PE.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_add_ts_rsp(tpAniSirGlobal pMac, void *pMsgBuf)
{
	tpSirAddtsRsp paddts_rsp = (tpSirAddtsRsp) pMsgBuf;
	sme_QosSessionInfo *pSession;
	uint8_t sessionId = paddts_rsp->sessionId;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	sme_QosWmmUpType up =
		(sme_QosWmmUpType) paddts_rsp->rsp.tspec.tsinfo.traffic.userPrio;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType ac;
#ifdef FEATURE_WLAN_DIAG_SUPPORT
	WLAN_HOST_DIAG_EVENT_DEF(qos, host_event_wlan_qos_payload_type);
#endif

	pSession = &sme_qos_cb.sessionInfo[sessionId];

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d for UP %d",
		  __func__, __LINE__, sessionId, up);

	ac = sme_qos_up_to_ac(up);
	if (SME_QOS_EDCA_AC_MAX == ac) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: invalid AC %d from UP %d",
			  __func__, __LINE__, ac, up);

		return QDF_STATUS_E_FAILURE;
	}
	pACInfo = &pSession->ac_info[ac];
	if (SME_QOS_HANDOFF == pACInfo->curr_state) {
		sms_log(pMac, LOG1,
			FL
				("ADDTS Response received for AC %d in HANDOFF State.. Dropping"),
			ac);
		pSession->readyForPowerSave = true;
		return QDF_STATUS_SUCCESS;
	}

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: Invoked on session %d with return code %d",
		  __func__, __LINE__, sessionId, paddts_rsp->rc);
	/* our outstanding request has been serviced */
	/* we can go into powersave */
	pSession->readyForPowerSave = true;
	if (paddts_rsp->rc) {
		/* event: EVENT_WLAN_QOS */
#ifdef FEATURE_WLAN_DIAG_SUPPORT
		qos.eventId = SME_QOS_DIAG_ADDTS_RSP;
		qos.reasonCode = SME_QOS_DIAG_ADDTS_REFUSED;
		WLAN_HOST_DIAG_EVENT_REPORT(&qos, EVENT_WLAN_QOS);
#endif /* FEATURE_WLAN_DIAG_SUPPORT */
		status =
			sme_qos_process_add_ts_failure_rsp(pMac, sessionId,
							   &paddts_rsp->rsp);
	} else {
		status =
			sme_qos_process_add_ts_success_rsp(pMac, sessionId,
							   &paddts_rsp->rsp);
	}
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_del_ts_rsp() - Function to process the
   eWNI_SME_DELTS_RSP came from PE

   \param pMac - Pointer to the global MAC parameter structure.
   \param pMsgBuf - Pointer to the msg buffer came from PE.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_del_ts_rsp(tpAniSirGlobal pMac, void *pMsgBuf)
{
	tpSirDeltsRsp pDeltsRsp = (tpSirDeltsRsp) pMsgBuf;
	sme_QosSessionInfo *pSession;
	uint8_t sessionId = pDeltsRsp->sessionId;
	/* msg */
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: Invoked on session %d with return code %d",
		  __func__, __LINE__, sessionId, pDeltsRsp->rc);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	/* our outstanding request has been serviced */
	/* we can go into powersave */
	pSession->readyForPowerSave = true;
	(void)sme_qos_process_buffered_cmd(sessionId);
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_del_ts_ind() - Function to process the
   eWNI_SME_DELTS_IND came from PE

   Since it's a DELTS indication from AP, will notify all the flows running on
   this AC about QoS release
   \param pMac - Pointer to the global MAC parameter structure.
   \param pMsgBuf - Pointer to the msg buffer came from PE.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_del_ts_ind(tpAniSirGlobal pMac, void *pMsgBuf)
{
	tpSirDeltsRsp pdeltsind = (tpSirDeltsRsp) pMsgBuf;
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	uint8_t sessionId = pdeltsind->sessionId;
	sme_QosEdcaAcType ac;
	sme_QosSearchInfo search_key;
	tSirMacTSInfo *tsinfo;
	sme_QosWmmUpType up =
		(sme_QosWmmUpType) pdeltsind->rsp.tspec.tsinfo.traffic.userPrio;
#ifdef FEATURE_WLAN_DIAG_SUPPORT
	WLAN_HOST_DIAG_EVENT_DEF(qos, host_event_wlan_qos_payload_type);
#endif
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: Invoked on session %d for UP %d",
		  __func__, __LINE__, sessionId, up);
	tsinfo = &pdeltsind->rsp.tspec.tsinfo;
	ac = sme_qos_up_to_ac(up);
	if (SME_QOS_EDCA_AC_MAX == ac) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: invalid AC %d from UP %d",
			  __func__, __LINE__, ac, up);
		return QDF_STATUS_E_FAILURE;
	}
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pACInfo = &pSession->ac_info[ac];

	qdf_mem_zero(&search_key, sizeof(sme_QosSearchInfo));
	/* set the key type & the key to be searched in the Flow List */
	search_key.key.ac_type = ac;
	search_key.index = SME_QOS_SEARCH_KEY_INDEX_2;
	search_key.sessionId = sessionId;
	/* find all Flows on the perticular AC & delete them, also send HDD indication */
	/* through the callback it registered per request */
	if (!QDF_IS_STATUS_SUCCESS
		    (sme_qos_find_all_in_flow_list(pMac, search_key, sme_qos_del_ts_ind_fnp))) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: no match found for ac = %d", __func__,
			  __LINE__, search_key.key.ac_type);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	sme_set_tspec_uapsd_mask_per_session(pMac, tsinfo, sessionId);
/* event: EVENT_WLAN_QOS */
#ifdef FEATURE_WLAN_DIAG_SUPPORT
	qos.eventId = SME_QOS_DIAG_DELTS;
	qos.reasonCode = SME_QOS_DIAG_DELTS_IND_FROM_AP;
	WLAN_HOST_DIAG_EVENT_REPORT(&qos, EVENT_WLAN_QOS);
#endif /* FEATURE_WLAN_DIAG_SUPPORT */

	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_assoc_complete_ev() - Function to process the
   SME_QOS_CSR_ASSOC_COMPLETE event indication from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_assoc_complete_ev(tpAniSirGlobal pMac, uint8_t sessionId,
					     void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	sme_QosEdcaAcType ac = SME_QOS_EDCA_AC_BE;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	if (((SME_QOS_INIT == pSession->ac_info[SME_QOS_EDCA_AC_BE].curr_state)
	     && (SME_QOS_INIT ==
		 pSession->ac_info[SME_QOS_EDCA_AC_BK].curr_state)
	     && (SME_QOS_INIT ==
		 pSession->ac_info[SME_QOS_EDCA_AC_VI].curr_state)
	     && (SME_QOS_INIT ==
		 pSession->ac_info[SME_QOS_EDCA_AC_VO].curr_state))
	    || (pSession->handoffRequested)) {
		/* get the association info */
		if (!pEvent_info) {
			/* err msg */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: pEvent_info is NULL",
				  __func__, __LINE__);
			return status;
		}
		if (!((sme_QosAssocInfo *) pEvent_info)->pBssDesc) {
			/* err msg */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: pBssDesc is NULL",
				  __func__, __LINE__);
			return status;
		}
		if ((pSession->assocInfo.pBssDesc) &&
		    (csr_is_bssid_match
			     (pMac, (struct qdf_mac_addr *) &pSession->assocInfo.pBssDesc->bssId,
			     (struct qdf_mac_addr *) &(((sme_QosAssocInfo *) pEvent_info)->
					     pBssDesc->bssId)))) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: assoc with the same BSS, no update needed",
				  __func__, __LINE__);
		} else {
			status = sme_qos_save_assoc_info(pSession, pEvent_info);
		}
	} else {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: wrong state: BE %d, BK %d, VI %d, VO %d",
			  __func__, __LINE__,
			  pSession->ac_info[SME_QOS_EDCA_AC_BE].curr_state,
			  pSession->ac_info[SME_QOS_EDCA_AC_BK].curr_state,
			  pSession->ac_info[SME_QOS_EDCA_AC_VI].curr_state,
			  pSession->ac_info[SME_QOS_EDCA_AC_VO].curr_state);
		QDF_ASSERT(0);
		return status;
	}
	/* the session is active */
	pSession->sessionActive = true;
	if (pSession->handoffRequested) {
		pSession->handoffRequested = false;
		/* renew all flows */
		(void)sme_qos_process_buffered_cmd(sessionId);
		status = QDF_STATUS_SUCCESS;
	} else {
		for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
			pACInfo = &pSession->ac_info[ac];
			switch (pACInfo->curr_state) {
			case SME_QOS_INIT:
				sme_qos_state_transition(sessionId, ac,
							 SME_QOS_LINK_UP);
				break;
			case SME_QOS_LINK_UP:
			case SME_QOS_REQUESTED:
			case SME_QOS_QOS_ON:
			case SME_QOS_HANDOFF:
			case SME_QOS_CLOSED:
			default:
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: On session %d AC %d is in wrong state %d",
					  __func__, __LINE__, sessionId, ac,
					  pACInfo->curr_state);
				break;
			}
		}
	}
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_reassoc_req_ev() - Function to process the
   SME_QOS_CSR_REASSOC_REQ event indication from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_reassoc_req_ev(tpAniSirGlobal pMac, uint8_t sessionId,
					  void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType ac;
	sme_QosFlowInfoEntry *flow_info = NULL;
	tListElem *entry = NULL;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];

	if (pSession->ftHandoffInProgress) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: no need for state transition, should "
			  "already be in handoff state", __func__, __LINE__);
		if ((pSession->ac_info[0].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[1].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[2].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[3].curr_state != SME_QOS_HANDOFF)) {
			return QDF_STATUS_E_FAILURE;
		}
		sme_qos_process_ft_reassoc_req_ev(sessionId);
		return QDF_STATUS_SUCCESS;
	}

	if (pSession->handoffRequested) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: no need for state transition, should "
			  "already be in handoff state", __func__, __LINE__);

		if ((pSession->ac_info[0].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[1].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[2].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[3].curr_state != SME_QOS_HANDOFF)) {
			QDF_ASSERT(0);
			return QDF_STATUS_E_FAILURE;
		}

		/*
		 * Now change reason and HO renewal of
		 * all the flow in this session only
		 */
		entry = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
		if (!entry) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
				FL("Flow List empty, nothing to update"));
			return QDF_STATUS_E_FAILURE;
		}

		do {
			flow_info = GET_BASE_ADDR(entry, sme_QosFlowInfoEntry,
						  link);
			if (sessionId == flow_info->sessionId) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  FL("Changing FlowID %d reason to"
					     " SETUP and HO renewal to true"),
					  flow_info->QosFlowID);
				flow_info->reason = SME_QOS_REASON_SETUP;
				flow_info->hoRenewal = true;
			}
			entry = csr_ll_next(&sme_qos_cb.flow_list, entry,
					    false);
		} while (entry);

		/* buffer the existing flows to be renewed after handoff is done */
		sme_qos_buffer_existing_flows(pMac, sessionId);
		/* clean up the control block partially for handoff */
		sme_qos_cleanup_ctrl_blk_for_handoff(pMac, sessionId);
		return QDF_STATUS_SUCCESS;
	}
/* TBH: Assuming both handoff algo & 11r willn't be enabled at the same time */
	if (pSession->ftHandoffInProgress) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: no need for state transition, should "
			  "already be in handoff state", __func__, __LINE__);

		if ((pSession->ac_info[0].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[1].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[2].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[3].curr_state != SME_QOS_HANDOFF)) {
			QDF_ASSERT(0);
			return QDF_STATUS_E_FAILURE;
		}

		sme_qos_process_ft_reassoc_req_ev(sessionId);
		return QDF_STATUS_SUCCESS;
	}

	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		pACInfo = &pSession->ac_info[ac];
		switch (pACInfo->curr_state) {
		case SME_QOS_LINK_UP:
		case SME_QOS_REQUESTED:
		case SME_QOS_QOS_ON:
			sme_qos_state_transition(sessionId, ac, SME_QOS_HANDOFF);
			break;
		case SME_QOS_HANDOFF:
			/* This is normal because sme_qos_request_reassoc may already change the state */
			break;
		case SME_QOS_CLOSED:
		case SME_QOS_INIT:
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d AC %d is in wrong state %d",
				  __func__, __LINE__,
				  sessionId, ac, pACInfo->curr_state);
			break;
		}
	}
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_handle_handoff_state() - utility function called by
 *                                  sme_qos_process_reassoc_success_ev
 * @mac_ctx: global MAC context
 * @qos_session: QOS session
 * @ac_info: AC information
 * @ac: current AC index
 * @sessionid: session id
 *
 * This function is called by sme_qos_process_reassoc_success_ev
 * to update the state machine on the reception of reassoc success
 * notificaiton
 *
 * Return: QDF_STATUS
 */
static
QDF_STATUS sme_qos_handle_handoff_state(tpAniSirGlobal mac_ctx,
		sme_QosSessionInfo *qos_session, sme_QosACInfo *ac_info,
		sme_QosEdcaAcType ac, uint8_t sessionid)

{
	sme_QosSearchInfo search_key;
	sme_QosSearchInfo search_key1;
	sme_QosEdcaAcType ac_index;
	tListElem *list_elt = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	/* return to our previous state */
	sme_qos_state_transition(sessionid, ac, ac_info->prev_state);
	/* for which ac APSD (hence the reassoc) is requested */
	if (!ac_info->reassoc_pending)
		return QDF_STATUS_SUCCESS;

	/*
	 * update the apsd mask in CB - make sure to take care of the
	 * case where we are resetting the bit in apsd_mask
	 */
	if (ac_info->requested_QoSInfo[SME_QOS_TSPEC_INDEX_0].ts_info.psb)
		qos_session->apsdMask |= 1 << (SME_QOS_EDCA_AC_VO - ac);
	else
		qos_session->apsdMask &= ~(1 << (SME_QOS_EDCA_AC_VO - ac));

	ac_info->reassoc_pending = false;
	/*
	 * during setup it gets set as addts & reassoc both gets a
	 * pending flag ac_info->tspec_pending = 0;
	 */
	sme_qos_state_transition(sessionid, ac, SME_QOS_QOS_ON);
	/* notify HDD with new Service Interval */
	ac_info->curr_QoSInfo[SME_QOS_TSPEC_INDEX_0] =
		ac_info->requested_QoSInfo[SME_QOS_TSPEC_INDEX_0];
	qdf_mem_zero(&search_key, sizeof(sme_QosSearchInfo));
	/* set the key type & the key to be searched in the Flow List */
	search_key.key.ac_type = ac;
	search_key.index = SME_QOS_SEARCH_KEY_INDEX_2;
	search_key.sessionId = sessionid;
	/* notify PMC that reassoc is done for APSD on certain AC?? */

	qdf_mem_zero(&search_key1, sizeof(sme_QosSearchInfo));
	/* set the hoRenewal field in control block if needed */
	search_key1.index = SME_QOS_SEARCH_KEY_INDEX_3;
	search_key1.key.reason = SME_QOS_REASON_SETUP;
	search_key1.sessionId = sessionid;
	for (ac_index = SME_QOS_EDCA_AC_BE; ac_index < SME_QOS_EDCA_AC_MAX;
	     ac_index++) {
		list_elt = sme_qos_find_in_flow_list(search_key1);
		if (list_elt) {
			flow_info = GET_BASE_ADDR(list_elt,
					sme_QosFlowInfoEntry, link);
			if (flow_info->ac_type == ac) {
			    ac_info->hoRenewal = flow_info->hoRenewal;
			    break;
			}
		}
	}
	/*
	 * notify HDD the success for the requested flow notify all the
	 * other flows running on the AC that QoS got modified
	 */
	status = sme_qos_find_all_in_flow_list(mac_ctx, search_key,
			sme_qos_reassoc_success_ev_fnp);
	if (!QDF_IS_STATUS_SUCCESS(status)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("no match found for ac = %d"),
			  search_key.key.ac_type);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	ac_info->hoRenewal = false;
	qdf_mem_zero(&ac_info->requested_QoSInfo[SME_QOS_TSPEC_INDEX_0],
		     sizeof(sme_QosWmmTspecInfo));

	return status;
}

/**
 * sme_qos_process_reassoc_success_ev() - process SME_QOS_CSR_REASSOC_COMPLETE
 *
 * @mac_ctx: global MAC context
 * @sessionid: session ID
 * @event_info: event buffer from CSR
 *
 * Function to process the SME_QOS_CSR_REASSOC_COMPLETE event indication
 * from CSR
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_process_reassoc_success_ev(tpAniSirGlobal mac_ctx,
				uint8_t sessionid, void *event_info)
{

	tCsrRoamSession *csr_roam_session = NULL;
	sme_QosSessionInfo *qos_session;
	sme_QosACInfo *ac_info;
	sme_QosEdcaAcType ac;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  FL("invoked on session %d"), sessionid);

	if (CSR_ROAM_SESSION_MAX <= sessionid) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("invoked on session %d"), sessionid);
		return status;
	}

	csr_roam_session = CSR_GET_SESSION(mac_ctx, sessionid);

	qos_session = &sme_qos_cb.sessionInfo[sessionid];
	/*
	 * our pending reassociation has completed
	 * we can allow powersave
	 */
	qos_session->readyForPowerSave = true;

	/* get the association info */
	if (!event_info) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("event_info is NULL"));
		return status;
	}

	if (!((sme_QosAssocInfo *) event_info)->pBssDesc) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("pBssDesc is NULL"));
		return status;
	}
	status = sme_qos_save_assoc_info(qos_session, event_info);
	if (status)
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("sme_qos_save_assoc_info() failed"));

	/*
	 * Assuming both handoff algo & 11r willn't be enabled
	 * at the same time
	 */
	if (qos_session->handoffRequested) {
		qos_session->handoffRequested = false;
		/* renew all flows */
		(void)sme_qos_process_buffered_cmd(sessionid);
		return QDF_STATUS_SUCCESS;
	}
	if (qos_session->ftHandoffInProgress) {
		if (csr_roam_is11r_assoc(mac_ctx, sessionid)) {
			if (csr_roam_session &&
			    csr_roam_session->connectedInfo.nRICRspLength) {
				status = sme_qos_process_ft_reassoc_rsp_ev(
						mac_ctx, sessionid,
						event_info);
			} else {
				QDF_TRACE(QDF_MODULE_ID_SME,
					QDF_TRACE_LEVEL_ERROR, FL(
					"session or RIC data is not present"));
			}
		}
#ifdef FEATURE_WLAN_ESE
		/*
		 * If ESE association check for TSPEC IEs in the
		 * reassoc rsp frame
		 */
		if (csr_roam_is_ese_assoc(mac_ctx, sessionid)) {
			if (csr_roam_session &&
			    csr_roam_session->connectedInfo.nTspecIeLength) {
				status = sme_qos_ese_process_reassoc_tspec_rsp(
						mac_ctx, sessionid, event_info);
			}
		}
#endif
		qos_session->ftHandoffInProgress = false;
		qos_session->handoffRequested = false;
		return status;
	}

	qos_session->sessionActive = true;
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		ac_info = &qos_session->ac_info[ac];
		switch (ac_info->curr_state) {
		case SME_QOS_HANDOFF:
			status = sme_qos_handle_handoff_state(mac_ctx,
					qos_session, ac_info, ac, sessionid);
			break;
		case SME_QOS_INIT:
		case SME_QOS_CLOSED:
			/* NOP */
			status = QDF_STATUS_SUCCESS;
			break;
		case SME_QOS_LINK_UP:
		case SME_QOS_REQUESTED:
		case SME_QOS_QOS_ON:
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  FL("session %d AC %d is in wrong state %d"),
				  sessionid, ac, ac_info->curr_state);
			break;
		}
	}
	(void)sme_qos_process_buffered_cmd(sessionid);
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_reassoc_failure_ev() - Function to process the
   SME_QOS_CSR_REASSOC_FAILURE event indication from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_reassoc_failure_ev(tpAniSirGlobal pMac,
					      uint8_t sessionId, void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType ac;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	/* our pending reassociation has completed */
	/* we can allow powersave */
	pSession->readyForPowerSave = true;
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		pACInfo = &pSession->ac_info[ac];
		switch (pACInfo->curr_state) {
		case SME_QOS_HANDOFF:
			sme_qos_state_transition(sessionId, ac, SME_QOS_INIT);
			if (pACInfo->reassoc_pending) {
				pACInfo->reassoc_pending = false;
			}
			qdf_mem_zero(&pACInfo->
				     curr_QoSInfo[SME_QOS_TSPEC_INDEX_0],
				     sizeof(sme_QosWmmTspecInfo));
			qdf_mem_zero(&pACInfo->
				     requested_QoSInfo[SME_QOS_TSPEC_INDEX_0],
				     sizeof(sme_QosWmmTspecInfo));
			qdf_mem_zero(&pACInfo->
				     curr_QoSInfo[SME_QOS_TSPEC_INDEX_1],
				     sizeof(sme_QosWmmTspecInfo));
			qdf_mem_zero(&pACInfo->
				     requested_QoSInfo[SME_QOS_TSPEC_INDEX_1],
				     sizeof(sme_QosWmmTspecInfo));
			pACInfo->tspec_mask_status = SME_QOS_TSPEC_MASK_CLEAR;
			pACInfo->tspec_pending = 0;
			pACInfo->num_flows[SME_QOS_TSPEC_INDEX_0] = 0;
			pACInfo->num_flows[SME_QOS_TSPEC_INDEX_1] = 0;
			break;
		case SME_QOS_INIT:
		case SME_QOS_CLOSED:
			/* NOP */
			break;
		case SME_QOS_LINK_UP:
		case SME_QOS_REQUESTED:
		case SME_QOS_QOS_ON:
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d AC %d is in wrong state %d",
				  __func__, __LINE__,
				  sessionId, ac, pACInfo->curr_state);
			break;
		}
	}
	/* need to clean up flows */
	sme_qos_delete_existing_flows(pMac, sessionId);
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_handoff_assoc_req_ev() - Function to process the
   SME_QOS_CSR_HANDOFF_ASSOC_REQ event indication from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_handoff_assoc_req_ev(tpAniSirGlobal pMac,
						uint8_t sessionId, void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	uint8_t ac;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		pACInfo = &pSession->ac_info[ac];
		switch (pACInfo->curr_state) {
		case SME_QOS_LINK_UP:
		case SME_QOS_REQUESTED:
		case SME_QOS_QOS_ON:
			sme_qos_state_transition(sessionId, ac, SME_QOS_HANDOFF);
			break;
		case SME_QOS_HANDOFF:
			/* print error msg */
			if (pSession->ftHandoffInProgress) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO,
					  "%s: %d: SME_QOS_CSR_HANDOFF_ASSOC_REQ received in "
					  "SME_QOS_HANDOFF state with FT in progress",
					  __func__, __LINE__);
				break;
			}

		case SME_QOS_CLOSED:
		case SME_QOS_INIT:
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d AC %d is in wrong state %d",
				  __func__, __LINE__,
				  sessionId, ac, pACInfo->curr_state);
			break;
		}
	}
#ifdef WLAN_FEATURE_ROAM_OFFLOAD
	if (csr_roam_is11r_assoc(pMac, sessionId)) {
		pSession->ftHandoffInProgress = true;
	}
#endif
	/* If FT handoff is in progress, legacy handoff need not be enabled */
	if (!pSession->ftHandoffInProgress) {
		pSession->handoffRequested = true;
	}
	/* this session no longer needs UAPSD */
	pSession->apsdMask = 0;
	/* do any sessions still require UAPSD? */
	sme_ps_uapsd_disable(pMac, sessionId);
	pSession->uapsdAlreadyRequested = false;
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_handoff_success_ev() - Function to process the
   SME_QOS_CSR_HANDOFF_COMPLETE event indication from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_handoff_success_ev(tpAniSirGlobal pMac,
					      uint8_t sessionId, void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	uint8_t ac;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	/* go back to original state before handoff */
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		pACInfo = &pSession->ac_info[ac];
		switch (pACInfo->curr_state) {
		case SME_QOS_HANDOFF:
			sme_qos_state_transition(sessionId, ac,
						 pACInfo->prev_state);
			/* we will retry for the requested flow(s) with the new AP */
			if (SME_QOS_REQUESTED == pACInfo->curr_state) {
				pACInfo->curr_state = SME_QOS_LINK_UP;
			}
			status = QDF_STATUS_SUCCESS;
			break;
		/* FT logic, has already moved it to QOS_REQUESTED state during the */
		/* reassoc request event, which would include the Qos (TSPEC) params */
		/* in the reassoc req frame */
		case SME_QOS_REQUESTED:
			break;
		case SME_QOS_INIT:
		case SME_QOS_CLOSED:
		case SME_QOS_LINK_UP:
		case SME_QOS_QOS_ON:
		default:
/* In case of 11r - RIC, we request QoS and Hand-off at the same time hence the
   state may be SME_QOS_REQUESTED */
			if (pSession->ftHandoffInProgress)
				break;
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d AC %d is in wrong state %d",
				  __func__, __LINE__,
				  sessionId, ac, pACInfo->curr_state);
			break;
		}
	}
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_handoff_failure_ev() - Function to process the
   SME_QOS_CSR_HANDOFF_FAILURE event indication from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_handoff_failure_ev(tpAniSirGlobal pMac,
					      uint8_t sessionId, void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	uint8_t ac;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		pACInfo = &pSession->ac_info[ac];
		switch (pACInfo->curr_state) {
		case SME_QOS_HANDOFF:
			sme_qos_state_transition(sessionId, ac, SME_QOS_INIT);
			/* need to clean up flows: TODO */
			qdf_mem_zero(&pACInfo->
				     curr_QoSInfo[SME_QOS_TSPEC_INDEX_0],
				     sizeof(sme_QosWmmTspecInfo));
			qdf_mem_zero(&pACInfo->
				     requested_QoSInfo[SME_QOS_TSPEC_INDEX_0],
				     sizeof(sme_QosWmmTspecInfo));
			qdf_mem_zero(&pACInfo->
				     curr_QoSInfo[SME_QOS_TSPEC_INDEX_1],
				     sizeof(sme_QosWmmTspecInfo));
			qdf_mem_zero(&pACInfo->
				     requested_QoSInfo[SME_QOS_TSPEC_INDEX_1],
				     sizeof(sme_QosWmmTspecInfo));
			pACInfo->tspec_mask_status = SME_QOS_TSPEC_MASK_CLEAR;
			pACInfo->tspec_pending = 0;
			pACInfo->num_flows[SME_QOS_TSPEC_INDEX_0] = 0;
			pACInfo->num_flows[SME_QOS_TSPEC_INDEX_1] = 0;
			break;
		case SME_QOS_INIT:
		case SME_QOS_CLOSED:
		case SME_QOS_LINK_UP:
		case SME_QOS_REQUESTED:
		case SME_QOS_QOS_ON:
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: On session %d AC %d is in wrong state %d",
				  __func__, __LINE__,
				  sessionId, ac, pACInfo->curr_state);
			break;
		}
	}
	/* no longer in handoff */
	pSession->handoffRequested = false;
	/* clean up the assoc info */
	if (pSession->assocInfo.pBssDesc) {
		qdf_mem_free(pSession->assocInfo.pBssDesc);
		pSession->assocInfo.pBssDesc = NULL;
	}
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_disconnect_ev() - Function to process the
   SME_QOS_CSR_DISCONNECT_REQ or  SME_QOS_CSR_DISCONNECT_IND event indication
   from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_disconnect_ev(tpAniSirGlobal pMac, uint8_t sessionId,
					 void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	/*
	 * In case of 11r - RIC, we request QoS and Hand-off at the
	 * same time hence the state may be SME_QOS_REQUESTED
	 */
	if ((pSession->handoffRequested)
	    && !pSession->ftHandoffInProgress) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: no need for state transition, should "
			  "already be in handoff state", __func__, __LINE__);
		if ((pSession->ac_info[0].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[1].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[2].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[3].curr_state != SME_QOS_HANDOFF)) {
			QDF_ASSERT(0);
			return QDF_STATUS_SUCCESS;
		}

		return QDF_STATUS_SUCCESS;
	}
	sme_qos_init_a_cs(pMac, sessionId);
	/* this session doesn't require UAPSD */
	pSession->apsdMask = 0;

	sme_ps_uapsd_disable(pMac, sessionId);

	pSession->uapsdAlreadyRequested = false;
	pSession->handoffRequested = false;
	pSession->readyForPowerSave = true;
	pSession->roamID = 0;
	/* need to clean up buffered req */
	sme_qos_delete_buffered_requests(pMac, sessionId);
	/* need to clean up flows */
	sme_qos_delete_existing_flows(pMac, sessionId);
	/* clean up the assoc info */
	if (pSession->assocInfo.pBssDesc) {
		qdf_mem_free(pSession->assocInfo.pBssDesc);
		pSession->assocInfo.pBssDesc = NULL;
	}
	sme_qos_cb.sessionInfo[sessionId].sessionActive = false;
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_join_req_ev() - Function to process the
   SME_QOS_CSR_JOIN_REQ event indication from CSR
   \param pEvent_info - Pointer to relevant info from CSR.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_join_req_ev(tpAniSirGlobal pMac, uint8_t sessionId,
				       void *pEvent_info)
{
	sme_QosSessionInfo *pSession;
	sme_QosEdcaAcType ac;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	if (pSession->handoffRequested) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: no need for state transition, should "
			  "already be in handoff state", __func__, __LINE__);
		if ((pSession->ac_info[0].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[1].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[2].curr_state != SME_QOS_HANDOFF) ||
		    (pSession->ac_info[3].curr_state != SME_QOS_HANDOFF)) {
			/* just print */
			QDF_ASSERT(0);
		}
		/* buffer the existing flows to be renewed after handoff is done */
		sme_qos_buffer_existing_flows(pMac, sessionId);
		/* clean up the control block partially for handoff */
		sme_qos_cleanup_ctrl_blk_for_handoff(pMac, sessionId);
		return QDF_STATUS_SUCCESS;
	}

	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		sme_qos_state_transition(sessionId, ac, SME_QOS_INIT);
	}
	/* clean up the assoc info if already set */
	if (pSession->assocInfo.pBssDesc) {
		qdf_mem_free(pSession->assocInfo.pBssDesc);
		pSession->assocInfo.pBssDesc = NULL;
	}
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_process_preauth_success_ind() - process preauth success indication
 * @mac_ctx: global MAC context
 * @sessionid: session ID
 * @event_info: event buffer
 *
 * Function to process the SME_QOS_CSR_PREAUTH_SUCCESS_IND event indication
 * from CSR
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_process_preauth_success_ind(tpAniSirGlobal mac_ctx,
				uint8_t sessionid, void *event_info)
{
	sme_QosSessionInfo *qos_session;
	tCsrRoamSession *sme_session = CSR_GET_SESSION(mac_ctx, sessionid);
	sme_QosACInfo *ac_info;
	uint8_t ac;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint16_t ric_offset = 0;
	uint32_t ric_ielen = 0;
	uint8_t *ric_ie;
	uint8_t tspec_mask_status = 0;
	uint8_t tspec_pending_status = 0;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  FL("invoked on SME session %d"), sessionid);

	if (NULL == sme_session) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("sme_session is NULL"));
		return QDF_STATUS_E_INVAL;
	}

	qos_session = &sme_qos_cb.sessionInfo[sessionid];

	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		ac_info = &qos_session->ac_info[ac];

		switch (ac_info->curr_state) {
		case SME_QOS_LINK_UP:
		case SME_QOS_REQUESTED:
		case SME_QOS_QOS_ON:
		    sme_qos_state_transition(sessionid, ac, SME_QOS_HANDOFF);
		    break;
		case SME_QOS_HANDOFF:
		/* print error msg */
		case SME_QOS_CLOSED:
		case SME_QOS_INIT:
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  FL("Session %d AC %d is in wrong state %d"),
				  sessionid, ac, ac_info->curr_state);
			break;
		}
	}

	qos_session->ftHandoffInProgress = true;

	/* Check if its a 11R roaming before preparing the RIC IEs */
	if (!csr_roam_is11r_assoc(mac_ctx, sessionid))
		return status;

	/* Data is accessed from saved PreAuth Rsp */
	if (NULL == sme_session->ftSmeContext.psavedFTPreAuthRsp) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("psavedFTPreAuthRsp is NULL"));
		return QDF_STATUS_E_INVAL;
	}

	/*
	 * Any Block Ack info there, should have been already filled by PE and
	 * present in this buffer and the ric_ies_length should contain the
	 * length of the whole RIC IEs. Filling of TSPEC info should start
	 * from this length
	 */
	ric_ie = sme_session->ftSmeContext.psavedFTPreAuthRsp->ric_ies;
	ric_offset =
		sme_session->ftSmeContext.psavedFTPreAuthRsp->ric_ies_length;

	/*
	 * Now we have to process the currentTspeInfo inside this session and
	 * create the RIC IEs
	 */
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		volatile uint8_t tspec_idx = 0;
		ric_ielen = 0;
		ac_info = &qos_session->ac_info[ac];
		tspec_pending_status = ac_info->tspec_pending;
		tspec_mask_status = ac_info->tspec_mask_status;
		qdf_mem_zero(ac_info->ricIdentifier, SME_QOS_TSPEC_INDEX_MAX);
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
			  FL("AC %d ==> TSPEC status = %d, tspec pending = %d"),
			  ac, tspec_mask_status, tspec_pending_status);

		do {
			if (!(tspec_mask_status & 0x1))
				goto add_next_ric;

			/*
			 * If a tspec status is pending, take requested_QoSInfo
			 * for RIC request, else use curr_QoSInfo for the
			 * RIC request
			 */
			if (tspec_pending_status & 0x1) {
			    status = sme_qos_create_tspec_ricie(mac_ctx,
					&ac_info->requested_QoSInfo[tspec_idx],
					ric_ie + ric_offset, &ric_ielen,
					&ac_info->ricIdentifier[tspec_idx]);
			} else {
			    status = sme_qos_create_tspec_ricie(mac_ctx,
					&ac_info->curr_QoSInfo[tspec_idx],
					ric_ie + ric_offset, &ric_ielen,
					&ac_info->ricIdentifier[tspec_idx]);
			}
add_next_ric:
			ric_offset += ric_ielen;
			sme_session->ftSmeContext.psavedFTPreAuthRsp->
				ric_ies_length += ric_ielen;
			tspec_mask_status >>= 1;
			tspec_pending_status >>= 1;
			tspec_idx++;
		} while (tspec_mask_status);
	}
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_add_ts_failure_rsp() - Function to process the
   Addts request failure response came from PE

   We will notify HDD only for the requested Flow, other Flows running on the AC
   stay intact

   \param pMac - Pointer to the global MAC parameter structure.
   \param pRsp - Pointer to the addts response structure came from PE.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_add_ts_failure_rsp(tpAniSirGlobal pMac,
					      uint8_t sessionId,
					      tSirAddtsRspInfo *pRsp)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType ac;
	sme_QosSearchInfo search_key;
	uint8_t tspec_pending;
	sme_QosWmmUpType up =
		(sme_QosWmmUpType) pRsp->tspec.tsinfo.traffic.userPrio;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d for UP %d", __func__, __LINE__,
		  sessionId, up);
	ac = sme_qos_up_to_ac(up);
	if (SME_QOS_EDCA_AC_MAX == ac) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: invalid AC %d from UP %d",
			  __func__, __LINE__, ac, up);
		return QDF_STATUS_E_FAILURE;
	}
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pACInfo = &pSession->ac_info[ac];
	/* is there a TSPEC request pending on this AC? */
	tspec_pending = pACInfo->tspec_pending;
	if (!tspec_pending) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d an AddTS is not pending on AC %d",
			  __func__, __LINE__, sessionId, ac);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}

	qdf_mem_zero(&search_key, sizeof(sme_QosSearchInfo));
	/* set the key type & the key to be searched in the Flow List */
	search_key.key.ac_type = ac;
	search_key.index = SME_QOS_SEARCH_KEY_INDEX_2;
	search_key.sessionId = sessionId;
	if (!QDF_IS_STATUS_SUCCESS
		    (sme_qos_find_all_in_flow_list
			    (pMac, search_key, sme_qos_add_ts_failure_fnp))) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d no match found for ac = %d",
			  __func__, __LINE__, sessionId,
			  search_key.key.ac_type);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	qdf_mem_zero(&pACInfo->requested_QoSInfo[tspec_pending - 1],
		     sizeof(sme_QosWmmTspecInfo));

	if ((!pACInfo->num_flows[0]) && (!pACInfo->num_flows[1])) {
		pACInfo->tspec_mask_status &= SME_QOS_TSPEC_MASK_BIT_1_2_SET &
					      (~pACInfo->tspec_pending);
		sme_qos_state_transition(sessionId, ac, SME_QOS_LINK_UP);
	} else {
		sme_qos_state_transition(sessionId, ac, SME_QOS_QOS_ON);
	}
	pACInfo->tspec_pending = 0;

	(void)sme_qos_process_buffered_cmd(sessionId);

	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_update_tspec_mask() - Utiltity function to update the tspec.
 * @sessionid: Session upon which the TSPEC is being updated
 * @search_key: search key
 * @new_tspec_mask: tspec to be set for this AC
 *
 * Typical usage while aggregating unidirectional flows into a bi-directional
 * flow on AC which is running multiple flows
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sme_qos_update_tspec_mask(uint8_t sessionid,
					    sme_QosSearchInfo search_key,
					    uint8_t new_tspec_mask)
{
	tListElem *list_elt = NULL, *list_next_elt = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosSessionInfo *qos_session;
	sme_QosACInfo *ac_info;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  FL("invoked on session %d for AC %d TSPEC %d"),
		  sessionid, search_key.key.ac_type, new_tspec_mask);

	qos_session = &sme_qos_cb.sessionInfo[sessionid];

	if (search_key.key.ac_type < SME_QOS_EDCA_AC_MAX) {
		ac_info = &qos_session->ac_info[search_key.key.ac_type];
	} else {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  FL("Exceeded the array bounds"));
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}

	list_elt = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!list_elt) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("Flow List empty, nothing to update"));
		return QDF_STATUS_E_FAILURE;
	}

	while (list_elt) {
		list_next_elt = csr_ll_next(&sme_qos_cb.flow_list, list_elt,
					    false);
		flow_info = GET_BASE_ADDR(list_elt, sme_QosFlowInfoEntry, link);

		if (search_key.sessionId != flow_info->sessionId) {
			list_elt = list_next_elt;
			continue;
		}

		if (search_key.index & SME_QOS_SEARCH_KEY_INDEX_4) {
			if ((search_key.key.ac_type == flow_info->ac_type) &&
			    (search_key.direction ==
				flow_info->QoSInfo.ts_info.direction)) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_INFO_HIGH,
				  FL("Flow %d matches"), flow_info->QosFlowID);
				ac_info->num_flows[flow_info->tspec_mask - 1]--;
				ac_info->num_flows[new_tspec_mask - 1]++;
				flow_info->tspec_mask = new_tspec_mask;
			}
		} else if (search_key.index & SME_QOS_SEARCH_KEY_INDEX_5) {
			if ((search_key.key.ac_type == flow_info->ac_type) &&
			    (search_key.tspec_mask == flow_info->tspec_mask)) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_INFO_HIGH,
				  FL("Flow %d matches"), flow_info->QosFlowID);
				ac_info->num_flows[flow_info->tspec_mask - 1]--;
				ac_info->num_flows[new_tspec_mask - 1]++;
				flow_info->tspec_mask = new_tspec_mask;
			}
		}
		list_elt = list_next_elt;
	}

	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_process_add_ts_success_rsp() - Function to process the
   Addts request success response came from PE

   We will notify HDD with addts success for the requested Flow, & for other
   Flows running on the AC we will send an addts modify status

   \param pMac - Pointer to the global MAC parameter structure.
   \param pRsp - Pointer to the addts response structure came from PE.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_process_add_ts_success_rsp(tpAniSirGlobal pMac,
					      uint8_t sessionId,
					      tSirAddtsRspInfo *pRsp)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType ac, ac_index;
	sme_QosSearchInfo search_key;
	sme_QosSearchInfo search_key1;
	tCsrRoamSession *csr_session;
	uint8_t tspec_pending;
	tListElem *pEntry = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosWmmUpType up =
		(sme_QosWmmUpType) pRsp->tspec.tsinfo.traffic.userPrio;
#ifdef FEATURE_WLAN_DIAG_SUPPORT
	WLAN_HOST_DIAG_EVENT_DEF(qos, host_event_wlan_qos_payload_type);
	host_log_qos_tspec_pkt_type *log_ptr = NULL;
#endif /* FEATURE_WLAN_DIAG_SUPPORT */
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d for UP %d",
		  __func__, __LINE__, sessionId, up);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	ac = sme_qos_up_to_ac(up);
	if (SME_QOS_EDCA_AC_MAX == ac) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: invalid AC %d from UP %d",
			  __func__, __LINE__, ac, up);
		return QDF_STATUS_E_FAILURE;
	}
	pACInfo = &pSession->ac_info[ac];
	/* is there a TSPEC request pending on this AC? */
	tspec_pending = pACInfo->tspec_pending;
	if (!tspec_pending) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d an AddTS is not pending on AC %d",
			  __func__, __LINE__, sessionId, ac);
		return QDF_STATUS_E_FAILURE;
	}
	/* App is looking for APSD or the App which was looking for APSD has been */
	/* released, so STA re-negotiated with AP */
	if (pACInfo->requested_QoSInfo[tspec_pending - 1].ts_info.psb) {
		/* update the session's apsd mask */
		pSession->apsdMask |= 1 << (SME_QOS_EDCA_AC_VO - ac);
	} else {
		if (((SME_QOS_TSPEC_MASK_BIT_1_2_SET & ~tspec_pending) > 0) &&
		    ((SME_QOS_TSPEC_MASK_BIT_1_2_SET & ~tspec_pending) <=
		     SME_QOS_TSPEC_INDEX_MAX)) {
			if (!pACInfo->requested_QoSInfo
			    [(SME_QOS_TSPEC_MASK_BIT_1_2_SET & ~tspec_pending) -
			     1].ts_info.psb) {
				/* update the session's apsd mask */
				pSession->apsdMask &=
					~(1 << (SME_QOS_EDCA_AC_VO - ac));
			}
		} else {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: Exceeded the array bounds of pACInfo->requested_QosInfo",
				  __func__, __LINE__);
			QDF_ASSERT(0);
			return QDF_STATUS_E_FAILURE;
		}
	}

	pACInfo->curr_QoSInfo[tspec_pending - 1].ts_info.burst_size_defn =
		pRsp->tspec.tsinfo.traffic.burstSizeDefn;
	pACInfo->curr_QoSInfo[tspec_pending - 1].ts_info.ack_policy =
		pRsp->tspec.tsinfo.traffic.ackPolicy;
	pACInfo->curr_QoSInfo[tspec_pending - 1].ts_info.up =
		pRsp->tspec.tsinfo.traffic.userPrio;
	pACInfo->curr_QoSInfo[tspec_pending - 1].ts_info.psb =
		pRsp->tspec.tsinfo.traffic.psb;
	pACInfo->curr_QoSInfo[tspec_pending - 1].ts_info.direction =
		pRsp->tspec.tsinfo.traffic.direction;
	pACInfo->curr_QoSInfo[tspec_pending - 1].ts_info.tid =
		pRsp->tspec.tsinfo.traffic.tsid;
	pACInfo->curr_QoSInfo[tspec_pending - 1].nominal_msdu_size =
		pRsp->tspec.nomMsduSz;
	pACInfo->curr_QoSInfo[tspec_pending - 1].maximum_msdu_size =
		pRsp->tspec.maxMsduSz;
	pACInfo->curr_QoSInfo[tspec_pending - 1].min_service_interval =
		pRsp->tspec.minSvcInterval;
	pACInfo->curr_QoSInfo[tspec_pending - 1].max_service_interval =
		pRsp->tspec.maxSvcInterval;
	pACInfo->curr_QoSInfo[tspec_pending - 1].inactivity_interval =
		pRsp->tspec.inactInterval;
	pACInfo->curr_QoSInfo[tspec_pending - 1].suspension_interval =
		pRsp->tspec.suspendInterval;
	pACInfo->curr_QoSInfo[tspec_pending - 1].svc_start_time =
		pRsp->tspec.svcStartTime;
	pACInfo->curr_QoSInfo[tspec_pending - 1].min_data_rate =
		pRsp->tspec.minDataRate;
	pACInfo->curr_QoSInfo[tspec_pending - 1].mean_data_rate =
		pRsp->tspec.meanDataRate;
	pACInfo->curr_QoSInfo[tspec_pending - 1].peak_data_rate =
		pRsp->tspec.peakDataRate;
	pACInfo->curr_QoSInfo[tspec_pending - 1].max_burst_size =
		pRsp->tspec.maxBurstSz;
	pACInfo->curr_QoSInfo[tspec_pending - 1].delay_bound =
		pRsp->tspec.delayBound;

	pACInfo->curr_QoSInfo[tspec_pending - 1].min_phy_rate =
		pRsp->tspec.minPhyRate;
	pACInfo->curr_QoSInfo[tspec_pending - 1].surplus_bw_allowance =
		pRsp->tspec.surplusBw;
	pACInfo->curr_QoSInfo[tspec_pending - 1].medium_time =
		pRsp->tspec.mediumTime;

	sme_set_tspec_uapsd_mask_per_session(pMac,
			&pRsp->tspec.tsinfo, sessionId);

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: On session %d AddTspec Medium Time %d",
		  __func__, __LINE__, sessionId, pRsp->tspec.mediumTime);

	/* Check if the current flow is for bi-directional. If so, update the number of flows
	 * to reflect that all flows are aggregated into tspec index 0. */
	if ((pACInfo->curr_QoSInfo[pACInfo->tspec_pending - 1].ts_info.
	     direction == SME_QOS_WMM_TS_DIR_BOTH)
	    && (pACInfo->num_flows[SME_QOS_TSPEC_INDEX_1] > 0)) {
		qdf_mem_zero(&search_key, sizeof(sme_QosSearchInfo));
		/* update tspec_mask for all the flows having SME_QOS_TSPEC_MASK_BIT_2_SET to SME_QOS_TSPEC_MASK_BIT_1_SET */
		search_key.key.ac_type = ac;
		search_key.index = SME_QOS_SEARCH_KEY_INDEX_5;
		search_key.sessionId = sessionId;
		search_key.tspec_mask = SME_QOS_TSPEC_MASK_BIT_2_SET;
		sme_qos_update_tspec_mask(sessionId, search_key,
					  SME_QOS_TSPEC_MASK_BIT_1_SET);
	}

	qdf_mem_zero(&search_key1, sizeof(sme_QosSearchInfo));
	/* set the horenewal field in control block if needed */
	search_key1.index = SME_QOS_SEARCH_KEY_INDEX_3;
	search_key1.key.reason = SME_QOS_REASON_SETUP;
	search_key1.sessionId = sessionId;
	for (ac_index = SME_QOS_EDCA_AC_BE; ac_index < SME_QOS_EDCA_AC_MAX;
	     ac_index++) {
		pEntry = sme_qos_find_in_flow_list(search_key1);
		if (pEntry) {
			flow_info =
				GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
			if (flow_info->ac_type == ac) {
				pACInfo->hoRenewal = flow_info->hoRenewal;
				break;
			}
		}
	}
	qdf_mem_zero(&search_key, sizeof(sme_QosSearchInfo));
	/* set the key type & the key to be searched in the Flow List */
	search_key.key.ac_type = ac;
	search_key.index = SME_QOS_SEARCH_KEY_INDEX_2;
	search_key.sessionId = sessionId;
	/* notify HDD the success for the requested flow */
	/* notify all the other flows running on the AC that QoS got modified */
	if (!QDF_IS_STATUS_SUCCESS
		    (sme_qos_find_all_in_flow_list
			    (pMac, search_key, sme_qos_add_ts_success_fnp))) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d no match found for ac %d",
			  __func__, __LINE__, sessionId,
			  search_key.key.ac_type);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	pACInfo->hoRenewal = false;
	qdf_mem_zero(&pACInfo->requested_QoSInfo[tspec_pending - 1],
		     sizeof(sme_QosWmmTspecInfo));
	/* event: EVENT_WLAN_QOS */
#ifdef FEATURE_WLAN_DIAG_SUPPORT
	qos.eventId = SME_QOS_DIAG_ADDTS_RSP;
	qos.reasonCode = SME_QOS_DIAG_ADDTS_ADMISSION_ACCEPTED;
	WLAN_HOST_DIAG_EVENT_REPORT(&qos, EVENT_WLAN_QOS);
	WLAN_HOST_DIAG_LOG_ALLOC(log_ptr, host_log_qos_tspec_pkt_type,
				 LOG_WLAN_QOS_TSPEC_C);
	if (log_ptr) {
		log_ptr->delay_bound =
			pACInfo->curr_QoSInfo[tspec_pending - 1].delay_bound;
		log_ptr->inactivity_interval =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].inactivity_interval;
		log_ptr->max_burst_size =
			pACInfo->curr_QoSInfo[tspec_pending - 1].max_burst_size;
		log_ptr->max_service_interval =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].max_service_interval;
		log_ptr->maximum_msdu_size =
			pACInfo->curr_QoSInfo[tspec_pending - 1].maximum_msdu_size;
		log_ptr->mean_data_rate =
			pACInfo->curr_QoSInfo[tspec_pending - 1].mean_data_rate;
		log_ptr->medium_time =
			pACInfo->curr_QoSInfo[tspec_pending - 1].medium_time;
		log_ptr->min_data_rate =
			pACInfo->curr_QoSInfo[tspec_pending - 1].min_data_rate;
		log_ptr->min_phy_rate =
			pACInfo->curr_QoSInfo[tspec_pending - 1].min_phy_rate;
		log_ptr->min_service_interval =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].min_service_interval;
		log_ptr->nominal_msdu_size =
			pACInfo->curr_QoSInfo[tspec_pending - 1].nominal_msdu_size;
		log_ptr->peak_data_rate =
			pACInfo->curr_QoSInfo[tspec_pending - 1].peak_data_rate;
		log_ptr->surplus_bw_allowance =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].surplus_bw_allowance;
		log_ptr->suspension_interval =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].surplus_bw_allowance;
		log_ptr->suspension_interval =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].suspension_interval;
		log_ptr->svc_start_time =
			pACInfo->curr_QoSInfo[tspec_pending - 1].svc_start_time;
		log_ptr->tsinfo[0] =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].ts_info.direction << 5 | pACInfo->
			curr_QoSInfo[tspec_pending - 1].ts_info.tid << 1;
		log_ptr->tsinfo[1] =
			pACInfo->curr_QoSInfo[tspec_pending -
					      1].ts_info.up << 11 | pACInfo->
			curr_QoSInfo[tspec_pending - 1].ts_info.psb << 10;
		log_ptr->tsinfo[2] = 0;
	}
	WLAN_HOST_DIAG_LOG_REPORT(log_ptr);
#endif /* FEATURE_WLAN_DIAG_SUPPORT */
	pACInfo->tspec_pending = 0;

	sme_qos_state_transition(sessionId, ac, SME_QOS_QOS_ON);

	/* Inform this TSPEC IE change to FW */
	csr_session = CSR_GET_SESSION(pMac, sessionId);
	if (csr_session != NULL &&
		csr_session->pCurRoamProfile->csrPersona == QDF_STA_MODE) {
		csr_roam_offload_scan(pMac, sessionId,
				      ROAM_SCAN_OFFLOAD_UPDATE_CFG,
				      REASON_CONNECT_IES_CHANGED);
	}

	(void)sme_qos_process_buffered_cmd(sessionId);
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_aggregate_params() - Utiltity function to increament the TSPEC
   params per AC. Typical usage while using flow aggregation or deletion of flows

   \param pInput_Tspec_Info - Pointer to sme_QosWmmTspecInfo which contains the
   WMM TSPEC related info with which pCurrent_Tspec_Info will be updated
   \param pCurrent_Tspec_Info - Pointer to sme_QosWmmTspecInfo which contains
   current the WMM TSPEC related info

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_aggregate_params(sme_QosWmmTspecInfo *pInput_Tspec_Info,
				    sme_QosWmmTspecInfo *pCurrent_Tspec_Info,
				    sme_QosWmmTspecInfo *pUpdated_Tspec_Info)
{
	sme_QosWmmTspecInfo TspecInfo;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked", __func__, __LINE__);
	if (!pInput_Tspec_Info) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: input is NULL, nothing to aggregate",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	if (!pCurrent_Tspec_Info) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Current is NULL, can't aggregate",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	qdf_mem_copy(&TspecInfo, pCurrent_Tspec_Info,
		     sizeof(sme_QosWmmTspecInfo));
	TspecInfo.ts_info.psb = pInput_Tspec_Info->ts_info.psb;
	/*-------------------------------------------------------------------------
	   APSD preference is only meaningful if service interval was set by app
	   -------------------------------------------------------------------------*/
	if (pCurrent_Tspec_Info->min_service_interval &&
	    pInput_Tspec_Info->min_service_interval &&
	    (pCurrent_Tspec_Info->ts_info.direction !=
	     pInput_Tspec_Info->ts_info.direction)) {
		TspecInfo.min_service_interval =
			QDF_MIN(pCurrent_Tspec_Info->min_service_interval,
				pInput_Tspec_Info->min_service_interval);
	} else if (pInput_Tspec_Info->min_service_interval) {
		TspecInfo.min_service_interval =
			pInput_Tspec_Info->min_service_interval;
	}
	if (pCurrent_Tspec_Info->max_service_interval &&
	    pInput_Tspec_Info->max_service_interval &&
	    (pCurrent_Tspec_Info->ts_info.direction !=
	     pInput_Tspec_Info->ts_info.direction)) {
		TspecInfo.max_service_interval =
			QDF_MIN(pCurrent_Tspec_Info->max_service_interval,
				pInput_Tspec_Info->max_service_interval);
	} else {
		TspecInfo.max_service_interval =
			pInput_Tspec_Info->max_service_interval;
	}
	/*-------------------------------------------------------------------------
	   If directions don't match, it must necessarily be both uplink and
	   downlink
	   -------------------------------------------------------------------------*/
	if (pCurrent_Tspec_Info->ts_info.direction !=
	    pInput_Tspec_Info->ts_info.direction) {
		TspecInfo.ts_info.direction =
			pInput_Tspec_Info->ts_info.direction;
	}
	/*-------------------------------------------------------------------------
	   Max MSDU size : these sizes are `maxed'
	   -------------------------------------------------------------------------*/
	TspecInfo.maximum_msdu_size =
		QDF_MAX(pCurrent_Tspec_Info->maximum_msdu_size,
			pInput_Tspec_Info->maximum_msdu_size);

	/*-------------------------------------------------------------------------
	   Inactivity interval : these sizes are `maxed'
	   -------------------------------------------------------------------------*/
	TspecInfo.inactivity_interval =
		QDF_MAX(pCurrent_Tspec_Info->inactivity_interval,
			pInput_Tspec_Info->inactivity_interval);

	/*-------------------------------------------------------------------------
	   Delay bounds: min of all values
	   Check on 0: if 0, it means initial value since delay can never be 0!!
	   -------------------------------------------------------------------------*/
	if (pCurrent_Tspec_Info->delay_bound) {
		TspecInfo.delay_bound =
			QDF_MIN(pCurrent_Tspec_Info->delay_bound,
				pInput_Tspec_Info->delay_bound);
	} else {
		TspecInfo.delay_bound = pInput_Tspec_Info->delay_bound;
	}
	TspecInfo.max_burst_size = QDF_MAX(pCurrent_Tspec_Info->max_burst_size,
					   pInput_Tspec_Info->max_burst_size);

	/*-------------------------------------------------------------------------
	   Nominal MSDU size also has a fixed bit that needs to be `handled' before
	   aggregation
	   This can be handled only if previous size is the same as new or both have
	   the fixed bit set
	   These sizes are not added: but `maxed'
	   -------------------------------------------------------------------------*/
	TspecInfo.nominal_msdu_size =
		QDF_MAX(pCurrent_Tspec_Info->nominal_msdu_size & ~SME_QOS_16BIT_MSB,
			pInput_Tspec_Info->nominal_msdu_size & ~SME_QOS_16BIT_MSB);

	if (((pCurrent_Tspec_Info->nominal_msdu_size == 0) ||
	     (pCurrent_Tspec_Info->nominal_msdu_size & SME_QOS_16BIT_MSB)) &&
	    ((pInput_Tspec_Info->nominal_msdu_size == 0) ||
	     (pInput_Tspec_Info->nominal_msdu_size & SME_QOS_16BIT_MSB))) {
		TspecInfo.nominal_msdu_size |= SME_QOS_16BIT_MSB;
	}

	/*-------------------------------------------------------------------------
	   Data rates:
	   Add up the rates for aggregation
	   -------------------------------------------------------------------------*/
	SME_QOS_BOUNDED_U32_ADD_Y_TO_X(TspecInfo.peak_data_rate,
				       pInput_Tspec_Info->peak_data_rate);
	SME_QOS_BOUNDED_U32_ADD_Y_TO_X(TspecInfo.min_data_rate,
				       pInput_Tspec_Info->min_data_rate);
	/* mean data rate = peak data rate: aggregate to be flexible on apps  */
	SME_QOS_BOUNDED_U32_ADD_Y_TO_X(TspecInfo.mean_data_rate,
				       pInput_Tspec_Info->mean_data_rate);

	/*-------------------------------------------------------------------------
	   Suspension interval : this is set to the inactivity interval since per
	   spec it is less than or equal to inactivity interval
	   This is not provided by app since we currently don't support the HCCA
	   mode of operation
	   Currently set it to 0 to avoid confusion: Cisco ESE needs ~0; spec
	   requires inactivity interval to be > suspension interval: this could
	   be tricky!
	   -------------------------------------------------------------------------*/
	TspecInfo.suspension_interval = pInput_Tspec_Info->suspension_interval;
	/*-------------------------------------------------------------------------
	   Remaining parameters do not come from app as they are very WLAN
	   air interface specific
	   Set meaningful values here
	   -------------------------------------------------------------------------*/
	TspecInfo.medium_time = 0;      /* per WMM spec                 */
	TspecInfo.min_phy_rate = SME_QOS_MIN_PHY_RATE;
	TspecInfo.svc_start_time = 0;   /* arbitrary                  */
	TspecInfo.surplus_bw_allowance +=
		pInput_Tspec_Info->surplus_bw_allowance;
	if (TspecInfo.surplus_bw_allowance > SME_QOS_SURPLUS_BW_ALLOWANCE) {
		TspecInfo.surplus_bw_allowance = SME_QOS_SURPLUS_BW_ALLOWANCE;
	}
	/* Set ack_policy to block ack even if one stream requests block ack policy */
	if ((pInput_Tspec_Info->ts_info.ack_policy ==
	     SME_QOS_WMM_TS_ACK_POLICY_HT_IMMEDIATE_BLOCK_ACK)
	    || (pCurrent_Tspec_Info->ts_info.ack_policy ==
		SME_QOS_WMM_TS_ACK_POLICY_HT_IMMEDIATE_BLOCK_ACK)) {
		TspecInfo.ts_info.ack_policy =
			SME_QOS_WMM_TS_ACK_POLICY_HT_IMMEDIATE_BLOCK_ACK;
	}

	if (pInput_Tspec_Info->ts_info.burst_size_defn
	    || pCurrent_Tspec_Info->ts_info.burst_size_defn) {
		TspecInfo.ts_info.burst_size_defn = 1;
	}
	if (pUpdated_Tspec_Info) {
		qdf_mem_copy(pUpdated_Tspec_Info, &TspecInfo,
			     sizeof(sme_QosWmmTspecInfo));
	} else {
		qdf_mem_copy(pCurrent_Tspec_Info, &TspecInfo,
			     sizeof(sme_QosWmmTspecInfo));
	}
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_update_params() - Utiltity function to update the TSPEC
   params per AC. Typical usage while deleting flows on AC which is running
   multiple flows

   \param sessionId - Session upon which the TSPEC is being updated
   \param ac - Enumeration of the various EDCA Access Categories.
   \param tspec_mask - on which tspec per AC, the update is requested

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
static QDF_STATUS sme_qos_update_params(uint8_t sessionId,
					sme_QosEdcaAcType ac,
					uint8_t tspec_mask,
					sme_QosWmmTspecInfo *pTspec_Info)
{
	tListElem *pEntry = NULL, *pNextEntry = NULL;
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosWmmTspecInfo Tspec_Info;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: invoked on session %d for AC %d TSPEC %d",
		  __func__, __LINE__, sessionId, ac, tspec_mask);
	if (!pTspec_Info) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: output is NULL, can't aggregate",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	qdf_mem_zero(&Tspec_Info, sizeof(sme_QosWmmTspecInfo));
	pEntry = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Flow List empty, nothing to update",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pACInfo = &pSession->ac_info[ac];
	/* init the TS info field */
	Tspec_Info.ts_info.up =
		pACInfo->curr_QoSInfo[tspec_mask - 1].ts_info.up;
	Tspec_Info.ts_info.psb =
		pACInfo->curr_QoSInfo[tspec_mask - 1].ts_info.psb;
	Tspec_Info.ts_info.tid =
		pACInfo->curr_QoSInfo[tspec_mask - 1].ts_info.tid;
	while (pEntry) {
		pNextEntry = csr_ll_next(&sme_qos_cb.flow_list, pEntry, false);
		flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
		if ((sessionId == flow_info->sessionId) &&
		    (ac == flow_info->ac_type) &&
		    (tspec_mask == flow_info->tspec_mask)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: Flow %d matches",
				  __func__, __LINE__, flow_info->QosFlowID);

			if ((SME_QOS_REASON_RELEASE == flow_info->reason) ||
			    (SME_QOS_REASON_MODIFY == flow_info->reason)) {
				/* msg */
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  "%s: %d: Skipping Flow %d as it is marked "
					  "for release/modify", __func__,
					  __LINE__, flow_info->QosFlowID);
			} else
			if (!QDF_IS_STATUS_SUCCESS
				    (sme_qos_aggregate_params
					    (&flow_info->QoSInfo, &Tspec_Info, NULL))) {
				/* err msg */
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: sme_qos_aggregate_params() failed",
					  __func__, __LINE__);
			}
		}
		pEntry = pNextEntry;
	}
	/* return the aggregate */
	*pTspec_Info = Tspec_Info;
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_ac_to_up() - Utiltity function to map an AC to UP
   Note: there is a quantization loss here because 4 ACs are mapped to 8 UPs
   Mapping is done for consistency
   \param ac - Enumeration of the various EDCA Access Categories.
   \return an User Priority

   \sa

   --------------------------------------------------------------------------*/
sme_QosWmmUpType sme_qos_ac_to_up(sme_QosEdcaAcType ac)
{
	sme_QosWmmUpType up = SME_QOS_WMM_UP_MAX;
	if (ac >= 0 && ac < SME_QOS_EDCA_AC_MAX) {
		up = sme_qos_a_cto_up_map[ac];
	}
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
		  "%s: %d: ac = %d up = %d returned",
		  __func__, __LINE__, ac, up);
	return up;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_up_to_ac() - Utiltity function to map an UP to AC
   \param up - Enumeration of the various User priorities (UP).
   \return an Access Category

   \sa

   --------------------------------------------------------------------------*/
sme_QosEdcaAcType sme_qos_up_to_ac(sme_QosWmmUpType up)
{
	sme_QosEdcaAcType ac = SME_QOS_EDCA_AC_MAX;
	if (up >= 0 && up < SME_QOS_WMM_UP_MAX) {
		ac = sme_qos_u_pto_ac_map[up];
	}
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
		  "%s: %d: up = %d ac = %d returned",
		  __func__, __LINE__, up, ac);
	return ac;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_state_transition() - The state transition function per AC. We
   save the previous state also.
   \param sessionId - Session upon which the state machine is running
   \param ac - Enumeration of the various EDCA Access Categories.
   \param new_state - The state FSM is moving to.

   \return None

   \sa

   --------------------------------------------------------------------------*/
static void sme_qos_state_transition(uint8_t sessionId,
				     sme_QosEdcaAcType ac,
				     sme_QosStates new_state)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pACInfo = &pSession->ac_info[ac];
	pACInfo->prev_state = pACInfo->curr_state;
	pACInfo->curr_state = new_state;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: On session %d new state=%d, old state=%d, for AC=%d",
		  __func__, __LINE__,
		  sessionId, pACInfo->curr_state, pACInfo->prev_state, ac);
}

/**
 * sme_qos_find_in_flow_list() - find a flow entry from the flow list
 * @search_key: We can either use the flowID or the ac type to find the
 *              entry in the flow list.
 *              A bitmap in sme_QosSearchInfo tells which key to use.
 *              Starting from LSB,
 *              bit 0 - Flow ID
 *              bit 1 - AC type
 *
 * Utility function to find an flow entry from the flow_list.
 *
 * Return: pointer to the list element
 */
tListElem *sme_qos_find_in_flow_list(sme_QosSearchInfo search_key)
{
	tListElem *list_elt = NULL, *list_next_elt = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;

	list_elt = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!list_elt) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("Flow List empty, can't search"));
		return NULL;
	}

	while (list_elt) {
		list_next_elt = csr_ll_next(&sme_qos_cb.flow_list, list_elt,
					    false);
		flow_info = GET_BASE_ADDR(list_elt, sme_QosFlowInfoEntry, link);

		if ((search_key.sessionId != flow_info->sessionId) &&
		    (search_key.sessionId != SME_QOS_SEARCH_SESSION_ID_ANY)) {
			list_elt = list_next_elt;
			continue;
		}

		if (search_key.index & SME_QOS_SEARCH_KEY_INDEX_1) {
			if (search_key.key.QosFlowID == flow_info->QosFlowID) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_INFO_HIGH,
				  FL("match found on flowID, ending search"));
				break;
			}
		} else if (search_key.index & SME_QOS_SEARCH_KEY_INDEX_2) {
			if (search_key.key.ac_type == flow_info->ac_type) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_INFO_HIGH,
				  FL("match found on ac, ending search"));
				break;
			}
		} else if (search_key.index & SME_QOS_SEARCH_KEY_INDEX_3) {
			if (search_key.key.reason == flow_info->reason) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_INFO_HIGH,
				  FL("match found on reason, ending search"));
				break;
			}
		} else if (search_key.index & SME_QOS_SEARCH_KEY_INDEX_4) {
			if ((search_key.key.ac_type == flow_info->ac_type) &&
			    (search_key.direction ==
				flow_info->QoSInfo.ts_info.direction)) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				  QDF_TRACE_LEVEL_INFO_HIGH,
				  FL("match found on reason, ending search"));
				break;
			}
		}
		list_elt = list_next_elt;
	}
	return list_elt;
}

/**
 * sme_qos_find_all_in_flow_list() - find a flow entry in the flow list
 * @mac_ctx: global MAC context
 * @search_key: search key
 * @fnp: function pointer specifying the action type for the entry found
 *
 * Utility function to find an flow entry from the flow_list & act on it.
 * search_key -  We can either use the flowID or the ac type to find the
 *   entry in the flow list.
 *  A bitmap in sme_QosSearchInfo tells which key to use. Starting from LSB,
 *  bit 0 - Flow ID
 *  bit 1 - AC type
 *
 * Return: None
 */
QDF_STATUS sme_qos_find_all_in_flow_list(tpAniSirGlobal mac_ctx,
					 sme_QosSearchInfo search_key,
					 sme_QosProcessSearchEntry fnp)
{
	tListElem *list_elt = NULL, *list_next_elt = NULL;
	sme_QosSessionInfo *qos_session;
	sme_QosFlowInfoEntry *flow_info = NULL;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	sme_QosEdcaAcType ac_type;

	list_elt = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!list_elt) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  FL("Flow List empty, can't search"));
		return QDF_STATUS_E_FAILURE;
	}

	while (list_elt) {
		list_next_elt = csr_ll_next(&sme_qos_cb.flow_list, list_elt,
					    false);
		flow_info = GET_BASE_ADDR(list_elt, sme_QosFlowInfoEntry, link);
		qos_session = &sme_qos_cb.sessionInfo[flow_info->sessionId];
		if ((search_key.sessionId != flow_info->sessionId) &&
		    (search_key.sessionId != SME_QOS_SEARCH_SESSION_ID_ANY)) {
			list_elt = list_next_elt;
			continue;
		}

		if ((search_key.index & SME_QOS_SEARCH_KEY_INDEX_1) &&
		    (search_key.key.QosFlowID == flow_info->QosFlowID)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			    FL("match found on flowID, ending search"));
			status = fnp(mac_ctx, list_elt);
			if (QDF_STATUS_E_FAILURE == status) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				    QDF_TRACE_LEVEL_ERROR,
				    FL("Failed to process entry"));
				break;
			}
		} else if ((search_key.index & SME_QOS_SEARCH_KEY_INDEX_2) &&
			   (search_key.key.ac_type == flow_info->ac_type)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			    FL("match found on ac, ending search"));
			ac_type = flow_info->ac_type;
			flow_info->hoRenewal =
				qos_session->ac_info[ac_type].hoRenewal;
			status = fnp(mac_ctx, list_elt);
			if (QDF_STATUS_E_FAILURE == status) {
				QDF_TRACE(QDF_MODULE_ID_SME,
				    QDF_TRACE_LEVEL_ERROR,
				    FL("Failed to process entry"));
				break;
			}
		}
		list_elt = list_next_elt;
	}
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_is_acm() - Utility function to check if a particular AC
   mandates Admission Control.
   \param ac - Enumeration of the various EDCA Access Categories.

   \return true if the AC mandates Admission Control

   \sa

   --------------------------------------------------------------------------*/
bool sme_qos_is_acm(tpAniSirGlobal pMac, tSirBssDescription *pSirBssDesc,
		    sme_QosEdcaAcType ac, tDot11fBeaconIEs *pIes)
{
	bool ret_val = false;
	tDot11fBeaconIEs *pIesLocal;
	if (!pSirBssDesc) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: pSirBssDesc is NULL", __func__, __LINE__);
		return false;
	}

	if (NULL != pIes) {
		/* IEs were provided so use them locally */
		pIesLocal = pIes;
	} else {
		/* IEs were not provided so parse them ourselves */
		if (!QDF_IS_STATUS_SUCCESS
			    (csr_get_parsed_bss_description_ies
				    (pMac, pSirBssDesc, &pIesLocal))) {
			/* err msg */
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: csr_get_parsed_bss_description_ies() failed",
				  __func__, __LINE__);
			return false;
		}

		/* if success then pIesLocal was allocated */
	}

	if (CSR_IS_QOS_BSS(pIesLocal)) {
		switch (ac) {
		case SME_QOS_EDCA_AC_BE:
			if (pIesLocal->WMMParams.acbe_acm)
				ret_val = true;
			break;
		case SME_QOS_EDCA_AC_BK:
			if (pIesLocal->WMMParams.acbk_acm)
				ret_val = true;
			break;
		case SME_QOS_EDCA_AC_VI:
			if (pIesLocal->WMMParams.acvi_acm)
				ret_val = true;
			break;
		case SME_QOS_EDCA_AC_VO:
			if (pIesLocal->WMMParams.acvo_acm)
				ret_val = true;
			break;
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: unknown AC = %d",
				  __func__, __LINE__, ac);
			/* Assert */
			QDF_ASSERT(0);
			break;
		}
	} /* IS_QOS_BSS */
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: ACM = %d for AC = %d",
		  __func__, __LINE__, ret_val, ac);
	if (NULL == pIes) {
		/* IEs were allocated locally so free them */
		qdf_mem_free(pIesLocal);
	}
	return ret_val;
}

/**
 * sme_qos_buffer_existing_flows() - buffer existing flows in flow_list
 * @mac_ctx: global MAC context
 * @sessionid: session ID
 *
 * Utility function to buffer the existing flows in flow_list,
 * so that we can renew them after handoff is done.
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sme_qos_buffer_existing_flows(tpAniSirGlobal mac_ctx,
						uint8_t sessionid)
{
	tListElem *list_entry = NULL, *list_nextentry = NULL;
	sme_QosSessionInfo *qos_session;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosCmdInfo cmd;
	sme_qos_setupCmdInfo *setupinfo;

	list_entry = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!list_entry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  FL("Flow List empty, nothing to buffer"));
		return QDF_STATUS_E_FAILURE;
	}

	while (list_entry) {
		list_nextentry = csr_ll_next(&sme_qos_cb.flow_list, list_entry,
					     false);
		flow_info = GET_BASE_ADDR(list_entry, sme_QosFlowInfoEntry,
					  link);
		if (flow_info->sessionId != sessionid) {
			list_entry = list_nextentry;
			continue;
		}

		if ((SME_QOS_REASON_REQ_SUCCESS == flow_info->reason) ||
		    (SME_QOS_REASON_SETUP == flow_info->reason)) {
			cmd.command = SME_QOS_SETUP_REQ;
			cmd.pMac = mac_ctx;
			cmd.sessionId = sessionid;
			setupinfo = &cmd.u.setupCmdInfo;

			setupinfo->HDDcontext = flow_info->HDDcontext;
			setupinfo->QoSInfo = flow_info->QoSInfo;
			setupinfo->QoSCallback = flow_info->QoSCallback;
			/* shouldn't be needed */
			setupinfo->UPType = SME_QOS_WMM_UP_MAX;
			setupinfo->QosFlowID = flow_info->QosFlowID;
			if (SME_QOS_REASON_SETUP == flow_info->reason)
				setupinfo->hoRenewal = false;
			else
				setupinfo->hoRenewal = true;

			if (!QDF_IS_STATUS_SUCCESS
				    (sme_qos_buffer_cmd(&cmd, true)))
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("couldn't buffer the setup request"
					  " for flow %d in handoff state"),
					  flow_info->QosFlowID);
			else
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  FL("buffered a setup request for "
					  "flow %d in handoff state"),
					  flow_info->QosFlowID);
		} else if (SME_QOS_REASON_RELEASE == flow_info->reason) {
			cmd.command = SME_QOS_RELEASE_REQ;
			cmd.pMac = mac_ctx;
			cmd.sessionId = sessionid;
			cmd.u.releaseCmdInfo.QosFlowID = flow_info->QosFlowID;
			if (!QDF_IS_STATUS_SUCCESS
				    (sme_qos_buffer_cmd(&cmd, true)))
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("couldn't buffer the release req"
					  " for flow %d in handoff state"),
					  flow_info->QosFlowID);
			else
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  FL("buffered a release request for "
					  "flow %d in handoff state"),
					  flow_info->QosFlowID);
		} else if (SME_QOS_REASON_MODIFY_PENDING ==
			   flow_info->reason) {
			cmd.command = SME_QOS_MODIFY_REQ;
			cmd.pMac = mac_ctx;
			cmd.sessionId = sessionid;
			cmd.u.modifyCmdInfo.QosFlowID = flow_info->QosFlowID;
			cmd.u.modifyCmdInfo.QoSInfo = flow_info->QoSInfo;
			if (!QDF_IS_STATUS_SUCCESS
				    (sme_qos_buffer_cmd(&cmd, true)))
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("couldn't buffer the modify req"
					  " for flow %d in handoff state"),
					  flow_info->QosFlowID);
			else
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_INFO_HIGH,
					  FL("buffered a modify request for "
					  "flow %d in handoff state"),
					  flow_info->QosFlowID);
		}
		/* delete the entry from Flow List */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  FL("Deleting original entry at %p with flowID %d"),
			  flow_info, flow_info->QosFlowID);
		csr_ll_remove_entry(&sme_qos_cb.flow_list, list_entry, true);
		qdf_mem_free(flow_info);

		list_entry = list_nextentry;
	}
	qos_session = &sme_qos_cb.sessionInfo[sessionid];
	qos_session->uapsdAlreadyRequested = false;
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_delete_existing_flows() - Utility function to Delete the existing
   flows in flow_list, if we lost connectivity.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
static QDF_STATUS sme_qos_delete_existing_flows(tpAniSirGlobal pMac,
						uint8_t sessionId)
{
	tListElem *pEntry = NULL, *pNextEntry = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;
	pEntry = csr_ll_peek_head(&sme_qos_cb.flow_list, true);
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
			  "%s: %d: Flow List empty, nothing to delete",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	while (pEntry) {
		pNextEntry = csr_ll_next(&sme_qos_cb.flow_list, pEntry, true);
		flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
		if (flow_info->sessionId == sessionId) {
			if ((SME_QOS_REASON_REQ_SUCCESS == flow_info->reason) ||
			    (SME_QOS_REASON_SETUP == flow_info->reason) ||
			    (SME_QOS_REASON_RELEASE == flow_info->reason) ||
			    (SME_QOS_REASON_MODIFY == flow_info->reason)) {
				flow_info->QoSCallback(pMac,
						       flow_info->HDDcontext,
						       NULL,
						       SME_QOS_STATUS_RELEASE_QOS_LOST_IND,
						       flow_info->QosFlowID);
			}
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
				  "%s: %d: Deleting entry at %p with flowID %d",
				  __func__, __LINE__,
				  flow_info, flow_info->QosFlowID);
			/* delete the entry from Flow List */
			csr_ll_remove_entry(&sme_qos_cb.flow_list, pEntry,
					    true);
			qdf_mem_free(flow_info);
		}
		pEntry = pNextEntry;
	}
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_buffer_cmd() - buffer a request.
 * @pcmd: a pointer to the cmd structure to be saved inside the buffered
 *               cmd link list
 * @insert_head: flag indicate if cmd should be added to the list head.
 *
 * Utility function to buffer a request (setup/modify/release) from client
 * while processing another one on the same AC.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_buffer_cmd(sme_QosCmdInfo *pcmd, bool insert_head)
{
	sme_QosSessionInfo *pSession;
	sme_QosCmdInfoEntry *pentry = NULL;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: Invoked", __func__, __LINE__);
	pentry =
		(sme_QosCmdInfoEntry *) qdf_mem_malloc(sizeof(sme_QosCmdInfoEntry));
	if (!pentry) {
		/* err msg */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Memory allocation failure",
			  __func__, __LINE__);
		return QDF_STATUS_E_NOMEM;
	}
	/* copy the entire CmdInfo */
	pentry->cmdInfo = *pcmd;

	pSession = &sme_qos_cb.sessionInfo[pcmd->sessionId];
	if (insert_head) {
		csr_ll_insert_head(&pSession->bufferedCommandList, &pentry->link,
				   true);
	} else {
		csr_ll_insert_tail(&pSession->bufferedCommandList, &pentry->link,
				   true);
	}
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_process_buffered_cmd() - process qos buffered request
 * @session_id: Session ID
 *
 * Utility function to process a buffered request (setup/modify/release)
 * initially came from the client.
 *
 * Return:QDF_STATUS
 */
static QDF_STATUS sme_qos_process_buffered_cmd(uint8_t session_id)
{
	sme_QosSessionInfo *qos_session;
	sme_QosCmdInfoEntry *pcmd = NULL;
	tListElem *list_elt = NULL;
	sme_QosStatusType hdd_status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
	QDF_STATUS qdf_ret_status = QDF_STATUS_SUCCESS;
	sme_QosCmdInfo *qos_cmd = NULL;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
		  FL("Invoked on session %d"), session_id);
	qos_session = &sme_qos_cb.sessionInfo[session_id];
	if (!csr_ll_is_list_empty(&qos_session->bufferedCommandList, false)) {
		list_elt = csr_ll_remove_head(&qos_session->bufferedCommandList,
					      true);
		if (!list_elt) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  FL("no more buffered commands on session %d"),
				  session_id);
			qos_session->readyForPowerSave = true;
			return QDF_STATUS_E_FAILURE;
		}
		pcmd = GET_BASE_ADDR(list_elt, sme_QosCmdInfoEntry, link);
		qos_cmd = &pcmd->cmdInfo;

		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  FL("Qos cmd %d"), qos_cmd->command);
		switch (qos_cmd->command) {
		case SME_QOS_SETUP_REQ:
			hdd_status = sme_qos_internal_setup_req(
				       qos_cmd->pMac, qos_cmd->sessionId,
				       &qos_cmd->u.setupCmdInfo.QoSInfo,
				       qos_cmd->u.setupCmdInfo.QoSCallback,
				       qos_cmd->u.setupCmdInfo.HDDcontext,
				       qos_cmd->u.setupCmdInfo.UPType,
				       qos_cmd->u.setupCmdInfo.QosFlowID,
				       true, qos_cmd->u.setupCmdInfo.hoRenewal);
			if (SME_QOS_STATUS_SETUP_FAILURE_RSP == hdd_status) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("sme_qos_internal_setup_req failed on session %d"),
					  session_id);
				qdf_ret_status = QDF_STATUS_E_FAILURE;
			}
			break;
		case SME_QOS_RELEASE_REQ:
			hdd_status = sme_qos_internal_release_req(qos_cmd->pMac,
					qos_cmd->sessionId,
					qos_cmd->u.releaseCmdInfo.QosFlowID,
					true);
			if (SME_QOS_STATUS_RELEASE_FAILURE_RSP == hdd_status) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("sme_qos_internal_release_req failed on session %d"),
					  session_id);
				qdf_ret_status = QDF_STATUS_E_FAILURE;
			}
			break;
		case SME_QOS_MODIFY_REQ:
			hdd_status = sme_qos_internal_modify_req(qos_cmd->pMac,
					&qos_cmd->u.modifyCmdInfo.QoSInfo,
					qos_cmd->u.modifyCmdInfo.QosFlowID,
					true);
			if (SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP ==
				hdd_status) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("sme_qos_internal_modify_req failed on session %d"),
					  session_id);
				qdf_ret_status = QDF_STATUS_E_FAILURE;
			}
			break;
		case SME_QOS_RESEND_REQ:
			hdd_status = sme_qos_re_request_add_ts(qos_cmd->pMac,
					qos_cmd->sessionId,
					&qos_cmd->u.resendCmdInfo.QoSInfo,
					qos_cmd->u.resendCmdInfo.ac,
					qos_cmd->u.resendCmdInfo.tspecMask);
			if (SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP ==
				hdd_status) {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  FL("sme_qos_re_request_add_ts failed on session %d"),
					  session_id);
				qdf_ret_status = QDF_STATUS_E_FAILURE;
			}
			break;
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  FL("On session %d unknown cmd = %d"),
				  session_id, qos_cmd->command);
			QDF_ASSERT(0);
			break;
		}
		/* buffered command has been processed, reclaim the memory */
		qdf_mem_free(pcmd);
	} else {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  FL("cmd buffer empty"));
		qos_session->readyForPowerSave = true;
	}
	return qdf_ret_status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_delete_buffered_requests() - Utility function to Delete the buffered
   requests in the buffered_cmd_list, if we lost connectivity.

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
static QDF_STATUS sme_qos_delete_buffered_requests(tpAniSirGlobal pMac,
						   uint8_t sessionId)
{
	sme_QosSessionInfo *pSession;
	sme_QosCmdInfoEntry *pcmd = NULL;
	tListElem *pEntry = NULL, *pNextEntry = NULL;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: Invoked on session %d",
		  __func__, __LINE__, sessionId);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	pEntry = csr_ll_peek_head(&pSession->bufferedCommandList, true);
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_WARN,
			  "%s: %d: Buffered List empty, nothing to delete on session %d",
			  __func__, __LINE__, sessionId);
		return QDF_STATUS_E_FAILURE;
	}
	while (pEntry) {
		pNextEntry =
			csr_ll_next(&pSession->bufferedCommandList, pEntry, true);
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
			  "%s: %d: deleting entry from buffered List", __func__,
			  __LINE__);
		/* delete the entry from Flow List */
		csr_ll_remove_entry(&pSession->bufferedCommandList, pEntry,
				    true);
		/* reclaim the memory */
		pcmd = GET_BASE_ADDR(pEntry, sme_QosCmdInfoEntry, link);
		qdf_mem_free(pcmd);
		pEntry = pNextEntry;
	}
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_save_assoc_info() - save assoc info.
 * @pSession: pointer to QOS session
 * @pAssoc_info: pointer to the assoc structure to store the BSS descriptor
 *               of the AP, the profile that HDD sent down with the
 *               connect request
 *
 * Utility function to save the assoc info in the CB like BSS descriptor
 * of the AP, the profile that HDD sent down with the connect request,
 * while CSR notifies for assoc/reassoc success.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS sme_qos_save_assoc_info(sme_QosSessionInfo *pSession,
				   sme_QosAssocInfo *pAssoc_info)
{
	tSirBssDescription *pBssDesc = NULL;
	uint32_t bssLen = 0;
	if (NULL == pAssoc_info) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: pAssoc_info is NULL", __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	/* clean up the assoc info if already set */
	if (pSession->assocInfo.pBssDesc) {
		qdf_mem_free(pSession->assocInfo.pBssDesc);
		pSession->assocInfo.pBssDesc = NULL;
	}
	bssLen = pAssoc_info->pBssDesc->length +
		 sizeof(pAssoc_info->pBssDesc->length);
	/* save the bss Descriptor */
	pBssDesc = (tSirBssDescription *) qdf_mem_malloc(bssLen);
	if (!pBssDesc) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: couldn't allocate memory for the bss Descriptor",
			  __func__, __LINE__);
		return QDF_STATUS_E_NOMEM;
	}
	qdf_mem_copy(pBssDesc, pAssoc_info->pBssDesc, bssLen);
	pSession->assocInfo.pBssDesc = pBssDesc;
	/* save the apsd info from assoc */
	if (pAssoc_info->pProfile) {
		pSession->apsdMask |= pAssoc_info->pProfile->uapsd_mask;
	}
	/* [TODO] Do we need to update the global APSD bitmap? */
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_setup_fnp() - Utility function (pointer) to notify other entries
   in FLOW list on the same AC that qos params got modified
   \param pMac - Pointer to the global MAC parameter structure.
   \param pEntry - Pointer to an entry in the flow_list(i.e. tListElem structure)

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_setup_fnp(tpAniSirGlobal pMac, tListElem *pEntry)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosStatusType hdd_status = SME_QOS_STATUS_SETUP_MODIFIED_IND;
	sme_QosEdcaAcType ac;
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Entry is NULL", __func__, __LINE__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;
	pSession = &sme_qos_cb.sessionInfo[flow_info->sessionId];
	pACInfo = &pSession->ac_info[ac];
	if (SME_QOS_REASON_REQ_SUCCESS == flow_info->reason) {
		/* notify HDD, only the other Flows running on the AC */
		flow_info->QoSCallback(pMac, flow_info->HDDcontext,
				       &pACInfo->curr_QoSInfo[flow_info->
							      tspec_mask - 1],
				       hdd_status, flow_info->QosFlowID);
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Entry with flowID = %d getting notified",
			  __func__, __LINE__, flow_info->QosFlowID);
	}
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_modification_notify_fnp() - Utility function (pointer) to notify
   other entries in FLOW list on the same AC that qos params got modified
   \param pMac - Pointer to the global MAC parameter structure.
   \param pEntry - Pointer to an entry in the flow_list(i.e. tListElem structure)

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_modification_notify_fnp(tpAniSirGlobal pMac, tListElem *pEntry)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosStatusType hdd_status = SME_QOS_STATUS_SETUP_MODIFIED_IND;
	sme_QosEdcaAcType ac;
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Entry is NULL", __func__, __LINE__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;
	pSession = &sme_qos_cb.sessionInfo[flow_info->sessionId];
	pACInfo = &pSession->ac_info[ac];
	if (SME_QOS_REASON_REQ_SUCCESS == flow_info->reason) {
		/* notify HDD, only the other Flows running on the AC */
		flow_info->QoSCallback(pMac, flow_info->HDDcontext,
				       &pACInfo->curr_QoSInfo[flow_info->
							      tspec_mask - 1],
				       hdd_status, flow_info->QosFlowID);
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Entry with flowID = %d getting notified",
			  __func__, __LINE__, flow_info->QosFlowID);
	}
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_modify_fnp() - Utility function (pointer) to delete the origianl
   entry in FLOW list & add the modified one
   \param pMac - Pointer to the global MAC parameter structure.
   \param pEntry - Pointer to an entry in the flow_list(i.e. tListElem structure)

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_modify_fnp(tpAniSirGlobal pMac, tListElem *pEntry)
{
	sme_QosFlowInfoEntry *flow_info = NULL;
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Entry is NULL", __func__, __LINE__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
		  FL("reason %d"), flow_info->reason);
	switch (flow_info->reason) {
	case SME_QOS_REASON_MODIFY_PENDING:
		/* set the proper reason code for the new (with modified params) entry */
		flow_info->reason = SME_QOS_REASON_REQ_SUCCESS;
		break;
	case SME_QOS_REASON_MODIFY:
		/* delete the original entry from Flow List */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Deleting original entry at %p with flowID %d",
			  __func__, __LINE__, flow_info, flow_info->QosFlowID);
		csr_ll_remove_entry(&sme_qos_cb.flow_list, pEntry, true);
		/* reclaim the memory */
		qdf_mem_free(flow_info);
		break;
	default:
		break;
	}
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_del_ts_ind_fnp() - Utility function (pointer) to find all Flows on
   the perticular AC & delete them, also send HDD indication through the callback
   it registered per request
   \param pMac - Pointer to the global MAC parameter structure.
   \param pEntry - Pointer to an entry in the flow_list(i.e. tListElem structure)

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_del_ts_ind_fnp(tpAniSirGlobal pMac, tListElem *pEntry)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosFlowInfoEntry *flow_info = NULL;
	sme_QosEdcaAcType ac;
	QDF_STATUS lock_status = QDF_STATUS_E_FAILURE;
	sme_QosStatusType status;

	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Entry is NULL", __func__, __LINE__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	/* delete the entry from Flow List */
	flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;
	pSession = &sme_qos_cb.sessionInfo[flow_info->sessionId];
	pACInfo = &pSession->ac_info[ac];
	pACInfo->relTrig = SME_QOS_RELEASE_BY_AP;

	lock_status = sme_acquire_global_lock(&pMac->sme);
	if (!QDF_IS_STATUS_SUCCESS(lock_status)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Unable to obtain lock", __func__, __LINE__);
		return SME_QOS_STATUS_RELEASE_FAILURE_RSP;
	}
	/* Call the internal function for QoS release, adding a layer of abstraction */
	status =
		sme_qos_internal_release_req(pMac, flow_info->sessionId,
					     flow_info->QosFlowID, false);
	sme_release_global_lock(&pMac->sme);
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: QoS Release return status on Flow %d is %d",
		  __func__, __LINE__, flow_info->QosFlowID, status);

	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_reassoc_success_ev_fnp  Notification function to HDD
 *
 * @mac_ctx: Mac context
 * @entry:   Pointer to an entry in the flow_list
 *
 * Utility function (pointer) to notify HDD
 * the success for the requested flow & notify all the other flows
 * running on the same AC that QoS params got modified
 *
 * Return:  QDF_STATUS enumaration
 */
QDF_STATUS
sme_qos_reassoc_success_ev_fnp(tpAniSirGlobal mac_ctx,
		tListElem *entry)
{
	sme_QosSessionInfo *qos_session;
	sme_QosACInfo *ac_info;
	sme_QosFlowInfoEntry *flow_info = NULL;
	bool delete_entry = false;
	sme_QosStatusType hdd_status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
	sme_QosEdcaAcType ac;
	QDF_STATUS pmc_status = QDF_STATUS_E_FAILURE;
	if (!entry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			"%s: %d: Entry is NULL", __func__, __LINE__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	flow_info = GET_BASE_ADDR(entry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;
	qos_session = &sme_qos_cb.sessionInfo[flow_info->sessionId];
	ac_info = &qos_session->ac_info[ac];
	switch (flow_info->reason) {
	case SME_QOS_REASON_SETUP:
		hdd_status = SME_QOS_STATUS_SETUP_SUCCESS_IND;
		delete_entry = false;
		flow_info->reason = SME_QOS_REASON_REQ_SUCCESS;
		/* -Check for the case where we had to do reassoc to
		 * reset the apsd bit for the ac - release or modify
		 * scenario.Notify PMC as App is looking for APSD
		 * If we already requested then we don't need to
		 * do anything.*/
		if (ac_info->requested_QoSInfo[SME_QOS_TSPEC_INDEX_0].ts_info.psb &&
			!qos_session->uapsdAlreadyRequested) {
			/* this is the first flow to detect we need
			 * PMC in UAPSD mode */
			pmc_status = sme_ps_start_uapsd(mac_ctx,
					flow_info->sessionId,
					sme_qos_pmc_offload_start_uapsd_callback,
					qos_session);
			/* if PMC doesn't return success right away means
			 * it is yet to put the module in BMPS state & later
			 * to UAPSD state */
			if (QDF_STATUS_E_FAILURE == pmc_status) {
				hdd_status =
					SME_QOS_STATUS_SETUP_SUCCESS_IND_APSD_SET_FAILED;
				/* we need to always notify this case */
				flow_info->hoRenewal = false;
			} else if (QDF_STATUS_PMC_PENDING == pmc_status) {
				/* let other flows know PMC has been notified */
				qos_session->uapsdAlreadyRequested =
				true;

			}
		}
		/* for any other pmc status we declare success */
		break;
	case SME_QOS_REASON_RELEASE:
		ac_info->num_flows[SME_QOS_TSPEC_INDEX_0]--;
	/* fall through */
	case SME_QOS_REASON_MODIFY:
		delete_entry = true;
		break;
	case SME_QOS_REASON_MODIFY_PENDING:
		hdd_status = SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_IND;
		delete_entry = false;
		flow_info->reason = SME_QOS_REASON_REQ_SUCCESS;
		if (ac_info->requested_QoSInfo[SME_QOS_TSPEC_INDEX_0].ts_info.psb &&
			!qos_session->uapsdAlreadyRequested) {
			/* this is the first flow to detect we need
			 * PMC in UAPSD mode */
			pmc_status = sme_ps_start_uapsd(mac_ctx,
					 flow_info->sessionId,
					 sme_qos_pmc_offload_start_uapsd_callback,
					 qos_session);
			/* if PMC doesn't return success right away means
			 * it is yet to put the module in BMPS state &
			 * later to UAPSD state */
			if (QDF_STATUS_E_FAILURE == pmc_status) {
				hdd_status =
					SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_IND_APSD_SET_FAILED;
				/* we need to always notify this case */
				flow_info->hoRenewal = false;
			} else if (QDF_STATUS_PMC_PENDING == pmc_status) {
				qos_session->uapsdAlreadyRequested =
					true;
			}
		}
		/* for any other pmc status we declare success */
		break;
	case SME_QOS_REASON_REQ_SUCCESS:
		hdd_status = SME_QOS_STATUS_SETUP_MODIFIED_IND;
	/* fall through */
	default:
		delete_entry = false;
		break;
	}
	if (!delete_entry) {
		if (!flow_info->hoRenewal) {
			flow_info->QoSCallback(mac_ctx, flow_info->HDDcontext,
				&ac_info->curr_QoSInfo[SME_QOS_TSPEC_INDEX_0],
				hdd_status, flow_info->QosFlowID);
		} else {
			flow_info->hoRenewal = false;
		}
	} else {
		/* delete the entry from Flow List */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			FL("Deleting entry at %p with flowID %d"),
			flow_info, flow_info->QosFlowID);
		csr_ll_remove_entry(&sme_qos_cb.flow_list, entry, true);
		/* reclaim the memory */
		qdf_mem_free(flow_info);
	}
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_add_ts_failure_fnp() - Utility function (pointer),
   if the Addts request was for for an flow setup request, delete the entry from
   Flow list & notify HDD
   if the Addts request was for downgrading of QoS params because of an flow
   release requested on the AC, delete the entry from Flow list & notify HDD
   if the Addts request was for change of QoS params because of an flow
   modification requested on the AC, delete the new entry from Flow list & notify
   HDD

   \param pMac - Pointer to the global MAC parameter structure.
   \param pEntry - Pointer to an entry in the flow_list(i.e. tListElem structure)

   \return QDF_STATUS

   \sa

   --------------------------------------------------------------------------*/
QDF_STATUS sme_qos_add_ts_failure_fnp(tpAniSirGlobal pMac, tListElem *pEntry)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosFlowInfoEntry *flow_info = NULL;
	bool inform_hdd = false;
	sme_QosStatusType hdd_status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
	sme_QosEdcaAcType ac;
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Entry is NULL", __func__, __LINE__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;
	pSession = &sme_qos_cb.sessionInfo[flow_info->sessionId];
	pACInfo = &pSession->ac_info[ac];
	switch (flow_info->reason) {
	case SME_QOS_REASON_SETUP:
		hdd_status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
		pACInfo->num_flows[pACInfo->tspec_pending - 1]--;
		inform_hdd = true;
		break;
	case SME_QOS_REASON_RELEASE:
		hdd_status = SME_QOS_STATUS_RELEASE_FAILURE_RSP;
		pACInfo->num_flows[pACInfo->tspec_pending - 1]--;
		inform_hdd = true;
		break;
	case SME_QOS_REASON_MODIFY_PENDING:
		hdd_status = SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
		inform_hdd = true;
		break;
	case SME_QOS_REASON_MODIFY:
		flow_info->reason = SME_QOS_REASON_REQ_SUCCESS;
	case SME_QOS_REASON_REQ_SUCCESS:
	default:
		inform_hdd = false;
		break;
	}
	if (inform_hdd) {
		/* notify HDD, only the requested Flow, other Flows running on the AC stay */
		/* intact */
		if (!flow_info->hoRenewal) {
			flow_info->QoSCallback(pMac, flow_info->HDDcontext,
					       &pACInfo->curr_QoSInfo[pACInfo->
								      tspec_pending
								      - 1],
					       hdd_status,
					       flow_info->QosFlowID);
		} else {
			flow_info->QoSCallback(pMac, flow_info->HDDcontext,
					       &pACInfo->curr_QoSInfo[pACInfo->
								      tspec_pending
								      - 1],
					       SME_QOS_STATUS_RELEASE_QOS_LOST_IND,
					       flow_info->QosFlowID);
		}
		/* delete the entry from Flow List */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Deleting entry at %p with flowID %d",
			  __func__, __LINE__, flow_info, flow_info->QosFlowID);
		csr_ll_remove_entry(&sme_qos_cb.flow_list, pEntry, true);
		/* reclaim the memory */
		qdf_mem_free(flow_info);
	}
	return QDF_STATUS_SUCCESS;
}

/**
 * sme_qos_add_ts_success_fnp() - Utility function (pointer) to notify HDD
 *
 * @mac_ctx: Mac context
 * @entry:   Pointer to an entry in the flow_list(i.e. tListElem structure).
 *
 * Description : Utility function (pointer),
 * If the Addts request was for for an flow setup request, notify
 * HDD for success for the flow & notify all the other flows running
 * on the same AC that QoS params got modified
 * if the Addts request was for downgrading of QoS params
 * because of an flow release requested on the AC, delete
 * the entry from Flow list & notify HDD if the Addts request
 * was for change of QoS params because of an flow modification
 * requested on the AC, delete the old entry from Flow list & notify
 * HDD for success for the flow & notify all the other flows running
 * on the same AC that QoS params got modified
 *
 * Return: Status
 */

QDF_STATUS sme_qos_add_ts_success_fnp(tpAniSirGlobal mac_ctx,
		tListElem *entry)
{
	sme_QosSessionInfo *qos_session;
	sme_QosACInfo *ac_info;
	sme_QosFlowInfoEntry *flow_info = NULL;
	bool inform_hdd = false;
	bool delete_entry = false;
	sme_QosStatusType hdd_status = SME_QOS_STATUS_SETUP_FAILURE_RSP;
	sme_QosEdcaAcType ac;
	QDF_STATUS pmc_status = QDF_STATUS_E_FAILURE;
	tCsrRoamModifyProfileFields profile_fields;
	uint8_t psb;
	uint8_t tspec_index;

	if (!entry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			FL("Entry is NULL"));
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}
	flow_info = GET_BASE_ADDR(entry, sme_QosFlowInfoEntry, link);
	ac = flow_info->ac_type;
	qos_session = &sme_qos_cb.sessionInfo[flow_info->sessionId];
	ac_info = &qos_session->ac_info[ac];
	tspec_index = ac_info->tspec_pending - 1;
	if (flow_info->tspec_mask != ac_info->tspec_pending) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			FL(" No need to notify the HDD, the ADDTS "
			"success is not for index = %d of the AC = %d"),
			flow_info->tspec_mask, ac);
		return QDF_STATUS_SUCCESS;
	}
	switch (flow_info->reason) {
	case SME_QOS_REASON_SETUP:
		hdd_status = SME_QOS_STATUS_SETUP_SUCCESS_IND;
		flow_info->reason = SME_QOS_REASON_REQ_SUCCESS;
		delete_entry = false;
		inform_hdd = true;
		/* check if App is looking for APSD
		 * notify PMC as App is looking for APSD. If we already
		 * requested then we don't need to do anything */
		if (ac_info->requested_QoSInfo[tspec_index].ts_info.psb &&
			!qos_session->uapsdAlreadyRequested) {
			/* this is the first flow to detect we need
			 * PMC in UAPSD mode */
			pmc_status = sme_ps_start_uapsd(mac_ctx,
				flow_info->sessionId,
				sme_qos_pmc_offload_start_uapsd_callback,
				qos_session);
			/* if PMC doesn't return success right away means
			 * it is yet to put the module in BMPS state & later
			 * to UAPSD state */
			if (QDF_STATUS_E_FAILURE == pmc_status) {
				hdd_status =
					SME_QOS_STATUS_SETUP_SUCCESS_IND_APSD_SET_FAILED;
				/* we need to always notify this case */
				flow_info->hoRenewal = false;
			} else if (QDF_STATUS_PMC_PENDING == pmc_status) {
				/* let other flows know PMC has been notified */
				qos_session->uapsdAlreadyRequested =
				true;
			}
			/* for any other pmc status we declare success */
		}
		break;
	case SME_QOS_REASON_RELEASE:
		ac_info->num_flows[tspec_index]--;
		hdd_status = SME_QOS_STATUS_RELEASE_SUCCESS_RSP;
		inform_hdd = true;
		delete_entry = true;
		break;
	case SME_QOS_REASON_MODIFY:
		delete_entry = true;
		inform_hdd = false;
		break;
	case SME_QOS_REASON_MODIFY_PENDING:
		hdd_status = SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_IND;
		delete_entry = false;
		flow_info->reason = SME_QOS_REASON_REQ_SUCCESS;
		inform_hdd = true;
		psb = ac_info->requested_QoSInfo[tspec_index].ts_info.psb;
		/* notify PMC if App is looking for APSD
		 * notify PMC as App is looking for APSD. If we already
		 * requested then we don't need to do anything. */
		if (psb && !qos_session->uapsdAlreadyRequested) {
			/* this is the first flow to detect
			 * we need PMC in UAPSD mode */
			pmc_status =
				sme_ps_start_uapsd(mac_ctx,
					flow_info->sessionId,
					sme_qos_pmc_offload_start_uapsd_callback,
					qos_session);
			/* if PMC doesn't return success right
			 * away means it is yet to put
			 * the module in BMPS state & later to UAPSD state */
			if (QDF_STATUS_E_FAILURE == pmc_status) {
				hdd_status =
				 SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_IND_APSD_SET_FAILED;
				/* we need to always notify this case */
				flow_info->hoRenewal = false;
			} else if (QDF_STATUS_PMC_PENDING == pmc_status) {
				/* let other flows know PMC has been notified */
				qos_session->uapsdAlreadyRequested =
				true;
			}
			/* for any other pmc status we declare success */
		} else if (!psb &&
		((ac_info->num_flows[flow_info->tspec_mask - 1] == 1)
			    && (SME_QOS_TSPEC_MASK_BIT_1_2_SET !=
			ac_info->tspec_mask_status))) {
			/* this is the only TSPEC active on this AC */
			/* so indicate that we no longer require APSD */
			qos_session->apsdMask &=
				~(1 << (SME_QOS_EDCA_AC_VO - ac));
			/* Also update modifyProfileFields.uapsd_mask
			 * in CSR for consistency */
			csr_get_modify_profile_fields(mac_ctx,
				flow_info->sessionId,
				&profile_fields);
			profile_fields.uapsd_mask =
				qos_session->apsdMask;
			csr_set_modify_profile_fields(mac_ctx,
				flow_info->sessionId,
				&profile_fields);
			if (!qos_session->apsdMask) {
				sme_ps_uapsd_disable(mac_ctx,
					flow_info->sessionId);
			}
		}
		break;
	case SME_QOS_REASON_REQ_SUCCESS:
		hdd_status = SME_QOS_STATUS_SETUP_MODIFIED_IND;
		inform_hdd = true;
	default:
		delete_entry = false;
		break;
	}
	if (inform_hdd) {
		if (!flow_info->hoRenewal) {
			flow_info->QoSCallback(mac_ctx, flow_info->HDDcontext,
			&ac_info->curr_QoSInfo[tspec_index],
			hdd_status,
			flow_info->QosFlowID);
		} else {
			flow_info->hoRenewal = false;
		}
	}
	if (delete_entry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			FL("Deleting entry at %p with flowID %d"),
			flow_info, flow_info->QosFlowID);
		/* delete the entry from Flow List */
		csr_ll_remove_entry(&sme_qos_cb.flow_list, entry, true);
		/* reclaim the memory */
		qdf_mem_free(flow_info);
	}
	return QDF_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_is_rsp_pending() - Utility function to check if we are waiting
   for an AddTS or reassoc response on some AC other than the given AC

   \param sessionId - Session we are interted in
   \param ac - Enumeration of the various EDCA Access Categories.

   \return bool
   true - Response is pending on an AC

   \sa

   --------------------------------------------------------------------------*/
static bool sme_qos_is_rsp_pending(uint8_t sessionId, sme_QosEdcaAcType ac)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType acIndex;
	bool status = false;
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	for (acIndex = SME_QOS_EDCA_AC_BE; acIndex < SME_QOS_EDCA_AC_MAX;
	     acIndex++) {
		if (acIndex == ac) {
			continue;
		}
		pACInfo = &pSession->ac_info[acIndex];
		if ((pACInfo->tspec_pending) || (pACInfo->reassoc_pending)) {
			status = true;
			break;
		}
	}
	return status;
}

/*--------------------------------------------------------------------------
   \brief sme_qos_update_hand_off() - Function which can be called to update
   Hand-off state of SME QoS Session
   \param sessionId - session id
   \param updateHandOff - value True/False to update the handoff flag

   \sa

   -------------------------------------------------------------------------*/
void sme_qos_update_hand_off(uint8_t sessionId, bool updateHandOff)
{
	sme_QosSessionInfo *pSession;
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_MED,
		  "%s: %d: handoffRequested %d updateHandOff %d",
		  __func__, __LINE__, pSession->handoffRequested,
		  updateHandOff);

	pSession->handoffRequested = updateHandOff;

}

/*--------------------------------------------------------------------------
   \brief sme_qos_is_uapsd_active() - Function which can be called to determine
   if any sessions require PMC to be in U-APSD mode.
   \return bool

   Returns true if at least one session required PMC to be in U-APSD mode
   Returns false if no sessions require PMC to be in U-APSD mode

   \sa

   --------------------------------------------------------------------------*/
static bool sme_qos_is_uapsd_active(void)
{
	sme_QosSessionInfo *pSession;
	uint8_t sessionId;
	for (sessionId = 0; sessionId < CSR_ROAM_SESSION_MAX; ++sessionId) {
		pSession = &sme_qos_cb.sessionInfo[sessionId];
		if ((pSession->sessionActive) && (pSession->apsdMask)) {
			return true;
		}
	}
	/* no active sessions have U-APSD active */
	return false;
}

/*--------------------------------------------------------------------------
   \brief sme_QosPmcStartUAPSDCallback() - Callback function registered with PMC
   to notify SME-QoS when it puts the chip into UAPSD mode

   \param callbackContext - The context passed to PMC during pmc_start_uapsd call.
   \param status - QDF_STATUS returned by PMC.

   \return None

   \sa

   --------------------------------------------------------------------------*/
void sme_qos_pmc_offload_start_uapsd_callback(void *callbackContext,
					      uint32_t sessionId, QDF_STATUS status)
{
	sme_QosSessionInfo *pSession = callbackContext;
	pSession->uapsdAlreadyRequested = false;
}

bool sme_qos_pmc_offload_check_routine(void *callbackContext, uint32_t sessionId)
{
	sme_QosSessionInfo *pSession = &sme_qos_cb.sessionInfo[sessionId];

	if ((pSession->sessionActive) && (!pSession->readyForPowerSave)) {
		return false;
	}
	return true;

}


QDF_STATUS sme_offload_qos_process_out_of_uapsd_mode(tpAniSirGlobal pMac,
						     uint32_t sessionId)
{
	sme_QosSessionInfo *pSession;
	tListElem *pEntry = NULL, *pNextEntry = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;

	pEntry = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: %d: Flow List empty, can't search",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	while (pEntry) {
		pNextEntry = csr_ll_next(&sme_qos_cb.flow_list, pEntry, false);
		flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
		pSession = &sme_qos_cb.sessionInfo[flow_info->sessionId];
		/* only notify the flows which already successfully setup UAPSD */
		if ((sessionId == flow_info->sessionId) &&
		    (flow_info->QoSInfo.max_service_interval ||
		     flow_info->QoSInfo.min_service_interval) &&
		    (SME_QOS_REASON_REQ_SUCCESS == flow_info->reason)) {
			flow_info->QoSCallback(pMac, flow_info->HDDcontext,
					       &pSession->ac_info[flow_info->
								  ac_type].curr_QoSInfo
					       [flow_info->tspec_mask - 1],
					       SME_QOS_STATUS_OUT_OF_APSD_POWER_MODE_IND,
					       flow_info->QosFlowID);
		}
		pEntry = pNextEntry;
	}
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS sme_offload_qos_process_into_uapsd_mode(tpAniSirGlobal pMac,
						   uint32_t sessionId)
{
	sme_QosSessionInfo *pSession;
	tListElem *pEntry = NULL, *pNextEntry = NULL;
	sme_QosFlowInfoEntry *flow_info = NULL;

	pEntry = csr_ll_peek_head(&sme_qos_cb.flow_list, false);
	if (!pEntry) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Flow List empty, can't search",
			  __func__, __LINE__);
		return QDF_STATUS_E_FAILURE;
	}
	while (pEntry) {
		pNextEntry = csr_ll_next(&sme_qos_cb.flow_list, pEntry, false);
		flow_info = GET_BASE_ADDR(pEntry, sme_QosFlowInfoEntry, link);
		pSession = &sme_qos_cb.sessionInfo[flow_info->sessionId];
		/* only notify the flows which already successfully setup UAPSD */
		if ((sessionId == flow_info->sessionId) &&
		    (flow_info->QoSInfo.max_service_interval ||
		     flow_info->QoSInfo.min_service_interval) &&
		    (SME_QOS_REASON_REQ_SUCCESS == flow_info->reason)) {
			flow_info->QoSCallback(pMac, flow_info->HDDcontext,
					       &pSession->ac_info[flow_info->
								  ac_type].curr_QoSInfo
					       [flow_info->tspec_mask - 1],
					       SME_QOS_STATUS_INTO_APSD_POWER_MODE_IND,
					       flow_info->QosFlowID);
		}
		pEntry = pNextEntry;
	}
	return QDF_STATUS_SUCCESS;
}

void sme_qos_cleanup_ctrl_blk_for_handoff(tpAniSirGlobal pMac, uint8_t sessionId)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	sme_QosEdcaAcType ac;
	pSession = &sme_qos_cb.sessionInfo[sessionId];

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
		  FL("invoked on session %d"), sessionId);

	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		pACInfo = &pSession->ac_info[ac];
		qdf_mem_zero(pACInfo->curr_QoSInfo,
			     sizeof(sme_QosWmmTspecInfo) *
			     SME_QOS_TSPEC_INDEX_MAX);
		qdf_mem_zero(pACInfo->requested_QoSInfo,
			     sizeof(sme_QosWmmTspecInfo) *
			     SME_QOS_TSPEC_INDEX_MAX);
		pACInfo->num_flows[0] = 0;
		pACInfo->num_flows[1] = 0;
		pACInfo->reassoc_pending = false;
		pACInfo->tspec_mask_status = 0;
		pACInfo->tspec_pending = false;
		pACInfo->hoRenewal = false;
		pACInfo->prev_state = SME_QOS_LINK_UP;
	}
}

/**
 * sme_qos_is_ts_info_ack_policy_valid() - check if ACK policy is allowed.
 * @pMac: The handle returned by mac_open.
 * @pQoSInfo: Pointer to sme_QosWmmTspecInfo which contains the WMM TSPEC
 * @          related info, provided by HDD
 * @sessionId: sessionId returned by sme_open_session.
 *
 * The SME QoS API exposed to HDD to check if TS info ack policy field can be
 * set to "HT-immediate block acknowledgement"
 *
 * Return: true - Current Association is HT association and so TS info ack
 *                 policy can be set to "HT-immediate block acknowledgement"
 */
bool sme_qos_is_ts_info_ack_policy_valid(tpAniSirGlobal pMac,
					 sme_QosWmmTspecInfo *pQoSInfo,
					 uint8_t sessionId)
{
	tDot11fBeaconIEs *pIes = NULL;
	sme_QosSessionInfo *pSession;
	QDF_STATUS hstatus;
	if (!CSR_IS_SESSION_VALID(pMac, sessionId)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Session Id %d is invalid",
			  __func__, __LINE__, sessionId);
		return false;
	}

	pSession = &sme_qos_cb.sessionInfo[sessionId];

	if (!pSession->sessionActive) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Session %d is inactive",
			  __func__, __LINE__, sessionId);
		return false;
	}

	if (!pSession->assocInfo.pBssDesc) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: Session %d has an Invalid BSS Descriptor",
			  __func__, __LINE__, sessionId);
		return false;
	}

	hstatus = csr_get_parsed_bss_description_ies(pMac,
						      pSession->assocInfo.pBssDesc,
						      &pIes);
	if (!QDF_IS_STATUS_SUCCESS(hstatus)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d unable to parse BSS IEs",
			  __func__, __LINE__, sessionId);
		return false;
	}

	/* success means pIes was allocated */

	if (!pIes->HTCaps.present &&
	    pQoSInfo->ts_info.ack_policy ==
	    SME_QOS_WMM_TS_ACK_POLICY_HT_IMMEDIATE_BLOCK_ACK) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			  "%s: %d: On session %d HT Caps aren't present but application set ack policy to HT ",
			  __func__, __LINE__, sessionId);

		qdf_mem_free(pIes);
		return false;
	}

	qdf_mem_free(pIes);
	return true;
}

bool sme_qos_validate_requested_params(tpAniSirGlobal pMac,
				       sme_QosWmmTspecInfo *pQoSInfo,
				       uint8_t sessionId)
{
	bool rc = false;

	do {
		if (SME_QOS_WMM_TS_DIR_RESV == pQoSInfo->ts_info.direction)
			break;
		if (!sme_qos_is_ts_info_ack_policy_valid(pMac, pQoSInfo, sessionId))
			break;

		rc = true;
	} while (0);
	return rc;
}

static QDF_STATUS qos_issue_command(tpAniSirGlobal pMac, uint8_t sessionId,
				    eSmeCommandType cmdType,
				    sme_QosWmmTspecInfo *pQoSInfo,
				    sme_QosEdcaAcType ac, uint8_t tspec_mask)
{
	QDF_STATUS status = QDF_STATUS_E_RESOURCES;
	tSmeCmd *pCommand = NULL;
	do {
		pCommand = sme_get_command_buffer(pMac);
		if (!pCommand) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: fail to get command buffer for command %d",
				  __func__, __LINE__, cmdType);
			break;
		}
		pCommand->command = cmdType;
		pCommand->sessionId = sessionId;
		switch (cmdType) {
		case eSmeCommandAddTs:
			if (pQoSInfo) {
				status = QDF_STATUS_SUCCESS;
				pCommand->u.qosCmd.tspecInfo = *pQoSInfo;
				pCommand->u.qosCmd.ac = ac;
			} else {
				QDF_TRACE(QDF_MODULE_ID_SME,
					  QDF_TRACE_LEVEL_ERROR,
					  "%s: %d: NULL pointer passed",
					  __func__, __LINE__);
				status = QDF_STATUS_E_INVAL;
			}
			break;
		case eSmeCommandDelTs:
			status = QDF_STATUS_SUCCESS;
			pCommand->u.qosCmd.ac = ac;
			pCommand->u.qosCmd.tspec_mask = tspec_mask;
			break;
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: invalid command type %d",
				  __func__, __LINE__, cmdType);
			status = QDF_STATUS_E_INVAL;
			break;
		}
	} while (0);
	if (QDF_IS_STATUS_SUCCESS(status) && pCommand) {
		sme_push_command(pMac, pCommand, false);
	} else if (pCommand) {
		qos_release_command(pMac, pCommand);
	}
	return status;
}

bool qos_process_command(tpAniSirGlobal pMac, tSmeCmd *pCommand)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	bool fRemoveCmd = true;
	do {
		switch (pCommand->command) {
		case eSmeCommandAddTs:
			status =
				sme_qos_add_ts_req(pMac, (uint8_t) pCommand->sessionId,
						   &pCommand->u.qosCmd.tspecInfo,
						   pCommand->u.qosCmd.ac);
			if (QDF_IS_STATUS_SUCCESS(status)) {
				fRemoveCmd = false;
				status = SME_QOS_STATUS_SETUP_REQ_PENDING_RSP;
			}
			break;
		case eSmeCommandDelTs:
			status =
				sme_qos_del_ts_req(pMac, (uint8_t) pCommand->sessionId,
						   pCommand->u.qosCmd.ac,
						   pCommand->u.qosCmd.tspec_mask);
			if (QDF_IS_STATUS_SUCCESS(status)) {
				fRemoveCmd = false;
			}
			break;
		default:
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				  "%s: %d: invalid command type %d",
				  __func__, __LINE__, pCommand->command);
			break;
		} /* switch */
	} while (0);
	return fRemoveCmd;
}

/**
 * sme_qos_re_request_add_ts - Re-send AddTS for the combined QoS request
 *
 * @mac_ctx  Pointer to mac context
 * @session_id  SME session id
 * @qos_info - Tspec information
 * @ac - Access category
 * @tspec_mask - Tspec Mask
 *
 * This function is called to re-send AddTS for the combined QoS request
 *
 * Return: status
 */
static
sme_QosStatusType sme_qos_re_request_add_ts(tpAniSirGlobal mac_ctx,
		uint8_t session_id, sme_QosWmmTspecInfo *qos_info,
		sme_QosEdcaAcType ac, uint8_t tspec_mask)
{
	sme_QosSessionInfo *session;
	sme_QosACInfo *ac_info;
	sme_QosStatusType status = SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
	sme_QosCmdInfo cmd;

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		FL(" Invoked on session %d for AC %d TSPEC %d"),
		session_id, ac, tspec_mask);
	session = &sme_qos_cb.sessionInfo[session_id];
	ac_info = &session->ac_info[ac];
	/* need to vote off powersave for the duration of this request */
	session->readyForPowerSave = false;
	/*
	 * call PMC's request for power function
	 * AND another check is added considering the flowing scenario
	 * Addts reqest is pending on one AC, while APSD requested on
	 * another which needs a reassoc. Will buffer a request if Addts
	 * is pending on any AC, which will safegaurd the above scenario,
	 * 2& also won't confuse PE with back to back Addts or Addts
	 * followed by Reassoc.
	 */
	if (sme_qos_is_rsp_pending(session_id, ac)) {
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			FL(" On session %d buffering the AddTS request "
			"for AC %d in state %d as Addts is pending "
			"on other AC or waiting for full power"),
			session_id, ac,
			ac_info->curr_state);
		/* buffer cmd */
		cmd.command = SME_QOS_RESEND_REQ;
		cmd.pMac = mac_ctx;
		cmd.sessionId = session_id;
		cmd.u.resendCmdInfo.ac = ac;
		cmd.u.resendCmdInfo.tspecMask = tspec_mask;
		cmd.u.resendCmdInfo.QoSInfo = *qos_info;
		if (!QDF_IS_STATUS_SUCCESS(sme_qos_buffer_cmd(&cmd, false))) {
			QDF_TRACE(QDF_MODULE_ID_SME,
				QDF_TRACE_LEVEL_ERROR,
				FL("On session %d unable to buffer the AddTS "
				"request for AC %d TSPEC %d in state %d"),
				session_id, ac, tspec_mask,
				ac_info->curr_state);
			/* unable to buffer the request
			 * nothing is pending so vote powersave back on */
			session->readyForPowerSave = true;
			return SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
		}
		return SME_QOS_STATUS_MODIFY_SETUP_PENDING_RSP;
	}

	/* get into the stat m/c to see if the request can be granted */
	switch (ac_info->curr_state) {
	case SME_QOS_QOS_ON:
	{
		/* if ACM, send out a new ADDTS */
		ac_info->hoRenewal = true;
		status = sme_qos_setup(mac_ctx, session_id, qos_info, ac);
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			FL("sme_qos_setup returned in SME_QOS_QOS_ON state"));
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
			FL("sme_qos_setup AC %d with status =%d"), ac, status);
		if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP != status) {
			/* we aren't waiting for a response from the AP */
			/* so vote powersave back on */
			session->readyForPowerSave = true;
		}
		if (SME_QOS_STATUS_SETUP_REQ_PENDING_RSP == status) {
			status = SME_QOS_STATUS_MODIFY_SETUP_PENDING_RSP;
			ac_info->tspec_pending = tspec_mask;
		} else if ((SME_QOS_STATUS_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP ==
			status) ||
			(SME_QOS_STATUS_SETUP_SUCCESS_APSD_SET_ALREADY ==
			status) ||
			(SME_QOS_STATUS_SETUP_SUCCESS_IND_APSD_PENDING ==
			status)) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				FL("UAPSD is setup already status = %d "),
				status);
		} else {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				FL("sme_qos_setup return status = %d "),
				status);
		}
	}
	break;
	case SME_QOS_HANDOFF:
	case SME_QOS_REQUESTED:
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			FL("Re-Add request in state = %d  buffer the request"),
			ac_info->curr_state);
		cmd.command = SME_QOS_RESEND_REQ;
		cmd.pMac = mac_ctx;
		cmd.sessionId = session_id;
		cmd.u.resendCmdInfo.ac = ac;
		cmd.u.resendCmdInfo.tspecMask = tspec_mask;
		cmd.u.resendCmdInfo.QoSInfo = *qos_info;
		if (!QDF_IS_STATUS_SUCCESS(sme_qos_buffer_cmd(&cmd, false))) {
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
				FL(" couldn't buf the read request state = %d"),
				ac_info->curr_state);
			/* unable to buffer the request
			 * nothing is pending so vote powersave back on */
			session->readyForPowerSave = true;
			return SME_QOS_STATUS_MODIFY_SETUP_FAILURE_RSP;
		}
		status = SME_QOS_STATUS_MODIFY_SETUP_PENDING_RSP;
		break;
	case SME_QOS_CLOSED:
	case SME_QOS_INIT:
	case SME_QOS_LINK_UP:
	default:
		/* print error msg, */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_ERROR,
			FL("ReAdd request in unexpected state = %d"),
			ac_info->curr_state);
		/* unable to service the request
		 * nothing is pending so vote powersave back on */
		session->readyForPowerSave = true;
		break;
	}
	if ((SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_NO_ACM_NO_APSD_RSP ==
		status) ||
		(SME_QOS_STATUS_MODIFY_SETUP_SUCCESS_APSD_SET_ALREADY ==
		status)) {
		(void)sme_qos_process_buffered_cmd(session_id);
	}
	return status;
}

static void sme_qos_init_a_cs(tpAniSirGlobal pMac, uint8_t sessionId)
{
	sme_QosSessionInfo *pSession;
	sme_QosEdcaAcType ac;
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
		qdf_mem_zero(&pSession->ac_info[ac], sizeof(sme_QosACInfo));
		sme_qos_state_transition(sessionId, ac, SME_QOS_INIT);
	}
}

static QDF_STATUS sme_qos_request_reassoc(tpAniSirGlobal pMac, uint8_t sessionId,
					  tCsrRoamModifyProfileFields *
					  pModFields, bool fForce)
{
	sme_QosSessionInfo *pSession;
	sme_QosACInfo *pACInfo;
	QDF_STATUS status;
	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: %d: Invoked on session %d with UAPSD mask 0x%X",
		  __func__, __LINE__, sessionId, pModFields->uapsd_mask);
	pSession = &sme_qos_cb.sessionInfo[sessionId];
	status =
		csr_reassoc(pMac, sessionId, pModFields, &pSession->roamID, fForce);
	if (QDF_IS_STATUS_SUCCESS(status)) {
		/* Update the state to Handoff so subsequent requests are queued until */
		/* this one is finished */
		sme_QosEdcaAcType ac;
		for (ac = SME_QOS_EDCA_AC_BE; ac < SME_QOS_EDCA_AC_MAX; ac++) {
			pACInfo = &pSession->ac_info[ac];
			QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
				  "%s: %d: AC[%d] is in state [%d]",
				  __func__, __LINE__, ac, pACInfo->curr_state);
			/* If it is already in HANDOFF state, don't do anything since we */
			/* MUST preserve the previous state and sme_qos_state_transition */
			/* will change the previous state */
			if (SME_QOS_HANDOFF != pACInfo->curr_state) {
				sme_qos_state_transition(sessionId, ac,
							 SME_QOS_HANDOFF);
			}
		}
	}
	return status;
}

static uint32_t sme_qos_assign_flow_id(void)
{
	uint32_t flowId;
	flowId = sme_qos_cb.nextFlowId;
	if (SME_QOS_MAX_FLOW_ID == flowId) {
		/* The Flow ID wrapped.  This is obviously not a real life scenario */
		/* but handle it to keep the software test folks happy */
		QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_FATAL,
			  "%s: %d: Software Test made the flow counter wrap, "
			  "QoS may no longer be functional",
			  __func__, __LINE__);
		sme_qos_cb.nextFlowId = SME_QOS_MIN_FLOW_ID;
	} else {
		sme_qos_cb.nextFlowId++;
	}
	return flowId;
}

static uint8_t sme_qos_assign_dialog_token(void)
{
	uint8_t token;
	token = sme_qos_cb.nextDialogToken;
	if (SME_QOS_MAX_DIALOG_TOKEN == token) {
		/* wrap is ok */
		sme_qos_cb.nextDialogToken = SME_QOS_MIN_DIALOG_TOKEN;
	} else {
		sme_qos_cb.nextDialogToken++;
	}

	QDF_TRACE(QDF_MODULE_ID_SME, QDF_TRACE_LEVEL_INFO,
		  FL("token %d"), token);
	return token;
}
#endif /* WLAN_MDM_CODE_REDUCTION_OPT */
