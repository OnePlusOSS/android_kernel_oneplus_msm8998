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

#ifndef WMA_API_H
#define WMA_API_H

#include "osdep.h"
#include "cds_mq.h"
#include "ani_global.h"
#include "a_types.h"
#include "osapi_linux.h"
#include "wmi_unified.h"
#ifdef NOT_YET
#include "htc_api.h"
#endif
#include "lim_global.h"
#include "cds_concurrency.h"
#include "cds_utils.h"

typedef void *WMA_HANDLE;

/**
 * enum GEN_PARAM - general parameters
 * @GEN_VDEV_PARAM_AMPDU: Set ampdu size
 * @GEN_VDEV_PARAM_AMSDU: Set amsdu size
 * @GEN_PARAM_CRASH_INJECT: inject crash
 * @GEN_PARAM_MODULATED_DTIM: moduled dtim
 * @GEN_PARAM_CAPTURE_TSF: read tsf
 * @GEN_PARAM_RESET_TSF_GPIO: reset tsf gpio
 * @GEN_VDEV_ROAM_SYNCH_DELAY: roam sync delay
 */
typedef enum {
	GEN_VDEV_PARAM_AMPDU = 0x1,
	GEN_VDEV_PARAM_AMSDU,
	GEN_PARAM_CRASH_INJECT,
	GEN_PARAM_MODULATED_DTIM,
	GEN_PARAM_CAPTURE_TSF,
	GEN_PARAM_RESET_TSF_GPIO,
	GEN_VDEV_ROAM_SYNCH_DELAY,
} GEN_PARAM;

/**
 * struct wma_caps_per_phy - various caps per phy
 * @ht_2g: entire HT cap for 2G band in terms of 32 bit flag
 * @ht_5g: entire HT cap for 5G band in terms of 32 bit flag
 * @vht_2g: entire VHT cap for 2G band in terms of 32 bit flag
 * @vht_5g: entire VHT cap for 5G band in terms of 32 bit flag
 * @he_2g: entire HE cap for 2G band in terms of 32 bit flag
 * @he_5g: entire HE cap for 5G band in terms of 32 bit flag
 */
struct wma_caps_per_phy {
	uint32_t ht_2g;
	uint32_t ht_5g;
	uint32_t vht_2g;
	uint32_t vht_5g;
	uint32_t he_2g;
	uint32_t he_5g;
};


#define VDEV_CMD 1
#define PDEV_CMD 2
#define GEN_CMD  3
#define DBG_CMD  4
#define PPS_CMD  5
#define QPOWER_CMD 6
#define GTX_CMD  7

/**
 * @DEBUG_PEER_CREATE_SEND: sent peer_create command to firmware
 * @DEBUG_PEER_CREATE_RESP: received peer create response
 * @DEBUG_PEER_DELETE_SEND: sent peer delete command to firmware
 * @DEBUG_PEER_DELETE_RESP: received peer delete response
 * @DEBUG_PEER_MAP_EVENT: received peer map event
 * @DEBUG_PEER_UNMAP_EVENT: received peer unmap event
 * @DEBUG_PEER_UNREF_DELETE: peer reference is decremented
 * @DEBUG_DELETING_PEER_OBJ: peer object is deleted
 * @DEBUG_ROAM_SYNCH_IND: received roam offload sync indication
 * @DEBUG_ROAM_SYNCH_CNF: sent roam offload sync confirmation
 * @DEBUG_ROAM_SYNCH_FAIL: received roam sync failure indication
 * @DEBUG_ROAM_EVENT: received roam event
 * @DEBUG_BUS_SUSPEND: host going into suspend mode
 * @DEBUG_BUS_RESUME: host operation resumed
 */

enum peer_debug_op {
	DEBUG_PEER_CREATE_SEND = 0,
	DEBUG_PEER_CREATE_RESP,
	DEBUG_PEER_DELETE_SEND,
	DEBUG_PEER_DELETE_RESP,
	DEBUG_PEER_MAP_EVENT,
	DEBUG_PEER_UNMAP_EVENT,
	DEBUG_PEER_UNREF_DELETE,
	DEBUG_DELETING_PEER_OBJ,
	DEBUG_ROAM_SYNCH_IND,
	DEBUG_ROAM_SYNCH_CNF,
	DEBUG_ROAM_SYNCH_FAIL,
	DEBUG_ROAM_EVENT,
	DEBUG_WOW_ROAM_EVENT,
	DEBUG_BUS_SUSPEND,
	DEBUG_BUS_RESUME,
	DEBUG_WOW_REASON,
};

#define DEBUG_INVALID_PEER_ID 0xffff
#define DEBUG_INVALID_VDEV_ID 0xff

typedef void (*wma_peer_authorized_fp) (uint32_t vdev_id);


QDF_STATUS wma_pre_start(void *cds_context);

void wma_mc_discard_msg(cds_msg_t *msg);

QDF_STATUS wma_mc_process_msg(void *cds_context, cds_msg_t *msg);

QDF_STATUS wma_start(void *cds_context);

QDF_STATUS wma_stop(void *cds_context, uint8_t reason);

QDF_STATUS wma_close(void *cds_context);

QDF_STATUS wma_wmi_service_close(void *cds_context);

QDF_STATUS wma_wmi_work_close(void *cds_context);

int wma_rx_ready_event(void *handle, uint8_t *ev, uint32_t len);

int  wma_rx_service_ready_event(void *handle, uint8_t *ev, uint32_t len);

int wma_rx_service_ready_ext_event(void *handle, uint8_t *ev, uint32_t len);

void wma_setneedshutdown(void *cds_context);

bool wma_needshutdown(void *cds_context);

QDF_STATUS wma_wait_for_ready_event(WMA_HANDLE handle);

uint8_t wma_map_channel(uint8_t mapChannel);

int wma_cli_get_command(int vdev_id, int param_id, int vpdev);
int wma_cli_set_command(int vdev_id, int param_id, int sval, int vpdev);
int wma_cli_set2_command(int vdev_id, int param_id, int sval1,
			 int sval2, int vpdev);

QDF_STATUS wma_set_htconfig(uint8_t vdev_id, uint16_t ht_capab, int value);
QDF_STATUS wma_set_reg_domain(void *clientCtxt, v_REGDOMAIN_t regId);

QDF_STATUS wma_get_wcnss_software_version(void *p_cds_gctx,
					  uint8_t *pVersion,
					  uint32_t versionBufferSize);
int wma_runtime_suspend(uint32_t wow_flags);
int wma_runtime_resume(void);
int wma_bus_suspend(uint32_t wow_flags);
int wma_is_target_wake_up_received(void);
int wma_clear_target_wake_up(void);
QDF_STATUS wma_suspend_target(WMA_HANDLE handle, int disable_target_intr);
void wma_target_suspend_acknowledge(void *context, bool wow_nack);
void wma_handle_initial_wake_up(void);
int wma_bus_resume(void);
QDF_STATUS wma_resume_target(WMA_HANDLE handle);
QDF_STATUS wma_disable_wow_in_fw(WMA_HANDLE handle);
QDF_STATUS wma_disable_d0wow_in_fw(WMA_HANDLE handle);
bool wma_is_wow_mode_selected(WMA_HANDLE handle);
QDF_STATUS wma_enable_wow_in_fw(WMA_HANDLE handle, uint32_t wow_flags);
QDF_STATUS wma_enable_d0wow_in_fw(WMA_HANDLE handle, uint32_t wow_flags);
void wma_set_peer_authorized_cb(void *wma_ctx, wma_peer_authorized_fp auth_cb);
QDF_STATUS wma_set_peer_param(void *wma_ctx, uint8_t *peer_addr,
		  uint32_t param_id,
		  uint32_t param_value, uint32_t vdev_id);
QDF_STATUS wma_get_link_speed(WMA_HANDLE handle, tSirLinkSpeedInfo *pLinkSpeed);
#ifdef NOT_YET
QDF_STATUS wma_update_channel_list(WMA_HANDLE handle, void *scan_chan_info);
#endif

uint8_t *wma_get_vdev_address_by_vdev_id(uint8_t vdev_id);
struct wma_txrx_node *wma_get_interface_by_vdev_id(uint8_t vdev_id);
bool wma_is_vdev_up(uint8_t vdev_id);

void *wma_get_beacon_buffer_by_vdev_id(uint8_t vdev_id, uint32_t *buffer_size);

uint8_t wma_get_fw_wlan_feat_caps(uint8_t featEnumValue);
tSirRetStatus wma_post_ctrl_msg(tpAniSirGlobal pMac, tSirMsgQ *pMsg);

void wma_enable_disable_wakeup_event(WMA_HANDLE handle,
				uint32_t vdev_id,
				uint32_t *bitmap,
				bool enable);
void wma_register_wow_wakeup_events(WMA_HANDLE handle, uint8_t vdev_id,
					uint8_t vdev_type, uint8_t sub_type);
void wma_register_wow_default_patterns(WMA_HANDLE handle, uint8_t vdev_id);
QDF_STATUS wma_register_action_frame_patterns(WMA_HANDLE handle,
					uint8_t vdev_id);

int8_t wma_get_hw_mode_idx_from_dbs_hw_list(enum hw_mode_ss_config mac0_ss,
		enum hw_mode_bandwidth mac0_bw,
		enum hw_mode_ss_config mac1_ss,
		enum hw_mode_bandwidth mac1_bw,
		enum hw_mode_dbs_capab dbs,
		enum hw_mode_agile_dfs_capab dfs,
		enum hw_mode_sbs_capab sbs);
QDF_STATUS wma_get_hw_mode_from_idx(uint32_t idx,
		struct sir_hw_mode_params *hw_mode);
int8_t wma_get_num_dbs_hw_modes(void);
bool wma_is_hw_dbs_capable(void);
int8_t wma_get_mac_id_of_vdev(uint32_t vdev_id);
void wma_update_intf_hw_mode_params(uint32_t vdev_id, uint32_t mac_id,
				uint32_t cfgd_hw_mode_index);
QDF_STATUS wma_get_old_and_new_hw_index(uint32_t *old_hw_mode_index,
		uint32_t *new_hw_mode_index);
void wma_set_dbs_capability_ut(uint32_t dbs);
QDF_STATUS wma_get_dbs_hw_modes(bool *one_by_one_dbs, bool *two_by_two_dbs);
QDF_STATUS wma_get_current_hw_mode(struct sir_hw_mode_params *hw_mode);
bool wma_is_dbs_enable(void);
enum cds_hw_mode_change
wma_get_cds_hw_mode_change_from_hw_mode_index(uint32_t hw_mode_index);

QDF_STATUS wma_get_updated_scan_config(uint32_t *scan_config,
		bool dbs_scan,
		bool dbs_plus_agile_scan,
		bool single_mac_scan_with_dfs);
QDF_STATUS wma_get_updated_fw_mode_config(uint32_t *fw_mode_config,
		bool dbs,
		bool agile_dfs);
bool wma_get_dbs_scan_config(void);
bool wma_get_dbs_plus_agile_scan_config(void);
bool wma_get_single_mac_scan_with_dfs_config(void);
bool wma_get_dbs_config(void);
bool wma_get_agile_dfs_config(void);
bool wma_is_dual_mac_disabled_in_ini(void);
bool wma_get_prev_dbs_config(void);
bool wma_get_prev_agile_dfs_config(void);
bool wma_get_prev_dbs_scan_config(void);
bool wma_get_prev_dbs_plus_agile_scan_config(void);
bool wma_get_prev_single_mac_scan_with_dfs_config(void);
QDF_STATUS wma_get_caps_for_phyidx_hwmode(struct wma_caps_per_phy *caps_per_phy,
		enum hw_mode_dbs_capab hw_mode, enum cds_band_type band);
bool wma_is_rx_ldpc_supported_for_channel(uint32_t channel);

#define LRO_IPV4_SEED_ARR_SZ 5
#define LRO_IPV6_SEED_ARR_SZ 11

/**
 * struct wma_lro_init_cmd_t - set LRO init parameters
 * @lro_enable: indicates whether lro is enabled
 * @tcp_flag: If the TCP flags from the packet do not match
 * the values in this field after masking with TCP flags mask
 * below, packet is not LRO eligible
 * @tcp_flag_mask: field for comparing the TCP values provided
 * above with the TCP flags field in the received packet
 * @toeplitz_hash_ipv4: contains seed needed to compute the flow id
 * 5-tuple toeplitz hash for ipv4 packets
 * @toeplitz_hash_ipv6: contains seed needed to compute the flow id
 * 5-tuple toeplitz hash for ipv6 packets
 */
struct wma_lro_config_cmd_t {
	uint32_t lro_enable;
	uint32_t tcp_flag:9,
		tcp_flag_mask:9;
	uint32_t toeplitz_hash_ipv4[LRO_IPV4_SEED_ARR_SZ];
	uint32_t toeplitz_hash_ipv6[LRO_IPV6_SEED_ARR_SZ];
};

#if defined(FEATURE_LRO)
int wma_lro_init(struct wma_lro_config_cmd_t *lro_config);
#endif
bool wma_is_scan_simultaneous_capable(void);

QDF_STATUS wma_remove_beacon_filter(WMA_HANDLE wma,
				struct beacon_filter_param *filter_params);

QDF_STATUS wma_add_beacon_filter(WMA_HANDLE wma,
				struct beacon_filter_param *filter_params);
QDF_STATUS wma_send_adapt_dwelltime_params(WMA_HANDLE handle,
			struct adaptive_dwelltime_params *dwelltime_params);
#ifdef FEATURE_GREEN_AP
void wma_setup_egap_support(struct wma_tgt_cfg *tgt_cfg, WMA_HANDLE handle);
void wma_register_egap_event_handle(WMA_HANDLE handle);
QDF_STATUS wma_send_egap_conf_params(WMA_HANDLE handle,
				     struct egap_conf_params *egap_params);
#else
static inline void wma_setup_egap_support(struct wma_tgt_cfg *tgt_cfg,
					  WMA_HANDLE handle) {}
static inline void wma_register_egap_event_handle(WMA_HANDLE handle) {}
static inline QDF_STATUS wma_send_egap_conf_params(WMA_HANDLE handle,
				     struct egap_conf_params *egap_params)
{
	return QDF_STATUS_E_NOSUPPORT;
}
#endif
QDF_STATUS wma_set_tx_power_scale(uint8_t vdev_id, int value);
QDF_STATUS wma_set_tx_power_scale_decr_db(uint8_t vdev_id, int value);

#ifdef WLAN_FEATURE_NAN_DATAPATH
QDF_STATUS wma_register_ndp_cb(QDF_STATUS (*pe_ndp_event_handler)
					  (tpAniSirGlobal mac_ctx,
					  cds_msg_t *msg));
#else
static inline QDF_STATUS wma_register_ndp_cb(QDF_STATUS (*pe_ndp_event_handler)
							(tpAniSirGlobal mac_ctx,
							cds_msg_t *msg))
{
	return QDF_STATUS_SUCCESS;
}
#endif

bool wma_is_p2p_lo_capable(void);
QDF_STATUS wma_p2p_lo_start(struct sir_p2p_lo_start *params);
QDF_STATUS wma_p2p_lo_stop(u_int32_t vdev_id);
QDF_STATUS wma_get_wakelock_stats(struct sir_wake_lock_stats *wake_lock_stats);
void wma_process_pdev_hw_mode_trans_ind(void *wma,
	wmi_pdev_hw_mode_transition_event_fixed_param *fixed_param,
	wmi_pdev_set_hw_mode_response_vdev_mac_entry *vdev_mac_entry,
	struct sir_hw_mode_trans_ind *hw_mode_trans_ind);

#ifdef WLAN_FEATURE_DISA
QDF_STATUS wma_encrypt_decrypt_msg(WMA_HANDLE wma,
		struct encrypt_decrypt_req_params *encrypt_decrypt_params);
#else
static inline QDF_STATUS wma_encrypt_decrypt_msg(WMA_HANDLE wma,
		struct encrypt_decrypt_req_params *encrypt_decrypt_params)
{
	return 0;
}
#endif

/**
 * wma_set_cts2self_for_p2p_go() - set CTS2SELF command for P2P GO.
 * @wma_handle:                  pointer to wma handle.
 * @cts2self_for_p2p_go:         value needs to set to firmware.
 *
 * At the time of driver startup, inform about ini parma to FW that
 * if legacy client connects to P2P GO, stop using NOA for P2P GO.
 *
 * Return: QDF_STATUS.
 */
QDF_STATUS wma_set_cts2self_for_p2p_go(void *wma_handle,
		uint32_t cts2self_for_p2p_go);
QDF_STATUS wma_set_tx_rx_aggregation_size
	(struct sir_set_tx_rx_aggregation_size *tx_rx_aggregation_size);
/**
 * wma_set_sar_limit() - set sar limits in the target
 * @handle: wma handle
 * @sar_limit_cmd_params: sar limit cmd params
 *
 *  This function sends WMI command to set SAR limits.
 *
 *  Return: QDF_STATUS enumeration
 */
QDF_STATUS wma_set_sar_limit(WMA_HANDLE handle,
		struct sar_limit_cmd_params *sar_limit_params);
/**
 * wma_set_qpower_config() - update qpower config in wma
 * @vdev_id:	the Id of the vdev to configure
 * @qpower:	new qpower value
 *
 * Return: QDF_STATUS_SUCCESS on success, error number otherwise
 */
QDF_STATUS wma_set_qpower_config(uint8_t vdev_id, uint8_t qpower);

/**
 * wma_peer_debug_log() - Add a debug log entry into peer debug records
 * @vdev_id: vdev identifier
 * @op: operation identifier
 * @peer_id: peer id
 * @mac_addr: mac address of peer, can be NULL
 * @peer_obj: peer object address, can be NULL
 * @arg1: extra argument #1
 * @arg2: extra argument #2
 *
 * Return: none
 */
void wma_peer_debug_log(uint8_t vdev_id, uint8_t op,
			uint16_t peer_id, void *mac_addr,
			void *peer_obj, uint32_t val1, uint32_t val2);
void wma_peer_debug_dump(void);

#endif
