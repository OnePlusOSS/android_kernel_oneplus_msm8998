/*
 * Copyright (c) 2013-2017 The Linux Foundation. All rights reserved.
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
 * This file contains the API definitions for the Unified Wireless
 * Module Interface (WMI).
 */
#ifndef _WMI_UNIFIED_PRIV_H_
#define _WMI_UNIFIED_PRIV_H_
#include <osdep.h>
#include "a_types.h"
#include "wmi_unified_param.h"
#include "qdf_atomic.h"

#define WMI_UNIFIED_MAX_EVENT 0x100
#define WMI_MAX_CMDS 1024

typedef qdf_nbuf_t wmi_buf_t;

#ifdef WMI_INTERFACE_EVENT_LOGGING

#define WMI_EVENT_DEBUG_MAX_ENTRY (1024)
#define WMI_EVENT_DEBUG_ENTRY_MAX_LENGTH (16)
/* wmi_mgmt commands */
#define WMI_MGMT_EVENT_DEBUG_MAX_ENTRY (256)

/**
 * struct wmi_command_debug - WMI command log buffer data type
 * @ command - Store WMI Command id
 * @ data - Stores WMI command data
 * @ time - Time of WMI command handling
 */
struct wmi_command_debug {
	uint32_t command;
	/*16 bytes of WMI cmd excluding TLV and WMI headers */
	uint32_t data[WMI_EVENT_DEBUG_ENTRY_MAX_LENGTH/sizeof(uint32_t)];
	uint64_t time;
};

/**
 * struct wmi_event_debug - WMI event log buffer data type
 * @ command - Store WMI Event id
 * @ data - Stores WMI Event data
 * @ time - Time of WMI Event handling
 */
struct wmi_event_debug {
	uint32_t event;
	/*16 bytes of WMI event data excluding TLV header */
	uint32_t data[WMI_EVENT_DEBUG_ENTRY_MAX_LENGTH/sizeof(uint32_t)];
	uint64_t time;
};

/**
 * struct wmi_command_header - Type for accessing frame data
 * @ type - 802.11 Frame type
 * @ subType - 802.11 Frame subtype
 * @ protVer - 802.11 Version
 */
struct wmi_command_header {
#ifndef ANI_LITTLE_BIT_ENDIAN

	uint32_t sub_type:4;
	uint32_t type:2;
	uint32_t prot_ver:2;

#else

	uint32_t prot_ver:2;
	uint32_t type:2;
	uint32_t sub_type:4;

#endif
};

/**
 * struct wmi_log_buf_t - WMI log buffer information type
 * @buf - Refernce to WMI log buffer
 * @ length - length of buffer
 * @ buf_tail_idx - Tail index of buffer
 * @ p_buf_tail_idx - refernce to buffer tail index. It is added to accommodate
 * unified design since MCL uses global variable for buffer tail index
 */
struct wmi_log_buf_t {
	void *buf;
	uint32_t length;
	uint32_t buf_tail_idx;
	uint32_t *p_buf_tail_idx;
};

/**
 * struct wmi_debug_log_info - Meta data to hold information of all buffers
 * used for WMI logging
 * @wmi_command_log_buf_info - Buffer info for WMI Command log
 * @wmi_command_tx_cmp_log_buf_info - Buffer info for WMI Command Tx completion
 * log
 * @wmi_event_log_buf_info - Buffer info for WMI Event log
 * @wmi_rx_event_log_buf_info - Buffer info for WMI event received log
 * @wmi_mgmt_command_log_buf_info - Buffer info for WMI Management Command log
 * @wmi_mgmt_command_tx_cmp_log_buf_info - Buffer info for WMI Management
 * Command Tx completion log
 * @wmi_mgmt_event_log_buf_info - Buffer info for WMI Management event log
 * @wmi_record_lock - Lock WMI recording
 * @wmi_logging_enable - Enable/Disable state for WMI logging
 * @buf_offset_command - Offset from where WMI command data should be logged
 * @buf_offset_event - Offset from where WMI event data should be logged
 * @is_management_record - Function refernce to check if command/event is
 *  management record
 * @wmi_id_to_name - Function refernce to API to convert Command id to
 * string name
 * @wmi_log_debugfs_dir - refernce to debugfs directory
 */
struct wmi_debug_log_info {
	struct wmi_log_buf_t wmi_command_log_buf_info;
	struct wmi_log_buf_t wmi_command_tx_cmp_log_buf_info;

	struct wmi_log_buf_t wmi_event_log_buf_info;
	struct wmi_log_buf_t wmi_rx_event_log_buf_info;

	struct wmi_log_buf_t wmi_mgmt_command_log_buf_info;
	struct wmi_log_buf_t wmi_mgmt_command_tx_cmp_log_buf_info;
	struct wmi_log_buf_t wmi_mgmt_event_log_buf_info;

	qdf_spinlock_t wmi_record_lock;
	bool wmi_logging_enable;
	uint32_t buf_offset_command;
	uint32_t buf_offset_event;
	bool (*is_management_record)(uint32_t cmd_id);
	uint8_t *(*wmi_id_to_name)(uint32_t cmd_id);
	struct dentry *wmi_log_debugfs_dir;
	uint8_t wmi_instance_id;
};

#endif /*WMI_INTERFACE_EVENT_LOGGING */

#ifdef WLAN_OPEN_SOURCE
struct fwdebug {
	struct sk_buff_head fwlog_queue;
	struct completion fwlog_completion;
	A_BOOL fwlog_open;
};
#endif /* WLAN_OPEN_SOURCE */

struct wmi_ops {
QDF_STATUS (*send_vdev_create_cmd)(wmi_unified_t wmi_handle,
				 uint8_t macaddr[IEEE80211_ADDR_LEN],
				 struct vdev_create_params *param);

QDF_STATUS (*send_vdev_delete_cmd)(wmi_unified_t wmi_handle,
					  uint8_t if_id);

QDF_STATUS (*send_vdev_stop_cmd)(wmi_unified_t wmi,
					uint8_t vdev_id);

QDF_STATUS (*send_conf_hw_filter_mode_cmd)(wmi_unified_t wmi, uint8_t vdev_id,
					   uint8_t mode_bitmap);

QDF_STATUS (*send_vdev_down_cmd)(wmi_unified_t wmi,
			uint8_t vdev_id);

QDF_STATUS (*send_vdev_start_cmd)(wmi_unified_t wmi,
		struct vdev_start_params *req);

QDF_STATUS (*send_hidden_ssid_vdev_restart_cmd)(wmi_unified_t wmi_handle,
		struct hidden_ssid_vdev_restart_params *restart_params);

QDF_STATUS (*send_peer_flush_tids_cmd)(wmi_unified_t wmi,
					 uint8_t peer_addr[IEEE80211_ADDR_LEN],
					 struct peer_flush_params *param);

QDF_STATUS (*send_peer_delete_cmd)(wmi_unified_t wmi,
				    uint8_t peer_addr[IEEE80211_ADDR_LEN],
				    uint8_t vdev_id);

QDF_STATUS (*send_peer_param_cmd)(wmi_unified_t wmi,
				uint8_t peer_addr[IEEE80211_ADDR_LEN],
				struct peer_set_params *param);

QDF_STATUS (*send_vdev_up_cmd)(wmi_unified_t wmi,
			     uint8_t bssid[IEEE80211_ADDR_LEN],
				 struct vdev_up_params *params);

QDF_STATUS (*send_peer_create_cmd)(wmi_unified_t wmi,
					struct peer_create_params *param);

QDF_STATUS (*send_green_ap_ps_cmd)(wmi_unified_t wmi_handle,
						uint32_t value, uint8_t mac_id);

QDF_STATUS
(*send_pdev_utf_cmd)(wmi_unified_t wmi_handle,
				struct pdev_utf_params *param,
				uint8_t mac_id);

QDF_STATUS
(*send_pdev_param_cmd)(wmi_unified_t wmi_handle,
			   struct pdev_params *param,
				uint8_t mac_id);

QDF_STATUS (*send_suspend_cmd)(wmi_unified_t wmi_handle,
				struct suspend_params *param,
				uint8_t mac_id);

QDF_STATUS (*send_resume_cmd)(wmi_unified_t wmi_handle,
				uint8_t mac_id);

QDF_STATUS (*send_wow_enable_cmd)(wmi_unified_t wmi_handle,
				struct wow_cmd_params *param,
				uint8_t mac_id);

QDF_STATUS (*send_set_ap_ps_param_cmd)(wmi_unified_t wmi_handle,
					   uint8_t *peer_addr,
					   struct ap_ps_params *param);

QDF_STATUS (*send_set_sta_ps_param_cmd)(wmi_unified_t wmi_handle,
					   struct sta_ps_params *param);

QDF_STATUS (*send_crash_inject_cmd)(wmi_unified_t wmi_handle,
			 struct crash_inject *param);

QDF_STATUS
(*send_dbglog_cmd)(wmi_unified_t wmi_handle,
				struct dbglog_params *dbglog_param);

QDF_STATUS (*send_vdev_set_param_cmd)(wmi_unified_t wmi_handle,
				struct vdev_set_params *param);

QDF_STATUS (*send_stats_request_cmd)(wmi_unified_t wmi_handle,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct stats_request_params *param);

#ifdef CONFIG_WIN
QDF_STATUS (*send_packet_log_enable_cmd)(wmi_unified_t wmi_handle,
				WMI_HOST_PKTLOG_EVENT PKTLOG_EVENT);
#else
QDF_STATUS (*send_packet_log_enable_cmd)(wmi_unified_t wmi_handle,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct packet_enable_params *param);
#endif

QDF_STATUS (*send_packet_log_disable_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_beacon_send_cmd)(wmi_unified_t wmi_handle,
				struct beacon_params *param);

QDF_STATUS (*send_beacon_tmpl_send_cmd)(wmi_unified_t wmi_handle,
				struct beacon_tmpl_params *param);

QDF_STATUS (*send_peer_assoc_cmd)(wmi_unified_t wmi_handle,
				struct peer_assoc_params *param);

QDF_STATUS (*send_scan_start_cmd)(wmi_unified_t wmi_handle,
				struct scan_start_params *param);

QDF_STATUS (*send_scan_stop_cmd)(wmi_unified_t wmi_handle,
				struct scan_stop_params *param);

QDF_STATUS (*send_scan_chan_list_cmd)(wmi_unified_t wmi_handle,
				struct scan_chan_list_params *param);

QDF_STATUS (*send_mgmt_cmd)(wmi_unified_t wmi_handle,
				struct wmi_mgmt_params *param);

QDF_STATUS (*send_modem_power_state_cmd)(wmi_unified_t wmi_handle,
		uint32_t param_value);

QDF_STATUS (*send_set_sta_ps_mode_cmd)(wmi_unified_t wmi_handle,
			       uint32_t vdev_id, uint8_t val);

QDF_STATUS (*send_get_temperature_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_set_p2pgo_oppps_req_cmd)(wmi_unified_t wmi_handle,
		struct p2p_ps_params *oppps);

QDF_STATUS (*send_set_p2pgo_noa_req_cmd)(wmi_unified_t wmi_handle,
			struct p2p_ps_params *noa);

QDF_STATUS (*send_set_smps_params_cmd)(wmi_unified_t wmi_handle,
			  uint8_t vdev_id,
			  int value);

QDF_STATUS (*send_set_mimops_cmd)(wmi_unified_t wmi_handle,
			uint8_t vdev_id, int value);

QDF_STATUS (*send_set_sta_uapsd_auto_trig_cmd)(wmi_unified_t wmi_handle,
				struct sta_uapsd_trig_params *param);

QDF_STATUS (*send_ocb_set_utc_time_cmd)(wmi_unified_t wmi_handle,
				struct ocb_utc_param *utc);

QDF_STATUS (*send_ocb_get_tsf_timer_cmd)(wmi_unified_t wmi_handle,
			  uint8_t vdev_id);

QDF_STATUS (*send_ocb_start_timing_advert_cmd)(wmi_unified_t wmi_handle,
	struct ocb_timing_advert_param *timing_advert);

QDF_STATUS (*send_ocb_stop_timing_advert_cmd)(wmi_unified_t wmi_handle,
	struct ocb_timing_advert_param *timing_advert);

QDF_STATUS (*send_dcc_get_stats_cmd)(wmi_unified_t wmi_handle,
		     struct dcc_get_stats_param *get_stats_param);

QDF_STATUS (*send_dcc_clear_stats_cmd)(wmi_unified_t wmi_handle,
				uint32_t vdev_id, uint32_t dcc_stats_bitmap);

QDF_STATUS (*send_dcc_update_ndl_cmd)(wmi_unified_t wmi_handle,
		       struct dcc_update_ndl_param *update_ndl_param);

QDF_STATUS (*send_ocb_set_config_cmd)(wmi_unified_t wmi_handle,
		  struct ocb_config_param *config, uint32_t *ch_mhz);

QDF_STATUS (*send_lro_config_cmd)(wmi_unified_t wmi_handle,
	 struct wmi_lro_config_cmd_t *wmi_lro_cmd);

QDF_STATUS (*send_set_thermal_mgmt_cmd)(wmi_unified_t wmi_handle,
				struct thermal_cmd_params *thermal_info);

QDF_STATUS (*send_peer_rate_report_cmd)(wmi_unified_t wmi_handle,
	 struct wmi_peer_rate_report_params *rate_report_params);

QDF_STATUS (*send_set_mcc_channel_time_quota_cmd)
	(wmi_unified_t wmi_handle,
	uint32_t adapter_1_chan_freq,
	uint32_t adapter_1_quota, uint32_t adapter_2_chan_freq);

QDF_STATUS (*send_set_mcc_channel_time_latency_cmd)
	(wmi_unified_t wmi_handle,
	uint32_t mcc_channel_freq, uint32_t mcc_channel_time_latency);

QDF_STATUS (*send_set_enable_disable_mcc_adaptive_scheduler_cmd)(
		  wmi_unified_t wmi_handle, uint32_t mcc_adaptive_scheduler,
		  uint32_t pdev_id);

QDF_STATUS (*send_p2p_go_set_beacon_ie_cmd)(wmi_unified_t wmi_handle,
				    A_UINT32 vdev_id, uint8_t *p2p_ie);

QDF_STATUS (*send_probe_rsp_tmpl_send_cmd)(wmi_unified_t wmi_handle,
			     uint8_t vdev_id,
			     struct wmi_probe_resp_params *probe_rsp_info,
			     uint8_t *frm);

QDF_STATUS (*send_setup_install_key_cmd)(wmi_unified_t wmi_handle,
				struct set_key_params *key_params);

QDF_STATUS (*send_vdev_set_gtx_cfg_cmd)(wmi_unified_t wmi_handle,
				  uint32_t if_id,
				  struct wmi_gtx_config *gtx_info);

QDF_STATUS (*send_set_sta_keep_alive_cmd)(wmi_unified_t wmi_handle,
				struct sta_params *params);

QDF_STATUS (*send_set_sta_sa_query_param_cmd)(wmi_unified_t wmi_handle,
				       uint8_t vdev_id, uint32_t max_retries,
					   uint32_t retry_interval);

QDF_STATUS (*send_set_gateway_params_cmd)(wmi_unified_t wmi_handle,
					struct gateway_update_req_param *req);

QDF_STATUS (*send_set_rssi_monitoring_cmd)(wmi_unified_t wmi_handle,
					struct rssi_monitor_param *req);

QDF_STATUS (*send_scan_probe_setoui_cmd)(wmi_unified_t wmi_handle,
			  struct scan_mac_oui *psetoui);

QDF_STATUS (*send_reset_passpoint_network_list_cmd)(wmi_unified_t wmi_handle,
					struct wifi_passpoint_req_param *req);

QDF_STATUS (*send_roam_scan_offload_rssi_thresh_cmd)(wmi_unified_t wmi_handle,
				struct roam_offload_scan_rssi_params *roam_req);

QDF_STATUS (*send_roam_scan_filter_cmd)(wmi_unified_t wmi_handle,
				struct roam_scan_filter_params *roam_req);

QDF_STATUS (*send_set_passpoint_network_list_cmd)(wmi_unified_t wmi_handle,
					struct wifi_passpoint_req_param *req);

QDF_STATUS (*send_set_epno_network_list_cmd)(wmi_unified_t wmi_handle,
		struct wifi_enhanched_pno_params *req);

QDF_STATUS (*send_extscan_get_capabilities_cmd)(wmi_unified_t wmi_handle,
			  struct extscan_capabilities_params *pgetcapab);

QDF_STATUS (*send_extscan_get_cached_results_cmd)(wmi_unified_t wmi_handle,
			  struct extscan_cached_result_params *pcached_results);

QDF_STATUS (*send_extscan_stop_change_monitor_cmd)(wmi_unified_t wmi_handle,
			  struct extscan_capabilities_reset_params *reset_req);

QDF_STATUS (*send_extscan_start_change_monitor_cmd)(wmi_unified_t wmi_handle,
		struct extscan_set_sig_changereq_params *
		psigchange);

QDF_STATUS (*send_extscan_stop_hotlist_monitor_cmd)(wmi_unified_t wmi_handle,
		struct extscan_bssid_hotlist_reset_params *photlist_reset);

QDF_STATUS (*send_stop_extscan_cmd)(wmi_unified_t wmi_handle,
		  struct extscan_stop_req_params *pstopcmd);

QDF_STATUS (*send_start_extscan_cmd)(wmi_unified_t wmi_handle,
		    struct wifi_scan_cmd_req_params *pstart);

QDF_STATUS (*send_plm_stop_cmd)(wmi_unified_t wmi_handle,
		 const struct plm_req_params *plm);


QDF_STATUS (*send_plm_start_cmd)(wmi_unified_t wmi_handle,
		  const struct plm_req_params *plm,
		  uint32_t *gchannel_list);

QDF_STATUS (*send_csa_offload_enable_cmd)(wmi_unified_t wmi_handle,
			uint8_t vdev_id);

QDF_STATUS (*send_pno_stop_cmd)(wmi_unified_t wmi_handle, uint8_t vdev_id);

#ifdef FEATURE_WLAN_SCAN_PNO
QDF_STATUS (*send_pno_start_cmd)(wmi_unified_t wmi_handle,
		   struct pno_scan_req_params *pno,
		   uint32_t *gchannel_freq_list);
#endif

QDF_STATUS (*send_ipa_offload_control_cmd)(wmi_unified_t wmi_handle,
		struct ipa_offload_control_params *ipa_offload);

QDF_STATUS (*send_set_ric_req_cmd)(wmi_unified_t wmi_handle, void *msg,
			uint8_t is_add_ts);

QDF_STATUS (*send_process_ll_stats_clear_cmd)
	   (wmi_unified_t wmi_handle,
	   const struct ll_stats_clear_params *clear_req,
	   uint8_t addr[IEEE80211_ADDR_LEN]);

QDF_STATUS (*send_process_ll_stats_set_cmd)
	(wmi_unified_t wmi_handle, const struct ll_stats_set_params *set_req);

QDF_STATUS (*send_process_ll_stats_get_cmd)
	(wmi_unified_t wmi_handle, const struct ll_stats_get_params  *get_req,
		 uint8_t addr[IEEE80211_ADDR_LEN]);

QDF_STATUS (*send_get_stats_cmd)(wmi_unified_t wmi_handle,
		       struct pe_stats_req  *get_stats_param,
			   uint8_t addr[IEEE80211_ADDR_LEN]);

QDF_STATUS (*send_snr_request_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_snr_cmd)(wmi_unified_t wmi_handle, uint8_t vdev_id);

QDF_STATUS (*send_link_status_req_cmd)(wmi_unified_t wmi_handle,
				 struct link_status_params *link_status);
#ifdef CONFIG_MCL
QDF_STATUS (*send_lphb_config_hbenable_cmd)(wmi_unified_t wmi_handle,
				wmi_hb_set_enable_cmd_fixed_param *params);

QDF_STATUS (*send_lphb_config_tcp_params_cmd)(wmi_unified_t wmi_handle,
				    wmi_hb_set_tcp_params_cmd_fixed_param *lphb_conf_req);

QDF_STATUS (*send_lphb_config_tcp_pkt_filter_cmd)(wmi_unified_t wmi_handle,
				wmi_hb_set_tcp_pkt_filter_cmd_fixed_param *g_hb_tcp_filter_fp);

QDF_STATUS (*send_lphb_config_udp_params_cmd)(wmi_unified_t wmi_handle,
				    wmi_hb_set_udp_params_cmd_fixed_param *lphb_conf_req);

QDF_STATUS (*send_lphb_config_udp_pkt_filter_cmd)(wmi_unified_t wmi_handle,
					wmi_hb_set_udp_pkt_filter_cmd_fixed_param *lphb_conf_req);

QDF_STATUS (*send_process_dhcp_ind_cmd)(wmi_unified_t wmi_handle,
				wmi_peer_set_param_cmd_fixed_param *ta_dhcp_ind);

QDF_STATUS (*send_get_link_speed_cmd)(wmi_unified_t wmi_handle,
			wmi_mac_addr peer_macaddr);

QDF_STATUS (*send_egap_conf_params_cmd)(wmi_unified_t wmi_handle,
				     wmi_ap_ps_egap_param_cmd_fixed_param *egap_params);

QDF_STATUS (*send_process_update_edca_param_cmd)(wmi_unified_t wmi_handle,
			     uint8_t vdev_id,
			     wmi_wmm_vparams gwmm_param[WMI_MAX_NUM_AC]);

QDF_STATUS (*send_bcn_buf_ll_cmd)(wmi_unified_t wmi_handle,
			wmi_bcn_send_from_host_cmd_fixed_param * param);

QDF_STATUS (*send_roam_scan_offload_mode_cmd)(wmi_unified_t wmi_handle,
				wmi_start_scan_cmd_fixed_param * scan_cmd_fp,
				struct roam_offload_scan_params *roam_req);

QDF_STATUS (*send_roam_scan_offload_ap_profile_cmd)(wmi_unified_t wmi_handle,
				    wmi_ap_profile * ap_profile_p,
				    uint32_t vdev_id);

QDF_STATUS (*send_pktlog_wmi_send_cmd)(wmi_unified_t wmi_handle,
				   WMI_PKTLOG_EVENT pktlog_event,
				   WMI_CMD_ID cmd_id, uint8_t user_triggered);
#endif

QDF_STATUS (*send_action_frame_patterns_cmd)(wmi_unified_t wmi_handle,
			struct action_wakeup_set_param *action_params);

QDF_STATUS (*send_fw_profiling_cmd)(wmi_unified_t wmi_handle,
			uint32_t cmd, uint32_t value1, uint32_t value2);

QDF_STATUS (*send_wow_sta_ra_filter_cmd)(wmi_unified_t wmi_handle,
				   uint8_t vdev_id, uint8_t default_pattern,
				   uint16_t rate_limit_interval);

QDF_STATUS (*send_nat_keepalive_en_cmd)(wmi_unified_t wmi_handle, uint8_t vdev_id);

QDF_STATUS (*send_start_oem_data_cmd)(wmi_unified_t wmi_handle,
			  uint32_t data_len,
			  uint8_t *data);

QDF_STATUS
(*send_dfs_phyerr_filter_offload_en_cmd)(wmi_unified_t wmi_handle,
			bool dfs_phyerr_filter_offload);

QDF_STATUS (*send_add_wow_wakeup_event_cmd)(wmi_unified_t wmi_handle,
					uint32_t vdev_id,
					uint32_t bitmap,
					bool enable);

QDF_STATUS (*send_wow_patterns_to_fw_cmd)(wmi_unified_t wmi_handle,
				uint8_t vdev_id, uint8_t ptrn_id,
				const uint8_t *ptrn, uint8_t ptrn_len,
				uint8_t ptrn_offset, const uint8_t *mask,
				uint8_t mask_len, bool user,
				uint8_t default_patterns);

QDF_STATUS (*send_wow_delete_pattern_cmd)(wmi_unified_t wmi_handle, uint8_t ptrn_id,
					uint8_t vdev_id);

QDF_STATUS (*send_host_wakeup_ind_to_fw_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_del_ts_cmd)(wmi_unified_t wmi_handle, uint8_t vdev_id,
				uint8_t ac);

QDF_STATUS (*send_aggr_qos_cmd)(wmi_unified_t wmi_handle,
		      struct aggr_add_ts_param *aggr_qos_rsp_msg);

QDF_STATUS (*send_add_ts_cmd)(wmi_unified_t wmi_handle,
		 struct add_ts_param *msg);

QDF_STATUS (*send_enable_disable_packet_filter_cmd)(wmi_unified_t wmi_handle,
					uint8_t vdev_id, bool enable);

QDF_STATUS (*send_config_packet_filter_cmd)(wmi_unified_t wmi_handle,
		uint8_t vdev_id, struct rcv_pkt_filter_config *rcv_filter_param,
		uint8_t filter_id, bool enable);

QDF_STATUS (*send_add_clear_mcbc_filter_cmd)(wmi_unified_t wmi_handle,
				     uint8_t vdev_id,
				     struct qdf_mac_addr multicast_addr,
				     bool clearList);

QDF_STATUS (*send_gtk_offload_cmd)(wmi_unified_t wmi_handle, uint8_t vdev_id,
					   struct gtk_offload_params *params,
					   bool enable_offload,
					   uint32_t gtk_offload_opcode);

QDF_STATUS (*send_process_gtk_offload_getinfo_cmd)(wmi_unified_t wmi_handle,
				uint8_t vdev_id,
				uint64_t offload_req_opcode);

QDF_STATUS (*send_process_add_periodic_tx_ptrn_cmd)(wmi_unified_t wmi_handle,
						struct periodic_tx_pattern  *
						pAddPeriodicTxPtrnParams,
						uint8_t vdev_id);

QDF_STATUS (*send_process_del_periodic_tx_ptrn_cmd)(wmi_unified_t wmi_handle,
						uint8_t vdev_id,
						uint8_t pattern_id);

QDF_STATUS (*send_stats_ext_req_cmd)(wmi_unified_t wmi_handle,
			struct stats_ext_params *preq);

QDF_STATUS (*send_enable_ext_wow_cmd)(wmi_unified_t wmi_handle,
			struct ext_wow_params *params);

QDF_STATUS (*send_set_app_type2_params_in_fw_cmd)(wmi_unified_t wmi_handle,
					  struct app_type2_params *appType2Params);

QDF_STATUS (*send_set_auto_shutdown_timer_cmd)(wmi_unified_t wmi_handle,
						  uint32_t timer_val);

QDF_STATUS (*send_nan_req_cmd)(wmi_unified_t wmi_handle,
			struct nan_req_params *nan_req);

QDF_STATUS (*send_process_dhcpserver_offload_cmd)(wmi_unified_t wmi_handle,
				struct dhcp_offload_info_params *pDhcpSrvOffloadInfo);

QDF_STATUS (*send_process_ch_avoid_update_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_regdomain_info_to_fw_cmd)(wmi_unified_t wmi_handle,
				   uint32_t reg_dmn, uint16_t regdmn2G,
				   uint16_t regdmn5G, int8_t ctl2G,
				   int8_t ctl5G);

QDF_STATUS (*send_set_tdls_offchan_mode_cmd)(wmi_unified_t wmi_handle,
			      struct tdls_channel_switch_params *chan_switch_params);

QDF_STATUS (*send_update_fw_tdls_state_cmd)(wmi_unified_t wmi_handle,
					 void *tdls_param, uint8_t tdls_state);

QDF_STATUS (*send_update_tdls_peer_state_cmd)(wmi_unified_t wmi_handle,
			       struct tdls_peer_state_params *peerStateParams,
				   uint32_t *ch_mhz);


QDF_STATUS (*send_process_fw_mem_dump_cmd)(wmi_unified_t wmi_handle,
					struct fw_dump_req_param *mem_dump_req);

QDF_STATUS (*send_process_set_ie_info_cmd)(wmi_unified_t wmi_handle,
				   struct vdev_ie_info_param *ie_info);

#ifdef CONFIG_MCL
QDF_STATUS (*send_init_cmd)(wmi_unified_t wmi_handle,
		wmi_resource_config *res_cfg,
		uint8_t num_mem_chunks, struct wmi_host_mem_chunk *mem_chunk,
		bool action);
#endif

QDF_STATUS (*save_fw_version_cmd)(wmi_unified_t wmi_handle, void *evt_buf);

QDF_STATUS (*check_and_update_fw_version_cmd)(wmi_unified_t wmi_hdl, void *ev);

QDF_STATUS (*send_saved_init_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_set_base_macaddr_indicate_cmd)(wmi_unified_t wmi_handle,
					 uint8_t *custom_addr);

QDF_STATUS (*send_log_supported_evt_cmd)(wmi_unified_t wmi_handle,
		uint8_t *event,
		uint32_t len);

QDF_STATUS (*send_enable_specific_fw_logs_cmd)(wmi_unified_t wmi_handle,
		struct wmi_wifi_start_log *start_log);

QDF_STATUS (*send_flush_logs_to_fw_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_pdev_set_pcl_cmd)(wmi_unified_t wmi_handle,
				struct wmi_pcl_chan_weights *msg);

QDF_STATUS (*send_pdev_set_hw_mode_cmd)(wmi_unified_t wmi_handle,
				uint32_t hw_mode_index);

QDF_STATUS (*send_pdev_set_dual_mac_config_cmd)(wmi_unified_t wmi_handle,
		struct wmi_dual_mac_config *msg);

QDF_STATUS (*send_enable_arp_ns_offload_cmd)(wmi_unified_t wmi_handle,
			   struct host_offload_req_param *arp_offload_req,
			   struct host_offload_req_param *ns_offload_req,
			   bool arp_only,
			   uint8_t vdev_id);

QDF_STATUS (*send_set_led_flashing_cmd)(wmi_unified_t wmi_handle,
				struct flashing_req_params *flashing);

QDF_STATUS (*send_app_type1_params_in_fw_cmd)(wmi_unified_t wmi_handle,
				   struct app_type1_params *app_type1_params);

QDF_STATUS (*send_set_ssid_hotlist_cmd)(wmi_unified_t wmi_handle,
		     struct ssid_hotlist_request_params *request);

QDF_STATUS (*send_process_roam_synch_complete_cmd)(wmi_unified_t wmi_handle,
		 uint8_t vdev_id);

QDF_STATUS (*send_unit_test_cmd)(wmi_unified_t wmi_handle,
				 struct wmi_unit_test_cmd *wmi_utest);

QDF_STATUS (*send_roam_invoke_cmd)(wmi_unified_t wmi_handle,
		struct wmi_roam_invoke_cmd *roaminvoke,
		uint32_t ch_hz);

QDF_STATUS (*send_roam_scan_offload_cmd)(wmi_unified_t wmi_handle,
				 uint32_t command, uint32_t vdev_id);

QDF_STATUS (*send_roam_scan_offload_scan_period_cmd)(wmi_unified_t wmi_handle,
				     uint32_t scan_period,
				     uint32_t scan_age,
				     uint32_t vdev_id);

QDF_STATUS (*send_roam_scan_offload_chan_list_cmd)(wmi_unified_t wmi_handle,
				   uint8_t chan_count,
				   uint32_t *chan_list,
				   uint8_t list_type, uint32_t vdev_id);

QDF_STATUS (*send_roam_scan_offload_rssi_change_cmd)(wmi_unified_t wmi_handle,
	uint32_t vdev_id,
	int32_t rssi_change_thresh,
	uint32_t bcn_rssi_weight,
	uint32_t hirssi_delay_btw_scans);

QDF_STATUS (*send_per_roam_config_cmd)(wmi_unified_t wmi_handle,
		struct wmi_per_roam_config_req *req_buf);

QDF_STATUS (*send_set_arp_stats_req_cmd)(wmi_unified_t wmi_handle,
					 struct set_arp_stats *req_buf);

QDF_STATUS (*send_get_arp_stats_req_cmd)(wmi_unified_t wmi_handle,
					 struct get_arp_stats *req_buf);

QDF_STATUS (*send_get_buf_extscan_hotlist_cmd)(wmi_unified_t wmi_handle,
				   struct ext_scan_setbssi_hotlist_params *
				   photlist, int *buf_len);

QDF_STATUS (*send_set_active_bpf_mode_cmd)(wmi_unified_t wmi_handle,
					   uint8_t vdev_id,
					   FW_ACTIVE_BPF_MODE ucast_mode,
					   FW_ACTIVE_BPF_MODE mcast_bcast_mode);

QDF_STATUS (*send_pdev_get_tpc_config_cmd)(wmi_unified_t wmi_handle,
		uint32_t param);

QDF_STATUS (*send_set_bwf_cmd)(wmi_unified_t wmi_handle,
		struct set_bwf_params *param);

QDF_STATUS (*send_set_atf_cmd)(wmi_unified_t wmi_handle,
		struct set_atf_params *param);

QDF_STATUS (*send_pdev_fips_cmd)(wmi_unified_t wmi_handle,
		struct fips_params *param);

QDF_STATUS (*send_wlan_profile_enable_cmd)(wmi_unified_t wmi_handle,
		struct wlan_profile_params *param);

QDF_STATUS (*send_wlan_profile_trigger_cmd)(wmi_unified_t wmi_handle,
		struct wlan_profile_params *param);

QDF_STATUS (*send_pdev_set_chan_cmd)(wmi_unified_t wmi_handle,
		struct channel_param *param);

QDF_STATUS (*send_set_ht_ie_cmd)(wmi_unified_t wmi_handle,
		struct ht_ie_params *param);

QDF_STATUS (*send_set_vht_ie_cmd)(wmi_unified_t wmi_handle,
		struct vht_ie_params *param);

QDF_STATUS (*send_wmm_update_cmd)(wmi_unified_t wmi_handle,
		struct wmm_update_params *param);

QDF_STATUS (*send_set_ant_switch_tbl_cmd)(wmi_unified_t wmi_handle,
		struct ant_switch_tbl_params *param);

QDF_STATUS (*send_set_ratepwr_table_cmd)(wmi_unified_t wmi_handle,
		struct ratepwr_table_params *param);

QDF_STATUS (*send_get_ratepwr_table_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_set_ctl_table_cmd)(wmi_unified_t wmi_handle,
		struct ctl_table_params *param);

QDF_STATUS (*send_set_mimogain_table_cmd)(wmi_unified_t wmi_handle,
		struct mimogain_table_params *param);

QDF_STATUS (*send_set_ratepwr_chainmsk_cmd)(wmi_unified_t wmi_handle,
		struct ratepwr_chainmsk_params *param);

QDF_STATUS (*send_set_macaddr_cmd)(wmi_unified_t wmi_handle,
		struct macaddr_params *param);

QDF_STATUS (*send_pdev_scan_start_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_pdev_scan_end_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_set_acparams_cmd)(wmi_unified_t wmi_handle,
		struct acparams_params *param);

QDF_STATUS (*send_set_vap_dscp_tid_map_cmd)(wmi_unified_t wmi_handle,
		struct vap_dscp_tid_map_params *param);

QDF_STATUS (*send_proxy_ast_reserve_cmd)(wmi_unified_t wmi_handle,
		struct proxy_ast_reserve_params *param);

QDF_STATUS (*send_pdev_qvit_cmd)(wmi_unified_t wmi_handle,
		struct pdev_qvit_params *param);

QDF_STATUS (*send_mcast_group_update_cmd)(wmi_unified_t wmi_handle,
		struct mcast_group_update_params *param);

QDF_STATUS (*send_peer_add_wds_entry_cmd)(wmi_unified_t wmi_handle,
		struct peer_add_wds_entry_params *param);

QDF_STATUS (*send_peer_del_wds_entry_cmd)(wmi_unified_t wmi_handle,
		struct peer_del_wds_entry_params *param);

QDF_STATUS (*send_peer_update_wds_entry_cmd)(wmi_unified_t wmi_handle,
		struct peer_update_wds_entry_params *param);

QDF_STATUS (*send_phyerr_enable_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_phyerr_disable_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_smart_ant_enable_cmd)(wmi_unified_t wmi_handle,
		struct smart_ant_enable_params *param);

QDF_STATUS (*send_smart_ant_set_rx_ant_cmd)(wmi_unified_t wmi_handle,
		struct smart_ant_rx_ant_params *param);

QDF_STATUS (*send_smart_ant_set_tx_ant_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct smart_ant_tx_ant_params *param);

QDF_STATUS (*send_smart_ant_set_training_info_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct smart_ant_training_info_params *param);

QDF_STATUS (*send_smart_ant_set_node_config_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct smart_ant_node_config_params *param);

QDF_STATUS (*send_smart_ant_enable_tx_feedback_cmd)(wmi_unified_t wmi_handle,
		struct smart_ant_enable_tx_feedback_params *param);

QDF_STATUS (*send_vdev_spectral_configure_cmd)(wmi_unified_t wmi_handle,
		struct vdev_spectral_configure_params *param);

QDF_STATUS (*send_vdev_spectral_enable_cmd)(wmi_unified_t wmi_handle,
		struct vdev_spectral_enable_params *param);

QDF_STATUS (*send_bss_chan_info_request_cmd)(wmi_unified_t wmi_handle,
		struct bss_chan_info_request_params *param);

QDF_STATUS (*send_thermal_mitigation_param_cmd)(wmi_unified_t wmi_handle,
		struct thermal_mitigation_params *param);

QDF_STATUS (*send_vdev_set_neighbour_rx_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct set_neighbour_rx_params *param);

QDF_STATUS (*send_vdev_set_fwtest_param_cmd)(wmi_unified_t wmi_handle,
		struct set_fwtest_params *param);

QDF_STATUS (*send_vdev_config_ratemask_cmd)(wmi_unified_t wmi_handle,
		struct config_ratemask_params *param);

QDF_STATUS (*send_vdev_install_key_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct vdev_install_key_params *param);

QDF_STATUS (*send_wow_wakeup_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_wow_add_wakeup_event_cmd)(wmi_unified_t wmi_handle,
		struct wow_add_wakeup_params *param);

QDF_STATUS (*send_wow_add_wakeup_pattern_cmd)(wmi_unified_t wmi_handle,
		struct wow_add_wakeup_pattern_params *param);

QDF_STATUS (*send_wow_remove_wakeup_pattern_cmd)(wmi_unified_t wmi_handle,
		struct wow_remove_wakeup_pattern_params *param);

QDF_STATUS (*send_pdev_set_regdomain_cmd)(wmi_unified_t wmi_handle,
		struct pdev_set_regdomain_params *param);

QDF_STATUS (*send_set_quiet_mode_cmd)(wmi_unified_t wmi_handle,
		struct set_quiet_mode_params *param);

QDF_STATUS (*send_set_beacon_filter_cmd)(wmi_unified_t wmi_handle,
		struct set_beacon_filter_params *param);

QDF_STATUS (*send_remove_beacon_filter_cmd)(wmi_unified_t wmi_handle,
		struct remove_beacon_filter_params *param);
/*
QDF_STATUS (*send_mgmt_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct mgmt_params *param);
		*/

QDF_STATUS (*send_addba_clearresponse_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct addba_clearresponse_params *param);

QDF_STATUS (*send_addba_send_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct addba_send_params *param);

QDF_STATUS (*send_delba_send_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct delba_send_params *param);

QDF_STATUS (*send_addba_setresponse_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct addba_setresponse_params *param);

QDF_STATUS (*send_singleamsdu_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct singleamsdu_params *param);

QDF_STATUS (*send_set_qboost_param_cmd)(wmi_unified_t wmi_handle,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
		struct set_qboost_params *param);

QDF_STATUS (*send_mu_scan_cmd)(wmi_unified_t wmi_handle,
		struct mu_scan_params *param);

QDF_STATUS (*send_lteu_config_cmd)(wmi_unified_t wmi_handle,
		struct lteu_config_params *param);

QDF_STATUS (*send_set_ps_mode_cmd)(wmi_unified_t wmi_handle,
		       struct set_ps_mode_params *param);
void (*save_service_bitmap)(wmi_unified_t wmi_handle,
		void *evt_buf);
bool (*is_service_enabled)(wmi_unified_t wmi_handle,
	uint32_t service_id);
QDF_STATUS (*get_target_cap_from_service_ready)(wmi_unified_t wmi_handle,
	void *evt_buf, target_capability_info *ev);

QDF_STATUS (*extract_fw_version)(wmi_unified_t wmi_handle,
				void *ev, struct wmi_host_fw_ver *fw_ver);

QDF_STATUS (*extract_fw_abi_version)(wmi_unified_t wmi_handle,
				void *ev, struct wmi_host_fw_abi_ver *fw_ver);

QDF_STATUS (*extract_hal_reg_cap)(wmi_unified_t wmi_handle, void *evt_buf,
	TARGET_HAL_REG_CAPABILITIES *hal_reg_cap);

host_mem_req * (*extract_host_mem_req)(wmi_unified_t wmi_handle,
	void *evt_buf, uint8_t *num_entries);

QDF_STATUS (*init_cmd_send)(wmi_unified_t wmi_handle,
		target_resource_config *res_cfg,
		uint8_t num_mem_chunks,
		struct wmi_host_mem_chunk *mem_chunk);

QDF_STATUS (*save_fw_version)(wmi_unified_t wmi_handle, void *evt_buf);
uint32_t (*ready_extract_init_status)(wmi_unified_t wmi_hdl, void *ev);
QDF_STATUS (*ready_extract_mac_addr)(wmi_unified_t wmi_hdl, void *ev,
		uint8_t *macaddr);
QDF_STATUS (*check_and_update_fw_version)(wmi_unified_t wmi_hdl, void *ev);
uint8_t* (*extract_dbglog_data_len)(wmi_unified_t wmi_handle, void *evt_buf,
		uint16_t *len);
QDF_STATUS (*send_ext_resource_config)(wmi_unified_t wmi_handle,
		wmi_host_ext_resource_config *ext_cfg);

QDF_STATUS (*send_nf_dbr_dbm_info_get_cmd)(wmi_unified_t wmi_handle);

QDF_STATUS (*send_packet_power_info_get_cmd)(wmi_unified_t wmi_handle,
		      struct packet_power_info_params *param);

QDF_STATUS (*send_gpio_config_cmd)(wmi_unified_t wmi_handle,
		      struct gpio_config_params *param);

QDF_STATUS (*send_gpio_output_cmd)(wmi_unified_t wmi_handle,
		      struct gpio_output_params *param);

QDF_STATUS (*send_rtt_meas_req_test_cmd)(wmi_unified_t wmi_handle,
		      struct rtt_meas_req_test_params *param);

QDF_STATUS (*send_rtt_meas_req_cmd)(wmi_unified_t wmi_handle,
		      struct rtt_meas_req_params *param);

QDF_STATUS (*send_rtt_keepalive_req_cmd)(wmi_unified_t wmi_handle,
		      struct rtt_keepalive_req_params *param);

QDF_STATUS (*send_lci_set_cmd)(wmi_unified_t wmi_handle,
		      struct lci_set_params *param);

QDF_STATUS (*send_lcr_set_cmd)(wmi_unified_t wmi_handle,
		      struct lcr_set_params *param);

QDF_STATUS (*send_periodic_chan_stats_config_cmd)(wmi_unified_t wmi_handle,
			struct periodic_chan_stats_params *param);

QDF_STATUS
(*send_atf_peer_request_cmd)(wmi_unified_t wmi_handle,
			struct atf_peer_request_params *param);

QDF_STATUS
(*send_set_atf_grouping_cmd)(wmi_unified_t wmi_handle,
			struct atf_grouping_params *param);

QDF_STATUS (*extract_wds_addr_event)(wmi_unified_t wmi_handle,
	void *evt_buf, uint16_t len, wds_addr_event_t *wds_ev);

QDF_STATUS (*extract_dcs_interference_type)(wmi_unified_t wmi_handle,
	void *evt_buf, uint32_t *interference_type);

QDF_STATUS (*extract_dcs_cw_int)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_ath_dcs_cw_int *cw_int);

QDF_STATUS (*extract_dcs_im_tgt_stats)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_dcs_im_tgt_stats_t *wlan_stat);

QDF_STATUS (*extract_fips_event_error_status)(wmi_unified_t wmi_handle,
	void *evt_buf, uint32_t *err_status);

QDF_STATUS (*extract_fips_event_data)(wmi_unified_t wmi_handle,
	void *evt_buf, uint32_t *data_len, uint32_t **data);
QDF_STATUS (*extract_vdev_start_resp)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_vdev_start_resp *vdev_rsp);

QDF_STATUS (*extract_tbttoffset_update_params)(void *wmi_hdl, void *evt_buf,
	uint32_t *vdev_map, uint32_t **tbttoffset_list);

QDF_STATUS (*extract_mgmt_rx_params)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_mgmt_rx_hdr *hdr, uint8_t **bufp);

QDF_STATUS (*extract_vdev_stopped_param)(wmi_unified_t wmi_handle,
		void *evt_buf, uint32_t *vdev_id);

QDF_STATUS (*extract_vdev_roam_param)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_roam_event *param);

QDF_STATUS (*extract_vdev_scan_ev_param)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_scan_event *param);

QDF_STATUS (*extract_mu_ev_param)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_mu_report_event *param);

QDF_STATUS (*extract_pdev_tpc_config_ev_param)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_pdev_tpc_config_event *param);

QDF_STATUS (*extract_gpio_input_ev_param)(wmi_unified_t wmi_handle,
	void *evt_buf, uint32_t *gpio_num);

QDF_STATUS (*extract_pdev_reserve_ast_ev_param)(wmi_unified_t wmi_handle,
	void *evt_buf, uint32_t *result);

QDF_STATUS (*extract_nfcal_power_ev_param)(wmi_unified_t wmi_handle,
		void *evt_buf,
		wmi_host_pdev_nfcal_power_all_channels_event *param);

QDF_STATUS (*extract_pdev_tpc_ev_param)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_pdev_tpc_event *param);

QDF_STATUS (*extract_pdev_generic_buffer_ev_param)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_pdev_generic_buffer_event *param);

QDF_STATUS (*extract_mgmt_tx_compl_param)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_mgmt_tx_compl_event *param);

QDF_STATUS (*extract_swba_vdev_map)(wmi_unified_t wmi_handle, void *evt_buf,
	uint32_t *vdev_map);

QDF_STATUS (*extract_swba_tim_info)(wmi_unified_t wmi_handle, void *evt_buf,
	uint32_t idx, wmi_host_tim_info *tim_info);

QDF_STATUS (*extract_swba_noa_info)(wmi_unified_t wmi_handle, void *evt_buf,
	    uint32_t idx, wmi_host_p2p_noa_info *p2p_desc);

QDF_STATUS (*extract_peer_sta_ps_statechange_ev)(wmi_unified_t wmi_handle,
	void *evt_buf, wmi_host_peer_sta_ps_statechange_event *ev);

QDF_STATUS (*extract_peer_sta_kickout_ev)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_peer_sta_kickout_event *ev);

QDF_STATUS (*extract_peer_ratecode_list_ev)(wmi_unified_t wmi_handle,
		void *evt_buf, uint8_t *peer_mac, wmi_sa_rate_cap *rate_cap);

QDF_STATUS (*extract_comb_phyerr)(wmi_unified_t wmi_handle, void *evt_buf,
	uint16_t datalen, uint16_t *buf_offset, wmi_host_phyerr_t *phyerr);

QDF_STATUS (*extract_single_phyerr)(wmi_unified_t wmi_handle, void *evt_buf,
	uint16_t datalen, uint16_t *buf_offset, wmi_host_phyerr_t *phyerr);

QDF_STATUS (*extract_composite_phyerr)(wmi_unified_t wmi_handle, void *evt_buf,
	uint16_t datalen, wmi_host_phyerr_t *phyerr);

QDF_STATUS (*extract_rtt_hdr)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_rtt_event_hdr *ev);

QDF_STATUS (*extract_rtt_ev)(wmi_unified_t wmi_handle, void *evt_buf,
	wmi_host_rtt_meas_event *ev, uint8_t *hdump, uint16_t hdump_len);

QDF_STATUS (*extract_rtt_error_report_ev)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_rtt_error_report_event *ev);

QDF_STATUS (*extract_all_stats_count)(wmi_unified_t wmi_handle, void *evt_buf,
			   wmi_host_stats_event *stats_param);

QDF_STATUS (*extract_pdev_stats)(wmi_unified_t wmi_handle, void *evt_buf,
			 uint32_t index, wmi_host_pdev_stats *pdev_stats);

QDF_STATUS (*extract_pdev_ext_stats)(wmi_unified_t wmi_handle, void *evt_buf,
		 uint32_t index, wmi_host_pdev_ext_stats *pdev_ext_stats);

QDF_STATUS (*extract_vdev_stats)(wmi_unified_t wmi_handle, void *evt_buf,
			 uint32_t index, wmi_host_vdev_stats *vdev_stats);

QDF_STATUS (*extract_peer_stats)(wmi_unified_t wmi_handle, void *evt_buf,
			 uint32_t index, wmi_host_peer_stats *peer_stats);

QDF_STATUS (*extract_bcnflt_stats)(wmi_unified_t wmi_handle, void *evt_buf,
			 uint32_t index, wmi_host_bcnflt_stats *bcnflt_stats);

QDF_STATUS (*extract_peer_extd_stats)(wmi_unified_t wmi_handle, void *evt_buf,
		 uint32_t index, wmi_host_peer_extd_stats *peer_extd_stats);

QDF_STATUS (*extract_chan_stats)(wmi_unified_t wmi_handle, void *evt_buf,
			 uint32_t index, wmi_host_chan_stats *chan_stats);

QDF_STATUS (*extract_thermal_stats)(wmi_unified_t wmi_handle, void *evt_buf,
	uint32_t *temp, uint32_t *level);

QDF_STATUS (*extract_thermal_level_stats)(wmi_unified_t wmi_handle,
		void *evt_buf, uint8_t idx, uint32_t *levelcount,
		uint32_t *dccount);

QDF_STATUS (*extract_profile_ctx)(wmi_unified_t wmi_handle, void *evt_buf,
				   wmi_host_wlan_profile_ctx_t *profile_ctx);

QDF_STATUS (*extract_profile_data)(wmi_unified_t wmi_handle, void *evt_buf,
				uint8_t idx,
				wmi_host_wlan_profile_t *profile_data);

QDF_STATUS (*extract_chan_info_event)(wmi_unified_t wmi_handle, void *evt_buf,
				   wmi_host_chan_info_event *chan_info);

QDF_STATUS (*extract_channel_hopping_event)(wmi_unified_t wmi_handle,
		void *evt_buf,
		wmi_host_pdev_channel_hopping_event *ch_hopping);

QDF_STATUS (*extract_bss_chan_info_event)(wmi_unified_t wmi_handle,
		void *evt_buf,
		wmi_host_pdev_bss_chan_info_event *bss_chan_info);

QDF_STATUS (*extract_inst_rssi_stats_event)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_inst_stats_resp *inst_rssi_resp);

QDF_STATUS (*extract_tx_data_traffic_ctrl_ev)(wmi_unified_t wmi_handle,
		void *evt_buf, wmi_host_tx_data_traffic_ctrl_event *ev);

QDF_STATUS (*extract_vdev_extd_stats)(wmi_unified_t wmi_handle, void *evt_buf,
		uint32_t index, wmi_host_vdev_extd_stats *vdev_extd_stats);

QDF_STATUS (*send_power_dbg_cmd)(wmi_unified_t wmi_handle,
				struct wmi_power_dbg_params *param);

QDF_STATUS (*send_adapt_dwelltime_params_cmd)(wmi_unified_t wmi_handle,
			struct wmi_adaptive_dwelltime_params *dwelltime_params);

QDF_STATUS (*send_fw_test_cmd)(wmi_unified_t wmi_handle,
			       struct set_fwtest_params *wmi_fwtest);

QDF_STATUS (*send_encrypt_decrypt_send_cmd)(wmi_unified_t wmi_handle,
				struct encrypt_decrypt_req_params *params);

QDF_STATUS (*send_sar_limit_cmd)(wmi_unified_t wmi_handle,
				struct sar_limit_cmd_params *params);
uint16_t (*wmi_set_htc_tx_tag)(wmi_unified_t wmi_handle,
				wmi_buf_t buf, uint32_t cmd_id);

QDF_STATUS (*send_get_rcpi_cmd)(wmi_unified_t wmi_handle,
				struct rcpi_req *get_rcpi_param);
};

struct target_abi_version {
	A_UINT32 abi_version_0;
	/** WMI Major and Minor versions */
	A_UINT32 abi_version_1;
	/** WMI change revision */
	A_UINT32 abi_version_ns_0;
	/** ABI version namespace first four dwords */
	A_UINT32 abi_version_ns_1;
	/** ABI version namespace second four dwords */
	A_UINT32 abi_version_ns_2;
	/** ABI version namespace third four dwords */
	A_UINT32 abi_version_ns_3;
	/** ABI version namespace fourth four dwords */
};

/**
 * struct wmi_init_cmd - Saved wmi INIT command
 * @buf: Buffer containing the wmi INIT command
 * @buf_len: Length of the buffer
 */
struct wmi_cmd_init {
	wmi_buf_t buf;
	uint32_t buf_len;
};

struct wmi_unified {
	void *scn_handle;    /* handle to device */
	osdev_t  osdev; /* handle to use OS-independent services */
	qdf_atomic_t pending_cmds;
	HTC_ENDPOINT_ID wmi_endpoint_id;
	uint16_t max_msg_len;
	uint32_t event_id[WMI_UNIFIED_MAX_EVENT];
	wmi_unified_event_handler event_handler[WMI_UNIFIED_MAX_EVENT];
	enum wmi_rx_exec_ctx ctx[WMI_UNIFIED_MAX_EVENT];
	uint32_t max_event_idx;
	void *htc_handle;
	qdf_spinlock_t eventq_lock;
	qdf_nbuf_queue_t event_queue;
	struct work_struct rx_event_work;
	int wmi_stop_in_progress;
#ifndef WMI_NON_TLV_SUPPORT
	struct _wmi_abi_version fw_abi_version;
	struct _wmi_abi_version final_abi_vers;
#endif
	struct wmi_cmd_init saved_wmi_init_cmd;
	uint32_t num_of_diag_events_logs;
	uint32_t *events_logs_list;
	struct host_offload_req_param arp_info;
#ifdef WLAN_OPEN_SOURCE
	struct fwdebug dbglog;
	struct dentry *debugfs_phy;
#endif /* WLAN_OPEN_SOURCE */

#ifdef WMI_INTERFACE_EVENT_LOGGING
	struct wmi_debug_log_info log_info;
#endif /*WMI_INTERFACE_EVENT_LOGGING */

	qdf_atomic_t is_target_suspended;

#ifdef FEATURE_RUNTIME_PM
	qdf_atomic_t runtime_pm_inprogress;
#endif
	qdf_atomic_t is_wow_bus_suspended;
	bool tag_crash_inject;
	bool tgt_force_assert_enable;
	enum wmi_target_type target_type;
	struct wmi_rx_ops rx_ops;
	struct wmi_ops *ops;
	bool use_cookie;
	bool wmi_stopinprogress;
	qdf_spinlock_t ctx_lock;
#ifdef WMI_TLV_AND_NON_TLV_SUPPORT
	/* WMI service bitmap recieved from target */
	uint32_t wmi_service_bitmap[wmi_services_max];
	uint32_t wmi_events[wmi_events_max];
	uint32_t pdev_param[wmi_pdev_param_max];
	uint32_t vdev_param[wmi_vdev_param_max];
	uint32_t services[wmi_services_max];
#endif
};
#ifdef WMI_NON_TLV_SUPPORT
/* ONLY_NON_TLV_TARGET:TLV attach dummy function defintion for case when
 * driver supports only NON-TLV target (WIN mainline) */
#define wmi_tlv_attach(x) qdf_print("TLV Unavailable\n")
#else
void wmi_tlv_attach(wmi_unified_t wmi_handle);
#endif
void wmi_non_tlv_attach(wmi_unified_t wmi_handle);

/**
 * wmi_align() - provides word aligned parameter
 * @param: parameter to be aligned
 *
 * Return: word aligned parameter
 */
static inline uint32_t wmi_align(uint32_t param)
{
	return roundup(param, sizeof(uint32_t));
}
#endif
