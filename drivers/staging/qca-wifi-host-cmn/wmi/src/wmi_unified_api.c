/*
 * Copyright (c) 2016-2017 The Linux Foundation. All rights reserved.
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
#include "athdefs.h"
#include "osapi_linux.h"
#include "a_types.h"
#include "a_debug.h"
#include "ol_if_athvar.h"
#include "ol_defines.h"
#include "wmi_unified_priv.h"
#include "wmi_unified_param.h"

/**
 * wmi_unified_vdev_create_send() - send VDEV create command to fw
 * @wmi_handle: wmi handle
 * @param: pointer to hold vdev create parameter
 * @macaddr: vdev mac address
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_create_send(void *wmi_hdl,
				 uint8_t macaddr[IEEE80211_ADDR_LEN],
				 struct vdev_create_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_create_cmd)
		return wmi_handle->ops->send_vdev_create_cmd(wmi_handle,
			   macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_vdev_delete_send() - send VDEV delete command to fw
 * @wmi_handle: wmi handle
 * @if_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_delete_send(void *wmi_hdl,
					  uint8_t if_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_delete_cmd)
		return wmi_handle->ops->send_vdev_delete_cmd(wmi_handle,
			   if_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_vdev_stop_send() - send vdev stop command to fw
 * @wmi: wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_stop_send(void *wmi_hdl,
					uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_stop_cmd)
		return wmi_handle->ops->send_vdev_stop_cmd(wmi_handle,
			   vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_vdev_down_send() - send vdev down command to fw
 * @wmi: wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_down_send(void *wmi_hdl, uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_down_cmd)
		return wmi_handle->ops->send_vdev_down_cmd(wmi_handle, vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_vdev_start_send() - send vdev start command to fw
 * @wmi: wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_start_send(void *wmi_hdl,
			struct vdev_start_params *req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_start_cmd)
		return wmi_handle->ops->send_vdev_start_cmd(wmi_handle, req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_hidden_ssid_vdev_restart_send() - restart vdev to set hidden ssid
 * @wmi: wmi handle
 * @restart_params: vdev restart params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_hidden_ssid_vdev_restart_send(void *wmi_hdl,
			struct hidden_ssid_vdev_restart_params *restart_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_hidden_ssid_vdev_restart_cmd)
		return wmi_handle->ops->send_hidden_ssid_vdev_restart_cmd(
			wmi_handle, restart_params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_peer_flush_tids_send() - flush peer tids packets in fw
 * @wmi: wmi handle
 * @peer_addr: peer mac address
 * @param: pointer to hold peer flush tid parameter
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_peer_flush_tids_send(void *wmi_hdl,
					 uint8_t peer_addr[IEEE80211_ADDR_LEN],
					 struct peer_flush_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_flush_tids_cmd)
		return wmi_handle->ops->send_peer_flush_tids_cmd(wmi_handle,
				  peer_addr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_peer_delete_send() - send PEER delete command to fw
 * @wmi: wmi handle
 * @peer_addr: peer mac addr
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_peer_delete_send(void *wmi_hdl,
				    uint8_t
				    peer_addr[IEEE80211_ADDR_LEN],
				    uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_delete_cmd)
		return wmi_handle->ops->send_peer_delete_cmd(wmi_handle,
				  peer_addr, vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_set_peer_param() - set peer parameter in fw
 * @wmi_ctx: wmi handle
 * @peer_addr: peer mac address
 * @param    : pointer to hold peer set parameter
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_set_peer_param_send(void *wmi_hdl,
				uint8_t peer_addr[IEEE80211_ADDR_LEN],
				struct peer_set_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_param_cmd)
		return wmi_handle->ops->send_peer_param_cmd(wmi_handle,
				peer_addr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_vdev_up_send() - send vdev up command in fw
 * @wmi: wmi handle
 * @bssid: bssid
 * @vdev_up_params: pointer to hold vdev up parameter
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_up_send(void *wmi_hdl,
			     uint8_t bssid[IEEE80211_ADDR_LEN],
				 struct vdev_up_params *params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_up_cmd)
		return wmi_handle->ops->send_vdev_up_cmd(wmi_handle, bssid,
					params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_peer_create_send() - send peer create command to fw
 * @wmi: wmi handle
 * @peer_addr: peer mac address
 * @peer_type: peer type
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_peer_create_send(void *wmi_hdl,
					struct peer_create_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_create_cmd)
		return wmi_handle->ops->send_peer_create_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

#ifdef FEATURE_GREEN_AP
/**
 * wmi_unified_green_ap_ps_send() - enable green ap powersave command
 * @wmi_handle: wmi handle
 * @value: value
 * @mac_id: mac id to have radio context
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_green_ap_ps_send(void *wmi_hdl,
						uint32_t value, uint8_t mac_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_green_ap_ps_cmd)
		return wmi_handle->ops->send_green_ap_ps_cmd(wmi_handle, value,
				  mac_id);

	return QDF_STATUS_E_FAILURE;
}
#else
QDF_STATUS wmi_unified_green_ap_ps_send(void *wmi_hdl,
						uint32_t value, uint8_t mac_id)
{
	return 0;
}
#endif /* FEATURE_GREEN_AP */

/**
 * wmi_unified_pdev_utf_cmd() - send utf command to fw
 * @wmi_handle: wmi handle
 * @param: pointer to pdev_utf_params
 * @mac_id: mac id to have radio context
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS
wmi_unified_pdev_utf_cmd_send(void *wmi_hdl,
				struct pdev_utf_params *param,
				uint8_t mac_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_utf_cmd)
		return wmi_handle->ops->send_pdev_utf_cmd(wmi_handle, param,
				  mac_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_pdev_param_send() - set pdev parameters
 * @wmi_handle: wmi handle
 * @param: pointer to pdev parameter
 * @mac_id: radio context
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures,
 *         errno on failure
 */
QDF_STATUS
wmi_unified_pdev_param_send(void *wmi_hdl,
			   struct pdev_params *param,
				uint8_t mac_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_param_cmd)
		return wmi_handle->ops->send_pdev_param_cmd(wmi_handle, param,
				  mac_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_suspend_send() - WMI suspend function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold suspend parameter
 *  @mac_id: radio context
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_suspend_send(void *wmi_hdl,
				struct suspend_params *param,
				uint8_t mac_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_suspend_cmd)
		return wmi_handle->ops->send_suspend_cmd(wmi_handle, param,
				  mac_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_resume_send - WMI resume function
 *  @param wmi_handle      : handle to WMI.
 *  @mac_id: radio context
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_resume_send(void *wmi_hdl,
				uint8_t mac_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_resume_cmd)
		return wmi_handle->ops->send_resume_cmd(wmi_handle,
				  mac_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wow_enable_send() - WMI wow enable function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold wow enable parameter
 *  @mac_id: radio context
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_enable_send(void *wmi_hdl,
				struct wow_cmd_params *param,
				uint8_t mac_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_wow_enable_cmd)
		return wmi_handle->ops->send_wow_enable_cmd(wmi_handle, param,
				  mac_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wow_wakeup_send() - WMI wow wakeup function
 *  @param wmi_hdl      : handle to WMI.
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_wakeup_send(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_wow_wakeup_cmd)
		return wmi_handle->ops->send_wow_wakeup_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wow_add_wakeup_event_send() - WMI wow wakeup function
 *  @param wmi_handle      : handle to WMI.
 *  @param: pointer to wow wakeup event parameter structure
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_add_wakeup_event_send(void *wmi_hdl,
		struct wow_add_wakeup_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_wow_add_wakeup_event_cmd)
		return wmi->ops->send_wow_add_wakeup_event_cmd(wmi,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wow_add_wakeup_pattern_send() - WMI wow wakeup pattern function
 *  @param wmi_handle      : handle to WMI.
 *  @param: pointer to wow wakeup pattern parameter structure
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_add_wakeup_pattern_send(void *wmi_hdl,
		struct wow_add_wakeup_pattern_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_wow_add_wakeup_pattern_cmd)
		return wmi->ops->send_wow_add_wakeup_pattern_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wow_remove_wakeup_pattern_send() - WMI wow wakeup pattern function
 *  @param wmi_handle      : handle to WMI.
 *  @param: pointer to wow wakeup pattern parameter structure
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_remove_wakeup_pattern_send(void *wmi_hdl,
		struct wow_remove_wakeup_pattern_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_wow_remove_wakeup_pattern_cmd)
		return wmi->ops->send_wow_remove_wakeup_pattern_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_ap_ps_cmd_send() - set ap powersave parameters
 * @wma_ctx: wma context
 * @peer_addr: peer mac address
 * @param: pointer to ap_ps parameter structure
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_ap_ps_cmd_send(void *wmi_hdl,
					   uint8_t *peer_addr,
					   struct ap_ps_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ap_ps_param_cmd)
		return wmi_handle->ops->send_set_ap_ps_param_cmd(wmi_handle,
				  peer_addr,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_sta_ps_cmd_send() - set sta powersave parameters
 * @wma_ctx: wma context
 * @peer_addr: peer mac address
 * @param: pointer to sta_ps parameter structure
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_sta_ps_cmd_send(void *wmi_hdl,
					   struct sta_ps_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_sta_ps_param_cmd)
		return wmi_handle->ops->send_set_sta_ps_param_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_crash_inject() - inject fw crash
 * @wma_handle: wma handle
 * @param: ponirt to crash inject paramter structure
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_crash_inject(void *wmi_hdl,
			 struct crash_inject *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_crash_inject_cmd)
		return wmi_handle->ops->send_crash_inject_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_dbglog_cmd_send() - set debug log level
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold dbglog level parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS
wmi_unified_dbglog_cmd_send(void *wmi_hdl,
				struct dbglog_params *dbglog_param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_dbglog_cmd)
		return wmi_handle->ops->send_dbglog_cmd(wmi_handle,
				  dbglog_param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_vdev_set_param_send() - WMI vdev set parameter function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold vdev set parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_set_param_send(void *wmi_hdl,
				struct vdev_set_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_set_param_cmd)
		return wmi_handle->ops->send_vdev_set_param_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_stats_request_send() - WMI request stats function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold stats request parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_stats_request_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct stats_request_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_stats_request_cmd)
		return wmi_handle->ops->send_stats_request_cmd(wmi_handle,
				   macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

#ifndef WMI_NON_TLV_SUPPORT
/**
 *  wmi_unified_packet_log_enable_send() - WMI request stats function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold stats request parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_packet_log_enable_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct packet_enable_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_packet_log_enable_cmd)
		return wmi_handle->ops->send_packet_log_enable_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}
#else
/**
 *  wmi_unified_packet_log_enable_send() - WMI request stats function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold stats request parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_packet_log_enable_send(void *wmi_hdl,
				WMI_HOST_PKTLOG_EVENT PKTLOG_EVENT)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_packet_log_enable_cmd)
		return wmi_handle->ops->send_packet_log_enable_cmd(wmi_handle,
				  PKTLOG_EVENT);

	return QDF_STATUS_E_FAILURE;
}

#endif
/**
 *  wmi_unified_packet_log_disable__send() - WMI pktlog disable function
 *  @param wmi_handle      : handle to WMI.
 *  @param PKTLOG_EVENT    : packet log event
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_packet_log_disable_send(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_packet_log_disable_cmd)
		return wmi_handle->ops->send_packet_log_disable_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_beacon_send_cmd() - WMI beacon send function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold beacon send cmd parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_beacon_send_cmd(void *wmi_hdl,
				struct beacon_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_beacon_send_cmd)
		return wmi_handle->ops->send_beacon_send_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_beacon_tmpl_send_cmd() - WMI beacon send function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold beacon send cmd parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_beacon_tmpl_send_cmd(void *wmi_hdl,
				struct beacon_tmpl_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_beacon_tmpl_send_cmd)
		return wmi_handle->ops->send_beacon_tmpl_send_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}
/**
 *  wmi_unified_peer_assoc_send() - WMI peer assoc function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to peer assoc parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_peer_assoc_send(void *wmi_hdl,
				struct peer_assoc_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_assoc_cmd)
		return wmi_handle->ops->send_peer_assoc_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_scan_start_cmd_send() - WMI scan start function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold scan start cmd parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_scan_start_cmd_send(void *wmi_hdl,
				struct scan_start_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_scan_start_cmd)
		return wmi_handle->ops->send_scan_start_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_scan_stop_cmd_send() - WMI scan start function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold scan start cmd parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_scan_stop_cmd_send(void *wmi_hdl,
				struct scan_stop_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_scan_stop_cmd)
		return wmi_handle->ops->send_scan_stop_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_scan_chan_list_cmd_send() - WMI scan channel list function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold scan channel list parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_scan_chan_list_cmd_send(void *wmi_hdl,
				struct scan_chan_list_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_scan_chan_list_cmd)
		return wmi_handle->ops->send_scan_chan_list_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_mgmt_unified_cmd_send() - management cmd over wmi layer
 *  @wmi_hdl      : handle to WMI.
 *  @param    : pointer to hold mgmt cmd parameter
 *
 *  Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_mgmt_unified_cmd_send(void *wmi_hdl,
				struct wmi_mgmt_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_mgmt_cmd)
		return wmi_handle->ops->send_mgmt_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_modem_power_state() - set modem power state to fw
 * @wmi_hdl: wmi handle
 * @param_value: parameter value
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_modem_power_state(void *wmi_hdl,
		uint32_t param_value)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_modem_power_state_cmd)
		return wmi_handle->ops->send_modem_power_state_cmd(wmi_handle,
				  param_value);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_sta_ps_mode() - set sta powersave params in fw
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 * @val: value
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS wmi_unified_set_sta_ps_mode(void *wmi_hdl,
			       uint32_t vdev_id, uint8_t val)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_sta_ps_mode_cmd)
		return wmi_handle->ops->send_set_sta_ps_mode_cmd(wmi_handle,
				  vdev_id, val);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_set_mimops() - set MIMO powersave
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 * @value: value
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS wmi_unified_set_mimops(void *wmi_hdl, uint8_t vdev_id, int value)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_mimops_cmd)
		return wmi_handle->ops->send_set_mimops_cmd(wmi_handle,
				  vdev_id, value);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_set_smps_params() - set smps params
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 * @value: value
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS wmi_unified_set_smps_params(void *wmi_hdl, uint8_t vdev_id,
			       int value)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_smps_params_cmd)
		return wmi_handle->ops->send_set_smps_params_cmd(wmi_handle,
				  vdev_id, value);

	return QDF_STATUS_E_FAILURE;
}


/**
 * wmi_set_p2pgo_oppps_req() - send p2p go opp power save request to fw
 * @wmi_hdl: wmi handle
 * @opps: p2p opp power save parameters
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_p2pgo_oppps_req(void *wmi_hdl,
		struct p2p_ps_params *oppps)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_p2pgo_oppps_req_cmd)
		return wmi_handle->ops->send_set_p2pgo_oppps_req_cmd(wmi_handle,
				  oppps);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_p2pgo_noa_req_cmd() - send p2p go noa request to fw
 * @wmi_hdl: wmi handle
 * @noa: p2p power save parameters
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_p2pgo_noa_req_cmd(void *wmi_hdl,
			struct p2p_ps_params *noa)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_p2pgo_noa_req_cmd)
		return wmi_handle->ops->send_set_p2pgo_noa_req_cmd(wmi_handle,
				  noa);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_get_temperature() - get pdev temperature req
 * @wmi_hdl: wmi handle
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS wmi_unified_get_temperature(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_get_temperature_cmd)
		return wmi_handle->ops->send_get_temperature_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_sta_uapsd_auto_trig_cmd() - set uapsd auto trigger command
 * @wmi_hdl: wmi handle
 * @end_set_sta_ps_mode_cmd: cmd paramter strcture
 *
 * This function sets the trigger
 * uapsd params such as service interval, delay interval
 * and suspend interval which will be used by the firmware
 * to send trigger frames periodically when there is no
 * traffic on the transmit side.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS
wmi_unified_set_sta_uapsd_auto_trig_cmd(void *wmi_hdl,
				struct sta_uapsd_trig_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_sta_uapsd_auto_trig_cmd)
		return wmi_handle->ops->send_set_sta_uapsd_auto_trig_cmd(wmi_handle,
					param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_ocb_start_timing_advert() - start sending the timing advertisement
 *			   frames on a channel
 * @wmi_handle: pointer to the wmi handle
 * @timing_advert: pointer to the timing advertisement struct
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_ocb_start_timing_advert(void *wmi_hdl,
	struct ocb_timing_advert_param *timing_advert)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_ocb_start_timing_advert_cmd)
		return wmi_handle->ops->send_ocb_start_timing_advert_cmd(wmi_handle,
				timing_advert);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_ocb_stop_timing_advert() - stop sending the timing advertisement
 *			frames on a channel
 * @wmi_handle: pointer to the wmi handle
 * @timing_advert: pointer to the timing advertisement struct
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_ocb_stop_timing_advert(void *wmi_hdl,
	struct ocb_timing_advert_param *timing_advert)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_ocb_stop_timing_advert_cmd)
		return wmi_handle->ops->send_ocb_stop_timing_advert_cmd(wmi_handle,
					timing_advert);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_ocb_set_utc_time_cmd() - get ocb tsf timer val
 * @wmi_handle: pointer to the wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_ocb_set_utc_time_cmd(void *wmi_hdl,
			struct ocb_utc_param *utc)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_ocb_set_utc_time_cmd)
		return wmi_handle->ops->send_ocb_set_utc_time_cmd(wmi_handle,
				utc);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_ocb_get_tsf_timer() - get ocb tsf timer val
 * @wmi_handle: pointer to the wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_ocb_get_tsf_timer(void *wmi_hdl,
			uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_ocb_get_tsf_timer_cmd)
		return wmi_handle->ops->send_ocb_get_tsf_timer_cmd(wmi_handle,
					vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_dcc_get_stats_cmd() - get the DCC channel stats
 * @wmi_handle: pointer to the wmi handle
 * @get_stats_param: pointer to the dcc stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_dcc_get_stats_cmd(void *wmi_hdl,
			struct dcc_get_stats_param *get_stats_param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_dcc_get_stats_cmd)
		return wmi_handle->ops->send_dcc_get_stats_cmd(wmi_handle,
					get_stats_param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_dcc_clear_stats() - command to clear the DCC stats
 * @wmi_handle: pointer to the wmi handle
 * @clear_stats_param: parameters to the command
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_dcc_clear_stats(void *wmi_hdl,
			uint32_t vdev_id, uint32_t dcc_stats_bitmap)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_dcc_clear_stats_cmd)
		return wmi_handle->ops->send_dcc_clear_stats_cmd(wmi_handle,
					vdev_id, dcc_stats_bitmap);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_dcc_update_ndl() - command to update the NDL data
 * @wmi_handle: pointer to the wmi handle
 * @update_ndl_param: pointer to the request parameters
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures
 */
QDF_STATUS wmi_unified_dcc_update_ndl(void *wmi_hdl,
			struct dcc_update_ndl_param *update_ndl_param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_dcc_update_ndl_cmd)
		return wmi_handle->ops->send_dcc_update_ndl_cmd(wmi_handle,
					update_ndl_param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_ocb_set_config() - send the OCB config to the FW
 * @wmi_handle: pointer to the wmi handle
 * @config: the OCB configuration
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures
 */
QDF_STATUS wmi_unified_ocb_set_config(void *wmi_hdl,
			struct ocb_config_param *config, uint32_t *ch_mhz)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_ocb_set_config_cmd)
		return wmi_handle->ops->send_ocb_set_config_cmd(wmi_handle,
					config, ch_mhz);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_enable_disable_mcc_adaptive_scheduler_cmd() - control mcc scheduler
 * @wmi_handle: wmi handle
 * @mcc_adaptive_scheduler: enable/disable
 *
 * This function enable/disable mcc adaptive scheduler in fw.
 *
 * Return: QDF_STATUS_SUCCESS for sucess or error code
 */
QDF_STATUS wmi_unified_set_enable_disable_mcc_adaptive_scheduler_cmd(
		void *wmi_hdl, uint32_t mcc_adaptive_scheduler,
		uint32_t pdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_enable_disable_mcc_adaptive_scheduler_cmd)
		return wmi_handle->ops->send_set_enable_disable_mcc_adaptive_scheduler_cmd(wmi_handle,
					mcc_adaptive_scheduler, pdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_mcc_channel_time_latency_cmd() - set MCC channel time latency
 * @wmi: wmi handle
 * @mcc_channel: mcc channel
 * @mcc_channel_time_latency: MCC channel time latency.
 *
 * Currently used to set time latency for an MCC vdev/adapter using operating
 * channel of it and channel number. The info is provided run time using
 * iwpriv command: iwpriv <wlan0 | p2p0> setMccLatency <latency in ms>.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_mcc_channel_time_latency_cmd(void *wmi_hdl,
	uint32_t mcc_channel_freq, uint32_t mcc_channel_time_latency)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_mcc_channel_time_latency_cmd)
		return wmi_handle->ops->send_set_mcc_channel_time_latency_cmd(wmi_handle,
					mcc_channel_freq,
					mcc_channel_time_latency);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_mcc_channel_time_quota_cmd() - set MCC channel time quota
 * @wmi: wmi handle
 * @adapter_1_chan_number: adapter 1 channel number
 * @adapter_1_quota: adapter 1 quota
 * @adapter_2_chan_number: adapter 2 channel number
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_mcc_channel_time_quota_cmd(void *wmi_hdl,
			 uint32_t adapter_1_chan_freq,
			 uint32_t adapter_1_quota, uint32_t adapter_2_chan_freq)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_mcc_channel_time_quota_cmd)
		return wmi_handle->ops->send_set_mcc_channel_time_quota_cmd(wmi_handle,
						adapter_1_chan_freq,
						adapter_1_quota,
						adapter_2_chan_freq);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_thermal_mgmt_cmd() - set thermal mgmt command to fw
 * @wmi_handle: Pointer to wmi handle
 * @thermal_info: Thermal command information
 *
 * This function sends the thermal management command
 * to the firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_thermal_mgmt_cmd(void *wmi_hdl,
				struct thermal_cmd_params *thermal_info)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_thermal_mgmt_cmd)
		return wmi_handle->ops->send_set_thermal_mgmt_cmd(wmi_handle,
					thermal_info);

	return QDF_STATUS_E_FAILURE;
}


/**
 * wmi_unified_lro_config_cmd() - process the LRO config command
 * @wmi: Pointer to wmi handle
 * @wmi_lro_cmd: Pointer to LRO configuration parameters
 *
 * This function sends down the LRO configuration parameters to
 * the firmware to enable LRO, sets the TCP flags and sets the
 * seed values for the toeplitz hash generation
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lro_config_cmd(void *wmi_hdl,
	 struct wmi_lro_config_cmd_t *wmi_lro_cmd)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lro_config_cmd)
		return wmi_handle->ops->send_lro_config_cmd(wmi_handle,
					wmi_lro_cmd);

	return QDF_STATUS_E_FAILURE;
}

#ifndef WMI_NON_TLV_SUPPORT
/**
 * wmi_unified_peer_rate_report_cmd() - process the peer rate report command
 * @wmi_hdl: Pointer to wmi handle
 * @rate_report_params: Pointer to peer rate report parameters
 *
 *
 * Return: QDF_STATUS_SUCCESS for success otherwise failure
 */
QDF_STATUS wmi_unified_peer_rate_report_cmd(void *wmi_hdl,
		struct wmi_peer_rate_report_params *rate_report_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_rate_report_cmd)
		return wmi_handle->ops->send_peer_rate_report_cmd(wmi_handle,
					rate_report_params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_bcn_buf_ll_cmd() - prepare and send beacon buffer to fw for LL
 * @wmi_hdl: wmi handle
 * @param: bcn ll cmd parameter
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_bcn_buf_ll_cmd(void *wmi_hdl,
			wmi_bcn_send_from_host_cmd_fixed_param *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_bcn_buf_ll_cmd)
		return wmi_handle->ops->send_bcn_buf_ll_cmd(wmi_handle,
						param);

	return QDF_STATUS_E_FAILURE;
}
#endif

/**
 * wmi_unified_set_sta_sa_query_param_cmd() - set sta sa query parameters
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 * @max_retries: max retries
 * @retry_interval: retry interval
 * This function sets sta query related parameters in fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */

QDF_STATUS wmi_unified_set_sta_sa_query_param_cmd(void *wmi_hdl,
					uint8_t vdev_id, uint32_t max_retries,
					uint32_t retry_interval)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_sta_sa_query_param_cmd)
		return wmi_handle->ops->send_set_sta_sa_query_param_cmd(wmi_handle,
						vdev_id, max_retries,
						retry_interval);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_sta_keep_alive_cmd() - set sta keep alive parameters
 * @wmi_hdl: wmi handle
 * @params: sta keep alive parameter
 *
 * This function sets keep alive related parameters in fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_sta_keep_alive_cmd(void *wmi_hdl,
				struct sta_params *params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_sta_keep_alive_cmd)
		return wmi_handle->ops->send_set_sta_keep_alive_cmd(wmi_handle,
						params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_vdev_set_gtx_cfg_cmd() - set GTX params
 * @wmi_hdl: wmi handle
 * @if_id: vdev id
 * @gtx_info: GTX config params
 *
 * This function set GTX related params in firmware.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_set_gtx_cfg_cmd(void *wmi_hdl, uint32_t if_id,
			struct wmi_gtx_config *gtx_info)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_set_gtx_cfg_cmd)
		return wmi_handle->ops->send_vdev_set_gtx_cfg_cmd(wmi_handle,
					if_id, gtx_info);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_update_edca_param() - update EDCA params
 * @wmi_hdl: wmi handle
 * @edca_params: edca parameters
 *
 * This function updates EDCA parameters to the target
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
#ifndef WMI_NON_TLV_SUPPORT
QDF_STATUS wmi_unified_process_update_edca_param(void *wmi_hdl,
				uint8_t vdev_id,
				wmi_wmm_vparams gwmm_param[WMI_MAX_NUM_AC])
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_update_edca_param_cmd)
		return wmi_handle->ops->send_process_update_edca_param_cmd(wmi_handle,
					 vdev_id, gwmm_param);

	return QDF_STATUS_E_FAILURE;
}
#endif

/**
 * wmi_unified_probe_rsp_tmpl_send_cmd() - send probe response template to fw
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 * @probe_rsp_info: probe response info
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_probe_rsp_tmpl_send_cmd(void *wmi_hdl,
				uint8_t vdev_id,
				struct wmi_probe_resp_params *probe_rsp_info,
				uint8_t *frm)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_probe_rsp_tmpl_send_cmd)
		return wmi_handle->ops->send_probe_rsp_tmpl_send_cmd(wmi_handle,
						 vdev_id, probe_rsp_info,
						 frm);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_setup_install_key_cmd - send key to install to fw
 * @wmi_hdl: wmi handle
 * @key_params: key parameters
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_setup_install_key_cmd(void *wmi_hdl,
				struct set_key_params *key_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_setup_install_key_cmd)
		return wmi_handle->ops->send_setup_install_key_cmd(wmi_handle,
							key_params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_p2p_go_set_beacon_ie_cmd() - set beacon IE for p2p go
 * @wma_handle: wma handle
 * @vdev_id: vdev id
 * @p2p_ie: p2p IE
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_p2p_go_set_beacon_ie_cmd(void *wmi_hdl,
				    A_UINT32 vdev_id, uint8_t *p2p_ie)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_p2p_go_set_beacon_ie_cmd)
		return wmi_handle->ops->send_p2p_go_set_beacon_ie_cmd(wmi_handle,
						 vdev_id, p2p_ie);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_gateway_params_cmd() - set gateway parameters
 * @wmi_hdl: wmi handle
 * @req: gateway parameter update request structure
 *
 * This function reads the incoming @req and fill in the destination
 * WMI structure and sends down the gateway configs down to the firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures;
 *         error number otherwise
 */
QDF_STATUS wmi_unified_set_gateway_params_cmd(void *wmi_hdl,
					struct gateway_update_req_param *req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_gateway_params_cmd)
		return wmi_handle->ops->send_set_gateway_params_cmd(wmi_handle,
				  req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_rssi_monitoring_cmd() - set rssi monitoring
 * @wmi_hdl: wmi handle
 * @req: rssi monitoring request structure
 *
 * This function reads the incoming @req and fill in the destination
 * WMI structure and send down the rssi monitoring configs down to the firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures;
 *         error number otherwise
 */
QDF_STATUS wmi_unified_set_rssi_monitoring_cmd(void *wmi_hdl,
					struct rssi_monitor_param *req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_rssi_monitoring_cmd)
		return wmi_handle->ops->send_set_rssi_monitoring_cmd(wmi_handle,
			    req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_scan_probe_setoui_cmd() - set scan probe OUI
 * @wmi_hdl: wmi handle
 * @psetoui: OUI parameters
 *
 * set scan probe OUI parameters in firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_scan_probe_setoui_cmd(void *wmi_hdl,
			  struct scan_mac_oui *psetoui)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_scan_probe_setoui_cmd)
		return wmi_handle->ops->send_scan_probe_setoui_cmd(wmi_handle,
			    psetoui);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_reset_passpoint_network_list_cmd() - reset passpoint network list
 * @wmi_hdl: wmi handle
 * @req: passpoint network request structure
 *
 * This function sends down WMI command with network id set to wildcard id.
 * firmware shall clear all the config entries
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_reset_passpoint_network_list_cmd(void *wmi_hdl,
					struct wifi_passpoint_req_param *req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_reset_passpoint_network_list_cmd)
		return wmi_handle->ops->send_reset_passpoint_network_list_cmd(wmi_handle,
			    req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_passpoint_network_list_cmd() - set passpoint network list
 * @wmi_hdl: wmi handle
 * @req: passpoint network request structure
 *
 * This function reads the incoming @req and fill in the destination
 * WMI structure and send down the passpoint configs down to the firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_passpoint_network_list_cmd(void *wmi_hdl,
					struct wifi_passpoint_req_param *req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_passpoint_network_list_cmd)
		return wmi_handle->ops->send_set_passpoint_network_list_cmd(wmi_handle,
			    req);

	return QDF_STATUS_E_FAILURE;
}

/** wmi_unified_set_epno_network_list_cmd() - set epno network list
 * @wmi_hdl: wmi handle
 * @req: epno config params request structure
 *
 * This function reads the incoming epno config request structure
 * and constructs the WMI message to the firmware.
 *
 * Returns: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures,
 *          error number otherwise
 */
QDF_STATUS wmi_unified_set_epno_network_list_cmd(void *wmi_hdl,
		struct wifi_enhanched_pno_params *req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_epno_network_list_cmd)
		return wmi_handle->ops->send_set_epno_network_list_cmd(wmi_handle,
			    req);

	return QDF_STATUS_E_FAILURE;
}

#ifndef WMI_NON_TLV_SUPPORT
/**
 * wmi_unified_roam_scan_offload_mode_cmd() - set roam scan parameters
 * @wmi_hdl: wmi handle
 * @scan_cmd_fp: scan related parameters
 * @roam_req: roam related parameters
 *
 * This function reads the incoming @roam_req and fill in the destination
 * WMI structure and send down the roam scan configs down to the firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_scan_offload_mode_cmd(void *wmi_hdl,
				wmi_start_scan_cmd_fixed_param *scan_cmd_fp,
				struct roam_offload_scan_params *roam_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_offload_mode_cmd)
		return wmi_handle->ops->send_roam_scan_offload_mode_cmd(
			wmi_handle, scan_cmd_fp, roam_req);

	return QDF_STATUS_E_FAILURE;
}
#endif

/**
 * wmi_unified_roam_scan_offload_rssi_thresh_cmd() - set roam scan rssi
 *							parameters
 * @wmi_hdl: wmi handle
 * @roam_req: roam rssi related parameters
 *
 * This function reads the incoming @roam_req and fill in the destination
 * WMI structure and send down the roam scan rssi configs down to the firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_scan_offload_rssi_thresh_cmd(void *wmi_hdl,
					struct roam_offload_scan_rssi_params
					*roam_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_offload_rssi_thresh_cmd)
		return wmi_handle->ops->send_roam_scan_offload_rssi_thresh_cmd(
				wmi_handle, roam_req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_roam_scan_filter_cmd() - send roam scan whitelist,
 *                                      blacklist and preferred list
 * @wmi_hdl: wmi handle
 * @roam_req: roam scan lists related parameters
 *
 * This function reads the incoming @roam_req and fill in the destination
 * WMI structure and send down the different roam scan lists down to the fw
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_scan_filter_cmd(void *wmi_hdl,
				struct roam_scan_filter_params *roam_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_filter_cmd)
		return wmi_handle->ops->send_roam_scan_filter_cmd(
				wmi_handle, roam_req);

	return QDF_STATUS_E_FAILURE;
}

/** wmi_unified_ipa_offload_control_cmd() - ipa offload control parameter
 * @wmi_hdl: wmi handle
 * @ipa_offload: ipa offload control parameter
 *
 * Returns: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures,
 *          error number otherwise
 */
QDF_STATUS  wmi_unified_ipa_offload_control_cmd(void *wmi_hdl,
		struct ipa_offload_control_params *ipa_offload)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_ipa_offload_control_cmd)
		return wmi_handle->ops->send_ipa_offload_control_cmd(wmi_handle,
			    ipa_offload);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_extscan_get_capabilities_cmd() - extscan get capabilities
 * @wmi_hdl: wmi handle
 * @pgetcapab: get capabilities params
 *
 * This function send request to fw to get extscan capabilities.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_extscan_get_capabilities_cmd(void *wmi_hdl,
			  struct extscan_capabilities_params *pgetcapab)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_extscan_get_capabilities_cmd)
		return wmi_handle->ops->send_extscan_get_capabilities_cmd(wmi_handle,
			    pgetcapab);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_extscan_get_cached_results_cmd() - extscan get cached results
 * @wmi_hdl: wmi handle
 * @pcached_results: cached results parameters
 *
 * This function send request to fw to get cached results.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_extscan_get_cached_results_cmd(void *wmi_hdl,
			  struct extscan_cached_result_params *pcached_results)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_extscan_get_cached_results_cmd)
		return wmi_handle->ops->send_extscan_get_cached_results_cmd(wmi_handle,
			    pcached_results);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_extscan_stop_change_monitor_cmd() - send stop change monitor cmd
 * @wmi_hdl: wmi handle
 * @reset_req: Reset change request params
 *
 * This function sends stop change monitor request to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_extscan_stop_change_monitor_cmd(void *wmi_hdl,
			  struct extscan_capabilities_reset_params *reset_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_extscan_stop_change_monitor_cmd)
		return wmi_handle->ops->send_extscan_stop_change_monitor_cmd(wmi_handle,
			    reset_req);

	return QDF_STATUS_E_FAILURE;
}



/**
 * wmi_unified_extscan_start_change_monitor_cmd() - start change monitor cmd
 * @wmi_hdl: wmi handle
 * @psigchange: change monitor request params
 *
 * This function sends start change monitor request to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_extscan_start_change_monitor_cmd(void *wmi_hdl,
				   struct extscan_set_sig_changereq_params *
				   psigchange)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_extscan_start_change_monitor_cmd)
		return wmi_handle->ops->send_extscan_start_change_monitor_cmd(wmi_handle,
			    psigchange);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_extscan_stop_hotlist_monitor_cmd() - stop hotlist monitor
 * @wmi_hdl: wmi handle
 * @photlist_reset: hotlist reset params
 *
 * This function configures hotlist monitor to stop in fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_extscan_stop_hotlist_monitor_cmd(void *wmi_hdl,
		  struct extscan_bssid_hotlist_reset_params *photlist_reset)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_extscan_stop_hotlist_monitor_cmd)
		return wmi_handle->ops->send_extscan_stop_hotlist_monitor_cmd(wmi_handle,
			    photlist_reset);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_stop_extscan_cmd() - stop extscan command to fw.
 * @wmi_hdl: wmi handle
 * @pstopcmd: stop scan command request params
 *
 * This function sends stop extscan request to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS wmi_unified_stop_extscan_cmd(void *wmi_hdl,
			  struct extscan_stop_req_params *pstopcmd)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_stop_extscan_cmd)
		return wmi_handle->ops->send_stop_extscan_cmd(wmi_handle,
			    pstopcmd);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_start_extscan_cmd() - start extscan command to fw.
 * @wmi_hdl: wmi handle
 * @pstart: scan command request params
 *
 * This function sends start extscan request to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS wmi_unified_start_extscan_cmd(void *wmi_hdl,
			  struct wifi_scan_cmd_req_params *pstart)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_start_extscan_cmd)
		return wmi_handle->ops->send_start_extscan_cmd(wmi_handle,
			    pstart);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_plm_stop_cmd() - plm stop request
 * @wmi_hdl: wmi handle
 * @plm: plm request parameters
 *
 * This function request FW to stop PLM.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_plm_stop_cmd(void *wmi_hdl,
			  const struct plm_req_params *plm)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_plm_stop_cmd)
		return wmi_handle->ops->send_plm_stop_cmd(wmi_handle,
			    plm);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_plm_start_cmd() - plm start request
 * @wmi_hdl: wmi handle
 * @plm: plm request parameters
 *
 * This function request FW to start PLM.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_plm_start_cmd(void *wmi_hdl,
			  const struct plm_req_params *plm,
			  uint32_t *gchannel_list)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_plm_start_cmd)
		return wmi_handle->ops->send_plm_start_cmd(wmi_handle,
			    plm, gchannel_list);

	return QDF_STATUS_E_FAILURE;
}

/**
 * send_pno_stop_cmd() - PNO stop request
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 *
 * This function request FW to stop ongoing PNO operation.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pno_stop_cmd(void *wmi_hdl, uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pno_stop_cmd)
		return wmi_handle->ops->send_pno_stop_cmd(wmi_handle,
			    vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_pno_start_cmd() - PNO start request
 * @wmi_hdl: wmi handle
 * @pno: PNO request
 * @gchannel_freq_list: channel frequency list
 *
 * This function request FW to start PNO request.
 * Request: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
#ifdef FEATURE_WLAN_SCAN_PNO
QDF_STATUS wmi_unified_pno_start_cmd(void *wmi_hdl,
		   struct pno_scan_req_params *pno,
		   uint32_t *gchannel_freq_list)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pno_start_cmd)
		return wmi_handle->ops->send_pno_start_cmd(wmi_handle,
			    pno, gchannel_freq_list);

	return QDF_STATUS_E_FAILURE;
}
#endif

/* wmi_unified_set_ric_req_cmd() - set ric request element
 * @wmi_hdl: wmi handle
 * @msg: message
 * @is_add_ts: is addts required
 *
 * This function sets ric request element for 11r roaming.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_ric_req_cmd(void *wmi_hdl, void *msg,
		uint8_t is_add_ts)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ric_req_cmd)
		return wmi_handle->ops->send_set_ric_req_cmd(wmi_handle, msg,
			    is_add_ts);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_ll_stats_clear_cmd() - clear link layer stats
 * @wmi_hdl: wmi handle
 * @clear_req: ll stats clear request command params
 * @addr: mac address
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_ll_stats_clear_cmd(void *wmi_hdl,
	 const struct ll_stats_clear_params *clear_req,
	 uint8_t addr[IEEE80211_ADDR_LEN])
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_ll_stats_clear_cmd)
		return wmi_handle->ops->send_process_ll_stats_clear_cmd(wmi_handle,
			   clear_req,  addr);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_ll_stats_get_cmd() - link layer stats get request
 * @wmi_hdl:wmi handle
 * @get_req:ll stats get request command params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_ll_stats_get_cmd(void *wmi_hdl,
		 const struct ll_stats_get_params  *get_req,
		 uint8_t addr[IEEE80211_ADDR_LEN])
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_ll_stats_get_cmd)
		return wmi_handle->ops->send_process_ll_stats_get_cmd(wmi_handle,
			   get_req,  addr);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_get_stats_cmd() - get stats request
 * @wmi_hdl: wma handle
 * @get_stats_param: stats params
 * @addr: mac address
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_get_stats_cmd(void *wmi_hdl,
		       struct pe_stats_req  *get_stats_param,
			   uint8_t addr[IEEE80211_ADDR_LEN])
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_get_stats_cmd)
		return wmi_handle->ops->send_get_stats_cmd(wmi_handle,
			   get_stats_param,  addr);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_congestion_request_cmd() - send request to fw to get CCA
 * @wmi_hdl: wma handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_congestion_request_cmd(void *wmi_hdl,
		uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_congestion_cmd)
		return wmi_handle->ops->send_congestion_cmd(wmi_handle,
			   vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_ll_stats_set_cmd() - link layer stats set request
 * @wmi_handle:       wmi handle
 * @set_req:  ll stats set request command params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_ll_stats_set_cmd(void *wmi_hdl,
		const struct ll_stats_set_params *set_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_ll_stats_set_cmd)
		return wmi_handle->ops->send_process_ll_stats_set_cmd(wmi_handle,
			   set_req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_snr_request_cmd() - send request to fw to get RSSI stats
 * @wmi_handle: wmi handle
 * @rssi_req: get RSSI request
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_snr_request_cmd(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_snr_request_cmd)
		return wmi_handle->ops->send_snr_request_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_snr_cmd() - get RSSI from fw
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_snr_cmd(void *wmi_hdl, uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_snr_cmd)
		return wmi_handle->ops->send_snr_cmd(wmi_handle,
			    vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_link_status_req_cmd() - process link status request from UMAC
 * @wmi_handle: wmi handle
 * @link_status: get link params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_link_status_req_cmd(void *wmi_hdl,
				 struct link_status_params *link_status)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_link_status_req_cmd)
		return wmi_handle->ops->send_link_status_req_cmd(wmi_handle,
			    link_status);

	return QDF_STATUS_E_FAILURE;
}

#ifdef FEATURE_WLAN_LPHB

/**
 * wmi_unified_lphb_config_hbenable_cmd() - enable command of LPHB configuration requests
 * @wmi_handle: wmi handle
 * @lphb_conf_req: configuration info
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lphb_config_hbenable_cmd(void *wmi_hdl,
				wmi_hb_set_enable_cmd_fixed_param *params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lphb_config_hbenable_cmd)
		return wmi_handle->ops->send_lphb_config_hbenable_cmd(wmi_handle,
			    params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_lphb_config_tcp_params_cmd() - set tcp params of LPHB configuration requests
 * @wmi_handle: wmi handle
 * @lphb_conf_req: lphb config request
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lphb_config_tcp_params_cmd(void *wmi_hdl,
				    wmi_hb_set_tcp_params_cmd_fixed_param *lphb_conf_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lphb_config_tcp_params_cmd)
		return wmi_handle->ops->send_lphb_config_tcp_params_cmd(wmi_handle,
			    lphb_conf_req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_lphb_config_tcp_pkt_filter_cmd() - configure tcp packet filter command of LPHB
 * @wmi_handle: wmi handle
 * @lphb_conf_req: lphb config request
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lphb_config_tcp_pkt_filter_cmd(void *wmi_hdl,
					wmi_hb_set_tcp_pkt_filter_cmd_fixed_param *g_hb_tcp_filter_fp)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lphb_config_tcp_pkt_filter_cmd)
		return wmi_handle->ops->send_lphb_config_tcp_pkt_filter_cmd(wmi_handle,
			    g_hb_tcp_filter_fp);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_lphb_config_udp_params_cmd() - configure udp param command of LPHB
 * @wmi_handle: wmi handle
 * @lphb_conf_req: lphb config request
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lphb_config_udp_params_cmd(void *wmi_hdl,
				    wmi_hb_set_udp_params_cmd_fixed_param *lphb_conf_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lphb_config_udp_params_cmd)
		return wmi_handle->ops->send_lphb_config_udp_params_cmd(wmi_handle,
			    lphb_conf_req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_lphb_config_udp_pkt_filter_cmd() - configure udp pkt filter command of LPHB
 * @wmi_handle: wmi handle
 * @lphb_conf_req: lphb config request
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lphb_config_udp_pkt_filter_cmd(void *wmi_hdl,
					wmi_hb_set_udp_pkt_filter_cmd_fixed_param *lphb_conf_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lphb_config_udp_pkt_filter_cmd)
		return wmi_handle->ops->send_lphb_config_udp_pkt_filter_cmd(wmi_handle,
			    lphb_conf_req);

	return QDF_STATUS_E_FAILURE;
}
#endif /* FEATURE_WLAN_LPHB */

/**
 * wmi_unified_process_dhcp_ind() - process dhcp indication from SME
 * @wmi_handle: wmi handle
 * @ta_dhcp_ind: DHCP indication parameter
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
#ifndef WMI_NON_TLV_SUPPORT
QDF_STATUS wmi_unified_process_dhcp_ind(void *wmi_hdl,
				wmi_peer_set_param_cmd_fixed_param *ta_dhcp_ind)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_dhcp_ind_cmd)
		return wmi_handle->ops->send_process_dhcp_ind_cmd(wmi_handle,
			    ta_dhcp_ind);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_get_link_speed_cmd() -send command to get linkspeed
 * @wmi_handle: wmi handle
 * @pLinkSpeed: link speed info
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_get_link_speed_cmd(void *wmi_hdl,
			wmi_mac_addr peer_macaddr)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_get_link_speed_cmd)
		return wmi_handle->ops->send_get_link_speed_cmd(wmi_handle,
			    peer_macaddr);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_egap_conf_params_cmd() - send wmi cmd of egap configuration params
 * @wmi_handle:	 wmi handler
 * @egap_params: pointer to egap_params
 *
 * Return:	 0 for success, otherwise appropriate error code
 */
QDF_STATUS wmi_unified_egap_conf_params_cmd(void *wmi_hdl,
				     wmi_ap_ps_egap_param_cmd_fixed_param *egap_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_egap_conf_params_cmd)
		return wmi_handle->ops->send_egap_conf_params_cmd(wmi_handle,
			    egap_params);

	return QDF_STATUS_E_FAILURE;
}

#endif

/**
 * wmi_unified_action_frame_patterns_cmd() - send wmi cmd of action filter params
 * @wmi_handle: wmi handler
 * @action_params: pointer to action_params
 *
 * Return: 0 for success, otherwise appropriate error code
 */
QDF_STATUS wmi_unified_action_frame_patterns_cmd(void *wmi_hdl,
				struct action_wakeup_set_param *action_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_action_frame_patterns_cmd)
		return wmi_handle->ops->send_action_frame_patterns_cmd(
				wmi_handle,
				action_params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_fw_profiling_data_cmd() - send FW profiling cmd to WLAN FW
 * @wmi_handl: wmi handle
 * @cmd: Profiling command index
 * @value1: parameter1 value
 * @value2: parameter2 value
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_fw_profiling_data_cmd(void *wmi_hdl,
			uint32_t cmd, uint32_t value1, uint32_t value2)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_fw_profiling_cmd)
		return wmi_handle->ops->send_fw_profiling_cmd(wmi_handle,
			    cmd, value1, value2);

	return QDF_STATUS_E_FAILURE;
}

#ifdef FEATURE_WLAN_RA_FILTERING
/**
 * wmi_unified_wow_sta_ra_filter_cmd() - set RA filter pattern in fw
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_sta_ra_filter_cmd(void *wmi_hdl,
				uint8_t vdev_id, uint8_t default_pattern,
				uint16_t rate_limit_interval)
{

	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_wow_sta_ra_filter_cmd)
		return wmi_handle->ops->send_wow_sta_ra_filter_cmd(wmi_handle,
			    vdev_id, default_pattern, rate_limit_interval);

	return QDF_STATUS_E_FAILURE;

}
#endif /* FEATURE_WLAN_RA_FILTERING */

/**
 * wmi_unified_nat_keepalive_en_cmd() - enable NAT keepalive filter
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_nat_keepalive_en_cmd(void *wmi_hdl, uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_nat_keepalive_en_cmd)
		return wmi_handle->ops->send_nat_keepalive_en_cmd(wmi_handle,
			    vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_csa_offload_enable() - send CSA offload enable command
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_csa_offload_enable(void *wmi_hdl, uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_csa_offload_enable_cmd)
		return wmi_handle->ops->send_csa_offload_enable_cmd(wmi_handle,
			    vdev_id);

	return QDF_STATUS_E_FAILURE;
}
/**
 * wmi_unified_start_oem_data_cmd() - start OEM data request to target
 * @wmi_handle: wmi handle
 * @startOemDataReq: start request params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_start_oem_data_cmd(void *wmi_hdl,
			  uint32_t data_len,
			  uint8_t *data)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_start_oem_data_cmd)
		return wmi_handle->ops->send_start_oem_data_cmd(wmi_handle,
			    data_len, data);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_dfs_phyerr_filter_offload_en_cmd() - enable dfs phyerr filter
 * @wmi_handle: wmi handle
 * @dfs_phyerr_filter_offload: is dfs phyerr filter offload
 *
 * Send WMI_DFS_PHYERR_FILTER_ENA_CMDID or
 * WMI_DFS_PHYERR_FILTER_DIS_CMDID command
 * to firmware based on phyerr filtering
 * offload status.
 *
 * Return: 1 success, 0 failure
 */
QDF_STATUS
wmi_unified_dfs_phyerr_filter_offload_en_cmd(void *wmi_hdl,
			bool dfs_phyerr_filter_offload)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_dfs_phyerr_filter_offload_en_cmd)
		return wmi_handle->ops->send_dfs_phyerr_filter_offload_en_cmd(wmi_handle,
			    dfs_phyerr_filter_offload);

	return QDF_STATUS_E_FAILURE;
}

#if !defined(REMOVE_PKT_LOG)
/**
 * wmi_unified_pktlog_wmi_send_cmd() - send pktlog enable/disable command to target
 * @wmi_handle: wmi handle
 * @pktlog_event: pktlog event
 * @cmd_id: pktlog cmd id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
#ifndef WMI_NON_TLV_SUPPORT
QDF_STATUS wmi_unified_pktlog_wmi_send_cmd(void *wmi_hdl,
				   WMI_PKTLOG_EVENT pktlog_event,
				   uint32_t cmd_id,
				   uint8_t user_triggered)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pktlog_wmi_send_cmd)
		return wmi_handle->ops->send_pktlog_wmi_send_cmd(wmi_handle,
			    pktlog_event, cmd_id, user_triggered);

	return QDF_STATUS_E_FAILURE;
}
#endif
#endif /* REMOVE_PKT_LOG */

/**
 * wmi_unified_add_wow_wakeup_event_cmd() -  Configures wow wakeup events.
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 * @bitmap: Event bitmap
 * @enable: enable/disable
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_add_wow_wakeup_event_cmd(void *wmi_hdl,
					uint32_t vdev_id,
					uint32_t *bitmap,
					bool enable)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_add_wow_wakeup_event_cmd)
		return wmi_handle->ops->send_add_wow_wakeup_event_cmd(
				wmi_handle, vdev_id, bitmap, enable);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_wow_patterns_to_fw_cmd() - Sends WOW patterns to FW.
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 * @ptrn_id: pattern id
 * @ptrn: pattern
 * @ptrn_len: pattern length
 * @ptrn_offset: pattern offset
 * @mask: mask
 * @mask_len: mask length
 * @user: true for user configured pattern and false for default pattern
 * @default_patterns: default patterns
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_patterns_to_fw_cmd(void *wmi_hdl,
				uint8_t vdev_id, uint8_t ptrn_id,
				const uint8_t *ptrn, uint8_t ptrn_len,
				uint8_t ptrn_offset, const uint8_t *mask,
				uint8_t mask_len, bool user,
				uint8_t default_patterns)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_wow_patterns_to_fw_cmd)
		return wmi_handle->ops->send_wow_patterns_to_fw_cmd(wmi_handle,
			    vdev_id, ptrn_id, ptrn,
				ptrn_len, ptrn_offset, mask,
				mask_len, user, default_patterns);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_wow_delete_pattern_cmd() - delete wow pattern in target
 * @wmi_handle: wmi handle
 * @ptrn_id: pattern id
 * @vdev_id: vdev id
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wow_delete_pattern_cmd(void *wmi_hdl, uint8_t ptrn_id,
					uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_wow_delete_pattern_cmd)
		return wmi_handle->ops->send_wow_delete_pattern_cmd(wmi_handle,
			    ptrn_id, vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_host_wakeup_ind_to_fw_cmd() - send wakeup ind to fw
 * @wmi_handle: wmi handle
 *
 * Sends host wakeup indication to FW. On receiving this indication,
 * FW will come out of WOW.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_host_wakeup_ind_to_fw_cmd(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_host_wakeup_ind_to_fw_cmd)
		return wmi_handle->ops->send_host_wakeup_ind_to_fw_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_del_ts_cmd() - send DELTS request to fw
 * @wmi_handle: wmi handle
 * @msg: delts params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_del_ts_cmd(void *wmi_hdl, uint8_t vdev_id,
				uint8_t ac)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_del_ts_cmd)
		return wmi_handle->ops->send_del_ts_cmd(wmi_handle,
			    vdev_id, ac);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_aggr_qos_cmd() - send aggr qos request to fw
 * @wmi_handle: handle to wmi
 * @aggr_qos_rsp_msg - combined struct for all ADD_TS requests.
 *
 * A function to handle WMI_AGGR_QOS_REQ. This will send out
 * ADD_TS requestes to firmware in loop for all the ACs with
 * active flow.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_aggr_qos_cmd(void *wmi_hdl,
		      struct aggr_add_ts_param *aggr_qos_rsp_msg)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_aggr_qos_cmd)
		return wmi_handle->ops->send_aggr_qos_cmd(wmi_handle,
			    aggr_qos_rsp_msg);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_add_ts_cmd() - send ADDTS request to fw
 * @wmi_handle: wmi handle
 * @msg: ADDTS params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_add_ts_cmd(void *wmi_hdl,
		 struct add_ts_param *msg)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_add_ts_cmd)
		return wmi_handle->ops->send_add_ts_cmd(wmi_handle,
			    msg);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_enable_disable_packet_filter_cmd() - enable/disable packet filter in target
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 * @enable: Flag to enable/disable packet filter
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_enable_disable_packet_filter_cmd(void *wmi_hdl,
					uint8_t vdev_id, bool enable)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_enable_disable_packet_filter_cmd)
		return wmi_handle->ops->send_enable_disable_packet_filter_cmd(
				wmi_handle, vdev_id, enable);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_config_packet_filter_cmd() - configure packet filter in target
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 * @rcv_filter_param: Packet filter parameters
 * @filter_id: Filter id
 * @enable: Flag to add/delete packet filter configuration
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_config_packet_filter_cmd(void *wmi_hdl,
		uint8_t vdev_id, struct rcv_pkt_filter_config *rcv_filter_param,
		uint8_t filter_id, bool enable)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_config_packet_filter_cmd)
		return wmi_handle->ops->send_config_packet_filter_cmd(wmi_handle,
			    vdev_id, rcv_filter_param,
				filter_id, enable);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_add_clear_mcbc_filter_cmd() - set mcast filter command to fw
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 * @multicastAddr: mcast address
 * @clearList: clear list flag
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_add_clear_mcbc_filter_cmd(void *wmi_hdl,
				     uint8_t vdev_id,
				     struct qdf_mac_addr multicast_addr,
				     bool clearList)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_add_clear_mcbc_filter_cmd)
		return wmi_handle->ops->send_add_clear_mcbc_filter_cmd(wmi_handle,
			    vdev_id, multicast_addr, clearList);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_send_gtk_offload_cmd() - send GTK offload command to fw
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 * @params: GTK offload parameters
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_send_gtk_offload_cmd(void *wmi_hdl, uint8_t vdev_id,
					   struct gtk_offload_params *params,
					   bool enable_offload,
					   uint32_t gtk_offload_opcode)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_gtk_offload_cmd)
		return wmi_handle->ops->send_gtk_offload_cmd(wmi_handle,
			    vdev_id, params,
				enable_offload, gtk_offload_opcode);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_gtk_offload_getinfo_cmd() - send GTK offload cmd to fw
 * @wmi_handle: wmi handle
 * @params: GTK offload params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_gtk_offload_getinfo_cmd(void *wmi_hdl,
				uint8_t vdev_id,
				uint64_t offload_req_opcode)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_gtk_offload_getinfo_cmd)
		return wmi_handle->ops->send_process_gtk_offload_getinfo_cmd(wmi_handle,
			    vdev_id,
				offload_req_opcode);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_add_periodic_tx_ptrn_cmd - add periodic tx ptrn
 * @wmi_handle: wmi handle
 * @pAddPeriodicTxPtrnParams: tx ptrn params
 *
 * Retrun: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_add_periodic_tx_ptrn_cmd(void *wmi_hdl,
						struct periodic_tx_pattern  *
						pAddPeriodicTxPtrnParams,
						uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_add_periodic_tx_ptrn_cmd)
		return wmi_handle->ops->send_process_add_periodic_tx_ptrn_cmd(wmi_handle,
			    pAddPeriodicTxPtrnParams,
				vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_del_periodic_tx_ptrn_cmd - del periodic tx ptrn
 * @wmi_handle: wmi handle
 * @vdev_id: vdev id
 * @pattern_id: pattern id
 *
 * Retrun: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_del_periodic_tx_ptrn_cmd(void *wmi_hdl,
						uint8_t vdev_id,
						uint8_t pattern_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_del_periodic_tx_ptrn_cmd)
		return wmi_handle->ops->send_process_del_periodic_tx_ptrn_cmd(wmi_handle,
			    vdev_id,
				pattern_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_stats_ext_req_cmd() - request ext stats from fw
 * @wmi_handle: wmi handle
 * @preq: stats ext params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_stats_ext_req_cmd(void *wmi_hdl,
			struct stats_ext_params *preq)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_stats_ext_req_cmd)
		return wmi_handle->ops->send_stats_ext_req_cmd(wmi_handle,
			    preq);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_enable_ext_wow_cmd() - enable ext wow in fw
 * @wmi_handle: wmi handle
 * @params: ext wow params
 *
 * Return:QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_enable_ext_wow_cmd(void *wmi_hdl,
			struct ext_wow_params *params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_enable_ext_wow_cmd)
		return wmi_handle->ops->send_enable_ext_wow_cmd(wmi_handle,
			    params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_app_type2_params_in_fw_cmd() - set app type2 params in fw
 * @wmi_handle: wmi handle
 * @appType2Params: app type2 params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_app_type2_params_in_fw_cmd(void *wmi_hdl,
					  struct app_type2_params *appType2Params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_app_type2_params_in_fw_cmd)
		return wmi_handle->ops->send_set_app_type2_params_in_fw_cmd(wmi_handle,
			     appType2Params);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_unified_set_auto_shutdown_timer_cmd() - sets auto shutdown timer in firmware
 * @wmi_handle: wmi handle
 * @timer_val: auto shutdown timer value
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_auto_shutdown_timer_cmd(void *wmi_hdl,
						  uint32_t timer_val)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_auto_shutdown_timer_cmd)
		return wmi_handle->ops->send_set_auto_shutdown_timer_cmd(wmi_handle,
			    timer_val);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_nan_req_cmd() - to send nan request to target
 * @wmi_handle: wmi handle
 * @nan_req: request data which will be non-null
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_nan_req_cmd(void *wmi_hdl,
			struct nan_req_params *nan_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_nan_req_cmd)
		return wmi_handle->ops->send_nan_req_cmd(wmi_handle,
			    nan_req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_dhcpserver_offload_cmd() - enable DHCP server offload
 * @wmi_handle: wmi handle
 * @pDhcpSrvOffloadInfo: DHCP server offload info
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_dhcpserver_offload_cmd(void *wmi_hdl,
				struct dhcp_offload_info_params *pDhcpSrvOffloadInfo)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_dhcpserver_offload_cmd)
		return wmi_handle->ops->send_process_dhcpserver_offload_cmd(wmi_handle,
			    pDhcpSrvOffloadInfo);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_ch_avoid_update_cmd() - handles channel avoid update request
 * @wmi_handle: wmi handle
 * @ch_avoid_update_req: channel avoid update params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_process_ch_avoid_update_cmd(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_ch_avoid_update_cmd)
		return wmi_handle->ops->send_process_ch_avoid_update_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_send_regdomain_info_to_fw_cmd() - send regdomain info to fw
 * @wmi_handle: wmi handle
 * @reg_dmn: reg domain
 * @regdmn2G: 2G reg domain
 * @regdmn5G: 5G reg domain
 * @ctl2G: 2G test limit
 * @ctl5G: 5G test limit
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_send_regdomain_info_to_fw_cmd(void *wmi_hdl,
				   uint32_t reg_dmn, uint16_t regdmn2G,
				   uint16_t regdmn5G, int8_t ctl2G,
				   int8_t ctl5G)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_regdomain_info_to_fw_cmd)
		return wmi_handle->ops->send_regdomain_info_to_fw_cmd(wmi_handle,
			    reg_dmn, regdmn2G,
				regdmn5G, ctl2G,
				ctl5G);

	return QDF_STATUS_E_FAILURE;
}


/**
 * wmi_unified_set_tdls_offchan_mode_cmd() - set tdls off channel mode
 * @wmi_handle: wmi handle
 * @chan_switch_params: Pointer to tdls channel switch parameter structure
 *
 * This function sets tdls off channel mode
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures;
 *         Negative errno otherwise
 */
QDF_STATUS wmi_unified_set_tdls_offchan_mode_cmd(void *wmi_hdl,
			      struct tdls_channel_switch_params *chan_switch_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_tdls_offchan_mode_cmd)
		return wmi_handle->ops->send_set_tdls_offchan_mode_cmd(wmi_handle,
			    chan_switch_params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_update_fw_tdls_state_cmd() - send enable/disable tdls for a vdev
 * @wmi_handle: wmi handle
 * @pwmaTdlsparams: TDLS params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_update_fw_tdls_state_cmd(void *wmi_hdl,
					 void *tdls_param, uint8_t tdls_state)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_update_fw_tdls_state_cmd)
		return wmi_handle->ops->send_update_fw_tdls_state_cmd(wmi_handle,
			    tdls_param, tdls_state);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_update_tdls_peer_state_cmd() - update TDLS peer state
 * @wmi_handle: wmi handle
 * @peerStateParams: TDLS peer state params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_update_tdls_peer_state_cmd(void *wmi_hdl,
			       struct tdls_peer_state_params *peerStateParams,
				   uint32_t *ch_mhz)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_update_tdls_peer_state_cmd)
		return wmi_handle->ops->send_update_tdls_peer_state_cmd(wmi_handle,
			    peerStateParams, ch_mhz);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_fw_mem_dump_cmd() - Function to request fw memory dump from
 * firmware
 * @wmi_handle:         Pointer to wmi handle
 * @mem_dump_req:       Pointer for mem_dump_req
 *
 * This function sends memory dump request to firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 *
 */
QDF_STATUS wmi_unified_process_fw_mem_dump_cmd(void *wmi_hdl,
					struct fw_dump_req_param *mem_dump_req)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_fw_mem_dump_cmd)
		return wmi_handle->ops->send_process_fw_mem_dump_cmd(wmi_handle,
			    mem_dump_req);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_process_set_ie_info_cmd() - Function to send IE info to firmware
 * @wmi_handle:    Pointer to WMi handle
 * @ie_data:       Pointer for ie data
 *
 * This function sends IE information to firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 *
 */
QDF_STATUS wmi_unified_process_set_ie_info_cmd(void *wmi_hdl,
				   struct vdev_ie_info_param *ie_info)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_set_ie_info_cmd)
		return wmi_handle->ops->send_process_set_ie_info_cmd(wmi_handle,
			    ie_info);

	return QDF_STATUS_E_FAILURE;
}
#ifdef CONFIG_MCL
/**
 * wmi_unified_send_init_cmd() - wmi init command
 * @wmi_handle:      pointer to wmi handle
 * @res_cfg:         resource config
 * @num_mem_chunks:  no of mem chunck
 * @mem_chunk:       pointer to mem chunck structure
 *
 * This function sends IE information to firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 *
 */
QDF_STATUS wmi_unified_send_init_cmd(void *wmi_hdl,
		wmi_resource_config *res_cfg,
		uint8_t num_mem_chunks, struct wmi_host_mem_chunk *mem_chunk,
		bool action)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_init_cmd)
		return wmi_handle->ops->send_init_cmd(wmi_handle,
			    res_cfg, num_mem_chunks, mem_chunk, action);

	return QDF_STATUS_E_FAILURE;
}
#endif
/**
 * wmi_unified_send_saved_init_cmd() - wmi init command
 * @wmi_handle:      pointer to wmi handle
 *
 * This function sends IE information to firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 *
 */
QDF_STATUS wmi_unified_send_saved_init_cmd(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_saved_init_cmd)
		return wmi_handle->ops->send_saved_init_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_save_fw_version_cmd() - save fw version
 * @wmi_handle:      pointer to wmi handle
 * @res_cfg:         resource config
 * @num_mem_chunks:  no of mem chunck
 * @mem_chunk:       pointer to mem chunck structure
 *
 * This function sends IE information to firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 *
 */
QDF_STATUS wmi_unified_save_fw_version_cmd(void *wmi_hdl,
		void *evt_buf)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->save_fw_version_cmd)
		return wmi_handle->ops->save_fw_version_cmd(wmi_handle,
			    evt_buf);

	return QDF_STATUS_E_FAILURE;
}

/**
 * send_set_base_macaddr_indicate_cmd() - set base mac address in fw
 * @wmi_hdl: wmi handle
 * @custom_addr: base mac address
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_base_macaddr_indicate_cmd(void *wmi_hdl,
					 uint8_t *custom_addr)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_base_macaddr_indicate_cmd)
		return wmi_handle->ops->send_set_base_macaddr_indicate_cmd(wmi_handle,
			    custom_addr);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_log_supported_evt_cmd() - Enable/Disable FW diag/log events
 * @wmi_hdl: wmi handle
 * @event:  Event received from FW
 * @len:    Length of the event
 *
 * Enables the low frequency events and disables the high frequency
 * events. Bit 17 indicates if the event if low/high frequency.
 * 1 - high frequency, 0 - low frequency
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures
 */
QDF_STATUS wmi_unified_log_supported_evt_cmd(void *wmi_hdl,
		uint8_t *event,
		uint32_t len)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_log_supported_evt_cmd)
		return wmi_handle->ops->send_log_supported_evt_cmd(wmi_handle,
			    event, len);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_enable_specific_fw_logs_cmd() - Start/Stop logging of diag log id
 * @wmi_hdl: wmi handle
 * @start_log: Start logging related parameters
 *
 * Send the command to the FW based on which specific logging of diag
 * event/log id can be started/stopped
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_enable_specific_fw_logs_cmd(void *wmi_hdl,
		struct wmi_wifi_start_log *start_log)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_enable_specific_fw_logs_cmd)
		return wmi_handle->ops->send_enable_specific_fw_logs_cmd(wmi_handle,
			    start_log);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_flush_logs_to_fw_cmd() - Send log flush command to FW
 * @wmi_hdl: WMI handle
 *
 * This function is used to send the flush command to the FW,
 * that will flush the fw logs that are residue in the FW
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_flush_logs_to_fw_cmd(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_flush_logs_to_fw_cmd)
		return wmi_handle->ops->send_flush_logs_to_fw_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_pdev_set_pcl_cmd() - Send WMI_SOC_SET_PCL_CMDID to FW
 * @wmi_hdl: wmi handle
 * @msg: PCL structure containing the PCL and the number of channels
 *
 * WMI_SOC_SET_PCL_CMDID provides a Preferred Channel List (PCL) to the WLAN
 * firmware. The DBS Manager is the consumer of this information in the WLAN
 * firmware. The channel list will be used when a Virtual DEVice (VDEV) needs
 * to migrate to a new channel without host driver involvement. An example of
 * this behavior is Legacy Fast Roaming (LFR 3.0). Generally, the host will
 * manage the channel selection without firmware involvement.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pdev_set_pcl_cmd(void *wmi_hdl,
				struct wmi_pcl_chan_weights *msg)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_set_pcl_cmd)
		return wmi_handle->ops->send_pdev_set_pcl_cmd(wmi_handle, msg);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_soc_set_hw_mode_cmd() - Send WMI_SOC_SET_HW_MODE_CMDID to FW
 * @wmi_hdl: wmi handle
 * @msg: Structure containing the following parameters
 *
 * - hw_mode_index: The HW_Mode field is a enumerated type that is selected
 * from the HW_Mode table, which is returned in the WMI_SERVICE_READY_EVENTID.
 *
 * Provides notification to the WLAN firmware that host driver is requesting a
 * HardWare (HW) Mode change. This command is needed to support iHelium in the
 * configurations that include the Dual Band Simultaneous (DBS) feature.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_soc_set_hw_mode_cmd(void *wmi_hdl,
				uint32_t hw_mode_index)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_set_hw_mode_cmd)
		return wmi_handle->ops->send_pdev_set_hw_mode_cmd(wmi_handle,
				  hw_mode_index);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_pdev_set_dual_mac_config_cmd() - Set dual mac config to FW
 * @wmi_hdl: wmi handle
 * @msg: Dual MAC config parameters
 *
 * Configures WLAN firmware with the dual MAC features
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failures.
 */
QDF_STATUS wmi_unified_pdev_set_dual_mac_config_cmd(void *wmi_hdl,
		struct wmi_dual_mac_config *msg)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_set_dual_mac_config_cmd)
		return wmi_handle->ops->send_pdev_set_dual_mac_config_cmd(wmi_handle,
				  msg);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_enable_arp_ns_offload_cmd() - enable ARP NS offload
 * @wmi_hdl: wmi handle
 * @param: offload request
 * @arp_only: flag
 *
 * To configure ARP NS off load data to firmware
 * when target goes to wow mode.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_enable_arp_ns_offload_cmd(void *wmi_hdl,
			   struct host_offload_req_param *arp_offload_req,
			   struct host_offload_req_param *ns_offload_req,
			   bool arp_only,
			   uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_enable_arp_ns_offload_cmd)
		return wmi_handle->ops->send_enable_arp_ns_offload_cmd(wmi_handle,
				  arp_offload_req, ns_offload_req, arp_only,
				  vdev_id);

	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wmi_unified_conf_hw_filter_mode_cmd(void *wmi_hdl,
					       uint8_t vdev_id,
					       uint8_t mode_bitmap)
{
	wmi_unified_t wmi = wmi_hdl;

	if (!wmi->ops->send_conf_hw_filter_mode_cmd)
		return QDF_STATUS_E_FAILURE;

	return wmi->ops->send_conf_hw_filter_mode_cmd(wmi, vdev_id,
						      mode_bitmap);
}

/**
 * wmi_unified_set_led_flashing_cmd() - set led flashing in fw
 * @wmi_hdl: wmi handle
 * @flashing: flashing request
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_led_flashing_cmd(void *wmi_hdl,
				struct flashing_req_params *flashing)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_led_flashing_cmd)
		return wmi_handle->ops->send_set_led_flashing_cmd(wmi_handle,
				  flashing);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_app_type1_params_in_fw_cmd() - set app type1 params in fw
 * @wmi_hdl: wmi handle
 * @appType1Params: app type1 params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_app_type1_params_in_fw_cmd(void *wmi_hdl,
				   struct app_type1_params *app_type1_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_app_type1_params_in_fw_cmd)
		return wmi_handle->ops->send_app_type1_params_in_fw_cmd(wmi_handle,
				  app_type1_params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_set_ssid_hotlist_cmd() - Handle an SSID hotlist set request
 * @wmi_hdl: wmi handle
 * @request: SSID hotlist set request
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS
wmi_unified_set_ssid_hotlist_cmd(void *wmi_hdl,
		     struct ssid_hotlist_request_params *request)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ssid_hotlist_cmd)
		return wmi_handle->ops->send_set_ssid_hotlist_cmd(wmi_handle,
				  request);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_roam_synch_complete_cmd() - roam synch complete command to fw.
 * @wmi_hdl: wmi handle
 * @vdev_id: vdev id
 *
 * This function sends roam synch complete event to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_synch_complete_cmd(void *wmi_hdl,
		 uint8_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_process_roam_synch_complete_cmd)
		return wmi_handle->ops->send_process_roam_synch_complete_cmd(wmi_handle,
				  vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_fw_test_cmd() - send fw test command to fw.
 * @wmi_hdl: wmi handle
 * @wmi_fwtest: fw test command
 *
 * This function sends fw test command to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_fw_test_cmd(void *wmi_hdl,
				   struct set_fwtest_params *wmi_fwtest)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_fw_test_cmd)
		return wmi_handle->ops->send_fw_test_cmd(wmi_handle,
				  wmi_fwtest);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_unified_unit_test_cmd() - send unit test command to fw.
 * @wmi_hdl: wmi handle
 * @wmi_utest: unit test command
 *
 * This function send unit test command to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_unit_test_cmd(void *wmi_hdl,
			       struct wmi_unit_test_cmd *wmi_utest)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_unit_test_cmd)
		return wmi_handle->ops->send_unit_test_cmd(wmi_handle,
				  wmi_utest);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified__roam_invoke_cmd() - send roam invoke command to fw.
 * @wmi_hdl: wmi handle
 * @roaminvoke: roam invoke command
 *
 * Send roam invoke command to fw for fastreassoc.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_invoke_cmd(void *wmi_hdl,
		struct wmi_roam_invoke_cmd *roaminvoke,
		uint32_t ch_hz)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_invoke_cmd)
		return wmi_handle->ops->send_roam_invoke_cmd(wmi_handle,
				  roaminvoke, ch_hz);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_roam_scan_offload_cmd() - set roam offload command
 * @wmi_hdl: wmi handle
 * @command: command
 * @vdev_id: vdev id
 *
 * This function set roam offload command to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_scan_offload_cmd(void *wmi_hdl,
					 uint32_t command, uint32_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_offload_cmd)
		return wmi_handle->ops->send_roam_scan_offload_cmd(wmi_handle,
				  command, vdev_id);

	return QDF_STATUS_E_FAILURE;
}
#ifndef WMI_NON_TLV_SUPPORT
/**
 * wmi_unified_send_roam_scan_offload_ap_cmd() - set roam ap profile in fw
 * @wmi_hdl: wmi handle
 * @ap_profile_p: ap profile
 * @vdev_id: vdev id
 *
 * Send WMI_ROAM_AP_PROFILE to firmware
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_send_roam_scan_offload_ap_cmd(void *wmi_hdl,
					    wmi_ap_profile *ap_profile_p,
					    uint32_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_offload_ap_profile_cmd)
		return wmi_handle->ops->send_roam_scan_offload_ap_profile_cmd(wmi_handle,
				  ap_profile_p, vdev_id);

	return QDF_STATUS_E_FAILURE;
}
#endif
/**
 * wmi_unified_roam_scan_offload_scan_period() - set roam offload scan period
 * @wmi_handle: wmi handle
 * @scan_period: scan period
 * @scan_age: scan age
 * @vdev_id: vdev id
 *
 * Send WMI_ROAM_SCAN_PERIOD parameters to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_scan_offload_scan_period(void *wmi_hdl,
					     uint32_t scan_period,
					     uint32_t scan_age,
					     uint32_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_offload_scan_period_cmd)
		return wmi_handle->ops->send_roam_scan_offload_scan_period_cmd(wmi_handle,
				  scan_period, scan_age, vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_roam_scan_offload_chan_list_cmd() - set roam offload channel list
 * @wmi_handle: wmi handle
 * @chan_count: channel count
 * @chan_list: channel list
 * @list_type: list type
 * @vdev_id: vdev id
 *
 * Set roam offload channel list.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_scan_offload_chan_list_cmd(void *wmi_hdl,
				   uint8_t chan_count,
				   uint32_t *chan_list,
				   uint8_t list_type, uint32_t vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_offload_chan_list_cmd)
		return wmi_handle->ops->send_roam_scan_offload_chan_list_cmd(wmi_handle,
				  chan_count, chan_list,
				  list_type, vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_roam_scan_offload_rssi_change_cmd() - set roam offload RSSI th
 * @wmi_hdl: wmi handle
 * @rssi_change_thresh: RSSI Change threshold
 * @bcn_rssi_weight: beacon RSSI weight
 * @vdev_id: vdev id
 *
 * Send WMI_ROAM_SCAN_RSSI_CHANGE_THRESHOLD parameters to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_roam_scan_offload_rssi_change_cmd(void *wmi_hdl,
	uint32_t vdev_id,
	int32_t rssi_change_thresh,
	uint32_t bcn_rssi_weight,
	uint32_t hirssi_delay_btw_scans)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_roam_scan_offload_rssi_change_cmd)
		return wmi_handle->ops->send_roam_scan_offload_rssi_change_cmd(wmi_handle,
				  vdev_id, rssi_change_thresh,
				  bcn_rssi_weight, hirssi_delay_btw_scans);

	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wmi_unified_set_per_roam_config(void *wmi_hdl,
		struct wmi_per_roam_config_req *req_buf)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_per_roam_config_cmd)
		return wmi_handle->ops->send_per_roam_config_cmd(wmi_handle,
					req_buf);

	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wmi_unified_set_arp_stats_req(void *wmi_hdl,
					 struct set_arp_stats *req_buf)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_arp_stats_req_cmd)
		return wmi_handle->ops->send_set_arp_stats_req_cmd(wmi_handle,
								   req_buf);

	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wmi_unified_get_arp_stats_req(void *wmi_hdl,
					 struct get_arp_stats *req_buf)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_get_arp_stats_req_cmd)
		return wmi_handle->ops->send_get_arp_stats_req_cmd(wmi_handle,
								   req_buf);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_get_buf_extscan_hotlist_cmd() - prepare hotlist command
 * @wmi_hdl: wmi handle
 * @photlist: hotlist command params
 * @buf_len: buffer length
 *
 * This function fills individual elements for  hotlist request and
 * TLV for bssid entries
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure.
 */
QDF_STATUS wmi_unified_get_buf_extscan_hotlist_cmd(void *wmi_hdl,
				   struct ext_scan_setbssi_hotlist_params *
				   photlist, int *buf_len)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_get_buf_extscan_hotlist_cmd)
		return wmi_handle->ops->send_get_buf_extscan_hotlist_cmd(wmi_handle,
				  photlist, buf_len);

	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS
wmi_unified_set_active_bpf_mode_cmd(void *wmi_hdl,
				    uint8_t vdev_id,
				    FW_ACTIVE_BPF_MODE ucast_mode,
				    FW_ACTIVE_BPF_MODE mcast_bcast_mode)
{
	wmi_unified_t wmi = (wmi_unified_t)wmi_hdl;

	if (!wmi->ops->send_set_active_bpf_mode_cmd) {
		WMI_LOGI("send_set_active_bpf_mode_cmd op is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	return wmi->ops->send_set_active_bpf_mode_cmd(wmi, vdev_id,
						      ucast_mode,
						      mcast_bcast_mode);
}

/**
 *  wmi_unified_pdev_get_tpc_config_cmd_send() - WMI get tpc config function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : tpc config param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pdev_get_tpc_config_cmd_send(void *wmi_hdl,
				uint32_t param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_get_tpc_config_cmd)
		return wmi_handle->ops->send_pdev_get_tpc_config_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_bwf_cmd_send() - WMI set bwf function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to set bwf param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_bwf_cmd_send(void *wmi_hdl,
				struct set_bwf_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_bwf_cmd)
		return wmi_handle->ops->send_set_bwf_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_atf_cmd_send() - WMI set atf function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to set atf param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_atf_cmd_send(void *wmi_hdl,
				struct set_atf_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_atf_cmd)
		return wmi_handle->ops->send_set_atf_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_pdev_fips_cmd_send() - WMI pdev fips cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold pdev fips param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pdev_fips_cmd_send(void *wmi_hdl,
				struct fips_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_fips_cmd)
		return wmi_handle->ops->send_pdev_fips_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wlan_profile_enable_cmd_send() - WMI wlan profile enable cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold wlan profile param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wlan_profile_enable_cmd_send(void *wmi_hdl,
				struct wlan_profile_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_wlan_profile_enable_cmd)
		return wmi_handle->ops->send_wlan_profile_enable_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wlan_profile_trigger_cmd_send() - WMI wlan profile trigger cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold wlan profile param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wlan_profile_trigger_cmd_send(void *wmi_hdl,
				struct wlan_profile_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_wlan_profile_trigger_cmd)
		return wmi->ops->send_wlan_profile_trigger_cmd(wmi,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_chan_cmd_send() - WMI set channel cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold channel param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_chan_cmd_send(void *wmi_hdl,
				struct channel_param *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_set_chan_cmd)
		return wmi_handle->ops->send_pdev_set_chan_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_ht_ie_cmd_send() - WMI set channel cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold channel param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_ht_ie_cmd_send(void *wmi_hdl,
				struct ht_ie_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ht_ie_cmd)
		return wmi_handle->ops->send_set_ht_ie_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_vht_ie_cmd_send() - WMI set channel cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold channel param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_vht_ie_cmd_send(void *wmi_hdl,
				struct vht_ie_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_vht_ie_cmd)
		return wmi_handle->ops->send_set_vht_ie_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_wmm_update_cmd_send() - WMI wmm update cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold wmm param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_wmm_update_cmd_send(void *wmi_hdl,
				struct wmm_update_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_wmm_update_cmd)
		return wmi_handle->ops->send_wmm_update_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_ant_switch_tbl_cmd_send() - WMI ant switch tbl cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold ant switch tbl param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_ant_switch_tbl_cmd_send(void *wmi_hdl,
				struct ant_switch_tbl_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ant_switch_tbl_cmd)
		return wmi_handle->ops->send_set_ant_switch_tbl_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_ratepwr_table_cmd_send() - WMI ratepwr table cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold ratepwr table param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_ratepwr_table_cmd_send(void *wmi_hdl,
				struct ratepwr_table_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ratepwr_table_cmd)
		return wmi_handle->ops->send_set_ratepwr_table_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_get_ratepwr_table_cmd_send() - WMI ratepwr table cmd function
 *  @param wmi_handle      : handle to WMI.
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_get_ratepwr_table_cmd_send(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_get_ratepwr_table_cmd)
		return wmi_handle->ops->send_get_ratepwr_table_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_ctl_table_cmd_send() - WMI ctl table cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold ctl table param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_ctl_table_cmd_send(void *wmi_hdl,
				struct ctl_table_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ctl_table_cmd)
		return wmi_handle->ops->send_set_ctl_table_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_mimogain_table_cmd_send() - WMI set mimogain cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold mimogain param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_mimogain_table_cmd_send(void *wmi_hdl,
				struct mimogain_table_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_mimogain_table_cmd)
		return wmi_handle->ops->send_set_mimogain_table_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_ratepwr_chainmsk_cmd_send() - WMI ratepwr
 *  chainmsk cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold ratepwr chainmsk param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_ratepwr_chainmsk_cmd_send(void *wmi_hdl,
				struct ratepwr_chainmsk_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_set_ratepwr_chainmsk_cmd)
		return wmi->ops->send_set_ratepwr_chainmsk_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_macaddr_cmd_send() - WMI set macaddr cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold macaddr param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_macaddr_cmd_send(void *wmi_hdl,
				struct macaddr_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_macaddr_cmd)
		return wmi_handle->ops->send_set_macaddr_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_pdev_scan_start_cmd_send() - WMI pdev scan start cmd function
 *  @param wmi_handle      : handle to WMI.
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pdev_scan_start_cmd_send(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_scan_start_cmd)
		return wmi_handle->ops->send_pdev_scan_start_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_pdev_scan_end_cmd_send() - WMI pdev scan end cmd function
 *  @param wmi_handle      : handle to WMI.
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pdev_scan_end_cmd_send(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_scan_end_cmd)
		return wmi_handle->ops->send_pdev_scan_end_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_acparams_cmd_send() - WMI set acparams cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold acparams param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_acparams_cmd_send(void *wmi_hdl,
				struct acparams_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_acparams_cmd)
		return wmi_handle->ops->send_set_acparams_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_vap_dscp_tid_map_cmd_send() - WMI set vap dscp
 *  tid map cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold dscp param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_vap_dscp_tid_map_cmd_send(void *wmi_hdl,
				struct vap_dscp_tid_map_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_set_vap_dscp_tid_map_cmd)
		return wmi->ops->send_set_vap_dscp_tid_map_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_proxy_ast_reserve_cmd_send() - WMI proxy ast
 *  reserve cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold ast param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_proxy_ast_reserve_cmd_send(void *wmi_hdl,
				struct proxy_ast_reserve_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_proxy_ast_reserve_cmd)
		return wmi_handle->ops->send_proxy_ast_reserve_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_pdev_qvit_cmd_send() - WMI pdev qvit cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold qvit param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pdev_qvit_cmd_send(void *wmi_hdl,
				struct pdev_qvit_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_qvit_cmd)
		return wmi_handle->ops->send_pdev_qvit_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_mcast_group_update_cmd_send() - WMI mcast grp update cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold mcast grp param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_mcast_group_update_cmd_send(void *wmi_hdl,
				struct mcast_group_update_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_mcast_group_update_cmd)
		return wmi_handle->ops->send_mcast_group_update_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_peer_add_wds_entry_cmd_send() - WMI add wds entry cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold wds entry param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_peer_add_wds_entry_cmd_send(void *wmi_hdl,
				struct peer_add_wds_entry_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_add_wds_entry_cmd)
		return wmi_handle->ops->send_peer_add_wds_entry_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_peer_del_wds_entry_cmd_send() - WMI del wds entry cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold wds entry param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_peer_del_wds_entry_cmd_send(void *wmi_hdl,
				struct peer_del_wds_entry_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_peer_del_wds_entry_cmd)
		return wmi_handle->ops->send_peer_del_wds_entry_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_peer_update_wds_entry_cmd_send() - WMI update wds entry cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold wds entry param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_peer_update_wds_entry_cmd_send(void *wmi_hdl,
				struct peer_update_wds_entry_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_peer_update_wds_entry_cmd)
		return wmi->ops->send_peer_update_wds_entry_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_phyerr_enable_cmd_send() - WMI phyerr enable cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold phyerr enable param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_phyerr_enable_cmd_send(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_phyerr_enable_cmd)
		return wmi_handle->ops->send_phyerr_enable_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_phyerr_disable_cmd_send() - WMI phyerr disable cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold phyerr disable param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_phyerr_disable_cmd_send(void *wmi_hdl)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_phyerr_disable_cmd)
		return wmi_handle->ops->send_phyerr_disable_cmd(wmi_handle);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_smart_ant_enable_cmd_send() - WMI smart ant enable function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold antenna param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_smart_ant_enable_cmd_send(void *wmi_hdl,
				struct smart_ant_enable_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_smart_ant_enable_cmd)
		return wmi_handle->ops->send_smart_ant_enable_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_smart_ant_set_rx_ant_cmd_send() - WMI set rx antenna function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold antenna param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_smart_ant_set_rx_ant_cmd_send(void *wmi_hdl,
				struct smart_ant_rx_ant_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_smart_ant_set_rx_ant_cmd)
		return wmi->ops->send_smart_ant_set_rx_ant_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_smart_ant_set_tx_ant_cmd_send() - WMI set tx antenna function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold antenna param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_smart_ant_set_tx_ant_cmd_send(void *wmi_hdl,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct smart_ant_tx_ant_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_smart_ant_set_tx_ant_cmd)
		return wmi->ops->send_smart_ant_set_tx_ant_cmd(wmi, macaddr,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_smart_ant_set_training_info_cmd_send() - WMI set tx antenna function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold antenna param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_smart_ant_set_training_info_cmd_send(void *wmi_hdl,
		uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct smart_ant_training_info_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_smart_ant_set_training_info_cmd)
		return wmi->ops->send_smart_ant_set_training_info_cmd(wmi,
				macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_smart_ant_node_config_cmd_send() - WMI set node config function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold node parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_smart_ant_node_config_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct smart_ant_node_config_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_smart_ant_set_node_config_cmd)
		return wmi->ops->send_smart_ant_set_node_config_cmd(wmi,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_smart_ant_enable_tx_feedback_cmd_send() - WMI set tx antenna function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold antenna param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_smart_ant_enable_tx_feedback_cmd_send(void *wmi_hdl,
			struct smart_ant_enable_tx_feedback_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_smart_ant_enable_tx_feedback_cmd)
		return wmi->ops->send_smart_ant_enable_tx_feedback_cmd(wmi,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_vdev_spectral_configure_cmd_send() - WMI set spectral config function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold spectral config param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_spectral_configure_cmd_send(void *wmi_hdl,
				struct vdev_spectral_configure_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_vdev_spectral_configure_cmd)
		return wmi->ops->send_vdev_spectral_configure_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_vdev_spectral_enable_cmd_send() - WMI enable spectral function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold enable spectral param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_spectral_enable_cmd_send(void *wmi_hdl,
				struct vdev_spectral_enable_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_vdev_spectral_enable_cmd)
		return wmi->ops->send_vdev_spectral_enable_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_bss_chan_info_request_cmd_send() - WMI bss chan info request function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold chan info param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_bss_chan_info_request_cmd_send(void *wmi_hdl,
				struct bss_chan_info_request_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_bss_chan_info_request_cmd)
		return wmi->ops->send_bss_chan_info_request_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_thermal_mitigation_param_cmd_send() - WMI thermal mitigation function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold thermal mitigation param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_thermal_mitigation_param_cmd_send(void *wmi_hdl,
				struct thermal_mitigation_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_thermal_mitigation_param_cmd)
		return wmi->ops->send_thermal_mitigation_param_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_vdev_set_neighbour_rx_cmd_send() - WMI set neighbour rx function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold neighbour rx parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_set_neighbour_rx_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct set_neighbour_rx_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_vdev_set_neighbour_rx_cmd)
		return wmi->ops->send_vdev_set_neighbour_rx_cmd(wmi,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_vdev_set_fwtest_param_cmd_send() - WMI set fwtest function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold fwtest param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_set_fwtest_param_cmd_send(void *wmi_hdl,
				struct set_fwtest_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_vdev_set_fwtest_param_cmd)
		return wmi->ops->send_vdev_set_fwtest_param_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_vdev_config_ratemask_cmd_send() - WMI config ratemask function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold config ratemask param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_config_ratemask_cmd_send(void *wmi_hdl,
				struct config_ratemask_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_vdev_config_ratemask_cmd)
		return wmi->ops->send_vdev_config_ratemask_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_vdev_install_key_cmd_send() - WMI install key function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold key parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_vdev_install_key_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct vdev_install_key_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_vdev_install_key_cmd)
		return wmi_handle->ops->send_vdev_install_key_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_pdev_set_regdomain_params_cmd_send() - WMI set regdomain function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold regdomain param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_pdev_set_regdomain_cmd_send(void *wmi_hdl,
				struct pdev_set_regdomain_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_pdev_set_regdomain_cmd)
		return wmi_handle->ops->send_pdev_set_regdomain_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_quiet_mode_cmd_send() - WMI set quiet mode function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold quiet mode param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_quiet_mode_cmd_send(void *wmi_hdl,
				struct set_quiet_mode_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_quiet_mode_cmd)
		return wmi_handle->ops->send_set_quiet_mode_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_beacon_filter_cmd_send() - WMI set beacon filter function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold beacon filter param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_beacon_filter_cmd_send(void *wmi_hdl,
				struct set_beacon_filter_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_beacon_filter_cmd)
		return wmi_handle->ops->send_set_beacon_filter_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_remove_beacon_filter_cmd_send() - WMI set beacon filter function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold beacon filter param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_remove_beacon_filter_cmd_send(void *wmi_hdl,
				struct remove_beacon_filter_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_remove_beacon_filter_cmd)
		return wmi->ops->send_remove_beacon_filter_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_mgmt_cmd_send() - WMI mgmt cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold mgmt parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
#if 0
QDF_STATUS wmi_unified_mgmt_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct mgmt_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_mgmt_cmd)
		return wmi_handle->ops->send_mgmt_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}
#endif

/**
 *  wmi_unified_addba_clearresponse_cmd_send() - WMI addba resp cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold addba resp parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_addba_clearresponse_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct addba_clearresponse_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_addba_clearresponse_cmd)
		return wmi_handle->ops->send_addba_clearresponse_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_addba_send_cmd_send() - WMI addba send function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold addba parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_addba_send_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct addba_send_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_addba_send_cmd)
		return wmi_handle->ops->send_addba_send_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_delba_send_cmd_send() - WMI delba cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold delba parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_delba_send_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct delba_send_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_delba_send_cmd)
		return wmi_handle->ops->send_delba_send_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_addba_setresponse_cmd_send() - WMI addba set resp cmd function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold addba set resp parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_addba_setresponse_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct addba_setresponse_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_addba_setresponse_cmd)
		return wmi_handle->ops->send_addba_setresponse_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_singleamsdu_cmd_send() - WMI singleamsdu function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold singleamsdu parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_singleamsdu_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct singleamsdu_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_singleamsdu_cmd)
		return wmi_handle->ops->send_singleamsdu_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_qboost_param_cmd_send() - WMI set_qboost function
 *  @param wmi_handle      : handle to WMI.
 *  @param macaddr        : MAC address
 *  @param param    : pointer to hold set_qboost parameter
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_qboost_param_cmd_send(void *wmi_hdl,
				uint8_t macaddr[IEEE80211_ADDR_LEN],
				struct set_qboost_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_qboost_param_cmd)
		return wmi_handle->ops->send_set_qboost_param_cmd(wmi_handle,
				  macaddr, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_mu_scan_cmd_send() - WMI set mu scan function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold mu scan param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_mu_scan_cmd_send(void *wmi_hdl,
				struct mu_scan_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_mu_scan_cmd)
		return wmi_handle->ops->send_mu_scan_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_lteu_config_cmd_send() - WMI set mu scan function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold mu scan param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lteu_config_cmd_send(void *wmi_hdl,
				struct lteu_config_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lteu_config_cmd)
		return wmi_handle->ops->send_lteu_config_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_set_psmode_cmd_send() - WMI set mu scan function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold mu scan param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_set_psmode_cmd_send(void *wmi_hdl,
				struct set_ps_mode_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_ps_mode_cmd)
		return wmi_handle->ops->send_set_ps_mode_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_init_cmd_send() - send initialization cmd to fw
 * @wmi_handle: wmi handle
 * @param tgt_res_cfg: pointer to target resource configuration
 * @param num_mem_chunks: Number of memory chunks
 * @param mem_chunks: pointer to target memory chunks
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_init_cmd_send(void *wmi_hdl,
		target_resource_config *res_cfg, uint8_t num_mem_chunks,
		struct wmi_host_mem_chunk *mem_chunk)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->init_cmd_send)
		return wmi_handle->ops->init_cmd_send(wmi_handle, res_cfg,
				num_mem_chunks,	mem_chunk);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_save_service_bitmap() - save service bitmap
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_save_service_bitmap(void *wmi_hdl, void *evt_buf)
{
	struct wmi_unified *wmi_handle = (struct wmi_unified *) wmi_hdl;

	if (wmi_handle->ops->save_service_bitmap) {
		wmi_handle->ops->save_service_bitmap(wmi_handle, evt_buf);
		return 0;
	}
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_save_fw_version() - Save fw version
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_save_fw_version(void *wmi_hdl, void *evt_buf)
{
	struct wmi_unified *wmi_handle = (struct wmi_unified *) wmi_hdl;

	if (wmi_handle->ops->save_fw_version) {
		wmi_handle->ops->save_fw_version(wmi_handle, evt_buf);
		return 0;
	}
	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_check_and_update_fw_version() - Ready and fw version check
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_check_and_update_fw_version(void *wmi_hdl, void *evt_buf)
{
	struct wmi_unified *wmi_handle = (struct wmi_unified *) wmi_hdl;

	if (wmi_handle->ops->check_and_update_fw_version)
		return wmi_handle->ops->check_and_update_fw_version(wmi_handle,
				evt_buf);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_service_enabled() - Check if service enabled
 * @param wmi_handle: wmi handle
 * @param service_id: service identifier
 *
 * Return: 1 enabled, 0 disabled
 */
#ifdef WMI_NON_TLV_SUPPORT
bool wmi_service_enabled(void *wmi_hdl, uint32_t service_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if ((service_id < wmi_services_max) &&
		(wmi_handle->services[service_id] != WMI_SERVICE_UNAVAILABLE)) {
		if (wmi_handle->ops->is_service_enabled) {
			return wmi_handle->ops->is_service_enabled(wmi_handle,
				wmi_handle->services[service_id]);
		}
	} else {
		qdf_print("Support not added yet for Service %d\n", service_id);
	}
	return false;
}
#endif

/**
 * wmi_get_target_cap_from_service_ready() - extract service ready event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to received event buffer
 * @param ev: pointer to hold target capability information extracted from even
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_get_target_cap_from_service_ready(void *wmi_hdl,
	void *evt_buf, target_capability_info *ev)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->get_target_cap_from_service_ready)
		return wmi->ops->get_target_cap_from_service_ready(wmi,
				evt_buf, ev);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_fw_version() - extract fw version
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param fw_ver: Pointer to hold fw version
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_fw_version(void *wmi_hdl,
				void *evt_buf, struct wmi_host_fw_ver *fw_ver)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_fw_version)
		return wmi_handle->ops->extract_fw_version(wmi_handle,
				evt_buf, fw_ver);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_fw_abi_version() - extract fw abi version
 * @wmi_handle: wmi handle
 * @param evt_buf: Pointer to event buffer
 * @param fw_ver: Pointer to hold fw abi version
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_fw_abi_version(void *wmi_hdl,
			void *evt_buf, struct wmi_host_fw_abi_ver *fw_ver)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_fw_abi_version)
		return wmi_handle->ops->extract_fw_abi_version(wmi_handle,
		evt_buf, fw_ver);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_hal_reg_cap() - extract HAL registered capabilities
 * @wmi_handle: wmi handle
 * @param evt_buf: Pointer to event buffer
 * @param hal_reg_cap: pointer to hold HAL reg capabilities
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_hal_reg_cap(void *wmi_hdl, void *evt_buf,
	TARGET_HAL_REG_CAPABILITIES *hal_reg_cap)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_hal_reg_cap)
		return wmi_handle->ops->extract_hal_reg_cap(wmi_handle,
			evt_buf, hal_reg_cap);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_host_mem_req_from_service_ready() - Extract host memory
 *                                                 request event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param num_entries: pointer to hold number of entries requested
 *
 * Return: Number of entries requested
 */
host_mem_req *wmi_extract_host_mem_req_from_service_ready(void *wmi_hdl,
	void *evt_buf, uint8_t *num_entries)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_host_mem_req)
		return wmi_handle->ops->extract_host_mem_req(wmi_handle,
			evt_buf, num_entries);

	*num_entries = 0;
	return NULL;
}

/**
 * wmi_ready_extract_init_status() - Extract init status from ready event
 * @wmi_handle: wmi handle
 * @param ev: Pointer to event buffer
 *
 * Return: ready status
 */
uint32_t wmi_ready_extract_init_status(void *wmi_hdl, void *ev)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->ready_extract_init_status)
		return wmi_handle->ops->ready_extract_init_status(wmi_handle,
			ev);


	return 1;

}

/**
 * wmi_ready_extract_mac_addr() - extract mac address from ready event
 * @wmi_handle: wmi handle
 * @param ev: pointer to event buffer
 * @param macaddr: Pointer to hold MAC address
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_ready_extract_mac_addr(void *wmi_hdl, void *ev, uint8_t *macaddr)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->ready_extract_mac_addr)
		return wmi_handle->ops->ready_extract_mac_addr(wmi_handle,
			ev, macaddr);


	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_dbglog_data_len() - extract debuglog data length
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param len:  length of buffer
 *
 * Return: length
 */
uint8_t *wmi_extract_dbglog_data_len(void *wmi_hdl, void *evt_buf,
			uint16_t *len)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_dbglog_data_len)
		return wmi_handle->ops->extract_dbglog_data_len(wmi_handle,
			evt_buf, len);


	return NULL;
}

/**
 * wmi_send_ext_resource_config() - send extended resource configuration
 * @wmi_handle: wmi handle
 * @param ext_cfg: pointer to extended resource configuration
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_send_ext_resource_config(void *wmi_hdl,
			wmi_host_ext_resource_config *ext_cfg)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_ext_resource_config)
		return wmi_handle->ops->send_ext_resource_config(wmi_handle,
				ext_cfg);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_nf_dbr_dbm_info_get_cmd_send() - WMI request nf info function
 *  @param wmi_handle	  : handle to WMI.
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_nf_dbr_dbm_info_get_cmd_send(void *wmi_hdl)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_nf_dbr_dbm_info_get_cmd)
		return wmi->ops->send_nf_dbr_dbm_info_get_cmd(wmi);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_packet_power_info_get_cmd_send() - WMI get packet power info function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold packet power info param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_packet_power_info_get_cmd_send(void *wmi_hdl,
				struct packet_power_info_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_packet_power_info_get_cmd)
		return wmi->ops->send_packet_power_info_get_cmd(wmi, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_gpio_config_cmd_send() - WMI gpio config function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold gpio config param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_gpio_config_cmd_send(void *wmi_hdl,
				struct gpio_config_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_gpio_config_cmd)
		return wmi_handle->ops->send_gpio_config_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_gpio_output_cmd_send() - WMI gpio config function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold gpio config param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_gpio_output_cmd_send(void *wmi_hdl,
				struct gpio_output_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_gpio_output_cmd)
		return wmi_handle->ops->send_gpio_output_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_rtt_meas_req_test_cmd_send() - WMI rtt meas req test function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold rtt meas req test param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_rtt_meas_req_test_cmd_send(void *wmi_hdl,
				struct rtt_meas_req_test_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_rtt_meas_req_test_cmd)
		return wmi_handle->ops->send_rtt_meas_req_test_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_rtt_meas_req_cmd_send() - WMI rtt meas req function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold rtt meas req param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_rtt_meas_req_cmd_send(void *wmi_hdl,
				struct rtt_meas_req_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_rtt_meas_req_cmd)
		return wmi_handle->ops->send_rtt_meas_req_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_lci_set_cmd_send() - WMI lci set function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold lci param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lci_set_cmd_send(void *wmi_hdl,
				struct lci_set_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lci_set_cmd)
		return wmi_handle->ops->send_lci_set_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_lcr_set_cmd_send() - WMI lcr set function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold lcr param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_lcr_set_cmd_send(void *wmi_hdl,
				struct lcr_set_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_lcr_set_cmd)
		return wmi_handle->ops->send_lcr_set_cmd(wmi_handle, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 *  wmi_unified_rtt_keepalive_req_cmd_send() - WMI rtt meas req test function
 *  @param wmi_handle      : handle to WMI.
 *  @param param    : pointer to hold rtt meas req test param
 *
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_rtt_keepalive_req_cmd_send(void *wmi_hdl,
				struct rtt_keepalive_req_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_rtt_keepalive_req_cmd)
		return wmi_handle->ops->send_rtt_keepalive_req_cmd(wmi_handle,
				param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_send_periodic_chan_stats_config_cmd() - send periodic chan stats cmd
 * to fw
 * @wmi_handle: wmi handle
 * @param: pointer to hold periodic chan stats param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_send_periodic_chan_stats_config_cmd(void *wmi_hdl,
			struct periodic_chan_stats_params *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->send_periodic_chan_stats_config_cmd)
		return wmi->ops->send_periodic_chan_stats_config_cmd(wmi,
					param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_send_atf_peer_request_cmd() - send atf peer request command to fw
 * @wmi_handle: wmi handle
 * @param: pointer to atf peer request param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS
wmi_send_atf_peer_request_cmd(void *wmi_hdl,
		struct atf_peer_request_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_atf_peer_request_cmd)
		return wmi_handle->ops->send_atf_peer_request_cmd(wmi_handle,
					param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_send_set_atf_grouping_cmd() - send set atf grouping command to fw
 * @wmi_handle: wmi handle
 * @param: pointer to set atf grouping param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS
wmi_send_set_atf_grouping_cmd(void *wmi_hdl,
		struct atf_grouping_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_set_atf_grouping_cmd)
		return wmi_handle->ops->send_set_atf_grouping_cmd(wmi_handle,
					param);

	return QDF_STATUS_E_FAILURE;

}


/* Extract - APIs */
/**
 *  wmi_extract_wds_addr_event - Extract WDS addr WMI event
 *
 *  @param wmi_handle      : handle to WMI.
 *  @param evt_buf    : pointer to event buffer
 *  @param len : length of the event buffer
 *  @param wds_ev: pointer to strct to extract
 *  @return QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_wds_addr_event(void *wmi_hdl, void *evt_buf,
	uint16_t len, wds_addr_event_t *wds_ev)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_wds_addr_event) {
		return wmi_handle->ops->extract_wds_addr_event(wmi_handle,
			evt_buf, len, wds_ev);
	}
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_dcs_interference_type() - extract dcs interference type
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param interference_type: Pointer to hold interference type
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_dcs_interference_type(void *wmi_hdl,
	void *evt_buf, uint32_t *interference_type)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_dcs_interference_type) {
		return wmi->ops->extract_dcs_interference_type(wmi,
			evt_buf, interference_type);
	}
	return QDF_STATUS_E_FAILURE;
}

/*
 * wmi_extract_dcs_cw_int() - extract dcs cw interference from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param cw_int: Pointer to hold cw interference
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_dcs_cw_int(void *wmi_hdl, void *evt_buf,
	wmi_host_ath_dcs_cw_int *cw_int)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_dcs_cw_int) {
		return wmi_handle->ops->extract_dcs_cw_int(wmi_handle,
			evt_buf, cw_int);
	}
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_dcs_im_tgt_stats() - extract dcs im target stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param wlan_stat: Pointer to hold wlan stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_dcs_im_tgt_stats(void *wmi_hdl, void *evt_buf,
	wmi_host_dcs_im_tgt_stats_t *wlan_stat)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_dcs_im_tgt_stats) {
		return wmi_handle->ops->extract_dcs_im_tgt_stats(wmi_handle,
			evt_buf, wlan_stat);
	}
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_fips_event_error_status() - extract fips event error status
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param err_status: Pointer to hold error status
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_fips_event_error_status(void *wmi_hdl, void *evt_buf,
	uint32_t *err_status)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_fips_event_error_status) {
		return wmi->ops->extract_fips_event_error_status(wmi,
			evt_buf, err_status);
	}
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_fips_event_data() - extract fips event data
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param data_len: Pointer to hold fips data length
 * @param data: Double pointer to hold fips data
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_fips_event_data(void *wmi_hdl, void *evt_buf,
	uint32_t *data_len, uint32_t **data)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_fips_event_data) {
		return wmi_handle->ops->extract_fips_event_data(wmi_handle,
			evt_buf, data_len, data);
	}
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_vdev_start_resp() - extract vdev start response
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param vdev_rsp: Pointer to hold vdev response
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_vdev_start_resp(void *wmi_hdl, void *evt_buf,
	wmi_host_vdev_start_resp *vdev_rsp)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_vdev_start_resp)
		return wmi_handle->ops->extract_vdev_start_resp(wmi_handle,
				evt_buf, vdev_rsp);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_tbttoffset_update_params() - extract tbtt offset update param
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param vdev_map: Pointer to hold vdev map
 * @param tbttoffset_list: Pointer to tbtt offset list
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_tbttoffset_update_params(void *wmi_hdl, void *evt_buf,
	uint32_t *vdev_map, uint32_t **tbttoffset_list)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_tbttoffset_update_params)
		return wmi->ops->extract_tbttoffset_update_params(wmi,
			evt_buf, vdev_map, tbttoffset_list);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_mgmt_rx_params() - extract management rx params from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param hdr: Pointer to hold header
 * @param bufp: Pointer to hold pointer to rx param buffer
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_mgmt_rx_params(void *wmi_hdl, void *evt_buf,
	wmi_host_mgmt_rx_hdr *hdr, uint8_t **bufp)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_mgmt_rx_params)
		return wmi_handle->ops->extract_mgmt_rx_params(wmi_handle,
				evt_buf, hdr, bufp);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_vdev_stopped_param() - extract vdev stop param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param vdev_id: Pointer to hold vdev identifier
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_vdev_stopped_param(void *wmi_hdl, void *evt_buf,
	uint32_t *vdev_id)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_vdev_stopped_param)
		return wmi_handle->ops->extract_vdev_stopped_param(wmi_handle,
				evt_buf, vdev_id);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_vdev_roam_param() - extract vdev roam param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to hold roam param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_vdev_roam_param(void *wmi_hdl, void *evt_buf,
	wmi_host_roam_event *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_vdev_roam_param)
		return wmi_handle->ops->extract_vdev_roam_param(wmi_handle,
				evt_buf, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_vdev_scan_ev_param() - extract vdev scan param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to hold vdev scan param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_vdev_scan_ev_param(void *wmi_hdl, void *evt_buf,
	wmi_host_scan_event *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_vdev_scan_ev_param)
		return wmi_handle->ops->extract_vdev_scan_ev_param(wmi_handle,
				evt_buf, param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_mu_ev_param() - extract mu param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to hold mu report
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_mu_ev_param(void *wmi_hdl, void *evt_buf,
	wmi_host_mu_report_event *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_mu_ev_param)
		return wmi_handle->ops->extract_mu_ev_param(wmi_handle, evt_buf,
			param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_pdev_tpc_config_ev_param() - extract pdev tpc configuration
 * param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to hold tpc configuration
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_pdev_tpc_config_ev_param(void *wmi_hdl, void *evt_buf,
	wmi_host_pdev_tpc_config_event *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_pdev_tpc_config_ev_param)
		return wmi->ops->extract_pdev_tpc_config_ev_param(wmi,
			evt_buf, param);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_gpio_input_ev_param() - extract gpio input param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param gpio_num: Pointer to hold gpio number
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_gpio_input_ev_param(void *wmi_hdl,
	void *evt_buf, uint32_t *gpio_num)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_gpio_input_ev_param)
		return wmi_handle->ops->extract_gpio_input_ev_param(wmi_handle,
			evt_buf, gpio_num);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_pdev_reserve_ast_ev_param() - extract reserve ast entry
 * param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param result: Pointer to hold reserve ast entry param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_pdev_reserve_ast_ev_param(void *wmi_hdl,
	void *evt_buf, uint32_t *result)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_pdev_reserve_ast_ev_param)
		return wmi->ops->extract_pdev_reserve_ast_ev_param(wmi,
			evt_buf, result);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_nfcal_power_ev_param() - extract noise floor calibration
 * power param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to hold nf cal power param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_nfcal_power_ev_param(void *wmi_hdl, void *evt_buf,
	wmi_host_pdev_nfcal_power_all_channels_event *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_nfcal_power_ev_param)
		return wmi_handle->ops->extract_nfcal_power_ev_param(wmi_handle,
				evt_buf, param);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_pdev_tpc_ev_param() - extract tpc param from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to hold tpc param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_pdev_tpc_ev_param(void *wmi_hdl, void *evt_buf,
	wmi_host_pdev_tpc_event *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_pdev_tpc_ev_param)
		return wmi_handle->ops->extract_pdev_tpc_ev_param(wmi_handle,
				evt_buf, param);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_pdev_generic_buffer_ev_param() - extract pdev generic buffer
 * from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to generic buffer param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_pdev_generic_buffer_ev_param(void *wmi_hdl,
		void *evt_buf, wmi_host_pdev_generic_buffer_event *param)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_pdev_generic_buffer_ev_param)
		return wmi->ops->extract_pdev_generic_buffer_ev_param(wmi,
				evt_buf, param);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_mgmt_tx_compl_param() - extract mgmt tx completion param
 * from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param param: Pointer to mgmt tx completion param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_mgmt_tx_compl_param(void *wmi_hdl, void *evt_buf,
	wmi_host_mgmt_tx_compl_event *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_mgmt_tx_compl_param)
		return wmi_handle->ops->extract_mgmt_tx_compl_param(wmi_handle,
				evt_buf, param);


	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_swba_vdev_map() - extract swba vdev map from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param vdev_map: Pointer to hold vdev map
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_swba_vdev_map(void *wmi_hdl, void *evt_buf,
		uint32_t *vdev_map)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_swba_vdev_map)
		return wmi_handle->ops->extract_swba_vdev_map(wmi_handle,
					evt_buf, vdev_map);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_swba_tim_info() - extract swba tim info from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param idx: Index to bcn info
 * @param tim_info: Pointer to hold tim info
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_swba_tim_info(void *wmi_hdl, void *evt_buf,
	    uint32_t idx, wmi_host_tim_info *tim_info)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_swba_tim_info)
		return wmi_handle->ops->extract_swba_tim_info(wmi_handle,
			evt_buf, idx, tim_info);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_swba_noa_info() - extract swba NoA information from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param idx: Index to bcn info
 * @param p2p_desc: Pointer to hold p2p NoA info
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_swba_noa_info(void *wmi_hdl, void *evt_buf,
	    uint32_t idx, wmi_host_p2p_noa_info *p2p_desc)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_swba_noa_info)
		return wmi_handle->ops->extract_swba_noa_info(wmi_handle,
			evt_buf, idx, p2p_desc);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_peer_sta_ps_statechange_ev() - extract peer sta ps state
 * from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param ev: Pointer to hold peer param and ps state
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_peer_sta_ps_statechange_ev(void *wmi_hdl, void *evt_buf,
	wmi_host_peer_sta_ps_statechange_event *ev)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_peer_sta_ps_statechange_ev)
		return wmi->ops->extract_peer_sta_ps_statechange_ev(wmi,
			evt_buf, ev);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_peer_sta_kickout_ev() - extract peer sta kickout event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param ev: Pointer to hold peer param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_peer_sta_kickout_ev(void *wmi_hdl, void *evt_buf,
	wmi_host_peer_sta_kickout_event *ev)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_peer_sta_kickout_ev)
		return wmi_handle->ops->extract_peer_sta_kickout_ev(wmi_handle,
			evt_buf, ev);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_peer_ratecode_list_ev() - extract peer ratecode from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param peer_mac: Pointer to hold peer mac address
 * @param rate_cap: Pointer to hold ratecode
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_peer_ratecode_list_ev(void *wmi_hdl, void *evt_buf,
	uint8_t *peer_mac, wmi_sa_rate_cap *rate_cap)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_peer_ratecode_list_ev)
		return wmi->ops->extract_peer_ratecode_list_ev(wmi,
			evt_buf, peer_mac, rate_cap);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_comb_phyerr() - extract comb phy error from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param datalen: data length of event buffer
 * @param buf_offset: Pointer to hold value of current event buffer offset
 * post extraction
 * @param phyer: Pointer to hold phyerr
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_comb_phyerr(void *wmi_hdl, void *evt_buf,
	uint16_t datalen, uint16_t *buf_offset, wmi_host_phyerr_t *phyerr)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_comb_phyerr)
		return wmi_handle->ops->extract_comb_phyerr(wmi_handle,
		evt_buf, datalen, buf_offset, phyerr);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_single_phyerr() - extract single phy error from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param datalen: data length of event buffer
 * @param buf_offset: Pointer to hold value of current event buffer offset
 * post extraction
 * @param phyerr: Pointer to hold phyerr
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_single_phyerr(void *wmi_hdl, void *evt_buf,
	uint16_t datalen, uint16_t *buf_offset, wmi_host_phyerr_t *phyerr)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_single_phyerr)
		return wmi_handle->ops->extract_single_phyerr(wmi_handle,
			evt_buf, datalen, buf_offset, phyerr);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_composite_phyerr() - extract composite phy error from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param datalen: Length of event buffer
 * @param phyerr: Pointer to hold phy error
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_composite_phyerr(void *wmi_hdl, void *evt_buf,
	uint16_t datalen, wmi_host_phyerr_t *phyerr)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_composite_phyerr)
		return wmi_handle->ops->extract_composite_phyerr(wmi_handle,
			evt_buf, datalen, phyerr);

	return QDF_STATUS_E_FAILURE;

}

/**
 * wmi_extract_stats_param() - extract all stats count from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param stats_param: Pointer to hold stats count
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_stats_param(void *wmi_hdl, void *evt_buf,
		   wmi_host_stats_event *stats_param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_all_stats_count)
		return wmi_handle->ops->extract_all_stats_count(wmi_handle,
			evt_buf, stats_param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_pdev_stats() - extract pdev stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into pdev stats
 * @param pdev_stats: Pointer to hold pdev stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_pdev_stats(void *wmi_hdl, void *evt_buf,
		 uint32_t index, wmi_host_pdev_stats *pdev_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_pdev_stats)
		return wmi_handle->ops->extract_pdev_stats(wmi_handle,
			evt_buf, index, pdev_stats);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_pdev_ext_stats() - extract extended pdev stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into extended pdev stats
 * @param pdev_ext_stats: Pointer to hold extended pdev stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_pdev_ext_stats(void *wmi_hdl, void *evt_buf,
		 uint32_t index, wmi_host_pdev_ext_stats *pdev_ext_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_pdev_ext_stats)
		return wmi_handle->ops->extract_pdev_ext_stats(wmi_handle,
			evt_buf, index, pdev_ext_stats);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_peer_stats() - extract peer stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into peer stats
 * @param peer_stats: Pointer to hold peer stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_peer_stats(void *wmi_hdl, void *evt_buf,
		 uint32_t index, wmi_host_peer_stats *peer_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_peer_stats)
		return wmi_handle->ops->extract_peer_stats(wmi_handle,
			evt_buf, index, peer_stats);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_vdev_stats() - extract vdev stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into vdev stats
 * @param vdev_stats: Pointer to hold vdev stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_vdev_stats(void *wmi_hdl, void *evt_buf,
		 uint32_t index, wmi_host_vdev_stats *vdev_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_vdev_stats)
		return wmi_handle->ops->extract_vdev_stats(wmi_handle,
			evt_buf, index, vdev_stats);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_rtt_hdr() - extract rtt header from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param ev: Pointer to hold rtt header
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_rtt_hdr(void *wmi_hdl, void *evt_buf,
	wmi_host_rtt_event_hdr *ev)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_rtt_hdr)
		return wmi_handle->ops->extract_rtt_hdr(wmi_handle,
			evt_buf, ev);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_bcnflt_stats() - extract bcn fault stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into bcn fault stats
 * @param bcnflt_stats: Pointer to hold bcn fault stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_bcnflt_stats(void *wmi_hdl, void *evt_buf,
		 uint32_t index, wmi_host_bcnflt_stats *bcnflt_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_bcnflt_stats)
		return wmi_handle->ops->extract_bcnflt_stats(wmi_handle,
			evt_buf, index, bcnflt_stats);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_rtt_ev() - extract rtt event
 * @wmi_handle: wmi handle
 * @param evt_buf: Pointer to event buffer
 * @param ev: Pointer to hold rtt event
 * @param hdump: Pointer to hold hex dump
 * @param hdump_len: hex dump length
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_rtt_ev(void *wmi_hdl, void *evt_buf,
	wmi_host_rtt_meas_event *ev, uint8_t *hdump, uint16_t hdump_len)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_rtt_ev)
		return wmi_handle->ops->extract_rtt_ev(wmi_handle,
			evt_buf, ev, hdump, hdump_len);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_peer_extd_stats() - extract extended peer stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into extended peer stats
 * @param peer_extd_stats: Pointer to hold extended peer stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_peer_extd_stats(void *wmi_hdl, void *evt_buf,
		 uint32_t index, wmi_host_peer_extd_stats *peer_extd_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_peer_extd_stats)
		return wmi_handle->ops->extract_peer_extd_stats(wmi_handle,
			evt_buf, index, peer_extd_stats);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_rtt_error_report_ev() - extract rtt error report from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param wds_ev: Pointer to hold rtt error report
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_rtt_error_report_ev(void *wmi_hdl, void *evt_buf,
	wmi_host_rtt_error_report_event *ev)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_rtt_error_report_ev)
		return wmi_handle->ops->extract_rtt_error_report_ev(wmi_handle,
			evt_buf, ev);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_chan_stats() - extract chan stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into chan stats
 * @param chanstats: Pointer to hold chan stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_chan_stats(void *wmi_hdl, void *evt_buf,
		 uint32_t index, wmi_host_chan_stats *chan_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_chan_stats)
		return wmi_handle->ops->extract_chan_stats(wmi_handle,
			evt_buf, index, chan_stats);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_thermal_stats() - extract thermal stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: Pointer to event buffer
 * @param temp: Pointer to hold extracted temperature
 * @param level: Pointer to hold extracted level
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_thermal_stats(void *wmi_hdl, void *evt_buf,
	uint32_t *temp, uint32_t *level)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_thermal_stats)
		return wmi_handle->ops->extract_thermal_stats(wmi_handle,
			evt_buf, temp, level);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_profile_ctx() - extract profile context from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param profile_ctx: Pointer to hold profile context
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_profile_ctx(void *wmi_hdl, void *evt_buf,
			    wmi_host_wlan_profile_ctx_t *profile_ctx)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_profile_ctx)
		return wmi_handle->ops->extract_profile_ctx(wmi_handle,
			evt_buf, profile_ctx);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_thermal_level_stats() - extract thermal level stats from
 * event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param idx: Index to level stats
 * @param levelcount: Pointer to hold levelcount
 * @param dccount: Pointer to hold dccount
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_thermal_level_stats(void *wmi_hdl, void *evt_buf,
	uint8_t idx, uint32_t *levelcount, uint32_t *dccount)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_thermal_level_stats)
		return wmi_handle->ops->extract_thermal_level_stats(wmi_handle,
			evt_buf, idx, levelcount, dccount);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_profile_data() - extract profile data from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @idx index: index of profile data
 * @param profile_data: Pointer to hold profile data
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_profile_data(void *wmi_hdl, void *evt_buf, uint8_t idx,
			       wmi_host_wlan_profile_t *profile_data)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_profile_data)
		return wmi_handle->ops->extract_profile_data(wmi_handle,
			evt_buf, idx, profile_data);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_chan_info_event() - extract chan information from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param chan_info: Pointer to hold chan information
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_chan_info_event(void *wmi_hdl, void *evt_buf,
			       wmi_host_chan_info_event *chan_info)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_chan_info_event)
		return wmi_handle->ops->extract_chan_info_event(wmi_handle,
			evt_buf, chan_info);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_channel_hopping_event() - extract channel hopping param
 * from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param ch_hopping: Pointer to hold channel hopping param
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_channel_hopping_event(void *wmi_hdl, void *evt_buf,
	     wmi_host_pdev_channel_hopping_event *ch_hopping)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_channel_hopping_event)
		return wmi->ops->extract_channel_hopping_event(wmi,
			evt_buf, ch_hopping);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_bss_chan_info_event() - extract bss channel information
 * from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param bss_chan_info: Pointer to hold bss channel information
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_bss_chan_info_event(void *wmi_hdl, void *evt_buf,
		    wmi_host_pdev_bss_chan_info_event *bss_chan_info)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_bss_chan_info_event)
		return wmi_handle->ops->extract_bss_chan_info_event(wmi_handle,
		evt_buf, bss_chan_info);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_inst_rssi_stats_event() - extract inst rssi stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param inst_rssi_resp: Pointer to hold inst rssi response
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_inst_rssi_stats_event(void *wmi_hdl, void *evt_buf,
			   wmi_host_inst_stats_resp *inst_rssi_resp)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_inst_rssi_stats_event)
		return wmi->ops->extract_inst_rssi_stats_event(wmi,
			evt_buf, inst_rssi_resp);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_tx_data_traffic_ctrl_ev() - extract tx data traffic control
 * from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into chan stats
 * @param ev: Pointer to hold data traffic control
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_tx_data_traffic_ctrl_ev(void *wmi_hdl, void *evt_buf,
			wmi_host_tx_data_traffic_ctrl_event *ev)
{
	wmi_unified_t wmi = (wmi_unified_t) wmi_hdl;

	if (wmi->ops->extract_tx_data_traffic_ctrl_ev)
		return wmi->ops->extract_tx_data_traffic_ctrl_ev(wmi,
				evt_buf, ev);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_extract_vdev_extd_stats() - extract extended vdev stats from event
 * @wmi_handle: wmi handle
 * @param evt_buf: pointer to event buffer
 * @param index: Index into extended vdev stats
 * @param vdev_extd_stats: Pointer to hold extended vdev stats
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_extract_vdev_extd_stats(void *wmi_hdl, void *evt_buf,
		uint32_t index, wmi_host_vdev_extd_stats *vdev_extd_stats)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->extract_vdev_extd_stats)
		return wmi_handle->ops->extract_vdev_extd_stats(wmi_handle,
				evt_buf, index, vdev_extd_stats);
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_send_adapt_dwelltime_params_cmd() - send wmi cmd of
 * adaptive dwelltime configuration params
 * @wma_handle:  wma handler
 * @dwelltime_params: pointer to dwelltime_params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF failure reason code for failure
 */
QDF_STATUS wmi_unified_send_adapt_dwelltime_params_cmd(void *wmi_hdl,
			struct wmi_adaptive_dwelltime_params *dwelltime_params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_adapt_dwelltime_params_cmd)
		return wmi_handle->ops->
			send_adapt_dwelltime_params_cmd(wmi_handle,
				  dwelltime_params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_send_power_dbg_cmd() - send power debug commands
 * @wmi_handle: wmi handle
 * @param: wmi power debug parameter
 *
 * Send WMI_POWER_DEBUG_CMDID parameters to fw.
 *
 * Return: QDF_STATUS_SUCCESS on success, QDF_STATUS_E_** on error
 */
QDF_STATUS wmi_unified_send_power_dbg_cmd(void *wmi_hdl,
				struct wmi_power_dbg_params *param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_power_dbg_cmd)
		return wmi_handle->ops->send_power_dbg_cmd(wmi_handle,
				  param);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_send_sar_limit_cmd() - send sar limit cmd to fw
 * @wmi_hdl: wmi handle
 * @params: sar limit command params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_send_sar_limit_cmd(void *wmi_hdl,
				struct sar_limit_cmd_params *params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_sar_limit_cmd)
		return wmi_handle->ops->send_sar_limit_cmd(
						wmi_handle,
						params);
	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_encrypt_decrypt_send_cmd() - send encryptdecrypt cmd to fw
 * @wmi_hdl: wmi handle
 * @params: encrypt/decrypt params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_encrypt_decrypt_send_cmd(void *wmi_hdl,
				struct encrypt_decrypt_req_params *params)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_encrypt_decrypt_send_cmd)
		return wmi_handle->ops->send_encrypt_decrypt_send_cmd(
						wmi_handle,
						params);

	return QDF_STATUS_E_FAILURE;
}

/**
 * wmi_unified_get_rcpi_cmd() - get rcpi request
 * @wmi_hdl: wma handle
 * @get_rcpi_param: rcpi params
 *
 * Return: QDF_STATUS_SUCCESS on success and QDF_STATUS_E_FAILURE for failure
 */
QDF_STATUS wmi_unified_get_rcpi_cmd(void *wmi_hdl,
				    struct rcpi_req *get_rcpi_param)
{
	wmi_unified_t wmi_handle = (wmi_unified_t) wmi_hdl;

	if (wmi_handle->ops->send_get_rcpi_cmd)
		return wmi_handle->ops->send_get_rcpi_cmd(wmi_handle,
			   get_rcpi_param);

	return QDF_STATUS_E_FAILURE;
}
