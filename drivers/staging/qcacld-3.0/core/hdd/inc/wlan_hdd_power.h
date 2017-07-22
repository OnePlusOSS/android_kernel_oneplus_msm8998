/*
 * Copyright (c) 2012, 2014-2017 The Linux Foundation. All rights reserved.
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

#ifndef __WLAN_HDD_POWER_H
#define __WLAN_HDD_POWER_H

/**
 * DOC: wlan_hdd_power.h
 *
 * HDD Power Management API
 */

#include "wlan_hdd_main.h"

#ifdef WLAN_FEATURE_PACKET_FILTERING

#define HDD_MAX_CMP_PER_PACKET_FILTER	5

/**
 * enum pkt_filter_protocol_layer - packet filter protocol layer
 * @HDD_FILTER_PROTO_TYPE_INVALID: Invalid initial value
 * @HDD_FILTER_PROTO_TYPE_MAC: MAC protocol
 * @HDD_FILTER_PROTO_TYPE_ARP: ARP protocol
 * @HDD_FILTER_PROTO_TYPE_IPV4: IP V4 protocol
 * @HDD_FILTER_PROTO_TYPE_IPV6: IP V6 protocol
 * @HDD_FILTER_PROTO_TYPE_UDP: UDP protocol
 * @HDD_FILTER_PROTO_TYPE_INVALID: Max place holder value
 */
enum pkt_filter_protocol_layer {
	HDD_FILTER_PROTO_TYPE_INVALID = 0,
	HDD_FILTER_PROTO_TYPE_MAC = 1,
	HDD_FILTER_PROTO_TYPE_ARP = 2,
	HDD_FILTER_PROTO_TYPE_IPV4 = 3,
	HDD_FILTER_PROTO_TYPE_IPV6 = 4,
	HDD_FILTER_PROTO_TYPE_UDP = 5,
	HDD_FILTER_PROTO_TYPE_MAX
};

/**
 * enum pkt_filter_action - packet filter action
 * @HDD_RCV_FILTER_INVALID: Invalid initial value
 * @HDD_RCV_FILTER_SET: Packet filter set
 * @HDD_RCV_FILTER_CLEAR: Packet filter clear
 * @HDD_RCV_FILTER_MAX: Max place holder value
 */
enum pkt_filter_action {
	HDD_RCV_FILTER_INVALID = 0,
	HDD_RCV_FILTER_SET = 1,
	HDD_RCV_FILTER_CLEAR = 2,
	HDD_RCV_FILTER_MAX
};

/**
 * enum pkt_filter_compare_flag - packet filter compare flag
 * @HDD_FILTER_CMP_TYPE_INVALID: Invalid initial value
 * @HDD_FILTER_CMP_TYPE_EQUAL: Compare if filter is equal
 * @HDD_FILTER_CMP_TYPE_MASK_EQUAL: Compare if filter mask is equal
 * @HDD_FILTER_CMP_TYPE_NOT_EQUAL: Compare if filter is not equal
 * @HDD_FILTER_CMP_TYPE_MASK_NOT_EQUAL: Compare if filter mask is not equal
 * @HDD_FILTER_CMP_TYPE_MAX: Max place holder value
 */
enum pkt_filter_compare_flag {
	HDD_FILTER_CMP_TYPE_INVALID = 0,
	HDD_FILTER_CMP_TYPE_EQUAL = 1,
	HDD_FILTER_CMP_TYPE_MASK_EQUAL = 2,
	HDD_FILTER_CMP_TYPE_NOT_EQUAL = 3,
	HDD_FILTER_CMP_TYPE_MASK_NOT_EQUAL = 4,
	HDD_FILTER_CMP_TYPE_MAX
};

/**
 * struct pkt_filter_param_cfg - packet filter parameter config
 * @protocol_layer: Protocol layer
 * @compare_flag: Compare flag
 * @data_fffset: Data offset
 * @data_length: Data length
 * @compare_data: Compare data
 * @data_mask: Data mask
 */
struct pkt_filter_param_cfg {
	uint8_t protocol_layer;
	uint8_t compare_flag;
	uint8_t data_offset;
	uint8_t data_length;
	uint8_t compare_data[SIR_MAX_FILTER_TEST_DATA_LEN];
	uint8_t data_mask[SIR_MAX_FILTER_TEST_DATA_LEN];
};

/**
 * struct pkt_filter_cfg - packet filter config received from user space
 * @filter_action: Filter action
 * @filter_id: Filter id
 * @num_params: Number of parameters
 * @params_data: Packet filter parameters detail
 */
struct pkt_filter_cfg {
	uint8_t filter_action;
	uint8_t filter_id;
	uint8_t num_params;
	struct pkt_filter_param_cfg params_data[HDD_MAX_CMP_PER_PACKET_FILTER];
};

#endif

/**
 * enum suspend_resume_state - Suspend resume state
 * @HDD_WLAN_EARLY_SUSPEND: Early suspend state.
 * @HDD_WLAN_SUSPEND: Suspend state.
 * @HDD_WLAN_EARLY_RESUME: Early resume state.
 * @HDD_WLAN_RESUME: Resume state.
 *
 * Suspend state to indicate in diag event of suspend resume.
 */
enum suspend_resume_state {
	 HDD_WLAN_EARLY_SUSPEND,
	 HDD_WLAN_SUSPEND,
	 HDD_WLAN_EARLY_RESUME,
	 HDD_WLAN_RESUME
};


/* SSR shutdown & re-init functions */
QDF_STATUS hdd_wlan_shutdown(void);
QDF_STATUS hdd_wlan_re_init(void);

QDF_STATUS hdd_conf_arp_offload(hdd_adapter_t *pAdapter, bool fenable);
void hdd_conf_hostoffload(hdd_adapter_t *pAdapter, bool fenable);

/**
 * hdd_set_non_arp_hw_broadcast_filter() - enable HW Broadcast filter
 * when target goes to wow suspend/resume mode
 * @adapter: Adapter context for which broadcast filter is to be configured
 *
 * Return: zero if success, non-zero otherwise
 */
int hdd_set_non_arp_hw_broadcast_filter(hdd_adapter_t *adapter);

/**
 * hdd_clear_non_arp_hw_broadcast_filter() - disable HW Broadcast filter
 * when target goes to wow suspend/resume mode
 * @adapter: Adapter context for which broadcast filter is to be configured
 *
 * Return: zero if success, non-zero otherwise
 */
int hdd_clear_non_arp_hw_broadcast_filter(hdd_adapter_t *adapter);

#ifdef WLAN_FEATURE_PACKET_FILTERING
int wlan_hdd_set_mc_addr_list(hdd_adapter_t *pAdapter, uint8_t set);
#else
static inline void
wlan_hdd_set_mc_addr_list(hdd_adapter_t *pAdapter, uint8_t set)
{
}
#endif

int wlan_hdd_cfg80211_suspend_wlan(struct wiphy *wiphy,
				   struct cfg80211_wowlan *wow);

int wlan_hdd_cfg80211_resume_wlan(struct wiphy *wiphy);

void hdd_ipv4_notifier_work_queue(struct work_struct *work);
#ifdef WLAN_NS_OFFLOAD
void hdd_conf_ns_offload(hdd_adapter_t *adapter, bool fenable);
void hdd_ipv6_notifier_work_queue(struct work_struct *work);
#endif

int wlan_hdd_cfg80211_get_txpower(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  int *dbm);
int wlan_hdd_cfg80211_set_txpower(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  enum nl80211_tx_power_setting type,
				  int dbm);
int wlan_hdd_cfg80211_set_power_mgmt(struct wiphy *wiphy,
				     struct net_device *dev,
				     bool allow_power_save,
				     int timeout);

int wlan_hdd_ipv4_changed(struct notifier_block *nb,
				unsigned long data, void *arg);

int wlan_hdd_ipv6_changed(struct notifier_block *nb,
				unsigned long data, void *arg);

int hdd_set_qpower_config(hdd_context_t *hddctx, hdd_adapter_t *adapter,
			  uint8_t qpower);

#ifdef FEATURE_WLAN_DIAG_SUPPORT
void hdd_wlan_suspend_resume_event(uint8_t state);
#else
static inline
void hdd_wlan_suspend_resume_event(uint8_t state) {}
#endif /* FEATURE_WLAN_DIAG_SUPPORT */

/**
 * wlan_hdd_inc_suspend_stats() - Prints, then increments, then prints suspend
 *	failed statistics.
 * @hdd_ctx:	The HDD context to operate on
 * @reason:	The suspend failed reason to increment
 *
 * This function prints all of the suspend failed statistics, increments the
 * specified suspend fail reason statistic, and prints the them all again. This
 * is for easily keeping track of the most common reasons suspend fails.
 *
 * Return: none
 */
void wlan_hdd_inc_suspend_stats(hdd_context_t *hdd_ctx,
				enum suspend_fail_reason reason);

/*
 * Unit-test suspend/resume is a testing feature that allows putting firmware
 * into WoW suspend irrespective of Apps suspend status. It emulates the chain
 * of events that occur durring normal system-level suspend/resume, such as
 * initiating all of the suspend/resume stages in the correct order, and
 * enabling/disabling appropriate copy engine irqs.
 */
#ifdef WLAN_SUSPEND_RESUME_TEST
/**
 * wlan_hdd_unit_test_bus_suspend() - suspend the wlan bus
 * @state: state containing the suspend source event
 *
 * This function does the same as wlan_hdd_bus_suspend, but additionally passes
 * the appropriate flags to FW, indicating this is a unit-test suspend and it
 * should use an HTC wakeup method to resume.
 *
 * Return: 0 for success or error code
 */
int wlan_hdd_unit_test_bus_suspend(pm_message_t state);

/**
 * hdd_wlan_fake_apps_resume() - Resume from unit-test triggered suspend
 * @wiphy: the kernel wiphy struct for the device being resumed
 * @dev: the kernel net_device struct for the device being resumed
 *
 * Return: Zero on success, calls QDF_BUG() on failure
 */
int hdd_wlan_fake_apps_resume(struct wiphy *wiphy, struct net_device *dev);

/**
 * hdd_wlan_fake_apps_suspend() - Initiate a unit-test triggered suspend
 * @wiphy: the kernel wiphy struct for the device being suspended
 * @dev: the kernel net_device struct for the device being suspended
 *
 * Return: Zero on success, suspend related non-zero error code on failure
 */
int hdd_wlan_fake_apps_suspend(struct wiphy *wiphy, struct net_device *dev);
#else
static inline int
hdd_wlan_fake_apps_resume(struct wiphy *wiphy, struct net_device *dev)
{
	return 0;
}

static inline int
hdd_wlan_fake_apps_suspend(struct wiphy *wiphy, struct net_device *dev)
{
	return 0;
}
#endif /* WLAN_SUSPEND_RESUME_TEST */

#endif /* __WLAN_HDD_POWER_H */
