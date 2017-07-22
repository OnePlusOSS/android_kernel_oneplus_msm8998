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

/**
 * DOC : wlan_hdd_scan.h
 *
 * WLAN Host Device Driver scan related implementation
 *
 */

#if !defined(WLAN_HDD_SCAN_H)
#define WLAN_HDD_SCAN_H

#include "wlan_hdd_main.h"

#define MAX_PENDING_LOG 5

/* (30 Mins) */
#define MIN_TIME_REQUIRED_FOR_NEXT_BUG_REPORT (30 * 60 * 1000)

/*
 * enum scan_source - scan request source
 *
 * @NL_SCAN: Scan initiated from NL
 * @VENDOR_SCAN: Scan intiated from vendor command
*/
enum scan_source {
	NL_SCAN,
	VENDOR_SCAN,
};

/**
 * enum wlan_hdd_scan_type - type of scan
 * @WLAN_HDD_HOST_SCAN: refers to scan request from cfg80211_ops "scan"
 * @WLAN_HDD_PNO_SCAN: refers to scan request is from "sched_scan_start"
 *
 * driver uses this enum to identify source of scan
 *
 */
enum wlan_hdd_scan_type {
	WLAN_HDD_HOST_SCAN,
	WLAN_HDD_PNO_SCAN,
};

int iw_get_scan(struct net_device *dev, struct iw_request_info *info,
		union iwreq_data *wrqu, char *extra);

int iw_set_scan(struct net_device *dev, struct iw_request_info *info,
		union iwreq_data *wrqu, char *extra);

int hdd_scan_context_init(hdd_context_t *hdd_ctx);
void hdd_scan_context_destroy(hdd_context_t *hdd_ctx);

int wlan_hdd_cfg80211_scan(struct wiphy *wiphy,
			   struct cfg80211_scan_request *request);

#ifdef FEATURE_WLAN_SCAN_PNO
int wlan_hdd_cfg80211_sched_scan_start(struct wiphy *wiphy,
				       struct net_device *dev,
				       struct cfg80211_sched_scan_request
				       *request);

/**
 * wlan_hdd_cfg80211_sched_scan_stop() - stop cfg80211 scheduled (PNO) scan
 * @wiphy: Pointer to wiphy
 * @dev: Pointer network device
 *
 * Note, this returns success if the driver is recovering or unloading to
 * prevent race conditions between PLD initiating an unload and kernel
 * initiating a scheduled scan stop via cfg80211. Unload is expected to stop
 * any pending scheduled scans in this case.
 *
 * Return: 0 for success, non zero for failure
 */
int wlan_hdd_cfg80211_sched_scan_stop(struct wiphy *wiphy,
				      struct net_device *dev);

/**
 * wlan_hdd_sched_scan_stop() - stop scheduled (PNO) scans
 * @dev: Pointer network device
 *
 * Return: 0 for success, non zero for failure
 */
int wlan_hdd_sched_scan_stop(struct net_device *dev);
#endif /* End of FEATURE_WLAN_SCAN_PNO */

int wlan_hdd_cfg80211_vendor_scan(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void *data,
		int data_len);

/**
 * wlan_hdd_vendor_abort_scan() - API to process vendor command for
 * abort scan
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to net device
 * @data : Pointer to the data
 * @data_len : length of the data
 *
 * This is called from supplicant to abort scan
 *
 * Return: zero for success and non zero for failure.
 */
int wlan_hdd_vendor_abort_scan(
	struct wiphy *wiphy, struct wireless_dev *wdev,
	const void *data, int data_len);

void hdd_cleanup_scan_queue(hdd_context_t *hdd_ctx);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)) || \
    defined(CFG80211_ABORT_SCAN)
void wlan_hdd_cfg80211_abort_scan(struct wiphy *wiphy,
				  struct wireless_dev *wdev);
#endif
#endif /* end #if !defined(WLAN_HDD_SCAN_H) */

