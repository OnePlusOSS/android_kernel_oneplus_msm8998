/*
 * Copyright (c) 2017 The Linux Foundation. All rights reserved.
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
 * DOC : wlan_hdd_spectralscan.h
 *
 * WLAN Host Device Driver spectral scan implementation
 *
 */

#if !defined(WLAN_HDD_SPECTRALSCAN_H)
#define WLAN_HDD_SPECTRALSCAN_H

#ifdef FEATURE_SPECTRAL_SCAN
/* Static default values for spectral state and configuration. */
#define SPECTRAL_SCAN_ACTIVE_DEFAULT           (0)
#define SPECTRAL_SCAN_ENABLE_DEFAULT           (0)
#define SPECTRAL_SCAN_COUNT_DEFAULT            (0)
#define SPECTRAL_SCAN_PERIOD_DEFAULT           (35)
#define SPECTRAL_SCAN_PRIORITY_DEFAULT         (1)
#define SPECTRAL_SCAN_FFT_SIZE_DEFAULT         (7)
#define SPECTRAL_SCAN_GC_ENA_DEFAULT           (1)
#define SPECTRAL_SCAN_RESTART_ENA_DEFAULT      (0)
#define SPECTRAL_SCAN_NOISE_FLOOR_REF_DEFAULT  (-96)
#define SPECTRAL_SCAN_INIT_DELAY_DEFAULT       (80)
#define SPECTRAL_SCAN_NB_TONE_THR_DEFAULT      (12)
#define SPECTRAL_SCAN_STR_BIN_THR_DEFAULT      (8)
#define SPECTRAL_SCAN_WB_RPT_MODE_DEFAULT      (0)
#define SPECTRAL_SCAN_RSSI_RPT_MODE_DEFAULT    (0)
#define SPECTRAL_SCAN_RSSI_THR_DEFAULT         (0xf0)
#define SPECTRAL_SCAN_PWR_FORMAT_DEFAULT       (0)
#define SPECTRAL_SCAN_RPT_MODE_DEFAULT         (2)
#define SPECTRAL_SCAN_BIN_SCALE_DEFAULT        (1)
#define SPECTRAL_SCAN_DBM_ADJ_DEFAULT          (1)
#define SPECTRAL_SCAN_CHN_MASK_DEFAULT         (1)

#define MAX_SPECTRAL_PAYLOAD 1500

/**
 * enum qca_wlan_vendor_attr_spectral_scan  -- spectral scan attributes
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_COUNT: number of report
 * to return
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_PERIOD: spectral scan period
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY: spectral scan periority
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_SIZE: number of FFT data
 * points to compute
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_GC_ENA: to enable targeted gain
 * change before starting the spectral scan FFT
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RESTART_ENA: restart spectral scan
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NOISE_FLOOR_REF: noise floor
 * reference number (signed) for the calculation of bin power
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_INIT_DELAY: Disallow spectral
 * scan triggers after Tx/Rx packets by setting this delay value to roughly
 * SIFS time period or greater. Delay timer counts in units of 0.25us
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NB_TONE_THR: number of strong
 * bins (inclusive) per sub-channel, below which a signal is declared a narrow
 * band tone
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_STR_BIN_THR: Set bin/max_bin
 * ratio threshold over which a bin is declared strong, for spectral scan
 * bandwidth analysis.
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_WB_RPT_MODE: Set this to 1 to
 * report spectral scans as EXT_BLOCKER (phy_error=36), if none of the
 * sub-channels are deemed narrow band.
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_RPT_MODE: RSSI report mode
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_THR: ADC RSSI must be
 * greater than or equal to this threshold (signed Db) to ensure spectral
 * scan reporting with normal PHY error codes
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PWR_FORMAT: Format of frequency
 * bin magnitude for spectral scan triggered FFTs. 0 - linear magnitude,
 * 1 - log magnitude
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RPT_MODE: Format of per-FFT
 * reports to software for spectral scan triggered FFTs
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_BIN_SCALE: Number of LSBs to
 * shift out to scale the FFT bins for spectral scan triggered FFTs.
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DBM_ADJ: Set to 1
 * (with pwr_format=1), to report bin magnitudes converted to dBm power
 * using the noisefloor calibration results.
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_CHN_MASK: Set per chain enable
 * mask to select input ADC for search FFT
 * @QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_COOKIE: an unsigned 64-bit integer
 * provided by host driver to identify the spectral scan request. This
 * attribute is included in the scan response message for
 * @QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START and used as an attribute in
 * @QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_STOP to identify the specific scan
 * to be stopped.
 */
enum qca_wlan_vendor_attr_spectral_scan {
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_INVALID = 0,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_COUNT = 1,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_PERIOD,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_SIZE,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_GC_ENA,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RESTART_ENA,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NOISE_FLOOR_REF,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_INIT_DELAY,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NB_TONE_THR,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_STR_BIN_THR,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_WB_RPT_MODE,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_RPT_MODE,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_THR,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PWR_FORMAT,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RPT_MODE,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_BIN_SCALE,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DBM_ADJ,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_CHN_MASK,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_COOKIE,

	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_AFTER_LAST,
	QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX =
		QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_AFTER_LAST - 1,
};

enum spectral_scan_msg_type {
	SPECTRAL_SCAN_REGISTER_REQ,
	SPECTRAL_SCAN_REGISTER_RSP,
};

struct spectral_scan_msg {
	uint32_t msg_type;
	uint32_t buf_len;
	uint8_t  *buf;
};

#define FEATURE_SPECTRAL_SCAN_VENDOR_COMMANDS \
{ \
	.info.vendor_id = QCA_NL80211_VENDOR_ID, \
	.info.subcmd = QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START, \
	.flags = WIPHY_VENDOR_CMD_NEED_WDEV | \
			WIPHY_VENDOR_CMD_NEED_NETDEV, \
	.doit = wlan_hdd_cfg80211_spectral_scan_start \
}, \
{ \
	.info.vendor_id = QCA_NL80211_VENDOR_ID, \
	.info.subcmd = QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_STOP, \
	.flags = WIPHY_VENDOR_CMD_NEED_WDEV | \
		WIPHY_VENDOR_CMD_NEED_NETDEV, \
	.doit = wlan_hdd_cfg80211_spectral_scan_stop \
},

/**
 * wlan_hdd_cfg80211_spectral_scan_start() - start spectral scan
 * @wiphy:    WIPHY structure pointer
 * @wdev:     Wireless device structure pointer
 * @data:     Pointer to the data received
 * @data_len: Length of the data received
 *
 * This function starts spectral scan
 *
 * Return: 0 on success and errno on failure
 */
int wlan_hdd_cfg80211_spectral_scan_start(struct wiphy *wiphy,
						struct wireless_dev *wdev,
						const void *data,
						int data_len);

/**
 * wlan_hdd_cfg80211_spectral_scan_stop() - stop spectral scan
 * @wiphy:    WIPHY structure pointer
 * @wdev:     Wireless device structure pointer
 * @data:     Pointer to the data received
 * @data_len: Length of the data received
 *
 * This function stops spectral scan
 *
 * Return: 0 on success and errno on failure
 */
int wlan_hdd_cfg80211_spectral_scan_stop(struct wiphy *wiphy,
						struct wireless_dev *wdev,
						const void *data,
						int data_len);

/**
 * spectral_scan_activate_service() - Activate spectral scan  message handler
 *
 *  This function registers a handler to receive netlink message from
 *  the spectral scan application process.
 *  param -
 *     - None
 *
 * Return - 0 for success, non zero for failure
 */
int spectral_scan_activate_service(void);

/**
 * hdd_init_spectral_scan() - Initialize spectral scan config parameters
 *
 * This function initialize spectral scan configuration parameters
 * with default values.
 * @hdd_ctx: HDD context pointer
 *
 * Return - None
 */
void hdd_init_spectral_scan(hdd_context_t *hdd_ctx);

/**
 * hdd_register_spectral_scan_cb() - register callback function for sending
 *	spectral scan results to user space.
 *
 * @hdd_ctx: HDD context pointer
 * @cb: callback function
 *
 * Return - None
 */
void hdd_register_spectral_scan_cb(hdd_context_t *hdd_ctx,
				void (*cb)(void *, struct spectral_samp_msg *));

/**
 * spectral_scan_callback() - callback function for sending
 *      spectral scan results to user space.
 *
 * @hdd_ctx: HDD context pointer
 * @samp_msg: SAMP message that contains spectral scan result
 *
 * Return - None
 */
void spectral_scan_callback(void *context, struct spectral_samp_msg *samp_msg);
#else
static inline int spectral_scan_activate_service(void)
{
	return 0;
}

static inline void hdd_init_spectral_scan(hdd_context_t *hdd_ctx)
{
}

static inline void hdd_register_spectral_scan_cb(hdd_context_t *hdd_ctx,
				void (*cb)(void *, struct spectral_samp_msg *))
{
}

static inline void spectral_scan_callback(void *context,
				struct spectral_samp_msg *samp_msg)
{
}

#define FEATURE_SPECTRAL_SCAN_VENDOR_COMMANDS
#endif
#endif

