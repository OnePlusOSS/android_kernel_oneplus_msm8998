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

/**
 * DOC: wlan_hdd_ocb.c
 *
 * WLAN Host Device Driver 802.11p OCB implementation
 */

#include "cds_sched.h"
#include "wlan_hdd_assoc.h"
#include "wlan_hdd_main.h"
#include "wlan_hdd_ocb.h"
#include "wlan_hdd_trace.h"
#include "wlan_tgt_def_config.h"
#include "sch_api.h"
#include "wma_api.h"
#include "ol_txrx.h"
#include <cdp_txrx_peer_ops.h>

/* Structure definitions for WLAN_SET_DOT11P_CHANNEL_SCHED */
#define AIFSN_MIN		(2)
#define AIFSN_MAX		(15)
#define CW_MIN			(1)
#define CW_MAX			(10)

/* Maximum time(ms) to wait for OCB operations */
#define WLAN_WAIT_TIME_OCB_CMD 1500
#define HDD_OCB_MAGIC 0x489a154f

/**
 * struct hdd_ocb_ctxt - Context for OCB operations
 * adapter: the ocb adapter
 * completion_evt: the completion event
 * status: status of the request
 */
struct hdd_ocb_ctxt {
	uint32_t magic;
	hdd_adapter_t *adapter;
	struct completion completion_evt;
	int status;
};

/**
 * hdd_set_dot11p_config() - Set 802.11p config flag
 * @hdd_ctx: HDD Context pointer
 *
 * TODO-OCB: This has been temporarily added to ensure this paramter
 * is set in CSR when we init the channel list. This should be removed
 * once the 5.9 GHz channels are added to the regulatory domain.
 */
void hdd_set_dot11p_config(hdd_context_t *hdd_ctx)
{
	sme_set_dot11p_config(hdd_ctx->hHal,
			      hdd_ctx->config->dot11p_mode !=
				WLAN_HDD_11P_DISABLED);
}

/**
 * dot11p_validate_qos_params() - Check if QoS parameters are valid
 * @qos_params:   Array of QoS parameters
 *
 * Return: 0 on success. error code on failure.
 */
static int dot11p_validate_qos_params(struct sir_qos_params qos_params[])
{
	int i;

	for (i = 0; i < MAX_NUM_AC; i++) {
		if ((!qos_params[i].aifsn) && (!qos_params[i].cwmin)
				&& (!qos_params[i].cwmax))
			continue;

		/* Validate AIFSN */
		if ((qos_params[i].aifsn < AIFSN_MIN)
				|| (qos_params[i].aifsn > AIFSN_MAX)) {
			hdd_err("Invalid QoS parameter aifsn %d",
				qos_params[i].aifsn);
			return -EINVAL;
		}

		/* Validate CWMin */
		if ((qos_params[i].cwmin < CW_MIN)
				|| (qos_params[i].cwmin > CW_MAX)) {
			hdd_err("Invalid QoS parameter cwmin %d",
				qos_params[i].cwmin);
			return -EINVAL;
		}

		/* Validate CWMax */
		if ((qos_params[i].cwmax < CW_MIN)
				|| (qos_params[i].cwmax > CW_MAX)) {
			hdd_err("Invalid QoS parameter cwmax %d",
				qos_params[i].cwmax);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * dot11p_validate_channel() - validates a DSRC channel
 * @center_freq: the channel's center frequency
 * @bandwidth: the channel's bandwidth
 * @tx_power: transmit power
 * @reg_power: (output) the max tx power from the regulatory domain
 * @antenna_max: (output) the max antenna gain from the regulatory domain
 *
 * Return: 0 if the channel is valid, error code otherwise.
 */
static int dot11p_validate_channel(struct wiphy *wiphy,
				   uint32_t channel_freq, uint32_t bandwidth,
				   uint32_t tx_power, uint8_t *reg_power,
				   uint8_t *antenna_max)
{
	int band_idx, channel_idx;
	struct ieee80211_supported_band *current_band;
	struct ieee80211_channel *current_channel;

	for (band_idx = 0; band_idx < NUM_NL80211_BANDS; band_idx++) {
		current_band = wiphy->bands[band_idx];
		if (!current_band)
			continue;

		for (channel_idx = 0; channel_idx < current_band->n_channels;
		      channel_idx++) {
			current_channel = &current_band->channels[channel_idx];

			if (channel_freq == current_channel->center_freq) {
				if (current_channel->flags &
				    IEEE80211_CHAN_DISABLED)
					return -EINVAL;

				if (reg_power)
					*reg_power =
						current_channel->max_reg_power;
				if (antenna_max)
					*antenna_max =
						current_channel->
						max_antenna_gain;

				switch (bandwidth) {
				case 0:
					if (current_channel->flags &
					    IEEE80211_CHAN_NO_10MHZ)
						bandwidth = 5;
					else if (current_channel->flags &
						 IEEE80211_CHAN_NO_20MHZ)
						bandwidth = 10;
					else
						bandwidth = 20;
					break;
				case 5:
					break;
				case 10:
					if (current_channel->flags &
					    IEEE80211_CHAN_NO_10MHZ)
						return -EINVAL;
					break;
				case 20:
					if (current_channel->flags &
					    IEEE80211_CHAN_NO_20MHZ)
						return -EINVAL;
					break;
				default:
					return -EINVAL;
				}

				if (tx_power > current_channel->max_power)
					return -EINVAL;

				return 0;
			}
		}
	}

	return -EINVAL;
}

/**
 * hdd_ocb_validate_config() - Validates the config data
 * @config: configuration to be validated
 *
 * Return: 0 on success.
 */
static int hdd_ocb_validate_config(hdd_adapter_t *adapter,
				   struct sir_ocb_config *config)
{
	int i;
	hdd_context_t *hdd_ctx = WLAN_HDD_GET_CTX(adapter);

	for (i = 0; i < config->channel_count; i++) {
		if (dot11p_validate_channel(hdd_ctx->wiphy,
					    config->channels[i].chan_freq,
					    config->channels[i].bandwidth,
					    config->channels[i].max_pwr,
					    &config->channels[i].reg_pwr,
					    &config->channels[i].antenna_max)) {
			hdd_err("Invalid channel frequency %d",
				config->channels[i].chan_freq);
			return -EINVAL;
		}
		if (dot11p_validate_qos_params(config->channels[i].qos_params))
			return -EINVAL;
	}

	return 0;
}

/**
 * hdd_ocb_register_sta() - Register station with Transport Layer
 * @adapter: Pointer to HDD Adapter
 *
 * This function should be invoked in the OCB Set Schedule callback
 * to enable the data path in the TL by calling RegisterSTAClient
 *
 * Return: 0 on success. -1 on failure.
 */
static int hdd_ocb_register_sta(hdd_adapter_t *adapter)
{
	QDF_STATUS qdf_status = QDF_STATUS_E_FAILURE;
	struct ol_txrx_desc_type sta_desc = {0};
	hdd_context_t *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	hdd_station_ctx_t *pHddStaCtx = WLAN_HDD_GET_STATION_CTX_PTR(adapter);
	uint8_t peer_id;
	struct ol_txrx_ops txrx_ops;

	qdf_status = ol_txrx_register_ocb_peer(hdd_ctx->pcds_context,
					       adapter->macAddressCurrent.bytes,
					       &peer_id);
	if (!QDF_IS_STATUS_SUCCESS(qdf_status)) {
		hdd_err("Error registering OCB Self Peer!");
		return -EINVAL;
	}

	hdd_ctx->sta_to_adapter[peer_id] = adapter;

	sta_desc.sta_id = peer_id;
	sta_desc.is_qos_enabled = 1;

	/* Register the vdev transmit and receive functions */
	qdf_mem_zero(&txrx_ops, sizeof(txrx_ops));
	txrx_ops.rx.rx = hdd_rx_packet_cbk;
	ol_txrx_vdev_register(
		 ol_txrx_get_vdev_from_vdev_id(adapter->sessionId),
		 adapter, &txrx_ops);
	adapter->tx_fn = txrx_ops.tx.tx;

	qdf_status = ol_txrx_register_peer(&sta_desc);
	if (!QDF_IS_STATUS_SUCCESS(qdf_status)) {
		hdd_err("Failed to register. Status= %d [0x%08X]",
		       qdf_status, qdf_status);
		return -EINVAL;
	}

	if (pHddStaCtx->conn_info.staId[0] != 0 &&
	     pHddStaCtx->conn_info.staId[0] != peer_id) {
		hdd_warn("The ID for the OCB station has changed.");
	}

	pHddStaCtx->conn_info.staId[0] = peer_id;
	qdf_copy_macaddr(&pHddStaCtx->conn_info.peerMacAddress[0],
			 &adapter->macAddressCurrent);

	return 0;
}

/**
 * hdd_ocb_config_new() - Creates a new OCB configuration
 * @num_channels: the number of channels
 * @num_schedule: the schedule size
 * @ndl_chan_list_len: length in bytes of the NDL chan blob
 * @ndl_active_state_list_len: length in bytes of the active state blob
 *
 * Return: A pointer to the OCB configuration struct, NULL on failure.
 */
static
struct sir_ocb_config *hdd_ocb_config_new(uint32_t num_channels,
					  uint32_t num_schedule,
					  uint32_t ndl_chan_list_len,
					  uint32_t ndl_active_state_list_len)
{
	struct sir_ocb_config *ret = 0;
	uint32_t len;
	void *cursor;

	if (num_channels > CFG_TGT_NUM_OCB_CHANNELS ||
			num_schedule > CFG_TGT_NUM_OCB_SCHEDULES)
		return NULL;

	len = sizeof(*ret) +
		num_channels * sizeof(struct sir_ocb_config_channel) +
		num_schedule * sizeof(struct sir_ocb_config_sched) +
		ndl_chan_list_len +
		ndl_active_state_list_len;

	cursor = qdf_mem_malloc(len);
	if (!cursor)
		goto fail;

	ret = cursor;
	cursor += sizeof(*ret);

	ret->channel_count = num_channels;
	ret->channels = cursor;
	cursor += num_channels * sizeof(*ret->channels);

	ret->schedule_size = num_schedule;
	ret->schedule = cursor;
	cursor += num_schedule * sizeof(*ret->schedule);

	ret->dcc_ndl_chan_list = cursor;
	cursor += ndl_chan_list_len;

	ret->dcc_ndl_active_state_list = cursor;
	cursor += ndl_active_state_list_len;

	return ret;

fail:
	qdf_mem_free(ret);
	return NULL;
}

/**
 * hdd_ocb_set_config_callback() - OCB set config callback function
 * @context_ptr: OCB call context
 * @response_ptr: Pointer to response structure
 *
 * This function is registered as a callback with the lower layers
 * and is used to respond with the status of a OCB set config command.
 */
static void hdd_ocb_set_config_callback(void *context_ptr, void *response_ptr)
{
	struct hdd_ocb_ctxt *context = context_ptr;
	struct sir_ocb_set_config_response *resp = response_ptr;

	if (!context)
		return;

	if (resp && resp->status)
		hdd_warn("Operation failed: %d", resp->status);

	spin_lock(&hdd_context_lock);
	if (context->magic == HDD_OCB_MAGIC) {
		hdd_adapter_t *adapter = context->adapter;
		if (!resp) {
			context->status = -EINVAL;
			complete(&context->completion_evt);
			spin_unlock(&hdd_context_lock);
			return;
		}

		context->adapter->ocb_set_config_resp = *resp;
		spin_unlock(&hdd_context_lock);
		if (!resp->status) {
			/*
			 * OCB set config command successful.
			 * Open the TX data path
			 */
			if (!hdd_ocb_register_sta(adapter)) {
				wlan_hdd_netif_queue_control(adapter,
					WLAN_START_ALL_NETIF_QUEUE_N_CARRIER,
					WLAN_CONTROL_PATH);
			}
		}

		spin_lock(&hdd_context_lock);
		if (context->magic == HDD_OCB_MAGIC)
			complete(&context->completion_evt);
		spin_unlock(&hdd_context_lock);
	} else {
		spin_unlock(&hdd_context_lock);
	}
}

/**
 * hdd_ocb_set_config_req() - Send an OCB set config request
 * @adapter: a pointer to the adapter
 * @config: a pointer to the OCB configuration
 *
 * Return: 0 on success.
 */
static int hdd_ocb_set_config_req(hdd_adapter_t *adapter,
				  struct sir_ocb_config *config)
{
	int rc;
	QDF_STATUS qdf_status;
	struct hdd_ocb_ctxt context = {0};

	if (hdd_ocb_validate_config(adapter, config)) {
		hdd_err("The configuration is invalid");
		return -EINVAL;
	}

	init_completion(&context.completion_evt);
	context.adapter = adapter;
	context.magic = HDD_OCB_MAGIC;

	hdd_notice("Disabling queues");
	wlan_hdd_netif_queue_control(adapter, WLAN_NETIF_TX_DISABLE_N_CARRIER,
		WLAN_CONTROL_PATH);

	/* Call the SME API to set the config */
	qdf_status = sme_ocb_set_config(
		((hdd_context_t *)adapter->pHddCtx)->hHal, &context,
		hdd_ocb_set_config_callback, config);
	if (qdf_status != QDF_STATUS_SUCCESS) {
		hdd_err("Error calling SME function.");
		/* Convert from qdf_status to errno */
		return -EINVAL;
	}

	/* Wait for the function to complete. */
	rc = wait_for_completion_timeout(&context.completion_evt,
		msecs_to_jiffies(WLAN_WAIT_TIME_OCB_CMD));
	if (rc == 0) {
		rc = -ETIMEDOUT;
		goto end;
	}
	rc = 0;

	if (context.status) {
		rc = context.status;
		goto end;
	}

	if (adapter->ocb_set_config_resp.status) {
		rc = -EINVAL;
		goto end;
	}

	/* fall through */
end:
	spin_lock(&hdd_context_lock);
	context.magic = 0;
	spin_unlock(&hdd_context_lock);
	if (rc)
		hdd_err("Operation failed: %d", rc);
	return rc;
}

/**
 * __iw_set_dot11p_channel_sched() - Handler for WLAN_SET_DOT11P_CHANNEL_SCHED
 *				     ioctl
 * @dev: Pointer to net_device structure
 * @iw_request_info: IW Request Info
 * @wrqu: IW Request Userspace Data Pointer
 * @extra: IW Request Kernel Data Pointer
 *
 * Return: 0 on success
 */
static int __iw_set_dot11p_channel_sched(struct net_device *dev,
					 struct iw_request_info *info,
					 union iwreq_data *wrqu, char *extra)
{
	int rc = 0;
	struct dot11p_channel_sched *sched;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct sir_ocb_config *config = NULL;
	uint8_t *mac_addr;
	int i, j;
	struct sir_ocb_config_channel *curr_chan;

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(WLAN_HDD_GET_CTX(adapter)))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	sched = (struct dot11p_channel_sched *)extra;

	/* Scheduled slots same as num channels for compatibility */
	config = hdd_ocb_config_new(sched->num_channels, sched->num_channels,
				    0, 0);
	if (config == NULL) {
		hdd_err("Failed to allocate memory!");
		return -ENOMEM;
	}

	/* Identify the vdev interface */
	config->session_id = adapter->sessionId;

	/* Release all the mac addresses used for OCB */
	for (i = 0; i < adapter->ocb_mac_addr_count; i++) {
		wlan_hdd_release_intf_addr(adapter->pHddCtx,
					   adapter->ocb_mac_address[i].bytes);
	}
	adapter->ocb_mac_addr_count = 0;

	config->channel_count = 0;
	for (i = 0; i < sched->num_channels; i++) {
		if (0 == sched->channels[i].channel_freq)
			continue;

		curr_chan = &(config->channels[config->channel_count]);

		curr_chan->chan_freq = sched->channels[i].channel_freq;
		/*
		 * tx_power is divided by 2 because ocb_channel.tx_power is
		 * in half dB increments and sir_ocb_config_channel.max_pwr
		 * is in 1 dB increments.
		 */
		curr_chan->max_pwr = sched->channels[i].tx_power / 2;
		curr_chan->bandwidth = sched->channels[i].channel_bandwidth;
		/* assume 10 as default if not provided */
		if (curr_chan->bandwidth == 0)
			curr_chan->bandwidth = 10;

		/*
		 * Setup locally administered mac addresses for each channel.
		 * First channel uses the adapter's address.
		 */
		if (i == 0) {
			qdf_copy_macaddr(&curr_chan->mac_address,
				     &adapter->macAddressCurrent);
		} else {
			mac_addr = wlan_hdd_get_intf_addr(adapter->pHddCtx);
			if (mac_addr == NULL) {
				hdd_err("Cannot obtain mac address");
				rc = -EINVAL;
				goto fail;
			}
			qdf_mem_copy(config->channels[
				     config->channel_count].mac_address.bytes,
				     mac_addr, sizeof(tSirMacAddr));
			/* Save the mac address to release later */
			qdf_mem_copy(adapter->ocb_mac_address[
				     adapter->ocb_mac_addr_count].bytes,
				     mac_addr, QDF_MAC_ADDR_SIZE);
			adapter->ocb_mac_addr_count++;
		}

		for (j = 0; j < MAX_NUM_AC; j++) {
			curr_chan->qos_params[j].aifsn =
				sched->channels[i].qos_params[j].aifsn;
			curr_chan->qos_params[j].cwmin =
				sched->channels[i].qos_params[j].cwmin;
			curr_chan->qos_params[j].cwmax =
				sched->channels[i].qos_params[j].cwmax;
		}

		config->channel_count++;
	}

	/*
	 * Scheduled slots same as num channels for compatibility with
	 * legacy use.
	 */
	for (i = 0; i < sched->num_channels; i++) {
		config->schedule[i].chan_freq = sched->channels[i].channel_freq;
		config->schedule[i].guard_interval =
			sched->channels[i].start_guard_interval;
		config->schedule[i].total_duration =
			sched->channels[i].duration;
	}

	rc = hdd_ocb_set_config_req(adapter, config);
	if (rc) {
		hdd_err("Error while setting OCB config");
		goto fail;
	}

	rc = 0;

fail:
	qdf_mem_free(config);
	return rc;
}

/**
 * iw_set_dot11p_channel_sched() - IOCTL interface for setting channel schedule
 * @dev: Pointer to net_device structure
 * @iw_request_info: IW Request Info
 * @wrqu: IW Request Userspace Data Pointer
 * @extra: IW Request Kernel Data Pointer
 *
 * Return: 0 on success.
 */
int iw_set_dot11p_channel_sched(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __iw_set_dot11p_channel_sched(dev, info, wrqu, extra);
	cds_ssr_unprotect(__func__);

	return ret;
}

static const struct nla_policy qca_wlan_vendor_ocb_set_config_policy[
		QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_CHANNEL_COUNT] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_SCHEDULE_SIZE] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_CHANNEL_ARRAY] = {
		.type = NLA_BINARY
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_SCHEDULE_ARRAY] = {
		.type = NLA_BINARY
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_NDL_CHANNEL_ARRAY] = {
		.type = NLA_BINARY
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_NDL_ACTIVE_STATE_ARRAY] = {
		.type = NLA_BINARY
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_FLAGS] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_DEF_TX_PARAM] = {
		.type = NLA_BINARY
	},

};

static const struct nla_policy qca_wlan_vendor_ocb_set_utc_time_policy[
		QCA_WLAN_VENDOR_ATTR_OCB_SET_UTC_TIME_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_UTC_TIME_VALUE] = {
		.type = NLA_BINARY, .len = SIZE_UTC_TIME
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_SET_UTC_TIME_ERROR] = {
		.type = NLA_BINARY, .len = SIZE_UTC_TIME_ERROR
	},
};

static const struct nla_policy qca_wlan_vendor_ocb_start_timing_advert_policy[
		QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_CHANNEL_FREQ] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_REPEAT_RATE] = {
		.type = NLA_U32
	},
};

static const struct nla_policy  qca_wlan_vendor_ocb_stop_timing_advert_policy[
		QCA_WLAN_VENDOR_ATTR_OCB_STOP_TIMING_ADVERT_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_OCB_STOP_TIMING_ADVERT_CHANNEL_FREQ] = {
		.type = NLA_U32
	},
};

static const struct nla_policy qca_wlan_vendor_ocb_get_tsf_timer_resp[] = {
	[QCA_WLAN_VENDOR_ATTR_OCB_GET_TSF_RESP_TIMER_HIGH] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_OCB_GET_TSF_RESP_TIMER_LOW] = {
		.type = NLA_U32
	},
};

static const struct nla_policy qca_wlan_vendor_dcc_get_stats[] = {
	[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_CHANNEL_COUNT] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_REQUEST_ARRAY] = {
		.type = NLA_BINARY
	},
};

static const struct nla_policy qca_wlan_vendor_dcc_get_stats_resp[] = {
	[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_RESP_CHANNEL_COUNT] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_RESP_STATS_ARRAY] = {
		.type = NLA_BINARY
	},
};

static const struct nla_policy qca_wlan_vendor_dcc_clear_stats[] = {
	[QCA_WLAN_VENDOR_ATTR_DCC_CLEAR_STATS_BITMAP] = {
		.type = NLA_U32
	},
};

static const struct nla_policy qca_wlan_vendor_dcc_update_ndl[
		QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_CHANNEL_COUNT] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_CHANNEL_ARRAY] = {
		.type = NLA_BINARY
	},
	[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_ACTIVE_STATE_ARRAY] = {
		.type = NLA_BINARY
	},
};

/**
 * struct wlan_hdd_ocb_config_channel
 * @chan_freq: frequency of the channel
 * @bandwidth: bandwidth of the channel, either 10 or 20 MHz
 * @mac_address: MAC address assigned to this channel
 * @qos_params: QoS parameters
 * @max_pwr: maximum transmit power of the channel (1/2 dBm)
 * @min_pwr: minimum transmit power of the channel (1/2 dBm)
 */
struct wlan_hdd_ocb_config_channel {
	uint32_t chan_freq;
	uint32_t bandwidth;
	uint16_t flags;
	uint8_t reserved[4];
	struct sir_qos_params qos_params[MAX_NUM_AC];
	uint32_t max_pwr;
	uint32_t min_pwr;
};

static void wlan_hdd_ocb_config_channel_to_sir_ocb_config_channel(
	struct sir_ocb_config_channel *dest,
	struct wlan_hdd_ocb_config_channel *src,
	uint32_t channel_count)
{
	uint32_t i;

	qdf_mem_zero(dest, channel_count * sizeof(*dest));

	for (i = 0; i < channel_count; i++) {
		dest[i].chan_freq = src[i].chan_freq;
		dest[i].bandwidth = src[i].bandwidth;
		qdf_mem_copy(dest[i].qos_params, src[i].qos_params,
			     sizeof(dest[i].qos_params));
		/*
		 *  max_pwr and min_pwr are divided by 2 because
		 *  wlan_hdd_ocb_config_channel.max_pwr and min_pwr
		 *  are in 1/2 dB increments and
		 *  sir_ocb_config_channel.max_pwr and min_pwr are in
		 *  1 dB increments.
		 */
		dest[i].max_pwr = src[i].max_pwr / 2;
		dest[i].min_pwr = (src[i].min_pwr + 1) / 2;
		dest[i].flags = src[i].flags;
	}
}

/**
 * __wlan_hdd_cfg80211_ocb_set_config() - Interface for set config command
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int __wlan_hdd_cfg80211_ocb_set_config(struct wiphy *wiphy,
					      struct wireless_dev *wdev,
					      const void *data,
					      int data_len)
{
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_MAX + 1];
	struct nlattr *channel_array;
	struct nlattr *sched_array;
	struct nlattr *ndl_chan_list;
	uint32_t ndl_chan_list_len;
	struct nlattr *ndl_active_state_list;
	uint32_t ndl_active_state_list_len;
	uint32_t flags = 0;
	void *def_tx_param = NULL;
	uint32_t def_tx_param_size = 0;
	int i;
	uint32_t channel_count, schedule_size;
	struct sir_ocb_config *config;
	int rc = -EINVAL;
	uint8_t *mac_addr;

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	/* Parse the netlink message */
	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_MAX,
			data,
			data_len, qca_wlan_vendor_ocb_set_config_policy)) {
		hdd_err("Invalid ATTR");
		return -EINVAL;
	}

	/* Get the number of channels in the schedule */
	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_CHANNEL_COUNT]) {
		hdd_err("CHANNEL_COUNT is not present");
		return -EINVAL;
	}
	channel_count = nla_get_u32(
		tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_CHANNEL_COUNT]);

	/* Get the size of the channel schedule */
	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_SCHEDULE_SIZE]) {
		hdd_err("SCHEDULE_SIZE is not present");
		return -EINVAL;
	}
	schedule_size = nla_get_u32(
		tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_SCHEDULE_SIZE]);

	/* Get the ndl chan array and the ndl active state array. */
	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_NDL_CHANNEL_ARRAY]) {
		hdd_err("NDL_CHANNEL_ARRAY is not present");
		return -EINVAL;
	}
	ndl_chan_list =
		tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_NDL_CHANNEL_ARRAY];
	ndl_chan_list_len = (ndl_chan_list ? nla_len(ndl_chan_list) : 0);

	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_NDL_ACTIVE_STATE_ARRAY]) {
		hdd_err("NDL_ACTIVE_STATE_ARRAY is not present");
		return -EINVAL;
	}
	ndl_active_state_list =
		tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_NDL_ACTIVE_STATE_ARRAY];
	ndl_active_state_list_len = (ndl_active_state_list ?
				    nla_len(ndl_active_state_list) : 0);

	/* Get the flags. This parameter is optional.*/
	if (tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_FLAGS])
		flags = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_FLAGS]);
/* Get the default TX parameters. This parameter is optional. */
	if (tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_DEF_TX_PARAM]) {
		def_tx_param_size = nla_len(tb[
			QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_DEF_TX_PARAM]);
		def_tx_param = nla_data(tb[
			QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_DEF_TX_PARAM]);
	}

	config = hdd_ocb_config_new(channel_count, schedule_size,
				    ndl_chan_list_len,
				    ndl_active_state_list_len);
	if (config == NULL) {
		hdd_err("Failed to allocate memory!");
		return -ENOMEM;
	}

	config->channel_count = channel_count;
	config->schedule_size = schedule_size;
	config->flags = flags;
	config->def_tx_param = def_tx_param;
	config->def_tx_param_size = def_tx_param_size;

	/* Read the channel array */
	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_CHANNEL_ARRAY]) {
		hdd_err("CHANNEL_ARRAY is not present");
		return -EINVAL;
	}
	channel_array = tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_CHANNEL_ARRAY];
	if (!channel_array) {
		hdd_err("No channel present");
		goto fail;
	}
	if (nla_len(channel_array) != channel_count *
	    sizeof(struct wlan_hdd_ocb_config_channel)) {
		hdd_err("CHANNEL_ARRAY is not the correct size");
		goto fail;
	}
	wlan_hdd_ocb_config_channel_to_sir_ocb_config_channel(
	    config->channels, nla_data(channel_array), channel_count);

	/* Identify the vdev interface */
	config->session_id = adapter->sessionId;

	/* Release all the mac addresses used for OCB */
	for (i = 0; i < adapter->ocb_mac_addr_count; i++) {
		wlan_hdd_release_intf_addr(adapter->pHddCtx,
					   adapter->ocb_mac_address[i].bytes);
	}
	adapter->ocb_mac_addr_count = 0;

	/*
	 * Setup locally administered mac addresses for each channel.
	 * First channel uses the adapter's address.
	 */
	for (i = 0; i < config->channel_count; i++) {
		if (i == 0) {
			qdf_copy_macaddr(&config->channels[i].mac_address,
				&adapter->macAddressCurrent);
		} else {
			mac_addr = wlan_hdd_get_intf_addr(adapter->pHddCtx);
			if (mac_addr == NULL) {
				hdd_err("Cannot obtain mac address");
				goto fail;
			}
			qdf_mem_copy(config->channels[i].mac_address.bytes,
				mac_addr, QDF_MAC_ADDR_SIZE);
			/* Save the mac address to release later */
			qdf_copy_macaddr(&adapter->ocb_mac_address[
				     adapter->ocb_mac_addr_count],
				     &config->channels[i].mac_address);
			adapter->ocb_mac_addr_count++;
		}
	}

	/* Read the schedule array */
	sched_array = tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_CONFIG_SCHEDULE_ARRAY];
	if (!sched_array) {
		hdd_err("No channel present");
		goto fail;
	}
	if (nla_len(sched_array) != schedule_size * sizeof(*config->schedule)) {
		hdd_err("SCHEDULE_ARRAY is not the correct size");
		goto fail;
	}
	qdf_mem_copy(config->schedule, nla_data(sched_array),
		nla_len(sched_array));

	/* Copy the NDL chan array */
	if (ndl_chan_list_len) {
		config->dcc_ndl_chan_list_len = ndl_chan_list_len;
		qdf_mem_copy(config->dcc_ndl_chan_list, nla_data(ndl_chan_list),
			nla_len(ndl_chan_list));
	}

	/* Copy the NDL active state array */
	if (ndl_active_state_list_len) {
		config->dcc_ndl_active_state_list_len =
			ndl_active_state_list_len;
		qdf_mem_copy(config->dcc_ndl_active_state_list,
			nla_data(ndl_active_state_list),
			nla_len(ndl_active_state_list));
	}

	rc = hdd_ocb_set_config_req(adapter, config);
	if (rc)
		hdd_err("Error while setting OCB config: %d", rc);

fail:
	qdf_mem_free(config);
	return rc;
}

/**
 * wlan_hdd_cfg80211_ocb_set_config() - Interface for set config command
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_ocb_set_config(struct wiphy *wiphy,
				     struct wireless_dev *wdev,
				     const void *data,
				     int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ocb_set_config(wiphy, wdev, data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * __wlan_hdd_cfg80211_ocb_set_utc_time() - Interface for set UTC time command
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int __wlan_hdd_cfg80211_ocb_set_utc_time(struct wiphy *wiphy,
						struct wireless_dev *wdev,
						const void *data,
						int data_len)
{
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_UTC_TIME_MAX + 1];
	struct nlattr *utc_attr;
	struct nlattr *time_error_attr;
	struct sir_ocb_utc *utc;
	int rc = -EINVAL;

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	if (!wma_is_vdev_up(adapter->sessionId)) {
		hdd_err("The device has not been started");
		return -EINVAL;
	}

	/* Parse the netlink message */
	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_OCB_SET_UTC_TIME_MAX,
		      data,
		      data_len, qca_wlan_vendor_ocb_set_utc_time_policy)) {
		hdd_err("Invalid ATTR");
		return -EINVAL;
	}

	/* Read the UTC time */
	utc_attr = tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_UTC_TIME_VALUE];
	if (!utc_attr) {
		hdd_err("UTC_TIME is not present");
		return -EINVAL;
	}
	if (nla_len(utc_attr) != SIZE_UTC_TIME) {
		hdd_err("UTC_TIME is not the correct size");
		return -EINVAL;
	}

	/* Read the time error */
	time_error_attr = tb[QCA_WLAN_VENDOR_ATTR_OCB_SET_UTC_TIME_ERROR];
	if (!time_error_attr) {
		hdd_err("UTC_TIME is not present");
		return -EINVAL;
	}
	if (nla_len(time_error_attr) != SIZE_UTC_TIME_ERROR) {
		hdd_err("UTC_TIME is not the correct size");
		return -EINVAL;
	}

	utc = qdf_mem_malloc(sizeof(*utc));
	if (!utc) {
		hdd_err("qdf_mem_malloc failed");
		return -ENOMEM;
	}
	utc->vdev_id = adapter->sessionId;
	qdf_mem_copy(utc->utc_time, nla_data(utc_attr), SIZE_UTC_TIME);
	qdf_mem_copy(utc->time_error, nla_data(time_error_attr),
		SIZE_UTC_TIME_ERROR);

	if (sme_ocb_set_utc_time(hdd_ctx->hHal, utc) != QDF_STATUS_SUCCESS) {
		hdd_err("Error while setting UTC time");
		rc = -EINVAL;
	} else {
		rc = 0;
	}

	qdf_mem_free(utc);
	return rc;
}

/**
 * wlan_hdd_cfg80211_ocb_set_utc_time() - Interface for the set UTC time command
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_ocb_set_utc_time(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       const void *data,
				       int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ocb_set_utc_time(wiphy, wdev, data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * __wlan_hdd_cfg80211_ocb_start_timing_advert() - Interface for start TA cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int
__wlan_hdd_cfg80211_ocb_start_timing_advert(struct wiphy *wiphy,
					    struct wireless_dev *wdev,
					    const void *data,
					    int data_len)
{
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_MAX + 1];
	struct sir_ocb_timing_advert *timing_advert;
	int rc = -EINVAL;

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	if (!wma_is_vdev_up(adapter->sessionId)) {
		hdd_err("The device has not been started");
		return -EINVAL;
	}

	timing_advert = qdf_mem_malloc(sizeof(*timing_advert));
	if (!timing_advert) {
		hdd_err("qdf_mem_malloc failed");
		return -ENOMEM;
	}
	timing_advert->vdev_id = adapter->sessionId;

	/* Parse the netlink message */
	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_MAX,
		      data,
		      data_len,
		      qca_wlan_vendor_ocb_start_timing_advert_policy)) {
		hdd_err("Invalid ATTR");
		goto fail;
	}

	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_CHANNEL_FREQ]) {
		hdd_err("CHANNEL_FREQ is not present");
		goto fail;
	}
	timing_advert->chan_freq = nla_get_u32(
		tb[QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_CHANNEL_FREQ]);

	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_REPEAT_RATE]) {
		hdd_err("REPEAT_RATE is not present");
		goto fail;
	}
	timing_advert->repeat_rate = nla_get_u32(
		tb[QCA_WLAN_VENDOR_ATTR_OCB_START_TIMING_ADVERT_REPEAT_RATE]);

	timing_advert->template_length =
		sme_ocb_gen_timing_advert_frame(hdd_ctx->hHal,
			*(tSirMacAddr *)&adapter->macAddressCurrent.bytes,
			&timing_advert->template_value,
			&timing_advert->timestamp_offset,
			&timing_advert->time_value_offset);
	if (timing_advert->template_length <= 0) {
		hdd_err("Error while generating the TA frame");
		goto fail;
	}

	if (sme_ocb_start_timing_advert(hdd_ctx->hHal, timing_advert) !=
			QDF_STATUS_SUCCESS) {
		hdd_err("Error while starting timing advert");
		rc = -EINVAL;
	} else {
		rc = 0;
	}

fail:
	if (timing_advert->template_value)
		qdf_mem_free(timing_advert->template_value);
	qdf_mem_free(timing_advert);
	return rc;
}

/**
 * wlan_hdd_cfg80211_ocb_start_timing_advert() - Interface for the start TA cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_ocb_start_timing_advert(struct wiphy *wiphy,
					      struct wireless_dev *wdev,
					      const void *data,
					      int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ocb_start_timing_advert(wiphy, wdev,
							  data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * __wlan_hdd_cfg80211_ocb_stop_timing_advert() - Interface for the stop TA cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int
__wlan_hdd_cfg80211_ocb_stop_timing_advert(struct wiphy *wiphy,
					   struct wireless_dev *wdev,
					   const void *data,
					   int data_len)
{
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_OCB_STOP_TIMING_ADVERT_MAX + 1];
	struct sir_ocb_timing_advert *timing_advert;
	int rc = -EINVAL;

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	if (!wma_is_vdev_up(adapter->sessionId)) {
		hdd_err("The device has not been started");
		return -EINVAL;
	}

	timing_advert = qdf_mem_malloc(sizeof(*timing_advert));
	if (!timing_advert) {
		hdd_err("qdf_mem_malloc failed");
		return -ENOMEM;
	}
	timing_advert->vdev_id = adapter->sessionId;

	/* Parse the netlink message */
	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_OCB_STOP_TIMING_ADVERT_MAX,
		      data,
		      data_len,
		      qca_wlan_vendor_ocb_stop_timing_advert_policy)) {
		hdd_err("Invalid ATTR");
		goto fail;
	}

	if (!tb[QCA_WLAN_VENDOR_ATTR_OCB_STOP_TIMING_ADVERT_CHANNEL_FREQ]) {
		hdd_err("CHANNEL_FREQ is not present");
		goto fail;
	}
	timing_advert->chan_freq = nla_get_u32(
		tb[QCA_WLAN_VENDOR_ATTR_OCB_STOP_TIMING_ADVERT_CHANNEL_FREQ]);

	if (sme_ocb_stop_timing_advert(hdd_ctx->hHal, timing_advert) !=
			QDF_STATUS_SUCCESS) {
		hdd_err("Error while stopping timing advert");
		rc = -EINVAL;
	} else {
		rc = 0;
	}

fail:
	qdf_mem_free(timing_advert);
	return rc;
}

/**
 * wlan_hdd_cfg80211_ocb_stop_timing_advert() - Interface for the stop TA cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_ocb_stop_timing_advert(struct wiphy *wiphy,
					     struct wireless_dev *wdev,
					     const void *data,
					     int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ocb_stop_timing_advert(wiphy, wdev,
							 data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * hdd_ocb_get_tsf_timer_callback() - Callback to get TSF command
 * @context_ptr: request context
 * @response_ptr: response data
 */
static void hdd_ocb_get_tsf_timer_callback(void *context_ptr,
					   void *response_ptr)
{
	struct hdd_ocb_ctxt *context = context_ptr;
	struct sir_ocb_get_tsf_timer_response *response = response_ptr;

	if (!context)
		return;

	spin_lock(&hdd_context_lock);
	if (context->magic == HDD_OCB_MAGIC) {
		if (response) {
			context->adapter->ocb_get_tsf_timer_resp = *response;
			context->status = 0;
		} else {
			context->status = -EINVAL;
		}
		complete(&context->completion_evt);
	}
	spin_unlock(&hdd_context_lock);
}

/**
 * __wlan_hdd_cfg80211_ocb_get_tsf_timer() - Interface for get TSF timer cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int
__wlan_hdd_cfg80211_ocb_get_tsf_timer(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data,
				      int data_len)
{
	struct sk_buff *nl_resp = 0;
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	int rc = -EINVAL;
	struct sir_ocb_get_tsf_timer request = {0};
	struct hdd_ocb_ctxt context = {0};

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	if (!wma_is_vdev_up(adapter->sessionId)) {
		hdd_err("The device has not been started");
		return -EINVAL;
	}

	/* Initialize the callback context */
	init_completion(&context.completion_evt);
	context.adapter = adapter;
	context.magic = HDD_OCB_MAGIC;

	request.vdev_id = adapter->sessionId;
	/* Call the SME function */
	rc = sme_ocb_get_tsf_timer(hdd_ctx->hHal, &context,
				   hdd_ocb_get_tsf_timer_callback,
				   &request);
	if (rc) {
		hdd_err("Error calling SME function");
		/* Need to convert from qdf_status to errno. */
		return -EINVAL;
	}

	rc = wait_for_completion_timeout(&context.completion_evt,
		msecs_to_jiffies(WLAN_WAIT_TIME_OCB_CMD));
	if (rc == 0) {
		hdd_err("Operation timed out");
		rc = -ETIMEDOUT;
		goto end;
	}
	rc = 0;

	if (context.status) {
		hdd_err("Operation failed: %d", context.status);
		rc = context.status;
		goto end;
	}

	/* Allocate the buffer for the response. */
	nl_resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
		2 * sizeof(uint32_t) + NLMSG_HDRLEN);

	if (!nl_resp) {
		hdd_err("cfg80211_vendor_cmd_alloc_reply_skb failed");
		rc = -ENOMEM;
		goto end;
	}

	hdd_notice("Got TSF timer response, high=%d, low=%d",
	       adapter->ocb_get_tsf_timer_resp.timer_high,
	       adapter->ocb_get_tsf_timer_resp.timer_low);

	/* Populate the response. */
	rc = nla_put_u32(nl_resp,
			QCA_WLAN_VENDOR_ATTR_OCB_GET_TSF_RESP_TIMER_HIGH,
			adapter->ocb_get_tsf_timer_resp.timer_high);
	if (rc)
		goto end;
	rc = nla_put_u32(nl_resp,
			    QCA_WLAN_VENDOR_ATTR_OCB_GET_TSF_RESP_TIMER_LOW,
			    adapter->ocb_get_tsf_timer_resp.timer_low);
	if (rc)
		goto end;

	/* Send the response. */
	rc = cfg80211_vendor_cmd_reply(nl_resp);
	nl_resp = NULL;
	if (rc) {
		hdd_err("cfg80211_vendor_cmd_reply failed: %d", rc);
		goto end;
	}

end:
	spin_lock(&hdd_context_lock);
	context.magic = 0;
	spin_unlock(&hdd_context_lock);
	if (nl_resp)
		kfree_skb(nl_resp);
	return rc;
}

/**
 * wlan_hdd_cfg80211_ocb_get_tsf_timer() - Interface for get TSF timer cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_ocb_get_tsf_timer(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ocb_get_tsf_timer(wiphy, wdev,
						    data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * hdd_dcc_get_stats_callback() - Callback to get stats command
 * @context_ptr: request context
 * @response_ptr: response data
 */
static void hdd_dcc_get_stats_callback(void *context_ptr, void *response_ptr)
{
	struct hdd_ocb_ctxt *context = context_ptr;
	struct sir_dcc_get_stats_response *response = response_ptr;
	struct sir_dcc_get_stats_response *hdd_resp;

	if (!context)
		return;

	spin_lock(&hdd_context_lock);
	if (context->magic == HDD_OCB_MAGIC) {
		if (response) {
			/*
			 * If the response is hanging around from the previous
			 * request, delete it
			 */
			if (context->adapter->dcc_get_stats_resp) {
				qdf_mem_free(
				    context->adapter->dcc_get_stats_resp);
			}
			context->adapter->dcc_get_stats_resp =
				qdf_mem_malloc(sizeof(
				    *context->adapter->dcc_get_stats_resp) +
				    response->channel_stats_array_len);
			if (context->adapter->dcc_get_stats_resp) {
				hdd_resp = context->adapter->dcc_get_stats_resp;
				*hdd_resp = *response;
				hdd_resp->channel_stats_array =
					(void *)hdd_resp + sizeof(*hdd_resp);
				qdf_mem_copy(hdd_resp->channel_stats_array,
					     response->channel_stats_array,
					     response->channel_stats_array_len);
				context->status = 0;
			} else {
				context->status = -ENOMEM;
			}
		} else {
			context->status = -EINVAL;
		}
		complete(&context->completion_evt);
	}
	spin_unlock(&hdd_context_lock);
}

/**
 * __wlan_hdd_cfg80211_dcc_get_stats() - Interface for get dcc stats
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int __wlan_hdd_cfg80211_dcc_get_stats(struct wiphy *wiphy,
					     struct wireless_dev *wdev,
					     const void *data,
					     int data_len)
{
	uint32_t channel_count = 0;
	uint32_t request_array_len = 0;
	void *request_array = 0;
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_MAX + 1];
	struct sk_buff *nl_resp = 0;
	int rc = -EINVAL;
	struct sir_dcc_get_stats request = {0};
	struct hdd_ocb_ctxt context = {0};

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	if (!wma_is_vdev_up(adapter->sessionId)) {
		hdd_err("The device has not been started");
		return -EINVAL;
	}

	/* Parse the netlink message */
	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_MAX,
		      data,
		      data_len,
		      qca_wlan_vendor_dcc_get_stats)) {
		hdd_err("Invalid ATTR");
		return -EINVAL;
	}

	/* Validate all the parameters are present */
	if (!tb[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_CHANNEL_COUNT] ||
	    !tb[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_REQUEST_ARRAY]) {
		hdd_err("Parameters are not present.");
		return -EINVAL;
	}

	channel_count = nla_get_u32(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_CHANNEL_COUNT]);
	request_array_len = nla_len(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_REQUEST_ARRAY]);
	request_array = nla_data(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_REQUEST_ARRAY]);

	/* Initialize the callback context */
	init_completion(&context.completion_evt);
	context.adapter = adapter;
	context.magic = HDD_OCB_MAGIC;

	request.vdev_id = adapter->sessionId;
	request.channel_count = channel_count;
	request.request_array_len = request_array_len;
	request.request_array = request_array;

	/* Call the SME function. */
	rc = sme_dcc_get_stats(hdd_ctx->hHal, &context,
			       hdd_dcc_get_stats_callback,
			       &request);
	if (rc) {
		hdd_err("Error calling SME function");
		/* Need to convert from qdf_status to errno. */
		return -EINVAL;
	}

	/* Wait for the function to complete. */
	rc = wait_for_completion_timeout(&context.completion_evt,
				msecs_to_jiffies(WLAN_WAIT_TIME_OCB_CMD));
	if (rc == 0) {
		hdd_err("Operation failed: %d", rc);
		rc = -ETIMEDOUT;
		goto end;
	}

	if (context.status) {
		hdd_err("There was error: %d", context.status);
		rc = context.status;
		goto end;
	}

	if (!adapter->dcc_get_stats_resp) {
		hdd_err("The response was NULL");
		rc = -EINVAL;
		goto end;
	}

	/* Allocate the buffer for the response. */
	nl_resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(uint32_t) +
		adapter->dcc_get_stats_resp->channel_stats_array_len +
		NLMSG_HDRLEN);
	if (!nl_resp) {
		hdd_err("cfg80211_vendor_cmd_alloc_reply_skb failed");
		rc = -ENOMEM;
		goto end;
	}

	/* Populate the response. */
	rc = nla_put_u32(nl_resp,
			 QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_RESP_CHANNEL_COUNT,
			 adapter->dcc_get_stats_resp->num_channels);
	if (rc)
		goto end;
	rc = nla_put(nl_resp,
		     QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_RESP_STATS_ARRAY,
		     adapter->dcc_get_stats_resp->channel_stats_array_len,
		     adapter->dcc_get_stats_resp->channel_stats_array);
	if (rc)
		goto end;

	/* Send the response. */
	rc = cfg80211_vendor_cmd_reply(nl_resp);
	nl_resp = NULL;
	if (rc) {
		hdd_err("cfg80211_vendor_cmd_reply failed: %d", rc);
		goto end;
	}

	/* fall through */
end:
	spin_lock(&hdd_context_lock);
	context.magic = 0;
	qdf_mem_free(adapter->dcc_get_stats_resp);
	adapter->dcc_get_stats_resp = NULL;
	spin_unlock(&hdd_context_lock);
	if (nl_resp)
		kfree_skb(nl_resp);
	return rc;
}

/**
 * wlan_hdd_cfg80211_dcc_get_stats() - Interface for get dcc stats
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_dcc_get_stats(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data,
				    int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_dcc_get_stats(wiphy, wdev,
						data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * __wlan_hdd_cfg80211_dcc_clear_stats() - Interface for clear dcc stats cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int __wlan_hdd_cfg80211_dcc_clear_stats(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data,
					       int data_len)
{
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_DCC_CLEAR_STATS_MAX + 1];

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		return -EINVAL;
	}

	if (!wma_is_vdev_up(adapter->sessionId)) {
		hdd_err("The device has not been started");
		return -EINVAL;
	}

	/* Parse the netlink message */
	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_DCC_CLEAR_STATS_MAX,
		      data,
		      data_len,
		      qca_wlan_vendor_dcc_clear_stats)) {
		hdd_err("Invalid ATTR");
		return -EINVAL;
	}

	/* Verify that the parameter is present */
	if (!tb[QCA_WLAN_VENDOR_ATTR_DCC_CLEAR_STATS_BITMAP]) {
		hdd_err("Parameters are not present.");
		return -EINVAL;
	}

	/* Call the SME function */
	if (sme_dcc_clear_stats(hdd_ctx->hHal, adapter->sessionId,
		nla_get_u32(
			tb[QCA_WLAN_VENDOR_ATTR_DCC_CLEAR_STATS_BITMAP])) !=
			QDF_STATUS_SUCCESS) {
		hdd_err("Error calling SME function.");
		return -EINVAL;
	}

	return 0;
}

/**
 * wlan_hdd_cfg80211_dcc_clear_stats() - Interface for clear dcc stats cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_dcc_clear_stats(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data,
				      int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_dcc_clear_stats(wiphy, wdev,
						  data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * hdd_dcc_update_ndl_callback() - Callback to update NDL command
 * @context_ptr: request context
 * @response_ptr: response data
 */
static void hdd_dcc_update_ndl_callback(void *context_ptr, void *response_ptr)
{
	struct hdd_ocb_ctxt *context = context_ptr;
	struct sir_dcc_update_ndl_response *response = response_ptr;

	if (!context)
		return;

	spin_lock(&hdd_context_lock);
	if (context->magic == HDD_OCB_MAGIC) {
		if (response) {
			context->adapter->dcc_update_ndl_resp = *response;
			context->status = 0;
		} else {
			context->status = -EINVAL;
		}
		complete(&context->completion_evt);
	}
	spin_unlock(&hdd_context_lock);
}

/**
 * __wlan_hdd_cfg80211_dcc_update_ndl() - Interface for update dcc cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
static int __wlan_hdd_cfg80211_dcc_update_ndl(struct wiphy *wiphy,
					      struct wireless_dev *wdev,
					      const void *data,
					      int data_len)
{
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_MAX + 1];
	struct sir_dcc_update_ndl request;
	uint32_t channel_count;
	uint32_t ndl_channel_array_len;
	void *ndl_channel_array;
	uint32_t ndl_active_state_array_len;
	void *ndl_active_state_array;
	int rc = -EINVAL;
	struct hdd_ocb_ctxt context = {0};

	ENTER_DEV(dev);

	if (wlan_hdd_validate_context(hdd_ctx))
		goto end;

	if (adapter->device_mode != QDF_OCB_MODE) {
		hdd_err("Device not in OCB mode!");
		goto end;
	}

	if (!wma_is_vdev_up(adapter->sessionId)) {
		hdd_err("The device has not been started");
		return -EINVAL;
	}

	/* Parse the netlink message */
	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_MAX,
		      data,
		      data_len,
		      qca_wlan_vendor_dcc_update_ndl)) {
		hdd_err("Invalid ATTR");
		goto end;
	}

	/* Verify that the parameter is present */
	if (!tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_CHANNEL_COUNT] ||
	    !tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_CHANNEL_ARRAY] ||
	    !tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_ACTIVE_STATE_ARRAY]) {
		hdd_err("Parameters are not present.");
		return -EINVAL;
	}

	channel_count = nla_get_u32(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_CHANNEL_COUNT]);
	ndl_channel_array_len = nla_len(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_CHANNEL_ARRAY]);
	ndl_channel_array = nla_data(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_CHANNEL_ARRAY]);
	ndl_active_state_array_len = nla_len(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_ACTIVE_STATE_ARRAY]);
	ndl_active_state_array = nla_data(
		tb[QCA_WLAN_VENDOR_ATTR_DCC_UPDATE_NDL_ACTIVE_STATE_ARRAY]);

	/* Initialize the callback context */
	init_completion(&context.completion_evt);
	context.adapter = adapter;
	context.magic = HDD_OCB_MAGIC;

	/* Copy the parameters to the request structure. */
	request.vdev_id = adapter->sessionId;
	request.channel_count = channel_count;
	request.dcc_ndl_chan_list_len = ndl_channel_array_len;
	request.dcc_ndl_chan_list = ndl_channel_array;
	request.dcc_ndl_active_state_list_len = ndl_active_state_array_len;
	request.dcc_ndl_active_state_list = ndl_active_state_array;

	/* Call the SME function */
	rc = sme_dcc_update_ndl(hdd_ctx->hHal, &context,
				hdd_dcc_update_ndl_callback,
				&request);
	if (rc) {
		hdd_err("Error calling SME function.");
		/* Convert from qdf_status to errno */
		return -EINVAL;
	}

	/* Wait for the function to complete. */
	rc = wait_for_completion_timeout(&context.completion_evt,
		msecs_to_jiffies(WLAN_WAIT_TIME_OCB_CMD));
	if (rc == 0) {
		hdd_err("Operation timed out");
		rc = -ETIMEDOUT;
		goto end;
	}
	rc = 0;

	if (context.status) {
		hdd_err("Operation failed: %d", context.status);
		rc = context.status;
		goto end;
	}

	if (adapter->dcc_update_ndl_resp.status) {
		hdd_err("Operation returned: %d",
		       adapter->dcc_update_ndl_resp.status);
		rc = -EINVAL;
		goto end;
	}

	/* fall through */
end:
	spin_lock(&hdd_context_lock);
	context.magic = 0;
	spin_unlock(&hdd_context_lock);
	return rc;
}

/**
 * wlan_hdd_cfg80211_dcc_update_ndl() - Interface for update dcc cmd
 * @wiphy: pointer to the wiphy
 * @wdev: pointer to the wdev
 * @data: The netlink data
 * @data_len: The length of the netlink data in bytes
 *
 * Return: 0 on success.
 */
int wlan_hdd_cfg80211_dcc_update_ndl(struct wiphy *wiphy,
				     struct wireless_dev *wdev,
				     const void *data,
				     int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_dcc_update_ndl(wiphy, wdev,
						 data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * wlan_hdd_dcc_stats_event_callback() - Callback to get stats event
 * @context_ptr: request context
 * @response_ptr: response data
 */
static void wlan_hdd_dcc_stats_event_callback(void *context_ptr,
					      void *response_ptr)
{
	hdd_context_t *hdd_ctx = (hdd_context_t *)context_ptr;
	struct sir_dcc_get_stats_response *resp = response_ptr;
	struct sk_buff *vendor_event;

	ENTER();

	vendor_event =
		cfg80211_vendor_event_alloc(hdd_ctx->wiphy,
			NULL, sizeof(uint32_t) + resp->channel_stats_array_len +
			NLMSG_HDRLEN,
			QCA_NL80211_VENDOR_SUBCMD_DCC_STATS_EVENT_INDEX,
			GFP_KERNEL);

	if (!vendor_event) {
		hdd_err("cfg80211_vendor_event_alloc failed");
		return;
	}

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_RESP_CHANNEL_COUNT,
			resp->num_channels) ||
		nla_put(vendor_event,
			QCA_WLAN_VENDOR_ATTR_DCC_GET_STATS_RESP_STATS_ARRAY,
			resp->channel_stats_array_len,
			resp->channel_stats_array)) {
		hdd_err("nla put failed");
		kfree_skb(vendor_event);
		return;
	}

	cfg80211_vendor_event(vendor_event, GFP_KERNEL);
}

/**
 * wlan_hdd_dcc_register_for_dcc_stats_event() - Register for dcc stats events
 * @hdd_ctx: hdd context
 */
void wlan_hdd_dcc_register_for_dcc_stats_event(hdd_context_t *hdd_ctx)
{
	int rc;

	rc = sme_register_for_dcc_stats_event(hdd_ctx->hHal, hdd_ctx,
				      wlan_hdd_dcc_stats_event_callback);
	if (rc)
		hdd_err("Register callback failed: %d", rc);
}
