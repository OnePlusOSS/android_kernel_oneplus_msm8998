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
 * DOC : wlan_hdd_stats.c
 *
 * WLAN Host Device Driver statistics related implementation
 *
 */

#include "wlan_hdd_stats.h"
#include "sme_api.h"
#include "cds_sched.h"
#include "wlan_hdd_trace.h"
#include "wlan_hdd_lpass.h"
#include "hif.h"
#include "wlan_hdd_hostapd.h"

#ifdef WLAN_FEATURE_LINK_LAYER_STATS

/**
 * struct hdd_ll_stats_context - hdd link layer stats context
 *
 * @request_id: userspace-assigned link layer stats request id
 * @request_bitmap: userspace-assigned link layer stats request bitmap
 * @response_event: LL stats request wait event
 */
struct hdd_ll_stats_context {
	uint32_t request_id;
	uint32_t request_bitmap;
	struct completion response_event;
	spinlock_t context_lock;
};

static struct hdd_ll_stats_context ll_stats_context;

#endif /* End of WLAN_FEATURE_LINK_LAYER_STATS */

/* 11B, 11G Rate table include Basic rate and Extended rate
 * The IDX field is the rate index
 * The HI field is the rate when RSSI is strong or being ignored
 *  (in this case we report actual rate)
 * The MID field is the rate when RSSI is moderate
 * (in this case we cap 11b rates at 5.5 and 11g rates at 24)
 * The LO field is the rate when RSSI is low
 *  (in this case we don't report rates, actual current rate used)
 */
static const struct {
	uint8_t beacon_rate_index;
	uint16_t supported_rate[4];
} supported_data_rate[] = {
/* IDX     HI  HM  LM LO (RSSI-based index */
	{
		2, {
			10, 10, 10, 0
		}
	}, {
		4, {
			20, 20, 10, 0
		}
	}, {
		11, {
			55, 20, 10, 0
		}
	}, {
		12, {
			60, 55, 20, 0
		}
	}, {
		18, {
			90, 55, 20, 0
		}
	}, {
		22, {
			110, 55, 20, 0
		}
	}, {
		24, {
			120, 90, 60, 0
		}
	}, {
		36, {
			180, 120, 60, 0
		}
	}, {
		44, {
			220, 180, 60, 0
		}
	}, {
		48, {
			240, 180, 90, 0
		}
	}, {
		66, {
			330, 180, 90, 0
		}
	}, {
		72, {
			360, 240, 90, 0
		}
	}, {
		96, {
			480, 240, 120, 0
		}
	}, {
		108, {
			540, 240, 120, 0
		}
	}
};
/* MCS Based rate table HT MCS parameters with Nss = 1 */
static struct index_data_rate_type supported_mcs_rate_nss1[] = {
/* MCS  L20   L40   S20  S40 */
	{0, {65, 135, 72, 150} },
	{1, {130, 270, 144, 300} },
	{2, {195, 405, 217, 450} },
	{3, {260, 540, 289, 600} },
	{4, {390, 810, 433, 900} },
	{5, {520, 1080, 578, 1200} },
	{6, {585, 1215, 650, 1350} },
	{7, {650, 1350, 722, 1500} }
};

/* HT MCS parameters with Nss = 2 */
static struct index_data_rate_type supported_mcs_rate_nss2[] = {
/* MCS  L20    L40   S20   S40 */
	{0, {130, 270, 144, 300} },
	{1, {260, 540, 289, 600} },
	{2, {390, 810, 433, 900} },
	{3, {520, 1080, 578, 1200} },
	{4, {780, 1620, 867, 1800} },
	{5, {1040, 2160, 1156, 2400} },
	{6, {1170, 2430, 1300, 2700} },
	{7, {1300, 2700, 1444, 3000} }
};

/* MCS Based VHT rate table MCS parameters with Nss = 1*/
static struct index_vht_data_rate_type supported_vht_mcs_rate_nss1[] = {
/* MCS  L80    S80     L40   S40    L20   S40*/
	{0, {293, 325}, {135, 150}, {65, 72} },
	{1, {585, 650}, {270, 300}, {130, 144} },
	{2, {878, 975}, {405, 450}, {195, 217} },
	{3, {1170, 1300}, {540, 600}, {260, 289} },
	{4, {1755, 1950}, {810, 900}, {390, 433} },
	{5, {2340, 2600}, {1080, 1200}, {520, 578} },
	{6, {2633, 2925}, {1215, 1350}, {585, 650} },
	{7, {2925, 3250}, {1350, 1500}, {650, 722} },
	{8, {3510, 3900}, {1620, 1800}, {780, 867} },
	{9, {3900, 4333}, {1800, 2000}, {780, 867} }
};

/*MCS parameters with Nss = 2*/
static struct index_vht_data_rate_type supported_vht_mcs_rate_nss2[] = {
/* MCS  L80    S80     L40   S40    L20   S40*/
	{0, {585, 650}, {270, 300}, {130, 144} },
	{1, {1170, 1300}, {540, 600}, {260, 289} },
	{2, {1755, 1950}, {810, 900}, {390, 433} },
	{3, {2340, 2600}, {1080, 1200}, {520, 578} },
	{4, {3510, 3900}, {1620, 1800}, {780, 867} },
	{5, {4680, 5200}, {2160, 2400}, {1040, 1156} },
	{6, {5265, 5850}, {2430, 2700}, {1170, 1300} },
	{7, {5850, 6500}, {2700, 3000}, {1300, 1444} },
	{8, {7020, 7800}, {3240, 3600}, {1560, 1733} },
	{9, {7800, 8667}, {3600, 4000}, {1560, 1733} }
};

/*array index ponints to MCS and array value points respective rssi*/
static int rssi_mcs_tbl[][10] = {
/*MCS 0   1     2   3    4    5    6    7    8    9*/
	{-82, -79, -77, -74, -70, -66, -65, -64, -59, -57},     /* 20 */
	{-79, -76, -74, -71, -67, -63, -62, -61, -56, -54},     /* 40 */
	{-76, -73, -71, -68, -64, -60, -59, -58, -53, -51} /* 80 */
};


#ifdef WLAN_FEATURE_LINK_LAYER_STATS

/**
 * put_wifi_rate_stat() - put wifi rate stats
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_rate_stat(tpSirWifiRateStat stats,
			       struct sk_buff *vendor_event)
{
	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_PREAMBLE,
		       stats->rate.preamble) ||
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_NSS,
		       stats->rate.nss) ||
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_BW,
		       stats->rate.bw) ||
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_MCS_INDEX,
		       stats->rate.rateMcsIdx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_BIT_RATE,
			stats->rate.bitrate) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_TX_MPDU,
			   stats->txMpdu) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RX_MPDU,
			   stats->rxMpdu) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_MPDU_LOST,
			   stats->mpduLost) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RETRIES,
			   stats->retries) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RETRIES_SHORT,
			   stats->retriesShort) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RETRIES_LONG,
			   stats->retriesLong)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	return true;
}

static tSirWifiPeerType wmi_to_sir_peer_type(enum wmi_peer_type type)
{
	switch (type) {
	case WMI_PEER_TYPE_DEFAULT:
		return WIFI_PEER_STA;
	case WMI_PEER_TYPE_BSS:
		return WIFI_PEER_AP;
	case WMI_PEER_TYPE_TDLS:
		return WIFI_PEER_TDLS;
	case WMI_PEER_TYPE_NAN_DATA:
		return WIFI_PEER_NAN;
	default:
		hdd_err("Cannot map wmi_peer_type %d to HAL peer type", type);
		return WIFI_PEER_INVALID;
	}
}

/**
 * put_wifi_peer_info() - put wifi peer info
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_peer_info(tpSirWifiPeerInfo stats,
			       struct sk_buff *vendor_event)
{
	u32 i = 0;
	tpSirWifiRateStat pRateStats;

	if (nla_put_u32
		    (vendor_event, QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_TYPE,
		    wmi_to_sir_peer_type(stats->type)) ||
	    nla_put(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_MAC_ADDRESS,
		       QDF_MAC_ADDR_SIZE, &stats->peerMacAddress.bytes[0]) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_CAPABILITIES,
			   stats->capabilities) ||
	    nla_put_u32(vendor_event,
			   QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_NUM_RATES,
			   stats->numRate)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		goto error;
	}

	if (stats->numRate) {
		struct nlattr *rateInfo;
		struct nlattr *rates;

		rateInfo = nla_nest_start(vendor_event,
					  QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_RATE_INFO);
		if (rateInfo == NULL)
			goto error;

		for (i = 0; i < stats->numRate; i++) {
			pRateStats = (tpSirWifiRateStat) ((uint8_t *)
							  stats->rateStats +
							  (i *
							   sizeof
							   (tSirWifiRateStat)));
			rates = nla_nest_start(vendor_event, i);
			if (rates == NULL)
				goto error;

			if (false ==
			    put_wifi_rate_stat(pRateStats, vendor_event)) {
				hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
				return false;
			}
			nla_nest_end(vendor_event, rates);
		}
		nla_nest_end(vendor_event, rateInfo);
	}

	return true;
error:
	return false;
}

/**
 * put_wifi_wmm_ac_stat() - put wifi wmm ac stats
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_wmm_ac_stat(tpSirWifiWmmAcStat stats,
				 struct sk_buff *vendor_event)
{
	if (nla_put_u32(vendor_event, QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_AC,
			stats->ac) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_TX_MPDU,
			stats->txMpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RX_MPDU,
			stats->rxMpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_TX_MCAST,
			stats->txMcast) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RX_MCAST,
			stats->rxMcast) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RX_AMPDU,
			stats->rxAmpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_TX_AMPDU,
			stats->txAmpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_MPDU_LOST,
			stats->mpduLost) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RETRIES,
			stats->retries) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RETRIES_SHORT,
			stats->retriesShort) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RETRIES_LONG,
			stats->retriesLong) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_TIME_MIN,
			stats->contentionTimeMin) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_TIME_MAX,
			stats->contentionTimeMax) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_TIME_AVG,
			stats->contentionTimeAvg) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_NUM_SAMPLES,
			stats->contentionNumSamples)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	return true;
}

/**
 * put_wifi_interface_info() - put wifi interface info
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_interface_info(tpSirWifiInterfaceInfo stats,
				    struct sk_buff *vendor_event)
{
	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_MODE,
			stats->mode) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_MAC_ADDR,
		    QDF_MAC_ADDR_SIZE, stats->macAddr.bytes) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_STATE,
			stats->state) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_ROAMING,
			stats->roaming) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_CAPABILITIES,
			stats->capabilities) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_SSID,
		    strlen(stats->ssid), stats->ssid) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_BSSID,
		    QDF_MAC_ADDR_SIZE, stats->bssid.bytes) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_AP_COUNTRY_STR,
		    WNI_CFG_COUNTRY_CODE_LEN, stats->apCountryStr) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_COUNTRY_STR,
		    WNI_CFG_COUNTRY_CODE_LEN, stats->countryStr)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	return true;
}

/**
 * put_wifi_iface_stats() - put wifi interface stats
 * @pWifiIfaceStat: Pointer to interface stats context
 * @num_peer: Number of peers
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_iface_stats(tpSirWifiIfaceStat pWifiIfaceStat,
				 u32 num_peers, struct sk_buff *vendor_event)
{
	int i = 0;
	struct nlattr *wmmInfo;
	struct nlattr *wmmStats;
	u64 average_tsf_offset;

	if (false == put_wifi_interface_info(&pWifiIfaceStat->info,
					     vendor_event)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;

	}

	average_tsf_offset =  pWifiIfaceStat->avg_bcn_spread_offset_high;
	average_tsf_offset =  (average_tsf_offset << 32) |
		pWifiIfaceStat->avg_bcn_spread_offset_low ;

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE_IFACE) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_NUM_PEERS,
			num_peers) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_BEACON_RX,
			pWifiIfaceStat->beaconRx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_MGMT_RX,
			pWifiIfaceStat->mgmtRx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_MGMT_ACTION_RX,
			pWifiIfaceStat->mgmtActionRx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_MGMT_ACTION_TX,
			pWifiIfaceStat->mgmtActionTx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RSSI_MGMT,
			pWifiIfaceStat->rssiMgmt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RSSI_DATA,
			pWifiIfaceStat->rssiData) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RSSI_ACK,
			pWifiIfaceStat->rssiAck) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_LEAKY_AP_DETECTED,
			pWifiIfaceStat->is_leaky_ap) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_LEAKY_AP_AVG_NUM_FRAMES_LEAKED,
			pWifiIfaceStat->avg_rx_frms_leaked) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_LEAKY_AP_GUARD_TIME,
			pWifiIfaceStat->rx_leak_window) ||
	    hdd_wlan_nla_put_u64(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_AVERAGE_TSF_OFFSET,
			average_tsf_offset)  ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RTS_SUCC_CNT,
			pWifiIfaceStat->rts_succ_cnt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RTS_FAIL_CNT,
			pWifiIfaceStat->rts_fail_cnt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_PPDU_SUCC_CNT,
			pWifiIfaceStat->ppdu_succ_cnt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_PPDU_FAIL_CNT,
			pWifiIfaceStat->ppdu_fail_cnt)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	wmmInfo = nla_nest_start(vendor_event,
				 QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_INFO);
	if (wmmInfo == NULL)
		return false;

	for (i = 0; i < WIFI_AC_MAX; i++) {
		wmmStats = nla_nest_start(vendor_event, i);
		if (wmmStats == NULL)
			return false;

		if (false ==
		    put_wifi_wmm_ac_stat(&pWifiIfaceStat->AccessclassStats[i],
					 vendor_event)) {
			hdd_err("put_wifi_wmm_ac_stat Fail");
			return false;
		}

		nla_nest_end(vendor_event, wmmStats);
	}
	nla_nest_end(vendor_event, wmmInfo);
	return true;
}

/**
 * hdd_map_device_to_ll_iface_mode() - map device to link layer interface mode
 * @deviceMode: Device mode
 *
 * Return: interface mode
 */
static tSirWifiInterfaceMode hdd_map_device_to_ll_iface_mode(int deviceMode)
{
	switch (deviceMode) {
	case QDF_STA_MODE:
		return WIFI_INTERFACE_STA;
	case QDF_SAP_MODE:
		return WIFI_INTERFACE_SOFTAP;
	case QDF_P2P_CLIENT_MODE:
		return WIFI_INTERFACE_P2P_CLIENT;
	case QDF_P2P_GO_MODE:
		return WIFI_INTERFACE_P2P_GO;
	case QDF_IBSS_MODE:
		return WIFI_INTERFACE_IBSS;
	default:
		/* Return Interface Mode as STA for all the unsupported modes */
		return WIFI_INTERFACE_STA;
	}
}

/**
 * hdd_get_interface_info() - get interface info
 * @pAdapter: Pointer to device adapter
 * @pInfo: Pointer to interface info
 *
 * Return: bool
 */
static bool hdd_get_interface_info(hdd_adapter_t *pAdapter,
				   tpSirWifiInterfaceInfo pInfo)
{
	uint8_t *staMac = NULL;
	hdd_station_ctx_t *pHddStaCtx;
	tHalHandle hHal = WLAN_HDD_GET_HAL_CTX(pAdapter);
	tpAniSirGlobal pMac = PMAC_STRUCT(hHal);

	pInfo->mode = hdd_map_device_to_ll_iface_mode(pAdapter->device_mode);

	qdf_copy_macaddr(&pInfo->macAddr, &pAdapter->macAddressCurrent);

	if (((QDF_STA_MODE == pAdapter->device_mode) ||
	     (QDF_P2P_CLIENT_MODE == pAdapter->device_mode) ||
	     (QDF_P2P_DEVICE_MODE == pAdapter->device_mode))) {
		pHddStaCtx = WLAN_HDD_GET_STATION_CTX_PTR(pAdapter);
		if (eConnectionState_NotConnected ==
		    pHddStaCtx->conn_info.connState) {
			pInfo->state = WIFI_DISCONNECTED;
		}
		if (eConnectionState_Connecting ==
		    pHddStaCtx->conn_info.connState) {
			hdd_err("Session ID %d, Connection is in progress",
				pAdapter->sessionId);
			pInfo->state = WIFI_ASSOCIATING;
		}
		if ((eConnectionState_Associated ==
		     pHddStaCtx->conn_info.connState)
		    && (false == pHddStaCtx->conn_info.uIsAuthenticated)) {
			staMac =
				(uint8_t *) &(pAdapter->macAddressCurrent.
					      bytes[0]);
			hdd_warn("client " MAC_ADDRESS_STR
				" is in the middle of WPS/EAPOL exchange.",
				MAC_ADDR_ARRAY(staMac));
			pInfo->state = WIFI_AUTHENTICATING;
		}
		if (eConnectionState_Associated ==
		    pHddStaCtx->conn_info.connState) {
			pInfo->state = WIFI_ASSOCIATED;
			qdf_copy_macaddr(&pInfo->bssid,
					 &pHddStaCtx->conn_info.bssId);
			qdf_mem_copy(pInfo->ssid,
				     pHddStaCtx->conn_info.SSID.SSID.ssId,
				     pHddStaCtx->conn_info.SSID.SSID.length);
			/*
			 * NULL Terminate the string
			 */
			pInfo->ssid[pHddStaCtx->conn_info.SSID.SSID.length] = 0;
		}
	}

	qdf_mem_copy(pInfo->countryStr,
		     pMac->scan.countryCodeCurrent, WNI_CFG_COUNTRY_CODE_LEN);

	qdf_mem_copy(pInfo->apCountryStr,
		     pMac->scan.countryCodeCurrent, WNI_CFG_COUNTRY_CODE_LEN);

	return true;
}

/**
 * hdd_link_layer_process_peer_stats() - This function is called after
 * @pAdapter: Pointer to device adapter
 * @more_data: More data
 * @pData: Pointer to stats data
 *
 * Receiving Link Layer Peer statistics from FW.This function converts
 * the firmware data to the NL data and sends the same to the kernel/upper
 * layers.
 *
 * Return: None
 */
static void hdd_link_layer_process_peer_stats(hdd_adapter_t *pAdapter,
					      u32 more_data,
					      tpSirWifiPeerStat pData)
{
	hdd_context_t *pHddCtx = WLAN_HDD_GET_CTX(pAdapter);
	tpSirWifiPeerStat pWifiPeerStat;
	tpSirWifiPeerInfo pWifiPeerInfo;
	struct sk_buff *vendor_event;
	int status, i;
	struct nlattr *peers;
	int numRate;

	ENTER();

	pWifiPeerStat = pData;

	status = wlan_hdd_validate_context(pHddCtx);
	if (0 != status)
		return;

	hdd_notice("LL_STATS_PEER_ALL : numPeers %u, more data = %u",
		   pWifiPeerStat->numPeers, more_data);

	/*
	 * Allocate a size of 4096 for the peer stats comprising
	 * each of size = sizeof (tSirWifiPeerInfo) + numRate *
	 * sizeof (tSirWifiRateStat).Each field is put with an
	 * NL attribute.The size of 4096 is considered assuming
	 * that number of rates shall not exceed beyond 50 with
	 * the sizeof (tSirWifiRateStat) being 32.
	 */
	vendor_event = cfg80211_vendor_cmd_alloc_reply_skb(pHddCtx->wiphy,
				LL_STATS_EVENT_BUF_SIZE);

	if (!vendor_event) {
		hdd_err("cfg80211_vendor_cmd_alloc_reply_skb failed");
		return;
	}

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE_PEER) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RESULTS_MORE_DATA,
			more_data) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_NUM_PEERS,
			pWifiPeerStat->numPeers)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");

		kfree_skb(vendor_event);
		return;
	}

	pWifiPeerInfo = (tpSirWifiPeerInfo) ((uint8_t *)
					     pWifiPeerStat->peerInfo);

	if (pWifiPeerStat->numPeers) {
		struct nlattr *peerInfo;
		peerInfo = nla_nest_start(vendor_event,
					  QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO);
		if (peerInfo == NULL) {
			hdd_err("nla_nest_start failed");
			kfree_skb(vendor_event);
			return;
		}

		for (i = 1; i <= pWifiPeerStat->numPeers; i++) {
			peers = nla_nest_start(vendor_event, i);
			if (peers == NULL) {
				hdd_err("nla_nest_start failed");
				kfree_skb(vendor_event);
				return;
			}

			numRate = pWifiPeerInfo->numRate;

			if (false ==
			    put_wifi_peer_info(pWifiPeerInfo, vendor_event)) {
				hdd_err("put_wifi_peer_info fail");
				kfree_skb(vendor_event);
				return;
			}

			pWifiPeerInfo = (tpSirWifiPeerInfo) ((uint8_t *)
							     pWifiPeerStat->
							     peerInfo +
							     (i *
							      sizeof
							      (tSirWifiPeerInfo))
							     +
							     (numRate *
							      sizeof
							      (tSirWifiRateStat)));
			nla_nest_end(vendor_event, peers);
		}
		nla_nest_end(vendor_event, peerInfo);
	}
	cfg80211_vendor_cmd_reply(vendor_event);
	EXIT();
	return;
}

/**
 * hdd_link_layer_process_iface_stats() - This function is called after
 * @pAdapter: Pointer to device adapter
 * @pData: Pointer to stats data
 * @num_peers: Number of peers
 *
 * Receiving Link Layer Interface statistics from FW.This function converts
 * the firmware data to the NL data and sends the same to the kernel/upper
 * layers.
 *
 * Return: None
 */
static void hdd_link_layer_process_iface_stats(hdd_adapter_t *pAdapter,
					       tpSirWifiIfaceStat pData,
					       u32 num_peers)
{
	tpSirWifiIfaceStat pWifiIfaceStat;
	struct sk_buff *vendor_event;
	hdd_context_t *pHddCtx = WLAN_HDD_GET_CTX(pAdapter);
	int status;

	ENTER();

	pWifiIfaceStat = pData;

	status = wlan_hdd_validate_context(pHddCtx);
	if (0 != status)
		return;

	/*
	 * Allocate a size of 4096 for the interface stats comprising
	 * sizeof (tpSirWifiIfaceStat).The size of 4096 is considered
	 * assuming that all these fit with in the limit.Please take
	 * a call on the limit based on the data requirements on
	 * interface statistics.
	 */
	vendor_event = cfg80211_vendor_cmd_alloc_reply_skb(pHddCtx->wiphy,
				LL_STATS_EVENT_BUF_SIZE);

	if (!vendor_event) {
		hdd_err("cfg80211_vendor_cmd_alloc_reply_skb failed");
		return;
	}

	hdd_notice("WMI_LINK_STATS_IFACE Data");

	if (false == hdd_get_interface_info(pAdapter, &pWifiIfaceStat->info)) {
		hdd_err("hdd_get_interface_info get fail");
		kfree_skb(vendor_event);
		return;
	}

	if (false ==
	    put_wifi_iface_stats(pWifiIfaceStat, num_peers, vendor_event)) {
		hdd_err("put_wifi_iface_stats fail");
		kfree_skb(vendor_event);
		return;
	}

	cfg80211_vendor_cmd_reply(vendor_event);
	EXIT();
	return;
}

/**
 * hdd_llstats_radio_fill_channels() - radio stats fill channels
 * @adapter: Pointer to device adapter
 * @radiostat: Pointer to stats data
 * @vendor_event: vendor event
 *
 * Return: 0 on success; errno on failure
 */
static int hdd_llstats_radio_fill_channels(hdd_adapter_t *adapter,
					   tSirWifiRadioStat *radiostat,
					   struct sk_buff *vendor_event)
{
	tSirWifiChannelStats *channel_stats;
	struct nlattr *chlist;
	struct nlattr *chinfo;
	int i;

	chlist = nla_nest_start(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CH_INFO);
	if (chlist == NULL) {
		hdd_err("nla_nest_start failed");
		return -EINVAL;
	}

	for (i = 0; i < radiostat->numChannels; i++) {
		channel_stats = (tSirWifiChannelStats *) ((uint8_t *)
				     radiostat->channels +
				     (i * sizeof(tSirWifiChannelStats)));

		chinfo = nla_nest_start(vendor_event, i);
		if (chinfo == NULL) {
			hdd_err("nla_nest_start failed");
			return -EINVAL;
		}

		if (nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_WIDTH,
				channel_stats->channel.width) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_CENTER_FREQ,
				channel_stats->channel.centerFreq) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_CENTER_FREQ0,
				channel_stats->channel.centerFreq0) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_CENTER_FREQ1,
				channel_stats->channel.centerFreq1) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_ON_TIME,
				channel_stats->onTime) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_CCA_BUSY_TIME,
				channel_stats->ccaBusyTime)) {
			hdd_err("nla_put failed");
			return -EINVAL;
		}
		nla_nest_end(vendor_event, chinfo);
	}
	nla_nest_end(vendor_event, chlist);

	return 0;
}

/**
 * hdd_llstats_post_radio_stats() - post radio stats
 * @adapter: Pointer to device adapter
 * @more_data: More data
 * @radiostat: Pointer to stats data
 * @num_radio: Number of radios
 *
 * Return: 0 on success; errno on failure
 */
static int hdd_llstats_post_radio_stats(hdd_adapter_t *adapter,
					u32 more_data,
					tSirWifiRadioStat *radiostat,
					u32 num_radio)
{
	struct sk_buff *vendor_event;
	hdd_context_t *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	int ret;

	/*
	 * Allocate a size of 4096 for the Radio stats comprising
	 * sizeof (tSirWifiRadioStat) + numChannels * sizeof
	 * (tSirWifiChannelStats).Each channel data is put with an
	 * NL attribute.The size of 4096 is considered assuming that
	 * number of channels shall not exceed beyond  60 with the
	 * sizeof (tSirWifiChannelStats) being 24 bytes.
	 */

	vendor_event = cfg80211_vendor_cmd_alloc_reply_skb(
					hdd_ctx->wiphy,
					LL_STATS_EVENT_BUF_SIZE);

	if (!vendor_event) {
		hdd_err("cfg80211_vendor_cmd_alloc_reply_skb failed");
		return -ENOMEM;
	}

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE_RADIO) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RESULTS_MORE_DATA,
			more_data) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_NUM_RADIOS,
			num_radio) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ID,
			radiostat->radio) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME,
			radiostat->onTime) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_TX_TIME,
			radiostat->txTime) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_RX_TIME,
			radiostat->rxTime) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_SCAN,
			radiostat->onTimeScan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_NBD,
			radiostat->onTimeNbd) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_GSCAN,
			radiostat->onTimeGscan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_ROAM_SCAN,
			radiostat->onTimeRoamScan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_PNO_SCAN,
			radiostat->onTimePnoScan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_HS20,
			radiostat->onTimeHs20) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_NUM_TX_LEVELS,
			radiostat->total_num_tx_power_levels)    ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_NUM_CHANNELS,
			radiostat->numChannels)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		goto failure;
	}

	if (radiostat->total_num_tx_power_levels) {
		if (nla_put(vendor_event,
			    QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_TX_TIME_PER_LEVEL,
			    sizeof(u32) *
			    radiostat->total_num_tx_power_levels,
			    radiostat->tx_time_per_power_level)) {
			hdd_err("nla_put fail");
			goto failure;
		}
	}

	if (radiostat->numChannels) {
		ret = hdd_llstats_radio_fill_channels(adapter, radiostat,
						      vendor_event);
		if (ret)
			goto failure;
	}

	cfg80211_vendor_cmd_reply(vendor_event);
	return 0;

failure:
	kfree_skb(vendor_event);
	return -EINVAL;
}

/**
 * hdd_link_layer_process_radio_stats() - This function is called after
 * @pAdapter: Pointer to device adapter
 * @more_data: More data
 * @pData: Pointer to stats data
 * @num_radios: Number of radios
 *
 * Receiving Link Layer Radio statistics from FW.This function converts
 * the firmware data to the NL data and sends the same to the kernel/upper
 * layers.
 *
 * Return: None
 */
static void hdd_link_layer_process_radio_stats(hdd_adapter_t *pAdapter,
					       u32 more_data,
					       tpSirWifiRadioStat pData,
					       u32 num_radio)
{
	int status, i, nr, ret;
	tSirWifiRadioStat *pWifiRadioStat = pData;
	hdd_context_t *pHddCtx = WLAN_HDD_GET_CTX(pAdapter);

	ENTER();

	status = wlan_hdd_validate_context(pHddCtx);
	if (0 != status)
		return;

	hdd_notice("LL_STATS_RADIO: number of radios: %u", num_radio);

	for (i = 0; i < num_radio; i++) {
		hdd_notice("LL_STATS_RADIO"
		       " radio: %u onTime: %u txTime: %u rxTime: %u"
		       " onTimeScan: %u onTimeNbd: %u"
		       " onTimeGscan: %u onTimeRoamScan: %u"
		       " onTimePnoScan: %u  onTimeHs20: %u"
		       " numChannels: %u total_num_tx_pwr_levels: %u",
		       pWifiRadioStat->radio, pWifiRadioStat->onTime,
		       pWifiRadioStat->txTime, pWifiRadioStat->rxTime,
		       pWifiRadioStat->onTimeScan, pWifiRadioStat->onTimeNbd,
		       pWifiRadioStat->onTimeGscan,
		       pWifiRadioStat->onTimeRoamScan,
		       pWifiRadioStat->onTimePnoScan,
		       pWifiRadioStat->onTimeHs20, pWifiRadioStat->numChannels,
		       pWifiRadioStat->total_num_tx_power_levels);
		pWifiRadioStat++;
	}

	pWifiRadioStat = pData;
	for (nr = 0; nr < num_radio; nr++) {
		ret = hdd_llstats_post_radio_stats(pAdapter, more_data,
						   pWifiRadioStat, num_radio);
		if (ret)
			return;

		pWifiRadioStat++;
	}
	EXIT();
	return;
}

/**
 * wlan_hdd_cfg80211_link_layer_stats_callback() - This function is called
 * @ctx: Pointer to hdd context
 * @indType: Indication type
 * @pRsp: Pointer to response
 *
 * After receiving Link Layer indications from FW.This callback converts the
 * firmware data to the NL data and send the same to the kernel/upper layers.
 *
 * Return: None
 */
void wlan_hdd_cfg80211_link_layer_stats_callback(void *ctx,
							int indType, void *pRsp)
{
	hdd_context_t *pHddCtx = (hdd_context_t *) ctx;
	struct hdd_ll_stats_context *context;
	hdd_adapter_t *pAdapter = NULL;
	tpSirLLStatsResults linkLayerStatsResults = (tpSirLLStatsResults) pRsp;
	int status;

	status = wlan_hdd_validate_context(pHddCtx);
	if (status)
		return;

	pAdapter = hdd_get_adapter_by_vdev(pHddCtx,
					   linkLayerStatsResults->ifaceId);

	if (NULL == pAdapter) {
		hdd_err("vdev_id %d does not exist with host",
			linkLayerStatsResults->ifaceId);
		return;
	}

	hdd_notice("Link Layer Indication indType: %d", indType);

	switch (indType) {
	case SIR_HAL_LL_STATS_RESULTS_RSP:
	{
		hdd_notice("LL_STATS RESP paramID = 0x%x, ifaceId = %u, respId= %u , moreResultToFollow = %u, num radio = %u result = %p",
			linkLayerStatsResults->paramId,
			linkLayerStatsResults->ifaceId,
			linkLayerStatsResults->rspId,
			linkLayerStatsResults->moreResultToFollow,
			linkLayerStatsResults->num_radio,
			linkLayerStatsResults->results);

		context = &ll_stats_context;
		spin_lock(&context->context_lock);
		/* validate response received from target */
		if ((context->request_id != linkLayerStatsResults->rspId) ||
		  !(context->request_bitmap & linkLayerStatsResults->paramId)) {
			spin_unlock(&context->context_lock);
			hdd_err("Error : Request id %d response id %d request bitmap 0x%x response bitmap 0x%x",
			context->request_id, linkLayerStatsResults->rspId,
			context->request_bitmap, linkLayerStatsResults->paramId);
			return;
		}
		spin_unlock(&context->context_lock);

		if (linkLayerStatsResults->
		    paramId & WMI_LINK_STATS_RADIO) {
			hdd_link_layer_process_radio_stats(pAdapter,
				linkLayerStatsResults->moreResultToFollow,
				(tpSirWifiRadioStat)linkLayerStatsResults->results,
				linkLayerStatsResults->num_radio);

			spin_lock(&context->context_lock);
			if (!linkLayerStatsResults->moreResultToFollow)
				context->request_bitmap &= ~(WMI_LINK_STATS_RADIO);
			spin_unlock(&context->context_lock);

		} else if (linkLayerStatsResults->
			   paramId & WMI_LINK_STATS_IFACE) {
			hdd_link_layer_process_iface_stats(pAdapter,
				(tpSirWifiIfaceStat)linkLayerStatsResults->results,
				linkLayerStatsResults->num_peers);

			spin_lock(&context->context_lock);
			/* Firmware doesn't send peerstats event if no peers are
			 * connected. HDD should not wait for any peerstats in
			 * this case and return the status to middleware after
			 * receiving iface stats
			 */
			if (!linkLayerStatsResults->num_peers)
				context->request_bitmap &=
					~(WMI_LINK_STATS_ALL_PEER);
			context->request_bitmap &= ~(WMI_LINK_STATS_IFACE);
			spin_unlock(&context->context_lock);

		} else if (linkLayerStatsResults->
			   paramId & WMI_LINK_STATS_ALL_PEER) {
			hdd_link_layer_process_peer_stats(pAdapter,
				linkLayerStatsResults->moreResultToFollow,
				(tpSirWifiPeerStat)linkLayerStatsResults->results);

			spin_lock(&context->context_lock);
			if (!linkLayerStatsResults->moreResultToFollow)
				context->request_bitmap &= ~(WMI_LINK_STATS_ALL_PEER);
			spin_unlock(&context->context_lock);

		} else {
			hdd_err("INVALID LL_STATS_NOTIFY RESPONSE");
		}

		spin_lock(&context->context_lock);
		/* complete response event if all requests are completed */
		if (0 == context->request_bitmap)
			complete(&context->response_event);
		spin_unlock(&context->context_lock);

		break;
	}
	default:
		hdd_err("invalid event type %d", indType);
		break;
	}

	return;
}

void hdd_lost_link_info_cb(void *context,
				  struct sir_lost_link_info *lost_link_info)
{
	hdd_context_t *hdd_ctx = (hdd_context_t *)context;
	int status;
	hdd_adapter_t *adapter;

	status = wlan_hdd_validate_context(hdd_ctx);
	if (0 != status)
		return;

	if (NULL == lost_link_info) {
		hdd_err("lost_link_info is NULL");
		return;
	}

	adapter = hdd_get_adapter_by_vdev(hdd_ctx, lost_link_info->vdev_id);
	if (NULL == adapter) {
		hdd_err("invalid adapter");
		return;
	}

	adapter->rssi_on_disconnect = lost_link_info->rssi;
	hdd_info("rssi on disconnect %d", adapter->rssi_on_disconnect);
}

const struct
nla_policy
	qca_wlan_vendor_ll_set_policy[QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_MPDU_SIZE_THRESHOLD] = {
						.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_AGGRESSIVE_STATS_GATHERING] = {
						.type = NLA_U32},
};

/**
 * __wlan_hdd_cfg80211_ll_stats_set() - set link layer stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int
__wlan_hdd_cfg80211_ll_stats_set(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data,
				   int data_len)
{
	int status;
	struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_MAX + 1];
	tSirLLStatsSetReq LinkLayerStatsSetReq;
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *pAdapter = WLAN_HDD_GET_PRIV_PTR(dev);
	hdd_context_t *pHddCtx = wiphy_priv(wiphy);

	ENTER_DEV(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("Command not allowed in FTM mode");
		return -EPERM;
	}

	status = wlan_hdd_validate_context(pHddCtx);
	if (0 != status)
		return -EINVAL;

	if (nla_parse(tb_vendor, QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_MAX,
		      (struct nlattr *)data,
		      data_len, qca_wlan_vendor_ll_set_policy)) {
		hdd_err("maximum attribute not present");
		return -EINVAL;
	}

	if (!tb_vendor
	    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_MPDU_SIZE_THRESHOLD]) {
		hdd_err("MPDU size Not present");
		return -EINVAL;
	}

	if (!tb_vendor
	    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_AGGRESSIVE_STATS_GATHERING]) {
		hdd_err("Stats Gathering Not Present");
		return -EINVAL;
	}

	/* Shall take the request Id if the Upper layers pass. 1 For now. */
	LinkLayerStatsSetReq.reqId = 1;

	LinkLayerStatsSetReq.mpduSizeThreshold =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_MPDU_SIZE_THRESHOLD]);

	LinkLayerStatsSetReq.aggressiveStatisticsGathering =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_AGGRESSIVE_STATS_GATHERING]);

	LinkLayerStatsSetReq.staId = pAdapter->sessionId;

	hdd_notice("LL_STATS_SET reqId = %d, staId = %d, mpduSizeThreshold = %d, Statistics Gathering = %d",
		LinkLayerStatsSetReq.reqId, LinkLayerStatsSetReq.staId,
		LinkLayerStatsSetReq.mpduSizeThreshold,
		LinkLayerStatsSetReq.aggressiveStatisticsGathering);

	if (QDF_STATUS_SUCCESS != sme_ll_stats_set_req(pHddCtx->hHal,
						       &LinkLayerStatsSetReq)) {
		hdd_err("sme_ll_stats_set_req Failed");
		return -EINVAL;
	}

	pAdapter->isLinkLayerStatsSet = 1;
	EXIT();
	return 0;
}

/**
 * wlan_hdd_cfg80211_ll_stats_set() - set ll stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: 0 if success, non-zero for failure
 */
int wlan_hdd_cfg80211_ll_stats_set(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret = 0;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ll_stats_set(wiphy, wdev, data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

const struct
nla_policy
	qca_wlan_vendor_ll_get_policy[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_MAX + 1] = {
	/* Unsigned 32bit value provided by the caller issuing the GET stats
	 * command. When reporting
	 * the stats results, the driver uses the same value to indicate
	 * which GET request the results
	 * correspond to.
	 */
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_ID] = {.type = NLA_U32},

	/* Unsigned 32bit value . bit mask to identify what statistics are
	   requested for retrieval */
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_MASK] = {.type = NLA_U32}
};

/**
 * __wlan_hdd_cfg80211_ll_stats_get() - get link layer stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int
__wlan_hdd_cfg80211_ll_stats_get(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data,
				   int data_len)
{
	unsigned long rc;
	struct hdd_ll_stats_context *context;
	hdd_context_t *pHddCtx = wiphy_priv(wiphy);
	struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_MAX + 1];
	tSirLLStatsGetReq LinkLayerStatsGetReq;
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *pAdapter = WLAN_HDD_GET_PRIV_PTR(dev);
	hdd_station_ctx_t *hddstactx = WLAN_HDD_GET_STATION_CTX_PTR(pAdapter);
	int status;

	/* ENTER() intentionally not used in a frequently invoked API */

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("Command not allowed in FTM mode");
		return -EPERM;
	}

	status = wlan_hdd_validate_context(pHddCtx);
	if (0 != status)
		return -EINVAL;

	if (!pAdapter->isLinkLayerStatsSet) {
		hdd_warn("isLinkLayerStatsSet: %d",
			 pAdapter->isLinkLayerStatsSet);
		return -EINVAL;
	}

	if (hddstactx->hdd_ReassocScenario) {
		hdd_err("Roaming in progress, so unable to proceed this request");
		return -EBUSY;
	}

	if (nla_parse(tb_vendor, QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_MAX,
		      (struct nlattr *)data,
		      data_len, qca_wlan_vendor_ll_get_policy)) {
		hdd_err("max attribute not present");
		return -EINVAL;
	}

	if (!tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_ID]) {
		hdd_err("Request Id Not present");
		return -EINVAL;
	}

	if (!tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_MASK]) {
		hdd_err("Req Mask Not present");
		return -EINVAL;
	}

	LinkLayerStatsGetReq.reqId =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_ID]);
	LinkLayerStatsGetReq.paramIdMask =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_MASK]);

	LinkLayerStatsGetReq.staId = pAdapter->sessionId;

	context = &ll_stats_context;
	spin_lock(&context->context_lock);
	context->request_id = LinkLayerStatsGetReq.reqId;
	context->request_bitmap = LinkLayerStatsGetReq.paramIdMask;
	INIT_COMPLETION(context->response_event);
	spin_unlock(&context->context_lock);

	if (QDF_STATUS_SUCCESS != sme_ll_stats_get_req(pHddCtx->hHal,
						       &LinkLayerStatsGetReq)) {
		hdd_err("sme_ll_stats_get_req Failed");
		return -EINVAL;
	}

	rc = wait_for_completion_timeout(&context->response_event,
			msecs_to_jiffies(WLAN_WAIT_TIME_LL_STATS));
	if (!rc) {
		hdd_err("Target response timed out request id %d request bitmap 0x%x",
			context->request_id, context->request_bitmap);
		return -ETIMEDOUT;
	}
	EXIT();
	return 0;
}

/**
 * wlan_hdd_cfg80211_ll_stats_get() - get ll stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: 0 if success, non-zero for failure
 */
int wlan_hdd_cfg80211_ll_stats_get(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data,
				int data_len)
{
	int ret = 0;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ll_stats_get(wiphy, wdev, data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

const struct
nla_policy
	qca_wlan_vendor_ll_clr_policy[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_REQ_MASK] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_REQ] = {.type = NLA_U8},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_RSP_MASK] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_RSP] = {.type = NLA_U8},
};

/**
 * __wlan_hdd_cfg80211_ll_stats_clear() - clear link layer stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int
__wlan_hdd_cfg80211_ll_stats_clear(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data,
				    int data_len)
{
	hdd_context_t *pHddCtx = wiphy_priv(wiphy);
	struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_MAX + 1];
	tSirLLStatsClearReq LinkLayerStatsClearReq;
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *pAdapter = WLAN_HDD_GET_PRIV_PTR(dev);
	u32 statsClearReqMask;
	u8 stopReq;
	int status;
	struct sk_buff *temp_skbuff;

	ENTER_DEV(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("Command not allowed in FTM mode");
		return -EPERM;
	}

	status = wlan_hdd_validate_context(pHddCtx);
	if (0 != status)
		return -EINVAL;

	if (!pAdapter->isLinkLayerStatsSet) {
		hdd_alert("isLinkLayerStatsSet : %d",
			  pAdapter->isLinkLayerStatsSet);
		return -EINVAL;
	}

	if (nla_parse(tb_vendor, QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_MAX,
		      (struct nlattr *)data,
		      data_len, qca_wlan_vendor_ll_clr_policy)) {
		hdd_err("STATS_CLR_MAX is not present");
		return -EINVAL;
	}

	if (!tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_REQ_MASK] ||
	    !tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_REQ]) {
		hdd_err("Error in LL_STATS CLR CONFIG PARA");
		return -EINVAL;
	}

	statsClearReqMask = LinkLayerStatsClearReq.statsClearReqMask =
				    nla_get_u32(tb_vendor
						[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_REQ_MASK]);

	stopReq = LinkLayerStatsClearReq.stopReq =
			  nla_get_u8(tb_vendor
				     [QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_REQ]);

	/*
	 * Shall take the request Id if the Upper layers pass. 1 For now.
	 */
	LinkLayerStatsClearReq.reqId = 1;

	LinkLayerStatsClearReq.staId = pAdapter->sessionId;

	hdd_notice("LL_STATS_CLEAR reqId = %d, staId = %d, statsClearReqMask = 0x%X, stopReq = %d",
		LinkLayerStatsClearReq.reqId,
		LinkLayerStatsClearReq.staId,
		LinkLayerStatsClearReq.statsClearReqMask,
		LinkLayerStatsClearReq.stopReq);

	if (QDF_STATUS_SUCCESS == sme_ll_stats_clear_req(pHddCtx->hHal,
					&LinkLayerStatsClearReq)) {
		temp_skbuff = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
								  2 *
								  sizeof(u32) +
								  2 *
								  NLMSG_HDRLEN);
		if (temp_skbuff != NULL) {
			if (nla_put_u32(temp_skbuff,
					QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_RSP_MASK,
					statsClearReqMask) ||
			    nla_put_u32(temp_skbuff,
					QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_RSP,
					stopReq)) {
				hdd_err("LL_STATS_CLR put fail");
				kfree_skb(temp_skbuff);
				return -EINVAL;
			}

			/* If the ask is to stop the stats collection
			 * as part of clear (stopReq = 1), ensure
			 * that no further requests of get go to the
			 * firmware by having isLinkLayerStatsSet set
			 * to 0.  However it the stopReq as part of
			 * the clear request is 0, the request to get
			 * the statistics are honoured as in this case
			 * the firmware is just asked to clear the
			 * statistics.
			 */
			if (stopReq == 1)
				pAdapter->isLinkLayerStatsSet = 0;

			return cfg80211_vendor_cmd_reply(temp_skbuff);
		}
		EXIT();
		return -ENOMEM;
	}

	return -EINVAL;
}

/**
 * wlan_hdd_cfg80211_ll_stats_clear() - clear ll stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: 0 if success, non-zero for failure
 */
int wlan_hdd_cfg80211_ll_stats_clear(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret = 0;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_ll_stats_clear(wiphy, wdev, data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

#endif /* WLAN_FEATURE_LINK_LAYER_STATS */

#ifdef WLAN_FEATURE_STATS_EXT
/**
 * __wlan_hdd_cfg80211_stats_ext_request() - ext stats request
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int __wlan_hdd_cfg80211_stats_ext_request(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 const void *data,
						 int data_len)
{
	tStatsExtRequestReq stats_ext_req;
	struct net_device *dev = wdev->netdev;
	hdd_adapter_t *pAdapter = WLAN_HDD_GET_PRIV_PTR(dev);
	int ret_val;
	QDF_STATUS status;
	hdd_context_t *hdd_ctx = wiphy_priv(wiphy);

	ENTER_DEV(dev);

	ret_val = wlan_hdd_validate_context(hdd_ctx);
	if (ret_val)
		return ret_val;

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("Command not allowed in FTM mode");
		return -EPERM;
	}

	stats_ext_req.request_data_len = data_len;
	stats_ext_req.request_data = (void *)data;

	status = sme_stats_ext_request(pAdapter->sessionId, &stats_ext_req);

	if (QDF_STATUS_SUCCESS != status)
		ret_val = -EINVAL;

	return ret_val;
}

/**
 * wlan_hdd_cfg80211_stats_ext_request() - ext stats request
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
int wlan_hdd_cfg80211_stats_ext_request(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_stats_ext_request(wiphy, wdev,
						    data, data_len);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * wlan_hdd_cfg80211_stats_ext_callback() - ext stats callback
 * @ctx: Pointer to HDD context
 * @msg: Message received
 *
 * Return: nothing
 */
void wlan_hdd_cfg80211_stats_ext_callback(void *ctx,
						 tStatsExtEvent *msg)
{

	hdd_context_t *pHddCtx = (hdd_context_t *) ctx;
	struct sk_buff *vendor_event;
	int status;
	int ret_val;
	tStatsExtEvent *data = msg;
	hdd_adapter_t *pAdapter = NULL;

	status = wlan_hdd_validate_context(pHddCtx);
	if (status)
		return;

	pAdapter = hdd_get_adapter_by_vdev(pHddCtx, data->vdev_id);

	if (NULL == pAdapter) {
		hdd_err("vdev_id %d does not exist with host", data->vdev_id);
		return;
	}

	vendor_event = cfg80211_vendor_event_alloc(pHddCtx->wiphy,
						   NULL,
						   data->event_data_len +
						   sizeof(uint32_t) +
						   NLMSG_HDRLEN + NLMSG_HDRLEN,
						   QCA_NL80211_VENDOR_SUBCMD_STATS_EXT_INDEX,
						   GFP_KERNEL);

	if (!vendor_event) {
		hdd_err("cfg80211_vendor_event_alloc failed");
		return;
	}

	ret_val = nla_put_u32(vendor_event, QCA_WLAN_VENDOR_ATTR_IFINDEX,
			      pAdapter->dev->ifindex);
	if (ret_val) {
		hdd_err("QCA_WLAN_VENDOR_ATTR_IFINDEX put fail");
		kfree_skb(vendor_event);

		return;
	}

	ret_val = nla_put(vendor_event, QCA_WLAN_VENDOR_ATTR_STATS_EXT,
			  data->event_data_len, data->event_data);

	if (ret_val) {
		hdd_err("QCA_WLAN_VENDOR_ATTR_STATS_EXT put fail");
		kfree_skb(vendor_event);

		return;
	}

	cfg80211_vendor_event(vendor_event, GFP_KERNEL);

}
#endif /* End of WLAN_FEATURE_STATS_EXT */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)) && !defined(WITH_BACKPORTS)
static inline void wlan_hdd_fill_station_info_signal(struct station_info
						     *sinfo)
{
	sinfo->filled |= STATION_INFO_SIGNAL;
}
#else
static inline void wlan_hdd_fill_station_info_signal(struct station_info
						     *sinfo)
{
	sinfo->filled |= BIT(NL80211_STA_INFO_SIGNAL);
}
#endif

/**
 * __wlan_hdd_cfg80211_get_station() - get station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
static int __wlan_hdd_cfg80211_get_station(struct wiphy *wiphy,
					   struct net_device *dev,
					   const uint8_t *mac,
					   struct station_info *sinfo)
{
	hdd_adapter_t *pAdapter = WLAN_HDD_GET_PRIV_PTR(dev);
	hdd_station_ctx_t *pHddStaCtx = WLAN_HDD_GET_STATION_CTX_PTR(pAdapter);
	int ssidlen = pHddStaCtx->conn_info.SSID.SSID.length;
	uint8_t rate_flags;
	uint8_t mcs_index;

	hdd_context_t *pHddCtx = (hdd_context_t *) wiphy_priv(wiphy);
	struct hdd_config *pCfg = pHddCtx->config;

	uint8_t OperationalRates[CSR_DOT11_SUPPORTED_RATES_MAX];
	uint32_t ORLeng = CSR_DOT11_SUPPORTED_RATES_MAX;
	uint8_t ExtendedRates[CSR_DOT11_EXTENDED_SUPPORTED_RATES_MAX];
	uint32_t ERLeng = CSR_DOT11_EXTENDED_SUPPORTED_RATES_MAX;
	uint8_t MCSRates[SIZE_OF_BASIC_MCS_SET];
	uint32_t MCSLeng = SIZE_OF_BASIC_MCS_SET;
	uint16_t maxRate = 0;
	int8_t snr = 0;
	uint16_t myRate;
	uint16_t currentRate = 0;
	uint8_t maxSpeedMCS = 0;
	uint8_t maxMCSIdx = 0;
	uint8_t rateFlag = 1;
	uint8_t i, j, rssidx;
	uint8_t nss = 1;
	int status, mode = 0, maxHtIdx;
	struct index_vht_data_rate_type *supported_vht_mcs_rate;
	struct index_data_rate_type *supported_mcs_rate;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
	bool rssi_stats_valid = false;
#endif

	uint32_t vht_mcs_map;
	enum eDataRate11ACMaxMcs vhtMaxMcs;
	int32_t rcpi_value;

	ENTER_DEV(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_session_id(pAdapter->sessionId)) {
		hdd_err("invalid session id: %d", pAdapter->sessionId);
		return -EINVAL;
	}

	if ((eConnectionState_Associated != pHddStaCtx->conn_info.connState) ||
	    (0 == ssidlen)) {
		hdd_notice("Not associated or Invalid ssidlen, %d",
			ssidlen);
		/*To keep GUI happy */
		return 0;
	}

	if (true == pHddStaCtx->hdd_ReassocScenario) {
		hdd_notice("Roaming is in progress, cannot continue with this request");
		/*
		 * supplicant reports very low rssi to upper layer
		 * and handover happens to cellular.
		 * send the cached rssi when get_station
		 */
		sinfo->signal = pAdapter->rssi;
		wlan_hdd_fill_station_info_signal(sinfo);
		return 0;
	}

	status = wlan_hdd_validate_context(pHddCtx);

	if (0 != status)
		return status;

	if (pHddCtx->rcpi_enabled)
		wlan_hdd_get_rcpi(pAdapter, (uint8_t *)mac, &rcpi_value,
				  RCPI_MEASUREMENT_TYPE_AVG_MGMT);

	wlan_hdd_get_station_stats(pAdapter);
	sinfo->signal = pAdapter->hdd_stats.summary_stat.rssi;
	snr = pAdapter->hdd_stats.summary_stat.snr;
	hdd_info("snr: %d, rssi: %d",
		pAdapter->hdd_stats.summary_stat.snr,
		pAdapter->hdd_stats.summary_stat.rssi);
	pHddStaCtx->conn_info.signal = sinfo->signal;
	pHddStaCtx->conn_info.noise =
		pHddStaCtx->conn_info.signal - snr;

	wlan_hdd_fill_station_info_signal(sinfo);

	/*
	 * we notify connect to lpass here instead of during actual
	 * connect processing because rssi info is not accurate during
	 * actual connection.  lpass will ensure the notification is
	 * only processed once per association.
	 */
	hdd_lpass_notify_connect(pAdapter);

	rate_flags = pAdapter->hdd_stats.ClassA_stat.tx_rate_flags;
	mcs_index = pAdapter->hdd_stats.ClassA_stat.mcs_index;

	/* convert to the UI units of 100kbps */
	myRate = pAdapter->hdd_stats.ClassA_stat.tx_rate * 5;
	if (!(rate_flags & eHAL_TX_RATE_LEGACY)) {
		nss = pAdapter->hdd_stats.ClassA_stat.rx_frag_cnt;

		if (eHDD_LINK_SPEED_REPORT_ACTUAL == pCfg->reportMaxLinkSpeed) {
			/* Get current rate flags if report actual */
			rate_flags =
				pAdapter->hdd_stats.ClassA_stat.
				promiscuous_rx_frag_cnt;
		}

		if (mcs_index == INVALID_MCS_IDX)
			mcs_index = 0;
	}

	hdd_info("RSSI %d, RLMS %u, rate %d, rssi high %d, rssi mid %d, rssi low %d, rate_flags 0x%x, MCS %d",
		 sinfo->signal, pCfg->reportMaxLinkSpeed, myRate,
		 (int)pCfg->linkSpeedRssiHigh, (int)pCfg->linkSpeedRssiMid,
		 (int)pCfg->linkSpeedRssiLow, (int)rate_flags, (int)mcs_index);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || defined(WITH_BACKPORTS)
	/* assume basic BW. anything else will override this later */
	sinfo->txrate.bw = RATE_INFO_BW_20;
#endif

	if (eHDD_LINK_SPEED_REPORT_ACTUAL != pCfg->reportMaxLinkSpeed) {
		/* we do not want to necessarily report the current speed */
		if (eHDD_LINK_SPEED_REPORT_MAX == pCfg->reportMaxLinkSpeed) {
			/* report the max possible speed */
			rssidx = 0;
		} else if (eHDD_LINK_SPEED_REPORT_MAX_SCALED ==
			   pCfg->reportMaxLinkSpeed) {
			/* report the max possible speed with RSSI scaling */
			if (sinfo->signal >= pCfg->linkSpeedRssiHigh) {
				/* report the max possible speed */
				rssidx = 0;
			} else if (sinfo->signal >= pCfg->linkSpeedRssiMid) {
				/* report middle speed */
				rssidx = 1;
			} else if (sinfo->signal >= pCfg->linkSpeedRssiLow) {
				/* report middle speed */
				rssidx = 2;
			} else {
				/* report actual speed */
				rssidx = 3;
			}
		} else {
			/* unknown, treat as eHDD_LINK_SPEED_REPORT_MAX */
			hdd_err("Invalid value for reportMaxLinkSpeed: %u",
			       pCfg->reportMaxLinkSpeed);
			rssidx = 0;
		}

		maxRate = 0;

		/* Get Basic Rate Set */
		if (0 !=
		    sme_cfg_get_str(WLAN_HDD_GET_HAL_CTX(pAdapter),
				    WNI_CFG_OPERATIONAL_RATE_SET,
				    OperationalRates,
				    &ORLeng)) {
			hdd_err("cfg get returned failure");
			/*To keep GUI happy */
			return 0;
		}

		for (i = 0; i < ORLeng; i++) {
			for (j = 0;
			     j < ARRAY_SIZE(supported_data_rate); j++) {
				/* Validate Rate Set */
				if (supported_data_rate[j].beacon_rate_index ==
				    (OperationalRates[i] & 0x7F)) {
					currentRate =
						supported_data_rate[j].
						supported_rate[rssidx];
					break;
				}
			}
			/* Update MAX rate */
			maxRate =
				(currentRate > maxRate) ? currentRate : maxRate;
		}

		/* Get Extended Rate Set */
		if (0 !=
		    sme_cfg_get_str(WLAN_HDD_GET_HAL_CTX(pAdapter),
				    WNI_CFG_EXTENDED_OPERATIONAL_RATE_SET,
				    ExtendedRates, &ERLeng)) {
			hdd_err("cfg get returned failure");
			/*To keep GUI happy */
			return 0;
		}

		for (i = 0; i < ERLeng; i++) {
			for (j = 0;
			     j < ARRAY_SIZE(supported_data_rate); j++) {
				if (supported_data_rate[j].beacon_rate_index ==
				    (ExtendedRates[i] & 0x7F)) {
					currentRate =
						supported_data_rate[j].
						supported_rate[rssidx];
					break;
				}
			}
			/* Update MAX rate */
			maxRate =
				(currentRate > maxRate) ? currentRate : maxRate;
		}
		/* Get MCS Rate Set --
		   Only if we are connected in non legacy mode and not reporting
		   actual speed */
		if ((3 != rssidx) && !(rate_flags & eHAL_TX_RATE_LEGACY)) {
			if (0 !=
			    sme_cfg_get_str(WLAN_HDD_GET_HAL_CTX(pAdapter),
					    WNI_CFG_CURRENT_MCS_SET, MCSRates,
					    &MCSLeng)) {
				hdd_err("cfg get returned failure");
				/*To keep GUI happy */
				return 0;
			}
			rateFlag = 0;
			supported_vht_mcs_rate =
				(struct index_vht_data_rate_type *)
				((nss ==
				  1) ? &supported_vht_mcs_rate_nss1 :
				 &supported_vht_mcs_rate_nss2);

			if (rate_flags & eHAL_TX_RATE_VHT80)
				mode = 2;
			else if ((rate_flags & eHAL_TX_RATE_VHT40) ||
				 (rate_flags & eHAL_TX_RATE_HT40))
				mode = 1;
			else
				mode = 0;

			/* VHT80 rate has seperate rate table */
			if (rate_flags &
			    (eHAL_TX_RATE_VHT20 | eHAL_TX_RATE_VHT40 |
			     eHAL_TX_RATE_VHT80)) {
				sme_cfg_get_int(WLAN_HDD_GET_HAL_CTX(pAdapter),
						WNI_CFG_VHT_TX_MCS_MAP,
						&vht_mcs_map);
				vhtMaxMcs = (enum eDataRate11ACMaxMcs)
					(vht_mcs_map & DATA_RATE_11AC_MCS_MASK);
				if (rate_flags & eHAL_TX_RATE_SGI)
					rateFlag |= 1;
				if (DATA_RATE_11AC_MAX_MCS_7 == vhtMaxMcs)
					maxMCSIdx = 7;
				else if (DATA_RATE_11AC_MAX_MCS_8 ==
					   vhtMaxMcs)
					maxMCSIdx = 8;
				else if (DATA_RATE_11AC_MAX_MCS_9 ==
					   vhtMaxMcs) {
					/*
					 * IEEE_P802.11ac_2013.pdf page 325, 326
					 * - MCS9 is valid for VHT20 when
					 *   Nss = 3 or Nss = 6
					 * - MCS9 is not valid for VHT20 when
					 *   Nss = 1,2,4,5,7,8
					 */
					if ((rate_flags & eHAL_TX_RATE_VHT20) &&
					     (nss != 3 && nss != 6))
						maxMCSIdx = 8;
					else
						maxMCSIdx = 9;
				}

				if (rssidx != 0) {
					for (i = 0; i <= maxMCSIdx; i++) {
						if (sinfo->signal <=
						    rssi_mcs_tbl[mode][i]) {
							maxMCSIdx = i;
							break;
						}
					}
				}

				if (rate_flags & eHAL_TX_RATE_VHT80) {
					currentRate =
					  supported_vht_mcs_rate[mcs_index].
					  supported_VHT80_rate[rateFlag];
					maxRate =
					  supported_vht_mcs_rate[maxMCSIdx].
						supported_VHT80_rate[rateFlag];
				} else if (rate_flags & eHAL_TX_RATE_VHT40) {
					currentRate =
					  supported_vht_mcs_rate[mcs_index].
					  supported_VHT40_rate[rateFlag];
					maxRate =
					  supported_vht_mcs_rate[maxMCSIdx].
						supported_VHT40_rate[rateFlag];
				} else if (rate_flags & eHAL_TX_RATE_VHT20) {
					currentRate =
					  supported_vht_mcs_rate[mcs_index].
					  supported_VHT20_rate[rateFlag];
					maxRate =
					  supported_vht_mcs_rate[maxMCSIdx].
					  supported_VHT20_rate[rateFlag];
				}

				maxSpeedMCS = 1;
				if (currentRate > maxRate)
					maxRate = currentRate;

			} else {
				if (rate_flags & eHAL_TX_RATE_HT40)
					rateFlag |= 1;
				if (rate_flags & eHAL_TX_RATE_SGI)
					rateFlag |= 2;

				supported_mcs_rate =
					(struct index_data_rate_type *)
					((nss ==
					  1) ? &supported_mcs_rate_nss1 :
					 &supported_mcs_rate_nss2);

				maxHtIdx = MAX_HT_MCS_IDX;
				if (rssidx != 0) {
					for (i = 0; i < MAX_HT_MCS_IDX; i++) {
						if (sinfo->signal <=
						    rssi_mcs_tbl[mode][i]) {
							maxHtIdx = i + 1;
							break;
						}
					}
				}

				for (i = 0; i < MCSLeng; i++) {
					for (j = 0; j < maxHtIdx; j++) {
						if (supported_mcs_rate[j].
						    beacon_rate_index ==
						    MCSRates[i]) {
							currentRate =
							  supported_mcs_rate[j].
							  supported_rate
							  [rateFlag];
							maxMCSIdx =
							  supported_mcs_rate[j].
							  beacon_rate_index;
							break;
						}
					}

					if ((j < MAX_HT_MCS_IDX)
					    && (currentRate > maxRate)) {
						maxRate = currentRate;
					}
					maxSpeedMCS = 1;
				}
			}
		}

		else if (!(rate_flags & eHAL_TX_RATE_LEGACY)) {
			maxRate = myRate;
			maxSpeedMCS = 1;
			maxMCSIdx = mcs_index;
		}
		/* report a value at least as big as current rate */
		if ((maxRate < myRate) || (0 == maxRate)) {
			maxRate = myRate;
			if (rate_flags & eHAL_TX_RATE_LEGACY) {
				maxSpeedMCS = 0;
			} else {
				maxSpeedMCS = 1;
				maxMCSIdx = mcs_index;
				/*
				 * IEEE_P802.11ac_2013.pdf page 325, 326
				 * - MCS9 is valid for VHT20 when
				 *   Nss = 3 or Nss = 6
				 * - MCS9 is not valid for VHT20 when
				 *   Nss = 1,2,4,5,7,8
				 */
				if ((rate_flags & eHAL_TX_RATE_VHT20) &&
				    (maxMCSIdx > 8) &&
				    (nss != 3 && nss != 6)) {
					maxMCSIdx = 8;
				}
			}
		}

		if (rate_flags & eHAL_TX_RATE_LEGACY) {
			sinfo->txrate.legacy = maxRate;
#ifdef LINKSPEED_DEBUG_ENABLED
			pr_info("Reporting legacy rate %d\n",
				sinfo->txrate.legacy);
#endif /* LINKSPEED_DEBUG_ENABLED */
		} else {
			sinfo->txrate.mcs = maxMCSIdx;
			sinfo->txrate.nss = nss;
			if (rate_flags & eHAL_TX_RATE_VHT80) {
				sinfo->txrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || defined(WITH_BACKPORTS)
				sinfo->txrate.bw = RATE_INFO_BW_80;
#else
				sinfo->txrate.flags |=
					RATE_INFO_FLAGS_80_MHZ_WIDTH;
#endif
			} else if (rate_flags & eHAL_TX_RATE_VHT40) {
				sinfo->txrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || defined(WITH_BACKPORTS)
				sinfo->txrate.bw = RATE_INFO_BW_40;
#else
				sinfo->txrate.flags |=
					RATE_INFO_FLAGS_40_MHZ_WIDTH;
#endif
			} else if (rate_flags & eHAL_TX_RATE_VHT20) {
				sinfo->txrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
			} else
				sinfo->txrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
			if (rate_flags &
			    (eHAL_TX_RATE_HT20 | eHAL_TX_RATE_HT40)) {
				sinfo->txrate.flags |= RATE_INFO_FLAGS_MCS;
				if (rate_flags & eHAL_TX_RATE_HT40) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || defined(WITH_BACKPORTS)
					sinfo->txrate.bw = RATE_INFO_BW_40;
#else
					sinfo->txrate.flags |=
						RATE_INFO_FLAGS_40_MHZ_WIDTH;
#endif
				}
			}
			if (rate_flags & eHAL_TX_RATE_SGI) {
				if (!
				    (sinfo->txrate.
				     flags & RATE_INFO_FLAGS_VHT_MCS))
					sinfo->txrate.flags |=
						RATE_INFO_FLAGS_MCS;
				sinfo->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
			}
#ifdef LINKSPEED_DEBUG_ENABLED
			pr_info("Reporting MCS rate %d flags %x\n",
				sinfo->txrate.mcs, sinfo->txrate.flags);
#endif /* LINKSPEED_DEBUG_ENABLED */
		}
	} else {
		/* report current rate instead of max rate */

		if (rate_flags & eHAL_TX_RATE_LEGACY) {
			/* provide to the UI in units of 100kbps */
			sinfo->txrate.legacy = myRate;
#ifdef LINKSPEED_DEBUG_ENABLED
			pr_info("Reporting actual legacy rate %d\n",
				sinfo->txrate.legacy);
#endif /* LINKSPEED_DEBUG_ENABLED */
		} else {
			/* must be MCS */
			sinfo->txrate.mcs = mcs_index;
			sinfo->txrate.nss = nss;
			sinfo->txrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
			if (rate_flags & eHAL_TX_RATE_VHT80) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || defined(WITH_BACKPORTS)
				sinfo->txrate.bw = RATE_INFO_BW_80;
#else
				sinfo->txrate.flags |=
					RATE_INFO_FLAGS_80_MHZ_WIDTH;
#endif
			} else if (rate_flags & eHAL_TX_RATE_VHT40) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || defined(WITH_BACKPORTS)
				sinfo->txrate.bw = RATE_INFO_BW_40;
#else
				sinfo->txrate.flags |=
					RATE_INFO_FLAGS_40_MHZ_WIDTH;
#endif
			}
			if (rate_flags &
			    (eHAL_TX_RATE_HT20 | eHAL_TX_RATE_HT40)) {
				sinfo->txrate.flags |= RATE_INFO_FLAGS_MCS;
				if (rate_flags & eHAL_TX_RATE_HT40) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || defined(WITH_BACKPORTS)
					sinfo->txrate.bw = RATE_INFO_BW_40;
#else
					sinfo->txrate.flags |=
						RATE_INFO_FLAGS_40_MHZ_WIDTH;
#endif
				}
			}
			if (rate_flags & eHAL_TX_RATE_SGI) {
				sinfo->txrate.flags |= RATE_INFO_FLAGS_MCS;
				sinfo->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
			}
#ifdef LINKSPEED_DEBUG_ENABLED
			pr_info("Reporting actual MCS rate %d flags %x\n",
				sinfo->txrate.mcs, sinfo->txrate.flags);
#endif /* LINKSPEED_DEBUG_ENABLED */
		}
	}

	sinfo->tx_bytes = pAdapter->stats.tx_bytes;

	sinfo->tx_packets =
		pAdapter->hdd_stats.summary_stat.tx_frm_cnt[0] +
		pAdapter->hdd_stats.summary_stat.tx_frm_cnt[1] +
		pAdapter->hdd_stats.summary_stat.tx_frm_cnt[2] +
		pAdapter->hdd_stats.summary_stat.tx_frm_cnt[3];

	sinfo->tx_retries =
		pAdapter->hdd_stats.summary_stat.multiple_retry_cnt[0] +
		pAdapter->hdd_stats.summary_stat.multiple_retry_cnt[1] +
		pAdapter->hdd_stats.summary_stat.multiple_retry_cnt[2] +
		pAdapter->hdd_stats.summary_stat.multiple_retry_cnt[3];

	sinfo->tx_failed =
		pAdapter->hdd_stats.summary_stat.fail_cnt[0] +
		pAdapter->hdd_stats.summary_stat.fail_cnt[1] +
		pAdapter->hdd_stats.summary_stat.fail_cnt[2] +
		pAdapter->hdd_stats.summary_stat.fail_cnt[3];

	sinfo->rx_bytes = pAdapter->stats.rx_bytes;
	sinfo->rx_packets = pAdapter->stats.rx_packets;

	qdf_mem_copy(&pHddStaCtx->conn_info.txrate,
		     &sinfo->txrate, sizeof(sinfo->txrate));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)) && !defined(WITH_BACKPORTS)
	sinfo->filled |= STATION_INFO_TX_BITRATE |
			 STATION_INFO_TX_BYTES   |
			 STATION_INFO_TX_PACKETS |
			 STATION_INFO_TX_RETRIES |
			 STATION_INFO_TX_FAILED  |
			 STATION_INFO_RX_BYTES   |
			 STATION_INFO_RX_PACKETS;
#else
	sinfo->filled |= BIT(NL80211_STA_INFO_TX_BYTES)   |
			 BIT(NL80211_STA_INFO_TX_BITRATE) |
			 BIT(NL80211_STA_INFO_TX_PACKETS) |
			 BIT(NL80211_STA_INFO_TX_RETRIES) |
			 BIT(NL80211_STA_INFO_TX_FAILED)  |
			 BIT(NL80211_STA_INFO_RX_BYTES)   |
			 BIT(NL80211_STA_INFO_RX_PACKETS);
#endif

	if (rate_flags & eHAL_TX_RATE_LEGACY)
		hdd_notice("Reporting legacy rate %d pkt cnt tx %d rx %d",
			sinfo->txrate.legacy, sinfo->tx_packets,
			sinfo->rx_packets);
	else
		hdd_notice("Reporting MCS rate %d flags 0x%x pkt cnt tx %d rx %d",
			sinfo->txrate.mcs, sinfo->txrate.flags,
			sinfo->tx_packets, sinfo->rx_packets);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
	sinfo->signal_avg = WLAN_HDD_TGT_NOISE_FLOOR_DBM;
	for (i = 0; i < NUM_CHAINS_MAX; i++) {
		sinfo->chain_signal_avg[i] =
			   pAdapter->hdd_stats.per_chain_rssi_stats.rssi[i];
		sinfo->chains |= 1 << i;
		if (sinfo->chain_signal_avg[i] > sinfo->signal_avg &&
				   sinfo->chain_signal_avg[i] != 0)
			sinfo->signal_avg = sinfo->chain_signal_avg[i];

		hdd_info("RSSI for chain %d, vdev_id %d is %d",
			i, pAdapter->sessionId, sinfo->chain_signal_avg[i]);

		if (!rssi_stats_valid && sinfo->chain_signal_avg[i])
			rssi_stats_valid = true;
	}

	if (rssi_stats_valid) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)) && !defined(WITH_BACKPORTS)
		sinfo->filled |= STATION_INFO_CHAIN_SIGNAL_AVG;
		sinfo->filled |= STATION_INFO_SIGNAL_AVG;
#else
		sinfo->filled |= BIT(NL80211_STA_INFO_CHAIN_SIGNAL_AVG);
		sinfo->filled |= BIT(NL80211_STA_INFO_SIGNAL_AVG);
#endif
	}
#endif


	MTRACE(qdf_trace(QDF_MODULE_ID_HDD,
			 TRACE_CODE_HDD_CFG80211_GET_STA,
			 pAdapter->sessionId, maxRate));
	EXIT();
	return 0;
}

/**
 * wlan_hdd_cfg80211_get_station() - get station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
int wlan_hdd_cfg80211_get_station(struct wiphy *wiphy,
				  struct net_device *dev, const uint8_t *mac,
				  struct station_info *sinfo)
#else
int wlan_hdd_cfg80211_get_station(struct wiphy *wiphy,
				  struct net_device *dev, uint8_t *mac,
				  struct station_info *sinfo)
#endif
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_get_station(wiphy, dev, mac, sinfo);
	cds_ssr_unprotect(__func__);

	return ret;
}

/**
 * __wlan_hdd_cfg80211_dump_station() - dump station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: variable to determine whether to get stats or not
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
static int __wlan_hdd_cfg80211_dump_station(struct wiphy *wiphy,
				struct net_device *dev,
				int idx, u8 *mac,
				struct station_info *sinfo)
{
	hdd_context_t *hdd_ctx = (hdd_context_t *) wiphy_priv(wiphy);

	hdd_debug("%s: idx %d", __func__, idx);
	if (idx != 0)
		return -ENOENT;
	qdf_mem_copy(mac, hdd_ctx->config->intfMacAddr[0].bytes,
				QDF_MAC_ADDR_SIZE);
	return __wlan_hdd_cfg80211_get_station(wiphy, dev, mac, sinfo);
}

/**
 * wlan_hdd_cfg80211_dump_station() - dump station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: variable to determine whether to get stats or not
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
int wlan_hdd_cfg80211_dump_station(struct wiphy *wiphy,
				struct net_device *dev,
				int idx, u8 *mac,
				struct station_info *sinfo)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_dump_station(wiphy, dev, idx, mac, sinfo);
	cds_ssr_unprotect(__func__);
	return ret;
}

/**
 * hdd_get_stats() - Function to retrieve interface statistics
 * @dev: pointer to network device
 *
 * This function is the ndo_get_stats method for all netdevs
 * registered with the kernel
 *
 * Return: pointer to net_device_stats structure
 */
struct net_device_stats *hdd_get_stats(struct net_device *dev)
{
	hdd_adapter_t *adapter = WLAN_HDD_GET_PRIV_PTR(dev);

	ENTER_DEV(dev);
	return &adapter->stats;
}
/**
 * __wlan_hdd_cfg80211_dump_survey() - get survey related info
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: Index
 * @survey: Pointer to survey info
 *
 * Return: 0 for success, non-zero for failure
 */
static int __wlan_hdd_cfg80211_dump_survey(struct wiphy *wiphy,
					   struct net_device *dev,
					   int idx, struct survey_info *survey)
{
	hdd_adapter_t *pAdapter = WLAN_HDD_GET_PRIV_PTR(dev);
	hdd_context_t *pHddCtx;
	hdd_station_ctx_t *pHddStaCtx;
	tHalHandle halHandle;
	uint32_t channel = 0, freq = 0; /* Initialization Required */
	int8_t snr, rssi;
	int status, i, j, filled = 0;

	ENTER_DEV(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("Command not allowed in FTM mode");
		return -EINVAL;
	}

	pHddCtx = WLAN_HDD_GET_CTX(pAdapter);
	status = wlan_hdd_validate_context(pHddCtx);

	if (0 != status)
		return status;

	pHddStaCtx = WLAN_HDD_GET_STATION_CTX_PTR(pAdapter);

	if (0 == pHddCtx->config->fEnableSNRMonitoring ||
	    0 != pAdapter->survey_idx ||
	    eConnectionState_Associated != pHddStaCtx->conn_info.connState) {
		/* The survey dump ops when implemented completely is expected
		 * to return a survey of all channels and the ops is called by
		 * the kernel with incremental values of the argument 'idx'
		 * till it returns -ENONET. But we can only support the survey
		 * for the operating channel for now. survey_idx is used to
		 * track that the ops is called only once and then return
		 * -ENONET for the next iteration
		 */
		pAdapter->survey_idx = 0;
		return -ENONET;
	}

	if (!pHddStaCtx->hdd_ReassocScenario) {
		hdd_err("Roaming in progress, hence return");
		return -ENONET;
	}

	halHandle = WLAN_HDD_GET_HAL_CTX(pAdapter);

	wlan_hdd_get_snr(pAdapter, &snr);
	wlan_hdd_get_rssi(pAdapter, &rssi);

	MTRACE(qdf_trace(QDF_MODULE_ID_HDD,
			 TRACE_CODE_HDD_CFG80211_DUMP_SURVEY,
			 pAdapter->sessionId, pAdapter->device_mode));

	sme_get_operation_channel(halHandle, &channel, pAdapter->sessionId);
	hdd_wlan_get_freq(channel, &freq);

	for (i = 0; i < NUM_NL80211_BANDS; i++) {
		if (NULL == wiphy->bands[i])
			continue;

		for (j = 0; j < wiphy->bands[i]->n_channels; j++) {
			struct ieee80211_supported_band *band = wiphy->bands[i];

			if (band->channels[j].center_freq == (uint16_t) freq) {
				survey->channel = &band->channels[j];
				/* The Rx BDs contain SNR values in dB for the
				 * received frames while the supplicant expects
				 * noise. So we calculate and return the value
				 * of noise (dBm)
				 *  SNR (dB) = RSSI (dBm) - NOISE (dBm)
				 */
				survey->noise = rssi - snr;
				survey->filled = SURVEY_INFO_NOISE_DBM;
				filled = 1;
			}
		}
	}

	if (filled)
		pAdapter->survey_idx = 1;
	else {
		pAdapter->survey_idx = 0;
		return -ENONET;
	}
	EXIT();
	return 0;
}

/**
 * wlan_hdd_cfg80211_dump_survey() - get survey related info
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: Index
 * @survey: Pointer to survey info
 *
 * Return: 0 for success, non-zero for failure
 */
int wlan_hdd_cfg80211_dump_survey(struct wiphy *wiphy,
				  struct net_device *dev,
				  int idx, struct survey_info *survey)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_cfg80211_dump_survey(wiphy, dev, idx, survey);
	cds_ssr_unprotect(__func__);

	return ret;
}
/**
 * hdd_init_ll_stats_ctx() - initialize link layer stats context
 *
 * Return: none
 */
inline void hdd_init_ll_stats_ctx(void)
{
	spin_lock_init(&ll_stats_context.context_lock);
	init_completion(&ll_stats_context.response_event);
	ll_stats_context.request_bitmap = 0;

	return;
}

/**
 * hdd_display_hif_stats() - display hif stats
 *
 * Return: none
 *
 */
void hdd_display_hif_stats(void)
{
	void *hif_ctx = cds_get_context(QDF_MODULE_ID_HIF);

	if (!hif_ctx)
		return;
	hif_display_stats(hif_ctx);
}

/**
 * hdd_clear_hif_stats() - clear hif stats
 *
 * Return: none
 */
void hdd_clear_hif_stats(void)
{
	void *hif_ctx = cds_get_context(QDF_MODULE_ID_HIF);

	if (!hif_ctx)
		return;
	hif_clear_stats(hif_ctx);
}

/**
 * hdd_is_rcpi_applicable() - validates RCPI request
 * @adapter: adapter upon which the measurement is requested
 * @mac_addr: peer addr for which measurement is requested
 * @rcpi_value: pointer to where the RCPI should be returned
 * @reassoc: used to return cached RCPI during reassoc
 *
 * Return: true for success, false for failure
 */

static bool hdd_is_rcpi_applicable(hdd_adapter_t *adapter,
				   struct qdf_mac_addr *mac_addr,
				   int32_t *rcpi_value,
				   bool *reassoc)
{
	hdd_station_ctx_t *hdd_sta_ctx;

	if (adapter->device_mode == QDF_STA_MODE ||
	    adapter->device_mode == QDF_P2P_CLIENT_MODE) {
		hdd_sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(adapter);
		if (hdd_sta_ctx->conn_info.connState !=
		    eConnectionState_Associated)
			return false;

		if (hdd_sta_ctx->hdd_ReassocScenario) {
			/* return the cached rcpi, if mac addr matches */
			hdd_info("Roaming in progress, return cached RCPI");
			if (!qdf_mem_cmp(&adapter->rcpi.mac_addr,
			    mac_addr, sizeof(*mac_addr))) {
				*rcpi_value = adapter->rcpi.rcpi;
				*reassoc = true;
				return true;
			}
			return false;
		}

		if (qdf_mem_cmp(mac_addr, &hdd_sta_ctx->conn_info.bssId,
		    sizeof(*mac_addr))) {
			hdd_err("mac addr is different from bssid connected");
			return false;
		}
	} else if (adapter->device_mode == QDF_SAP_MODE ||
		   adapter->device_mode == QDF_P2P_GO_MODE) {
		if (!test_bit(SOFTAP_BSS_STARTED, &adapter->event_flags)) {
			hdd_err("Invalid rcpi request, softap not started");
			return false;
		}

		/* check if peer mac addr is associated to softap */
		if (!hdd_is_peer_associated(adapter, mac_addr)) {
			hdd_err("invalid peer mac-addr: not associated");
			return false;
		}
	} else {
		hdd_err("Invalid rcpi request");
		return false;
	}

	*reassoc = false;
	return true;
}

/**
 * wlan_hdd_get_rcpi_cb() - callback function for rcpi response
 * @context: Pointer to rcpi context
 * @rcpi_req: Pointer to rcpi response
 *
 * Return: None
 */
static void wlan_hdd_get_rcpi_cb(void *context, struct qdf_mac_addr mac_addr,
				 int32_t rcpi, QDF_STATUS status)
{
	hdd_adapter_t *adapter;
	struct statsContext *rcpi_context;

	if (!context) {
		hdd_err("No rcpi context");
		return;
	}

	rcpi_context = context;
	adapter = rcpi_context->pAdapter;
	if (adapter->magic != WLAN_HDD_ADAPTER_MAGIC) {
		hdd_err("Invalid adapter magic");
		return;
	}

	/*
	 * there is a race condition that exists between this callback
	 * function and the caller since the caller could time out
	 * either before or while this code is executing.  we use a
	 * spinlock to serialize these actions
	 */
	spin_lock(&hdd_context_lock);
	if (rcpi_context->magic != RCPI_CONTEXT_MAGIC) {
		/*
		 * the caller presumably timed out so there is nothing
		 * we can do
		 */
		spin_unlock(&hdd_context_lock);
		hdd_warn("Invalid RCPI context magic");
		return;
	}

	rcpi_context->magic = 0;
	adapter->rcpi.mac_addr = mac_addr;
	if (status != QDF_STATUS_SUCCESS)
		/* peer rcpi is not available for requested mac addr */
		adapter->rcpi.rcpi = 0;
	else
		adapter->rcpi.rcpi = rcpi;

	/* notify the caller */
	complete(&rcpi_context->completion);

	/* serialization is complete */
	spin_unlock(&hdd_context_lock);
}

/**
 * __wlan_hdd_get_rcpi() - local function to get RCPI
 * @adapter: adapter upon which the measurement is requested
 * @mac: peer addr for which measurement is requested
 * @rcpi_value: pointer to where the RCPI should be returned
 * @measurement_type: type of rcpi measurement
 *
 * Return: 0 for success, non-zero for failure
 */
static int __wlan_hdd_get_rcpi(hdd_adapter_t *adapter,
			       uint8_t *mac,
			       int32_t *rcpi_value,
			       enum rcpi_measurement_type measurement_type)
{
	hdd_context_t *hdd_ctx;
	static struct statsContext rcpi_context;
	int status = 0;
	unsigned long rc;
	struct qdf_mac_addr mac_addr;
	QDF_STATUS qdf_status = QDF_STATUS_SUCCESS;
	struct sme_rcpi_req *rcpi_req;
	bool reassoc;

	ENTER();

	/* initialize the rcpi value to zero, useful in error cases */
	*rcpi_value = 0;

	if (hdd_get_conparam() == QDF_GLOBAL_FTM_MODE) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (!adapter) {
		hdd_warn("adapter context is NULL");
		return -EINVAL;
	}

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	status = wlan_hdd_validate_context(hdd_ctx);
	if (status)
		return -EINVAL;

	if (!hdd_ctx->rcpi_enabled) {
		hdd_info("RCPI not supported");
		return -EINVAL;
	}

	if (!mac) {
		hdd_warn("RCPI peer mac-addr is NULL");
		return -EINVAL;
	}

	qdf_mem_copy(&mac_addr, mac, QDF_MAC_ADDR_SIZE);

	if (!hdd_is_rcpi_applicable(adapter, &mac_addr, rcpi_value, &reassoc))
		return -EINVAL;
	if (reassoc)
		return 0;

	rcpi_req = qdf_mem_malloc(sizeof(*rcpi_req));
	if (!rcpi_req) {
		hdd_err("unable to allocate memory for RCPI req");
		return -EINVAL;
	}

	init_completion(&rcpi_context.completion);
	rcpi_context.pAdapter = adapter;
	rcpi_context.magic = RCPI_CONTEXT_MAGIC;

	rcpi_req->mac_addr = mac_addr;
	rcpi_req->session_id = adapter->sessionId;
	rcpi_req->measurement_type = measurement_type;
	rcpi_req->rcpi_callback = wlan_hdd_get_rcpi_cb;
	rcpi_req->rcpi_context = &rcpi_context;

	qdf_status = sme_get_rcpi(hdd_ctx->hHal, rcpi_req);
	if (qdf_status != QDF_STATUS_SUCCESS) {
		hdd_err("Unable to retrieve RCPI");
		status = qdf_status_to_os_return(qdf_status);
	} else {
		/* request was sent -- wait for the response */
		rc = wait_for_completion_timeout(&rcpi_context.completion,
					msecs_to_jiffies(WLAN_WAIT_TIME_RCPI));
		if (!rc) {
			hdd_err("SME timed out while retrieving RCPI");
			status = -EINVAL;
		}
	}
	qdf_mem_free(rcpi_req);

	spin_lock(&hdd_context_lock);
	rcpi_context.magic = 0;
	spin_unlock(&hdd_context_lock);

	if (status) {
		hdd_err("rcpi computation is failed");
	} else {
		if (qdf_mem_cmp(&mac_addr, &adapter->rcpi.mac_addr,
		    sizeof(mac_addr))) {
			hdd_err("mac addr is not matching from call-back");
			status = -EINVAL;
		} else {
			*rcpi_value = adapter->rcpi.rcpi;
			hdd_info("RCPI = %d", *rcpi_value);
		}
	}

	EXIT();
	return status;
}

int wlan_hdd_get_rcpi(hdd_adapter_t *adapter, uint8_t *mac,
		      int32_t *rcpi_value,
		      enum rcpi_measurement_type measurement_type)
{
	int ret;

	cds_ssr_protect(__func__);
	ret = __wlan_hdd_get_rcpi(adapter, mac, rcpi_value, measurement_type);
	cds_ssr_unprotect(__func__);

	return ret;
}
