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

#if !defined(WLAN_HDD_PACKET_FILTER_API_H__)
#define WLAN_HDD_PACKET_FILTER_API_H__

/**
 * DOC: wlan_hdd_packet_filter_rules.h
 *
 */

/* Include files */
#include "wlan_hdd_assoc.h"
#include "wlan_hdd_power.h"
/**
 * hdd_enable_default_pkt_filters() - Enable default packet filters based
 * on, filters bit map provided in INI, when target goes to suspend mode
 * @adapter: Adapter context for which default filters to be configure
 *
 * Return: zero if success, non-zero otherwise
 */
int hdd_enable_default_pkt_filters(hdd_adapter_t *pAadapter);

/**
 * hdd_disable_default_pkt_filters() - Disable default packet filters based
 * on, filters bit map provided in INI, when target resumes
 * @adapter: Adapter context for which default filters to be cleared
 *
 * Return: zero if success, non-zero otherwise
 */
int hdd_disable_default_pkt_filters(hdd_adapter_t *pAdapter);

/**
 * wlan_hdd_set_filter() - Set packet filter
 * @hdd_ctx: Global HDD context
 * @request: Packet filter request struct
 * @sessionId: Target session for the request
 *
 * Return: 0 on success, non-zero on error
 */
int wlan_hdd_set_filter(hdd_context_t *hdd_ctx,
			struct pkt_filter_cfg *request,
			uint8_t sessionId);
#endif
