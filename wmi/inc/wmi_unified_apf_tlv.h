/*
 * Copyright (c) 2016-2018 The Linux Foundation. All rights reserved.
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

#ifndef _WMI_UNIFIED_APF_TLV_H_
#define _WMI_UNIFIED_APF_TLV_H_

#include "wmi_unified.h"
#include "wmi_unified_api.h"

/**
 * send_set_active_apf_mode_cmd_tlv() - configure active APF mode in FW
 * @wmi_handle: the WMI handle
 * @vdev_id: the Id of the vdev to apply the configuration to
 * @ucast_mode: the active APF mode to configure for unicast packets
 * @mcast_bcast_mode: the active APF mode to configure for multicast/broadcast
 *	packets
 *
 * Return: QDF status
 */
QDF_STATUS
send_set_active_apf_mode_cmd_tlv(wmi_unified_t wmi_handle,
				 uint8_t vdev_id,
				 FW_ACTIVE_BPF_MODE ucast_mode,
				 FW_ACTIVE_BPF_MODE mcast_bcast_mode);
#endif /* _WMI_UNIFIED_APF_TLV_H_ */
