/*
 * Copyright (c) 2012-2016 The Linux Foundation. All rights reserved.
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


#ifndef HIF_HW_VERSION_H
#define HIF_HW_VERSION_H

#define AR6004_VERSION_REV1_3           0x31c8088a
#define AR9888_REV2_VERSION             0x4100016c
#define AR9887_REV1_VERSION             0x4100016d
#define AR6320_REV1_VERSION             0x5000000
#define AR6320_REV1_1_VERSION           0x5000001
#define AR6320_REV1_3_VERSION           0x5000003
#define AR6320_REV2_1_VERSION           0x5010000
#define AR6320_REV3_VERSION             0x5020000
#define AR6320_REV3_2_VERSION           0x5030000
#define AR6320_DEV_VERSION              0x1000000
#define QCA9377_REV1_1_VERSION          0x5020001
#define QCA9379_REV1_VERSION            0x5040000
#define WCN3990_v1                      0x40000000
#define WCN3990_v2                      0x40010000
#define WCN3990_v2_1                    0x40010002

struct qwlan_hw {
	u32 id;
	u32 subid;
	const char *name;
};

#endif /* HIF_HW_VERSION_H */
