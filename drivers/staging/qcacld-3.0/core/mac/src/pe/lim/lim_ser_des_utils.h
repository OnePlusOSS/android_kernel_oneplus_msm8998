/*
 * Copyright (c) 2011-2015,2016 The Linux Foundation. All rights reserved.
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
 *
 * This file lim_ser_des_utils.h contains the utility definitions
 * LIM uses while processing messages from upper layer software
 * modules
 * Author:        Chandra Modumudi
 * Date:          10/20/02
 * History:-
 * Date           Modified by    Modification Information
 * --------------------------------------------------------------------
 */
#ifndef __LIM_SERDES_UTILS_H
#define __LIM_SERDES_UTILS_H

#include "sir_api.h"
#include "ani_system_defs.h"
#include "sir_mac_prot_def.h"
#include "utils_api.h"
#include "lim_types.h"
#include "lim_prop_exts_utils.h"

void lim_get_session_info(tpAniSirGlobal pMac, uint8_t *,
			  uint8_t *, uint16_t *);

/* Byte String <--> uint16_t/uint32_t copy functions */
static inline void lim_copy_u16(uint8_t *ptr, uint16_t u16Val)
{
#if ((defined(ANI_OS_TYPE_QNX) && defined(ANI_LITTLE_BYTE_ENDIAN)) ||	\
	(defined(ANI_OS_TYPE_ANDROID) && defined(ANI_LITTLE_BYTE_ENDIAN)))
	*ptr++ = (uint8_t) (u16Val & 0xff);
	*ptr = (uint8_t) ((u16Val >> 8) & 0xff);
#else
#error "Unknown combination of OS Type and endianess"
#endif
}

static inline uint16_t lim_get_u16(uint8_t *ptr)
{
#if ((defined(ANI_OS_TYPE_QNX) && defined(ANI_LITTLE_BYTE_ENDIAN)) ||	\
	(defined(ANI_OS_TYPE_ANDROID) && defined(ANI_LITTLE_BYTE_ENDIAN)))
	return ((uint16_t) (*(ptr + 1) << 8)) | ((uint16_t) (*ptr));
#else
#error "Unknown combination of OS Type and endianess"
#endif
}

static inline void lim_copy_u32(uint8_t *ptr, uint32_t u32Val)
{
#if ((defined(ANI_OS_TYPE_QNX) && defined(ANI_LITTLE_BYTE_ENDIAN)) ||	\
	(defined(ANI_OS_TYPE_ANDROID) && defined(ANI_LITTLE_BYTE_ENDIAN)))
	*ptr++ = (uint8_t) (u32Val & 0xff);
	*ptr++ = (uint8_t) ((u32Val >> 8) & 0xff);
	*ptr++ = (uint8_t) ((u32Val >> 16) & 0xff);
	*ptr = (uint8_t) ((u32Val >> 24) & 0xff);
#else
#error "Unknown combination of OS Type and endianess"
#endif
}

static inline uint32_t lim_get_u32(uint8_t *ptr)
{
#if ((defined(ANI_OS_TYPE_QNX) && defined(ANI_LITTLE_BYTE_ENDIAN)) ||	\
	(defined(ANI_OS_TYPE_ANDROID) && defined(ANI_LITTLE_BYTE_ENDIAN)))
	return ((*(ptr + 3) << 24) |
		(*(ptr + 2) << 16) | (*(ptr + 1) << 8) | (*(ptr)));
#else
#error "Unknown combination of OS Type and endianess"
#endif
}

tSirRetStatus lim_send_disassoc_frm_req_ser_des(tpAniSirGlobal mac_ctx,
		struct sme_send_disassoc_frm_req *disassoc_frm_req,
		uint8_t *buf);

#endif /* __LIM_SERDES_UTILS_H */
