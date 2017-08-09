/*
 * Copyright (c) 2011-2016 The Linux Foundation. All rights reserved.
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
 * This file ani_system_defs.h contains definitions used by
 * various ANI entities
 * Author:    Chandra Modumudi
 * Date:      09/18/2002
 * History:-
 * Date       Modified by    Modification Information
 * --------------------------------------------------------------------
 */

#ifndef __ANI_SYSTEM_DEFS_H
#define __ANI_SYSTEM_DEFS_H

#include "sir_types.h"
#include "sir_mac_prot_def.h"

#define ANI_OUI  0x000AF5

/* / Max WDS info length. */
#define ANI_WDS_INFO_MAX_LENGTH        64

/* This is to force compiler to use the maximum of an int for enum */
#define SIR_MAX_ENUM_SIZE    0x7FFFFFFF

/* Max key size  including the WAPI and TKIP */
#define WLAN_MAX_KEY_RSC_LEN         16
#define WLAN_WAPI_KEY_RSC_LEN        16

#ifndef false
#undef false
#define false   0
#endif
#ifndef true
#undef true
#define true    1
#endif

typedef enum eAniBool {
	eSIR_FALSE,
	eSIR_TRUE,
	eSIR_DONOT_USE_BOOL = SIR_MAX_ENUM_SIZE
} tAniBool;

/* / Authentication type enum used with peer */
typedef enum eAniAuthType {
	eSIR_OPEN_SYSTEM,
	eSIR_SHARED_KEY,
	eSIR_FT_AUTH,
#if defined FEATURE_WLAN_ESE
	eSIR_LEAP_AUTH = 0x80,
#endif
	eSIR_AUTO_SWITCH,
	eSIR_DONOT_USE_AUTH_TYPE = SIR_MAX_ENUM_SIZE
} tAniAuthType;

/* / Encryption type enum used with peer */
typedef enum eAniEdType {
	eSIR_ED_NONE,
	eSIR_ED_WEP40,
	eSIR_ED_WEP104,
	eSIR_ED_TKIP,
	eSIR_ED_CCMP,
#if defined(FEATURE_WLAN_WAPI)
	eSIR_ED_WPI,
#endif
	/*DPU HW treats encryption mode 4 plus RMF bit set in TX BD as BIP.
	   Thus while setting BIP encryption mode in corresponding DPU Desc
	   eSIR_ED_AES_128_CMAC should be set to eSIR_ED_CCMP */
	eSIR_ED_AES_128_CMAC,
	eSIR_ED_NOT_IMPLEMENTED = SIR_MAX_ENUM_SIZE
} tAniEdType;

typedef enum eAniWepType {
	eSIR_WEP_STATIC,
	eSIR_WEP_DYNAMIC,
} tAniWepType;

/* / Enum to specify whether key is used */
/* / for TX only, RX only or both */
typedef enum eAniKeyDirection {
	eSIR_TX_ONLY,
	eSIR_RX_ONLY,
	eSIR_TX_RX,
	eSIR_TX_DEFAULT,
	eSIR_DONOT_USE_KEY_DIRECTION = SIR_MAX_ENUM_SIZE
} tAniKeyDirection;

typedef struct sAniSSID {
	uint8_t length;
	uint8_t ssId[SIR_MAC_MAX_SSID_LENGTH];
} tAniSSID, *tpAniSSID;

typedef struct sAniApName {
	uint8_t length;
	uint8_t name[SIR_MAC_MAX_SSID_LENGTH];
} tAniApName, *tpAniApName;

/* / RSN IE information */
typedef struct sSirRSNie {
	uint16_t length;
	uint8_t rsnIEdata[SIR_MAC_MAX_IE_LENGTH + 2];
} tSirRSNie, *tpSirRSNie;

typedef struct sSirWAPIie {
	uint16_t length;
	uint8_t wapiIEdata[SIR_MAC_MAX_IE_LENGTH + 2];
} tSirWAPIie, *tpSirWAPIie;
/* / Additional IE information : */
/* / This can include WSC IE, P2P IE, and/or FTIE from upper layer. */
/* / MAC layer transparently convey these IE info between peer STA and upper layer, */
/* / but never requires to parse it. */
typedef struct sSirAddie {
	uint16_t length;
	uint8_t addIEdata[SIR_MAC_MAX_ADD_IE_LENGTH + 2];
} tSirAddie, *tpSirAddie;

#ifdef FEATURE_WLAN_ESE

/* The CCKM IE needs to be in the */
/* Join and Reassoc Req. */
typedef struct sSirCCKMie {
	uint16_t length;
	uint8_t cckmIEdata[SIR_MAC_MAX_IE_LENGTH + 2];
} tSirCCKMie, *tpSirCCKMie;

#endif

/* / Definition for Encryption Keys */
typedef struct sSirKeys {
	uint8_t keyId;
	uint8_t unicast;        /* 0 for multicast */
	tAniKeyDirection keyDirection;
	uint8_t keyRsc[WLAN_MAX_KEY_RSC_LEN];   /* Usage is unknown */
	uint8_t paeRole;        /* =1 for authenticator, */
	/* =0 for supplicant */
	uint16_t keyLength;
	uint8_t key[SIR_MAC_MAX_KEY_LENGTH];
} tSirKeys, *tpSirKeys;

/* / Definition for Keying material */
typedef struct sSirKeyMaterial {
	uint16_t length;        /* This is the length of all */
	/* data that follows */
	tAniEdType edType;      /* Encryption/Decryption type */
	uint8_t numKeys;
	tSirKeys key[1];
} tSirKeyMaterial, *tpSirKeyMaterial;

#define SIR_CIPHER_SEQ_CTR_SIZE 6
/* / Definition for MIC failure indication */
typedef struct sSirMicFailureInfo {
	tSirMacAddr srcMacAddr; /* address used to compute MIC */
	tSirMacAddr taMacAddr;  /* transmitter address */
	tSirMacAddr dstMacAddr;
	tAniBool multicast;
	uint8_t IV1;            /* first byte of IV */
	uint8_t keyId;          /* second byte of IV */
	uint8_t TSC[SIR_CIPHER_SEQ_CTR_SIZE];   /* sequence number */
	tSirMacAddr rxMacAddr;  /* receive address */

} tSirMicFailureInfo, *tpSirMicFailureInfo;

typedef struct sTrafStrmMetrics {
	uint16_t UplinkPktQueueDly;
	uint16_t UplinkPktQueueDlyHist[4];
	uint32_t UplinkPktTxDly;
	uint16_t UplinkPktLoss;
	uint16_t UplinkPktCount;
	uint8_t RoamingCount;
	uint16_t RoamingDly;
} qdf_packed tTrafStrmMetrics, *tpTrafStrmMetrics;

typedef struct sBcnReportFields {
	uint8_t ChanNum;
	uint8_t Spare;
	uint16_t MeasDuration;
	uint8_t PhyType;
	uint8_t RecvSigPower;
	tSirMacAddr Bssid;
	uint32_t ParentTsf;
	uint32_t TargetTsf[2];
	uint16_t BcnInterval;
	uint16_t CapabilityInfo;
} qdf_packed tBcnReportFields, *tpBcnReportFields;

#endif /* __ANI_SYSTEM_DEFS_H */
