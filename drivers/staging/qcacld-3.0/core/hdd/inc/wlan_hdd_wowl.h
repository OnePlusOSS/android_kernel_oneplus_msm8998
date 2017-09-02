/*
 * Copyright (c) 2013-2017 The Linux Foundation. All rights reserved.
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

#ifndef _WLAN_HDD_WOWL_H
#define _WLAN_HDD_WOWL_H

/**
 * DOC: wlan_hdd_wowl
 *
 * This module houses all the logic for WOWL in HDD.
 *
 * It provides the following APIs
 *
 * - Ability to enable/disable following WoWL modes
 *  1) Magic packet (MP) mode
 *  2) Pattern Byte Matching (PBM) mode
 * - Ability to add/remove patterns for PBM
 *
 * A Magic Packet is a packet that contains 6 0xFFs followed by 16
 * contiguous copies of the receiving NIC's Ethernet address. There is
 * no API to configure Magic Packet Pattern.
 *
 * Wakeup pattern (used for PBM) is defined as following:
 * typedef struct
 * {
 *  U8  PatternSize;                  // Non-Zero pattern size
 *  U8  PatternMaskSize;              // Non-zero pattern mask size
 *  U8  PatternMask[PatternMaskSize]; // Pattern mask
 *  U8  Pattern[PatternSize];         // Pattern
 * } hdd_wowl_ptrn_t;
 *
 * PatternSize and PatternMaskSize indicate size of the variable
 * length Pattern and PatternMask. PatternMask indicates which bytes
 * of an incoming packet should be compared with corresponding bytes
 * in the pattern.
 *
 * Maximum allowed pattern size is 128 bytes. Maximum allowed
 * PatternMaskSize is 16 bytes.
 *
 * Maximum number of patterns that can be configured is 8
 *
 * HDD will add following 2 commonly used patterns for PBM by default:
 *  1) ARP Broadcast Pattern
 *  2) Unicast Pattern
 *
 * However note that WoWL will not be enabled by default by HDD. WoWL
 * needs to enabled explcitly by exercising the iwpriv command.
 *
 * HDD will expose an API that accepts patterns as Hex string in the
 * following format:
 * "PatternSize:PatternMaskSize:PatternMask:Pattern"
 *
 * Multiple patterns can be specified by deleimiting each pattern with
 * the ';' token:
 * "PatternSize1:PatternMaskSize1:PatternMask1:Pattern1;PatternSize2:..."
 *
 * Patterns can be configured dynamically via iwpriv cmd or statically
 * via qcom_cfg.ini file
 *
 * PBM (when enabled) can perform filtering on unicast data or
 * broadcast data or both. These configurations are part of factory
 * defaults (cfg.dat) and the deafult behavior is to perform filtering
 * on both unicast and data frames.
 *
 * MP filtering (when enabled) is performed ALWAYS on both unicast and
 * broadcast data frames.
 *
 * Mangement frames are not subjected to WoWL filtering and are
 * discarded when WoWL is enabled.
 *
 * Whenever a patern match succeeds, RX path is restored and packets
 * (both management and data) will be pushed to the host from that
 * point onwards.  Therefore, exit from WoWL is implicit and happens
 * automatically when the first packet match succeeds.
 *
 * WoWL works on top of BMPS. So when WoWL is requested, SME will
 * attempt to put the device in BMPS mode (if not already in BMPS). If
 * attempt to BMPS fails, request for WoWL will be rejected.
 */

#include <qdf_types.h>

#define WOWL_PTRN_MAX_SIZE          146
#define WOWL_PTRN_MASK_MAX_SIZE      19
#define WOWL_MAX_PTRNS_ALLOWED       CFG_MAX_WOW_FILTERS_MAX

/**
 * hdd_add_wowl_ptrn() - Function which will add the WoWL pattern to be
 *			 used when PBM filtering is enabled
 * @pAdapter: pointer to the adapter
 * @ptrn: pointer to the pattern string to be added
 *
 * Return: false if any errors encountered, true otherwise
 */
bool hdd_add_wowl_ptrn(hdd_adapter_t *pAdapter, const char *ptrn);

/**
 * hdd_del_wowl_ptrn() - Function which will remove a WoWL pattern
 * @pAdapter: pointer to the adapter
 * @ptrn: pointer to the pattern string to be removed
 *
 * Return: false if any errors encountered, true otherwise
 */
bool hdd_del_wowl_ptrn(hdd_adapter_t *pAdapter, const char *ptrn);

/**
 * hdd_add_wowl_ptrn_debugfs() - Function which will add a WoW pattern
 *				 sent from debugfs interface
 * @pAdapter: pointer to the adapter
 * @pattern_idx: index of the pattern to be added
 * @pattern_offset: offset of the pattern in the frame payload
 * @pattern_buf: pointer to the pattern hex string to be added
 * @pattern_mask: pointer to the pattern mask hex string
 *
 * Return: false if any errors encountered, true otherwise
 */
bool hdd_add_wowl_ptrn_debugfs(hdd_adapter_t *pAdapter, uint8_t pattern_idx,
			       uint8_t pattern_offset, char *pattern_buf,
			       char *pattern_mask);

/**
 * hdd_del_wowl_ptrn_debugfs() - Function which will remove a WoW pattern
 *				 sent from debugfs interface
 * @pAdapter: pointer to the adapter
 * @pattern_idx: index of the pattern to be removed
 *
 * Return: false if any errors encountered, true otherwise
 */
bool hdd_del_wowl_ptrn_debugfs(hdd_adapter_t *pAdapter, uint8_t pattern_idx);

/**
 * hdd_enter_wowl() - Function which will enable WoWL. At least one
 *		      of MP and PBM must be enabled
 * @pAdapter: pointer to the adapter
 * @enable_mp: Whether to enable magic packet WoWL mode
 * @enable_pbm: Whether to enable pattern byte matching WoWL mode
 *
 * Return: false if any errors encountered, true otherwise
 */
bool hdd_enter_wowl(hdd_adapter_t *pAdapter, bool enable_mp, bool enable_pbm);

/**
 * hdd_exit_wowl() - Function which will disable WoWL
 * @pAdapter: pointer to the adapter
 *
 * Return: false if any errors encountered, true otherwise
 */
bool hdd_exit_wowl(hdd_adapter_t *pAdapter);

/**
 * hdd_deinit_wowl() - Deinit function to cleanup WoWL allocated memory
 *
 * Return: None
 */
void hdd_deinit_wowl(void);

#endif /* #ifndef _WLAN_HDD_WOWL_H */
