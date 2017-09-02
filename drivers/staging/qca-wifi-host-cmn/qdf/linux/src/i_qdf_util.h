/*
 * Copyright (c) 2014-2017 The Linux Foundation. All rights reserved.
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
 * DOC: i_qdf_util.h
 * This file provides OS dependent API's.
 */

#ifndef _I_QDF_UTIL_H
#define _I_QDF_UTIL_H

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/errno.h>

#include <linux/random.h>

#include <qdf_types.h>
#include <qdf_status.h>
#include <asm/byteorder.h>

#if LINUX_VERSION_CODE  <= KERNEL_VERSION(3, 3, 8)
#include <asm/system.h>
#else
#if defined(__LINUX_MIPS32_ARCH__) || defined(__LINUX_MIPS64_ARCH__)
#include <asm/dec/system.h>
#else
#endif
#endif

#include <qdf_types.h>
#include <asm/io.h>
#include <asm/byteorder.h>

#ifdef QCA_PARTNER_PLATFORM
#include "ath_carr_pltfrm.h"
#else
#include <linux/byteorder/generic.h>
#endif

/*
 * Generic compiler-dependent macros if defined by the OS
 */
#define __qdf_unlikely(_expr)   unlikely(_expr)
#define __qdf_likely(_expr)     likely(_expr)

/**
 * __qdf_status_to_os_return() - translates qdf_status types to linux return types
 * @status: status to translate
 *
 * Translates error types that linux may want to handle specially.
 *
 * return: 0 or the linux error code that most closely matches the QDF_STATUS.
 * defaults to -1 (EPERM)
 */
static inline int __qdf_status_to_os_return(QDF_STATUS status)
{
	switch (status) {
	case QDF_STATUS_SUCCESS:
		return 0;
	case QDF_STATUS_E_RESOURCES:
		return -EBUSY;
	case QDF_STATUS_E_NOMEM:
		return -ENOMEM;
	case QDF_STATUS_E_AGAIN:
		return -EAGAIN;
	case QDF_STATUS_E_INVAL:
		return -EINVAL;
	case QDF_STATUS_E_FAULT:
		return -EFAULT;
	case QDF_STATUS_E_ALREADY:
		return -EALREADY;
	case QDF_STATUS_E_BADMSG:
		return -EBADMSG;
	case QDF_STATUS_E_BUSY:
		return -EBUSY;
	case QDF_STATUS_E_CANCELED:
		return -ECANCELED;
	case QDF_STATUS_E_ABORTED:
		return -ECONNABORTED;
	case QDF_STATUS_E_PERM:
		return -EPERM;
	case QDF_STATUS_E_EXISTS:
		return -EEXIST;
	case QDF_STATUS_E_NOENT:
		return -ENOENT;
	case QDF_STATUS_E_E2BIG:
		return -E2BIG;
	case QDF_STATUS_E_NOSPC:
		return -ENOSPC;
	case QDF_STATUS_E_ADDRNOTAVAIL:
		return -EADDRNOTAVAIL;
	case QDF_STATUS_E_ENXIO:
		return -ENXIO;
	case QDF_STATUS_E_NETDOWN:
		return -ENETDOWN;
	case QDF_STATUS_E_IO:
		return -EIO;
	case QDF_STATUS_E_NETRESET:
		return -ENETRESET;
	default:
		return -EPERM;
	}
}

/**
 * __qdf_set_bit() - set bit in address
 * @nr: bit number to be set
 * @addr: address buffer pointer
 *
 * Return: none
 */
static inline void __qdf_set_bit(unsigned int nr, unsigned long *addr)
{
	__set_bit(nr, addr);
}

/**
 * __qdf_set_macaddr_broadcast() - set a QDF MacAddress to the 'broadcast'
 * @mac_addr: pointer to the qdf MacAddress to set to broadcast
 *
 * This function sets a QDF MacAddress to the 'broadcast' MacAddress. Broadcast
 * MacAddress contains all 0xFF bytes.
 *
 * Return: none
 */
static inline void __qdf_set_macaddr_broadcast(struct qdf_mac_addr *mac_addr)
{
	memset(mac_addr, 0xff, QDF_MAC_ADDR_SIZE);
}

/**
 * __qdf_zero_macaddr() - zero out a MacAddress
 * @mac_addr: pointer to the struct qdf_mac_addr to zero.
 *
 * This function zeros out a QDF MacAddress type.
 *
 * Return: none
 */
static inline void __qdf_zero_macaddr(struct qdf_mac_addr *mac_addr)
{
	memset(mac_addr, 0, QDF_MAC_ADDR_SIZE);
}

/**
 * __qdf_is_macaddr_equal() - compare two QDF MacAddress
 * @mac_addr1: Pointer to one qdf MacAddress to compare
 * @mac_addr2: Pointer to the other qdf MacAddress to compare
 *
 * This function returns a bool that tells if a two QDF MacAddress'
 * are equivalent.
 *
 * Return: true if the MacAddress's are equal
 *      not true if the MacAddress's are not equal
 */
static inline bool __qdf_is_macaddr_equal(struct qdf_mac_addr *mac_addr1,
					  struct qdf_mac_addr *mac_addr2)
{
	return 0 == memcmp(mac_addr1, mac_addr2, QDF_MAC_ADDR_SIZE);
}

/**
 * qdf_in_interrupt - returns true if in interrupt context
 */
#define qdf_in_interrupt          in_interrupt

/**
 * @brief memory barriers.
 */
#define __qdf_min(_a, _b)         ((_a) < (_b) ? _a : _b)
#define __qdf_max(_a, _b)         ((_a) > (_b) ? _a : _b)

#define MEMINFO_KB(x)  ((x) << (PAGE_SHIFT - 10))   /* In kilobytes */

/**
 * @brief Assert
 */
#define __qdf_assert(expr)  do { \
		if (unlikely(!(expr))) { \
			pr_err("Assertion failed! %s:%s %s:%d\n", \
			       # expr, __func__, __FILE__, __LINE__); \
			dump_stack(); \
			QDF_BUG(0); \
		} \
} while (0)

/**
 * @brief Assert
 */
#define __qdf_target_assert(expr)  do {    \
	if (unlikely(!(expr))) {                                 \
		qdf_print("Assertion failed! %s:%s %s:%d\n",   \
		#expr, __FUNCTION__, __FILE__, __LINE__);      \
		dump_stack();                                      \
		panic("Take care of the TARGET ASSERT first\n");          \
	}     \
} while (0)

#define __qdf_cpu_to_le64                cpu_to_le64
#define __qdf_container_of(ptr, type, member) container_of(ptr, type, member)

#define __qdf_ntohs                      ntohs
#define __qdf_ntohl                      ntohl

#define __qdf_htons                      htons
#define __qdf_htonl                      htonl

#define __qdf_cpu_to_le16                cpu_to_le16
#define __qdf_cpu_to_le32                cpu_to_le32
#define __qdf_cpu_to_le64                cpu_to_le64

#define __qdf_le16_to_cpu                le16_to_cpu
#define __qdf_le32_to_cpu                le32_to_cpu

#define __qdf_be32_to_cpu                be32_to_cpu
#define __qdf_be64_to_cpu                be64_to_cpu
#define __qdf_le64_to_cpu                le64_to_cpu
#define __qdf_le16_to_cpu                le16_to_cpu

/**
 * @brief memory barriers.
 */
#define __qdf_wmb()                wmb()
#define __qdf_rmb()                rmb()
#define __qdf_mb()                 mb()

#define __qdf_roundup(x, y) roundup(x, y)

#ifdef QCA_CONFIG_SMP
/**
 * __qdf_get_cpu() - get cpu_index
 *
 * Return: cpu_index
 */
static inline
int __qdf_get_cpu(void)
{
	int cpu_index = get_cpu();

	put_cpu();
	return cpu_index;
}
#else
static inline
int __qdf_get_cpu(void)
{
	return 0;
}
#endif

static inline int __qdf_device_init_wakeup(__qdf_device_t qdf_dev, bool enable)
{
	return device_init_wakeup(qdf_dev->dev, enable);
}

/**
 * __qdf_get_totalramsize() -  Get total ram size in Kb
 *
 * Return: Total ram size in Kb
 */
static inline uint64_t
__qdf_get_totalramsize(void)
{
	struct sysinfo meminfo;
	si_meminfo(&meminfo);
	return MEMINFO_KB(meminfo.totalram);
}

/**
 * __qdf_get_lower_32_bits() - get lower 32 bits from an address.
 * @addr: address
 *
 * This api returns the lower 32 bits of an address.
 *
 * Return: lower 32 bits.
 */
static inline
uint32_t __qdf_get_lower_32_bits(__qdf_dma_addr_t addr)
{
	return lower_32_bits(addr);
}

/**
 * __qdf_get_upper_32_bits() - get upper 32 bits from an address.
 * @addr: address
 *
 * This api returns the upper 32 bits of an address.
 *
 * Return: upper 32 bits.
 */
static inline
uint32_t __qdf_get_upper_32_bits(__qdf_dma_addr_t addr)
{
	return upper_32_bits(addr);
}

/**
 * __qdf_rounddown_pow_of_two() - Round down to nearest power of two
 * @n: number to be tested
 *
 * Test if the input number is power of two, and return the nearest power of two
 *
 * Return: number rounded down to the nearest power of two
 */
static inline
unsigned long __qdf_rounddown_pow_of_two(unsigned long n)
{
	if (is_power_of_2(n))
		return n; /* already a power of 2 */

	return __rounddown_pow_of_two(n);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)

/**
 * __qdf_set_dma_coherent_mask() - set max number of bits allowed in dma addr
 * @dev: device pointer
 * @addr_bits: max number of bits allowed in dma address
 *
 * This API sets the maximum allowed number of bits in the dma address.
 *
 * Return: 0 - success, non zero - failure
 */
static inline
int __qdf_set_dma_coherent_mask(struct device *dev, uint8_t addr_bits)
{
	return dma_set_mask_and_coherent(dev, DMA_BIT_MASK(addr_bits));
}

#else

/**
 * __qdf_set_dma_coherent_mask() - set max number of bits allowed in dma addr
 * @dev: device pointer
 * @addr_bits: max number of bits allowed in dma address
 *
 * This API sets the maximum allowed number of bits in the dma address.
 *
 * Return: 0 - success, non zero - failure
 */
static inline
int __qdf_set_dma_coherent_mask(struct device *dev, uint8_t addr_bits)
{
	return dma_set_coherent_mask(dev, DMA_BIT_MASK(addr_bits));
}
#endif

/**
 * __qdf_do_div() - wrapper function for kernel macro(do_div).
 * @dividend: Dividend value
 * @divisor : Divisor value
 *
 * Return: Quotient
 */
static inline
uint64_t __qdf_do_div(uint64_t dividend, uint32_t divisor)
{
	do_div(dividend, divisor);
	/*do_div macro updates dividend with Quotient of dividend/divisor */
	return dividend;
}

/**
 * __qdf_do_mod() - wrapper function for kernel macro(do_div).
 * @dividend: Dividend value
 * @divisor : Divisor value
 *
 * Return: Modulo
 */
static inline
uint64_t __qdf_do_mod(uint64_t dividend, uint32_t divisor)
{
	return do_div(dividend, divisor);
}

#endif /*_I_QDF_UTIL_H*/
