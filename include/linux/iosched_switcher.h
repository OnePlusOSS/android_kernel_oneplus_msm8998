/*
 * Copyright (C) 2017, Sultanxda <sultanxda@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _IOSCHED_SWITCHER_H
#define _IOSCHED_SWITCHER_H

#ifdef CONFIG_IOSCHED_SWITCHER
int init_iosched_switcher(struct request_queue *q);
#else
static inline int init_iosched_switcher(struct request_queue *q)
{
	return 0;
}
#endif

#endif /* _IOSCHED_SWITCHER_H */
