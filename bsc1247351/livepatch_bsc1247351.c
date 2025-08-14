/*
 * livepatch_bsc1247351
 *
 * Fix for CVE-2025-38495, bsc#1247351
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_HID)

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include <asm/byteorder.h>
#include <linux/input.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/semaphore.h>

#include <linux/hid.h>

/* klp-ccp: from drivers/hid/hid-core.c */
u8 *klpp_hid_alloc_report_buf(struct hid_report *report, gfp_t flags)
{
	/*
	 * 7 extra bytes are necessary to achieve proper functionality
	 * of implement() working on 8 byte chunks
	 * 1 extra byte for the report ID if it is null (not used) so
	 * we can reserve that extra byte in the first position of the buffer
	 * when sending it to .raw_request()
	 */

	u32 len = hid_report_len(report) + 7 + (report->id == 0);

	return kzalloc(len, flags);
}

typeof(klpp_hid_alloc_report_buf) klpp_hid_alloc_report_buf;


#include "livepatch_bsc1247351.h"


#endif /* IS_ENABLED(CONFIG_HID) */
