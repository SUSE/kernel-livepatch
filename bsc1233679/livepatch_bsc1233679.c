/*
 * livepatch_bsc1233679
 *
 * Fix for CVE-2024-50302, bsc#1233679
 *
 *  Upstream commit:
 *  177f25d1292c ("HID: core: zero-initialize the report buffer")
 *
 *  SLE12-SP5 commit:
 *  6bc7fd89245ac70a2cb5ee50b5d9dc5b5b4df604
 *
 *  SLE15-SP3 commit:
 *  f2b9a673aa2d389dd53022857184ceb5dec97278
 *
 *  SLE15-SP4 and -SP5 commit:
 *  086ff16554fcfae0b8bfd1d433abee99b743cbcd
 *
 *  SLE15-SP6 commit:
 *  9115733fa3efc888f28cd62151e71e5b4f6e4e85
 *
 *  SLE MICRO-6-0 commit:
 *  9115733fa3efc888f28cd62151e71e5b4f6e4e85
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

/* klp-ccp: from drivers/hid/hid-core.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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

#include <linux/sched.h>
#include <linux/semaphore.h>

#include <linux/hid.h>

/* klp-ccp: from drivers/hid/hid-core.c */
u8 *klpp_hid_alloc_report_buf(struct hid_report *report, gfp_t flags)
{
	/*
	 * 7 extra bytes are necessary to achieve proper functionality
	 * of implement() working on 8 byte chunks
	 */

	u32 len = hid_report_len(report) + 7;

	return kzalloc(len, flags);
}

#include "livepatch_bsc1233679.h"

#endif /* IS_ENABLED(CONFIG_HID) */
