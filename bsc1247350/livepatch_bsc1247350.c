/*
 * livepatch_bsc1247350
 *
 * Fix for CVE-2025-38494, bsc#1247350
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

/* klp-ccp: from include/linux/hid.h */
void klpp___hid_request(struct hid_device *hid, struct hid_report *rep, int reqtype);

/* klp-ccp: from drivers/hid/hid-core.c */
extern int hid_debug;

extern typeof(hid_debug) hid_debug;

void hid_output_report(struct hid_report *report, __u8 *data);

extern typeof(hid_output_report) hid_output_report;

u8 *hid_alloc_report_buf(struct hid_report *report, gfp_t flags);

extern typeof(hid_alloc_report_buf) hid_alloc_report_buf;

void klpp___hid_request(struct hid_device *hid, struct hid_report *report,
		int reqtype)
{
	char *buf;
	int ret;
	int len;

	buf = hid_alloc_report_buf(report, GFP_KERNEL);
	if (!buf)
		return;

	len = hid_report_len(report);

	if (reqtype == HID_REQ_SET_REPORT)
		hid_output_report(report, buf);

	ret = hid_hw_raw_request(hid, report->id, buf, len, report->type, reqtype);
	if (ret < 0) {
		dbg_hid("unable to complete request: %d\n", ret);
		goto out;
	}

	if (reqtype == HID_REQ_GET_REPORT)
		hid_input_report(hid, report->type, buf, ret, 0);

out:
	kfree(buf);
}

typeof(klpp___hid_request) klpp___hid_request;

int hid_input_report(struct hid_device *hid, int type, u8 *data, int size, int interrupt);

extern typeof(hid_input_report) hid_input_report;


#include "livepatch_bsc1247350.h"


#endif /* IS_ENABLED(CONFIG_HID) */
