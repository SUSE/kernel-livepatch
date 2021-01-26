/*
 * livepatch_bsc1180030
 *
 * Fix for CVE-2020-0465, bsc#1180030
 *
 *  Upstream commit:
 *  35556bed836f ("HID: core: Sanitize event code and type when mapping input")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  396f3963e96b22b2349e4576e5a94f1d805da7d2
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  ebf9f0ea8ad8612e0fd8f9fb7cdac5164c9b0b82
 *
 *  SLE15-SP2 commit:
 *  b6c4f54e5f92ad6408efd84929722f48ed98d2d1
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1180030.h"

int livepatch_bsc1180030_init(void)
{
	int r;

	r = livepatch_bsc1180030_hid_input_init();
	if (r)
		return r;

	r = livepatch_bsc1180030_hid_multitouch_init();
	if (r) {
		livepatch_bsc1180030_hid_input_cleanup();
		return r;
	}

	return 0;
}

void livepatch_bsc1180030_cleanup(void)
{
	livepatch_bsc1180030_hid_multitouch_cleanup();
	livepatch_bsc1180030_hid_input_cleanup();
}

#endif /* IS_ENABLED(CONFIG_HID) */
