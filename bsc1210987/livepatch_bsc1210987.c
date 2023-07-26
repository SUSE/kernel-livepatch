/*
 * livepatch_bsc1210987
 *
 * Fix for CVE-2023-2235, bsc#1210987
 *
 *  Upstream commit:
 *  fd0815f632c2 ("perf: Fix check before add_event_to_groups() in perf_group_detach()")
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  4cee3ee6817c5ae71f238e0d261b1d10f5cd440f
 *
 *  Copyright (c) 2023 SUSE
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

#include "livepatch_bsc1210987.h"

int livepatch_bsc1210987_init(void)
{
	int ret;

	ret = bsc1210987_kernel_events_core_init();
	if (ret)
		return ret;

	return bsc1210987_fs_exec_init();
}
