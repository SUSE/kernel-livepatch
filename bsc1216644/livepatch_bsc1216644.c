/*
 * livepatch_bsc1216644
 *
 * Fix for CVE-2023-5717, bsc#1216644
 *
 *  Upstream commit:
 *  2aeb18835476 ("perf/core: Fix locking for children siblings group read")
 *  a9cd8194e1e6 ("perf/core: Fix __perf_read_group_add() locking")
 *  32671e3799ca ("perf: Disallow mis-matched inherited group reads")
 *  a71ef31485bb ("perf/core: Fix potential NULL deref")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#include "livepatch_bsc1216644.h"

int livepatch_bsc1216644_init(void)
{
	int ret;

	ret = bsc1216644_fs_read_write_init();
	if (ret)
		return ret;

	ret = bsc1216644_kernel_events_core_init();

	return ret;
}

void livepatch_bsc1216644_cleanup(void)
{
}

