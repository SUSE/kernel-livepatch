/*
 * livepatch_bsc1218259
 *
 * Fix for CVE-2023-6931, bsc#1218259
 *
 *  Upstream commit:
 *  382c27f4ed28 ("perf: Fix perf_event_validate_size()")
 *  7e2c1e4b34f0 ("perf: Fix perf_event_validate_size() lockdep splat")
 *
 *  SLE12-SP5 commit:
 *  3382aa663bf38157af75198132218bb7a2270785
 *  fd712a18a542d00b5713fdf45ac946c540c15dd2
 *  6cfe60a0ed9f9c6cf176d9d4c16e63369450bce7
 *
 *  SLE15-SP2 and -SP3 commit:
 *  dbc4d269434669b20c6c80a78807399da0d73c69
 *  e551d3dee61967e9a6e1171c5ca931b00d982520
 *
 *  SLE15-SP4 and -SP5 commit:
 *  4facf16cb84c1c10a9988ec963bca97836179edc
 *  00427a6c56c991558f517efb938587b224fa5f0c
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

#include "livepatch_bsc1218259.h"

int livepatch_bsc1218259_init(void)
{
	int ret;

	ret = bsc1218259_kernel_events_core_init();
	if (ret)
		return ret;
	return bsc1218259_fs_read_write_init();
}

