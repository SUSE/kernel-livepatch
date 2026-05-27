/*
 * livepatch_bsc1265384
 *
 * Fix for CVE-2026-46333, bsc#1265384
 *
 *  Copyright (c) 2026 SUSE
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

#include "livepatch_bsc1265384.h"

int livepatch_bsc1265384_init(void)
{

	int ret;

	ret = bsc1265384_kernel_exit_init();
	if (ret)
		return ret;

	ret = bsc1265384_kernel_ptrace_init();
	if (ret)
		return ret;

	return 0;
}
