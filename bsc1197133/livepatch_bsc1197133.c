/*
 * livepatch_bsc1197133
 *
 * Fix for CVE-2022-0886, bsc#1197133
 *
 *  Upstream commit:
 *  ebe48d368e97 ("esp: Fix possible buffer overflow in ESP transformation")
 *
 *  SLE12-SP3 commit:
 *  Not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d9e58bc952382484e5a99d925f4a816b3a19f06a
 *
 *  SLE15-SP2 and -SP3 commit:
 *  39a5891f4700699c8c60ae78f7ebd3331edc5275
 *
 *  Copyright (c) 2022 SUSE
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


#include "livepatch_bsc1197133.h"
#include "../kallsyms_relocs.h"

int livepatch_bsc1197133_init(void)
{
	int ret;

	ret = bsc1197133_esp4_init();
	if (ret)
		return ret;

	ret = bsc1197133_esp6_init();
	if (ret)
		bsc1197133_esp4_cleanup();

	return ret;
}

void livepatch_bsc1197133_cleanup(void)
{
	bsc1197133_esp6_cleanup();
	bsc1197133_esp4_cleanup();
}
