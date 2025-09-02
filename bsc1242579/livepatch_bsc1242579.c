/*
 * livepatch_bsc1242579
 *
 * Fix for CVE-2025-21999, bsc#1242579
 *
 *  Upstream commit:
 *  654b33ada4ab ("proc: fix UAF in proc_get_inode()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  8fb79443f171c25aa2bc5c937b7a3d1b47231ba2
 *
 *  SLE15-SP6 commit:
 *  15e810e82439d49cdc4d92417d8417c077c79cba
 *
 *  SLE MICRO-6-0 commit:
 *  15e810e82439d49cdc4d92417d8417c077c79cba
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

#include "livepatch_bsc1242579.h"

int livepatch_bsc1242579_init(void)
{
    return 0;
}

void livepatch_bsc1242579_cleanup(void)
{
}

