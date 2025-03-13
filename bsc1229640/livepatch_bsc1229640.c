/*
 * livepatch_bsc1229640
 *
 * Fix for CVE-2022-48911, bsc#1229640
 *
 *  Upstream commit:
 *  c3873070247d ("netfilter: nf_queue: fix possible use-after-free")
 *
 *  SLE12-SP5 commit:
 *  c9290c819f2c50b00ce1887644ae99c1c7226d37
 *  ffffe4c02f4c7d96e0d21754c333ebd6922e22dd
 *
 *  SLE15-SP3 commit:
 *  255f1f20ed6c931bc352bab1d1fd40a6b4937c21
 *  5c4894e8238d5251870b7d94f667348ac7e5c668
 *
 *  SLE15-SP4 and -SP5 commit:
 *  758c6b1299c09ef730f452c74ec7f72a9327354f
 *  09526c9424a7fbc2a4d656f79c4ad7878f435ecb
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

#include "livepatch_bsc1229640.h"

int livepatch_bsc1229640_init(void)
{
	return bsc1229640_net_netfilter_nfnetlink_queue_init();
}

void livepatch_bsc1229640_cleanup(void)
{
	bsc1229640_net_netfilter_nfnetlink_queue_cleanup();
}

