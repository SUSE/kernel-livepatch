/*
 * livepatch_bsc1207822
 *
 * Fix for CVE-2023-0590, bsc#1207822
 *
 *  Upstream commit:
 *  5891cd5ec46c ("net_sched: add __rcu annotation to netdev->qdisc")
 *  ebda44da44f6 ("net: sched: fix race condition in qdisc_graft()")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  e8d302b6bcacbcc1b1cf5bb3e6cb63d3b6313c5d
 *  880415ec0772223ead8ac06ee63c63f25172de60
 *
 *  SLE15-SP2 and -SP3 commit:
 *  89a2abc12040e875828d461c1912730354bb20f0
 *  c6f042bad3a3eff336026ed65bb33b00ba322c06
 *
 *  SLE15-SP4 commit:
 *  4949e69d638ebbc678e948d4ee9f47d76275e315
 *  37e8915496bf62feba511789c7d351bc4102df89
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

#include "livepatch_bsc1207822.h"

int livepatch_bsc1207822_init(void)
{
	int ret;

	ret = bsc1207822_net_core_rtnetlink_init();
	if (ret)
		return ret;

	ret = bsc1207822_net_sched_cls_api_init();
	if (ret)
		return ret;

	ret = bsc1207822_net_sched_sch_api_init();
	if (ret)
		return ret;

	return bsc1207822_net_sched_sch_generic_init();
}
