/*
 * livepatch_bsc1188117
 *
 * Fix for CVE-2021-22555, bsc#1188117
 *
 *  Upstream commit:
 *  b29c457a6511 ("netfilter: x_tables: fix compat match/target pad out-of-bound
 *                 write")
 *
 *  SLE12-SP3 commit:
 *  96e51bef4a760ec1c389968f68cc4c7b7f082144
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  62f135929e4afec6e29519fb073df22eff7d31d8
 *
 *  SLE15-SP2 and -SP3 commit:
 *  5d3d4dac3a7f8d698be29f411f0b9a8c6d38932b
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

#if !IS_ENABLED(CONFIG_COMPAT)
#error "Live patch supports only CONFIG_CONPAT=y"
#endif

#include <linux/kernel.h>
#include "bsc1188117_common.h"
#include "livepatch_bsc1188117.h"

int livepatch_bsc1188117_init(void)
{
	int ret;

	ret = livepatch_bsc1188117_x_tables_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1188117_arp_tables_init();
	if (ret) {
		livepatch_bsc1188117_x_tables_cleanup();
		return ret;
	}

	ret = livepatch_bsc1188117_ip_tables_init();
	if (ret) {
		livepatch_bsc1188117_arp_tables_cleanup();
		livepatch_bsc1188117_x_tables_cleanup();
		return ret;
	}

	ret = livepatch_bsc1188117_ip6_tables_init();
	if (ret) {
		livepatch_bsc1188117_ip_tables_cleanup();
		livepatch_bsc1188117_arp_tables_cleanup();
		livepatch_bsc1188117_x_tables_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1188117_cleanup(void)
{
	livepatch_bsc1188117_ip6_tables_cleanup();
	livepatch_bsc1188117_ip_tables_cleanup();
	livepatch_bsc1188117_arp_tables_cleanup();
	livepatch_bsc1188117_x_tables_cleanup();
}
