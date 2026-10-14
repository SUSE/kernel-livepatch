/*
 * livepatch_bsc1269775
 *
 * Fix for CVE-2026-53131, bsc#1269775
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

#include "livepatch_bsc1269775.h"

int livepatch_bsc1269775_init(void)
{

	int ret;

	ret = bsc1269775_net_ipv4_netfilter_nf_log_ipv4_init();
	if (ret)
		return ret;

	ret = bsc1269775_net_netfilter_ipset_ip_set_hash_ipmac_init();
	if (ret) {
		bsc1269775_net_ipv4_netfilter_nf_log_ipv4_cleanup();
		return ret;
	}

	ret = bsc1269775_net_netfilter_ipset_ip_set_hash_mac_init();
	if (ret) {
		bsc1269775_net_netfilter_ipset_ip_set_hash_ipmac_cleanup();
		bsc1269775_net_ipv4_netfilter_nf_log_ipv4_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1269775_cleanup(void)
{
	bsc1269775_net_ipv4_netfilter_nf_log_ipv4_cleanup();

	bsc1269775_net_netfilter_ipset_ip_set_hash_ipmac_cleanup();

	bsc1269775_net_netfilter_ipset_ip_set_hash_mac_cleanup();

}

