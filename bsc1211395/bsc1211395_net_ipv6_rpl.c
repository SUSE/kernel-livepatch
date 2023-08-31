/*
 * bsc1211395_net_ipv6_rpl
 *
 * Fix for CVE-2023-2156, bsc#1211395
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

/* klp-ccp: from net/ipv6/rpl.c */
#include <net/ipv6.h>

#include <net/rpl.h>
#include <linux/types.h>

/* klp-ccp: from net/ipv6/rpl.c */
#define IPV6_PFXTAIL_LEN(x) (sizeof(struct in6_addr) - (x))

size_t klpp_ipv6_rpl_srh_size(unsigned char n, unsigned char cmpri,
			 unsigned char cmpre)
{
	return sizeof(struct ipv6_rpl_sr_hdr) + (n * IPV6_PFXTAIL_LEN(cmpri)) +
		IPV6_PFXTAIL_LEN(cmpre);
}
