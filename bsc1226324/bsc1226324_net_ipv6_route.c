/*
 * bsc1226324_net_ipv6_route
 *
 * Fix for CVE-2024-36971, bsc#1226324
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

#include <linux/socket.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#include <linux/in6.h>
#include <linux/mroute6.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/dst.h>

extern bool rt6_check_expired(const struct rt6_info *rt);

extern int rt6_remove_exception_rt(struct rt6_info *rt);

void klpp_ip6_negative_advice(struct sock *sk,
				struct dst_entry *dst)
{
	struct rt6_info *rt = (struct rt6_info *) dst;

	if (rt->rt6i_flags & RTF_CACHE) {
		rcu_read_lock();
		if (rt6_check_expired(rt)) {
			/* counteract the dst_release() in sk_dst_reset() */
			dst_hold(dst);
			sk_dst_reset(sk);

			rt6_remove_exception_rt(rt);
		}
		rcu_read_unlock();
		return;
	}
	sk_dst_reset(sk);
}

#include <linux/livepatch.h>

#include "bsc1226324_net_sock.h"

extern typeof(rt6_check_expired) rt6_check_expired
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rt6_check_expired);
extern typeof(rt6_remove_exception_rt) rt6_remove_exception_rt
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rt6_remove_exception_rt);
