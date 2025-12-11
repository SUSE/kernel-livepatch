/*
 * bsc1249241_net_ipv6_route
 *
 * Fix for CVE-2025-38588, bsc#1249241
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/ipv6/route.c */
#define pr_fmt(fmt) "IPv6: " fmt

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/times.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/mroute6.h>
#include <linux/init.h>
#include <linux/if_arp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/siphash.h>
#include <net/net_namespace.h>
#include <net/snmp.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/tcp.h>
#include <linux/rtnetlink.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/xfrm.h>
#include <net/netevent.h>
#include <net/netlink.h>
#include <net/rtnh.h>
#include <net/lwtunnel.h>
#include <net/ip_tunnels.h>
#include <net/l3mdev.h>
#include <net/ip.h>
#include <linux/uaccess.h>
#include <linux/btf_ids.h>

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#include <linux/in6.h>
#include <net/flow.h>
#include <net/ip6_fib.h>
#include <linux/tracepoint.h>

#include "livepatch_bsc1249241.h"

/* klp-ccp: from net/ipv6/route.c */
extern int rt6_nh_nlmsg_size(struct fib6_nh *nh, void *arg);

size_t klpp_rt6_nlmsg_size(struct fib6_info *f6i)
{
	struct fib6_info *sibling;
	struct fib6_nh *nh;
	int nexthop_len;

	if (f6i->nh) {
		nexthop_len = nla_total_size(4); /* RTA_NH_ID */
		nexthop_for_each_fib6_nh(f6i->nh, rt6_nh_nlmsg_size,
					 &nexthop_len);
		goto common;
	}

	rcu_read_lock();
retry:
	nh = f6i->fib6_nh;
	nexthop_len = 0;
	if (READ_ONCE(f6i->fib6_nsiblings)) {
		rt6_nh_nlmsg_size(nh, &nexthop_len);

		list_for_each_entry_rcu(sibling, &f6i->fib6_siblings,
					fib6_siblings) {
			rt6_nh_nlmsg_size(sibling->fib6_nh, &nexthop_len);
			if (!READ_ONCE(f6i->fib6_nsiblings))
				goto retry;
		}
	}

	rcu_read_unlock();
	nexthop_len += lwtunnel_get_encap_size(nh->fib_nh_lws);
common:
	return NLMSG_ALIGN(sizeof(struct rtmsg))
	       + nla_total_size(16) /* RTA_SRC */
	       + nla_total_size(16) /* RTA_DST */
	       + nla_total_size(16) /* RTA_GATEWAY */
	       + nla_total_size(16) /* RTA_PREFSRC */
	       + nla_total_size(4) /* RTA_TABLE */
	       + nla_total_size(4) /* RTA_IIF */
	       + nla_total_size(4) /* RTA_OIF */
	       + nla_total_size(4) /* RTA_PRIORITY */
	       + RTAX_MAX * nla_total_size(4) /* RTA_METRICS */
	       + nla_total_size(sizeof(struct rta_cacheinfo))
	       + nla_total_size(TCP_CA_NAME_MAX) /* RTAX_CC_ALGO */
	       + nla_total_size(1) /* RTA_PREF */
	       + nexthop_len;
}

#include <linux/livepatch.h>

extern typeof(rt6_nh_nlmsg_size) rt6_nh_nlmsg_size
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rt6_nh_nlmsg_size);
