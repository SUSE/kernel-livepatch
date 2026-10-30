/*
 * livepatch_bsc1272521
 *
 * Fix for CVE-2026-63968, bsc#1272521
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1272521.h"


#define CC_USING_FENTRY 1
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

/* klp-ccp: from include/net/ip6_fib.h */
/* klp-ccp: from net/ipv6/route.c */
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

/* klp-ccp: from net/ipv6/route.c */
extern int rt6_score_route(const struct fib6_nh *nh, u32 fib6_flags, int oif,
			   int strict);

static struct fib6_info *
rt6_multipath_first_sibling_rcu(const struct fib6_info *rt)
{
	struct fib6_info *iter;
	struct fib6_node *fn;

	fn = rcu_dereference(rt->fib6_node);
	if (!fn)
		goto out;
	iter = rcu_dereference(fn->leaf);
	if (!iter)
		goto out;

	while (iter) {
		if (iter->fib6_metric == rt->fib6_metric &&
		    rt6_qualify_for_ecmp(iter))
			return iter;
		iter = rcu_dereference(iter->fib6_next);
	}

out:
	return NULL;
}

void klpp_fib6_select_path(const struct net *net, struct fib6_result *res,
		      struct flowi6 *fl6, int oif, bool have_oif_match,
		      const struct sk_buff *skb, int strict)
{
	struct fib6_info *first, *match = res->f6i;
	struct fib6_info *sibling;
	int hash;

	if (!match->nh && (!match->fib6_nsiblings || have_oif_match))
		goto out;

	if (match->nh && have_oif_match && res->nh)
		return;

	if (skb)
		IP6CB(skb)->flags |= IP6SKB_MULTIPATH;

	/* We might have already computed the hash for ICMPv6 errors. In such
	 * case it will always be non-zero. Otherwise now is the time to do it.
	 */
	if (!fl6->mp_hash &&
	    (!match->nh || nexthop_is_multipath(match->nh)))
		fl6->mp_hash = rt6_multipath_hash(net, fl6, skb, NULL);

	if (unlikely(match->nh)) {
		nexthop_path_fib6_result(res, fl6->mp_hash);
		return;
	}

	first = rt6_multipath_first_sibling_rcu(match);
	if (!first)
		goto out;

	hash = fl6->mp_hash;
	if (hash <= atomic_read(&first->fib6_nh->fib_nh_upper_bound)) {
		if (rt6_score_route(first->fib6_nh, first->fib6_flags, oif,
				    strict) >= 0)
			match = first;
		goto out;
	}

	list_for_each_entry_rcu(sibling, &first->fib6_siblings,
				fib6_siblings) {
		const struct fib6_nh *nh = sibling->fib6_nh;
		int nh_upper_bound;

		if (!READ_ONCE(first->fib6_nsiblings))
			break;

		nh_upper_bound = atomic_read(&nh->fib_nh_upper_bound);
		if (hash > nh_upper_bound)
			continue;
		if (rt6_score_route(nh, sibling->fib6_flags, oif, strict) < 0)
			break;
		match = sibling;
		break;
	}

out:
	res->f6i = match;
	res->nh = match->fib6_nh;
}

int rt6_score_route(const struct fib6_nh *nh, u32 fib6_flags, int oif,
			   int strict);

u32 rt6_multipath_hash(const struct net *net, const struct flowi6 *fl6,
		       const struct sk_buff *skb, struct flow_keys *flkeys);


#include <linux/livepatch.h>

extern typeof(rt6_multipath_hash) rt6_multipath_hash
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rt6_multipath_hash);
extern typeof(rt6_score_route) rt6_score_route
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rt6_score_route);
