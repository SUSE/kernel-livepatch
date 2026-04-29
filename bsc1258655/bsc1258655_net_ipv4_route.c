/*
 * bsc1258655_net_ipv4_route
 *
 * Fix for CVE-2026-23004, bsc#1258655
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


#include "livepatch_bsc1258655.h"


/* klp-ccp: from net/ipv4/route.c */
#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/pkt_sched.h>
#include <linux/mroute.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <net/dst.h>
#include <net/dst_metadata.h>

/* klp-ccp: from include/net/route.h */
void klpp_rt_del_uncached_list(struct rtable *rt);

/* klp-ccp: from net/ipv4/route.c */
#include <net/inet_dscp.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/nexthop.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/lwtunnel.h>
#include <net/netevent.h>
#include <net/rtnetlink.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <net/secure_seq.h>
#include <net/ip_tunnels.h>
/* klp-ccp: from net/ipv4/fib_lookup.h */
#include <linux/types.h>
#include <linux/list.h>
#include <net/inet_dscp.h>
#include <net/ip_fib.h>
#include <net/nexthop.h>

/* klp-ccp: from net/ipv4/route.c */
struct uncached_list {
	spinlock_t		lock;
	struct list_head	head;
	struct list_head	quarantine;
};

void klpp_rt_del_uncached_list(struct rtable *rt)
{
	if (!list_empty_careful(&rt->dst.rt_uncached)) {
		struct uncached_list *ul = rt->dst.rt_uncached_list;

		spin_lock_bh(&ul->lock);
		list_del_init(&rt->dst.rt_uncached);
		spin_unlock_bh(&ul->lock);
	}
}


