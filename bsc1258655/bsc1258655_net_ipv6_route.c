/*
 * bsc1258655_net_ipv6_route
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
#include <net/net_namespace.h>
#include <net/snmp.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
/* klp-ccp: from net/ipv6/route.c */
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/tcp.h>
#include <linux/rtnetlink.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/xfrm.h>
#include <net/netevent.h>
#include <net/netlink.h>
#include <net/nexthop.h>
#include <net/lwtunnel.h>
#include <net/ip_tunnels.h>
#include <net/l3mdev.h>
#include <trace/events/fib6.h>
#include <linux/uaccess.h>

struct uncached_list {
	spinlock_t		lock;
	struct list_head	head;
};

void klpp_rt6_uncached_list_del(struct rt6_info *rt)
{
	if (!list_empty_careful(&rt->rt6i_uncached)) {
		struct uncached_list *ul = rt->rt6i_uncached_list;

		spin_lock_bh(&ul->lock);
		list_del(&rt->rt6i_uncached);
		spin_unlock_bh(&ul->lock);
	}
}


