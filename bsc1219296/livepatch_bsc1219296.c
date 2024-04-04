/*
 * livepatch_bsc1219296
 *
 * Fix for CVE-2023-52340, bsc#1219296
 *
 *  Upstream commit:
 *  af6d10345ca7 ("ipv6: remove max_size check inline with ipv4")
 *
 *  SLE12-SP5 commit:
 *  86328ba67bbf43a3e277d56203112245a5b1b6c4
 *
 *  SLE15-SP2 and -SP3 commit:
 *  ab715a2964f172bbf3dba8149b0e2cecb004f0bc
 *
 *  SLE15-SP4 and SLE15-SP5 commit:
 *  cef4e7475f0d99a43934aaacf38cb76f557da5f7
 *
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from net/ipv6/route.c */
#define pr_fmt(fmt) "IPv6: " fmt

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/if_arp.h>
#include <linux/seq_file.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/siphash.h>
#include <net/net_namespace.h>
#include <net/snmp.h>
#include <net/ipv6.h>

/* klp-ccp: from include/net/ip6_fib.h */
static void (*klpe_fib6_run_gc)(unsigned long expires, struct net *net, bool force);

/* klp-ccp: from net/ipv6/route.c */
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <linux/rtnetlink.h>
#include <net/dst.h>
#include <net/netlink.h>
#include <net/lwtunnel.h>
#include <net/ip_tunnels.h>
#include <net/l3mdev.h>
#include <net/ip.h>
#include <linux/uaccess.h>

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

int klpp_ip6_dst_gc(struct dst_ops *ops)
{
	struct net *net = container_of(ops, struct net, ipv6.ip6_dst_ops);
	int rt_min_interval = net->ipv6.sysctl.ip6_rt_gc_min_interval;
	int rt_elasticity = net->ipv6.sysctl.ip6_rt_gc_elasticity;
	int rt_gc_timeout = net->ipv6.sysctl.ip6_rt_gc_timeout;
	unsigned long rt_last_gc = net->ipv6.ip6_rt_last_gc;
	int entries;

	entries = dst_entries_get_fast(ops);
	if (time_after(rt_last_gc + rt_min_interval, jiffies))
		goto out;

	net->ipv6.ip6_rt_gc_expire++;
	(*klpe_fib6_run_gc)(net->ipv6.ip6_rt_gc_expire, net, true);
	entries = dst_entries_get_slow(ops);
	if (entries < ops->gc_thresh)
		net->ipv6.ip6_rt_gc_expire = rt_gc_timeout>>1;
out:
	net->ipv6.ip6_rt_gc_expire -= net->ipv6.ip6_rt_gc_expire>>rt_elasticity;
	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1219296.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fib6_run_gc", (void *)&klpe_fib6_run_gc },
};

int livepatch_bsc1219296_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
