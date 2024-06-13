/*
 * livepatch_bsc1223059
 *
 * Fix for CVE-2024-26852, bsc#1223059
 *
 *  Upstream commit:
 *  685f7d531264 ("net/ipv6: avoid possible UAF in ip6_route_mpath_notify()")
 *
 *  SLE12-SP5 commit:
 *  598df4c510ba3a9fc203619e0eae9469e340cbbd
 *
 *  SLE15-SP2 and -SP3 commit:
 *  f51e7441add03a2c748e316d8b09c3cda32b6a55
 *
 *  SLE15-SP4 and -SP5 commit:
 *  d89430d2ce6ed60231027b56b365a526531440f7
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from net/ipv6/route.c */
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/mroute6.h>
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
#include <net/ip6_fib.h>

/* klp-ccp: from include/net/ip6_fib.h */
static int (*klpe_call_fib6_multipath_entry_notifiers)(struct net *net,
					enum fib_event_type event_type,
					struct fib6_info *rt,
					unsigned int nsiblings,
					struct netlink_ext_ack *extack);

/* klp-ccp: from net/ipv6/route.c */
#include <net/ip6_route.h>
#include <net/ndisc.h>
#include <net/addrconf.h>

/* klp-ccp: from net/ipv6/route.c */
#include <linux/rtnetlink.h>
#include <net/dst.h>

/* klp-ccp: from net/ipv6/route.c */
#include <net/netlink.h>
#include <net/rtnh.h>
#include <net/lwtunnel.h>
#include <net/ip_tunnels.h>
#include <net/l3mdev.h>
#include <net/ip.h>
#include <linux/uaccess.h>

#include <linux/sysctl.h>

/* klp-ccp: from net/ipv6/route.c */
static int (*klpe___ip6_ins_rt)(struct fib6_info *rt, struct nl_info *info,
			struct netlink_ext_ack *extack);

static struct fib6_info *(*klpe_ip6_route_info_create)(struct fib6_config *cfg,
					      gfp_t gfp_flags,
					      struct netlink_ext_ack *extack);

static int (*klpe_ip6_route_del)(struct fib6_config *cfg,
			 struct netlink_ext_ack *extack);

struct rt6_nh {
	struct fib6_info *fib6_info;
	struct fib6_config r_cfg;
	struct list_head next;
};

static int ip6_route_info_append(struct net *net,
				 struct list_head *rt6_nh_list,
				 struct fib6_info *rt,
				 struct fib6_config *r_cfg)
{
	struct rt6_nh *nh;
	int err = -EEXIST;

	list_for_each_entry(nh, rt6_nh_list, next) {
		/* check if fib6_info already exists */
		if (rt6_duplicate_nexthop(nh->fib6_info, rt))
			return err;
	}

	nh = kzalloc(sizeof(*nh), GFP_KERNEL);
	if (!nh)
		return -ENOMEM;
	nh->fib6_info = rt;
	memcpy(&nh->r_cfg, r_cfg, sizeof(*r_cfg));
	list_add_tail(&nh->next, rt6_nh_list);

	return 0;
}

static void (*klpe_ip6_route_mpath_notify)(struct fib6_info *rt,
				   struct fib6_info *rt_last,
				   struct nl_info *info,
				   __u16 nlflags);

static bool ip6_route_mpath_should_notify(const struct fib6_info *rt)
{
	bool rt_can_ecmp = rt6_qualify_for_ecmp(rt);
	bool should_notify = false;
	struct fib6_info *leaf;
	struct fib6_node *fn;

	rcu_read_lock();
	fn = rcu_dereference(rt->fib6_node);
	if (!fn)
		goto out;

	leaf = rcu_dereference(fn->leaf);
	if (!leaf)
		goto out;

	if (rt == leaf ||
	    (rt_can_ecmp && rt->fib6_metric == leaf->fib6_metric &&
	     rt6_qualify_for_ecmp(leaf)))
		should_notify = true;
out:
	rcu_read_unlock();

	return should_notify;
}

int klpp_ip6_route_multipath_add(struct fib6_config *cfg,
				   struct netlink_ext_ack *extack)
{
	struct fib6_info *rt_notif = NULL, *rt_last = NULL;
	struct nl_info *info = &cfg->fc_nlinfo;
	struct fib6_config r_cfg;
	struct rtnexthop *rtnh;
	struct fib6_info *rt;
	struct rt6_nh *err_nh;
	struct rt6_nh *nh, *nh_safe;
	__u16 nlflags;
	int remaining;
	int attrlen;
	int err = 1;
	int nhn = 0;
	int replace = (cfg->fc_nlinfo.nlh &&
		       (cfg->fc_nlinfo.nlh->nlmsg_flags & NLM_F_REPLACE));
	LIST_HEAD(rt6_nh_list);

	nlflags = replace ? NLM_F_REPLACE : NLM_F_CREATE;
	if (info->nlh && info->nlh->nlmsg_flags & NLM_F_APPEND)
		nlflags |= NLM_F_APPEND;

	remaining = cfg->fc_mp_len;
	rtnh = (struct rtnexthop *)cfg->fc_mp;

	/* Parse a Multipath Entry and build a list (rt6_nh_list) of
	 * fib6_info structs per nexthop
	 */
	while (rtnh_ok(rtnh, remaining)) {
		memcpy(&r_cfg, cfg, sizeof(*cfg));
		if (rtnh->rtnh_ifindex)
			r_cfg.fc_ifindex = rtnh->rtnh_ifindex;

		attrlen = rtnh_attrlen(rtnh);
		if (attrlen > 0) {
			struct nlattr *nla, *attrs = rtnh_attrs(rtnh);

			nla = nla_find(attrs, attrlen, RTA_GATEWAY);
			if (nla) {
				r_cfg.fc_gateway = nla_get_in6_addr(nla);
				r_cfg.fc_flags |= RTF_GATEWAY;
			}
			r_cfg.fc_encap = nla_find(attrs, attrlen, RTA_ENCAP);
			nla = nla_find(attrs, attrlen, RTA_ENCAP_TYPE);
			if (nla)
				r_cfg.fc_encap_type = nla_get_u16(nla);
		}

		r_cfg.fc_flags |= (rtnh->rtnh_flags & RTNH_F_ONLINK);
		rt = (*klpe_ip6_route_info_create)(&r_cfg, GFP_KERNEL, extack);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			goto cleanup;
		}
		if (!rt6_qualify_for_ecmp(rt)) {
			err = -EINVAL;
			NL_SET_ERR_MSG(extack,
				       "Device only routes can not be added for IPv6 using the multipath API.");
			fib6_info_release(rt);
			goto cleanup;
		}

		rt->fib6_nh->fib_nh_weight = rtnh->rtnh_hops + 1;

		err = ip6_route_info_append(info->nl_net, &rt6_nh_list,
					    rt, &r_cfg);
		if (err) {
			fib6_info_release(rt);
			goto cleanup;
		}

		rtnh = rtnh_next(rtnh, &remaining);
	}

	if (list_empty(&rt6_nh_list)) {
		NL_SET_ERR_MSG(extack,
			       "Invalid nexthop configuration - no valid nexthops");
		return -EINVAL;
	}

	/* for add and replace send one notification with all nexthops.
	 * Skip the notification in fib6_add_rt2node and send one with
	 * the full route when done
	 */
	info->skip_notify = 1;

	/* For add and replace, send one notification with all nexthops. For
	 * append, send one notification with all appended nexthops.
	 */
	info->skip_notify_kernel = 1;

	err_nh = NULL;
	list_for_each_entry(nh, &rt6_nh_list, next) {
		err = (*klpe___ip6_ins_rt)(nh->fib6_info, info, extack);

		if (err) {
			if (replace && nhn)
				NL_SET_ERR_MSG_MOD(extack,
						   "multipath route replace failed (check consistency of installed routes)");
			err_nh = nh;
			goto add_errout;
		}
		/* save reference to last route successfully inserted */
		rt_last = nh->fib6_info;

		/* save reference to first route for notification */
		if (!rt_notif)
			rt_notif = nh->fib6_info;

		/* Because each route is added like a single route we remove
		 * these flags after the first nexthop: if there is a collision,
		 * we have already failed to add the first nexthop:
		 * fib6_add_rt2node() has rejected it; when replacing, old
		 * nexthops have been replaced by first new, the rest should
		 * be added to it.
		 */
		if (cfg->fc_nlinfo.nlh) {
			cfg->fc_nlinfo.nlh->nlmsg_flags &= ~(NLM_F_EXCL |
							     NLM_F_REPLACE);
			cfg->fc_nlinfo.nlh->nlmsg_flags |= NLM_F_CREATE;
		}
		nhn++;
	}

	/* An in-kernel notification should only be sent in case the new
	 * multipath route is added as the first route in the node, or if
	 * it was appended to it. We pass 'rt_notif' since it is the first
	 * sibling and might allow us to skip some checks in the replace case.
	 */
	if (ip6_route_mpath_should_notify(rt_notif)) {
		enum fib_event_type fib_event;

		if (rt_notif->fib6_nsiblings != nhn - 1)
			fib_event = FIB_EVENT_ENTRY_APPEND;
		else
			fib_event = FIB_EVENT_ENTRY_REPLACE;

		err = (*klpe_call_fib6_multipath_entry_notifiers)(info->nl_net,
							  fib_event, rt_notif,
							  nhn - 1, extack);
		if (err) {
			/* Delete all the siblings that were just added */
			err_nh = NULL;
			goto add_errout;
		}
	}

	/* success ... tell user about new route */
	(*klpe_ip6_route_mpath_notify)(rt_notif, rt_last, info, nlflags);
	goto cleanup;

add_errout:
	/* send notification for routes that were added so that
	 * the delete notifications sent by ip6_route_del are
	 * coherent
	 */
	if (rt_notif)
		(*klpe_ip6_route_mpath_notify)(rt_notif, rt_last, info, nlflags);

	/* Delete routes that were already added */
	list_for_each_entry(nh, &rt6_nh_list, next) {
		if (err_nh == nh)
			break;
		(*klpe_ip6_route_del)(&nh->r_cfg, extack);
	}

cleanup:
	list_for_each_entry_safe(nh, nh_safe, &rt6_nh_list, next) {
		fib6_info_release(nh->fib6_info);
		list_del(&nh->next);
		kfree(nh);
	}

	return err;
}


#include "livepatch_bsc1223059.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__ip6_ins_rt", (void *)&klpe___ip6_ins_rt },
	{ "call_fib6_multipath_entry_notifiers",
	  (void *)&klpe_call_fib6_multipath_entry_notifiers },
	{ "ip6_route_del", (void *)&klpe_ip6_route_del },
	{ "ip6_route_info_create", (void *)&klpe_ip6_route_info_create },
	{ "ip6_route_mpath_notify", (void *)&klpe_ip6_route_mpath_notify },
};

int livepatch_bsc1223059_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

