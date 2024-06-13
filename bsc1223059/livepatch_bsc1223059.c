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

/* klp-ccp: from net/ipv6/route.c */
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/mroute6.h>
#include <linux/init.h>

/* klp-ccp: from include/uapi/linux/if_arp.h */
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from net/ipv6/route.c */
#include <linux/seq_file.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
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

/* klp-ccp: from net/ipv6/route.c */
#include <net/netlink.h>
#include <net/nexthop.h>
#include <net/lwtunnel.h>
#include <net/ip_tunnels.h>
#include <net/l3mdev.h>
#include <linux/uaccess.h>

#include <linux/sysctl.h>

static int (*klpe___ip6_ins_rt)(struct rt6_info *rt, struct nl_info *info,
			struct mx6_config *mxc,
			struct netlink_ext_ack *extack);

static int ip6_convert_metrics(struct mx6_config *mxc,
			       const struct fib6_config *cfg)
{
	bool ecn_ca = false;
	struct nlattr *nla;
	int remaining;
	u32 *mp;

	if (!cfg->fc_mx)
		return 0;

	mp = kzalloc(sizeof(u32) * RTAX_MAX, GFP_KERNEL);
	if (unlikely(!mp))
		return -ENOMEM;

	nla_for_each_attr(nla, cfg->fc_mx, cfg->fc_mx_len, remaining) {
		int type = nla_type(nla);
		u32 val;

		if (!type)
			continue;
		if (unlikely(type > RTAX_MAX))
			goto err;

		if (type == RTAX_CC_ALGO) {
			char tmp[TCP_CA_NAME_MAX];

			nla_strlcpy(tmp, nla, sizeof(tmp));
			val = tcp_ca_get_key_by_name(tmp, &ecn_ca);
			if (val == TCP_CA_UNSPEC)
				goto err;
		} else {
			val = nla_get_u32(nla);
		}
		if (type == RTAX_HOPLIMIT && val > 255)
			val = 255;
		if (type == RTAX_FEATURES && (val & ~RTAX_FEATURE_MASK))
			goto err;

		mp[type - 1] = val;
		__set_bit(type - 1, mxc->mx_valid);
	}

	if (ecn_ca) {
		__set_bit(RTAX_FEATURES - 1, mxc->mx_valid);
		mp[RTAX_FEATURES - 1] |= DST_FEATURE_ECN_CA;
	}

	mxc->mx = mp;
	return 0;
 err:
	kfree(mp);
	return -EINVAL;
}

static struct rt6_info *(*klpe_ip6_route_info_create)(struct fib6_config *cfg,
					      struct netlink_ext_ack *extack);

static int (*klpe_ip6_route_del)(struct fib6_config *cfg,
			 struct netlink_ext_ack *extack);

struct rt6_nh {
	struct rt6_info *rt6_info;
	struct fib6_config r_cfg;
	struct mx6_config mxc;
	struct list_head next;
};

static void ip6_print_replace_route_err(struct list_head *rt6_nh_list)
{
	struct rt6_nh *nh;

	list_for_each_entry(nh, rt6_nh_list, next) {
		pr_warn("IPV6: multipath route replace failed (check consistency of installed routes): %pI6c nexthop %pI6c ifi %d\n",
		        &nh->r_cfg.fc_dst, &nh->r_cfg.fc_gateway,
		        nh->r_cfg.fc_ifindex);
	}
}

static int ip6_route_info_append(struct list_head *rt6_nh_list,
				 struct rt6_info *rt, struct fib6_config *r_cfg)
{
	struct rt6_nh *nh;
	int err = -EEXIST;

	list_for_each_entry(nh, rt6_nh_list, next) {
		/* check if rt6_info already exists */
		if (rt6_duplicate_nexthop(nh->rt6_info, rt))
			return err;
	}

	nh = kzalloc(sizeof(*nh), GFP_KERNEL);
	if (!nh)
		return -ENOMEM;
	nh->rt6_info = rt;
	err = ip6_convert_metrics(&nh->mxc, r_cfg);
	if (err) {
		kfree(nh);
		return err;
	}
	memcpy(&nh->r_cfg, r_cfg, sizeof(*r_cfg));
	list_add_tail(&nh->next, rt6_nh_list);

	return 0;
}

static void (*klpe_ip6_route_mpath_notify)(struct rt6_info *rt,
				   struct rt6_info *rt_last,
				   struct nl_info *info,
				   __u16 nlflags);

int klpp_ip6_route_multipath_add(struct fib6_config *cfg,
				   struct netlink_ext_ack *extack)
{
	struct rt6_info *rt_notif = NULL, *rt_last = NULL;
	struct nl_info *info = &cfg->fc_nlinfo;
	struct fib6_config r_cfg;
	struct rtnexthop *rtnh;
	struct rt6_info *rt;
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
	 * rt6_info structs per nexthop
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

		rt = (*klpe_ip6_route_info_create)(&r_cfg, extack);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			goto cleanup;
		}

		err = ip6_route_info_append(&rt6_nh_list, rt, &r_cfg);
		if (err) {
			dst_release_immediate(&rt->dst);
			goto cleanup;
		}

		rtnh = rtnh_next(rtnh, &remaining);
	}

	/* for add and replace send one notification with all nexthops.
	 * Skip the notification in fib6_add_rt2node and send one with
	 * the full route when done
	 */
	info->skip_notify = 1;

	err_nh = NULL;
	list_for_each_entry(nh, &rt6_nh_list, next) {
		err = (*klpe___ip6_ins_rt)(nh->rt6_info, info, &nh->mxc, extack);

		if (err) {
			if (replace && nhn)
				ip6_print_replace_route_err(&rt6_nh_list);
			err_nh = nh;
			goto add_errout;
		}
		/* save reference to last route successfully inserted */
		rt_last = nh->rt6_info;

		/* save reference to first route for notification */
		if (!rt_notif)
			rt_notif = nh->rt6_info;

		/* Because each route is added like a single route we remove
		 * these flags after the first nexthop: if there is a collision,
		 * we have already failed to add the first nexthop:
		 * fib6_add_rt2node() has rejected it; when replacing, old
		 * nexthops have been replaced by first new, the rest should
		 * be added to it.
		 */
		cfg->fc_nlinfo.nlh->nlmsg_flags &= ~(NLM_F_EXCL |
						     NLM_F_REPLACE);
		cfg->fc_nlinfo.nlh->nlmsg_flags |= NLM_F_CREATE;
		nhn++;
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
		dst_release_immediate(&nh->rt6_info->dst);
		kfree(nh->mxc.mx);
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
	{ "ip6_route_del", (void *)&klpe_ip6_route_del },
	{ "ip6_route_info_create", (void *)&klpe_ip6_route_info_create },
	{ "ip6_route_mpath_notify", (void *)&klpe_ip6_route_mpath_notify },
};

int livepatch_bsc1223059_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

