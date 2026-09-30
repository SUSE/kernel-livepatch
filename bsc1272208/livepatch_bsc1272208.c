/*
 * livepatch_bsc1272208
 *
 * Fix for CVE-2026-64189, bsc#1272208
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1272208.h"


/* klp-ccp: from net/netfilter/ipset/ip_set_core.c */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

extern rwlock_t ip_set_ref_lock;

struct ip_set_net {
	struct ip_set * __rcu *ip_set_list;	/* all individual sets */
	ip_set_id_t	ip_set_max;	/* max number of sets */
	bool		is_deleted;	/* deleted by ip_set_net_exit */
	bool		is_destroyed;	/* all sets are destroyed */
};

extern unsigned int ip_set_net_id __read_mostly;

static struct ip_set_net *ip_set_pernet(struct net *net)
{
	return net_generic(net, ip_set_net_id);
}

#define ip_set_dereference(p)		\
	rcu_dereference_protected(p,	\
		lockdep_nfnl_is_held(NFNL_SUBSYS_IPSET) || \
		lockdep_is_held(&ip_set_ref_lock))

#define ip_set_ref_netlink(inst,id)	\
	rcu_dereference_raw((inst)->ip_set_list)[id]

static void
__ip_set_put_netlink(struct ip_set *set)
{
	write_lock_bh(&ip_set_ref_lock);
	BUG_ON(set->ref_netlink == 0);
	set->ref_netlink--;
	write_unlock_bh(&ip_set_ref_lock);
}

static struct nlmsghdr *
start_msg(struct sk_buff *skb, u32 portid, u32 seq, unsigned int flags,
	  enum ipset_cmd cmd)
{
	return nfnl_msg_put(skb, portid, seq,
			    nfnl_msg_type(NFNL_SUBSYS_IPSET, cmd), flags,
			    NFPROTO_IPV4, NFNETLINK_V0, 0);
}

#define DUMP_ALL	1
#define DUMP_ONE	2
#define DUMP_LAST	3

#define DUMP_TYPE(arg)		(((u32)(arg)) & 0x0000FFFF)
#define DUMP_FLAGS(arg)		(((u32)(arg)) >> 16)

int
klpp_ip_set_dump_done(struct netlink_callback *cb)
{
	if (cb->args[IPSET_CB_ARG0]) {
		struct ip_set_net *inst =
			(struct ip_set_net *)cb->args[IPSET_CB_NET];
		ip_set_id_t index = (ip_set_id_t)cb->args[IPSET_CB_INDEX];
		struct ip_set *set;

		rcu_read_lock();
		set = ip_set_ref_netlink(inst, index);
		rcu_read_unlock();

		if (set->variant->uref)
			set->variant->uref(set, cb, false);
		pr_debug("release set %s\n", set->name);
		__ip_set_put_netlink(set);
	}
	return 0;
}

static inline void
dump_attrs(struct nlmsghdr *nlh)
{
	const struct nlattr *attr;
	int rem;

	pr_debug("dump nlmsg\n");
	nlmsg_for_each_attr(attr, nlh, sizeof(struct nfgenmsg), rem) {
		pr_debug("type: %u, len %u\n", nla_type(attr), attr->nla_len);
	}
}

int
klpp_ip_set_dump_do(struct sk_buff *skb, struct netlink_callback *cb)
{
	ip_set_id_t index = IPSET_INVALID_ID, max;
	struct ip_set *set = NULL;
	struct nlmsghdr *nlh = NULL;
	unsigned int flags = NETLINK_CB(cb->skb).portid ? NLM_F_MULTI : 0;
	struct ip_set_net *inst = ip_set_pernet(sock_net(skb->sk));
	u32 dump_type, dump_flags;
	bool is_destroyed;
	int ret = 0;

	if (!cb->args[IPSET_CB_DUMP])
		return -EINVAL;

	if (cb->args[IPSET_CB_INDEX] >= inst->ip_set_max)
		goto out;

	dump_type = DUMP_TYPE(cb->args[IPSET_CB_DUMP]);
	dump_flags = DUMP_FLAGS(cb->args[IPSET_CB_DUMP]);
	max = dump_type == DUMP_ONE ? cb->args[IPSET_CB_INDEX] + 1
				    : inst->ip_set_max;
dump_last:
	pr_debug("dump type, flag: %u %u index: %ld\n",
		 dump_type, dump_flags, cb->args[IPSET_CB_INDEX]);
	for (; cb->args[IPSET_CB_INDEX] < max; cb->args[IPSET_CB_INDEX]++) {
		index = (ip_set_id_t)cb->args[IPSET_CB_INDEX];
		write_lock_bh(&ip_set_ref_lock);
		set = 

#define ip_set(inst, id)		\
	ip_set_dereference((inst)->ip_set_list)[id]
ip_set(inst, index);
		is_destroyed = inst->is_destroyed;
		if (!set || is_destroyed) {
			write_unlock_bh(&ip_set_ref_lock);
			if (dump_type == DUMP_ONE) {
				ret = -ENOENT;
				goto out;
			}
			if (is_destroyed) {
				/* All sets are just being destroyed */
				ret = 0;
				goto out;
			}
			continue;
		}
		/* When dumping all sets, we must dump "sorted"
		 * so that lists (unions of sets) are dumped last.
		 */
		if (dump_type != DUMP_ONE &&
		    ((dump_type == DUMP_ALL) ==
		     !!(set->type->features & IPSET_DUMP_LAST))) {
			write_unlock_bh(&ip_set_ref_lock);
			continue;
		}
		pr_debug("List set: %s\n", set->name);
		if (!cb->args[IPSET_CB_ARG0]) {
			/* Start listing: make sure set won't be destroyed */
			pr_debug("reference set\n");
			set->ref_netlink++;
		}
		write_unlock_bh(&ip_set_ref_lock);
		nlh = start_msg(skb, NETLINK_CB(cb->skb).portid,
				cb->nlh->nlmsg_seq, flags,
				IPSET_CMD_LIST);
		if (!nlh) {
			ret = -EMSGSIZE;
			goto release_refcount;
		}
		if (nla_put_u8(skb, IPSET_ATTR_PROTOCOL,
			       cb->args[IPSET_CB_PROTO]) ||
		    nla_put_string(skb, IPSET_ATTR_SETNAME, set->name))
			goto nla_put_failure;
		if (dump_flags & IPSET_FLAG_LIST_SETNAME)
			goto next_set;
		switch (cb->args[IPSET_CB_ARG0]) {
		case 0:
			/* Core header data */
			if (nla_put_string(skb, IPSET_ATTR_TYPENAME,
					   set->type->name) ||
			    nla_put_u8(skb, IPSET_ATTR_FAMILY,
				       set->family) ||
			    nla_put_u8(skb, IPSET_ATTR_REVISION,
				       set->revision))
				goto nla_put_failure;
			if (cb->args[IPSET_CB_PROTO] > IPSET_PROTOCOL_MIN &&
			    nla_put_net16(skb, IPSET_ATTR_INDEX, htons(index)))
				goto nla_put_failure;
			ret = set->variant->head(set, skb);
			if (ret < 0)
				goto release_refcount;
			if (dump_flags & IPSET_FLAG_LIST_HEADER)
				goto next_set;
			if (set->variant->uref)
				set->variant->uref(set, cb, true);
			fallthrough;
		default:
			ret = set->variant->list(set, skb, cb);
			if (!cb->args[IPSET_CB_ARG0])
				/* Set is done, proceed with next one */
				goto next_set;
			goto release_refcount;
		}
	}
	/* If we dump all sets, continue with dumping last ones */
	if (dump_type == DUMP_ALL) {
		dump_type = DUMP_LAST;
		cb->args[IPSET_CB_DUMP] = dump_type | (dump_flags << 16);
		cb->args[IPSET_CB_INDEX] = 0;
		if (set && set->variant->uref)
			set->variant->uref(set, cb, false);
		goto dump_last;
	}
	goto out;

nla_put_failure:
	ret = -EFAULT;
next_set:
	if (dump_type == DUMP_ONE)
		cb->args[IPSET_CB_INDEX] = IPSET_INVALID_ID;
	else
		cb->args[IPSET_CB_INDEX]++;
release_refcount:
	/* If there was an error or set is done, release set */
	if (ret || !cb->args[IPSET_CB_ARG0]) {
		rcu_read_lock();
		set = ip_set_ref_netlink(inst, index);
		rcu_read_unlock();
		if (set->variant->uref)
			set->variant->uref(set, cb, false);
		pr_debug("release set %s\n", set->name);
		__ip_set_put_netlink(set);
		cb->args[IPSET_CB_ARG0] = 0;
	}
out:
	if (nlh) {
		nlmsg_end(skb, nlh);
		pr_debug("nlmsg_len: %u\n", nlh->nlmsg_len);
		dump_attrs(nlh);
	}

	return ret < 0 ? ret : skb->len;
}


#include <linux/livepatch.h>

extern typeof(ip_set_net_id) ip_set_net_id
	 KLP_RELOC_SYMBOL(ip_set, ip_set, ip_set_net_id);
extern typeof(ip_set_ref_lock) ip_set_ref_lock
	 KLP_RELOC_SYMBOL(ip_set, ip_set, ip_set_ref_lock);
