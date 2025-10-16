/*
 * livepatch_bsc1245794
 *
 * Fix for CVE-2025-21971, bsc#1245794
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from net/sched/sch_api.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/init.h>

#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>

/* klp-ccp: from include/linux/hashtable.h */
#define _LINUX_HASHTABLE_H

#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]

/* klp-ccp: from net/sched/sch_api.c */
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

const struct nla_policy rtm_tca_policy[TCA_MAX + 1] = {
	[TCA_KIND]		= { .type = NLA_STRING },
	[TCA_RATE]		= { .type = NLA_BINARY,
				    .len = sizeof(struct tc_estimator) },
	[TCA_STAB]		= { .type = NLA_NESTED },
	[TCA_DUMP_INVISIBLE]	= { .type = NLA_FLAG },
	[TCA_CHAIN]		= { .type = NLA_U32 },
	[TCA_INGRESS_BLOCK]	= { .type = NLA_U32 },
	[TCA_EGRESS_BLOCK]	= { .type = NLA_U32 },
};

extern int tc_fill_tclass(struct sk_buff *skb, struct Qdisc *q,
			  unsigned long cl, u32 portid, u32 seq, u16 flags,
			  int event, struct netlink_ext_ack *extack);

static int tclass_notify(struct net *net, struct sk_buff *oskb,
			 struct nlmsghdr *n, struct Qdisc *q,
			 unsigned long cl, int event, struct netlink_ext_ack *extack)
{
	struct sk_buff *skb;
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tc_fill_tclass(skb, q, cl, portid, n->nlmsg_seq, 0, event, extack) < 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	return rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

static int tclass_del_notify(struct net *net,
			     const struct Qdisc_class_ops *cops,
			     struct sk_buff *oskb, struct nlmsghdr *n,
			     struct Qdisc *q, unsigned long cl,
			     struct netlink_ext_ack *extack)
{
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
	struct sk_buff *skb;
	int err = 0;

	if (!cops->delete)
		return -EOPNOTSUPP;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tc_fill_tclass(skb, q, cl, portid, n->nlmsg_seq, 0,
			   RTM_DELTCLASS, extack) < 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	err = cops->delete(q, cl, extack);
	if (err) {
		kfree_skb(skb);
		return err;
	}

	err = rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			     n->nlmsg_flags & NLM_F_ECHO);
	return err;
}

#ifdef CONFIG_NET_CLS

extern void tc_bind_tclass(struct Qdisc *q, u32 portid, u32 clid,
			   unsigned long new_cl);

#else
#error "klp-ccp: non-taken branch"
#endif

int klpp_tc_ctl_tclass(struct sk_buff *skb, struct nlmsghdr *n,
			 struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct tcmsg *tcm = nlmsg_data(n);
	struct nlattr *tca[TCA_MAX + 1];
	struct net_device *dev;
	struct Qdisc *q = NULL;
	const struct Qdisc_class_ops *cops;
	unsigned long cl = 0;
	unsigned long new_cl;
	u32 portid;
	u32 clid;
	u32 qid;
	int err;

	err = nlmsg_parse_deprecated(n, sizeof(*tcm), tca, TCA_MAX,
				     rtm_tca_policy, extack);
	if (err < 0)
		return err;

	dev = __dev_get_by_index(net, tcm->tcm_ifindex);
	if (!dev)
		return -ENODEV;

	/*
	   parent == TC_H_UNSPEC - unspecified parent.
	   parent == TC_H_ROOT   - class is root, which has no parent.
	   parent == X:0	 - parent is root class.
	   parent == X:Y	 - parent is a node in hierarchy.
	   parent == 0:Y	 - parent is X:Y, where X:0 is qdisc.

	   handle == 0:0	 - generate handle from kernel pool.
	   handle == 0:Y	 - class is X:Y, where X:0 is qdisc.
	   handle == X:Y	 - clear.
	   handle == X:0	 - root class.
	 */

	/* Step 1. Determine qdisc handle X:0 */

	portid = tcm->tcm_parent;
	clid = tcm->tcm_handle;
	qid = TC_H_MAJ(clid);

	if (portid != TC_H_ROOT) {
		u32 qid1 = TC_H_MAJ(portid);

		if (qid && qid1) {
			/* If both majors are known, they must be identical. */
			if (qid != qid1)
				return -EINVAL;
		} else if (qid1) {
			qid = qid1;
		} else if (qid == 0)
			qid = rtnl_dereference(dev->qdisc)->handle;

		/* Now qid is genuine qdisc handle consistent
		 * both with parent and child.
		 *
		 * TC_H_MAJ(portid) still may be unspecified, complete it now.
		 */
		if (portid)
			portid = TC_H_MAKE(qid, portid);
	} else {
		if (qid == 0)
			qid = rtnl_dereference(dev->qdisc)->handle;
	}

	/* OK. Locate qdisc */
	q = qdisc_lookup(dev, qid);
	if (!q)
		return -ENOENT;

	/* An check that it supports classes */
	cops = q->ops->cl_ops;
	if (cops == NULL)
		return -EINVAL;

	/* Now try to get class */
	if (clid == 0) {
		if (portid == TC_H_ROOT)
			clid = qid;
	} else
		clid = TC_H_MAKE(qid, clid);

	if (clid)
		cl = cops->find(q, clid);

	if (cl == 0) {
		err = -ENOENT;
		if (n->nlmsg_type != RTM_NEWTCLASS ||
		    !(n->nlmsg_flags & NLM_F_CREATE))
			goto out;
	} else {
		switch (n->nlmsg_type) {
		case RTM_NEWTCLASS:
			err = -EEXIST;
			if (n->nlmsg_flags & NLM_F_EXCL)
				goto out;
			break;
		case RTM_DELTCLASS:
			err = tclass_del_notify(net, cops, skb, n, q, cl, extack);
			/* Unbind the class with flilters with 0 */
			tc_bind_tclass(q, portid, clid, 0);
			goto out;
		case RTM_GETTCLASS:
			err = tclass_notify(net, skb, n, q, cl, RTM_NEWTCLASS, extack);
			goto out;
		default:
			err = -EINVAL;
			goto out;
		}
	}

	if (tca[TCA_INGRESS_BLOCK] || tca[TCA_EGRESS_BLOCK]) {
		NL_SET_ERR_MSG(extack, "Shared blocks are not supported for classes");
		return -EOPNOTSUPP;
	}

	/* Prevent creation of traffic classes with classid TC_H_ROOT */
	if (clid == TC_H_ROOT) {
		NL_SET_ERR_MSG(extack, "Cannot create traffic class with classid TC_H_ROOT");
		return -EINVAL;
	}

	new_cl = cl;
	err = -EOPNOTSUPP;
	if (cops->change)
		err = cops->change(q, clid, portid, tca, &new_cl, extack);
	if (err == 0) {
		tclass_notify(net, skb, n, q, new_cl, RTM_NEWTCLASS, extack);
		/* We just create a new class, need to do reverse binding. */
		if (cl != new_cl)
			tc_bind_tclass(q, portid, clid, new_cl);
	}
out:
	return err;
}


#include "livepatch_bsc1245794.h"

#include <linux/livepatch.h>

extern typeof(qdisc_lookup) qdisc_lookup
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, qdisc_lookup);
extern typeof(rtnetlink_send) rtnetlink_send
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rtnetlink_send);
extern typeof(tc_bind_tclass) tc_bind_tclass
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tc_bind_tclass);
extern typeof(tc_fill_tclass) tc_fill_tclass
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tc_fill_tclass);
