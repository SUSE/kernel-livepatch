/*
 * bsc1207822_net_sched_sch_api
 *
 * Fix for CVE-2023-0590, bsc#1207822
 *
 *  Copyright (c) 2023 SUSE
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
#include <linux/hashtable.h>

/* klp-ccp: from net/sched/sch_api.c */
#include <net/net_namespace.h>
#include <net/sock.h>

/* klp-ccp: from include/linux/rtnetlink.h */
static int (*klpe_rtnetlink_send)(struct sk_buff *skb, struct net *net, u32 pid, u32 group, int echo);

static struct netdev_queue *(*klpe_dev_ingress_queue_create)(struct net_device *dev);

/* klp-ccp: from net/sched/sch_api.c */
#include <net/netlink.h>
#include <net/pkt_sched.h>

/* klp-ccp: from net/sched/sch_api.c */
static struct Qdisc *(*klpe_qdisc_match_from_root)(struct Qdisc *root, u32 handle);

struct Qdisc *klpp_qdisc_lookup(struct net_device *dev, u32 handle)
{
	struct Qdisc *q;

	if (!handle)
		return NULL;
	q = (*klpe_qdisc_match_from_root)(rtnl_dereference(dev->qdisc), handle);
	if (q)
		goto out;

	if (dev_ingress_queue(dev))
		q = (*klpe_qdisc_match_from_root)(
			dev_ingress_queue(dev)->qdisc_sleeping,
			handle);
out:
	return q;
}

struct Qdisc *klpp_qdisc_lookup_rcu(struct net_device *dev, u32 handle)
{
	struct netdev_queue *nq;
	struct Qdisc *q;

	if (!handle)
		return NULL;
	q = (*klpe_qdisc_match_from_root)(rcu_dereference(dev->qdisc), handle);
	if (q)
		goto out;

	nq = dev_ingress_queue_rcu(dev);
	if (nq)
		q = (*klpe_qdisc_match_from_root)(nq->qdisc_sleeping, handle);
out:
	return q;
}

static struct Qdisc *(*klpe_qdisc_leaf)(struct Qdisc *p, u32 classid);

static struct qdisc_size_table *(*klpe_qdisc_get_stab)(struct nlattr *opt,
					       struct netlink_ext_ack *extack);

void qdisc_put_stab(struct qdisc_size_table *tab);

static int (*klpe_tc_fill_qdisc)(struct sk_buff *skb, struct Qdisc *q, u32 clid,
			 u32 portid, u32 seq, u16 flags, int event);

static bool tc_qdisc_dump_ignore(struct Qdisc *q, bool dump_invisible)
{
	if (q->flags & TCQ_F_BUILTIN)
		return true;
	if ((q->flags & TCQ_F_INVISIBLE) && !dump_invisible)
		return true;

	return false;
}

static int (*klpe_qdisc_notify)(struct net *net, struct sk_buff *oskb,
			struct nlmsghdr *n, u32 clid,
			struct Qdisc *old, struct Qdisc *new);

static void (*klpe_notify_and_destroy)(struct net *net, struct sk_buff *skb,
			       struct nlmsghdr *n, u32 clid,
			       struct Qdisc *old, struct Qdisc *new);

static void qdisc_clear_nolock(struct Qdisc *sch)
{
	sch->flags &= ~TCQ_F_NOLOCK;
	if (!(sch->flags & TCQ_F_CPUSTATS))
		return;

	free_percpu(sch->cpu_bstats);
	free_percpu(sch->cpu_qstats);
	sch->cpu_bstats = NULL;
	sch->cpu_qstats = NULL;
	sch->flags &= ~TCQ_F_CPUSTATS;
}

int klpp_qdisc_graft(struct net_device *dev, struct Qdisc *parent,
		       struct sk_buff *skb, struct nlmsghdr *n, u32 classid,
		       struct Qdisc *new, struct Qdisc *old,
		       struct netlink_ext_ack *extack)
{
	struct Qdisc *q = old;
	struct net *net = dev_net(dev);
	int err = 0;

	if (parent == NULL) {
		unsigned int i, num_q, ingress;

		ingress = 0;
		num_q = dev->num_tx_queues;
		if ((q && q->flags & TCQ_F_INGRESS) ||
		    (new && new->flags & TCQ_F_INGRESS)) {
			num_q = 1;
			ingress = 1;
			if (!dev_ingress_queue(dev)) {
				NL_SET_ERR_MSG(extack, "Device does not have an ingress queue");
				return -ENOENT;
			}
		}

		if (dev->flags & IFF_UP)
			dev_deactivate(dev);

		if (new && new->ops->attach)
			goto skip;

		for (i = 0; i < num_q; i++) {
			struct netdev_queue *dev_queue = dev_ingress_queue(dev);

			if (!ingress)
				dev_queue = netdev_get_tx_queue(dev, i);

			old = dev_graft_qdisc(dev_queue, new);
			if (new && i > 0)
				qdisc_refcount_inc(new);

			if (!ingress)
				qdisc_put(old);
		}

skip:
		if (!ingress) {
			old = rtnl_dereference(dev->qdisc);
			if (new && !new->ops->attach)
				qdisc_refcount_inc(new);
			rcu_assign_pointer(dev->qdisc, new ? : &noop_qdisc);

			(*klpe_notify_and_destroy)(net, skb, n, classid, old, new);

			if (new && new->ops->attach)
				new->ops->attach(new);
		} else {
			(*klpe_notify_and_destroy)(net, skb, n, classid, old, new);
		}

		if (dev->flags & IFF_UP)
			dev_activate(dev);
	} else {
		const struct Qdisc_class_ops *cops = parent->ops->cl_ops;

		/* Only support running class lockless if parent is lockless */
		if (new && (new->flags & TCQ_F_NOLOCK) &&
		    parent && !(parent->flags & TCQ_F_NOLOCK))
			qdisc_clear_nolock(new);

		err = -EOPNOTSUPP;
		if (cops && cops->graft) {
			unsigned long cl = cops->find(parent, classid);

			if (cl) {
				err = cops->graft(parent, cl, new, &old,
						  extack);
			} else {
				NL_SET_ERR_MSG(extack, "Specified class not found");
				err = -ENOENT;
			}
		}
		if (!err)
			(*klpe_notify_and_destroy)(net, skb, n, classid, old, new);
	}
	return err;
}

static struct Qdisc *(*klpe_qdisc_create)(struct net_device *dev,
				  struct netdev_queue *dev_queue,
				  struct Qdisc *p, u32 parent, u32 handle,
				  struct nlattr **tca, int *errp,
				  struct netlink_ext_ack *extack);

static int klpr_qdisc_change(struct Qdisc *sch, struct nlattr **tca,
			struct netlink_ext_ack *extack)
{
	struct qdisc_size_table *ostab, *stab = NULL;
	int err = 0;

	if (tca[TCA_OPTIONS]) {
		if (!sch->ops->change) {
			NL_SET_ERR_MSG(extack, "Change operation not supported by specified qdisc");
			return -EINVAL;
		}
		if (tca[TCA_INGRESS_BLOCK] || tca[TCA_EGRESS_BLOCK]) {
			NL_SET_ERR_MSG(extack, "Change of blocks is not supported");
			return -EOPNOTSUPP;
		}
		err = sch->ops->change(sch, tca[TCA_OPTIONS], extack);
		if (err)
			return err;
	}

	if (tca[TCA_STAB]) {
		stab = (*klpe_qdisc_get_stab)(tca[TCA_STAB], extack);
		if (IS_ERR(stab))
			return PTR_ERR(stab);
	}

	ostab = rtnl_dereference(sch->stab);
	rcu_assign_pointer(sch->stab, stab);
	qdisc_put_stab(ostab);

	if (tca[TCA_RATE]) {
		/* NB: ignores errors from replace_estimator
		   because change can't be undone. */
		if (sch->flags & TCQ_F_MQROOT)
			goto out;
		gen_replace_estimator(&sch->bstats,
				      sch->cpu_bstats,
				      &sch->rate_est,
				      NULL,
				      qdisc_root_sleeping_running(sch),
				      tca[TCA_RATE]);
	}
out:
	return 0;
}

static int (*klpe_check_loop)(struct Qdisc *q, struct Qdisc *p, int depth);

static const struct nla_policy (*klpe_rtm_tca_policy)[TCA_MAX + 1];

int klpp_tc_get_qdisc(struct sk_buff *skb, struct nlmsghdr *n,
			struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct tcmsg *tcm = nlmsg_data(n);
	struct nlattr *tca[TCA_MAX + 1];
	struct net_device *dev;
	u32 clid;
	struct Qdisc *q = NULL;
	struct Qdisc *p = NULL;
	int err;

	if ((n->nlmsg_type != RTM_GETQDISC) &&
	    !netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, (*klpe_rtm_tca_policy),
			  extack);
	if (err < 0)
		return err;

	dev = __dev_get_by_index(net, tcm->tcm_ifindex);
	if (!dev)
		return -ENODEV;

	clid = tcm->tcm_parent;
	if (clid) {
		if (clid != TC_H_ROOT) {
			if (TC_H_MAJ(clid) != TC_H_MAJ(TC_H_INGRESS)) {
				p = klpp_qdisc_lookup(dev, TC_H_MAJ(clid));
				if (!p) {
					NL_SET_ERR_MSG(extack, "Failed to find qdisc with specified classid");
					return -ENOENT;
				}
				q = (*klpe_qdisc_leaf)(p, clid);
			} else if (dev_ingress_queue(dev)) {
				q = dev_ingress_queue(dev)->qdisc_sleeping;
			}
		} else {
			q = rtnl_dereference(dev->qdisc);
		}
		if (!q) {
			NL_SET_ERR_MSG(extack, "Cannot find specified qdisc on specified device");
			return -ENOENT;
		}

		if (tcm->tcm_handle && q->handle != tcm->tcm_handle) {
			NL_SET_ERR_MSG(extack, "Invalid handle");
			return -EINVAL;
		}
	} else {
		q = klpp_qdisc_lookup(dev, tcm->tcm_handle);
		if (!q) {
			NL_SET_ERR_MSG(extack, "Failed to find qdisc with specified handle");
			return -ENOENT;
		}
	}

	if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id)) {
		NL_SET_ERR_MSG(extack, "Invalid qdisc name");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELQDISC) {
		if (!clid) {
			NL_SET_ERR_MSG(extack, "Classid cannot be zero");
			return -EINVAL;
		}
		if (q->handle == 0) {
			NL_SET_ERR_MSG(extack, "Cannot delete qdisc with handle of zero");
			return -ENOENT;
		}
		err = klpp_qdisc_graft(dev, p, skb, n, clid, NULL, q, extack);
		if (err != 0)
			return err;
	} else {
		(*klpe_qdisc_notify)(net, skb, n, clid, NULL, q);
	}
	return 0;
}

int klpp_tc_modify_qdisc(struct sk_buff *skb, struct nlmsghdr *n,
			   struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct tcmsg *tcm;
	struct nlattr *tca[TCA_MAX + 1];
	struct net_device *dev;
	u32 clid;
	struct Qdisc *q, *p;
	int err;

	if (!netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

replay:
	/* Reinit, just in case something touches this. */
	err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, (*klpe_rtm_tca_policy),
			  extack);
	if (err < 0)
		return err;

	tcm = nlmsg_data(n);
	clid = tcm->tcm_parent;
	q = p = NULL;

	dev = __dev_get_by_index(net, tcm->tcm_ifindex);
	if (!dev)
		return -ENODEV;


	if (clid) {
		if (clid != TC_H_ROOT) {
			if (clid != TC_H_INGRESS) {
				p = klpp_qdisc_lookup(dev, TC_H_MAJ(clid));
				if (!p) {
					NL_SET_ERR_MSG(extack, "Failed to find specified qdisc");
					return -ENOENT;
				}
				q = (*klpe_qdisc_leaf)(p, clid);
			} else if ((*klpe_dev_ingress_queue_create)(dev)) {
				q = dev_ingress_queue(dev)->qdisc_sleeping;
			}
		} else {
			q = rtnl_dereference(dev->qdisc);
		}

		/* It may be default qdisc, ignore it */
		if (q && q->handle == 0)
			q = NULL;

		if (!q || !tcm->tcm_handle || q->handle != tcm->tcm_handle) {
			if (tcm->tcm_handle) {
				if (q && !(n->nlmsg_flags & NLM_F_REPLACE)) {
					NL_SET_ERR_MSG(extack, "NLM_F_REPLACE needed to override");
					return -EEXIST;
				}
				if (TC_H_MIN(tcm->tcm_handle)) {
					NL_SET_ERR_MSG(extack, "Invalid minor handle");
					return -EINVAL;
				}
				q = klpp_qdisc_lookup(dev, tcm->tcm_handle);
				if (!q)
					goto create_n_graft;
				if (n->nlmsg_flags & NLM_F_EXCL) {
					NL_SET_ERR_MSG(extack, "Exclusivity flag on, cannot override");
					return -EEXIST;
				}
				if (tca[TCA_KIND] &&
				    nla_strcmp(tca[TCA_KIND], q->ops->id)) {
					NL_SET_ERR_MSG(extack, "Invalid qdisc name");
					return -EINVAL;
				}
				if (q == p ||
				    (p && (*klpe_check_loop)(q, p, 0))) {
					NL_SET_ERR_MSG(extack, "Qdisc parent/child loop detected");
					return -ELOOP;
				}
				qdisc_refcount_inc(q);
				goto graft;
			} else {
				if (!q)
					goto create_n_graft;

				/* This magic test requires explanation.
				 *
				 *   We know, that some child q is already
				 *   attached to this parent and have choice:
				 *   either to change it or to create/graft new one.
				 *
				 *   1. We are allowed to create/graft only
				 *   if CREATE and REPLACE flags are set.
				 *
				 *   2. If EXCL is set, requestor wanted to say,
				 *   that qdisc tcm_handle is not expected
				 *   to exist, so that we choose create/graft too.
				 *
				 *   3. The last case is when no flags are set.
				 *   Alas, it is sort of hole in API, we
				 *   cannot decide what to do unambiguously.
				 *   For now we select create/graft, if
				 *   user gave KIND, which does not match existing.
				 */
				if ((n->nlmsg_flags & NLM_F_CREATE) &&
				    (n->nlmsg_flags & NLM_F_REPLACE) &&
				    ((n->nlmsg_flags & NLM_F_EXCL) ||
				     (tca[TCA_KIND] &&
				      nla_strcmp(tca[TCA_KIND], q->ops->id))))
					goto create_n_graft;
			}
		}
	} else {
		if (!tcm->tcm_handle) {
			NL_SET_ERR_MSG(extack, "Handle cannot be zero");
			return -EINVAL;
		}
		q = klpp_qdisc_lookup(dev, tcm->tcm_handle);
	}

	/* Change qdisc parameters */
	if (!q) {
		NL_SET_ERR_MSG(extack, "Specified qdisc not found");
		return -ENOENT;
	}
	if (n->nlmsg_flags & NLM_F_EXCL) {
		NL_SET_ERR_MSG(extack, "Exclusivity flag on, cannot modify");
		return -EEXIST;
	}
	if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id)) {
		NL_SET_ERR_MSG(extack, "Invalid qdisc name");
		return -EINVAL;
	}
	err = klpr_qdisc_change(q, tca, extack);
	if (err == 0)
		(*klpe_qdisc_notify)(net, skb, n, clid, NULL, q);
	return err;

create_n_graft:
	if (!(n->nlmsg_flags & NLM_F_CREATE)) {
		NL_SET_ERR_MSG(extack, "Qdisc not found. To create specify NLM_F_CREATE flag");
		return -ENOENT;
	}
	if (clid == TC_H_INGRESS) {
		if (dev_ingress_queue(dev)) {
			q = (*klpe_qdisc_create)(dev, dev_ingress_queue(dev), p,
					 tcm->tcm_parent, tcm->tcm_parent,
					 tca, &err, extack);
		} else {
			NL_SET_ERR_MSG(extack, "Cannot find ingress queue for specified device");
			err = -ENOENT;
		}
	} else {
		struct netdev_queue *dev_queue;

		if (p && p->ops->cl_ops && p->ops->cl_ops->select_queue)
			dev_queue = p->ops->cl_ops->select_queue(p, tcm);
		else if (p)
			dev_queue = p->dev_queue;
		else
			dev_queue = netdev_get_tx_queue(dev, 0);

		q = (*klpe_qdisc_create)(dev, dev_queue, p,
				 tcm->tcm_parent, tcm->tcm_handle,
				 tca, &err, extack);
	}
	if (q == NULL) {
		if (err == -EAGAIN)
			goto replay;
		return err;
	}

graft:
	err = klpp_qdisc_graft(dev, p, skb, n, clid, q, NULL, extack);
	if (err) {
		if (q)
			qdisc_put(q);
		return err;
	}

	return 0;
}

static int klpr_tc_dump_qdisc_root(struct Qdisc *root, struct sk_buff *skb,
			      struct netlink_callback *cb,
			      int *q_idx_p, int s_q_idx, bool recur,
			      bool dump_invisible)
{
	int ret = 0, q_idx = *q_idx_p;
	struct Qdisc *q;
	int b;

	if (!root)
		return 0;

	q = root;
	if (q_idx < s_q_idx) {
		q_idx++;
	} else {
		if (!tc_qdisc_dump_ignore(q, dump_invisible) &&
		    (*klpe_tc_fill_qdisc)(skb, q, q->parent, NETLINK_CB(cb->skb).portid,
				  cb->nlh->nlmsg_seq, NLM_F_MULTI,
				  RTM_NEWQDISC) <= 0)
			goto done;
		q_idx++;
	}

	/* If dumping singletons, there is no qdisc_dev(root) and the singleton
	 * itself has already been dumped.
	 *
	 * If we've already dumped the top-level (ingress) qdisc above and the global
	 * qdisc hashtable, we don't want to hit it again
	 */
	if (!qdisc_dev(root) || !recur)
		goto out;

	hash_for_each(qdisc_dev(root)->qdisc_hash, b, q, hash) {
		if (q_idx < s_q_idx) {
			q_idx++;
			continue;
		}
		if (!tc_qdisc_dump_ignore(q, dump_invisible) &&
		    (*klpe_tc_fill_qdisc)(skb, q, q->parent, NETLINK_CB(cb->skb).portid,
				  cb->nlh->nlmsg_seq, NLM_F_MULTI,
				  RTM_NEWQDISC) <= 0)
			goto done;
		q_idx++;
	}

out:
	*q_idx_p = q_idx;
	return ret;
done:
	ret = -1;
	goto out;
}

int klpp_tc_dump_qdisc(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	int idx, q_idx;
	int s_idx, s_q_idx;
	struct net_device *dev;
	const struct nlmsghdr *nlh = cb->nlh;
	struct nlattr *tca[TCA_MAX + 1];
	int err;

	s_idx = cb->args[0];
	s_q_idx = q_idx = cb->args[1];

	idx = 0;
	ASSERT_RTNL();

	err = nlmsg_parse(nlh, sizeof(struct tcmsg), tca, TCA_MAX,
			  (*klpe_rtm_tca_policy), NULL);
	if (err < 0)
		return err;

	for_each_netdev(net, dev) {
		struct netdev_queue *dev_queue;

		if (idx < s_idx)
			goto cont;
		if (idx > s_idx)
			s_q_idx = 0;
		q_idx = 0;

		if (klpr_tc_dump_qdisc_root(rtnl_dereference(dev->qdisc),
					skb, cb, &q_idx, s_q_idx,
					true, tca[TCA_DUMP_INVISIBLE]) < 0)
			goto done;

		dev_queue = dev_ingress_queue(dev);
		if (dev_queue &&
		    klpr_tc_dump_qdisc_root(dev_queue->qdisc_sleeping, skb, cb,
				       &q_idx, s_q_idx, false,
				       tca[TCA_DUMP_INVISIBLE]) < 0)
			goto done;

cont:
		idx++;
	}

done:
	cb->args[0] = idx;
	cb->args[1] = q_idx;

	return skb->len;
}

static int (*klpe_tc_fill_tclass)(struct sk_buff *skb, struct Qdisc *q,
			  unsigned long cl,
			  u32 portid, u32 seq, u16 flags, int event);

static int klpr_tclass_notify(struct net *net, struct sk_buff *oskb,
			 struct nlmsghdr *n, struct Qdisc *q,
			 unsigned long cl, int event)
{
	struct sk_buff *skb;
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if ((*klpe_tc_fill_tclass)(skb, q, cl, portid, n->nlmsg_seq, 0, event) < 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	return (*klpe_rtnetlink_send)(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

static int klpr_tclass_del_notify(struct net *net,
			     const struct Qdisc_class_ops *cops,
			     struct sk_buff *oskb, struct nlmsghdr *n,
			     struct Qdisc *q, unsigned long cl)
{
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
	struct sk_buff *skb;
	int err = 0;

	if (!cops->delete)
		return -EOPNOTSUPP;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if ((*klpe_tc_fill_tclass)(skb, q, cl, portid, n->nlmsg_seq, 0,
			   RTM_DELTCLASS) < 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	err = cops->delete(q, cl);
	if (err) {
		kfree_skb(skb);
		return err;
	}

	return (*klpe_rtnetlink_send)(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

#ifdef CONFIG_NET_CLS

static void (*klpe_tc_bind_tclass)(struct Qdisc *q, u32 portid, u32 clid,
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

	if ((n->nlmsg_type != RTM_GETTCLASS) &&
	    !netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, (*klpe_rtm_tca_policy),
			  extack);
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
	q = klpp_qdisc_lookup(dev, qid);
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
			err = klpr_tclass_del_notify(net, cops, skb, n, q, cl);
			/* Unbind the class with flilters with 0 */
			(*klpe_tc_bind_tclass)(q, portid, clid, 0);
			goto out;
		case RTM_GETTCLASS:
			err = klpr_tclass_notify(net, skb, n, q, cl, RTM_NEWTCLASS);
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

	new_cl = cl;
	err = -EOPNOTSUPP;
	if (cops->change)
		err = cops->change(q, clid, portid, tca, &new_cl, extack);
	if (err == 0) {
		klpr_tclass_notify(net, skb, n, q, new_cl, RTM_NEWTCLASS);
		/* We just create a new class, need to do reverse binding. */
		if (cl != new_cl)
			(*klpe_tc_bind_tclass)(q, portid, clid, new_cl);
	}
out:
	return err;
}

static int (*klpe_tc_dump_tclass_root)(struct Qdisc *root, struct sk_buff *skb,
			       struct tcmsg *tcm, struct netlink_callback *cb,
			       int *t_p, int s_t);

int klpp_tc_dump_tclass(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct tcmsg *tcm = nlmsg_data(cb->nlh);
	struct net *net = sock_net(skb->sk);
	struct netdev_queue *dev_queue;
	struct net_device *dev;
	int t, s_t;

	if (nlmsg_len(cb->nlh) < sizeof(*tcm))
		return 0;
	dev = dev_get_by_index(net, tcm->tcm_ifindex);
	if (!dev)
		return 0;

	s_t = cb->args[0];
	t = 0;

	if ((*klpe_tc_dump_tclass_root)(rtnl_dereference(dev->qdisc),
					skb, tcm, cb, &t, s_t) < 0)
		goto done;

	dev_queue = dev_ingress_queue(dev);
	if (dev_queue &&
	    (*klpe_tc_dump_tclass_root)(dev_queue->qdisc_sleeping, skb, tcm, cb,
				&t, s_t) < 0)
		goto done;

done:
	cb->args[0] = t;

	dev_put(dev);
	return skb->len;
}



#include <linux/kernel.h>
#include "livepatch_bsc1207822.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "check_loop", (void *)&klpe_check_loop },
	{ "dev_ingress_queue_create", (void *)&klpe_dev_ingress_queue_create },
	{ "notify_and_destroy", (void *)&klpe_notify_and_destroy },
	{ "qdisc_create", (void *)&klpe_qdisc_create },
	{ "qdisc_get_stab", (void *)&klpe_qdisc_get_stab },
	{ "qdisc_leaf", (void *)&klpe_qdisc_leaf },
	{ "qdisc_match_from_root", (void *)&klpe_qdisc_match_from_root },
	{ "qdisc_notify", (void *)&klpe_qdisc_notify },
	{ "rtm_tca_policy", (void *)&klpe_rtm_tca_policy },
	{ "rtnetlink_send", (void *)&klpe_rtnetlink_send },
	{ "tc_bind_tclass", (void *)&klpe_tc_bind_tclass },
	{ "tc_dump_tclass_root", (void *)&klpe_tc_dump_tclass_root },
	{ "tc_fill_qdisc", (void *)&klpe_tc_fill_qdisc },
	{ "tc_fill_tclass", (void *)&klpe_tc_fill_tclass },
};

int bsc1207822_net_sched_sch_api_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

