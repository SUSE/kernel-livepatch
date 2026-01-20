/*
 * bsc1249241_net_ipv6_ip6_fib
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

/* klp-ccp: from net/ipv6/ip6_fib.c */
#define pr_fmt(fmt) "IPv6: " fmt

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/lwtunnel.h>
#include <net/fib_notifier.h>
#include <net/ip_fib.h>
#include <net/ip6_fib.h>

/* klp-ccp: from include/net/ip6_fib.h */
int klpp_fib6_add(struct fib6_node *root, struct fib6_info *rt,
	     struct nl_info *info, struct netlink_ext_ack *extack);
int klpp_fib6_del(struct fib6_info *rt, struct nl_info *info);

/* klp-ccp: from net/ipv6/ip6_fib.c */
#include <net/ip6_route.h>

extern struct kmem_cache *fib6_node_kmem __read_mostly;

#define FWS_INIT FWS_S

static struct fib6_info *fib6_find_prefix(struct net *net,
					 struct fib6_table *table,
					 struct fib6_node *fn);
static struct fib6_node *fib6_repair_tree(struct net *net,
					  struct fib6_table *table,
					  struct fib6_node *fn);

#define FOR_WALKERS(net, w) \
	list_for_each_entry(w, &(net)->ipv6.fib6_walkers, lh)

static int fib6_new_sernum(struct net *net)
{
	int new, old = atomic_read(&net->ipv6.fib6_sernum);

	do {
		new = old < INT_MAX ? old + 1 : 1;
	} while (!atomic_try_cmpxchg(&net->ipv6.fib6_sernum, &old, new));

	return new;
}

#if defined(__LITTLE_ENDIAN)
# define BITOP_BE32_SWIZZLE	(0x1F & ~7)
#else
# define BITOP_BE32_SWIZZLE     0
#endif

static __be32 addr_bit_set(const void *token, int fn_bit)
{
	const __be32 *addr = token;
	/*
	 * Here,
	 *	1 << ((~fn_bit ^ BITOP_BE32_SWIZZLE) & 0x1f)
	 * is optimized version of
	 *	htonl(1 << ((~fn_bit)&0x1F))
	 * See include/asm-generic/bitops/le.h.
	 */
	return (__force __be32)(1 << ((~fn_bit ^ BITOP_BE32_SWIZZLE) & 0x1f)) &
	       addr[fn_bit >> 5];
}

void fib6_info_destroy_rcu(struct rcu_head *head);

extern typeof(fib6_info_destroy_rcu) fib6_info_destroy_rcu;

static struct fib6_node *node_alloc(struct net *net)
{
	struct fib6_node *fn;

	fn = kmem_cache_zalloc(fib6_node_kmem, GFP_ATOMIC);
	if (fn)
		net->ipv6.rt6_stats->fib_nodes++;

	return fn;
}

static void node_free_immediate(struct net *net, struct fib6_node *fn)
{
	kmem_cache_free(fib6_node_kmem, fn);
	net->ipv6.rt6_stats->fib_nodes--;
}

extern void node_free_rcu(struct rcu_head *head);

static void node_free(struct net *net, struct fib6_node *fn)
{
	call_rcu(&fn->rcu, node_free_rcu);
	net->ipv6.rt6_stats->fib_nodes--;
}

int call_fib6_entry_notifiers(struct net *net,
			      enum fib_event_type event_type,
			      struct fib6_info *rt,
			      struct netlink_ext_ack *extack);

int call_fib6_entry_notifiers_replace(struct net *net, struct fib6_info *rt);

void fib6_metric_set(struct fib6_info *f6i, int metric, u32 val);

static struct fib6_node *fib6_add_1(struct net *net,
				    struct fib6_table *table,
				    struct fib6_node *root,
				    struct in6_addr *addr, int plen,
				    int offset, int allow_create,
				    int replace_required,
				    struct netlink_ext_ack *extack)
{
	struct fib6_node *fn, *in, *ln;
	struct fib6_node *pn = NULL;
	struct rt6key *key;
	int	bit;
	__be32	dir = 0;

	RT6_TRACE("fib6_add_1\n");

	/* insert node in tree */

	fn = root;

	do {
		struct fib6_info *leaf = rcu_dereference_protected(fn->leaf,
					    lockdep_is_held(&table->tb6_lock));
		key = (struct rt6key *)((u8 *)leaf + offset);

		/*
		 *	Prefix match
		 */
		if (plen < fn->fn_bit ||
		    !ipv6_prefix_equal(&key->addr, addr, fn->fn_bit)) {
			if (!allow_create) {
				if (replace_required) {
					NL_SET_ERR_MSG(extack,
						       "Can not replace route - no match found");
					pr_warn("Can't replace route, no match found\n");
					return ERR_PTR(-ENOENT);
				}
				pr_warn("NLM_F_CREATE should be set when creating new route\n");
			}
			goto insert_above;
		}

		/*
		 *	Exact match ?
		 */

		if (plen == fn->fn_bit) {
			/* clean up an intermediate node */
			if (!(fn->fn_flags & RTN_RTINFO)) {
				RCU_INIT_POINTER(fn->leaf, NULL);
				fib6_info_release(leaf);
			/* remove null_entry in the root node */
			} else if (fn->fn_flags & RTN_TL_ROOT &&
				   rcu_access_pointer(fn->leaf) ==
				   net->ipv6.fib6_null_entry) {
				RCU_INIT_POINTER(fn->leaf, NULL);
			}

			return fn;
		}

		/*
		 *	We have more bits to go
		 */

		/* Try to walk down on tree. */
		dir = addr_bit_set(addr, fn->fn_bit);
		pn = fn;
		fn = dir ?
		     rcu_dereference_protected(fn->right,
					lockdep_is_held(&table->tb6_lock)) :
		     rcu_dereference_protected(fn->left,
					lockdep_is_held(&table->tb6_lock));
	} while (fn);

	if (!allow_create) {
		/* We should not create new node because
		 * NLM_F_REPLACE was specified without NLM_F_CREATE
		 * I assume it is safe to require NLM_F_CREATE when
		 * REPLACE flag is used! Later we may want to remove the
		 * check for replace_required, because according
		 * to netlink specification, NLM_F_CREATE
		 * MUST be specified if new route is created.
		 * That would keep IPv6 consistent with IPv4
		 */
		if (replace_required) {
			NL_SET_ERR_MSG(extack,
				       "Can not replace route - no match found");
			pr_warn("Can't replace route, no match found\n");
			return ERR_PTR(-ENOENT);
		}
		pr_warn("NLM_F_CREATE should be set when creating new route\n");
	}
	/*
	 *	We walked to the bottom of tree.
	 *	Create new leaf node without children.
	 */

	ln = node_alloc(net);

	if (!ln)
		return ERR_PTR(-ENOMEM);
	ln->fn_bit = plen;
	RCU_INIT_POINTER(ln->parent, pn);

	if (dir)
		rcu_assign_pointer(pn->right, ln);
	else
		rcu_assign_pointer(pn->left, ln);

	return ln;
insert_above:
	/*
	 * split since we don't have a common prefix anymore or
	 * we have a less significant route.
	 * we've to insert an intermediate node on the list
	 * this new node will point to the one we need to create
	 * and the current
	 */

	pn = rcu_dereference_protected(fn->parent,
				       lockdep_is_held(&table->tb6_lock));

	/* find 1st bit in difference between the 2 addrs.

	   See comment in __ipv6_addr_diff: bit may be an invalid value,
	   but if it is >= plen, the value is ignored in any case.
	 */

	bit = __ipv6_addr_diff(addr, &key->addr, sizeof(*addr));

	/*
	 *		(intermediate)[in]
	 *	          /	   \
	 *	(new leaf node)[ln] (old node)[fn]
	 */
	if (plen > bit) {
		in = node_alloc(net);
		ln = node_alloc(net);

		if (!in || !ln) {
			if (in)
				node_free_immediate(net, in);
			if (ln)
				node_free_immediate(net, ln);
			return ERR_PTR(-ENOMEM);
		}

		/*
		 * new intermediate node.
		 * RTN_RTINFO will
		 * be off since that an address that chooses one of
		 * the branches would not match less specific routes
		 * in the other branch
		 */

		in->fn_bit = bit;

		RCU_INIT_POINTER(in->parent, pn);
		in->leaf = fn->leaf;
		fib6_info_hold(rcu_dereference_protected(in->leaf,
				lockdep_is_held(&table->tb6_lock)));

		/* update parent pointer */
		if (dir)
			rcu_assign_pointer(pn->right, in);
		else
			rcu_assign_pointer(pn->left, in);

		ln->fn_bit = plen;

		RCU_INIT_POINTER(ln->parent, in);
		rcu_assign_pointer(fn->parent, in);

		if (addr_bit_set(addr, bit)) {
			rcu_assign_pointer(in->right, ln);
			rcu_assign_pointer(in->left, fn);
		} else {
			rcu_assign_pointer(in->left, ln);
			rcu_assign_pointer(in->right, fn);
		}
	} else { /* plen <= bit */

		/*
		 *		(new leaf node)[ln]
		 *	          /	   \
		 *	     (old node)[fn] NULL
		 */

		ln = node_alloc(net);

		if (!ln)
			return ERR_PTR(-ENOMEM);

		ln->fn_bit = plen;

		RCU_INIT_POINTER(ln->parent, pn);

		if (addr_bit_set(&key->addr, plen))
			RCU_INIT_POINTER(ln->right, fn);
		else
			RCU_INIT_POINTER(ln->left, fn);

		rcu_assign_pointer(fn->parent, ln);

		if (dir)
			rcu_assign_pointer(pn->right, ln);
		else
			rcu_assign_pointer(pn->left, ln);
	}
	return ln;
}

extern void fib6_purge_rt(struct fib6_info *rt, struct fib6_node *fn,
			  struct net *net);

static int klpp_fib6_add_rt2node(struct fib6_node *fn, struct fib6_info *rt,
			    struct nl_info *info,
			    struct netlink_ext_ack *extack)
{
	struct fib6_info *leaf = rcu_dereference_protected(fn->leaf,
				    lockdep_is_held(&rt->fib6_table->tb6_lock));
	struct fib6_info *iter = NULL;
	struct fib6_info __rcu **ins;
	struct fib6_info __rcu **fallback_ins = NULL;
	int replace = (info->nlh &&
		       (info->nlh->nlmsg_flags & NLM_F_REPLACE));
	int add = (!info->nlh ||
		   (info->nlh->nlmsg_flags & NLM_F_CREATE));
	int found = 0;
	bool rt_can_ecmp = rt6_qualify_for_ecmp(rt);
	bool notify_sibling_rt = false;
	u16 nlflags = NLM_F_EXCL;
	int err;

	if (info->nlh && (info->nlh->nlmsg_flags & NLM_F_APPEND))
		nlflags |= NLM_F_APPEND;

	ins = &fn->leaf;

	for (iter = leaf; iter;
	     iter = rcu_dereference_protected(iter->fib6_next,
				lockdep_is_held(&rt->fib6_table->tb6_lock))) {
		/*
		 *	Search for duplicates
		 */

		if (iter->fib6_metric == rt->fib6_metric) {
			/*
			 *	Same priority level
			 */
			if (info->nlh &&
			    (info->nlh->nlmsg_flags & NLM_F_EXCL))
				return -EEXIST;

			nlflags &= ~NLM_F_EXCL;
			if (replace) {
				if (rt_can_ecmp == rt6_qualify_for_ecmp(iter)) {
					found++;
					break;
				}
				fallback_ins = fallback_ins ?: ins;
				goto next_iter;
			}

			if (rt6_duplicate_nexthop(iter, rt)) {
				if (rt->fib6_nsiblings)
					rt->fib6_nsiblings = 0;
				if (!(iter->fib6_flags & RTF_EXPIRES))
					return -EEXIST;
				if (!(rt->fib6_flags & RTF_EXPIRES))
					fib6_clean_expires(iter);
				else
					fib6_set_expires(iter, rt->expires);

				if (rt->fib6_pmtu)
					fib6_metric_set(iter, RTAX_MTU,
							rt->fib6_pmtu);
				return -EEXIST;
			}
			/* If we have the same destination and the same metric,
			 * but not the same gateway, then the route we try to
			 * add is sibling to this route, increment our counter
			 * of siblings, and later we will add our route to the
			 * list.
			 * Only static routes (which don't have flag
			 * RTF_EXPIRES) are used for ECMPv6.
			 *
			 * To avoid long list, we only had siblings if the
			 * route have a gateway.
			 */
			if (rt_can_ecmp &&
			    rt6_qualify_for_ecmp(iter))
				rt->fib6_nsiblings++;
		}

		if (iter->fib6_metric > rt->fib6_metric)
			break;

next_iter:
		ins = &iter->fib6_next;
	}

	if (fallback_ins && !found) {
		/* No matching route with same ecmp-able-ness found, replace
		 * first matching route
		 */
		ins = fallback_ins;
		iter = rcu_dereference_protected(*ins,
				    lockdep_is_held(&rt->fib6_table->tb6_lock));
		found++;
	}

	/* Reset round-robin state, if necessary */
	if (ins == &fn->leaf)
		fn->rr_ptr = NULL;

	/* Link this route to others same route. */
	if (rt->fib6_nsiblings) {
		unsigned int fib6_nsiblings;
		struct fib6_info *sibling, *temp_sibling;

		/* Find the first route that have the same metric */
		sibling = leaf;
		notify_sibling_rt = true;
		while (sibling) {
			if (sibling->fib6_metric == rt->fib6_metric &&
			    rt6_qualify_for_ecmp(sibling)) {
				list_add_tail_rcu(&rt->fib6_siblings,
						  &sibling->fib6_siblings);
				break;
			}
			sibling = rcu_dereference_protected(sibling->fib6_next,
				    lockdep_is_held(&rt->fib6_table->tb6_lock));
			notify_sibling_rt = false;
		}
		/* For each sibling in the list, increment the counter of
		 * siblings. BUG() if counters does not match, list of siblings
		 * is broken!
		 */
		fib6_nsiblings = 0;
		list_for_each_entry_safe(sibling, temp_sibling,
					 &rt->fib6_siblings, fib6_siblings) {
			sibling->fib6_nsiblings++;
			BUG_ON(sibling->fib6_nsiblings != rt->fib6_nsiblings);
			fib6_nsiblings++;
		}
		BUG_ON(fib6_nsiblings != rt->fib6_nsiblings);
		rt6_multipath_rebalance(temp_sibling);
	}

	/*
	 *	insert node
	 */
	if (!replace) {
		if (!add)
			pr_warn("NLM_F_CREATE should be set when creating new route\n");

add:
		nlflags |= NLM_F_CREATE;

		/* The route should only be notified if it is the first
		 * route in the node or if it is added as a sibling
		 * route to the first route in the node.
		 */
		if (!info->skip_notify_kernel &&
		    (notify_sibling_rt || ins == &fn->leaf)) {
			enum fib_event_type fib_event;

			if (notify_sibling_rt)
				fib_event = FIB_EVENT_ENTRY_APPEND;
			else
				fib_event = FIB_EVENT_ENTRY_REPLACE;
			err = call_fib6_entry_notifiers(info->nl_net,
							fib_event, rt,
							extack);
			if (err) {
				struct fib6_info *sibling, *next_sibling;

				/* If the route has siblings, then it first
				 * needs to be unlinked from them.
				 */
				if (!rt->fib6_nsiblings)
					return err;

				list_for_each_entry_safe(sibling, next_sibling,
							 &rt->fib6_siblings,
							 fib6_siblings)
					sibling->fib6_nsiblings--;
				WRITE_ONCE(rt->fib6_nsiblings, 0);
				list_del_rcu(&rt->fib6_siblings);
				rt6_multipath_rebalance(next_sibling);
				return err;
			}
		}

		rcu_assign_pointer(rt->fib6_next, iter);
		fib6_info_hold(rt);
		rcu_assign_pointer(rt->fib6_node, fn);
		rcu_assign_pointer(*ins, rt);
		if (!info->skip_notify)
			inet6_rt_notify(RTM_NEWROUTE, rt, info, nlflags);
		info->nl_net->ipv6.rt6_stats->fib_rt_entries++;

		if (!(fn->fn_flags & RTN_RTINFO)) {
			info->nl_net->ipv6.rt6_stats->fib_route_nodes++;
			fn->fn_flags |= RTN_RTINFO;
		}

	} else {
		int nsiblings;

		if (!found) {
			if (add)
				goto add;
			pr_warn("NLM_F_REPLACE set, but no existing node found!\n");
			return -ENOENT;
		}

		if (!info->skip_notify_kernel && ins == &fn->leaf) {
			err = call_fib6_entry_notifiers(info->nl_net,
							FIB_EVENT_ENTRY_REPLACE,
							rt, extack);
			if (err)
				return err;
		}

		fib6_info_hold(rt);
		rcu_assign_pointer(rt->fib6_node, fn);
		rt->fib6_next = iter->fib6_next;
		rcu_assign_pointer(*ins, rt);
		if (!info->skip_notify)
			inet6_rt_notify(RTM_NEWROUTE, rt, info, NLM_F_REPLACE);
		if (!(fn->fn_flags & RTN_RTINFO)) {
			info->nl_net->ipv6.rt6_stats->fib_route_nodes++;
			fn->fn_flags |= RTN_RTINFO;
		}
		nsiblings = iter->fib6_nsiblings;
		iter->fib6_node = NULL;
		fib6_purge_rt(iter, fn, info->nl_net);
		if (rcu_access_pointer(fn->rr_ptr) == iter)
			fn->rr_ptr = NULL;
		fib6_info_release(iter);

		if (nsiblings) {
			/* Replacing an ECMP route, remove all siblings */
			ins = &rt->fib6_next;
			iter = rcu_dereference_protected(*ins,
				    lockdep_is_held(&rt->fib6_table->tb6_lock));
			while (iter) {
				if (iter->fib6_metric > rt->fib6_metric)
					break;
				if (rt6_qualify_for_ecmp(iter)) {
					*ins = iter->fib6_next;
					iter->fib6_node = NULL;
					fib6_purge_rt(iter, fn, info->nl_net);
					if (rcu_access_pointer(fn->rr_ptr) == iter)
						fn->rr_ptr = NULL;
					fib6_info_release(iter);
					nsiblings--;
					info->nl_net->ipv6.rt6_stats->fib_rt_entries--;
				} else {
					ins = &iter->fib6_next;
				}
				iter = rcu_dereference_protected(*ins,
					lockdep_is_held(&rt->fib6_table->tb6_lock));
			}
			WARN_ON(nsiblings != 0);
		}
	}

	return 0;
}

static void fib6_start_gc(struct net *net, struct fib6_info *rt)
{
	if (!timer_pending(&net->ipv6.ip6_fib_timer) &&
	    (rt->fib6_flags & RTF_EXPIRES))
		mod_timer(&net->ipv6.ip6_fib_timer,
			  jiffies + net->ipv6.sysctl.ip6_rt_gc_interval);
}

static void __fib6_update_sernum_upto_root(struct fib6_info *rt,
					   int sernum)
{
	struct fib6_node *fn = rcu_dereference_protected(rt->fib6_node,
				lockdep_is_held(&rt->fib6_table->tb6_lock));

	/* paired with smp_rmb() in fib6_get_cookie_safe() */
	smp_wmb();
	while (fn) {
		WRITE_ONCE(fn->fn_sernum, sernum);
		fn = rcu_dereference_protected(fn->parent,
				lockdep_is_held(&rt->fib6_table->tb6_lock));
	}
}

int klpp_fib6_add(struct fib6_node *root, struct fib6_info *rt,
	     struct nl_info *info, struct netlink_ext_ack *extack)
{
	struct fib6_table *table = rt->fib6_table;
	struct fib6_node *fn;
#ifdef CONFIG_IPV6_SUBTREES
	struct fib6_node *pn = NULL;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	int err = -ENOMEM;
	int allow_create = 1;
	int replace_required = 0;

	if (info->nlh) {
		if (!(info->nlh->nlmsg_flags & NLM_F_CREATE))
			allow_create = 0;
		if (info->nlh->nlmsg_flags & NLM_F_REPLACE)
			replace_required = 1;
	}
	if (!allow_create && !replace_required)
		pr_warn("RTM_NEWROUTE with no NLM_F_CREATE or NLM_F_REPLACE\n");

	fn = fib6_add_1(info->nl_net, table, root,
			&rt->fib6_dst.addr, rt->fib6_dst.plen,
			offsetof(struct fib6_info, fib6_dst), allow_create,
			replace_required, extack);
	if (IS_ERR(fn)) {
		err = PTR_ERR(fn);
		fn = NULL;
		goto out;
	}

#ifdef CONFIG_IPV6_SUBTREES
	pn = fn;

	if (rt->fib6_src.plen) {
		struct fib6_node *sn;

		if (!rcu_access_pointer(fn->subtree)) {
			struct fib6_node *sfn;

			/*
			 * Create subtree.
			 *
			 *		fn[main tree]
			 *		|
			 *		sfn[subtree root]
			 *		   \
			 *		    sn[new leaf node]
			 */

			/* Create subtree root node */
			sfn = node_alloc(info->nl_net);
			if (!sfn)
				goto failure;

			fib6_info_hold(info->nl_net->ipv6.fib6_null_entry);
			rcu_assign_pointer(sfn->leaf,
					   info->nl_net->ipv6.fib6_null_entry);
			sfn->fn_flags = RTN_ROOT;

			/* Now add the first leaf node to new subtree */

			sn = fib6_add_1(info->nl_net, table, sfn,
					&rt->fib6_src.addr, rt->fib6_src.plen,
					offsetof(struct fib6_info, fib6_src),
					allow_create, replace_required, extack);

			if (IS_ERR(sn)) {
				/* If it is failed, discard just allocated
				   root, and then (in failure) stale node
				   in main tree.
				 */
				node_free_immediate(info->nl_net, sfn);
				err = PTR_ERR(sn);
				goto failure;
			}

			/* Now link new subtree to main tree */
			rcu_assign_pointer(sfn->parent, fn);
			rcu_assign_pointer(fn->subtree, sfn);
		} else {
			sn = fib6_add_1(info->nl_net, table, FIB6_SUBTREE(fn),
					&rt->fib6_src.addr, rt->fib6_src.plen,
					offsetof(struct fib6_info, fib6_src),
					allow_create, replace_required, extack);

			if (IS_ERR(sn)) {
				err = PTR_ERR(sn);
				goto failure;
			}
		}

		if (!rcu_access_pointer(fn->leaf)) {
			if (fn->fn_flags & RTN_TL_ROOT) {
				/* put back null_entry for root node */
				rcu_assign_pointer(fn->leaf,
					    info->nl_net->ipv6.fib6_null_entry);
			} else {
				fib6_info_hold(rt);
				rcu_assign_pointer(fn->leaf, rt);
			}
		}
		fn = sn;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	err = klpp_fib6_add_rt2node(fn, rt, info, extack);
	if (!err) {
		if (rt->nh)
			list_add(&rt->nh_list, &rt->nh->f6i_list);
		__fib6_update_sernum_upto_root(rt, fib6_new_sernum(info->nl_net));
		fib6_start_gc(info->nl_net, rt);
	}

out:
	if (err) {
#ifdef CONFIG_IPV6_SUBTREES
		if (pn != fn) {
			struct fib6_info *pn_leaf =
				rcu_dereference_protected(pn->leaf,
				    lockdep_is_held(&table->tb6_lock));
			if (pn_leaf == rt) {
				pn_leaf = NULL;
				RCU_INIT_POINTER(pn->leaf, NULL);
				fib6_info_release(rt);
			}
			if (!pn_leaf && !(pn->fn_flags & RTN_RTINFO)) {
				pn_leaf = fib6_find_prefix(info->nl_net, table,
							   pn);
				if (!pn_leaf)
					pn_leaf =
					    info->nl_net->ipv6.fib6_null_entry;
				fib6_info_hold(pn_leaf);
				rcu_assign_pointer(pn->leaf, pn_leaf);
			}
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		goto failure;
	} else if (fib6_requires_src(rt)) {
		fib6_routes_require_src_inc(info->nl_net);
	}
	return err;

failure:
	/* fn->leaf could be NULL and fib6_repair_tree() needs to be called if:
	 * 1. fn is an intermediate node and we failed to add the new
	 * route to it in both subtree creation failure and fib6_add_rt2node()
	 * failure case.
	 * 2. fn is the root node in the table and we fail to add the first
	 * default route to it.
	 */
	if (fn &&
	    (!(fn->fn_flags & (RTN_RTINFO|RTN_ROOT)) ||
	     (fn->fn_flags & RTN_TL_ROOT &&
	      !rcu_access_pointer(fn->leaf))))
		fib6_repair_tree(info->nl_net, table, fn);
	return err;
}

static struct fib6_info *fib6_find_prefix(struct net *net,
					 struct fib6_table *table,
					 struct fib6_node *fn)
{
	struct fib6_node *child_left, *child_right;

	if (fn->fn_flags & RTN_ROOT)
		return net->ipv6.fib6_null_entry;

	while (fn) {
		child_left = rcu_dereference_protected(fn->left,
				    lockdep_is_held(&table->tb6_lock));
		child_right = rcu_dereference_protected(fn->right,
				    lockdep_is_held(&table->tb6_lock));
		if (child_left)
			return rcu_dereference_protected(child_left->leaf,
					lockdep_is_held(&table->tb6_lock));
		if (child_right)
			return rcu_dereference_protected(child_right->leaf,
					lockdep_is_held(&table->tb6_lock));

		fn = FIB6_SUBTREE(fn);
	}
	return NULL;
}

static struct fib6_node *fib6_repair_tree(struct net *net,
					  struct fib6_table *table,
					  struct fib6_node *fn)
{
	int children;
	int nstate;
	struct fib6_node *child;
	struct fib6_walker *w;
	int iter = 0;

	/* Set fn->leaf to null_entry for root node. */
	if (fn->fn_flags & RTN_TL_ROOT) {
		rcu_assign_pointer(fn->leaf, net->ipv6.fib6_null_entry);
		return fn;
	}

	for (;;) {
		struct fib6_node *fn_r = rcu_dereference_protected(fn->right,
					    lockdep_is_held(&table->tb6_lock));
		struct fib6_node *fn_l = rcu_dereference_protected(fn->left,
					    lockdep_is_held(&table->tb6_lock));
		struct fib6_node *pn = rcu_dereference_protected(fn->parent,
					    lockdep_is_held(&table->tb6_lock));
		struct fib6_node *pn_r = rcu_dereference_protected(pn->right,
					    lockdep_is_held(&table->tb6_lock));
		struct fib6_node *pn_l = rcu_dereference_protected(pn->left,
					    lockdep_is_held(&table->tb6_lock));
		struct fib6_info *fn_leaf = rcu_dereference_protected(fn->leaf,
					    lockdep_is_held(&table->tb6_lock));
		struct fib6_info *pn_leaf = rcu_dereference_protected(pn->leaf,
					    lockdep_is_held(&table->tb6_lock));
		struct fib6_info *new_fn_leaf;

		RT6_TRACE("fixing tree: plen=%d iter=%d\n", fn->fn_bit, iter);
		iter++;

		WARN_ON(fn->fn_flags & RTN_RTINFO);
		WARN_ON(fn->fn_flags & RTN_TL_ROOT);
		WARN_ON(fn_leaf);

		children = 0;
		child = NULL;
		if (fn_r) {
			child = fn_r;
			children |= 1;
		}
		if (fn_l) {
			child = fn_l;
			children |= 2;
		}

		if (children == 3 || FIB6_SUBTREE(fn)
#ifdef CONFIG_IPV6_SUBTREES
		    || (children && fn->fn_flags & RTN_ROOT)
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		    ) {
			new_fn_leaf = fib6_find_prefix(net, table, fn);
#if RT6_DEBUG >= 2
			if (!new_fn_leaf) {
				WARN_ON(!new_fn_leaf);
				new_fn_leaf = net->ipv6.fib6_null_entry;
			}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
			fib6_info_hold(new_fn_leaf);
			rcu_assign_pointer(fn->leaf, new_fn_leaf);
			return pn;
		}

#ifdef CONFIG_IPV6_SUBTREES
		if (FIB6_SUBTREE(pn) == fn) {
			WARN_ON(!(fn->fn_flags & RTN_ROOT));
			RCU_INIT_POINTER(pn->subtree, NULL);
			nstate = FWS_L;
		} else {
			WARN_ON(fn->fn_flags & RTN_ROOT);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
			if (pn_r == fn)
				rcu_assign_pointer(pn->right, child);
			else if (pn_l == fn)
				rcu_assign_pointer(pn->left, child);
#if RT6_DEBUG >= 2
			else
				WARN_ON(1);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
			if (child)
				rcu_assign_pointer(child->parent, pn);
			nstate = FWS_R;
#ifdef CONFIG_IPV6_SUBTREES
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		read_lock(&net->ipv6.fib6_walker_lock);
		FOR_WALKERS(net, w) {
			if (!child) {
				if (w->node == fn) {
					RT6_TRACE("W %p adjusted by delnode 1, s=%d/%d\n", w, w->state, nstate);
					w->node = pn;
					w->state = nstate;
				}
			} else {
				if (w->node == fn) {
					w->node = child;
					if (children&2) {
						RT6_TRACE("W %p adjusted by delnode 2, s=%d\n", w, w->state);
						w->state = w->state >= FWS_R ? FWS_U : FWS_INIT;
					} else {
						RT6_TRACE("W %p adjusted by delnode 2, s=%d\n", w, w->state);
						w->state = w->state >= FWS_C ? FWS_U : FWS_INIT;
					}
				}
			}
		}
		read_unlock(&net->ipv6.fib6_walker_lock);

		node_free(net, fn);
		if (pn->fn_flags & RTN_RTINFO || FIB6_SUBTREE(pn))
			return pn;

		RCU_INIT_POINTER(pn->leaf, NULL);
		fib6_info_release(pn_leaf);
		fn = pn;
	}
}

static void klpp_fib6_del_route(struct fib6_table *table, struct fib6_node *fn,
			   struct fib6_info __rcu **rtp, struct nl_info *info)
{
	struct fib6_info *leaf, *replace_rt = NULL;
	struct fib6_walker *w;
	struct fib6_info *rt = rcu_dereference_protected(*rtp,
				    lockdep_is_held(&table->tb6_lock));
	struct net *net = info->nl_net;
	bool notify_del = false;

	RT6_TRACE("fib6_del_route\n");

	/* If the deleted route is the first in the node and it is not part of
	 * a multipath route, then we need to replace it with the next route
	 * in the node, if exists.
	 */
	leaf = rcu_dereference_protected(fn->leaf,
					 lockdep_is_held(&table->tb6_lock));
	if (leaf == rt && !rt->fib6_nsiblings) {
		if (rcu_access_pointer(rt->fib6_next))
			replace_rt = rcu_dereference_protected(rt->fib6_next,
					    lockdep_is_held(&table->tb6_lock));
		else
			notify_del = true;
	}

	/* Unlink it */
	*rtp = rt->fib6_next;
	rt->fib6_node = NULL;
	net->ipv6.rt6_stats->fib_rt_entries--;
	net->ipv6.rt6_stats->fib_discarded_routes++;

	/* Reset round-robin state, if necessary */
	if (rcu_access_pointer(fn->rr_ptr) == rt)
		fn->rr_ptr = NULL;

	/* Remove this entry from other siblings */
	if (rt->fib6_nsiblings) {
		struct fib6_info *sibling, *next_sibling;

		/* The route is deleted from a multipath route. If this
		 * multipath route is the first route in the node, then we need
		 * to emit a delete notification. Otherwise, we need to skip
		 * the notification.
		 */
		if (rt->fib6_metric == leaf->fib6_metric &&
		    rt6_qualify_for_ecmp(leaf))
			notify_del = true;
		list_for_each_entry_safe(sibling, next_sibling,
					 &rt->fib6_siblings, fib6_siblings)
			sibling->fib6_nsiblings--;
		WRITE_ONCE(rt->fib6_nsiblings, 0);
		list_del_rcu(&rt->fib6_siblings);
		rt6_multipath_rebalance(next_sibling);
	}

	/* Adjust walkers */
	read_lock(&net->ipv6.fib6_walker_lock);
	FOR_WALKERS(net, w) {
		if (w->state == FWS_C && w->leaf == rt) {
			RT6_TRACE("walker %p adjusted by delroute\n", w);
			w->leaf = rcu_dereference_protected(rt->fib6_next,
					    lockdep_is_held(&table->tb6_lock));
			if (!w->leaf)
				w->state = FWS_U;
		}
	}
	read_unlock(&net->ipv6.fib6_walker_lock);

	/* If it was last route, call fib6_repair_tree() to:
	 * 1. For root node, put back null_entry as how the table was created.
	 * 2. For other nodes, expunge its radix tree node.
	 */
	if (!rcu_access_pointer(fn->leaf)) {
		if (!(fn->fn_flags & RTN_TL_ROOT)) {
			fn->fn_flags &= ~RTN_RTINFO;
			net->ipv6.rt6_stats->fib_route_nodes--;
		}
		fn = fib6_repair_tree(net, table, fn);
	}

	fib6_purge_rt(rt, fn, net);

	if (!info->skip_notify_kernel) {
		if (notify_del)
			call_fib6_entry_notifiers(net, FIB_EVENT_ENTRY_DEL,
						  rt, NULL);
		else if (replace_rt)
			call_fib6_entry_notifiers_replace(net, replace_rt);
	}
	if (!info->skip_notify)
		inet6_rt_notify(RTM_DELROUTE, rt, info, 0);

	fib6_info_release(rt);
}

int klpp_fib6_del(struct fib6_info *rt, struct nl_info *info)
{
	struct net *net = info->nl_net;
	struct fib6_info __rcu **rtp;
	struct fib6_info __rcu **rtp_next;
	struct fib6_table *table;
	struct fib6_node *fn;

	if (rt == net->ipv6.fib6_null_entry)
		return -ENOENT;

	table = rt->fib6_table;
	fn = rcu_dereference_protected(rt->fib6_node,
				       lockdep_is_held(&table->tb6_lock));
	if (!fn)
		return -ENOENT;

	WARN_ON(!(fn->fn_flags & RTN_RTINFO));

	/*
	 *	Walk the leaf entries looking for ourself
	 */

	for (rtp = &fn->leaf; *rtp; rtp = rtp_next) {
		struct fib6_info *cur = rcu_dereference_protected(*rtp,
					lockdep_is_held(&table->tb6_lock));
		if (rt == cur) {
			if (fib6_requires_src(cur))
				fib6_routes_require_src_dec(info->nl_net);
			klpp_fib6_del_route(table, fn, rtp, info);
			return 0;
		}
		rtp_next = &cur->fib6_next;
	}
	return -ENOENT;
}


#include "livepatch_bsc1249241.h"

#include <linux/livepatch.h>

extern typeof(call_fib6_entry_notifiers) call_fib6_entry_notifiers
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, call_fib6_entry_notifiers);
extern typeof(call_fib6_entry_notifiers_replace)
	 call_fib6_entry_notifiers_replace
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, call_fib6_entry_notifiers_replace);
extern typeof(fib6_metric_set) fib6_metric_set
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fib6_metric_set);
extern typeof(fib6_node_kmem) fib6_node_kmem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fib6_node_kmem);
extern typeof(fib6_purge_rt) fib6_purge_rt
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fib6_purge_rt);
extern typeof(inet6_rt_notify) inet6_rt_notify
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, inet6_rt_notify);
extern typeof(node_free_rcu) node_free_rcu
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, node_free_rcu);
extern typeof(rt6_multipath_rebalance) rt6_multipath_rebalance
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rt6_multipath_rebalance);
