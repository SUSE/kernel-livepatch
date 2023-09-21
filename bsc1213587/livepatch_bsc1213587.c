/*
 * livepatch_bsc1213587
 *
 * Fix for CVE-2023-3609, bsc#1213587
 *
 *  Upstream commit:
 *  04c55383fa56 ("net/sched: cls_u32: Fix reference counter leak leading to overflow")
 *
 *  SLE12-SP5 commit:
 *  a166dc285d6ef84c018f94467ae62e701654abd9
 *
 *  SLE15-SP1 commit:
 *  adaee394c77c2667bd01993d50b344c049ee908a
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b22e9b96b7bd91c0e24ac76c3bf0e2ff73ed2d4d
 *
 *  SLE15-SP4 and -SP5 commit:
 *  e129a1f07642a255814cecf6ee294dcf319e4683
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

#if !IS_MODULE(CONFIG_NET_CLS_U32)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/sched/cls_u32.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/bitmap.h>
#include <linux/netdevice.h>
#include <linux/hash.h>
#include <net/netlink.h>
#include <net/act_api.h>
#include <net/pkt_cls.h>
#include <linux/netdevice.h>
#include <linux/idr.h>

struct tc_u_knode {
	struct tc_u_knode __rcu	*next;
	u32			handle;
	struct tc_u_hnode __rcu	*ht_up;
	struct tcf_exts		exts;
#ifdef CONFIG_NET_CLS_IND
	int			ifindex;
#endif
	u8			fshift;
	struct tcf_result	res;
	struct tc_u_hnode __rcu	*ht_down;
#ifdef CONFIG_CLS_U32_PERF
	struct tc_u32_pcnt __percpu *pf;
#endif
	u32			flags;
	unsigned int		in_hw_count;
#ifdef CONFIG_CLS_U32_MARK
	u32			val;
	u32			mask;
	u32 __percpu		*pcpu_success;
#endif
	struct rcu_work		rwork;
	/* The 'sel' field MUST be the last field in structure to allow for
	 * tc_u32_keys allocated at end of structure.
	 */
	struct tc_u32_sel	sel;
};

struct tc_u_hnode {
	struct tc_u_hnode __rcu	*next;
	u32			handle;
	u32			prio;
	int			refcnt;
	unsigned int		divisor;
	struct idr		handle_idr;
	bool			is_root;
	struct rcu_head		rcu;
	u32			flags;
	/* The 'ht' field MUST be the last field in structure to allow for
	 * more entries allocated at end of structure.
	 */
	struct tc_u_knode __rcu	*ht[1];
};

struct tc_u_common {
	struct tc_u_hnode __rcu	*hlist;
	void			*ptr;
	int			refcnt;
	struct idr		handle_idr;
	struct hlist_node	hnode;
	long			knodes;
};

static struct tc_u_hnode *u32_lookup_ht(struct tc_u_common *tp_c, u32 handle)
{
	struct tc_u_hnode *ht;

	for (ht = rtnl_dereference(tp_c->hlist);
	     ht;
	     ht = rtnl_dereference(ht->next))
		if (ht->handle == handle)
			break;

	return ht;
}

int klpp_u32_set_parms(struct net *net, struct tcf_proto *tp,
			 unsigned long base,
			 struct tc_u_knode *n, struct nlattr **tb,
			 struct nlattr *est, bool ovr,
			 struct netlink_ext_ack *extack)
{
	int err;
#ifdef CONFIG_NET_CLS_IND
	int ifindex = -1;
#endif

	err = tcf_exts_validate(net, tp, tb, est, &n->exts, ovr, extack);
	if (err < 0)
		return err;

#ifdef CONFIG_NET_CLS_IND
	if (tb[TCA_U32_INDEV]) {
		ifindex = tcf_change_indev(net, tb[TCA_U32_INDEV], extack);
		if (ifindex < 0)
			return -EINVAL;
	}
#endif

	if (tb[TCA_U32_LINK]) {
		u32 handle = nla_get_u32(tb[TCA_U32_LINK]);
		struct tc_u_hnode *ht_down = NULL, *ht_old;

		if (TC_U32_KEY(handle)) {
			NL_SET_ERR_MSG_MOD(extack, "u32 Link handle must be a hash table");
			return -EINVAL;
		}

		if (handle) {
			ht_down = u32_lookup_ht(tp->data, handle);

			if (!ht_down) {
				NL_SET_ERR_MSG_MOD(extack, "Link hash table not found");
				return -EINVAL;
			}
			if (ht_down->is_root) {
				NL_SET_ERR_MSG_MOD(extack, "Not linking to root node");
				return -EINVAL;
			}
			ht_down->refcnt++;
		}

		ht_old = rtnl_dereference(n->ht_down);
		rcu_assign_pointer(n->ht_down, ht_down);

		if (ht_old)
			ht_old->refcnt--;
	}
	if (tb[TCA_U32_CLASSID]) {
		n->res.classid = nla_get_u32(tb[TCA_U32_CLASSID]);
		tcf_bind_filter(tp, &n->res, base);
	}

 #ifdef CONFIG_NET_CLS_IND
	if (ifindex >= 0)
		n->ifindex = ifindex;
 #endif
	return 0;
}
