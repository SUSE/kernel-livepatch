/*
 * livepatch_bsc1199695
 *
 * Fix for CVE-2022-29581, bsc#1199695
 *
 *  Upstream commit:
 *  3db09e762dc7 ("net/sched: cls_u32: fix netns refcount changes in
 *                 u32_change()")
 *
 *  SLE12-SP4 and SLE15 commit:
 *  not affected
 *
 *  SLE12-SP5 commit:
 *  944805bf9e0ead186b2348597af746d8cdff1ce7
 *
 *  SLE15-SP1 commit:
 *  ad4e35cfea7579c3fbbcc2f34e972b3799db7cce
 *
 *  SLE15-SP2 and -SP3 commit:
 *  e1d69920a75bc2f1be2ed8ea3dee68fe0341c07b
 *
 *  SLE15-SP4 commit:
 *  6f81977bee4b6e3c5b29d35517a8497ff49d92cd
 *
 *
 *  Copyright (c) 2022 SUSE
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

#if !IS_MODULE(CONFIG_NET_CLS_U32)
#error "Live patch supports only CONFIG_NET_CLS_U32=m"
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
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u32			flags;
	unsigned int		in_hw_count;
#ifdef CONFIG_CLS_U32_MARK
	u32			val;
	u32			mask;
	u32 __percpu		*pcpu_success;
#else
#error "klp-ccp: a preceeding branch should have been taken"
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

static u32 gen_new_htid(struct tc_u_common *tp_c, struct tc_u_hnode *ptr)
{
	int id = idr_alloc_cyclic(&tp_c->handle_idr, ptr, 1, 0x7FF, GFP_KERNEL);
	if (id < 0)
		return 0;
	return (id | 0x800U) << 20;
}


/*
 * Fix CVE-2022-29581
 *  -1 line, +1 line
 */
static void klpp___u32_destroy_key(struct tc_u_knode *n)
{
	struct tc_u_hnode *ht = rtnl_dereference(n->ht_down);

	tcf_exts_destroy(&n->exts);
	/*
	 * Fix CVE-2022-29581
	 *  -1 line
	 */

	if (ht && --ht->refcnt == 0)
		kfree(ht);
	/*
	 * Fix CVE-2022-29581
	 *  -14 lines, +1 line
	 */
	 kfree(n);
}

static void (*klpe_u32_delete_key_work)(struct work_struct *work);

static int (*klpe_u32_replace_hw_hnode)(struct tcf_proto *tp, struct tc_u_hnode *h,
				u32 flags, struct netlink_ext_ack *extack);

static int (*klpe_u32_replace_hw_knode)(struct tcf_proto *tp, struct tc_u_knode *n,
				u32 flags, struct netlink_ext_ack *extack);

static u32 gen_new_kid(struct tc_u_hnode *ht, u32 htid)
{
	u32 index = htid | 0x800;
	u32 max = htid | 0xFFF;

	if (idr_alloc_u32(&ht->handle_idr, NULL, &index, max, GFP_KERNEL)) {
		index = htid + 1;
		if (idr_alloc_u32(&ht->handle_idr, NULL, &index, max,
				 GFP_KERNEL))
			index = max;
	}

	return index;
}

static const struct nla_policy (*klpe_u32_policy)[TCA_U32_MAX + 1];

static int (*klpe_u32_set_parms)(struct net *net, struct tcf_proto *tp,
			 unsigned long base,
			 struct tc_u_knode *n, struct nlattr **tb,
			 struct nlattr *est, bool ovr,
			 struct netlink_ext_ack *extack);

static void u32_replace_knode(struct tcf_proto *tp, struct tc_u_common *tp_c,
			      struct tc_u_knode *n)
{
	struct tc_u_knode __rcu **ins;
	struct tc_u_knode *pins;
	struct tc_u_hnode *ht;

	if (TC_U32_HTID(n->handle) == TC_U32_ROOT)
		ht = rtnl_dereference(tp->root);
	else
		ht = u32_lookup_ht(tp_c, TC_U32_HTID(n->handle));

	ins = &ht->ht[TC_U32_HASH(n->handle)];

	/* The node must always exist for it to be replaced if this is not the
	 * case then something went very wrong elsewhere.
	 */
	for (pins = rtnl_dereference(*ins); ;
	     ins = &pins->next, pins = rtnl_dereference(*ins))
		if (pins->handle == n->handle)
			break;

	idr_replace(&ht->handle_idr, n, n->handle);
	RCU_INIT_POINTER(n->next, pins->next);
	rcu_assign_pointer(*ins, n);
}

static struct tc_u_knode *u32_init_knode(struct tcf_proto *tp,
					 struct tc_u_knode *n)
{
	struct tc_u_hnode *ht = rtnl_dereference(n->ht_down);
	struct tc_u32_sel *s = &n->sel;
	struct tc_u_knode *new;

	new = kzalloc(sizeof(*n) + s->nkeys*sizeof(struct tc_u32_key),
		      GFP_KERNEL);

	if (!new)
		return NULL;

	RCU_INIT_POINTER(new->next, n->next);
	new->handle = n->handle;
	RCU_INIT_POINTER(new->ht_up, n->ht_up);

#ifdef CONFIG_NET_CLS_IND
	new->ifindex = n->ifindex;
#endif
	new->fshift = n->fshift;
	new->res = n->res;
	new->flags = n->flags;
	RCU_INIT_POINTER(new->ht_down, ht);

	/* bump reference count as long as we hold pointer to structure */
	if (ht)
		ht->refcnt++;

#ifdef CONFIG_CLS_U32_PERF
	new->pf = n->pf;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_CLS_U32_MARK
	new->val = n->val;
	new->mask = n->mask;
	/* Similarly success statistics must be moved as pointers */
	new->pcpu_success = n->pcpu_success;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	memcpy(&new->sel, s, sizeof(*s) + s->nkeys*sizeof(struct tc_u32_key));

	if (tcf_exts_init(&new->exts, TCA_U32_ACT, TCA_U32_POLICE)) {
		kfree(new);
		return NULL;
	}

	return new;
}

int klpp_u32_change(struct net *net, struct sk_buff *in_skb,
		      struct tcf_proto *tp, unsigned long base, u32 handle,
		      struct nlattr **tca, void **arg, bool ovr,
		      struct netlink_ext_ack *extack)
{
	struct tc_u_common *tp_c = tp->data;
	struct tc_u_hnode *ht;
	struct tc_u_knode *n;
	struct tc_u32_sel *s;
	struct nlattr *opt = tca[TCA_OPTIONS];
	struct nlattr *tb[TCA_U32_MAX + 1];
	u32 htid, flags = 0;
	size_t sel_size;
	int err;
#ifdef CONFIG_CLS_U32_PERF
	size_t size;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (!opt) {
		if (handle) {
			NL_SET_ERR_MSG_MOD(extack, "Filter handle requires options");
			return -EINVAL;
		} else {
			return 0;
		}
	}

	err = nla_parse_nested(tb, TCA_U32_MAX, opt, (*klpe_u32_policy), extack);
	if (err < 0)
		return err;

	if (tb[TCA_U32_FLAGS]) {
		flags = nla_get_u32(tb[TCA_U32_FLAGS]);
		if (!tc_flags_valid(flags)) {
			NL_SET_ERR_MSG_MOD(extack, "Invalid filter flags");
			return -EINVAL;
		}
	}

	n = *arg;
	if (n) {
		struct tc_u_knode *new;

		if (TC_U32_KEY(n->handle) == 0) {
			NL_SET_ERR_MSG_MOD(extack, "Key node id cannot be zero");
			return -EINVAL;
		}

		if ((n->flags ^ flags) &
		    ~(TCA_CLS_FLAGS_IN_HW | TCA_CLS_FLAGS_NOT_IN_HW)) {
			NL_SET_ERR_MSG_MOD(extack, "Key node flags do not match passed flags");
			return -EINVAL;
		}

		new = u32_init_knode(tp, n);
		if (!new)
			return -ENOMEM;

		err = (*klpe_u32_set_parms)(net, tp, base, new, tb,
				    tca[TCA_RATE], ovr, extack);

		if (err) {
			/*
			 * Fix CVE-2022-29581
			 *  -1 line, +1 line
			 */
			klpp___u32_destroy_key(new);
			return err;
		}

		err = (*klpe_u32_replace_hw_knode)(tp, new, flags, extack);
		if (err) {
			/*
			 * Fix CVE-2022-29581
			 *  -1 line, +1 line
			 */
			klpp___u32_destroy_key(new);
			return err;
		}

		if (!tc_in_hw(new->flags))
			new->flags |= TCA_CLS_FLAGS_NOT_IN_HW;

		u32_replace_knode(tp, tp_c, new);
		tcf_unbind_filter(tp, &n->res);
		tcf_exts_get_net(&n->exts);
		tcf_queue_work(&n->rwork, (*klpe_u32_delete_key_work));
		return 0;
	}

	if (tb[TCA_U32_DIVISOR]) {
		unsigned int divisor = nla_get_u32(tb[TCA_U32_DIVISOR]);

		if (!is_power_of_2(divisor)) {
			NL_SET_ERR_MSG_MOD(extack, "Divisor is not a power of 2");
			return -EINVAL;
		}
		if (divisor-- > 0x100) {
			NL_SET_ERR_MSG_MOD(extack, "Exceeded maximum 256 hash buckets");
			return -EINVAL;
		}
		if (TC_U32_KEY(handle)) {
			NL_SET_ERR_MSG_MOD(extack, "Divisor can only be used on a hash table");
			return -EINVAL;
		}
		ht = kzalloc(sizeof(*ht) + divisor*sizeof(void *), GFP_KERNEL);
		if (ht == NULL)
			return -ENOBUFS;
		if (handle == 0) {
			handle = gen_new_htid(tp->data, ht);
			if (handle == 0) {
				kfree(ht);
				return -ENOMEM;
			}
		} else {
			err = idr_alloc_u32(&tp_c->handle_idr, ht, &handle,
					    handle, GFP_KERNEL);
			if (err) {
				kfree(ht);
				return err;
			}
		}
		ht->refcnt = 1;
		ht->divisor = divisor;
		ht->handle = handle;
		ht->prio = tp->prio;
		idr_init(&ht->handle_idr);
		ht->flags = flags;

		err = (*klpe_u32_replace_hw_hnode)(tp, ht, flags, extack);
		if (err) {
			idr_remove(&tp_c->handle_idr, handle);
			kfree(ht);
			return err;
		}

		RCU_INIT_POINTER(ht->next, tp_c->hlist);
		rcu_assign_pointer(tp_c->hlist, ht);
		*arg = ht;

		return 0;
	}

	if (tb[TCA_U32_HASH]) {
		htid = nla_get_u32(tb[TCA_U32_HASH]);
		if (TC_U32_HTID(htid) == TC_U32_ROOT) {
			ht = rtnl_dereference(tp->root);
			htid = ht->handle;
		} else {
			ht = u32_lookup_ht(tp->data, TC_U32_HTID(htid));
			if (!ht) {
				NL_SET_ERR_MSG_MOD(extack, "Specified hash table not found");
				return -EINVAL;
			}
		}
	} else {
		ht = rtnl_dereference(tp->root);
		htid = ht->handle;
	}

	if (ht->divisor < TC_U32_HASH(htid)) {
		NL_SET_ERR_MSG_MOD(extack, "Specified hash table buckets exceed configured value");
		return -EINVAL;
	}

	if (handle) {
		if (TC_U32_HTID(handle) && TC_U32_HTID(handle ^ htid)) {
			NL_SET_ERR_MSG_MOD(extack, "Handle specified hash table address mismatch");
			return -EINVAL;
		}
		handle = htid | TC_U32_NODE(handle);
		err = idr_alloc_u32(&ht->handle_idr, NULL, &handle, handle,
				    GFP_KERNEL);
		if (err)
			return err;
	} else
		handle = gen_new_kid(ht, htid);

	if (tb[TCA_U32_SEL] == NULL) {
		NL_SET_ERR_MSG_MOD(extack, "Selector not specified");
		err = -EINVAL;
		goto erridr;
	}

	s = nla_data(tb[TCA_U32_SEL]);
	sel_size = sizeof(*s) + s->nkeys * sizeof(*s->keys);
	if (nla_len(tb[TCA_U32_SEL]) < sel_size)
		return -EINVAL;

	n = kzalloc(offsetof(typeof(*n), sel) + sel_size, GFP_KERNEL);
	if (n == NULL) {
		err = -ENOBUFS;
		goto erridr;
	}

#ifdef CONFIG_CLS_U32_PERF
	size = sizeof(struct tc_u32_pcnt) + s->nkeys * sizeof(u64);
	n->pf = __alloc_percpu(size, __alignof__(struct tc_u32_pcnt));
	if (!n->pf) {
		err = -ENOBUFS;
		goto errfree;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	memcpy(&n->sel, s, sel_size);
	RCU_INIT_POINTER(n->ht_up, ht);
	n->handle = handle;
	n->fshift = s->hmask ? ffs(ntohl(s->hmask)) - 1 : 0;
	n->flags = flags;

	err = tcf_exts_init(&n->exts, TCA_U32_ACT, TCA_U32_POLICE);
	if (err < 0)
		goto errout;

#ifdef CONFIG_CLS_U32_MARK
	n->pcpu_success = alloc_percpu(u32);
	if (!n->pcpu_success) {
		err = -ENOMEM;
		goto errout;
	}

	if (tb[TCA_U32_MARK]) {
		struct tc_u32_mark *mark;

		mark = nla_data(tb[TCA_U32_MARK]);
		n->val = mark->val;
		n->mask = mark->mask;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	err = (*klpe_u32_set_parms)(net, tp, base, n, tb, tca[TCA_RATE], ovr,
			    extack);
	if (err == 0) {
		struct tc_u_knode __rcu **ins;
		struct tc_u_knode *pins;

		err = (*klpe_u32_replace_hw_knode)(tp, n, flags, extack);
		if (err)
			goto errhw;

		if (!tc_in_hw(n->flags))
			n->flags |= TCA_CLS_FLAGS_NOT_IN_HW;

		ins = &ht->ht[TC_U32_HASH(handle)];
		for (pins = rtnl_dereference(*ins); pins;
		     ins = &pins->next, pins = rtnl_dereference(*ins))
			if (TC_U32_NODE(handle) < TC_U32_NODE(pins->handle))
				break;

		RCU_INIT_POINTER(n->next, pins);
		rcu_assign_pointer(*ins, n);
		tp_c->knodes++;
		*arg = n;
		return 0;
	}

errhw:
#ifdef CONFIG_CLS_U32_MARK
	free_percpu(n->pcpu_success);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
errout:
	tcf_exts_destroy(&n->exts);
#ifdef CONFIG_CLS_U32_PERF
errfree:
	free_percpu(n->pf);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	kfree(n);
erridr:
	idr_remove(&ht->handle_idr, handle);
	return err;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1199695.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "cls_u32"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "u32_delete_key_work", (void *)&klpe_u32_delete_key_work, "cls_u32" },
	{ "u32_policy", (void *)&klpe_u32_policy, "cls_u32" },
	{ "u32_replace_hw_hnode", (void *)&klpe_u32_replace_hw_hnode,
	  "cls_u32" },
	{ "u32_replace_hw_knode", (void *)&klpe_u32_replace_hw_knode,
	  "cls_u32" },
	{ "u32_set_parms", (void *)&klpe_u32_set_parms, "cls_u32" },
};

static int livepatch_bsc1199695_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1199695_module_nb = {
	.notifier_call = livepatch_bsc1199695_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1199695_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1199695_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1199695_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1199695_module_nb);
}
