/*
 * livepatch_bsc1203613
 *
 * Fix for CVE-2022-2588, bsc#1203613
 *
 *  Upstream commit:
 *  9ad36309e271 ("net_sched: cls_route: remove from list when handle is 0")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  9a68fb32d26175b075af81528345121ac2f06ef0
 *
 *  SLE15-SP2 and -SP3 commit:
 *  754369729f8b479abb17036668eaf04bd564c9f3
 *
 *  SLE15-SP4 commit:
 *  a6b822399d138bb4bfac2208211b6334d1ea9b3c
 *
 *  Copyright (c) 2022 SUSE
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

/* klp-ccp: from net/sched/cls_route.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/netlink.h>
#include <net/act_api.h>
#include <net/pkt_cls.h>

struct route4_fastmap {
	struct route4_filter		*filter;
	u32				id;
	int				iif;
};

struct route4_head {
	struct route4_fastmap		fastmap[16];
	struct route4_bucket __rcu	*table[256 + 1];
	struct rcu_head			rcu;
};

struct route4_bucket {
	/* 16 FROM buckets + 16 IIF buckets + 1 wildcard bucket */
	struct route4_filter __rcu	*ht[16 + 16 + 1];
	struct rcu_head			rcu;
};

struct route4_filter {
	struct route4_filter __rcu	*next;
	u32			id;
	int			iif;

	struct tcf_result	res;
	struct tcf_exts		exts;
	u32			handle;
	struct route4_bucket	*bkt;
	struct tcf_proto	*tp;
	struct rcu_work		rwork;
};

static void
(*klpe_route4_reset_fastmap)(struct route4_head *head);

static inline u32 to_hash(u32 id)
{
	u32 h = id & 0xFF;

	if (id & 0x8000)
		h += 256;
	return h;
}

static inline u32 from_hash(u32 id)
{
	id &= 0xFFFF;
	if (id == 0xFFFF)
		return 32;
	if (!(id & 0x8000)) {
		if (id > 255)
			return 256;
		return id & 0xF;
	}
	return 16 + (id & 0xF);
}

static void (*klpe_route4_delete_filter_work)(struct work_struct *work);

static const struct nla_policy (*klpe_route4_policy)[TCA_ROUTE4_MAX + 1];

static int route4_set_parms(struct net *net, struct tcf_proto *tp,
			    unsigned long base, struct route4_filter *f,
			    u32 handle, struct route4_head *head,
			    struct nlattr **tb, struct nlattr *est, int new,
			    bool ovr, struct netlink_ext_ack *extack)
{
	u32 id = 0, to = 0, nhandle = 0x8000;
	struct route4_filter *fp;
	unsigned int h1;
	struct route4_bucket *b;
	int err;

	err = tcf_exts_validate(net, tp, tb, est, &f->exts, ovr, extack);
	if (err < 0)
		return err;

	if (tb[TCA_ROUTE4_TO]) {
		if (new && handle & 0x8000)
			return -EINVAL;
		to = nla_get_u32(tb[TCA_ROUTE4_TO]);
		if (to > 0xFF)
			return -EINVAL;
		nhandle = to;
	}

	if (tb[TCA_ROUTE4_FROM]) {
		if (tb[TCA_ROUTE4_IIF])
			return -EINVAL;
		id = nla_get_u32(tb[TCA_ROUTE4_FROM]);
		if (id > 0xFF)
			return -EINVAL;
		nhandle |= id << 16;
	} else if (tb[TCA_ROUTE4_IIF]) {
		id = nla_get_u32(tb[TCA_ROUTE4_IIF]);
		if (id > 0x7FFF)
			return -EINVAL;
		nhandle |= (id | 0x8000) << 16;
	} else
		nhandle |= 0xFFFF << 16;

	if (handle && new) {
		nhandle |= handle & 0x7F00;
		if (nhandle != handle)
			return -EINVAL;
	}

	h1 = to_hash(nhandle);
	b = rtnl_dereference(head->table[h1]);
	if (!b) {
		b = kzalloc(sizeof(struct route4_bucket), GFP_KERNEL);
		if (b == NULL)
			return -ENOBUFS;

		rcu_assign_pointer(head->table[h1], b);
	} else {
		unsigned int h2 = from_hash(nhandle >> 16);

		for (fp = rtnl_dereference(b->ht[h2]);
		     fp;
		     fp = rtnl_dereference(fp->next))
			if (fp->handle == f->handle)
				return -EEXIST;
	}

	if (tb[TCA_ROUTE4_TO])
		f->id = to;

	if (tb[TCA_ROUTE4_FROM])
		f->id = to | id<<16;
	else if (tb[TCA_ROUTE4_IIF])
		f->iif = id;

	f->handle = nhandle;
	f->bkt = b;
	f->tp = tp;

	if (tb[TCA_ROUTE4_CLASSID]) {
		f->res.classid = nla_get_u32(tb[TCA_ROUTE4_CLASSID]);
		tcf_bind_filter(tp, &f->res, base);
	}

	return 0;
}

int klpp_route4_change(struct net *net, struct sk_buff *in_skb,
			 struct tcf_proto *tp, unsigned long base, u32 handle,
			 struct nlattr **tca, void **arg, bool ovr,
			 struct netlink_ext_ack *extack)
{
	struct route4_head *head = rtnl_dereference(tp->root);
	struct route4_filter __rcu **fp;
	struct route4_filter *fold, *f1, *pfp, *f = NULL;
	struct route4_bucket *b;
	struct nlattr *opt = tca[TCA_OPTIONS];
	struct nlattr *tb[TCA_ROUTE4_MAX + 1];
	unsigned int h, th;
	int err;
	bool new = true;

	if (opt == NULL)
		return handle ? -EINVAL : 0;

	err = nla_parse_nested(tb, TCA_ROUTE4_MAX, opt, (*klpe_route4_policy), NULL);
	if (err < 0)
		return err;

	fold = *arg;
	if (fold && handle && fold->handle != handle)
			return -EINVAL;

	err = -ENOBUFS;
	f = kzalloc(sizeof(struct route4_filter), GFP_KERNEL);
	if (!f)
		goto errout;

	err = tcf_exts_init(&f->exts, TCA_ROUTE4_ACT, TCA_ROUTE4_POLICE);
	if (err < 0)
		goto errout;

	if (fold) {
		f->id = fold->id;
		f->iif = fold->iif;
		f->res = fold->res;
		f->handle = fold->handle;

		f->tp = fold->tp;
		f->bkt = fold->bkt;
		new = false;
	}

	err = route4_set_parms(net, tp, base, f, handle, head, tb,
			       tca[TCA_RATE], new, ovr, extack);
	if (err < 0)
		goto errout;

	h = from_hash(f->handle >> 16);
	fp = &f->bkt->ht[h];
	for (pfp = rtnl_dereference(*fp);
	     (f1 = rtnl_dereference(*fp)) != NULL;
	     fp = &f1->next)
		if (f->handle < f1->handle)
			break;

	tcf_block_netif_keep_dst(tp->chain->block);
	rcu_assign_pointer(f->next, f1);
	rcu_assign_pointer(*fp, f);

	if (fold) {
		th = to_hash(fold->handle);
		h = from_hash(fold->handle >> 16);
		b = rtnl_dereference(head->table[th]);
		if (b) {
			fp = &b->ht[h];
			for (pfp = rtnl_dereference(*fp); pfp;
			     fp = &pfp->next, pfp = rtnl_dereference(*fp)) {
				if (pfp == fold) {
					rcu_assign_pointer(*fp, fold->next);
					break;
				}
			}
		}
	}

	(*klpe_route4_reset_fastmap)(head);
	*arg = f;
	if (fold) {
		tcf_unbind_filter(tp, &fold->res);
		tcf_exts_get_net(&fold->exts);
		tcf_queue_work(&fold->rwork, (*klpe_route4_delete_filter_work));
	}
	return 0;

errout:
	if (f)
		tcf_exts_destroy(&f->exts);
	kfree(f);
	return err;
}



#define LP_MODULE "cls_route"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1203613.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "route4_delete_filter_work", (void *)&klpe_route4_delete_filter_work,
	  "cls_route" },
	{ "route4_policy", (void *)&klpe_route4_policy, "cls_route" },
	{ "route4_reset_fastmap", (void *)&klpe_route4_reset_fastmap,
	  "cls_route" },
};

static int livepatch_bsc1203613_module_notify(struct notifier_block *nb,
					unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = livepatch_bsc1203613_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1203613_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1203613_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
