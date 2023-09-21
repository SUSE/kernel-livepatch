/*
 * livepatch_bsc1210619
 *
 * Fix for CVE-2023-1829, bsc#1210619
 *
 *  Upstream commit:
 *  8c710f75256b ("net/sched: Retire tcindex classifier")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  none yet
 *
 *  SLE15-SP2 and -SP3 commit:
 *  none yet
 *
 *  SLE15-SP4 and SLE15-SP5 commit:
 *  28b65ec9908b70cbbbed942c928edd2141631a26
 *
 *
 *  Copyright (c) 2023 SUSE
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

#if !IS_MODULE(CONFIG_NET_CLS_TCINDEX)
#error "Live patch supports only CONFIG_NET_CLS_TCINDEX=m"
#endif

/* klp-ccp: from net/sched/cls_tcindex.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/refcount.h>
#include <net/act_api.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>

struct tcindex_filter_result {
	struct tcf_exts		exts;
	struct tcf_result	res;
	struct tcindex_data	*p;
	struct rcu_work		rwork;
};

struct tcindex_filter {
	u16 key;
	struct tcindex_filter_result result;
	struct tcindex_filter __rcu *next;
	struct rcu_work rwork;
};

struct tcindex_data {
	struct tcindex_filter_result *perfect; /* perfect hash; NULL if none */
	struct tcindex_filter __rcu **h; /* imperfect hash; */
	struct tcf_proto *tp;
	u16 mask;		/* AND key with mask */
	u32 shift;		/* shift ANDed key to the right */
	u32 hash;		/* hash table size; 0 if undefined */
	u32 alloc_hash;		/* allocated size */
	u32 fall_through;	/* 0: only classify if explicit match */
	refcount_t refcnt;	/* a temporary refcnt for perfect hash */
	struct rcu_work rwork;
};

static void tcindex_data_get(struct tcindex_data *p)
{
	refcount_inc(&p->refcnt);
}

static void (*klpe_tcindex_data_put)(struct tcindex_data *p);

void klpp___tcindex_destroy_rexts(struct tcindex_filter_result *r)
{
	tcf_exts_destroy(&r->exts);
	/*
	 * Fix CVE-2023-1829
	 *  +1 line
	 */
	r->exts.actions = NULL;
	tcf_exts_put_net(&r->exts);
	(*klpe_tcindex_data_put)(r->p);
}

static void (*klpe_tcindex_destroy_rexts_work)(struct work_struct *work);

static int (*klpe_tcindex_delete)(struct tcf_proto *tp, void *arg, bool *last,
			  bool rtnl_held, struct netlink_ext_ack *extack);

static void (*klpe_tcindex_destroy_work)(struct work_struct *work);

void klpp_tcindex_destroy(struct tcf_proto *tp, bool rtnl_held,
			    struct netlink_ext_ack *extack)
{
	struct tcindex_data *p = rtnl_dereference(tp->root);
	int i;

	pr_debug("tcindex_destroy(tp %p),p %p\n", tp, p);

	if (p->perfect) {
		for (i = 0; i < p->hash; i++) {
			struct tcindex_filter_result *r = p->perfect + i;

			/* tcf_queue_work() does not guarantee the ordering we
			 * want, so we have to take this refcnt temporarily to
			 * ensure 'p' is freed after all tcindex_filter_result
			 * here. Imperfect hash does not need this, because it
			 * uses linked lists rather than an array.
			 */
			tcindex_data_get(p);

			tcf_unbind_filter(tp, &r->res);
			/*
			 * Fix CVE-2023-1829
			 *  -5 lines, + lines
			 * Do not re-enqueue if the ->rwork is already
			 * pending. Note that tcf_queue_work() would
			 * unconditionally wipe ->rwork before
			 * enqueueing.
			 */
			if (tcf_exts_get_net(&r->exts)) {
				if (!work_pending(&r->rwork.work)) {
					tcf_queue_work(&r->rwork,
						(*klpe_tcindex_destroy_rexts_work));
				} else {
					tcf_exts_put_net(&r->exts);
					(*klpe_tcindex_data_put)(p);
				}
			} else {
				klpp___tcindex_destroy_rexts(r);
			}
		}
	}

	for (i = 0; p->h && i < p->hash; i++) {
		struct tcindex_filter *f, *next;
		bool last;

		for (f = rtnl_dereference(p->h[i]); f; f = next) {
			next = rtnl_dereference(f->next);
			(*klpe_tcindex_delete)(tp, &f->result, &last, rtnl_held, NULL);
		}
	}

	tcf_queue_work(&p->rwork, (*klpe_tcindex_destroy_work));
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1210619.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "cls_tcindex"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tcindex_data_put", (void *)&klpe_tcindex_data_put, "cls_tcindex" },
	{ "tcindex_delete", (void *)&klpe_tcindex_delete, "cls_tcindex" },
	{ "tcindex_destroy_rexts_work",
	  (void *)&klpe_tcindex_destroy_rexts_work, "cls_tcindex" },
	{ "tcindex_destroy_work", (void *)&klpe_tcindex_destroy_work,
	  "cls_tcindex" },
};

static int livepatch_bsc1210619_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1210619_module_nb = {
	.notifier_call = livepatch_bsc1210619_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1210619_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&livepatch_bsc1210619_module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LIVEPATCHED_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						  ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&livepatch_bsc1210619_module_nb);

	module_put(mod);
	return ret;
}

void livepatch_bsc1210619_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1210619_module_nb);
}
