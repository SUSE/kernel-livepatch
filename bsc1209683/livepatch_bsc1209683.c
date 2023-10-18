/*
 * livepatch_bsc1209683
 *
 * Fix for CVE-2023-1281, bsc#1209683 and CVE-2023-1829, bsc#1210619
 *
 *  Upstream commit:
 *  ee059170b1f7 ("net/sched: tcindex: update imperfect hash filters respecting rcu")
 *
 *  SLE12-SP4 commit:
 *  Not affected
 *
 *  SLE12-SP5 commit:
 *  79d6cb4ebd55e1e89cfd1576af963911bd9087f0
 *
 *  SLE15-SP1 commit:
 *  972d4ccee318ac2c49d93bfe12b797d0f3fe8a0b
 *
 *  SLE15-SP2 and -SP3 commit:
 *  97b3f9df8e15cfbccf45bb33effdeb6a1ad10225
 *
 *  SLE15-SP4 commits:
 *  aced962af6ef750f2a692b9a203ecffe2ff1b131
 *  28b65ec9908b70cbbbed942c928edd2141631a26
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

/* klp-ccp: from net/sched/cls_tcindex.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <net/act_api.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>

#define rcu_replace_pointer(rcu_ptr, ptr, c)				\
({									\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	__tmp;								\
})

#define PERFECT_HASH_THRESHOLD	64	/* use perfect hash if not bigger */
#define DEFAULT_HASH_SIZE	64	/* optimized for diffserv */

struct tcindex_filter_result {
	struct tcf_exts		exts;
	struct tcf_result	res;
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
	struct rcu_work rwork;
};

static struct tcindex_filter_result *(*klpe_tcindex_lookup)(struct tcindex_data *p,
						    u16 key);

static void klpp___tcindex_destroy_rexts(struct tcindex_filter_result *r)
{
	tcf_exts_destroy(&r->exts);
	/*
	 * Fix CVE-2023-1829
	 *  +1 line
	 */
	r->exts.actions = NULL;
	tcf_exts_put_net(&r->exts);
}

static void (*klpe_tcindex_destroy_rexts_work)(struct work_struct *work);

void klpp_tcindex_destroy_rexts_work(struct work_struct *work)
{
	struct tcindex_filter_result *r;

	r = container_of(to_rcu_work(work),
			 struct tcindex_filter_result,
			 rwork);
	rtnl_lock();
	klpp___tcindex_destroy_rexts(r);
	rtnl_unlock();
}

static void (*klpe___tcindex_destroy_fexts)(struct tcindex_filter *f);

static void (*klpe_tcindex_destroy_fexts_work)(struct work_struct *work);

int klpp_tcindex_delete(struct tcf_proto *tp, void *arg, bool *last,
			  struct netlink_ext_ack *extack)
{
	struct tcindex_data *p = rtnl_dereference(tp->root);
	struct tcindex_filter_result *r = arg;
	struct tcindex_filter __rcu **walk;
	struct tcindex_filter *f = NULL;

	pr_debug("tcindex_delete(tp %p,arg %p),p %p\n", tp, arg, p);
	if (p->perfect) {
		if (!r->res.class)
			return -ENOENT;
	} else {
		int i;

		for (i = 0; i < p->hash; i++) {
			walk = p->h + i;
			for (f = rtnl_dereference(*walk); f;
			     walk = &f->next, f = rtnl_dereference(*walk)) {
				if (&f->result == r)
					goto found;
			}
		}
		return -ENOENT;

found:
		rcu_assign_pointer(*walk, rtnl_dereference(f->next));
	}
	tcf_unbind_filter(tp, &r->res);
	/* all classifiers are required to call tcf_exts_destroy() after rcu
	 * grace period, since converted-to-rcu actions are relying on that
	 * in cleanup() callback
	 */
	if (f) {
		if (tcf_exts_get_net(&f->result.exts))
			tcf_queue_work(&f->rwork, (*klpe_tcindex_destroy_fexts_work));
		else
			(*klpe___tcindex_destroy_fexts)(f);
	} else {
		/*
		 * Fix CVE-2023-1829
		 *  -4 lines, +9 lines
		 * Do not re-enqueue if the ->rwork is already pending. Note
		 * that tcf_queue_work() would unconditionally wipe ->rwork
		 * before enqueueing.
		 */
		if (tcf_exts_get_net(&r->exts)) {
			if (!work_pending(&r->rwork.work)) {
				tcf_queue_work(&r->rwork, (*klpe_tcindex_destroy_rexts_work));
			} else {
				tcf_exts_put_net(&r->exts);
			}
		} else {
			klpp___tcindex_destroy_rexts(r);
		}
	}

	*last = false;
	return 0;
}

static int (*klpe_tcindex_destroy_element)(struct tcf_proto *tp,
				   void *arg, struct tcf_walker *walker);

static void (*klpe_tcindex_destroy_work)(struct work_struct *work);

static inline int
valid_perfect_hash(struct tcindex_data *p)
{
	return  p->hash > (p->mask >> p->shift);
}

static int (*klpe_tcindex_filter_result_init)(struct tcindex_filter_result *r);

static void (*klpe_tcindex_partial_destroy_work)(struct work_struct *work);

static void tcindex_free_perfect_hash(struct tcindex_data *cp)
{
	int i;

	for (i = 0; i < cp->hash; i++)
		tcf_exts_destroy(&cp->perfect[i].exts);
	kfree(cp->perfect);
}

static int (*klpe_tcindex_alloc_perfect_hash)(struct tcindex_data *cp);

int
klpp_tcindex_set_parms(struct net *net, struct tcf_proto *tp, unsigned long base,
		  u32 handle, struct tcindex_data *p,
		  struct tcindex_filter_result *r, struct nlattr **tb,
		  struct nlattr *est, bool ovr, struct netlink_ext_ack *extack)
{
	struct tcindex_filter_result new_filter_result, *old_r = r;
	struct tcindex_data *cp = NULL, *oldp;
	struct tcindex_filter *f = NULL; /* make gcc behave */
	struct tcf_result cr = {};
	int err, balloc = 0;
	struct tcf_exts e;
	bool update_h = false;

	err = tcf_exts_init(&e, TCA_TCINDEX_ACT, TCA_TCINDEX_POLICE);
	if (err < 0)
		return err;
	err = tcf_exts_validate(net, tp, tb, est, &e, ovr, extack);
	if (err < 0)
		goto errout;

	err = -ENOMEM;
	/* tcindex_data attributes must look atomic to classifier/lookup so
	 * allocate new tcindex data and RCU assign it onto root. Keeping
	 * perfect hash and hash pointers from old data.
	 */
	cp = kzalloc(sizeof(*cp), GFP_KERNEL);
	if (!cp)
		goto errout;

	cp->mask = p->mask;
	cp->shift = p->shift;
	cp->hash = p->hash;
	cp->alloc_hash = p->alloc_hash;
	cp->fall_through = p->fall_through;
	cp->tp = tp;

	if (tb[TCA_TCINDEX_HASH])
		cp->hash = nla_get_u32(tb[TCA_TCINDEX_HASH]);

	if (tb[TCA_TCINDEX_MASK])
		cp->mask = nla_get_u16(tb[TCA_TCINDEX_MASK]);

	if (tb[TCA_TCINDEX_SHIFT])
		cp->shift = nla_get_u32(tb[TCA_TCINDEX_SHIFT]);

	if (!cp->hash) {
		/* Hash not specified, use perfect hash if the upper limit
		 * of the hashing index is below the threshold.
		 */
		if ((cp->mask >> cp->shift) < PERFECT_HASH_THRESHOLD)
			cp->hash = (cp->mask >> cp->shift) + 1;
		else
			cp->hash = DEFAULT_HASH_SIZE;
	}

	if (p->perfect) {
		int i;

		if ((*klpe_tcindex_alloc_perfect_hash)(cp) < 0)
			goto errout;
		cp->alloc_hash = cp->hash;
		for (i = 0; i < min(cp->hash, p->hash); i++)
			cp->perfect[i].res = p->perfect[i].res;
		balloc = 1;
	}
	cp->h = p->h;

	err = (*klpe_tcindex_filter_result_init)(&new_filter_result);
	if (err < 0)
		goto errout_alloc;
	if (old_r)
		cr = r->res;

	err = -EBUSY;

	/* Hash already allocated, make sure that we still meet the
	 * requirements for the allocated hash.
	 */
	if (cp->perfect) {
		if (!valid_perfect_hash(cp) ||
		    cp->hash > cp->alloc_hash)
			goto errout_alloc;
	} else if (cp->h && cp->hash != cp->alloc_hash) {
		goto errout_alloc;
	}

	err = -EINVAL;
	if (tb[TCA_TCINDEX_FALL_THROUGH])
		cp->fall_through = nla_get_u32(tb[TCA_TCINDEX_FALL_THROUGH]);

	if (!cp->perfect && !cp->h)
		cp->alloc_hash = cp->hash;

	/* Note: this could be as restrictive as if (handle & ~(mask >> shift))
	 * but then, we'd fail handles that may become valid after some future
	 * mask change. While this is extremely unlikely to ever matter,
	 * the check below is safer (and also more backwards-compatible).
	 */
	if (cp->perfect || valid_perfect_hash(cp))
		if (handle >= cp->alloc_hash)
			goto errout_alloc;


	err = -ENOMEM;
	if (!cp->perfect && !cp->h) {
		if (valid_perfect_hash(cp)) {
			if ((*klpe_tcindex_alloc_perfect_hash)(cp) < 0)
				goto errout_alloc;
			balloc = 1;
		} else {
			struct tcindex_filter __rcu **hash;

			hash = kcalloc(cp->hash,
				       sizeof(struct tcindex_filter *),
				       GFP_KERNEL);

			if (!hash)
				goto errout_alloc;

			cp->h = hash;
			balloc = 2;
		}
	}

	if (cp->perfect) {
		r = cp->perfect + handle;
	} else {
		/* imperfect area is updated in-place using rcu */
		update_h = !!(*klpe_tcindex_lookup)(cp, handle);
		r = &new_filter_result;
	}

	if (r == &new_filter_result) {
		f = kzalloc(sizeof(*f), GFP_KERNEL);
		if (!f)
			goto errout_alloc;
		f->key = handle;
		f->next = NULL;
		err = (*klpe_tcindex_filter_result_init)(&f->result);
		if (err < 0) {
			kfree(f);
			goto errout_alloc;
		}
	}

	if (tb[TCA_TCINDEX_CLASSID]) {
		cr.classid = nla_get_u32(tb[TCA_TCINDEX_CLASSID]);
		tcf_bind_filter(tp, &cr, base);
	}

	if (old_r && old_r != r) {
		err = (*klpe_tcindex_filter_result_init)(old_r);
		if (err < 0) {
			kfree(f);
			goto errout_alloc;
		}
	}

	oldp = p;
	r->res = cr;
	tcf_exts_change(&r->exts, &e);

	rcu_assign_pointer(tp->root, cp);

	if (update_h) {
		struct tcindex_filter __rcu **fp;
		struct tcindex_filter *cf;

		f->result.res = r->res;
		tcf_exts_change(&f->result.exts, &r->exts);

		/* imperfect area bucket */
		fp = cp->h + (handle % cp->hash);

		/* lookup the filter, guaranteed to exist */
		for (cf = rcu_dereference_bh_rtnl(*fp); cf;
		     fp = &cf->next, cf = rcu_dereference_bh_rtnl(*fp))
			if (cf->key == handle)
				break;

		f->next = cf->next;

		cf = rcu_replace_pointer(*fp, f, 1);
		tcf_exts_get_net(&cf->result.exts);
		tcf_queue_work(&cf->rwork, (*klpe_tcindex_destroy_fexts_work));
	} else if (r == &new_filter_result) {
		struct tcindex_filter *nfp;
		struct tcindex_filter __rcu **fp;

		f->result.res = r->res;
		tcf_exts_change(&f->result.exts, &r->exts);

		fp = cp->h + (handle % cp->hash);
		for (nfp = rtnl_dereference(*fp);
		     nfp;
		     fp = &nfp->next, nfp = rtnl_dereference(*fp))
				; /* nothing */

		rcu_assign_pointer(*fp, f);
	} else {
		tcf_exts_destroy(&new_filter_result.exts);
	}

	/*
	 * Fix CVE-2023-1829
	 *  -2 lines, +10 lines
	 */
	if (oldp) {
		/*
		 * The tc_filter_wq is ordered. So only make sure
		 * that all currently pending ->perfect[...].rwork
		 * rcu_works get enqueued there before submitting
		 * the work that would free ->perfect.
		 */
		rcu_barrier();
		tcf_queue_work(&oldp->rwork, (*klpe_tcindex_partial_destroy_work));
	}

	return 0;

errout_alloc:
	if (balloc == 1)
		tcindex_free_perfect_hash(cp);
	else if (balloc == 2)
		kfree(cp->h);
	tcf_exts_destroy(&new_filter_result.exts);
errout:
	kfree(cp);
	tcf_exts_destroy(&e);
	return err;
}

static void (*klpe_tcindex_walk)(struct tcf_proto *tp, struct tcf_walker *walker);

void klpp_tcindex_destroy(struct tcf_proto *tp,
			    struct netlink_ext_ack *extack)
{
	struct tcindex_data *p = rtnl_dereference(tp->root);
	struct tcf_walker walker;

	pr_debug("tcindex_destroy(tp %p),p %p\n", tp, p);
	walker.count = 0;
	walker.skip = 0;
	walker.fn = (*klpe_tcindex_destroy_element);
	(*klpe_tcindex_walk)(tp, &walker);

	/*
	 * Fix CVE-2023-1829
	 *  +7 lines
	 */
	/*
	 * The tc_filter_wq is ordered. So only make sure
	 * that all currently pending ->perfect[...].rwork
	 * rcu_works get enqueued there before submitting
	 * the work that would free ->perfect.
	 */
	rcu_barrier();
	tcf_queue_work(&p->rwork, (*klpe_tcindex_destroy_work));
}



#define LP_MODULE "cls_tcindex"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1209683.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__tcindex_destroy_fexts", (void *)&klpe___tcindex_destroy_fexts,
	  "cls_tcindex" },
	{ "tcindex_alloc_perfect_hash",
	  (void *)&klpe_tcindex_alloc_perfect_hash, "cls_tcindex" },
	{ "tcindex_destroy_element", (void *)&klpe_tcindex_destroy_element,
	  "cls_tcindex" },
	{ "tcindex_destroy_fexts_work",
	  (void *)&klpe_tcindex_destroy_fexts_work, "cls_tcindex" },
	{ "tcindex_destroy_rexts_work",
	  (void *)&klpe_tcindex_destroy_rexts_work, "cls_tcindex" },
	{ "tcindex_destroy_work", (void *)&klpe_tcindex_destroy_work,
	  "cls_tcindex" },
	{ "tcindex_filter_result_init",
	  (void *)&klpe_tcindex_filter_result_init, "cls_tcindex" },
	{ "tcindex_lookup", (void *)&klpe_tcindex_lookup, "cls_tcindex" },
	{ "tcindex_partial_destroy_work",
	  (void *)&klpe_tcindex_partial_destroy_work, "cls_tcindex" },
	{ "tcindex_walk", (void *)&klpe_tcindex_walk, "cls_tcindex" },
};

static int module_notify(struct notifier_block *nb,
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
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1209683_init(void)
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

void livepatch_bsc1209683_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
