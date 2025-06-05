/*
 * livepatch_bsc1238324
 *
 * Fix for CVE-2022-49080, bsc#1238324
 *
 *  Upstream commit:
 *  4ad099559b00 ("mm/mempolicy: fix mpol_new leak in shared_policy_replace")
 *
 *  SLE12-SP5 commit:
 *  067e764242e8aa6f98b660fbd3b441015a1b6864
 *
 *  SLE15-SP3 commit:
 *  60fff825f2ca8e3cb3e3bca497733347a789ca3a
 *
 *  SLE15-SP4 and -SP5 commit:
 *  ee261e855e98319240dc4cea4621aa7a5aa0bd8a
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


/* klp-ccp: from mm/mempolicy.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mempolicy.h>

/* klp-ccp: from include/linux/mempolicy.h */
#ifdef CONFIG_NUMA

void (*klpe___mpol_put)(struct mempolicy *pol);
static inline void klpr_mpol_put(struct mempolicy *pol)
{
	if (pol)
		(*klpe___mpol_put)(pol);
}

struct mempolicy *(*klpe___mpol_dup)(struct mempolicy *pol);
static inline struct mempolicy *klpr_mpol_dup(struct mempolicy *pol)
{
	if (pol)
		pol = (*klpe___mpol_dup)(pol);
	return pol;
}

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_NUMA */

/* klp-ccp: from mm/mempolicy.c */
#include <linux/mm.h>
#include <linux/highmem.h>

/* klp-ccp: from arch/x86/include/asm/tlbflush.h */
#define _ASM_X86_TLBFLUSH_H

/* klp-ccp: from mm/mempolicy.c */
#include <linux/kernel.h>
#include <linux/sched.h>

#include <linux/nodemask.h>

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/nsproxy.h>

#include <linux/init.h>

#include <linux/swap.h>
#include <linux/seq_file.h>

/* klp-ccp: from include/linux/rmap.h */
#define _LINUX_RMAP_H

/* klp-ccp: from mm/mempolicy.c */
#include <linux/rmap.h>

#include <linux/printk.h>

#include <asm/tlbflush.h>
#include <linux/uaccess.h>

/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

/* klp-ccp: from mm/mempolicy.c */
static struct kmem_cache *(*klpe_policy_cache);
static struct kmem_cache *(*klpe_sn_cache);

void (*klpe___mpol_put)(struct mempolicy *p);

struct mempolicy *(*klpe___mpol_dup)(struct mempolicy *old);

static struct sp_node *
sp_lookup(struct shared_policy *sp, unsigned long start, unsigned long end)
{
	struct rb_node *n = sp->root.rb_node;

	while (n) {
		struct sp_node *p = rb_entry(n, struct sp_node, nd);

		if (start >= p->end)
			n = n->rb_right;
		else if (end <= p->start)
			n = n->rb_left;
		else
			break;
	}
	if (!n)
		return NULL;
	for (;;) {
		struct sp_node *w = NULL;
		struct rb_node *prev = rb_prev(n);
		if (!prev)
			break;
		w = rb_entry(prev, struct sp_node, nd);
		if (w->end <= start)
			break;
		n = prev;
	}
	return rb_entry(n, struct sp_node, nd);
}

static void (*klpe_sp_insert)(struct shared_policy *sp, struct sp_node *new);

static void (*klpe_sp_free)(struct sp_node *n);

static void (*klpe_sp_delete)(struct shared_policy *sp, struct sp_node *n);

static void sp_node_init(struct sp_node *node, unsigned long start,
			unsigned long end, struct mempolicy *pol)
{
	node->start = start;
	node->end = end;
	node->policy = pol;
}

static struct sp_node *klpr_sp_alloc(unsigned long start, unsigned long end,
				struct mempolicy *pol)
{
	struct sp_node *n;
	struct mempolicy *newpol;

	n = kmem_cache_alloc((*klpe_sn_cache), GFP_KERNEL);
	if (!n)
		return NULL;

	newpol = klpr_mpol_dup(pol);
	if (IS_ERR(newpol)) {
		kmem_cache_free((*klpe_sn_cache), n);
		return NULL;
	}
	newpol->flags |= MPOL_F_SHARED;
	sp_node_init(n, start, end, newpol);

	return n;
}

static int klpp_shared_policy_replace(struct shared_policy *sp, unsigned long start,
				 unsigned long end, struct sp_node *new)
{
	struct sp_node *n;
	struct sp_node *n_new = NULL;
	struct mempolicy *mpol_new = NULL;
	int ret = 0;

restart:
	write_lock(&sp->lock);
	n = sp_lookup(sp, start, end);
	/* Take care of old policies in the same range. */
	while (n && n->start < end) {
		struct rb_node *next = rb_next(&n->nd);
		if (n->start >= start) {
			if (n->end <= end)
				(*klpe_sp_delete)(sp, n);
			else
				n->start = end;
		} else {
			/* Old policy spanning whole new range. */
			if (n->end > end) {
				if (!n_new)
					goto alloc_new;

				*mpol_new = *n->policy;
				atomic_set(&mpol_new->refcnt, 1);
				sp_node_init(n_new, end, n->end, mpol_new);
				n->end = start;
				(*klpe_sp_insert)(sp, n_new);
				n_new = NULL;
				mpol_new = NULL;
				break;
			} else
				n->end = start;
		}
		if (!next)
			break;
		n = rb_entry(next, struct sp_node, nd);
	}
	if (new)
		(*klpe_sp_insert)(sp, new);
	write_unlock(&sp->lock);
	ret = 0;

err_out:
	if (mpol_new)
		klpr_mpol_put(mpol_new);
	if (n_new)
		kmem_cache_free((*klpe_sn_cache), n_new);

	return ret;

alloc_new:
	write_unlock(&sp->lock);
	ret = -ENOMEM;
	n_new = kmem_cache_alloc((*klpe_sn_cache), GFP_KERNEL);
	if (!n_new)
		goto err_out;
	mpol_new = kmem_cache_alloc((*klpe_policy_cache), GFP_KERNEL);
	if (!mpol_new)
		goto err_out;
	atomic_set(&mpol_new->refcnt, 1);
	goto restart;
}

int klpp_mpol_set_shared_policy(struct shared_policy *info,
			struct vm_area_struct *vma, struct mempolicy *npol)
{
	int err;
	struct sp_node *new = NULL;
	unsigned long sz = vma_pages(vma);

	pr_debug("set_shared_policy %lx sz %lu %d %d %lx\n",
		 vma->vm_pgoff,
		 sz, npol ? npol->mode : -1,
		 npol ? npol->flags : -1,
		 npol ? nodes_addr(npol->v.nodes)[0] : NUMA_NO_NODE);

	if (npol) {
		new = klpr_sp_alloc(vma->vm_pgoff, vma->vm_pgoff + sz, npol);
		if (!new)
			return -ENOMEM;
	}
	err = klpp_shared_policy_replace(info, vma->vm_pgoff, vma->vm_pgoff+sz, new);
	if (err && new)
		(*klpe_sp_free)(new);
	return err;
}


#include "livepatch_bsc1238324.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__mpol_dup", (void *)&klpe___mpol_dup },
	{ "__mpol_put", (void *)&klpe___mpol_put },
	{ "policy_cache", (void *)&klpe_policy_cache },
	{ "sn_cache", (void *)&klpe_sn_cache },
	{ "sp_delete", (void *)&klpe_sp_delete },
	{ "sp_free", (void *)&klpe_sp_free },
	{ "sp_insert", (void *)&klpe_sp_insert },
};

int livepatch_bsc1238324_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

