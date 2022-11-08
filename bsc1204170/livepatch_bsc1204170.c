/*
 * livepatch_bsc1204170
 *
 * Fix for CVE-2022-42703, bsc#1204170
 *
 *  Upstream commit:
 *  2555283eb40d ("mm/rmap: Fix anon_vma->degree ambiguity leading to
 *                 double-reuse")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  9b7937227f3f0c60964eee3b8cc6406b04d9c0f1
 *
 *  SLE15-SP2 and -SP3 commit:
 *  cfac9ee563facaab2b63d66d59f0f5280cbba419
 *
 *  SLE15-SP4 commit:
 *  513d1e1c9a97d44a01791f1bf527387df824c716
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

/* klp-ccp: from mm/rmap.c */
#include <linux/mm.h>

/* klp-ccp: from include/linux/mm.h */
static void (*klpe_anon_vma_interval_tree_insert)(struct anon_vma_chain *node,
				   struct rb_root *root);

/* klp-ccp: from mm/rmap.c */
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/ksm.h>

/* klp-ccp: from include/linux/rmap.h */
static void (*klpe_unlink_anon_vmas)(struct vm_area_struct *);
int klpp_anon_vma_clone(struct vm_area_struct *, struct vm_area_struct *);

/* klp-ccp: from mm/rmap.c */
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/memcontrol.h>
#include <linux/hugetlb.h>
#include <linux/memremap.h>
#include <asm/tlbflush.h>
/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

/* klp-ccp: from mm/rmap.c */
static struct kmem_cache *(*klpe_anon_vma_chain_cachep);

static inline struct anon_vma_chain *klpr_anon_vma_chain_alloc(gfp_t gfp)
{
	return kmem_cache_alloc((*klpe_anon_vma_chain_cachep), gfp);
}

static void klpr_anon_vma_chain_link(struct vm_area_struct *vma,
				struct anon_vma_chain *avc,
				struct anon_vma *anon_vma)
{
	avc->vma = vma;
	avc->anon_vma = anon_vma;
	list_add(&avc->same_vma, &vma->anon_vma_chain);
	(*klpe_anon_vma_interval_tree_insert)(avc, &anon_vma->rb_root);
}

static inline struct anon_vma *lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
	struct anon_vma *new_root = anon_vma->root;
	if (new_root != root) {
		if (WARN_ON_ONCE(root))
			up_write(&root->rwsem);
		root = new_root;
		down_write(&root->rwsem);
	}
	return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
	if (root)
		up_write(&root->rwsem);
}

int klpp_anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	struct anon_vma_chain *avc, *pavc;
	struct anon_vma *root = NULL;

	list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma;

		avc = klpr_anon_vma_chain_alloc(GFP_NOWAIT | __GFP_NOWARN);
		if (unlikely(!avc)) {
			unlock_anon_vma_root(root);
			root = NULL;
			avc = klpr_anon_vma_chain_alloc(GFP_KERNEL);
			if (!avc)
				goto enomem_failure;
		}
		anon_vma = pavc->anon_vma;
		root = lock_anon_vma_root(root, anon_vma);
		klpr_anon_vma_chain_link(dst, avc, anon_vma);

		/*
		 * Reuse existing anon_vma if its degree lower than two,
		 * that means it has no vma and only one anon_vma child.
		 *
		 * Do not chose parent anon_vma, otherwise first child
		 * will always reuse it. Root anon_vma is never reused:
		 * it has self-parent reference and at least one child.
		 */
		/*
		 * Fix CVE-2022-42703
		 *  -3 lines, +12 lines
		 */
		if (!dst->anon_vma && src->anon_vma) {
			if (anon_vma->degree == 0 &&
			    !WARN_ON_ONCE(anon_vma == src->anon_vma)) {
				dst->anon_vma = anon_vma;
			} else {
				anon_vma = anon_vma->parent;
				if (anon_vma && anon_vma->degree < 2 &&
				    !WARN_ON_ONCE(anon_vma == src->anon_vma)) {
					dst->anon_vma = anon_vma;
				}
			}
		}
	}
	if (dst->anon_vma)
		dst->anon_vma->degree++;
	unlock_anon_vma_root(root);
	return 0;

 enomem_failure:
	/*
	 * dst->anon_vma is dropped here otherwise its degree can be incorrectly
	 * decremented in unlink_anon_vmas().
	 * We can safely do this because callers of anon_vma_clone() don't care
	 * about dst->anon_vma if anon_vma_clone() failed.
	 */
	dst->anon_vma = NULL;
	(*klpe_unlink_anon_vmas)(dst);
	return -ENOMEM;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1204170.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "anon_vma_chain_cachep", (void *)&klpe_anon_vma_chain_cachep },
	{ "anon_vma_interval_tree_insert",
	  (void *)&klpe_anon_vma_interval_tree_insert },
	{ "unlink_anon_vmas", (void *)&klpe_unlink_anon_vmas },
};

int livepatch_bsc1204170_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
