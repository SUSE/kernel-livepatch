/*
 * livepatch_bsc1179646
 *
 * Fix for CVE-2020-29369, bsc#1179646
 *
 *  Upstream commit:
 *  246c320a8cfe ("mm/mmap.c: close race between munmap() and
 *                 expand_upwards()/downwards()")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  not affected
 *
 *  SLE15-SP2 commit:
 *  8d322cd9c3b5c37c54dafea6ebc6e7dcabc3b0c1
 *
 *
 *  Copyright (c) 2020 SUSE
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

#include <linux/types.h>
#include "livepatch_bsc1179646.h"

/* klp-ccp: from mm/mmap.c */
#define pr_fmt(fmt) "mmap" ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>

/* klp-ccp: from include/linux/mm.h */
static int (*klpe_sysctl_max_map_count);

static int (*klpe___split_vma)(struct mm_struct *, struct vm_area_struct *,
	unsigned long addr, int new_below);

static void (*klpe_vm_stat_account)(struct mm_struct *, vm_flags_t, long npages);

static unsigned long (*klpe_stack_guard_gap);

static inline unsigned long klpr_vm_start_gap(struct vm_area_struct *vma)
{
	unsigned long vm_start = vma->vm_start;

	if (vma->vm_flags & VM_GROWSDOWN) {
		vm_start -= (*klpe_stack_guard_gap);
		if (vm_start > vma->vm_start)
			vm_start = 0;
	}
	return vm_start;
}

static inline unsigned long klpr_vm_end_gap(struct vm_area_struct *vma)
{
	unsigned long vm_end = vma->vm_end;

	if (vma->vm_flags & VM_GROWSUP) {
		vm_end += (*klpe_stack_guard_gap);
		if (vm_end < vma->vm_end)
			vm_end = -PAGE_SIZE;
	}
	return vm_end;
}

/* klp-ccp: from mm/mmap.c */
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/shm.h>

/* klp-ccp: from include/linux/mman.h */
static struct percpu_counter (*klpe_vm_committed_as);

#ifdef CONFIG_SMP
static s32 (*klpe_vm_committed_as_batch);
#else
#error "klp-ccp: non-taken branch"
#endif

static inline void klpr_vm_acct_memory(long pages)
{
	percpu_counter_add_batch(&(*klpe_vm_committed_as), pages, (*klpe_vm_committed_as_batch));
}

static inline void klpr_vm_unacct_memory(long pages)
{
	klpr_vm_acct_memory(-pages);
}

/* klp-ccp: from mm/mmap.c */
#include <linux/pagemap.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/export.h>
#include <linux/mempolicy.h>
#include <linux/mmdebug.h>
#include <linux/perf_event.h>
#include <linux/uprobes.h>
#include <linux/rbtree_augmented.h>
#include <linux/notifier.h>
#include <linux/printk.h>

/* klp-ccp: from include/linux/userfaultfd_k.h */
#ifdef CONFIG_USERFAULTFD

static int (*klpe_userfaultfd_unmap_prep)(struct vm_area_struct *vma,
				  unsigned long start, unsigned long end,
				  struct list_head *uf);

#else /* CONFIG_USERFAULTFD */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_USERFAULTFD */

/* klp-ccp: from mm/mmap.c */
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>

#if defined(CONFIG_X86_64)

/* klp-ccp: from arch/x86/include/asm/mpx.h */
#ifdef CONFIG_X86_INTEL_MPX

static void (*klpe_mpx_notify_unmap)(struct mm_struct *mm, unsigned long start, unsigned long end);

#endif /* CONFIG_X86_INTEL_MPX */

/* klp-ccp: from arch/x86/include/asm/mmu_context.h */
static inline void klpr_arch_unmap(struct mm_struct *mm, unsigned long start,
			      unsigned long end)
{
	/*
	 * mpx_notify_unmap() goes and reads a rarely-hot
	 * cacheline in the mm_struct.  That can be expensive
	 * enough to be seen in profiles.
	 *
	 * The mpx_notify_unmap() call and its contents have been
	 * observed to affect munmap() performance on hardware
	 * where MPX is not present.
	 *
	 * The unlikely() optimizes for the fast case: no MPX
	 * in the CPU, or no MPX use in the process.  Even if
	 * we get this wrong (in the unlikely event that MPX
	 * is widely enabled on some system) the overhead of
	 * MPX itself (reading bounds tables) is expected to
	 * overwhelm the overhead of getting this unlikely()
	 * consistently wrong.
	 */
	if (unlikely(cpu_feature_enabled(X86_FEATURE_MPX)))
		(*klpe_mpx_notify_unmap)(mm, start, end);
}

#elif defined(CONFIG_PPC)

/* klp-ccp: from arch/powerpc/include/asm/mmu_context.h */
#include <asm/mmu_context.h>

#define klpr_arch_unmap arch_unmap

#elif defined (CONFIG_S390)

#define klpr_arch_unmap arch_unmap

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

#ifdef CONFIG_MMU

static void (*klpe_munlock_vma_pages_range)(struct vm_area_struct *vma,
			unsigned long start, unsigned long end);
static inline void klpr_munlock_vma_pages_all(struct vm_area_struct *vma)
{
	(*klpe_munlock_vma_pages_range)(vma, vma->vm_start, vma->vm_end);
}

#else /* !CONFIG_MMU */
#error "klp-ccp: non-taken branch"
#endif /* !CONFIG_MMU */

/* klp-ccp: from mm/mmap.c */
static void (*klpe_unmap_region)(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end);

static struct vm_area_struct *(*klpe_remove_vma)(struct vm_area_struct *vma);

static inline unsigned long klpr_vma_compute_gap(struct vm_area_struct *vma)
{
	unsigned long gap, prev_end;

	/*
	 * Note: in the rare case of a VM_GROWSDOWN above a VM_GROWSUP, we
	 * allow two stack_guard_gaps between them here, and when choosing
	 * an unmapped area; whereas when expanding we only require one.
	 * That's a little inconsistent, but keeps the code here simpler.
	 */
	gap = klpr_vm_start_gap(vma);
	if (vma->vm_prev) {
		prev_end = klpr_vm_end_gap(vma->vm_prev);
		if (gap > prev_end)
			gap -= prev_end;
		else
			gap = 0;
	}
	return gap;
}

#define validate_mm_rb(root, ignore) do { } while (0)
#define validate_mm(mm) do { } while (0)

/* klp-ccp: from mm/mmap.c */
RB_DECLARE_CALLBACKS_MAX(static, klpr_vma_gap_callbacks,
			 struct vm_area_struct, vm_rb,
			 unsigned long, rb_subtree_gap, klpr_vma_compute_gap)

static void klpr_vma_gap_update(struct vm_area_struct *vma)
{
	/*
	 * As it turns out, RB_DECLARE_CALLBACKS_MAX() already created
	 * a callback function that does exactly what we want.
	 */
	klpr_vma_gap_callbacks_propagate(&vma->vm_rb, NULL);
}

static void (*klpe___vma_rb_erase)(struct vm_area_struct *vma, struct rb_root *root);

static __always_inline void klpr_vma_rb_erase(struct vm_area_struct *vma,
					 struct rb_root *root)
{
	/*
	 * All rb_subtree_gap values must be consistent prior to erase,
	 * with the possible exception of the vma being erased.
	 */
	validate_mm_rb(root, vma);

	(*klpe___vma_rb_erase)(vma, root);
}

static void klpr_remove_vma_list(struct mm_struct *mm, struct vm_area_struct *vma)
{
	unsigned long nr_accounted = 0;

	/* Update high watermark before we lower total_vm */
	update_hiwater_vm(mm);
	do {
		long nrpages = vma_pages(vma);

		if (vma->vm_flags & VM_ACCOUNT)
			nr_accounted += nrpages;
		(*klpe_vm_stat_account)(mm, vma->vm_flags, -nrpages);
		vma = (*klpe_remove_vma)(vma);
	} while (vma);
	klpr_vm_unacct_memory(nr_accounted);
	validate_mm(mm);
}

static void (*klpe_unmap_region)(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end);

/*
 * Fix CVE-2020-29369
 *  -1 line, +1 line
 */
static bool
klpp_detach_vmas_to_be_unmapped(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, unsigned long end)
{
	struct vm_area_struct **insertion_point;
	struct vm_area_struct *tail_vma = NULL;

	insertion_point = (prev ? &prev->vm_next : &mm->mmap);
	vma->vm_prev = NULL;
	do {
		klpr_vma_rb_erase(vma, &mm->mm_rb);
		mm->map_count--;
		tail_vma = vma;
		vma = vma->vm_next;
	} while (vma && vma->vm_start < end);
	*insertion_point = vma;
	if (vma) {
		vma->vm_prev = prev;
		klpr_vma_gap_update(vma);
	} else
		mm->highest_vm_end = prev ? klpr_vm_end_gap(prev) : 0;
	tail_vma->vm_next = NULL;

	/* Kill the cache */
	vmacache_invalidate(mm);

	/*
	 * Fix CVE-2020-29369
	 *  +10 lines
	 */
	/*
	 * Do not downgrade mmap_lock if we are next to VM_GROWSDOWN or
	 * VM_GROWSUP VMA. Such VMAs can change their size under
	 * down_read(mmap_lock) and collide with the VMA we are about to unmap.
	 */
	if (vma && (vma->vm_flags & VM_GROWSDOWN))
		return false;
	if (prev && (prev->vm_flags & VM_GROWSUP))
		return false;
	return true;
}

int klpp___do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
		struct list_head *uf, bool downgrade)
{
	unsigned long end;
	struct vm_area_struct *vma, *prev, *last;

	if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;

	len = PAGE_ALIGN(len);
	end = start + len;
	if (len == 0)
		return -EINVAL;

	/*
	 * arch_unmap() might do unmaps itself.  It must be called
	 * and finish any rbtree manipulation before this code
	 * runs and also starts to manipulate the rbtree.
	 */
	klpr_arch_unmap(mm, start, end);

	/* Find the first overlapping VMA */
	vma = find_vma(mm, start);
	if (!vma)
		return 0;
	prev = vma->vm_prev;
	/* we have  start < vma->vm_end  */

	/* if it doesn't overlap, we have nothing.. */
	if (vma->vm_start >= end)
		return 0;

	/*
	 * If we need to split any vma, do it now to save pain later.
	 *
	 * Note: mremap's move_vma VM_ACCOUNT handling assumes a partially
	 * unmapped vm_area_struct will remain in use: so lower split_vma
	 * places tmp vma above, and higher split_vma places tmp vma below.
	 */
	if (start > vma->vm_start) {
		int error;

		/*
		 * Make sure that map_count on return from munmap() will
		 * not exceed its limit; but let map_count go just above
		 * its limit temporarily, to help free resources as expected.
		 */
		if (end < vma->vm_end && mm->map_count >= (*klpe_sysctl_max_map_count))
			return -ENOMEM;

		error = (*klpe___split_vma)(mm, vma, start, 0);
		if (error)
			return error;
		prev = vma;
	}

	/* Does it split the last one? */
	last = find_vma(mm, end);
	if (last && end > last->vm_start) {
		int error = (*klpe___split_vma)(mm, last, end, 1);
		if (error)
			return error;
	}
	vma = prev ? prev->vm_next : mm->mmap;

	if (unlikely(uf)) {
		/*
		 * If userfaultfd_unmap_prep returns an error the vmas
		 * will remain splitted, but userland will get a
		 * highly unexpected error anyway. This is no
		 * different than the case where the first of the two
		 * __split_vma fails, but we don't undo the first
		 * split, despite we could. This is unlikely enough
		 * failure that it's not worth optimizing it for.
		 */
		int error = (*klpe_userfaultfd_unmap_prep)(vma, start, end, uf);
		if (error)
			return error;
	}

	/*
	 * unlock any mlock()ed ranges before detaching vmas
	 */
	if (mm->locked_vm) {
		struct vm_area_struct *tmp = vma;
		while (tmp && tmp->vm_start < end) {
			if (tmp->vm_flags & VM_LOCKED) {
				mm->locked_vm -= vma_pages(tmp);
				klpr_munlock_vma_pages_all(tmp);
			}

			tmp = tmp->vm_next;
		}
	}

	/* Detach vmas from rbtree */
	/*
	 * Fix CVE-2020-29369
	 *  -1 line, +2 lines
	 */
	if (!klpp_detach_vmas_to_be_unmapped(mm, vma, prev, end))
		downgrade = false;

	if (downgrade)
		downgrade_write(&mm->mmap_sem);

	(*klpe_unmap_region)(mm, vma, prev, start, end);

	/* Fix up all other VM information */
	klpr_remove_vma_list(mm, vma);

	return downgrade ? 1 : 0;
}



#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "stack_guard_gap", (void *)&klpe_stack_guard_gap },
	{ "vm_committed_as", (void *)&klpe_vm_committed_as },
	{ "vm_committed_as_batch", (void *)&klpe_vm_committed_as_batch },
	{ "sysctl_max_map_count", (void *)&klpe_sysctl_max_map_count },
	{ "__split_vma", (void *)&klpe___split_vma },
	{ "vm_stat_account", (void *)&klpe_vm_stat_account },
	{ "remove_vma", (void *)&klpe_remove_vma },
	{ "__vma_rb_erase", (void *)&klpe___vma_rb_erase },
	{ "userfaultfd_unmap_prep", (void *)&klpe_userfaultfd_unmap_prep },
	{ "munlock_vma_pages_range", (void *)&klpe_munlock_vma_pages_range },
	{ "unmap_region", (void *)&klpe_unmap_region },
#ifdef CONFIG_X86_INTEL_MPX
	{ "mpx_notify_unmap", (void *)&klpe_mpx_notify_unmap },
#endif
};

int livepatch_bsc1179646_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
