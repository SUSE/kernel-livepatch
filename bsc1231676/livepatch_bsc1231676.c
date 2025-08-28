/*
 * livepatch_bsc1231676
 *
 * Fix for CVE-2024-47674, bsc#1231676
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


/* klp-ccp: from mm/memory.c */
#include <linux/kernel_stat.h>
#include <linux/mm.h>


#ifdef __HAVE_PFNMAP_TRACKING

static int (*klpe_track_pfn_remap)(struct vm_area_struct *vma, pgprot_t *prot,
			   unsigned long pfn, unsigned long addr,
			   unsigned long size);

static void (*klpe_untrack_pfn)(struct vm_area_struct *vma, unsigned long pfn,
			unsigned long size);


#define untrack_pfn (*klpe_untrack_pfn)
#define track_pfn_remap (*klpe_track_pfn_remap)

#else

/* The next two functions are different for not x86_64 archs, thus included
 * here manually from "asm-generic/pgtable.h"
*/

static inline int klpr_track_pfn_remap(struct vm_area_struct *vma, pgprot_t *prot,
				  unsigned long pfn, unsigned long addr,
				  unsigned long size)
{
	return 0;
}

static inline void klpr_untrack_pfn(struct vm_area_struct *vma,
			       unsigned long pfn, unsigned long size)
{
}

#define track_pfn_remap klpr_track_pfn_remap
#define untrack_pfn klpr_untrack_pfn

#endif

#ifdef __HAVE_ARCH_PFN_MODIFY_ALLOWED

static bool (*klpe_pfn_modify_allowed)(unsigned long pfn, pgprot_t prot);
#define pfn_modify_allowed (*klpe_pfn_modify_allowed)

#else

static inline bool klpr_pfn_modify_allowed(unsigned long pfn, pgprot_t prot)
{
	return true;
}

#define pfn_modify_allowed klpr_pfn_modify_allowed

#endif /* !_HAVE_ARCH_PFN_MODIFY_ALLOWED */

#if defined(CONFIG_S390)

/* In s390 arch, the set_pte_at function included from <asm/pgtable.h>, uses
 * the function ptep_set_pte_at defined in arch/s390/mm/pagetable.c, such
 * function is not exported to modules, hence resolve it through livepatching
 * externalization.
 */

static void (*klpe_ptep_set_pte_at)(struct mm_struct *mm, unsigned long addr, pte_t
			     *ptep, pte_t entry);

static inline void klpr_set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t entry)
{
	if (pte_present(entry))
		pte_val(entry) &= ~_PAGE_UNUSED;
	if (mm_has_pgste(mm))
		(*klpe_ptep_set_pte_at)(mm, addr, ptep, entry);
	else
		*ptep = entry;
}

#define set_pte_at klpr_set_pte_at
#endif /* CONFIG_S390 */

#if defined(CONFIG_PPC64)

 /* The symbols __flush_tlb_pending and ppc64_tlb_batch used by
  * arch_enter_lazy_mmu_mode and arch_leave_lazy_mmu_mode need to be resolved
  * through livepatching externalization for ppc64le
  */

#include <linux/percpu.h>

static struct ppc64_tlb_batch __percpu (*klpe_ppc64_tlb_batch);

static inline void klpr_arch_enter_lazy_mmu_mode(void)
{
	struct ppc64_tlb_batch *batch;

	if (radix_enabled())
		return;
	batch = this_cpu_ptr(klpe_ppc64_tlb_batch);
	batch->active = 1;
}

static void (*klpe___flush_tlb_pending)(struct ppc64_tlb_batch *batch);
static inline void klpr_arch_leave_lazy_mmu_mode(void)
{
	struct ppc64_tlb_batch *batch;

	if (radix_enabled())
		return;
	batch = this_cpu_ptr(klpe_ppc64_tlb_batch);

	if (batch->index)
		(*klpe___flush_tlb_pending)(batch);
	batch->active = 0;
}

#define arch_enter_lazy_mmu_mode klpr_arch_enter_lazy_mmu_mode
#define arch_leave_lazy_mmu_mode klpr_arch_leave_lazy_mmu_mode

/* pmd_page seems to be implemented as macro for the other archs but not for
 * ppc64le, thus it results in the symbol needing to be externalized. In
 * particular, this is used by pte_lockptr in the macro expanded in
 * klpr_remap_pte_range by klp-ccp. */

#if USE_SPLIT_PTE_PTLOCKS
static struct page *(*klpe_pmd_page)(pmd_t pmd);
static inline spinlock_t *klpr_pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr((*klpe_pmd_page)(*pmd));
}
#define pte_lockptr klpr_pte_lockptr
#endif /* USE_SPLIT_PTE_PTLOCKS */

/* Resolve  set_pte_at through externalization */
static void (*klpe_set_pte_at)(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
			pte_t pte);

#define set_pte_at (*klpe_set_pte_at)

#endif /* CONFIG_PPC64 */


/* klp-ccp: from include/linux/mm.h */
#ifdef __PAGETABLE_PUD_FOLDED
#error "klp-ccp: non-taken branch"
#else
static int (*klpe___pud_alloc)(struct mm_struct *mm, p4d_t *p4d, unsigned long address);
#endif

#if defined(__PAGETABLE_PMD_FOLDED) || !defined(CONFIG_MMU)
#error "klp-ccp: non-taken branch"
#else
static int (*klpe___pmd_alloc)(struct mm_struct *mm, pud_t *pud, unsigned long address);

#endif

static int (*klpe___pte_alloc)(struct mm_struct *mm, pmd_t *pmd, unsigned long address);

#if defined(CONFIG_MMU) && !defined(__ARCH_HAS_4LEVEL_HACK)

#ifndef __ARCH_HAS_5LEVEL_HACK

static inline pud_t *klpr_pud_alloc(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && (*klpe___pud_alloc)(mm, p4d, address)) ?
		NULL : pud_offset(p4d, address);
}
#else

/* manually included from "asm-generic/5level-fixup.h" */

#define klpr_pud_alloc(mm, p4d, address) \
	((unlikely(pgd_none(*(p4d))) && (*klpe___pud_alloc)(mm, p4d, address)) ? \
		NULL : pud_offset(p4d, address))

#undef  p4d_addr_end
#define p4d_addr_end(addr, end)		(end)

#endif /* !__ARCH_HAS_5LEVEL_HACK */

static inline pmd_t *klpr_pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && (*klpe___pmd_alloc)(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_MMU && !__ARCH_HAS_4LEVEL_HACK */

int klpp_remap_pfn_range(struct vm_area_struct *, unsigned long addr,
			unsigned long pfn, unsigned long size, pgprot_t);

/* klp-ccp: from mm/memory.c */
#include <linux/sched/coredump.h>

/* klp-ccp: from include/linux/dax.h */
#define _LINUX_DAX_H

/* klp-ccp: from include/linux/pagemap.h */
#define _LINUX_PAGEMAP_H

/* klp-ccp: from include/linux/highmem.h */
#define _LINUX_HIGHMEM_H

/* klp-ccp: from include/linux/uaccess.h */
#define __LINUX_UACCESS_H__

/* klp-ccp: from include/asm-generic/cacheflush.h */
#define flush_cache_range(vma, start, end)	do { } while (0)

/* klp-ccp: from include/linux/swap.h */
#define _LINUX_SWAP_H

/* klp-ccp: from include/linux/memcontrol.h */
#define _LINUX_MEMCONTROL_H

/* klp-ccp: from include/linux/writeback.h */
#define WRITEBACK_H

/* klp-ccp: from arch/x86/include/asm/tlbflush.h */
#define _ASM_X86_TLBFLUSH_H

/* klp-ccp: from mm/memory.c */
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>

/* klp-ccp: from include/linux/rmap.h */
#define _LINUX_RMAP_H

/* klp-ccp: from mm/memory.c */
#include <linux/rmap.h>
#include <linux/export.h>

#include <linux/init.h>

#include <linux/writeback.h>
#include <linux/memcontrol.h>

#include <linux/gfp.h>

#include <linux/string.h>

#include <linux/dax.h>

#include <linux/numa.h>

#include <asm/io.h>

/* klp-ccp: from arch/x86/include/asm/pgalloc.h */
#define _ASM_X86_PGALLOC_H

/* klp-ccp: from mm/memory.c */
#include <asm/pgalloc.h>
#include <linux/uaccess.h>

#include <asm/tlbflush.h>
#include <asm/pgtable.h>

/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

static inline bool is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

static void (*klpe_zap_page_range_single)(struct vm_area_struct *vma, unsigned long address,
		unsigned long size, struct zap_details *details);

static int klpr_remap_pte_range(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pte_t *pte;
	spinlock_t *ptl;
	int err = 0;

	pte = ((__builtin_expect(!!(pmd_none(*(pmd))), 0) &&
		(*klpe___pte_alloc)(mm, pmd, addr)) ? ((void *)0) : ({
			spinlock_t *__ptl = pte_lockptr(mm, pmd); pte_t *__pte
				= pte_offset_kernel((pmd), (addr)); *(&ptl) =
				__ptl; spin_lock(__ptl); __pte; }));
	if (!pte)
		return -ENOMEM;
	arch_enter_lazy_mmu_mode();
	do {
		BUG_ON(!pte_none(*pte));
		if (!pfn_modify_allowed(pfn, prot)) {
			err = -EACCES;
			break;
		}
		set_pte_at(mm, addr, pte, pte_mkspecial(pfn_pte(pfn, prot)));
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);
	return err;
}

static inline int klpr_remap_pmd_range(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	pmd = klpr_pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		err = klpr_remap_pte_range(mm, pmd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int klpr_remap_pud_range(struct mm_struct *mm, p4d_t *p4d,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	pud = klpr_pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		err = klpr_remap_pmd_range(mm, pud, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static inline int klpr_remap_p4d_range(struct mm_struct *mm, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	p4d_t *p4d;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		err = klpr_remap_pud_range(mm, p4d, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

int klpp_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long pfn, unsigned long size, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long start = addr;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	unsigned long remap_pfn = pfn;
	int err;

	/*
	 * Physically remapped pages are special. Tell the
	 * rest of the world about it:
	 *   VM_IO tells people not to look at these pages
	 *	(accesses can have side effects).
	 *   VM_PFNMAP tells the core MM that the base pages are just
	 *	raw PFN mappings, and do not have a "struct page" associated
	 *	with them.
	 *   VM_DONTEXPAND
	 *      Disable vma merging and expanding with mremap().
	 *   VM_DONTDUMP
	 *      Omit vma from core dump, even when VM_IO turned off.
	 *
	 * There's a horrible special case to handle copy-on-write
	 * behaviour that some programs depend on. We mark the "original"
	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
	 * See vm_normal_page() for details.
	 */
	if (is_cow_mapping(vma->vm_flags)) {
		if (addr != vma->vm_start || end != vma->vm_end)
			return -EINVAL;
		vma->vm_pgoff = pfn;
	}

	err = track_pfn_remap(vma, &prot, remap_pfn, addr, PAGE_ALIGN(size));
	if (err)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;

	BUG_ON(addr >= end);
	pfn -= addr >> PAGE_SHIFT;
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		err = klpr_remap_p4d_range(mm, pgd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	if (err) {
		/*
		 * A partial pfn range mapping is dangerous: it does not
		 * maintain page reference counts, and callers may free
		 * pages due to the error. So zap it early.
		 */
		(*klpe_zap_page_range_single)(vma, start, size, NULL);
		untrack_pfn(vma, remap_pfn, PAGE_ALIGN(size));
	}

	return err;
}

typeof(klpp_remap_pfn_range) klpp_remap_pfn_range;

#ifndef __PAGETABLE_PUD_FOLDED

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __PAGETABLE_PUD_FOLDED */

#ifndef __PAGETABLE_PMD_FOLDED

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __PAGETABLE_PMD_FOLDED */


#include "livepatch_bsc1231676.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__pmd_alloc", (void *)&klpe___pmd_alloc },
	{ "__pte_alloc", (void *)&klpe___pte_alloc },
	{ "__pud_alloc", (void *)&klpe___pud_alloc },
	{ "zap_page_range_single", (void *)&klpe_zap_page_range_single },
#ifdef __HAVE_ARCH_PFN_MODIFY_ALLOWED
	{ "pfn_modify_allowed", (void *)&klpe_pfn_modify_allowed },
#endif
#ifdef __HAVE_PFNMAP_TRACKING
	{ "track_pfn_remap", (void *)&klpe_track_pfn_remap },
	{ "untrack_pfn", (void *)&klpe_untrack_pfn },
#endif
#if defined(CONFIG_S390)
	{ "ptep_set_pte_at", (void *)&klpe_ptep_set_pte_at },
#endif
#if defined(CONFIG_PPC64)
	{ "__flush_tlb_pending", (void *)&klpe___flush_tlb_pending },
	{ "pmd_page", (void *)&klpe_pmd_page },
	{ "ppc64_tlb_batch", (void *)&klpe_ppc64_tlb_batch },
	{ "set_pte_at", (void *)&klpe_set_pte_at },
#endif
};

int livepatch_bsc1231676_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

