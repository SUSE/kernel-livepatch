/*
 * livepatch_bsc1179664
 *
 * Fix for CVE-2020-29368, bsc#1179664
 *
 *  Upstream commits:
 *  c444eb564fb1 ("mm: thp: make the THP mapcount atomic against
 *                 __split_huge_pmd_locked()")
 *  1c2f67308af4 ("mm: thp: fix MADV_REMOVE deadlock on shmem THP")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  To be determined, evaluation pending.
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  None yet.
 *
 *  SLE15-SP2 commits:
 *  842b18f53c6671062a6a8183a5f9e01842deb847
 *  9d15b367d1aad9257acf13e589b29b74a7b069f6
 *
 *
 *  Copyright (c) 2021 SUSE
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

/* klp-ccp: from mm/huge_memory.c */
#define pr_fmt(fmt) "huge_memory" ": " fmt

#include <linux/mm.h>

/* klp-ccp: from include/linux/gfp.h */
#ifdef CONFIG_NUMA

static struct page *(*klpe_alloc_pages_vma)(gfp_t gfp_mask, int order,
			struct vm_area_struct *vma, unsigned long addr,
			int node, bool hugepage);
#define klpr_alloc_hugepage_vma(gfp_mask, vma, addr, order)			\
	(*klpe_alloc_pages_vma)(gfp_mask, order, vma, addr, numa_node_id(), true)

#else
#error "klp-ccp: non-taken branch"
#endif

#define klpr_alloc_page_vma_node(gfp_mask, vma, addr, node)		\
	(*klpe_alloc_pages_vma)(gfp_mask, 0, vma, addr, node, false)

#if defined(CONFIG_X86_64)

#define klpr_set_pte_at set_pte_at

#elif defined(CONFIG_PPC_BOOK3S)

/* klp-ccp: from arch/powerpc/include/asm/book3s/pgtable.h */
static void (*klpe_set_pte_at)(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
		       pte_t pte);

#define klpr_set_pte_at (*klpe_set_pte_at)

#elif defined(CONFIG_S390)

/* klp-ccp: from arch/s390/include/asm/pgtable.h */
static void (*klpe_ptep_set_pte_at)(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t entry);

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

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif


#if defined(CONFIG_PPC_BOOK3S)

/* klp-ccp: from arch/powerpc/include/asm/book3s/64/pgtable.h */
struct page *(*klpe_pmd_page)(pmd_t pmd);
#define klpr_pmd_page (*klpe_pmd_page)

/* klp-ccp: from arch/powerpc/include/asm/book3s/64/pgalloc.h */
static void (*klpe_pte_fragment_free)(unsigned long *, int);

static inline void klpr_pte_free(struct mm_struct *mm, pgtable_t ptepage)
{
	(*klpe_pte_fragment_free)((unsigned long *)ptepage, 0);
}

#else
#define klpr_pmd_page pmd_page
#define klpr_pte_free pte_free
#endif

#if defined(CONFIG_X86_64)

/* klp-ccp: from arch/x86/include/asm/pgtable.h */
static int (*klpe_pmdp_set_access_flags)(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);

#define klpr_pmdp_set_access_flags (*klpe_pmdp_set_access_flags)

#elif defined(CONFIG_PPC_BOOK3S)

/* klp-ccp: from arch/powerpc/include/asm/book3s/64/pgtable.h */
static int (*klpe_pmdp_set_access_flags)(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);

#define klpr_pmdp_set_access_flags (*klpe_pmdp_set_access_flags)

#elif defined(CONFIG_S390)

#define klpr_pmdp_set_access_flags pmdp_set_access_flags

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from include/asm-generic/pgtable.h */
#ifndef __HAVE_ARCH_PMDP_HUGE_CLEAR_FLUSH
static pmd_t (*klpe_pmdp_huge_clear_flush)(struct vm_area_struct *vma,
			      unsigned long address,
			      pmd_t *pmdp);

#define klpr_pmdp_huge_clear_flush (*klpe_pmdp_huge_clear_flush)

#else
#define klpr_pmdp_huge_clear_flush pmdp_huge_clear_flush
#endif

#if !defined(__HAVE_ARCH_PGTABLE_WITHDRAW) || defined(CONFIG_S390)
static pgtable_t (*klpe_pgtable_trans_huge_withdraw)(struct mm_struct *mm, pmd_t *pmdp);

#define klpr_pgtable_trans_huge_withdraw (*klpe_pgtable_trans_huge_withdraw)

#elif defined(CONFIG_PPC_BOOK3S)

/* klp-ccp: from arch/powerpc/include/asm/book3s/64/pgtable.h */
static pgtable_t (*klpe_radix__pgtable_trans_huge_withdraw)(struct mm_struct *mm, pmd_t *pmdp);
static pgtable_t (*klpe_hash__pgtable_trans_huge_withdraw)(struct mm_struct *mm, pmd_t *pmdp);

static inline pgtable_t klpr_pgtable_trans_huge_withdraw(struct mm_struct *mm,
						    pmd_t *pmdp)
{
	if (radix_enabled())
		return (*klpe_radix__pgtable_trans_huge_withdraw)(mm, pmdp);
	return (*klpe_hash__pgtable_trans_huge_withdraw)(mm, pmdp);
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#if !defined(__HAVE_ARCH_PMDP_INVALIDATE) || defined(CONFIG_PPC_BOOK3S)
static void (*klpe_pmdp_invalidate)(struct vm_area_struct *vma, unsigned long address,
			    pmd_t *pmdp);

#define klpr_pmdp_invalidate (*klpe_pmdp_invalidate)

#elif defined(CONFIG_S390)

#define klpr_pmdp_invalidate pmdp_invalidate

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#if defined(CONFIG_PPC_BOOK3S)
/* klp-ccp: from arch/powerpc/include/asm/book3s/64/hash-64k.h */
static void (*klpe_hash__pmdp_huge_split_prepare)(struct vm_area_struct *vma,
				      unsigned long address, pmd_t *pmdp);


/* klp-ccp: from arch/powerpc/include/asm/book3s/64/pgtable.h */
static pmd_t (*klpe_mk_pmd)(struct page *page, pgprot_t pgprot);
#define klpr_mk_pmd (*klpe_mk_pmd)

static void (*klpe_set_pmd_at)(struct mm_struct *mm, unsigned long addr,
		       pmd_t *pmdp, pmd_t pmd);
#define klpr_set_pmd_at (*klpe_set_pmd_at)

static void (*klpe_update_mmu_cache_pmd)(struct vm_area_struct *vma, unsigned long addr,
				 pmd_t *pmd);
#define klpr_update_mmu_cache_pmd (*klpe_update_mmu_cache_pmd)

static inline void klpr_pmdp_huge_split_prepare(struct vm_area_struct *vma,
					   unsigned long address, pmd_t *pmdp)
{
	if (radix_enabled())
		return radix__pmdp_huge_split_prepare(vma, address, pmdp);
	return (*klpe_hash__pmdp_huge_split_prepare)(vma, address, pmdp);
}

/* klp-ccp: from arch/powerpc/include/asm/page.h */
static void (*klpe_copy_user_page)(void *to, void *from, unsigned long vaddr,
		struct page *p);

#else

#define klpr_mk_pmd mk_pmd
#define klpr_set_pmd_at set_pmd_at
#define klpr_update_mmu_cache_pmd update_mmu_cache_pmd
#define klpr_pmdp_huge_split_prepare pmdp_huge_split_prepare

#endif

/* klp-ccp: from include/linux/huge_mm.h */
int klpp_do_huge_pmd_wp_page(struct vm_fault *vmf, pmd_t orig_pmd);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static bool (*klpe_is_vma_temporary_stack)(struct vm_area_struct *vma);

static unsigned long (*klpe_transparent_hugepage_flags);

static inline bool klpr_transparent_hugepage_enabled(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_NOHUGEPAGE)
		return false;

	if ((*klpe_is_vma_temporary_stack)(vma))
		return false;

	if (test_bit(MMF_DISABLE_THP, &vma->vm_mm->flags))
		return false;

	if ((*klpe_transparent_hugepage_flags) & (1 << TRANSPARENT_HUGEPAGE_FLAG))
		return true;

	if (vma_is_dax(vma))
		return true;

	if ((*klpe_transparent_hugepage_flags) &
				(1 << TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG))
		return !!(vma->vm_flags & VM_HUGEPAGE);

	return false;
}

static void (*klpe_prep_transhuge_page)(struct page *page);

void klpp___split_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct page *page);

#define klpr_split_huge_pmd(__vma, __pmd, __address)				\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		if (pmd_trans_huge(*____pmd)				\
					|| pmd_devmap(*____pmd))	\
			klpp___split_huge_pmd(__vma, __pmd, __address,	\
						false, NULL);		\
	}  while (0)

static struct page *(*klpe_huge_zero_page);

static inline bool klpr_is_huge_zero_page(struct page *page)
{
	return READ_ONCE((*klpe_huge_zero_page)) == page;
}

static inline bool klpr_is_huge_zero_pmd(pmd_t pmd)
{
	return klpr_is_huge_zero_page(klpr_pmd_page(pmd));
}

#define klpr_mk_huge_pmd(page, prot) pmd_mkhuge(klpr_mk_pmd(page, prot))

#else /* CONFIG_TRANSPARENT_HUGEPAGE */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/* klp-ccp: from include/linux/mm.h */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE

static int (*klpe_page_trans_huge_mapcount)(struct page *page, int *total_mapcount);
#else
#error "klp-ccp: non-taken branch"
#endif

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_HUGETLBFS)
static void (*klpe_clear_huge_page)(struct page *page,
			    unsigned long addr_hint,
			    unsigned int pages_per_huge_page);
static void (*klpe_copy_user_huge_page)(struct page *dst, struct page *src,
				unsigned long addr, struct vm_area_struct *vma,
				unsigned int pages_per_huge_page);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_HUGETLBFS */

/* klp-ccp: from mm/huge_memory.c */
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/highmem.h>

#if defined (CONFIG_PPC_BOOK3S)
/* klp-ccp: from include/linux/highmem.h */
static inline void klpr_copy_user_highpage(struct page *to, struct page *from,
	unsigned long vaddr, struct vm_area_struct *vma)
{
	char *vfrom, *vto;

	vfrom = kmap_atomic(from);
	vto = kmap_atomic(to);
	(*klpe_copy_user_page)(vto, vfrom, vaddr, to);
	kunmap_atomic(vto);
	kunmap_atomic(vfrom);
}
#else
#define klpr_copy_user_highpage copy_user_highpage
#endif

/* klp-ccp: from mm/huge_memory.c */
#include <linux/hugetlb.h>

/* klp-ccp: from include/linux/memcontrol.h */
#ifdef CONFIG_MEMCG

static int (*klpe_mem_cgroup_try_charge)(struct page *page, struct mm_struct *mm,
			  gfp_t gfp_mask, struct mem_cgroup **memcgp,
			  bool compound);
static void (*klpe_mem_cgroup_commit_charge)(struct page *page, struct mem_cgroup *memcg,
			      bool lrucare, bool compound);
static void (*klpe_mem_cgroup_cancel_charge)(struct page *page, struct mem_cgroup *memcg,
		bool compound);

#else /* CONFIG_MEMCG */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_MEMCG */

/* klp-ccp: from include/linux/swap.h */
static void (*klpe_lru_cache_add_active_or_unevictable)(struct page *page,
						struct vm_area_struct *vma);

/* klp-ccp: from mm/huge_memory.c */
#include <linux/mmu_notifier.h>

/* klp-ccp: from include/linux/mmu_notifier.h */
#ifdef CONFIG_MMU_NOTIFIER
#define klpr_pmdp_huge_clear_flush_notify(__vma, __haddr, __pmd)		\
({									\
	unsigned long ___haddr = __haddr & HPAGE_PMD_MASK;		\
	struct mm_struct *___mm = (__vma)->vm_mm;			\
	pmd_t ___pmd;							\
									\
	___pmd = klpr_pmdp_huge_clear_flush(__vma, __haddr, __pmd);		\
	mmu_notifier_invalidate_range(___mm, ___haddr,			\
				      ___haddr + HPAGE_PMD_SIZE);	\
									\
	___pmd;								\
})

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from include/linux/rmap.h */
static void (*klpe_page_add_new_anon_rmap)(struct page *, struct vm_area_struct *,
		unsigned long, bool);

static void (*klpe_page_remove_rmap)(struct page *, bool);

/* klp-ccp: from mm/huge_memory.c */
#include <linux/swap.h>
#include <linux/shrinker.h>
#include <linux/swapops.h>
#include <linux/dax.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/numa.h>
#include <asm/tlb.h>
#include <asm/pgalloc.h>
/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

static void (*klpe_clear_page_mlock)(struct page *page);

static pmd_t (*klpe_maybe_pmd_mkwrite)(pmd_t pmd, struct vm_area_struct *vma);

#include "livepatch_bsc1179664.h"

/* klp-ccp: from mm/huge_memory.c */
static inline gfp_t klpr_alloc_hugepage_direct_gfpmask(struct vm_area_struct *vma)
{
	const bool vma_madvised = !!(vma->vm_flags & VM_HUGEPAGE);

	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &(*klpe_transparent_hugepage_flags)))
		return GFP_TRANSHUGE | (vma_madvised ? 0 : __GFP_NORETRY);
	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &(*klpe_transparent_hugepage_flags)))
		return GFP_TRANSHUGE_LIGHT | __GFP_KSWAPD_RECLAIM;
	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &(*klpe_transparent_hugepage_flags)))
		return GFP_TRANSHUGE_LIGHT | (vma_madvised ? __GFP_DIRECT_RECLAIM :
							     __GFP_KSWAPD_RECLAIM);
	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &(*klpe_transparent_hugepage_flags)))
		return GFP_TRANSHUGE_LIGHT | (vma_madvised ? __GFP_DIRECT_RECLAIM :
							     0);
	return GFP_TRANSHUGE_LIGHT;
}

static int klpr_do_huge_pmd_wp_page_fallback(struct vm_fault *vmf, pmd_t orig_pmd,
		struct page *page)
{
	struct vm_area_struct *vma = vmf->vma;
	unsigned long haddr = vmf->address & HPAGE_PMD_MASK;
	struct mem_cgroup *memcg;
	pgtable_t pgtable;
	pmd_t _pmd;
	int ret = 0, i;
	struct page **pages;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */

	pages = kmalloc(sizeof(struct page *) * HPAGE_PMD_NR,
			GFP_KERNEL);
	if (unlikely(!pages)) {
		ret |= VM_FAULT_OOM;
		goto out;
	}

	for (i = 0; i < HPAGE_PMD_NR; i++) {
		pages[i] = klpr_alloc_page_vma_node(GFP_HIGHUSER_MOVABLE, vma,
					       vmf->address, page_to_nid(page));
		if (unlikely(!pages[i] ||
			     (*klpe_mem_cgroup_try_charge)(pages[i], vma->vm_mm,
				     GFP_KERNEL, &memcg, false))) {
			if (pages[i])
				put_page(pages[i]);
			while (--i >= 0) {
				memcg = (void *)page_private(pages[i]);
				set_page_private(pages[i], 0);
				(*klpe_mem_cgroup_cancel_charge)(pages[i], memcg,
						false);
				put_page(pages[i]);
			}
			kfree(pages);
			ret |= VM_FAULT_OOM;
			goto out;
		}
		set_page_private(pages[i], (unsigned long)memcg);
	}

	for (i = 0; i < HPAGE_PMD_NR; i++) {
		klpr_copy_user_highpage(pages[i], page + i,
				   haddr + PAGE_SIZE * i, vma);
		__SetPageUptodate(pages[i]);
		cond_resched();
	}

	mmun_start = haddr;
	mmun_end   = haddr + HPAGE_PMD_SIZE;
	mmu_notifier_invalidate_range_start(vma->vm_mm, mmun_start, mmun_end);

	vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
	if (unlikely(!pmd_same(*vmf->pmd, orig_pmd)))
		goto out_free_pages;
	VM_BUG_ON_PAGE(!PageHead(page), page);

	klpr_pmdp_huge_clear_flush_notify(vma, haddr, vmf->pmd);
	/* leave pmd empty until pte is filled */

	pgtable = klpr_pgtable_trans_huge_withdraw(vma->vm_mm, vmf->pmd);
	pmd_populate(vma->vm_mm, &_pmd, pgtable);

	for (i = 0; i < HPAGE_PMD_NR; i++, haddr += PAGE_SIZE) {
		pte_t entry;
		entry = mk_pte(pages[i], vma->vm_page_prot);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		memcg = (void *)page_private(pages[i]);
		set_page_private(pages[i], 0);
		(*klpe_page_add_new_anon_rmap)(pages[i], vmf->vma, haddr, false);
		(*klpe_mem_cgroup_commit_charge)(pages[i], memcg, false, false);
		(*klpe_lru_cache_add_active_or_unevictable)(pages[i], vma);
		vmf->pte = pte_offset_map(&_pmd, haddr);
		VM_BUG_ON(!pte_none(*vmf->pte));
		klpr_set_pte_at(vma->vm_mm, haddr, vmf->pte, entry);
		pte_unmap(vmf->pte);
	}
	kfree(pages);

	smp_wmb(); /* make pte visible before pmd */
	pmd_populate(vma->vm_mm, vmf->pmd, pgtable);
	(*klpe_page_remove_rmap)(page, true);
	spin_unlock(vmf->ptl);

	mmu_notifier_invalidate_range_end(vma->vm_mm, mmun_start, mmun_end);

	ret |= VM_FAULT_WRITE;
	put_page(page);

out:
	return ret;

out_free_pages:
	spin_unlock(vmf->ptl);
	mmu_notifier_invalidate_range_end(vma->vm_mm, mmun_start, mmun_end);
	for (i = 0; i < HPAGE_PMD_NR; i++) {
		memcg = (void *)page_private(pages[i]);
		set_page_private(pages[i], 0);
		(*klpe_mem_cgroup_cancel_charge)(pages[i], memcg, false);
		put_page(pages[i]);
	}
	kfree(pages);
	goto out;
}

int klpp_do_huge_pmd_wp_page(struct vm_fault *vmf, pmd_t orig_pmd)
{
	struct vm_area_struct *vma = vmf->vma;
	struct page *page = NULL, *new_page;
	struct mem_cgroup *memcg;
	unsigned long haddr = vmf->address & HPAGE_PMD_MASK;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */
	gfp_t huge_gfp;			/* for allocation and charge */
	int ret = 0;

	vmf->ptl = pmd_lockptr(vma->vm_mm, vmf->pmd);
	VM_BUG_ON_VMA(!vma->anon_vma, vma);
	if (klpr_is_huge_zero_pmd(orig_pmd))
		goto alloc;
	spin_lock(vmf->ptl);
	if (unlikely(!pmd_same(*vmf->pmd, orig_pmd)))
		goto out_unlock;

	page = klpr_pmd_page(orig_pmd);
	VM_BUG_ON_PAGE(!PageCompound(page) || !PageHead(page), page);
	/*
	 * We can only reuse the page if nobody else maps the huge page or it's
	 * part.
	 */
	/*
	 * Fix CVE-2020-29368
	 *  +12 lines
	 */
	if (!trylock_page(page)) {
		get_page(page);
		spin_unlock(vmf->ptl);
		lock_page(page);
		spin_lock(vmf->ptl);
		if (unlikely(!pmd_same(*vmf->pmd, orig_pmd))) {
			unlock_page(page);
			put_page(page);
			goto out_unlock;
		}
		put_page(page);
	}
	if ((*klpe_page_trans_huge_mapcount)(page, NULL) == 1) {
		pmd_t entry;
		entry = pmd_mkyoung(orig_pmd);
		entry = (*klpe_maybe_pmd_mkwrite)(pmd_mkdirty(entry), vma);
		if (klpr_pmdp_set_access_flags(vma, haddr, vmf->pmd, entry,  1))
			klpr_update_mmu_cache_pmd(vma, vmf->address, vmf->pmd);
		ret |= VM_FAULT_WRITE;
		/*
		 * Fix CVE-2020-29368
		 *  +1 line
		 */
		unlock_page(page);
		goto out_unlock;
	}
	/*
	 * Fix CVE-2020-29368
	 *  +1 line
	 */
	unlock_page(page);
	get_page(page);
	spin_unlock(vmf->ptl);
alloc:
	if (klpr_transparent_hugepage_enabled(vma) &&
	    !transparent_hugepage_debug_cow()) {
		huge_gfp = klpr_alloc_hugepage_direct_gfpmask(vma);
		new_page = klpr_alloc_hugepage_vma(huge_gfp, vma, haddr, HPAGE_PMD_ORDER);
	} else
		new_page = NULL;

	if (likely(new_page)) {
		(*klpe_prep_transhuge_page)(new_page);
	} else {
		if (!page) {
			klpr_split_huge_pmd(vma, vmf->pmd, vmf->address);
			ret |= VM_FAULT_FALLBACK;
		} else {
			ret = klpr_do_huge_pmd_wp_page_fallback(vmf, orig_pmd, page);
			if (ret & VM_FAULT_OOM) {
				klpr_split_huge_pmd(vma, vmf->pmd, vmf->address);
				ret |= VM_FAULT_FALLBACK;
			}
			put_page(page);
		}
		count_vm_event(THP_FAULT_FALLBACK);
		goto out;
	}

	if (unlikely((*klpe_mem_cgroup_try_charge)(new_page, vma->vm_mm,
					huge_gfp, &memcg, true))) {
		put_page(new_page);
		klpr_split_huge_pmd(vma, vmf->pmd, vmf->address);
		if (page)
			put_page(page);
		ret |= VM_FAULT_FALLBACK;
		count_vm_event(THP_FAULT_FALLBACK);
		goto out;
	}

	count_vm_event(THP_FAULT_ALLOC);

	if (!page)
		(*klpe_clear_huge_page)(new_page, vmf->address, HPAGE_PMD_NR);
	else
		(*klpe_copy_user_huge_page)(new_page, page, haddr, vma, HPAGE_PMD_NR);
	__SetPageUptodate(new_page);

	mmun_start = haddr;
	mmun_end   = haddr + HPAGE_PMD_SIZE;
	mmu_notifier_invalidate_range_start(vma->vm_mm, mmun_start, mmun_end);

	spin_lock(vmf->ptl);
	if (page)
		put_page(page);
	if (unlikely(!pmd_same(*vmf->pmd, orig_pmd))) {
		spin_unlock(vmf->ptl);
		(*klpe_mem_cgroup_cancel_charge)(new_page, memcg, true);
		put_page(new_page);
		goto out_mn;
	} else {
		pmd_t entry;
		entry = klpr_mk_huge_pmd(new_page, vma->vm_page_prot);
		entry = (*klpe_maybe_pmd_mkwrite)(pmd_mkdirty(entry), vma);
		klpr_pmdp_huge_clear_flush_notify(vma, haddr, vmf->pmd);
		(*klpe_page_add_new_anon_rmap)(new_page, vma, haddr, true);
		(*klpe_mem_cgroup_commit_charge)(new_page, memcg, false, true);
		(*klpe_lru_cache_add_active_or_unevictable)(new_page, vma);
		klpr_set_pmd_at(vma->vm_mm, haddr, vmf->pmd, entry);
		klpr_update_mmu_cache_pmd(vma, vmf->address, vmf->pmd);
		if (!page) {
			add_mm_counter(vma->vm_mm, MM_ANONPAGES, HPAGE_PMD_NR);
		} else {
			VM_BUG_ON_PAGE(!PageHead(page), page);
			(*klpe_page_remove_rmap)(page, true);
			put_page(page);
		}
		ret |= VM_FAULT_WRITE;
	}
	spin_unlock(vmf->ptl);
out_mn:
	mmu_notifier_invalidate_range_end(vma->vm_mm, mmun_start, mmun_end);
out:
	return ret;
out_unlock:
	spin_unlock(vmf->ptl);
	return ret;
}

static inline void klpr_zap_deposited_table(struct mm_struct *mm, pmd_t *pmd)
{
	pgtable_t pgtable;

	pgtable = klpr_pgtable_trans_huge_withdraw(mm, pmd);
	klpr_pte_free(mm, pgtable);
	atomic_long_dec(&mm->nr_ptes);
}

static void klpr___split_huge_zero_page_pmd(struct vm_area_struct *vma,
		unsigned long haddr, pmd_t *pmd)
{
	struct mm_struct *mm = vma->vm_mm;
	pgtable_t pgtable;
	pmd_t _pmd;
	int i;

	/* leave pmd empty until pte is filled */
	klpr_pmdp_huge_clear_flush_notify(vma, haddr, pmd);

	pgtable = klpr_pgtable_trans_huge_withdraw(mm, pmd);
	pmd_populate(mm, &_pmd, pgtable);

	for (i = 0; i < HPAGE_PMD_NR; i++, haddr += PAGE_SIZE) {
		pte_t *pte, entry;
		entry = pfn_pte(my_zero_pfn(haddr), vma->vm_page_prot);
		entry = pte_mkspecial(entry);
		pte = pte_offset_map(&_pmd, haddr);
		VM_BUG_ON(!pte_none(*pte));
		klpr_set_pte_at(mm, haddr, pte, entry);
		pte_unmap(pte);
	}
	smp_wmb(); /* make pte visible before pmd */
	pmd_populate(mm, pmd, pgtable);
}

static void klpr___split_huge_pmd_locked(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long haddr, bool freeze)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	pgtable_t pgtable;
	pmd_t _pmd;
	bool young, write, dirty, soft_dirty;
	unsigned long addr;
	int i;

	VM_BUG_ON(haddr & ~HPAGE_PMD_MASK);
	VM_BUG_ON_VMA(vma->vm_start > haddr, vma);
	VM_BUG_ON_VMA(vma->vm_end < haddr + HPAGE_PMD_SIZE, vma);
	VM_BUG_ON(!pmd_trans_huge(*pmd) && !pmd_devmap(*pmd));

	count_vm_event(THP_SPLIT_PMD);

	if (!vma_is_anonymous(vma)) {
		_pmd = klpr_pmdp_huge_clear_flush_notify(vma, haddr, pmd);
		/*
		 * We are going to unmap this huge page. So
		 * just go ahead and zap it
		 */
		if (arch_needs_pgtable_deposit())
			klpr_zap_deposited_table(mm, pmd);
		if (vma_is_dax(vma))
			return;
		page = klpr_pmd_page(_pmd);
		if (!PageDirty(page) && pmd_dirty(_pmd))
			set_page_dirty(page);
		if (!PageReferenced(page) && pmd_young(_pmd))
			SetPageReferenced(page);
		(*klpe_page_remove_rmap)(page, true);
		put_page(page);
		add_mm_counter(mm, MM_FILEPAGES, -HPAGE_PMD_NR);
		return;
	} else if (klpr_is_huge_zero_pmd(*pmd)) {
		return klpr___split_huge_zero_page_pmd(vma, haddr, pmd);
	}

	page = klpr_pmd_page(*pmd);
	VM_BUG_ON_PAGE(!page_count(page), page);
	page_ref_add(page, HPAGE_PMD_NR - 1);
	write = pmd_write(*pmd);
	young = pmd_young(*pmd);
	dirty = pmd_dirty(*pmd);
	soft_dirty = pmd_soft_dirty(*pmd);

	klpr_pmdp_huge_split_prepare(vma, haddr, pmd);
	pgtable = klpr_pgtable_trans_huge_withdraw(mm, pmd);
	pmd_populate(mm, &_pmd, pgtable);

	for (i = 0, addr = haddr; i < HPAGE_PMD_NR; i++, addr += PAGE_SIZE) {
		pte_t entry, *pte;
		/*
		 * Note that NUMA hinting access restrictions are not
		 * transferred to avoid any possibility of altering
		 * permissions across VMAs.
		 */
		if (freeze) {
			swp_entry_t swp_entry;
			swp_entry = make_migration_entry(page + i, write);
			entry = swp_entry_to_pte(swp_entry);
			if (soft_dirty)
				entry = pte_swp_mksoft_dirty(entry);
		} else {
			entry = mk_pte(page + i, READ_ONCE(vma->vm_page_prot));
			entry = maybe_mkwrite(entry, vma);
			if (!write)
				entry = pte_wrprotect(entry);
			if (!young)
				entry = pte_mkold(entry);
			if (soft_dirty)
				entry = pte_mksoft_dirty(entry);
		}
		if (dirty)
			SetPageDirty(page + i);
		pte = pte_offset_map(&_pmd, addr);
		BUG_ON(!pte_none(*pte));
		klpr_set_pte_at(mm, addr, pte, entry);
		atomic_inc(&page[i]._mapcount);
		pte_unmap(pte);
	}

	/*
	 * Set PG_double_map before dropping compound_mapcount to avoid
	 * false-negative page_mapped().
	 */
	if (compound_mapcount(page) > 1 && !TestSetPageDoubleMap(page)) {
		for (i = 0; i < HPAGE_PMD_NR; i++)
			atomic_inc(&page[i]._mapcount);
	}

	if (atomic_add_negative(-1, compound_mapcount_ptr(page))) {
		/* Last compound_mapcount is gone. */
		__dec_node_page_state(page, NR_ANON_THPS);
		if (TestClearPageDoubleMap(page)) {
			/* No need in mapcount reference anymore */
			for (i = 0; i < HPAGE_PMD_NR; i++)
				atomic_dec(&page[i]._mapcount);
		}
	}

	smp_wmb(); /* make pte visible before pmd */
	/*
	 * Up to this point the pmd is present and huge and userland has the
	 * whole access to the hugepage during the split (which happens in
	 * place). If we overwrite the pmd with the not-huge version pointing
	 * to the pte here (which of course we could if all CPUs were bug
	 * free), userland could trigger a small page size TLB miss on the
	 * small sized TLB while the hugepage TLB entry is still established in
	 * the huge TLB. Some CPU doesn't like that.
	 * See http://support.amd.com/us/Processor_TechDocs/41322.pdf, Erratum
	 * 383 on page 93. Intel should be safe but is also warns that it's
	 * only safe if the permission and cache attributes of the two entries
	 * loaded in the two TLB is identical (which should be the case here).
	 * But it is generally safer to never allow small and huge TLB entries
	 * for the same virtual address to be loaded simultaneously. So instead
	 * of doing "pmd_populate(); flush_pmd_tlb_range();" we first mark the
	 * current pmd notpresent (atomically because here the pmd_trans_huge
	 * and pmd_trans_splitting must remain set at all times on the pmd
	 * until the split is complete for this pmd), then we flush the SMP TLB
	 * and finally we write the non-huge version of the pmd entry with
	 * pmd_populate.
	 */
	klpr_pmdp_invalidate(vma, haddr, pmd);
	pmd_populate(mm, pmd, pgtable);

	if (freeze) {
		for (i = 0; i < HPAGE_PMD_NR; i++) {
			(*klpe_page_remove_rmap)(page + i, false);
			put_page(page + i);
		}
	}
}

void klpp___split_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct page *page)
{
	spinlock_t *ptl;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long haddr = address & HPAGE_PMD_MASK;
	/*
	 * Fix CVE-2020-29368
	 * +2 lines
	 */
	bool do_unlock_page = false;
	pmd_t _pmd;

	mmu_notifier_invalidate_range_start(mm, haddr, haddr + HPAGE_PMD_SIZE);
	ptl = pmd_lock(mm, pmd);

	/*
	 * If caller asks to setup a migration entries, we need a page to check
	 * pmd against. Otherwise we can end up replacing wrong page.
	 */
	VM_BUG_ON(freeze && !page);
	/*
	 * Fix CVE-2020-29368
	 *  -2 lines, +5 lines
	 */
	if (page) {
		VM_WARN_ON_ONCE(!PageLocked(page));
		if (page != klpr_pmd_page(*pmd))
			goto out;
	}

	/*
	 * Fix CVE-2020-29368
	 *  +1 line
	 */
repeat:
	if (pmd_trans_huge(*pmd)) {
		/*
		 * Fix CVE-2020-29368
		 *  -1 line, +27 lines
		 */
		if (!page) {
			page = klpr_pmd_page(*pmd);
			/*
			 * An anonymous page must be locked, to ensure that a
			 * concurrent reuse_swap_page() sees stable mapcount;
			 * but reuse_swap_page() is not used on shmem or file,
			 * and page lock must not be taken when zap_pmd_range()
			 * calls __split_huge_pmd() while i_mmap_lock is held.
			 */
			if (PageAnon(page)) {
				if (unlikely(!trylock_page(page))) {
					get_page(page);
					_pmd = *pmd;
					spin_unlock(ptl);
					lock_page(page);
					spin_lock(ptl);
					if (unlikely(!pmd_same(*pmd, _pmd))) {
						unlock_page(page);
						put_page(page);
						page = NULL;
						goto repeat;
					}
					put_page(page);
				}
				do_unlock_page = true;
			}
		}
		if (PageMlocked(page))
			(*klpe_clear_page_mlock)(page);
	} else if (!pmd_devmap(*pmd))
		goto out;
	klpr___split_huge_pmd_locked(vma, pmd, haddr, freeze);
out:
	spin_unlock(ptl);
	/*
	 * Fix CVE-2020-29368
	 *  +1 line
	 */
	if (do_unlock_page)
		unlock_page(page);
	mmu_notifier_invalidate_range_end(mm, haddr, haddr + HPAGE_PMD_SIZE);
}



#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "transparent_hugepage_flags",
	  (void *)&klpe_transparent_hugepage_flags },
	{ "huge_zero_page", (void *)&klpe_huge_zero_page },
#if defined (CONFIG_PPC_BOOK3S)
	{ "set_pte_at", (void *)&klpe_set_pte_at },
#elif defined(CONFIG_S390)
	{ "ptep_set_pte_at", (void *)&klpe_ptep_set_pte_at },
#endif
#if defined (CONFIG_PPC_BOOK3S)
	{ "pmd_page", (void *)&klpe_pmd_page },
	{ "pte_fragment_free", (void *)&klpe_pte_fragment_free },
#endif
#if defined(CONFIG_X86_64) || defined(CONFIG_PPC_BOOK3S)
	{ "pmdp_set_access_flags", (void *)&klpe_pmdp_set_access_flags },
#endif
#ifndef __HAVE_ARCH_PMDP_HUGE_CLEAR_FLUSH
	{ "pmdp_huge_clear_flush", (void *)&klpe_pmdp_huge_clear_flush },
#endif
#if !defined(__HAVE_ARCH_PGTABLE_WITHDRAW) || defined(CONFIG_S390)
	{ "pgtable_trans_huge_withdraw",
	  (void *)&klpe_pgtable_trans_huge_withdraw },
#elif defined(CONFIG_PPC_BOOK3S)
	{ "radix__pgtable_trans_huge_withdraw",
	  (void *)&klpe_radix__pgtable_trans_huge_withdraw },
	{ "hash__pgtable_trans_huge_withdraw",
	  (void *)&klpe_hash__pgtable_trans_huge_withdraw },
#endif
#if !defined(__HAVE_ARCH_PMDP_INVALIDATE) || defined(CONFIG_PPC_BOOK3S)
	{ "pmdp_invalidate", (void *)&klpe_pmdp_invalidate },
#endif
#if defined(CONFIG_PPC_BOOK3S)
	{ "mk_pmd", (void *)&klpe_mk_pmd },
	{ "set_pmd_at", (void *)&klpe_set_pmd_at },
	{ "update_mmu_cache_pmd", (void *)&klpe_update_mmu_cache_pmd },
	{ "hash__pmdp_huge_split_prepare",
	  (void *)&klpe_hash__pmdp_huge_split_prepare },
	{ "copy_user_page", (void *)&klpe_copy_user_page },
#endif
	{ "is_vma_temporary_stack", (void *)&klpe_is_vma_temporary_stack },
	{ "prep_transhuge_page", (void *)&klpe_prep_transhuge_page },
	{ "page_trans_huge_mapcount", (void *)&klpe_page_trans_huge_mapcount },
	{ "clear_huge_page", (void *)&klpe_clear_huge_page },
	{ "copy_user_huge_page", (void *)&klpe_copy_user_huge_page },
	{ "alloc_pages_vma", (void *)&klpe_alloc_pages_vma },
	{ "page_add_new_anon_rmap", (void *)&klpe_page_add_new_anon_rmap },
	{ "page_remove_rmap", (void *)&klpe_page_remove_rmap },
	{ "clear_page_mlock", (void *)&klpe_clear_page_mlock },
	{ "maybe_pmd_mkwrite", (void *)&klpe_maybe_pmd_mkwrite },
	{ "mem_cgroup_try_charge", (void *)&klpe_mem_cgroup_try_charge },
	{ "mem_cgroup_commit_charge", (void *)&klpe_mem_cgroup_commit_charge },
	{ "mem_cgroup_cancel_charge", (void *)&klpe_mem_cgroup_cancel_charge },
	{ "lru_cache_add_active_or_unevictable",
	  (void *)&klpe_lru_cache_add_active_or_unevictable },
};

int livepatch_bsc1179664_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
