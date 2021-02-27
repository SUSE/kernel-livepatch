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
static struct page *(*klpe_pmd_page)(pmd_t pmd);
#define klpr_pmd_page (*klpe_pmd_page)

/* klp-ccp: from arch/powerpc/include/asm/pgalloc.h */
static void (*klpe_pte_fragment_free)(unsigned long *table, int kernel);

static inline void klpr_pte_free(struct mm_struct *mm, pgtable_t ptepage)
{
	(*klpe_pte_fragment_free)((unsigned long *)ptepage, 0);
}

#else
#define klpr_pmd_page pmd_page
#define klpr_pte_free pte_free
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
static pmd_t (*klpe_pmdp_invalidate)(struct vm_area_struct *vma, unsigned long address,
			    pmd_t *pmdp);

#define klpr_pmdp_invalidate (*klpe_pmdp_invalidate)

#elif defined(CONFIG_S390)

#define klpr_pmdp_invalidate pmdp_invalidate

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from include/linux/huge_mm.h */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE

void klpp___split_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct page *page);

static struct page *(*klpe_huge_zero_page);

static inline bool klpr_is_huge_zero_page(struct page *page)
{
	return READ_ONCE((*klpe_huge_zero_page)) == page;
}

static inline bool klpr_is_huge_zero_pmd(pmd_t pmd)
{
	return klpr_is_huge_zero_page(klpr_pmd_page(pmd));
}

#else /* CONFIG_TRANSPARENT_HUGEPAGE */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/* klp-ccp: from include/linux/mm.h */
static void (*klpe_mm_trace_rss_stat)(struct mm_struct *mm, int member, long count);

static inline void klpr_add_mm_counter(struct mm_struct *mm, int member, long value)
{
	long count = atomic_long_add_return(value, &mm->rss_stat.count[member]);

       (*klpe_mm_trace_rss_stat)(mm, member, count);
}

/* klp-ccp: from mm/huge_memory.c */
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/hugetlb.h>
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

#include <linux/rmap.h>

/* klp-ccp: from include/linux/rmap.h */
static void (*klpe_page_remove_rmap)(struct page *, bool);

/* klp-ccp: from mm/huge_memory.c */
#include <linux/swap.h>
#include <linux/shrinker.h>
#include <linux/swapops.h>
#include <linux/dax.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/hashtable.h>
#include <linux/numa.h>
#include <asm/tlb.h>
#include <asm/pgalloc.h>
/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

static void (*klpe_clear_page_mlock)(struct page *page);

/* klp-ccp: from mm/huge_memory.c */
static inline void klpr_zap_deposited_table(struct mm_struct *mm, pmd_t *pmd)
{
	pgtable_t pgtable;

	pgtable = klpr_pgtable_trans_huge_withdraw(mm, pmd);
	klpr_pte_free(mm, pgtable);
	mm_dec_nr_ptes(mm);
}

static void klpr___split_huge_zero_page_pmd(struct vm_area_struct *vma,
		unsigned long haddr, pmd_t *pmd)
{
	struct mm_struct *mm = vma->vm_mm;
	pgtable_t pgtable;
	pmd_t _pmd;
	int i;

	/*
	 * Leave pmd empty until pte is filled note that it is fine to delay
	 * notification until mmu_notifier_invalidate_range_end() as we are
	 * replacing a zero pmd write protected page with a zero pte write
	 * protected page.
	 *
	 * See Documentation/vm/mmu_notifier.rst
	 */
	klpr_pmdp_huge_clear_flush(vma, haddr, pmd);

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
	pmd_t old_pmd, _pmd;
	bool young, write, soft_dirty, pmd_migration = false;
	unsigned long addr;
	int i;

	VM_BUG_ON(haddr & ~HPAGE_PMD_MASK);
	VM_BUG_ON_VMA(vma->vm_start > haddr, vma);
	VM_BUG_ON_VMA(vma->vm_end < haddr + HPAGE_PMD_SIZE, vma);
	VM_BUG_ON(!is_pmd_migration_entry(*pmd) && !pmd_trans_huge(*pmd)
				&& !pmd_devmap(*pmd));

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
		klpr_add_mm_counter(mm, mm_counter_file(page), -HPAGE_PMD_NR);
		return;
	} else if (klpr_is_huge_zero_pmd(*pmd)) {
		/*
		 * FIXME: Do we want to invalidate secondary mmu by calling
		 * mmu_notifier_invalidate_range() see comments below inside
		 * __split_huge_pmd() ?
		 *
		 * We are going from a zero huge page write protected to zero
		 * small page also write protected so it does not seems useful
		 * to invalidate secondary mmu at this time.
		 */
		return klpr___split_huge_zero_page_pmd(vma, haddr, pmd);
	}

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
	 * must remain set at all times on the pmd until the split is complete
	 * for this pmd), then we flush the SMP TLB and finally we write the
	 * non-huge version of the pmd entry with pmd_populate.
	 */
	old_pmd = klpr_pmdp_invalidate(vma, haddr, pmd);

	pmd_migration = is_pmd_migration_entry(old_pmd);
	if (unlikely(pmd_migration)) {
		swp_entry_t entry;

		entry = pmd_to_swp_entry(old_pmd);
		page = pfn_to_page(swp_offset(entry));
		write = is_write_migration_entry(entry);
		young = false;
		soft_dirty = pmd_swp_soft_dirty(old_pmd);
	} else {
		page = klpr_pmd_page(old_pmd);
		if (pmd_dirty(old_pmd))
			SetPageDirty(page);
		write = pmd_write(old_pmd);
		young = pmd_young(old_pmd);
		soft_dirty = pmd_soft_dirty(old_pmd);
	}
	VM_BUG_ON_PAGE(!page_count(page), page);
	page_ref_add(page, HPAGE_PMD_NR - 1);

	/*
	 * Withdraw the table only after we mark the pmd entry invalid.
	 * This's critical for some architectures (Power).
	 */
	pgtable = klpr_pgtable_trans_huge_withdraw(mm, pmd);
	pmd_populate(mm, &_pmd, pgtable);

	for (i = 0, addr = haddr; i < HPAGE_PMD_NR; i++, addr += PAGE_SIZE) {
		pte_t entry, *pte;
		/*
		 * Note that NUMA hinting access restrictions are not
		 * transferred to avoid any possibility of altering
		 * permissions across VMAs.
		 */
		if (freeze || pmd_migration) {
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
	pmd_populate(mm, pmd, pgtable);

	if (freeze) {
		for (i = 0; i < HPAGE_PMD_NR; i++) {
			(*klpe_page_remove_rmap)(page + i, false);
			put_page(page + i);
		}
	}
}

#include "livepatch_bsc1179664.h"

void klpp___split_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct page *page)
{
	spinlock_t *ptl;
	struct mmu_notifier_range range;
	/*
	 * Fix CVE-2020-29368
	 * +2 lines
	 */
	bool do_unlock_page = false;
	pmd_t _pmd;

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
				address & HPAGE_PMD_MASK,
				(address & HPAGE_PMD_MASK) + HPAGE_PMD_SIZE);
	mmu_notifier_invalidate_range_start(&range);
	ptl = pmd_lock(vma->vm_mm, pmd);

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
	} else if (!(pmd_devmap(*pmd) || is_pmd_migration_entry(*pmd)))
		goto out;
	klpr___split_huge_pmd_locked(vma, pmd, range.start, freeze);
out:
	spin_unlock(ptl);
	/*
	 * Fix CVE-2020-29368
	 *  +1 line
	 */
	if (do_unlock_page)
		unlock_page(page);
	/*
	 * No need to double call mmu_notifier->invalidate_range() callback.
	 * They are 3 cases to consider inside __split_huge_pmd_locked():
	 *  1) pmdp_huge_clear_flush_notify() call invalidate_range() obvious
	 *  2) __split_huge_zero_page_pmd() read only zero page and any write
	 *    fault will trigger a flush_notify before pointing to a new page
	 *    (it is fine if the secondary mmu keeps pointing to the old zero
	 *    page in the meantime)
	 *  3) Split a huge pmd into pte pointing to the same page. No need
	 *     to invalidate secondary tlb entry they are all still valid.
	 *     any further changes to individual pte will notify. So no need
	 *     to call mmu_notifier->invalidate_range()
	 */
	mmu_notifier_invalidate_range_only_end(&range);
}



#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "huge_zero_page", (void *)&klpe_huge_zero_page },
#if defined(CONFIG_PPC_BOOK3S)
	{ "set_pte_at", (void *)&klpe_set_pte_at },
#elif defined(CONFIG_S390)
	{ "ptep_set_pte_at", (void *)&klpe_ptep_set_pte_at },
#endif
#if defined(CONFIG_PPC_BOOK3S)
	{ "pmd_page", (void *)&klpe_pmd_page },
	{ "pte_fragment_free", (void *)&klpe_pte_fragment_free },
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
	{ "mm_trace_rss_stat", (void *)&klpe_mm_trace_rss_stat },
	{ "page_remove_rmap", (void *)&klpe_page_remove_rmap },
	{ "clear_page_mlock", (void *)&klpe_clear_page_mlock },
};

int livepatch_bsc1179664_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
