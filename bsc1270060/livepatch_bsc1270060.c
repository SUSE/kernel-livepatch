/*
 * livepatch_bsc1270060
 *
 * Fix for CVE-2026-53359, bsc#1270060
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_X86)

#include "livepatch_bsc1270060.h"

/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>

/* klp-ccp: from include/linux/kvm_host.h */
static void (*klpe_kvm_flush_remote_tlbs)(struct kvm *kvm);

/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/spinlock.h>

#include <kvm/iodev.h>

/* klp-ccp: from arch/x86/kvm/ioapic.h */
#include <linux/kvm_host.h>

#include <kvm/iodev.h>

/* klp-ccp: from arch/x86/kvm/lapic.h */
#include <kvm/iodev.h>

#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/mmu.h */
#include <linux/kvm_host.h>

#define PT_WRITABLE_SHIFT 1
#define PT_USER_SHIFT 2

#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << PT_USER_SHIFT)

#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)

#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define PT_PAGE_TABLE_LEVEL 1

/* klp-ccp: from arch/x86/kvm/x86.h */
#include <asm/processor.h>
#include <asm/mwait.h>
#include <linux/kvm_host.h>
#include <asm/pvclock.h>

/* klp-ccp: from arch/x86/kvm/cpuid.h */
#include <asm/cpu.h>
#include <asm/processor.h>

/* klp-ccp: from arch/x86/kvm/mmu.c */
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/compiler.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/kern_levels.h>
#include <linux/kthread.h>

#include <asm/page.h>
#include <asm/pat.h>
#include <asm/cmpxchg.h>
#include <asm/io.h>
#include <asm/vmx.h>
#include <asm/kvm_page_track.h>

#include <linux/tracepoint.h>
#include <asm/vmx.h>
#include <asm/svm.h>
#include <asm/clocksource.h>
#include <asm/pvclock-abi.h>

/* klp-ccp: from arch/x86/kvm/mmu.c */
static int __read_mostly (*klpe_nx_huge_pages);

#define PTE_PREFETCH_NUM		8

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))

#define PT32_LEVEL_BITS 10

#define PT32_LVL_OFFSET_MASK(level) \
	(PT32_BASE_ADDR_MASK & ((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT32_LEVEL_BITS))) - 1))

#define PT64_BASE_ADDR_MASK __sme_clr((((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1)))

#define PT64_LVL_OFFSET_MASK(level) \
	(PT64_BASE_ADDR_MASK & ((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT64_LEVEL_BITS))) - 1))

#define PT32_BASE_ADDR_MASK PAGE_MASK

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#include <trace/events/kvm.h>

#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

enum {
	RET_PF_RETRY = 0,
	RET_PF_EMULATE = 1,
	RET_PF_INVALID = 2,
};

struct kvm_shadow_walk_iterator {
	u64 addr;
	hpa_t shadow_addr;
	u64 *sptep;
	int level;
	unsigned index;
};

static u64 __read_mostly (*klpe_shadow_mmio_mask);
static u64 __read_mostly (*klpe_shadow_mmio_value);

#define CREATE_TRACE_POINTS

/* klp-ccp: from arch/x86/kvm/mmutrace.h */
#if !defined(_TRACE_KVMMMU_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>
#include <linux/trace_events.h>
#include "../klp_trace.h"

/* klp-ccp: from arch/x86/kvm/mmutrace.h */
KLPR_TRACE_EVENT(
	kvm_mmu_spte_requested,
	TP_PROTO(gpa_t addr, int level, kvm_pfn_t pfn),
	TP_ARGS(addr, level, pfn)
)

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_KVMMMU_H */

/* klp-ccp: from arch/x86/kvm/mmu.c */
static inline bool sp_ad_disabled(struct kvm_mmu_page *sp)
{
	return sp->role.ad_disabled;
}

static bool klpr_is_nx_huge_page_enabled(void)
{
	return READ_ONCE((*klpe_nx_huge_pages));
}

static bool klpr_is_mmio_spte(u64 spte)
{
	return (spte & (*klpe_shadow_mmio_mask)) == (*klpe_shadow_mmio_value);
}

static int klpr_is_shadow_present_pte(u64 pte)
{
	return (pte != 0) && !klpr_is_mmio_spte(pte);
}

static int is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

#ifdef CONFIG_X86_64

static void __update_clear_spte_fast(u64 *sptep, u64 spte)
{
	WRITE_ONCE(*sptep, spte);
}

#else
#error "klp-ccp: non-taken branch"
#endif

static void mmu_spte_clear_no_track(u64 *sptep)
{
	__update_clear_spte_fast(sptep, 0ull);
}

static void account_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	if (sp->lpage_disallowed)
		return;

	++kvm->stat.nx_lpage_splits;
	list_add_tail(&sp->lpage_disallowed_link,
		      &kvm->arch.lpage_disallowed_mmu_pages);
	sp->lpage_disallowed = true;
}

static void (*klpe_pte_list_remove)(u64 *spte, struct kvm_rmap_head *rmap_head);

static void (*klpe_drop_spte)(struct kvm *kvm, u64 *sptep);

static bool klpr___drop_large_spte(struct kvm *kvm, u64 *sptep)
{
	if (is_large_pte(*sptep)) {
		WARN_ON(page_header(__pa(sptep))->role.level ==
			PT_PAGE_TABLE_LEVEL);
		(*klpe_drop_spte)(kvm, sptep);
		--kvm->stat.lpages;
		return true;
	}

	return false;
}

static void klpr_drop_large_spte(struct kvm_vcpu *vcpu, u64 *sptep)
{
	if (klpr___drop_large_spte(vcpu->kvm, sptep))
		(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
}

static void klpr_mmu_page_remove_parent_pte(struct kvm_mmu_page *sp,
				       u64 *parent_pte)
{
	(*klpe_pte_list_remove)(parent_pte, &sp->parent_ptes);
}

static void klpr_drop_parent_pte(struct kvm_mmu_page *sp,
			    u64 *parent_pte)
{
	klpr_mmu_page_remove_parent_pte(sp, parent_pte);
	mmu_spte_clear_no_track(parent_pte);
}

#ifdef CONFIG_KVM_MMU_AUDIT

/* klp-ccp: from arch/x86/kvm/mmu_audit.c */
#include <linux/ratelimit.h>

/* klp-ccp: from arch/x86/kvm/mmu.c */
#else
#error "klp-ccp: non-taken branch"
#endif

static void __clear_sp_write_flooding_count(struct kvm_mmu_page *sp)
{
	atomic_set(&sp->write_flooding_count,  0);
}

static void clear_sp_write_flooding_count(u64 *spte)
{
	struct kvm_mmu_page *sp =  page_header(__pa(spte));

	__clear_sp_write_flooding_count(sp);
}

static struct kvm_mmu_page *(*klpe_kvm_mmu_get_page)(struct kvm_vcpu *vcpu,
					     gfn_t gfn,
					     gva_t gaddr,
					     unsigned level,
					     int direct,
					     unsigned access);

static void (*klpe_shadow_walk_init)(struct kvm_shadow_walk_iterator *iterator,
			     struct kvm_vcpu *vcpu, u64 addr);

static bool shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator)
{
	if (iterator->level < PT_PAGE_TABLE_LEVEL)
		return false;

	iterator->index = SHADOW_PT_INDEX(iterator->addr, iterator->level);
	iterator->sptep	= ((u64 *)__va(iterator->shadow_addr)) + iterator->index;
	return true;
}

static void (*klpe_shadow_walk_next)(struct kvm_shadow_walk_iterator *iterator);

static void (*klpe_link_shadow_page)(struct kvm_vcpu *vcpu, u64 *sptep,
			     struct kvm_mmu_page *sp);

static void klpr_validate_direct_spte(struct kvm_vcpu *vcpu, u64 *sptep,
				   unsigned direct_access)
{
	if (klpr_is_shadow_present_pte(*sptep) && !is_large_pte(*sptep)) {
		struct kvm_mmu_page *child;

		/*
		 * For the direct sp, if the guest pte's dirty bit
		 * changed form clean to dirty, it will corrupt the
		 * sp's access: allow writable in the read-only sp,
		 * so we should update the spte at this point to get
		 * a new sp with the correct access.
		 */
		child = page_header(*sptep & PT64_BASE_ADDR_MASK);
		if (child->role.access == direct_access)
			return;

		klpr_drop_parent_pte(child, sptep);
		(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
	}
}

static bool (*klpe_mmu_page_zap_pte)(struct kvm *kvm, struct kvm_mmu_page *sp,
			     u64 *spte);

static int (*klpe_mmu_set_spte)(struct kvm_vcpu *vcpu, u64 *sptep, unsigned pte_access,
			int write_fault, int level, gfn_t gfn, kvm_pfn_t pfn,
		       	bool speculative, bool host_writable);

static void (*klpe___direct_pte_prefetch)(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *sptep);

static void klpr_direct_pte_prefetch(struct kvm_vcpu *vcpu, u64 *sptep)
{
	struct kvm_mmu_page *sp;

	sp = page_header(__pa(sptep));

	/*
	 * Without accessed bits, there's no way to distinguish between
	 * actually accessed translations and prefetched, so disable pte
	 * prefetch if accessed bits aren't available.
	 */
	if (sp_ad_disabled(sp))
		return;

	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	(*klpe___direct_pte_prefetch)(vcpu, sp, sptep);
}

static void klpr_disallowed_hugepage_adjust(struct kvm_shadow_walk_iterator it,
				       gfn_t gfn, kvm_pfn_t *pfnp, int *levelp)
{
	int level = *levelp;
	u64 spte = *it.sptep;

	if (it.level == level && level > PT_PAGE_TABLE_LEVEL &&
	    klpr_is_nx_huge_page_enabled() &&
	    klpr_is_shadow_present_pte(spte) &&
	    !is_large_pte(spte)) {
		/*
		 * A small SPTE exists for this pfn, but FNAME(fetch)
		 * and __direct_map would like to create a large PTE
		 * instead: just force them to go down another level,
		 * patching back for them into pfn the next 9 bits of
		 * the address.
		 */
		u64 page_mask = KVM_PAGES_PER_HPAGE(level) - KVM_PAGES_PER_HPAGE(level - 1);
		*pfnp |= gfn & page_mask;
		(*levelp)--;
	}
}

int klpp___direct_map(struct kvm_vcpu *vcpu, gpa_t gpa, int write,
			int map_writable, int level, kvm_pfn_t pfn,
			bool prefault, bool lpage_disallowed)
{
	struct kvm_shadow_walk_iterator it;
	struct kvm_mmu_page *sp;
	int ret;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	gfn_t base_gfn = gfn;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		return RET_PF_RETRY;

	klpr_trace_kvm_mmu_spte_requested(gpa, level, pfn);
	for ((*klpe_shadow_walk_init)(&(it), vcpu, gpa); shadow_walk_okay(&(it)); (*klpe_shadow_walk_next)(&(it))) {
		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		klpr_disallowed_hugepage_adjust(it, gfn, &pfn, &level);

		base_gfn = gfn & ~(KVM_PAGES_PER_HPAGE(it.level) - 1);
		if (it.level == level)
			break;

		klpr_drop_large_spte(vcpu, it.sptep);
		if (klpr_is_shadow_present_pte(*it.sptep)) {
			struct kvm_mmu_page *child = page_header(*it.sptep & PT64_BASE_ADDR_MASK);
			struct kvm_mmu_page *parent_sp;

			if (!child || child->gfn != base_gfn || child->role.direct != true) {
				parent_sp = page_header(__pa(it.sptep));
				WARN_ON_ONCE(parent_sp->role.level == PT_PAGE_TABLE_LEVEL);

				(*klpe_mmu_page_zap_pte)(vcpu->kvm, parent_sp, it.sptep);
				(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
			}
		}
		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			sp = (*klpe_kvm_mmu_get_page)(vcpu, base_gfn, it.addr,
					      it.level - 1, true, ACC_ALL);

			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
			if (lpage_disallowed)
				account_huge_nx_page(vcpu->kvm, sp);
		}
	}

	ret = (*klpe_mmu_set_spte)(vcpu, it.sptep, ACC_ALL,
			   write, level, base_gfn, pfn, prefault,
			   map_writable);
	klpr_direct_pte_prefetch(vcpu, it.sptep);
	++vcpu->stat.pf_fixed;
	return ret;
}

/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#define pt_element_t u64
#define guest_walker guest_walkerEPT

#define PT_LVL_OFFSET_MASK(lvl) PT64_LVL_OFFSET_MASK(lvl)

#define PT_MAX_FULL_LEVELS 4

struct guest_walker {
	int level;
	unsigned max_level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t ptes[PT_MAX_FULL_LEVELS];
	pt_element_t prefetch_ptes[PTE_PREFETCH_NUM];
	gpa_t pte_gpa[PT_MAX_FULL_LEVELS];
	pt_element_t __user *ptep_user[PT_MAX_FULL_LEVELS];
	bool pte_writable[PT_MAX_FULL_LEVELS];
	unsigned int pt_access[PT_MAX_FULL_LEVELS];
	unsigned int pte_access;
	gfn_t gfn;
	struct x86_exception fault;
};

static bool
(*klpe_ept_prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     u64 *spte, pt_element_t gpte, bool no_dirty_log);

static bool (*klpe_ept_gpte_changed)(struct kvm_vcpu *vcpu,
				struct guest_walker *gw, int level);

static void klpr_ept_pte_prefetch(struct kvm_vcpu *vcpu, struct guest_walker *gw,
				u64 *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	u64 *spte;
	int i;

	sp = page_header(__pa(sptep));

	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	if (sp->role.direct)
		return (*klpe___direct_pte_prefetch)(vcpu, sp, sptep);

	i = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (klpr_is_shadow_present_pte(*spte))
			continue;

		if (!(*klpe_ept_prefetch_gpte)(vcpu, sp, spte, gptep[i], true))
			break;
	}
}

int klpp_ept_fetch(struct kvm_vcpu *vcpu, gva_t addr,
			 struct guest_walker *gw,
			 int write_fault, int hlevel,
			 kvm_pfn_t pfn, bool map_writable, bool prefault,
			 bool lpage_disallowed)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	unsigned int direct_access, access;
	int top_level, ret;
	gfn_t gfn, base_gfn;

	direct_access = gw->pte_access;

	top_level = vcpu->arch.mmu.root_level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if ((*klpe_ept_gpte_changed)(vcpu, gw, top_level))
		goto out_gpte_changed;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		goto out_gpte_changed;

	for ((*klpe_shadow_walk_init)(&it, vcpu, addr);
	     shadow_walk_okay(&it) && it.level > gw->level;
	     (*klpe_shadow_walk_next)(&it)) {
		gfn_t table_gfn;

		clear_sp_write_flooding_count(it.sptep);
		klpr_drop_large_spte(vcpu, it.sptep);

		if (klpr_is_shadow_present_pte(*it.sptep)) {
			struct kvm_mmu_page *child = page_header(*it.sptep & PT64_BASE_ADDR_MASK);
			struct kvm_mmu_page *parent_sp;

			if (!child || child->gfn != gw->table_gfn[it.level - 2] || child->role.direct != false) {
				parent_sp = page_header(__pa(it.sptep));
				WARN_ON_ONCE(parent_sp->role.level == PT_PAGE_TABLE_LEVEL);

				(*klpe_mmu_page_zap_pte)(vcpu->kvm, parent_sp, it.sptep);
				(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
			}
		}

		sp = NULL;
		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			table_gfn = gw->table_gfn[it.level - 2];
			access = gw->pt_access[it.level - 2];
			sp = (*klpe_kvm_mmu_get_page)(vcpu, table_gfn, addr, it.level-1,
					      false, access);
		}

		/*
		 * Verify that the gpte in the page we've just write
		 * protected is still there.
		 */
		if ((*klpe_ept_gpte_changed)(vcpu, gw, it.level - 1))
			goto out_gpte_changed;

		if (sp)
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
	}

	/*
	 * FNAME(page_fault) might have clobbered the bottom bits of
	 * gw->gfn, restore them from the virtual address.
	 */
	gfn = gw->gfn | ((addr & PT_LVL_OFFSET_MASK(gw->level)) >> PAGE_SHIFT);
	base_gfn = gfn;

	klpr_trace_kvm_mmu_spte_requested(addr, gw->level, pfn);

	for (; shadow_walk_okay(&it); (*klpe_shadow_walk_next)(&it)) {
		clear_sp_write_flooding_count(it.sptep);

		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		klpr_disallowed_hugepage_adjust(it, gfn, &pfn, &hlevel);

		base_gfn = gfn & ~(KVM_PAGES_PER_HPAGE(it.level) - 1);
		if (it.level == hlevel)
			break;

		klpr_validate_direct_spte(vcpu, it.sptep, direct_access);

		klpr_drop_large_spte(vcpu, it.sptep);

		if (klpr_is_shadow_present_pte(*it.sptep)) {
			struct kvm_mmu_page *child = page_header(*it.sptep & PT64_BASE_ADDR_MASK);
			struct kvm_mmu_page *parent_sp;

			if (!child || child->gfn != base_gfn || child->role.direct != true) {
				parent_sp = page_header(__pa(it.sptep));
				WARN_ON_ONCE(parent_sp->role.level == PT_PAGE_TABLE_LEVEL);

				(*klpe_mmu_page_zap_pte)(vcpu->kvm, parent_sp, it.sptep);
				(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
			}
		}

		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			sp = (*klpe_kvm_mmu_get_page)(vcpu, base_gfn, addr,
					      it.level - 1, true, direct_access);
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
			if (lpage_disallowed)
				account_huge_nx_page(vcpu->kvm, sp);
		}
	}

	ret = (*klpe_mmu_set_spte)(vcpu, it.sptep, gw->pte_access, write_fault,
			   it.level, base_gfn, pfn, prefault, map_writable);
	klpr_ept_pte_prefetch(vcpu, gw, it.sptep);
	++vcpu->stat.pf_fixed;
	return ret;

out_gpte_changed:
	return RET_PF_RETRY;
}

#undef guest_walker
/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#define guest_walker guest_walker64

struct guest_walker {
	int level;
	unsigned max_level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t ptes[PT_MAX_FULL_LEVELS];
	pt_element_t prefetch_ptes[PTE_PREFETCH_NUM];
	gpa_t pte_gpa[PT_MAX_FULL_LEVELS];
	pt_element_t __user *ptep_user[PT_MAX_FULL_LEVELS];
	bool pte_writable[PT_MAX_FULL_LEVELS];
	unsigned int pt_access[PT_MAX_FULL_LEVELS];
	unsigned int pte_access;
	gfn_t gfn;
	struct x86_exception fault;
};

static bool
(*klpe_paging64_prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     u64 *spte, pt_element_t gpte, bool no_dirty_log);

static bool (*klpe_paging64_gpte_changed)(struct kvm_vcpu *vcpu,
				struct guest_walker *gw, int level);

static void klpr_paging64_pte_prefetch(struct kvm_vcpu *vcpu, struct guest_walker *gw,
				u64 *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	u64 *spte;
	int i;

	sp = page_header(__pa(sptep));

	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	if (sp->role.direct)
		return (*klpe___direct_pte_prefetch)(vcpu, sp, sptep);

	i = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (klpr_is_shadow_present_pte(*spte))
			continue;

		if (!(*klpe_paging64_prefetch_gpte)(vcpu, sp, spte, gptep[i], true))
			break;
	}
}

int klpp_paging64_fetch(struct kvm_vcpu *vcpu, gva_t addr,
			 struct guest_walker *gw,
			 int write_fault, int hlevel,
			 kvm_pfn_t pfn, bool map_writable, bool prefault,
			 bool lpage_disallowed)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	unsigned int direct_access, access;
	int top_level, ret;
	gfn_t gfn, base_gfn;

	direct_access = gw->pte_access;

	top_level = vcpu->arch.mmu.root_level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if ((*klpe_paging64_gpte_changed)(vcpu, gw, top_level))
		goto out_gpte_changed;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		goto out_gpte_changed;

	for ((*klpe_shadow_walk_init)(&it, vcpu, addr);
	     shadow_walk_okay(&it) && it.level > gw->level;
	     (*klpe_shadow_walk_next)(&it)) {
		gfn_t table_gfn;

		clear_sp_write_flooding_count(it.sptep);
		klpr_drop_large_spte(vcpu, it.sptep);

		if (klpr_is_shadow_present_pte(*it.sptep)) {
			struct kvm_mmu_page *child = page_header(*it.sptep & PT64_BASE_ADDR_MASK);
			struct kvm_mmu_page *parent_sp;

			if (!child || child->gfn != gw->table_gfn[it.level - 2] || child->role.direct != false) {
				parent_sp = page_header(__pa(it.sptep));
				WARN_ON_ONCE(parent_sp->role.level == PT_PAGE_TABLE_LEVEL);

				(*klpe_mmu_page_zap_pte)(vcpu->kvm, parent_sp, it.sptep);
				(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
			}
		}

		sp = NULL;
		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			table_gfn = gw->table_gfn[it.level - 2];
			access = gw->pt_access[it.level - 2];
			sp = (*klpe_kvm_mmu_get_page)(vcpu, table_gfn, addr, it.level-1,
					      false, access);
		}

		/*
		 * Verify that the gpte in the page we've just write
		 * protected is still there.
		 */
		if ((*klpe_paging64_gpte_changed)(vcpu, gw, it.level - 1))
			goto out_gpte_changed;

		if (sp)
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
	}

	/*
	 * FNAME(page_fault) might have clobbered the bottom bits of
	 * gw->gfn, restore them from the virtual address.
	 */
	gfn = gw->gfn | ((addr & PT_LVL_OFFSET_MASK(gw->level)) >> PAGE_SHIFT);
	base_gfn = gfn;

	klpr_trace_kvm_mmu_spte_requested(addr, gw->level, pfn);

	for (; shadow_walk_okay(&it); (*klpe_shadow_walk_next)(&it)) {
		clear_sp_write_flooding_count(it.sptep);

		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		klpr_disallowed_hugepage_adjust(it, gfn, &pfn, &hlevel);

		base_gfn = gfn & ~(KVM_PAGES_PER_HPAGE(it.level) - 1);
		if (it.level == hlevel)
			break;

		klpr_validate_direct_spte(vcpu, it.sptep, direct_access);

		klpr_drop_large_spte(vcpu, it.sptep);

		if (klpr_is_shadow_present_pte(*it.sptep)) {
			struct kvm_mmu_page *child = page_header(*it.sptep & PT64_BASE_ADDR_MASK);
			struct kvm_mmu_page *parent_sp;

			if (!child || child->gfn != base_gfn || child->role.direct != true) {
				parent_sp = page_header(__pa(it.sptep));
				WARN_ON_ONCE(parent_sp->role.level == PT_PAGE_TABLE_LEVEL);

				(*klpe_mmu_page_zap_pte)(vcpu->kvm, parent_sp, it.sptep);
				(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
			}
		}

		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			sp = (*klpe_kvm_mmu_get_page)(vcpu, base_gfn, addr,
					      it.level - 1, true, direct_access);
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
			if (lpage_disallowed)
				account_huge_nx_page(vcpu->kvm, sp);
		}
	}

	ret = (*klpe_mmu_set_spte)(vcpu, it.sptep, gw->pte_access, write_fault,
			   it.level, base_gfn, pfn, prefault, map_writable);
	klpr_paging64_pte_prefetch(vcpu, gw, it.sptep);
	++vcpu->stat.pf_fixed;
	return ret;

out_gpte_changed:
	return RET_PF_RETRY;
}

#undef pt_element_t
/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#define pt_element_t u32

/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#undef guest_walker
/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#define guest_walker guest_walker32

/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#undef PT_LVL_OFFSET_MASK
/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#define PT_LVL_OFFSET_MASK(lvl) PT32_LVL_OFFSET_MASK(lvl)

/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#undef PT_MAX_FULL_LEVELS
/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#define PT_MAX_FULL_LEVELS 2

struct guest_walker {
	int level;
	unsigned max_level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t ptes[PT_MAX_FULL_LEVELS];
	pt_element_t prefetch_ptes[PTE_PREFETCH_NUM];
	gpa_t pte_gpa[PT_MAX_FULL_LEVELS];
	pt_element_t __user *ptep_user[PT_MAX_FULL_LEVELS];
	bool pte_writable[PT_MAX_FULL_LEVELS];
	unsigned int pt_access[PT_MAX_FULL_LEVELS];
	unsigned int pte_access;
	gfn_t gfn;
	struct x86_exception fault;
};

static bool
(*klpe_paging32_prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     u64 *spte, pt_element_t gpte, bool no_dirty_log);

static bool (*klpe_paging32_gpte_changed)(struct kvm_vcpu *vcpu,
				struct guest_walker *gw, int level);

static void klpr_paging32_pte_prefetch(struct kvm_vcpu *vcpu, struct guest_walker *gw,
				u64 *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	u64 *spte;
	int i;

	sp = page_header(__pa(sptep));

	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	if (sp->role.direct)
		return (*klpe___direct_pte_prefetch)(vcpu, sp, sptep);

	i = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (klpr_is_shadow_present_pte(*spte))
			continue;

		if (!(*klpe_paging32_prefetch_gpte)(vcpu, sp, spte, gptep[i], true))
			break;
	}
}

int klpp_paging32_fetch(struct kvm_vcpu *vcpu, gva_t addr,
			 struct guest_walker *gw,
			 int write_fault, int hlevel,
			 kvm_pfn_t pfn, bool map_writable, bool prefault,
			 bool lpage_disallowed)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	unsigned int direct_access, access;
	int top_level, ret;
	gfn_t gfn, base_gfn;

	direct_access = gw->pte_access;

	top_level = vcpu->arch.mmu.root_level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if ((*klpe_paging32_gpte_changed)(vcpu, gw, top_level))
		goto out_gpte_changed;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		goto out_gpte_changed;

	for ((*klpe_shadow_walk_init)(&it, vcpu, addr);
	     shadow_walk_okay(&it) && it.level > gw->level;
	     (*klpe_shadow_walk_next)(&it)) {
		gfn_t table_gfn;

		clear_sp_write_flooding_count(it.sptep);
		klpr_drop_large_spte(vcpu, it.sptep);

		if (klpr_is_shadow_present_pte(*it.sptep)) {
			struct kvm_mmu_page *child = page_header(*it.sptep & PT64_BASE_ADDR_MASK);
			struct kvm_mmu_page *parent_sp;

			if (!child || child->gfn != gw->table_gfn[it.level - 2] || child->role.direct != false) {
				parent_sp = page_header(__pa(it.sptep));
				WARN_ON_ONCE(parent_sp->role.level == PT_PAGE_TABLE_LEVEL);

				(*klpe_mmu_page_zap_pte)(vcpu->kvm, parent_sp, it.sptep);
				(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
			}
		}

		sp = NULL;
		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			table_gfn = gw->table_gfn[it.level - 2];
			access = gw->pt_access[it.level - 2];
			sp = (*klpe_kvm_mmu_get_page)(vcpu, table_gfn, addr, it.level-1,
					      false, access);
		}

		/*
		 * Verify that the gpte in the page we've just write
		 * protected is still there.
		 */
		if ((*klpe_paging32_gpte_changed)(vcpu, gw, it.level - 1))
			goto out_gpte_changed;

		if (sp)
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
	}

	/*
	 * FNAME(page_fault) might have clobbered the bottom bits of
	 * gw->gfn, restore them from the virtual address.
	 */
	gfn = gw->gfn | ((addr & PT_LVL_OFFSET_MASK(gw->level)) >> PAGE_SHIFT);
	base_gfn = gfn;

	klpr_trace_kvm_mmu_spte_requested(addr, gw->level, pfn);

	for (; shadow_walk_okay(&it); (*klpe_shadow_walk_next)(&it)) {
		clear_sp_write_flooding_count(it.sptep);

		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		klpr_disallowed_hugepage_adjust(it, gfn, &pfn, &hlevel);

		base_gfn = gfn & ~(KVM_PAGES_PER_HPAGE(it.level) - 1);
		if (it.level == hlevel)
			break;

		klpr_validate_direct_spte(vcpu, it.sptep, direct_access);

		klpr_drop_large_spte(vcpu, it.sptep);

		if (klpr_is_shadow_present_pte(*it.sptep)) {
			struct kvm_mmu_page *child = page_header(*it.sptep & PT64_BASE_ADDR_MASK);
			struct kvm_mmu_page *parent_sp;

			if (!child || child->gfn != base_gfn || child->role.direct != true) {
				parent_sp = page_header(__pa(it.sptep));
				WARN_ON_ONCE(parent_sp->role.level == PT_PAGE_TABLE_LEVEL);

				(*klpe_mmu_page_zap_pte)(vcpu->kvm, parent_sp, it.sptep);
				(*klpe_kvm_flush_remote_tlbs)(vcpu->kvm);
			}
		}

		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			sp = (*klpe_kvm_mmu_get_page)(vcpu, base_gfn, addr,
					      it.level - 1, true, direct_access);
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
			if (lpage_disallowed)
				account_huge_nx_page(vcpu->kvm, sp);
		}
	}

	ret = (*klpe_mmu_set_spte)(vcpu, it.sptep, gw->pte_access, write_fault,
			   it.level, base_gfn, pfn, prefault, map_writable);
	klpr_paging32_pte_prefetch(vcpu, gw, it.sptep);
	++vcpu->stat.pf_fixed;
	return ret;

out_gpte_changed:
	return RET_PF_RETRY;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "kvm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__direct_pte_prefetch", (void *)&klpe___direct_pte_prefetch,
	  "kvm" },
	{ "__tracepoint_kvm_mmu_spte_requested",
	  (void *)&klpe___tracepoint_kvm_mmu_spte_requested, "kvm" },
	{ "drop_spte", (void *)&klpe_drop_spte, "kvm" },
	{ "ept_gpte_changed", (void *)&klpe_ept_gpte_changed, "kvm" },
	{ "ept_prefetch_gpte", (void *)&klpe_ept_prefetch_gpte, "kvm" },
	{ "kvm_flush_remote_tlbs", (void *)&klpe_kvm_flush_remote_tlbs,
	  "kvm" },
	{ "kvm_mmu_get_page", (void *)&klpe_kvm_mmu_get_page, "kvm" },
	{ "link_shadow_page", (void *)&klpe_link_shadow_page, "kvm" },
	{ "mmu_page_zap_pte", (void *)&klpe_mmu_page_zap_pte, "kvm" },
	{ "mmu_set_spte", (void *)&klpe_mmu_set_spte, "kvm" },
	{ "nx_huge_pages", (void *)&klpe_nx_huge_pages, "kvm" },
	{ "paging32_gpte_changed", (void *)&klpe_paging32_gpte_changed,
	  "kvm" },
	{ "paging32_prefetch_gpte", (void *)&klpe_paging32_prefetch_gpte,
	  "kvm" },
	{ "paging64_gpte_changed", (void *)&klpe_paging64_gpte_changed,
	  "kvm" },
	{ "paging64_prefetch_gpte", (void *)&klpe_paging64_prefetch_gpte,
	  "kvm" },
	{ "pte_list_remove", (void *)&klpe_pte_list_remove, "kvm" },
	{ "shadow_mmio_mask", (void *)&klpe_shadow_mmio_mask, "kvm" },
	{ "shadow_mmio_value", (void *)&klpe_shadow_mmio_value, "kvm" },
	{ "shadow_walk_init", (void *)&klpe_shadow_walk_init, "kvm" },
	{ "shadow_walk_next", (void *)&klpe_shadow_walk_next, "kvm" },
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

int livepatch_bsc1270060_init(void)
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

void livepatch_bsc1270060_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_X86) */
