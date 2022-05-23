/*
 * livepatch_bsc1189278
 *
 * Fix for CVE-2021-38198, bsc#1189278
 *
 *  Upstream commit:
 *  b1bd5cba3306 ("KVM: X86: MMU: Use the correct inherited permissions to get
 *                 shadow page")
 *
 *  SLE12-SP3 commit:
 *  07db41a66b3d7c9f8d3fc3487c43d349fcd77a1b
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  41b872da6e79a89c0544a9a6fe7175e86f06bdd4
 *
 *  SLE15-SP2 and -SP3 commit:
 *  1a0a225f892118e5ca56e5d299f9e5cdb685acc6
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

#if IS_ENABLED(CONFIG_X86_64)

#if !IS_MODULE(CONFIG_KVM)
#error "Live patch supports only CONFIG_KVM=m"
#endif

#include <linux/kernel.h>
#include <linux/tracepoint.h>

/* from include/linux/tracepoint.h */
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static struct tracepoint (*klpe___tracepoint_##name);		\
	static inline void klpr_trace_##name(proto)			\
	{								\
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key))) \
			__DO_TRACE(&(*klpe___tracepoint_##name),	\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond), 0);		\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs); \
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\

#define KLPR_DECLARE_TRACE(name, proto, args)				\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KLPR_TRACE_EVENT(name, proto, args)	\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))


/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/include/asm/kvm_host.h */
static struct kvm_x86_ops *(*klpe_kvm_x86_ops);

/* klp-ccp: from include/linux/kvm_host.h */
static void (*klpe_kvm_release_page_dirty)(struct page *page);

static void (*klpe_kvm_release_pfn_clean)(kvm_pfn_t pfn);

static unsigned long (*klpe_kvm_vcpu_gfn_to_hva_prot)(struct kvm_vcpu *vcpu, gfn_t gfn, bool *writable);

static int (*klpe_kvm_vcpu_read_guest_atomic)(struct kvm_vcpu *vcpu, gpa_t gpa, void *data,
			       unsigned long len);

static void (*klpe_kvm_vcpu_mark_page_dirty)(struct kvm_vcpu *vcpu, gfn_t gfn);

static void (*klpe_kvm_flush_remote_tlbs)(struct kvm *kvm);

/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/spinlock.h>

/* klp-ccp: from arch/x86/kvm/ioapic.h */
#include <linux/kvm_host.h>
#include <kvm/iodev.h>

#define ASSERT(x) do { } while (0)

/* klp-ccp: from arch/x86/kvm/lapic.h */
#include <kvm/iodev.h>
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/mmu.h */
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/kvm_cache_regs.h */
#define KVM_POSSIBLE_CR0_GUEST_BITS X86_CR0_TS
#define KVM_POSSIBLE_CR4_GUEST_BITS				  \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR  \
	 | X86_CR4_OSXMMEXCPT | X86_CR4_LA57 | X86_CR4_PGE)

static inline ulong klpr_kvm_read_cr0_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR0_GUEST_BITS;
	if (tmask & vcpu->arch.cr0_guest_owned_bits)
		(*klpe_kvm_x86_ops)->decache_cr0_guest_bits(vcpu);
	return vcpu->arch.cr0 & mask;
}

static inline ulong klpr_kvm_read_cr4_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR4_GUEST_BITS;
	if (tmask & vcpu->arch.cr4_guest_owned_bits)
		(*klpe_kvm_x86_ops)->decache_cr4_guest_bits(vcpu);
	return vcpu->arch.cr4 & mask;
}

/* klp-ccp: from arch/x86/kvm/mmu.h */
#define PT_WRITABLE_SHIFT 1
#define PT_USER_SHIFT 2

#define PT_PRESENT_MASK (1ULL << 0)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << PT_USER_SHIFT)

#define PT_ACCESSED_SHIFT 5

#define PT_DIRTY_SHIFT 6

#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)

#define PT64_NX_SHIFT 63

#define PT32_DIR_PSE36_SIZE 4
#define PT32_DIR_PSE36_SHIFT 13
#define PT32_DIR_PSE36_MASK \
	(((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)

#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define PT_DIRECTORY_LEVEL 2
#define PT_PAGE_TABLE_LEVEL 1

static inline unsigned long kvm_mmu_available_pages(struct kvm *kvm)
{
	if (kvm->arch.n_max_mmu_pages > kvm->arch.n_used_mmu_pages)
		return kvm->arch.n_max_mmu_pages -
			kvm->arch.n_used_mmu_pages;

	return 0;
}

static inline bool klpr_is_write_protection(struct kvm_vcpu *vcpu)
{
	return klpr_kvm_read_cr0_bits(vcpu, X86_CR0_WP);
}

static inline u8 klpr_permission_fault(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				  unsigned pte_access, unsigned pte_pkey,
				  unsigned pfec)
{
	int cpl = (*klpe_kvm_x86_ops)->get_cpl(vcpu);
	unsigned long rflags = (*klpe_kvm_x86_ops)->get_rflags(vcpu);

	/*
	 * If CPL < 3, SMAP prevention are disabled if EFLAGS.AC = 1.
	 *
	 * If CPL = 3, SMAP applies to all supervisor-mode data accesses
	 * (these are implicit supervisor accesses) regardless of the value
	 * of EFLAGS.AC.
	 *
	 * This computes (cpl < 3) && (rflags & X86_EFLAGS_AC), leaving
	 * the result in X86_EFLAGS_AC. We then insert it in place of
	 * the PFERR_RSVD_MASK bit; this bit will always be zero in pfec,
	 * but it will be one in index if SMAP checks are being overridden.
	 * It is important to keep this branchless.
	 */
	unsigned long smap = (cpl - 3) & (rflags & X86_EFLAGS_AC);
	int index = (pfec >> 1) +
		    (smap >> (X86_EFLAGS_AC_BIT - PFERR_RSVD_BIT + 1));
	bool fault = (mmu->permissions[index] >> pte_access) & 1;
	u32 errcode = PFERR_PRESENT_MASK;

	WARN_ON(pfec & (PFERR_PK_MASK | PFERR_RSVD_MASK));
	if (unlikely(mmu->pkru_mask)) {
		u32 pkru_bits, offset;

		/*
		* PKRU defines 32 bits, there are 16 domains and 2
		* attribute bits per domain in pkru.  pte_pkey is the
		* index of the protection domain, so pte_pkey * 2 is
		* is the index of the first bit for the domain.
		*/
		pkru_bits = (vcpu->arch.pkru >> (pte_pkey * 2)) & 3;

		/* clear present bit, replace PFEC.RSVD with ACC_USER_MASK. */
		offset = (pfec & ~1) +
			((pte_access & PT_USER_MASK) << (PFERR_RSVD_BIT - PT_USER_SHIFT));

		pkru_bits &= mmu->pkru_mask >> offset;
		errcode |= -pkru_bits & PFERR_PK_MASK;
		fault |= (pkru_bits != 0);
	}

	return -(u32)fault & errcode;
}

static int (*klpe_kvm_arch_write_log_dirty)(struct kvm_vcpu *vcpu);

/* klp-ccp: from arch/x86/kvm/x86.h */
#include <asm/processor.h>
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/cpuid.h */
#include <asm/processor.h>
/* klp-ccp: from arch/x86/kvm/mmu.c */
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/compiler.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/kern_levels.h>
#include <asm/page.h>
#include <asm/pat.h>
#include <asm/cmpxchg.h>
#include <asm/io.h>
#include <asm/vmx.h>

/* klp-ccp: from arch/x86/kvm/mmu.c */
#include <asm/kvm_page_track.h>

/* klp-ccp: from arch/x86/kvm/trace.h */
#include <linux/tracepoint.h>
#include <asm/vmx.h>
#include <asm/clocksource.h>
#include <asm/pvclock-abi.h>

/* klp-ccp: from arch/x86/kvm/mmu.c */
static int __read_mostly (*klpe_nx_huge_pages);

enum {
	AUDIT_PRE_PAGE_FAULT,
	AUDIT_POST_PAGE_FAULT,
	AUDIT_PRE_PTE_WRITE,
	AUDIT_POST_PTE_WRITE,
	AUDIT_PRE_SYNC,
	AUDIT_POST_SYNC
};

#define pgprintk(x...) do { } while (0)

#define PTE_PREFETCH_NUM		8

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))

#define PT32_LEVEL_BITS 10

#define PT32_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT32_LEVEL_BITS)

#define PT32_LVL_OFFSET_MASK(level) \
	(PT32_BASE_ADDR_MASK & ((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT32_LEVEL_BITS))) - 1))

#define PT32_INDEX(address, level)\
	(((address) >> PT32_LEVEL_SHIFT(level)) & ((1 << PT32_LEVEL_BITS) - 1))

#define PT64_BASE_ADDR_MASK __sme_clr((((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1)))

#define PT64_LVL_ADDR_MASK(level) \
	(PT64_BASE_ADDR_MASK & ~((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT64_LEVEL_BITS))) - 1))
#define PT64_LVL_OFFSET_MASK(level) \
	(PT64_BASE_ADDR_MASK & ((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT64_LEVEL_BITS))) - 1))

#define PT32_BASE_ADDR_MASK PAGE_MASK

#define PT32_LVL_ADDR_MASK(level) \
	(PAGE_MASK & ~((1ULL << (PAGE_SHIFT + (((level) - 1) \
					    * PT32_LEVEL_BITS))) - 1))

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK

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

/* klp-ccp: from arch/x86/kvm/mmutrace.h */
KLPR_TRACE_EVENT(
	kvm_mmu_pagetable_walk,
	TP_PROTO(u64 addr, u32 pferr),
	TP_ARGS(addr, pferr)
);

KLPR_TRACE_EVENT(
	kvm_mmu_paging_element,
	TP_PROTO(u64 pte, int level),
	TP_ARGS(pte, level)
);

static void (*klpe_trace_kvm_mmu_set_accessed_bit)(unsigned long table_gfn, unsigned index, unsigned size);

static void (*klpe_trace_kvm_mmu_set_dirty_bit)(unsigned long table_gfn, unsigned index, unsigned size);

KLPR_TRACE_EVENT(
	kvm_mmu_walker_error,
	TP_PROTO(u32 pferr),
	TP_ARGS(pferr)
);

KLPR_TRACE_EVENT(
	kvm_mmu_spte_requested,
	TP_PROTO(gpa_t addr, int level, kvm_pfn_t pfn),
	TP_ARGS(addr, level, pfn)
);

/* klp-ccp: from arch/x86/kvm/mmu.c */
static bool klpr_is_nx_huge_page_enabled(void)
{
	return READ_ONCE((*klpe_nx_huge_pages));
}

static bool klpr_is_mmio_spte(u64 spte)
{
	return (spte & (*klpe_shadow_mmio_mask)) == (*klpe_shadow_mmio_value);
}

static int is_cpuid_PSE36(void)
{
	return 1;
}

static int klpr_is_shadow_present_pte(u64 pte)
{
	return (pte != 0) && !klpr_is_mmio_spte(pte);
}

static int is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static int is_last_spte(u64 pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return 1;
	if (is_large_pte(pte))
		return 1;
	return 0;
}

static gfn_t pse36_gfn_delta(u32 gpte)
{
	int shift = 32 - PT32_DIR_PSE36_SHIFT - PAGE_SHIFT;

	return (gpte & PT32_DIR_PSE36_MASK) << shift;
}

#ifdef CONFIG_X86_64

static void __update_clear_spte_fast(u64 *sptep, u64 spte)
{
	WRITE_ONCE(*sptep, spte);
}

static u64 __get_spte_lockless(u64 *sptep)
{
	return READ_ONCE(*sptep);
}
#else
#error "klp-ccp: non-taken branch"
#endif

static void mmu_spte_clear_no_track(u64 *sptep)
{
	__update_clear_spte_fast(sptep, 0ull);
}

static u64 mmu_spte_get_lockless(u64 *sptep)
{
	return __get_spte_lockless(sptep);
}

static void walk_shadow_page_lockless_begin(struct kvm_vcpu *vcpu)
{
	/*
	 * Prevent page table teardown by making any free-er wait during
	 * kvm_flush_remote_tlbs() IPI to all active vcpus.
	 */
	local_irq_disable();

	/*
	 * Make sure a following spte read is not reordered ahead of the write
	 * to vcpu->mode.
	 */
	smp_store_mb(vcpu->mode, READING_SHADOW_PAGE_TABLES);
}

static void walk_shadow_page_lockless_end(struct kvm_vcpu *vcpu)
{
	/*
	 * Make sure the write to vcpu->mode is not reordered in front of
	 * reads to sptes.  If it does, kvm_commit_zap_page() can see us
	 * OUTSIDE_GUEST_MODE and proceed to free the shadow page table.
	 */
	smp_store_release(&vcpu->mode, OUTSIDE_GUEST_MODE);
	local_irq_enable();
}

static int (*klpe_mmu_topup_memory_caches)(struct kvm_vcpu *vcpu);

static void account_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	if (sp->lpage_disallowed)
		return;

	++kvm->stat.nx_lpage_splits;
	list_add_tail(&sp->lpage_disallowed_link,
		      &kvm->arch.lpage_disallowed_mmu_pages);
	sp->lpage_disallowed = true;
}

static int (*klpe_mapping_level)(struct kvm_vcpu *vcpu, gfn_t large_gfn,
			 bool *force_pt_level);

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

static int (*klpe_kvm_mmu_prepare_zap_page)(struct kvm *kvm, struct kvm_mmu_page *sp,
				    struct list_head *invalid_list);
static void (*klpe_kvm_mmu_commit_zap_page)(struct kvm *kvm,
				    struct list_head *invalid_list);

#ifdef CONFIG_KVM_MMU_AUDIT

/* klp-ccp: from arch/x86/kvm/mmu_audit.c */
#include <linux/ratelimit.h>

static struct static_key (*klpe_mmu_audit_key);

static void (*klpe___kvm_mmu_audit)(struct kvm_vcpu *vcpu, int point);

/* klp-ccp: from arch/x86/kvm/mmu_audit.c */
static inline void klpr_kvm_mmu_audit(struct kvm_vcpu *vcpu, int point)
{
	if (static_key_enabled(&(*klpe_mmu_audit_key)))
		(*klpe___kvm_mmu_audit)(vcpu, point);
}

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

static void __shadow_walk_next(struct kvm_shadow_walk_iterator *iterator,
			       u64 spte)
{
	if (is_last_spte(spte, iterator->level)) {
		iterator->level = 0;
		return;
	}

	iterator->shadow_addr = spte & PT64_BASE_ADDR_MASK;
	--iterator->level;
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

static int (*klpe_kvm_mmu_prepare_zap_page)(struct kvm *kvm, struct kvm_mmu_page *sp,
				    struct list_head *invalid_list);

static void (*klpe_kvm_mmu_commit_zap_page)(struct kvm *kvm,
				    struct list_head *invalid_list);

static bool klpr_prepare_zap_oldest_mmu_page(struct kvm *kvm,
					struct list_head *invalid_list)
{
	struct kvm_mmu_page *sp;

	if (list_empty(&kvm->arch.active_mmu_pages))
		return false;

	sp = list_last_entry(&kvm->arch.active_mmu_pages,
			     struct kvm_mmu_page, link);
	return (*klpe_kvm_mmu_prepare_zap_page)(kvm, sp, invalid_list);
}

static int (*klpe_mmu_set_spte)(struct kvm_vcpu *vcpu, u64 *sptep, unsigned pte_access,
			int write_fault, int level, gfn_t gfn, kvm_pfn_t pfn,
		       	bool speculative, bool host_writable);

static void (*klpe___direct_pte_prefetch)(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *sptep);

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

static void (*klpe_transparent_hugepage_adjust)(struct kvm_vcpu *vcpu,
					gfn_t gfn, kvm_pfn_t *pfnp,
					int *levelp);

static bool (*klpe_handle_abnormal_pfn)(struct kvm_vcpu *vcpu, gva_t gva, gfn_t gfn,
				kvm_pfn_t pfn, unsigned access, int *ret_val);

static bool (*klpe_try_async_pf)(struct kvm_vcpu *vcpu, bool prefault, gfn_t gfn,
			 gva_t gva, kvm_pfn_t *pfn, bool write, bool *writable);
static int klpr_make_mmu_pages_available(struct kvm_vcpu *vcpu);

static bool
__is_rsvd_bits_set(struct rsvd_bits_validate *rsvd_check, u64 pte, int level)
{
	int bit7 = (pte >> 7) & 1, low6 = pte & 0x3f;

	return (pte & rsvd_check->rsvd_bits_mask[bit7][level-1]) |
		((rsvd_check->bad_mt_xwr & (1ull << low6)) != 0);
}

static bool is_rsvd_bits_set(struct kvm_mmu *mmu, u64 gpte, int level)
{
	return __is_rsvd_bits_set(&mmu->guest_rsvd_check, gpte, level);
}

static bool (*klpe_page_fault_handle_page_track)(struct kvm_vcpu *vcpu,
					 u32 error_code, gfn_t gfn);

static void klpr_shadow_page_table_clear_flood(struct kvm_vcpu *vcpu, gva_t addr)
{
	struct kvm_shadow_walk_iterator iterator;
	u64 spte;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		return;

	walk_shadow_page_lockless_begin(vcpu);
	for ((*klpe_shadow_walk_init)(&(iterator), vcpu, addr); shadow_walk_okay(&(iterator)) && ({ spte = mmu_spte_get_lockless(iterator.sptep); 1; }); __shadow_walk_next(&(iterator), spte)) {
		clear_sp_write_flooding_count(iterator.sptep);
		if (!klpr_is_shadow_present_pte(spte))
			break;
	}
	walk_shadow_page_lockless_end(vcpu);
}

static bool (*klpe_try_async_pf)(struct kvm_vcpu *vcpu, bool prefault, gfn_t gfn,
			 gva_t gva, kvm_pfn_t *pfn, bool write, bool *writable);

static void inject_page_fault(struct kvm_vcpu *vcpu,
			      struct x86_exception *fault)
{
	vcpu->arch.mmu.inject_page_fault(vcpu, fault);
}

static inline bool is_last_gpte(struct kvm_mmu *mmu,
				unsigned level, unsigned gpte)
{
	/*
	 * The RHS has bit 7 set iff level < mmu->last_nonleaf_level.
	 * If it is clear, there are no large pages at this level, so clear
	 * PT_PAGE_SIZE_MASK in gpte if that is the case.
	 */
	gpte &= level - mmu->last_nonleaf_level;

	/*
	 * PT_PAGE_TABLE_LEVEL always terminates.  The RHS has bit 7 set
	 * iff level <= PT_PAGE_TABLE_LEVEL, which for our purpose means
	 * level == PT_PAGE_TABLE_LEVEL; set PT_PAGE_SIZE_MASK in gpte then.
	 */
	gpte |= level - PT_PAGE_TABLE_LEVEL - 1;

	return gpte & PT_PAGE_SIZE_MASK;
}

#define PTTYPE_EPT 18 /* arbitrary */
#define PTTYPE PTTYPE_EPT
#include "bsc1189278_paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 64
#include "bsc1189278_paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 32
#include "bsc1189278_paging_tmpl.h"
#undef PTTYPE

/* klp-ccp: from arch/x86/kvm/mmu.c */
static int klpr_make_mmu_pages_available(struct kvm_vcpu *vcpu)
{
	LIST_HEAD(invalid_list);

	if (likely(kvm_mmu_available_pages(vcpu->kvm) >= KVM_MIN_FREE_MMU_PAGES))
		return 0;

	while (kvm_mmu_available_pages(vcpu->kvm) < KVM_REFILL_PAGES) {
		if (!klpr_prepare_zap_oldest_mmu_page(vcpu->kvm, &invalid_list))
			break;

		++vcpu->kvm->stat.mmu_recycled;
	}
	(*klpe_kvm_mmu_commit_zap_page)(vcpu->kvm, &invalid_list);

	if (!kvm_mmu_available_pages(vcpu->kvm))
		return -ENOSPC;
	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1189278.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "kvm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "kvm_x86_ops", (void *)&klpe_kvm_x86_ops, "kvm" },
	{ "nx_huge_pages", (void *)&klpe_nx_huge_pages, "kvm" },
	{ "shadow_mmio_value", (void *)&klpe_shadow_mmio_value, "kvm" },
	{ "shadow_mmio_mask", (void *)&klpe_shadow_mmio_mask, "kvm" },
	{ "__tracepoint_kvm_mmu_paging_element",
	  (void *)&klpe___tracepoint_kvm_mmu_paging_element, "kvm" },
	{ "__tracepoint_kvm_mmu_pagetable_walk",
	  (void *)&klpe___tracepoint_kvm_mmu_pagetable_walk, "kvm" },
	{ "__tracepoint_kvm_mmu_walker_error",
	  (void *)&klpe___tracepoint_kvm_mmu_walker_error, "kvm" },
	{ "__tracepoint_kvm_mmu_spte_requested",
	  (void *)&klpe___tracepoint_kvm_mmu_spte_requested, "kvm" },
	{ "mmu_audit_key", (void *)&klpe_mmu_audit_key, "kvm" },
	{ "kvm_vcpu_mark_page_dirty", (void *)&klpe_kvm_vcpu_mark_page_dirty,
	  "kvm" },
	{ "kvm_release_page_dirty", (void *)&klpe_kvm_release_page_dirty,
	  "kvm" },
	{ "kvm_release_pfn_clean", (void *)&klpe_kvm_release_pfn_clean, "kvm" },
	{ "kvm_vcpu_gfn_to_hva_prot", (void *)&klpe_kvm_vcpu_gfn_to_hva_prot,
	  "kvm" },
	{ "kvm_vcpu_read_guest_atomic",
	  (void *)&klpe_kvm_vcpu_read_guest_atomic, "kvm" },
	{ "kvm_flush_remote_tlbs", (void *)&klpe_kvm_flush_remote_tlbs, "kvm" },
	{ "kvm_arch_write_log_dirty", (void *)&klpe_kvm_arch_write_log_dirty,
	  "kvm" },
	{ "trace_kvm_mmu_set_accessed_bit",
	  (void *)&klpe_trace_kvm_mmu_set_accessed_bit, "kvm" },
	{ "trace_kvm_mmu_set_dirty_bit",
	  (void *)&klpe_trace_kvm_mmu_set_dirty_bit, "kvm" },
	{ "mmu_topup_memory_caches", (void *)&klpe_mmu_topup_memory_caches,
	  "kvm" },
	{ "drop_spte", (void *)&klpe_drop_spte, "kvm" },
	{ "mapping_level", (void *)&klpe_mapping_level, "kvm" },
	{ "pte_list_remove", (void *)&klpe_pte_list_remove, "kvm" },
	{ "kvm_mmu_prepare_zap_page", (void *)&klpe_kvm_mmu_prepare_zap_page,
	  "kvm" },
	{ "kvm_mmu_commit_zap_page", (void *)&klpe_kvm_mmu_commit_zap_page,
	  "kvm" },
	{ "__kvm_mmu_audit", (void *)&klpe___kvm_mmu_audit, "kvm" },
	{ "shadow_walk_next", (void *)&klpe_shadow_walk_next, "kvm" },
	{ "shadow_walk_init", (void *)&klpe_shadow_walk_init, "kvm" },
	{ "kvm_mmu_get_page", (void *)&klpe_kvm_mmu_get_page, "kvm" },
	{ "link_shadow_page", (void *)&klpe_link_shadow_page, "kvm" },
	{ "mmu_set_spte", (void *)&klpe_mmu_set_spte, "kvm" },
	{ "transparent_hugepage_adjust",
	  (void *)&klpe_transparent_hugepage_adjust, "kvm" },
	{ "__direct_pte_prefetch", (void *)&klpe___direct_pte_prefetch, "kvm" },
	{ "handle_abnormal_pfn", (void *)&klpe_handle_abnormal_pfn, "kvm" },
	{ "try_async_pf", (void *)&klpe_try_async_pf, "kvm" },
	{ "page_fault_handle_page_track",
	  (void *)&klpe_page_fault_handle_page_track, "kvm" },
	{ "ept_prefetch_gpte", (void *)&klpe_ept_prefetch_gpte, "kvm" },
	{ "paging64_prefetch_gpte", (void *)&klpe_paging64_prefetch_gpte,
	  "kvm" },
	{ "paging32_prefetch_gpte", (void *)&klpe_paging32_prefetch_gpte,
	  "kvm" }
};

static int livepatch_bsc1189278_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1189278_module_nb = {
	.notifier_call = livepatch_bsc1189278_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1189278_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1189278_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1189278_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1189278_module_nb);
}

#endif /* IS_ENABLED(CONFIG_X86_64) */
