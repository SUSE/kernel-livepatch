/*
 * livepatch_bsc1266970
 *
 * Fix for CVE-2026-46113, bsc#1266970
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

#include "livepatch_bsc1266970.h"

/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>

#include <kvm/iodev.h>

/* klp-ccp: from arch/x86/kvm/lapic.h */
#include <kvm/iodev.h>

#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/hyperv.h */
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/x86.h */
#include <linux/kvm_host.h>
#include <asm/fpu/xstate.h>
#include <asm/mce.h>
#include <asm/pvclock.h>

/* klp-ccp: from arch/x86/kvm/kvm_cache_regs.h */
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/kvm_emulate.h */
#include <asm/desc_defs.h>

/* klp-ccp: from arch/x86/kvm/fpu.h */
#include <asm/fpu/api.h>

/* klp-ccp: from arch/x86/kvm/kvm_emulate.h */
struct x86_exception {
	u8 vector;
	bool error_code_valid;
	u16 error_code;
	bool nested_page_fault;
	u64 address; /* cr2 or nested page fault gpa */
	u8 async_page_fault;
	unsigned long exit_qualification;
};

/* klp-ccp: from arch/x86/kvm/reverse_cpuid.h */
#include <uapi/asm/kvm.h>
#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>

/* klp-ccp: from arch/x86/kvm/cpuid.h */
#include <asm/cpu.h>
#include <asm/processor.h>
#include <uapi/asm/kvm_para.h>

/* klp-ccp: from arch/x86/kvm/smm.h */
#include <linux/build_bug.h>

/* klp-ccp: from arch/x86/kvm/ioapic.h */
#include <linux/kvm_host.h>
#include <kvm/iodev.h>

/* klp-ccp: from arch/x86/kvm/mmu.h */
#include <linux/kvm_host.h>

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

#define PT64_ROOT_4LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

/* klp-ccp: from arch/x86/kvm/mmu/mmu_internal.h */
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <asm/kvm_host.h>

#define KVM_MMU_WARN_ON(x) BUILD_BUG_ON_INVALID(x)

#define __PT_BASE_ADDR_MASK GENMASK_ULL(51, 12)
#define __PT_LEVEL_SHIFT(level, bits_per_level)	\
	(PAGE_SHIFT + ((level) - 1) * (bits_per_level))
#define __PT_INDEX(address, level, bits_per_level) \
	(((address) >> __PT_LEVEL_SHIFT(level, bits_per_level)) & ((1 << (bits_per_level)) - 1))

#define __PT_LVL_ADDR_MASK(base_addr_mask, level, bits_per_level) \
	((base_addr_mask) & ~((1ULL << (PAGE_SHIFT + (((level) - 1) * (bits_per_level)))) - 1))

#define __PT_ENT_PER_PAGE(bits_per_level)  (1 << (bits_per_level))

static inline bool kvm_mmu_is_dummy_root(hpa_t shadow_page)
{
	return is_zero_pfn(shadow_page >> PAGE_SHIFT);
}

typedef u64 __rcu *tdp_ptep_t;

struct kvm_mmu_page {
	/*
	 * Note, "link" through "spt" fit in a single 64 byte cache line on
	 * 64-bit kernels, keep it that way unless there's a reason not to.
	 */
	struct list_head link;
	struct hlist_node hash_link;

	bool tdp_mmu_page;
	bool unsync;
	union {
		u8 mmu_valid_gen;

		/* Only accessed under slots_lock.  */
		bool tdp_mmu_scheduled_root_to_zap;
	};

	 /*
	  * The shadow page can't be replaced by an equivalent huge page
	  * because it is being used to map an executable page in the guest
	  * and the NX huge page mitigation is enabled.
	  */
	bool nx_huge_page_disallowed;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	union kvm_mmu_page_role role;
	gfn_t gfn;

	u64 *spt;

	/*
	 * Stores the result of the guest translation being shadowed by each
	 * SPTE.  KVM shadows two types of guest translations: nGPA -> GPA
	 * (shadow EPT/NPT) and GVA -> GPA (traditional shadow paging). In both
	 * cases the result of the translation is a GPA and a set of access
	 * constraints.
	 *
	 * The GFN is stored in the upper bits (PAGE_SHIFT) and the shadowed
	 * access permissions are stored in the lower bits. Note, for
	 * convenience and uniformity across guests, the access permissions are
	 * stored in KVM format (e.g.  ACC_EXEC_MASK) not the raw guest format.
	 */
	u64 *shadowed_translation;

	/* Currently serving as active root */
	union {
		int root_count;
		refcount_t tdp_mmu_root_count;
	};
	unsigned int unsync_children;
	union {
		struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */
		tdp_ptep_t ptep;
	};
	DECLARE_BITMAP(unsync_child_bitmap, 512);

	/*
	 * Tracks shadow pages that, if zapped, would allow KVM to create an NX
	 * huge page.  A shadow page will have nx_huge_page_disallowed set but
	 * not be on the list if a huge page is disallowed for other reasons,
	 * e.g. because KVM is shadowing a PTE at the same gfn, the memslot
	 * isn't properly aligned, etc...
	 */
	struct list_head possible_nx_huge_page_link;
#ifdef CONFIG_X86_32
#error "klp-ccp: non-taken branch"
#endif
	atomic_t write_flooding_count;

#ifdef CONFIG_X86_64
	struct rcu_head rcu_head;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

static inline gfn_t gfn_round_for_level(gfn_t gfn, int level)
{
	return gfn & -KVM_PAGES_PER_HPAGE(level);
}

struct kvm_page_fault {
	/* arguments to kvm_mmu_do_page_fault.  */
	const gpa_t addr;
	const u64 error_code;
	const bool prefetch;

	/* Derived from error_code.  */
	const bool exec;
	const bool write;
	const bool present;
	const bool rsvd;
	const bool user;

	/* Derived from mmu and global state.  */
	const bool is_tdp;
	const bool is_private;
	const bool nx_huge_page_workaround_enabled;

	/*
	 * Whether a >4KB mapping can be created or is forbidden due to NX
	 * hugepages.
	 */
	bool huge_page_disallowed;

	/*
	 * Maximum page size that can be created for this fault; input to
	 * FNAME(fetch), direct_map() and kvm_tdp_mmu_map().
	 */
	u8 max_level;

	/*
	 * Page size that can be created based on the max_level and the
	 * page size used by the host mapping.
	 */
	u8 req_level;

	/*
	 * Page size that will be created based on the req_level and
	 * huge_page_disallowed.
	 */
	u8 goal_level;

	/* Shifted addr, or result of guest page table walk if addr is a gva.  */
	gfn_t gfn;

	/* The memslot containing gfn. May be NULL. */
	struct kvm_memory_slot *slot;

	/* Outputs of kvm_faultin_pfn.  */
	unsigned long mmu_seq;
	kvm_pfn_t pfn;
	hva_t hva;
	bool map_writable;

	/*
	 * Indicates the guest is trying to write a gfn that contains one or
	 * more of the PTEs used to translate the write itself, i.e. the access
	 * is changing its own translation in the guest page tables.
	 */
	bool write_fault_to_shadow_pgtable;
};

enum {
	RET_PF_CONTINUE = 0,
	RET_PF_RETRY,
	RET_PF_EMULATE,
	RET_PF_WRITE_PROTECTED,
	RET_PF_INVALID,
	RET_PF_FIXED,
	RET_PF_SPURIOUS,
};

void kvm_mmu_hugepage_adjust(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
void disallowed_hugepage_adjust(struct kvm_page_fault *fault, u64 spte, int cur_level);

void track_possible_nx_huge_page(struct kvm *kvm, struct kvm_mmu_page *sp);

/* klp-ccp: from arch/x86/kvm/mmu/tdp_mmu.h */
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/mmu/spte.h */
#include <asm/vmx.h>

#define SPTE_MMU_PRESENT_MASK		BIT_ULL(11)

#define SPTE_BASE_ADDR_MASK (physical_mask & ~(u64)(PAGE_SIZE-1))

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#define SPTE_LEVEL_BITS			9

#define SPTE_INDEX(address, level)	__PT_INDEX(address, level, SPTE_LEVEL_BITS)
#define SPTE_ENT_PER_PAGE		__PT_ENT_PER_PAGE(SPTE_LEVEL_BITS)

#define SHADOW_NONPRESENT_VALUE	BIT_ULL(63)

static inline int spte_index(u64 *sptep)
{
	return ((unsigned long)sptep / sizeof(*sptep)) & (SPTE_ENT_PER_PAGE - 1);
}

static inline struct kvm_mmu_page *to_shadow_page(hpa_t shadow_page)
{
	struct page *page = pfn_to_page((shadow_page) >> PAGE_SHIFT);

	return (struct kvm_mmu_page *)page_private(page);
}

static inline struct kvm_mmu_page *spte_to_child_sp(u64 spte)
{
	return to_shadow_page(spte & SPTE_BASE_ADDR_MASK);
}

static inline struct kvm_mmu_page *sptep_to_sp(u64 *sptep)
{
	return to_shadow_page(__pa(sptep));
}

static inline bool is_shadow_present_pte(u64 pte)
{
	return !!(pte & SPTE_MMU_PRESENT_MASK);
}

extern u64 __read_mostly shadow_present_mask;

static inline bool is_ept_ve_possible(u64 spte)
{
	return (shadow_present_mask & VMX_EPT_SUPPRESS_VE_BIT) &&
	       !(spte & VMX_EPT_SUPPRESS_VE_BIT) &&
	       (spte & VMX_EPT_RWX_MASK) != VMX_EPT_MISCONFIG_WX_VALUE;
}

static inline bool sp_ad_disabled(struct kvm_mmu_page *sp)
{
	return sp->role.ad_disabled;
}

static inline bool is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static inline u64 get_rsvd_bits(struct rsvd_bits_validate *rsvd_check, u64 pte,
				int level)
{
	int bit7 = (pte >> 7) & 1;

	return rsvd_check->rsvd_bits_mask[bit7][level-1];
}

static inline bool __is_rsvd_bits_set(struct rsvd_bits_validate *rsvd_check,
				      u64 pte, int level)
{
	return pte & get_rsvd_bits(rsvd_check, pte, level);
}

static inline bool __is_bad_mt_xwr(struct rsvd_bits_validate *rsvd_check,
				   u64 pte)
{
	return rsvd_check->bad_mt_xwr & BIT_ULL(pte & 0x3f);
}

u64 make_nonleaf_spte(u64 *child_pt, bool ad_disabled);

/* klp-ccp: from arch/x86/kvm/mmu/page_track.h */
#include <linux/kvm_host.h>

#include <asm/kvm_page_track.h>

bool kvm_gfn_is_write_tracked(struct kvm *kvm,
			      const struct kvm_memory_slot *slot, gfn_t gfn);

/* klp-ccp: from arch/x86/kvm/mmu/mmu.c */
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
#include <linux/kstrtox.h>
#include <linux/kthread.h>

#include <asm/page.h>
#include <asm/memtype.h>
#include <asm/cmpxchg.h>
#include <asm/io.h>
#include <asm/set_memory.h>
#include <asm/spec-ctrl.h>
#include <asm/vmx.h>

#include <trace/define_trace.h>

/* klp-ccp: from arch/x86/kvm/mmu/mmu.c */
#define PTE_PREFETCH_NUM		8

#include <trace/events/kvm.h>

struct kvm_shadow_walk_iterator {
	u64 addr;
	hpa_t shadow_addr;
	u64 *sptep;
	int level;
	unsigned index;
};

#define for_each_shadow_entry(_vcpu, _addr, _walker)            \
	for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
	     shadow_walk_okay(&(_walker));			\
	     shadow_walk_next(&(_walker)))

static void mmu_spte_set(u64 *sptep, u64 spte);
extern int mmu_page_zap_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
			    u64 *spte, struct list_head *invalid_list);

/* klp-ccp: from arch/x86/kvm/mmu/mmu.c */
#define BUILD_MMU_ROLE_ACCESSOR(base_or_ext, reg, name)		\
static inline bool __maybe_unused is_##reg##_##name(struct kvm_mmu *mmu)	\
{								\
	return !!(mmu->cpu_role. base_or_ext . reg##_##name);	\
}
BUILD_MMU_ROLE_ACCESSOR(base, cr0, wp)

BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, smep)

extern void kvm_flush_remote_tlbs_sptep(struct kvm *kvm, u64 *sptep);

#ifdef CONFIG_X86_64
static void __set_spte(u64 *sptep, u64 spte)
{
	KVM_MMU_WARN_ON(is_ept_ve_possible(spte));
	WRITE_ONCE(*sptep, spte);
}

static void __update_clear_spte_fast(u64 *sptep, u64 spte)
{
	KVM_MMU_WARN_ON(is_ept_ve_possible(spte));
	WRITE_ONCE(*sptep, spte);
}

#else
#error "klp-ccp: non-taken branch"
#endif

static void mmu_spte_set(u64 *sptep, u64 new_spte)
{
	WARN_ON_ONCE(is_shadow_present_pte(*sptep));
	__set_spte(sptep, new_spte);
}

static void mmu_spte_clear_no_track(u64 *sptep)
{
	__update_clear_spte_fast(sptep, SHADOW_NONPRESENT_VALUE);
}

extern int mmu_topup_memory_caches(struct kvm_vcpu *vcpu, bool maybe_indirect);

void track_possible_nx_huge_page(struct kvm *kvm, struct kvm_mmu_page *sp);

static void account_nx_huge_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				 bool nx_huge_page_possible)
{
	sp->nx_huge_page_disallowed = true;

	if (nx_huge_page_possible)
		track_possible_nx_huge_page(kvm, sp);
}

extern struct kvm_memory_slot *gfn_to_memslot_dirty_bitmap(struct kvm_vcpu *vcpu,
							   gfn_t gfn,
							   bool no_dirty_log);

extern int pte_list_add(struct kvm_mmu_memory_cache *cache, u64 *spte,
			struct kvm_rmap_head *rmap_head);

extern void pte_list_remove(struct kvm *kvm, u64 *spte,
			    struct kvm_rmap_head *rmap_head);

extern void drop_spte(struct kvm *kvm, u64 *sptep);

static void mmu_page_add_parent_pte(struct kvm_mmu_memory_cache *cache,
				    struct kvm_mmu_page *sp, u64 *parent_pte)
{
	if (!parent_pte)
		return;

	pte_list_add(cache, parent_pte, &sp->parent_ptes);
}

static void mmu_page_remove_parent_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
				       u64 *parent_pte)
{
	pte_list_remove(kvm, parent_pte, &sp->parent_ptes);
}

static void drop_parent_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
			    u64 *parent_pte)
{
	mmu_page_remove_parent_pte(kvm, sp, parent_pte);
	mmu_spte_clear_no_track(parent_pte);
}

extern void mark_unsync(u64 *spte);

void mark_unsync(u64 *spte);

extern bool kvm_mmu_remote_flush_or_zap(struct kvm *kvm,
					struct list_head *invalid_list,
					bool remote_flush);

extern int mmu_sync_children(struct kvm_vcpu *vcpu,
			     struct kvm_mmu_page *parent, bool can_yield);

static void __clear_sp_write_flooding_count(struct kvm_mmu_page *sp)
{
	atomic_set(&sp->write_flooding_count,  0);
}

static void clear_sp_write_flooding_count(u64 *spte)
{
	__clear_sp_write_flooding_count(sptep_to_sp(spte));
}

struct shadow_page_caches {
	struct kvm_mmu_memory_cache *page_header_cache;
	struct kvm_mmu_memory_cache *shadow_page_cache;
	struct kvm_mmu_memory_cache *shadowed_info_cache;
};

extern struct kvm_mmu_page *__kvm_mmu_get_shadow_page(struct kvm *kvm,
						      struct kvm_vcpu *vcpu,
						      struct shadow_page_caches *caches,
						      gfn_t gfn,
						      union kvm_mmu_page_role role);

static struct kvm_mmu_page *kvm_mmu_get_shadow_page(struct kvm_vcpu *vcpu,
						    gfn_t gfn,
						    union kvm_mmu_page_role role)
{
	struct shadow_page_caches caches = {
		.page_header_cache = &vcpu->arch.mmu_page_header_cache,
		.shadow_page_cache = &vcpu->arch.mmu_shadow_page_cache,
		.shadowed_info_cache = &vcpu->arch.mmu_shadowed_info_cache,
	};

	return __kvm_mmu_get_shadow_page(vcpu->kvm, vcpu, &caches, gfn, role);
}

extern union kvm_mmu_page_role kvm_mmu_child_role(u64 *sptep, bool direct,
						  unsigned int access);

static struct kvm_mmu_page *klpp_kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
						 u64 *sptep, gfn_t gfn,
						 bool direct, unsigned int access)
{
	union kvm_mmu_page_role role = kvm_mmu_child_role(sptep, direct, access);

	if (is_shadow_present_pte(*sptep) &&
	    !is_large_pte(*sptep) &&
	    spte_to_child_sp(*sptep) &&
	    spte_to_child_sp(*sptep)->gfn == gfn &&
	    spte_to_child_sp(*sptep)->role.word == role.word)
		return ERR_PTR(-EEXIST);

	return kvm_mmu_get_shadow_page(vcpu, gfn, role);
}

static void shadow_walk_init_using_root(struct kvm_shadow_walk_iterator *iterator,
					struct kvm_vcpu *vcpu, hpa_t root,
					u64 addr)
{
	iterator->addr = addr;
	iterator->shadow_addr = root;
	iterator->level = vcpu->arch.mmu->root_role.level;

	if (iterator->level >= PT64_ROOT_4LEVEL &&
	    vcpu->arch.mmu->cpu_role.base.level < PT64_ROOT_4LEVEL &&
	    !vcpu->arch.mmu->root_role.direct)
		iterator->level = PT32E_ROOT_LEVEL;

	if (iterator->level == PT32E_ROOT_LEVEL) {
		/*
		 * prev_root is currently only used for 64-bit hosts. So only
		 * the active root_hpa is valid here.
		 */
		BUG_ON(root != vcpu->arch.mmu->root.hpa);

		iterator->shadow_addr
			= vcpu->arch.mmu->pae_root[(addr >> 30) & 3];
		iterator->shadow_addr &= SPTE_BASE_ADDR_MASK;
		--iterator->level;
		if (!iterator->shadow_addr)
			iterator->level = 0;
	}
}

static void shadow_walk_init(struct kvm_shadow_walk_iterator *iterator,
			     struct kvm_vcpu *vcpu, u64 addr)
{
	shadow_walk_init_using_root(iterator, vcpu, vcpu->arch.mmu->root.hpa,
				    addr);
}

static bool shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator)
{
	if (iterator->level < PG_LEVEL_4K)
		return false;

	iterator->index = SPTE_INDEX(iterator->addr, iterator->level);
	iterator->sptep	= ((u64 *)__va(iterator->shadow_addr)) + iterator->index;
	return true;
}

extern void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator);

void klpp___link_shadow_page(struct kvm *kvm,
			       struct kvm_mmu_memory_cache *cache, u64 *sptep,
			       struct kvm_mmu_page *sp, bool flush)
{
	u64 spte;

	BUILD_BUG_ON(VMX_EPT_WRITABLE_MASK != PT_WRITABLE_MASK);

	if (is_shadow_present_pte(*sptep)) {
		struct kvm_mmu_page *parent_sp;
		LIST_HEAD(invalid_list);

		parent_sp = sptep_to_sp(sptep);
		WARN_ON_ONCE(parent_sp->role.level == PG_LEVEL_4K);

		mmu_page_zap_pte(kvm, parent_sp, sptep, &invalid_list);
		kvm_mmu_remote_flush_or_zap(kvm, &invalid_list, true);
	}

	spte = make_nonleaf_spte(sp->spt, sp_ad_disabled(sp));

	mmu_spte_set(sptep, spte);

	mmu_page_add_parent_pte(cache, sp, sptep);

	/*
	 * The non-direct sub-pagetable must be updated before linking.  For
	 * L1 sp, the pagetable is updated via kvm_sync_page() in
	 * kvm_mmu_find_shadow_page() without write-protecting the gfn,
	 * so sp->unsync can be true or false.  For higher level non-direct
	 * sp, the pagetable is updated/synced via mmu_sync_children() in
	 * FNAME(fetch)(), so sp->unsync_children can only be false.
	 * WARN_ON_ONCE() if anything happens unexpectedly.
	 */
	if (WARN_ON_ONCE(sp->unsync_children) || sp->unsync)
		mark_unsync(sptep);
}

static void klpr_link_shadow_page(struct kvm_vcpu *vcpu, u64 *sptep,
			     struct kvm_mmu_page *sp)
{
	klpp___link_shadow_page(vcpu->kvm, &vcpu->arch.mmu_pte_list_desc_cache, sptep, sp, true);
}

static void validate_direct_spte(struct kvm_vcpu *vcpu, u64 *sptep,
				   unsigned direct_access)
{
	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep)) {
		struct kvm_mmu_page *child;

		/*
		 * For the direct sp, if the guest pte's dirty bit
		 * changed form clean to dirty, it will corrupt the
		 * sp's access: allow writable in the read-only sp,
		 * so we should update the spte at this point to get
		 * a new sp with the correct access.
		 */
		child = spte_to_child_sp(*sptep);
		if (child->role.access == direct_access)
			return;

		drop_parent_pte(vcpu->kvm, child, sptep);
		kvm_flush_remote_tlbs_sptep(vcpu->kvm, sptep);
	}
}

int mmu_page_zap_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
			    u64 *spte, struct list_head *invalid_list);

extern unsigned long kvm_mmu_zap_oldest_mmu_pages(struct kvm *kvm,
						  unsigned long nr_to_zap);

static inline unsigned long kvm_mmu_available_pages(struct kvm *kvm)
{
	if (kvm->arch.n_max_mmu_pages > kvm->arch.n_used_mmu_pages)
		return kvm->arch.n_max_mmu_pages -
			kvm->arch.n_used_mmu_pages;

	return 0;
}

static int make_mmu_pages_available(struct kvm_vcpu *vcpu)
{
	unsigned long avail = kvm_mmu_available_pages(vcpu->kvm);

	if (likely(avail >= KVM_MIN_FREE_MMU_PAGES))
		return 0;

	kvm_mmu_zap_oldest_mmu_pages(vcpu->kvm, KVM_REFILL_PAGES - avail);

	/*
	 * Note, this check is intentionally soft, it only guarantees that one
	 * page is available, while the caller may end up allocating as many as
	 * four pages, e.g. for PAE roots or for 5-level paging.  Temporarily
	 * exceeding the (arbitrary by default) limit will not harm the host,
	 * being too aggressive may unnecessarily kill the guest, and getting an
	 * exact count is far more trouble than it's worth, especially in the
	 * page fault paths.
	 */
	if (!kvm_mmu_available_pages(vcpu->kvm))
		return -ENOSPC;
	return 0;
}

extern int mmu_set_spte(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			u64 *sptep, unsigned int pte_access, gfn_t gfn,
			kvm_pfn_t pfn, struct kvm_page_fault *fault);

extern void __direct_pte_prefetch(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *sptep);

static void direct_pte_prefetch(struct kvm_vcpu *vcpu, u64 *sptep)
{
	struct kvm_mmu_page *sp;

	sp = sptep_to_sp(sptep);

	/*
	 * Without accessed bits, there's no way to distinguish between
	 * actually accessed translations and prefetched, so disable pte
	 * prefetch if accessed bits aren't available.
	 */
	if (sp_ad_disabled(sp))
		return;

	if (sp->role.level > PG_LEVEL_4K)
		return;

	/*
	 * If addresses are being invalidated, skip prefetching to avoid
	 * accidentally prefetching those addresses.
	 */
	if (unlikely(vcpu->kvm->mmu_invalidate_in_progress))
		return;

	__direct_pte_prefetch(vcpu, sp, sptep);
}

void kvm_mmu_hugepage_adjust(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);

void disallowed_hugepage_adjust(struct kvm_page_fault *fault, u64 spte, int cur_level);

extern  void trace_kvm_mmu_spte_requested(struct kvm_page_fault *fault);

static int klpp_direct_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_shadow_walk_iterator it;
	struct kvm_mmu_page *sp;
	int ret;
	gfn_t base_gfn = fault->gfn;

	kvm_mmu_hugepage_adjust(vcpu, fault);

	trace_kvm_mmu_spte_requested(fault);
	for_each_shadow_entry(vcpu, fault->addr, it) {
		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, *it.sptep, it.level);

		base_gfn = gfn_round_for_level(fault->gfn, it.level);
		if (it.level == fault->goal_level)
			break;

		sp = klpp_kvm_mmu_get_child_sp(vcpu, it.sptep, base_gfn, true, ACC_ALL);
		if (sp == ERR_PTR(-EEXIST))
			continue;

		klpr_link_shadow_page(vcpu, it.sptep, sp);
		if (fault->huge_page_disallowed)
			account_nx_huge_page(vcpu->kvm, sp,
					     fault->req_level >= it.level);
	}

	if (WARN_ON_ONCE(it.level != fault->goal_level))
		return -EFAULT;

	ret = mmu_set_spte(vcpu, fault->slot, it.sptep, ACC_ALL,
			   base_gfn, fault->pfn, fault);
	if (ret == RET_PF_SPURIOUS)
		return ret;

	direct_pte_prefetch(vcpu, it.sptep);
	return ret;
}

extern int fast_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);

static bool page_fault_handle_page_track(struct kvm_vcpu *vcpu,
					 struct kvm_page_fault *fault)
{
	if (unlikely(fault->rsvd))
		return false;

	if (!fault->present || !fault->write)
		return false;

	/*
	 * guest is writing the page which is write tracked which can
	 * not be fixed by page fault handler.
	 */
	if (kvm_gfn_is_write_tracked(vcpu->kvm, fault->slot, fault->gfn))
		return true;

	return false;
}

extern void shadow_page_table_clear_flood(struct kvm_vcpu *vcpu, gva_t addr);

extern int kvm_faultin_pfn(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			   unsigned int access);

extern bool is_page_fault_stale(struct kvm_vcpu *vcpu,
				struct kvm_page_fault *fault);

int klpp_direct_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	int r;

	/* Dummy roots are used only for shadowing bad guest roots. */
	if (WARN_ON_ONCE(kvm_mmu_is_dummy_root(vcpu->arch.mmu->root.hpa)))
		return RET_PF_RETRY;

	if (page_fault_handle_page_track(vcpu, fault))
		return RET_PF_WRITE_PROTECTED;

	r = fast_page_fault(vcpu, fault);
	if (r != RET_PF_INVALID)
		return r;

	r = mmu_topup_memory_caches(vcpu, false);
	if (r)
		return r;

	r = kvm_faultin_pfn(vcpu, fault, ACC_ALL);
	if (r != RET_PF_CONTINUE)
		return r;

	r = RET_PF_RETRY;
	write_lock(&vcpu->kvm->mmu_lock);

	if (is_page_fault_stale(vcpu, fault))
		goto out_unlock;

	r = make_mmu_pages_available(vcpu);
	if (r)
		goto out_unlock;

	r = klpp_direct_map(vcpu, fault);

out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(fault->pfn);
	return r;
}

#define PTTYPE_EPT 18 /* arbitrary */
#define PTTYPE PTTYPE_EPT

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define pt_element_t u64
#define guest_walker guest_walkerEPT
#define FNAME(name) ept_##name
#define PT_LEVEL_BITS 9
#define PT_GUEST_DIRTY_SHIFT 9
#define PT_GUEST_ACCESSED_SHIFT 8
#define PT_HAVE_ACCESSED_DIRTY(mmu) (!(mmu)->cpu_role.base.ad_disabled)
#define PT_MAX_FULL_LEVELS PT64_ROOT_MAX_LEVEL

#define PT_BASE_ADDR_MASK	((pt_element_t)__PT_BASE_ADDR_MASK)
#define PT_LVL_ADDR_MASK(lvl)	__PT_LVL_ADDR_MASK(PT_BASE_ADDR_MASK, lvl, PT_LEVEL_BITS)

#define PT_GUEST_ACCESSED_MASK (1 << PT_GUEST_ACCESSED_SHIFT)

#define gpte_to_gfn_lvl FNAME(gpte_to_gfn_lvl)
#define gpte_to_gfn(pte) gpte_to_gfn_lvl((pte), PG_LEVEL_4K)

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

static gfn_t gpte_to_gfn_lvl(pt_element_t gpte, int lvl)
{
	return (gpte & PT_LVL_ADDR_MASK(lvl)) >> PAGE_SHIFT;
}

static inline void FNAME(protect_clean_gpte)(struct kvm_mmu *mmu, unsigned *access,
					     unsigned gpte)
{
	unsigned mask;

	/* dirty bit is not supported, so no need to track it */
	if (!PT_HAVE_ACCESSED_DIRTY(mmu))
		return;

	BUILD_BUG_ON(PT_WRITABLE_MASK != ACC_WRITE_MASK);

	mask = (unsigned)~ACC_WRITE_MASK;
	/* Allow write access to dirty gptes */
	mask |= (gpte >> (PT_GUEST_DIRTY_SHIFT - PT_WRITABLE_SHIFT)) &
		PT_WRITABLE_MASK;
	*access &= mask;
}

static inline int FNAME(is_present_gpte)(unsigned long pte)
{
#if PTTYPE != PTTYPE_EPT
#error "klp-ccp: non-taken branch"
#else
	return pte & 7;
#endif
}

static bool FNAME(is_bad_mt_xwr)(struct rsvd_bits_validate *rsvd_check, u64 gpte)
{
#if PTTYPE != PTTYPE_EPT
#error "klp-ccp: non-taken branch"
#else
	return __is_bad_mt_xwr(rsvd_check, gpte);
#endif
}

static bool FNAME(is_rsvd_bits_set)(struct kvm_mmu *mmu, u64 gpte, int level)
{
	return __is_rsvd_bits_set(&mmu->guest_rsvd_check, gpte, level) ||
	       FNAME(is_bad_mt_xwr)(&mmu->guest_rsvd_check, gpte);
}

static bool FNAME(prefetch_invalid_gpte)(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *spte,
				  u64 gpte)
{
	if (!FNAME(is_present_gpte)(gpte))
		goto no_present;

	/* Prefetch only accessed entries (unless A/D bits are disabled). */
	if (PT_HAVE_ACCESSED_DIRTY(vcpu->arch.mmu) &&
	    !(gpte & PT_GUEST_ACCESSED_MASK))
		goto no_present;

	if (FNAME(is_rsvd_bits_set)(vcpu->arch.mmu, gpte, PG_LEVEL_4K))
		goto no_present;

	return false;

no_present:
	drop_spte(vcpu->kvm, spte);
	return true;
}

static inline unsigned FNAME(gpte_access)(u64 gpte)
{
	unsigned access;
#if PTTYPE == PTTYPE_EPT
	access = ((gpte & VMX_EPT_WRITABLE_MASK) ? ACC_WRITE_MASK : 0) |
		((gpte & VMX_EPT_EXECUTABLE_MASK) ? ACC_EXEC_MASK : 0) |
		((gpte & VMX_EPT_READABLE_MASK) ? ACC_USER_MASK : 0);
#else
#error "klp-ccp: non-taken branch"
#endif
	return access;
}

extern int FNAME(walk_addr_generic)(struct guest_walker *walker,
				    struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				    gpa_t addr, u64 access);

static int FNAME(walk_addr)(struct guest_walker *walker,
			    struct kvm_vcpu *vcpu, gpa_t addr, u64 access)
{
	return FNAME(walk_addr_generic)(walker, vcpu, vcpu->arch.mmu, addr,
					access);
}

static bool
FNAME(prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     u64 *spte, pt_element_t gpte)
{
	struct kvm_memory_slot *slot;
	unsigned pte_access;
	gfn_t gfn;
	kvm_pfn_t pfn;

	if (FNAME(prefetch_invalid_gpte)(vcpu, sp, spte, gpte))
		return false;

	gfn = gpte_to_gfn(gpte);
	pte_access = sp->role.access & FNAME(gpte_access)(gpte);
	FNAME(protect_clean_gpte)(vcpu->arch.mmu, &pte_access, gpte);

	slot = gfn_to_memslot_dirty_bitmap(vcpu, gfn, pte_access & ACC_WRITE_MASK);
	if (!slot)
		return false;

	pfn = gfn_to_pfn_memslot_atomic(slot, gfn);
	if (is_error_pfn(pfn))
		return false;

	mmu_set_spte(vcpu, slot, spte, pte_access, gfn, pfn, NULL);
	kvm_release_pfn_clean(pfn);
	return true;
}

extern bool FNAME(gpte_changed)(struct kvm_vcpu *vcpu,
				struct guest_walker *gw, int level);

static void FNAME(pte_prefetch)(struct kvm_vcpu *vcpu, struct guest_walker *gw,
				u64 *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	u64 *spte;
	int i;

	sp = sptep_to_sp(sptep);

	if (sp->role.level > PG_LEVEL_4K)
		return;

	/*
	 * If addresses are being invalidated, skip prefetching to avoid
	 * accidentally prefetching those addresses.
	 */
	if (unlikely(vcpu->kvm->mmu_invalidate_in_progress))
		return;

	if (sp->role.direct)
		return __direct_pte_prefetch(vcpu, sp, sptep);

	i = spte_index(sptep) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (is_shadow_present_pte(*spte))
			continue;

		if (!FNAME(prefetch_gpte)(vcpu, sp, spte, gptep[i]))
			break;
	}
}

static int klpp_ept_fetch(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			 struct guest_walker *gw)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	unsigned int direct_access, access;
	int top_level, ret;
	gfn_t base_gfn = fault->gfn;

	WARN_ON_ONCE(gw->gfn != base_gfn);
	direct_access = gw->pte_access;

	top_level = vcpu->arch.mmu->cpu_role.base.level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if (FNAME(gpte_changed)(vcpu, gw, top_level))
		return RET_PF_RETRY;

	if (WARN_ON_ONCE(!VALID_PAGE(vcpu->arch.mmu->root.hpa)))
		return RET_PF_RETRY;

	/*
	 * Load a new root and retry the faulting instruction in the extremely
	 * unlikely scenario that the guest root gfn became visible between
	 * loading a dummy root and handling the resulting page fault, e.g. if
	 * userspace create a memslot in the interim.
	 */
	if (unlikely(kvm_mmu_is_dummy_root(vcpu->arch.mmu->root.hpa))) {
		kvm_make_request(KVM_REQ_MMU_FREE_OBSOLETE_ROOTS, vcpu);
		return RET_PF_RETRY;
	}

	for_each_shadow_entry(vcpu, fault->addr, it) {
		gfn_t table_gfn;

		clear_sp_write_flooding_count(it.sptep);
		if (it.level == gw->level)
			break;

		table_gfn = gw->table_gfn[it.level - 2];
		access = gw->pt_access[it.level - 2];
		sp = klpp_kvm_mmu_get_child_sp(vcpu, it.sptep, table_gfn,
					  false, access);

		/*
		 * Synchronize the new page before linking it, as the CPU (KVM)
		 * is architecturally disallowed from inserting non-present
		 * entries into the TLB, i.e. the guest isn't required to flush
		 * the TLB when changing the gPTE from non-present to present.
		 *
		 * For PG_LEVEL_4K, kvm_mmu_find_shadow_page() has already
		 * synchronized the page via kvm_sync_page().
		 *
		 * For higher level pages, which cannot be unsync themselves
		 * but can have unsync children, synchronize via the slower
		 * mmu_sync_children().  If KVM needs to drop mmu_lock due to
		 * contention or to reschedule, instruct the caller to retry
		 * the #PF (mmu_sync_children() ensures forward progress will
		 * be made).
		 */
		if (sp != ERR_PTR(-EEXIST) && sp->unsync_children &&
		    mmu_sync_children(vcpu, sp, false))
			return RET_PF_RETRY;

		/*
		 * Verify that the gpte in the page, which is now either
		 * write-protected or unsync, wasn't modified between the fault
		 * and acquiring mmu_lock.  This needs to be done even when
		 * reusing an existing shadow page to ensure the information
		 * gathered by the walker matches the information stored in the
		 * shadow page (which could have been modified by a different
		 * vCPU even if the page was already linked).  Holding mmu_lock
		 * prevents the shadow page from changing after this point.
		 */
		if (FNAME(gpte_changed)(vcpu, gw, it.level - 1))
			return RET_PF_RETRY;

		if (sp != ERR_PTR(-EEXIST))
			klpr_link_shadow_page(vcpu, it.sptep, sp);

		if (fault->write && table_gfn == fault->gfn)
			fault->write_fault_to_shadow_pgtable = true;
	}

	/*
	 * Adjust the hugepage size _after_ resolving indirect shadow pages.
	 * KVM doesn't support mapping hugepages into the guest for gfns that
	 * are being shadowed by KVM, i.e. allocating a new shadow page may
	 * affect the allowed hugepage size.
	 */
	kvm_mmu_hugepage_adjust(vcpu, fault);

	trace_kvm_mmu_spte_requested(fault);

	for (; shadow_walk_okay(&it); shadow_walk_next(&it)) {
		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, *it.sptep, it.level);

		base_gfn = gfn_round_for_level(fault->gfn, it.level);
		if (it.level == fault->goal_level)
			break;

		validate_direct_spte(vcpu, it.sptep, direct_access);

		sp = klpp_kvm_mmu_get_child_sp(vcpu, it.sptep, base_gfn,
					  true, direct_access);
		if (sp == ERR_PTR(-EEXIST))
			continue;

		klpr_link_shadow_page(vcpu, it.sptep, sp);
		if (fault->huge_page_disallowed)
			account_nx_huge_page(vcpu->kvm, sp,
					     fault->req_level >= it.level);
	}

	if (WARN_ON_ONCE(it.level != fault->goal_level))
		return -EFAULT;

	ret = mmu_set_spte(vcpu, fault->slot, it.sptep, gw->pte_access,
			   base_gfn, fault->pfn, fault);
	if (ret == RET_PF_SPURIOUS)
		return ret;

	FNAME(pte_prefetch)(vcpu, gw, it.sptep);
	return ret;
}

int klpp_ept_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct guest_walker walker;
	int r;

	WARN_ON_ONCE(fault->is_tdp);

	/*
	 * Look up the guest pte for the faulting address.
	 * If PFEC.RSVD is set, this is a shadow page fault.
	 * The bit needs to be cleared before walking guest page tables.
	 */
	r = FNAME(walk_addr)(&walker, vcpu, fault->addr,
			     fault->error_code & ~PFERR_RSVD_MASK);

	/*
	 * The page is not mapped by the guest.  Let the guest handle it.
	 */
	if (!r) {
		if (!fault->prefetch)
			kvm_inject_emulated_page_fault(vcpu, &walker.fault);

		return RET_PF_RETRY;
	}

	fault->gfn = walker.gfn;
	fault->max_level = walker.level;
	fault->slot = kvm_vcpu_gfn_to_memslot(vcpu, fault->gfn);

	if (page_fault_handle_page_track(vcpu, fault)) {
		shadow_page_table_clear_flood(vcpu, fault->addr);
		return RET_PF_WRITE_PROTECTED;
	}

	r = mmu_topup_memory_caches(vcpu, true);
	if (r)
		return r;

	r = kvm_faultin_pfn(vcpu, fault, walker.pte_access);
	if (r != RET_PF_CONTINUE)
		return r;

	/*
	 * Do not change pte_access if the pfn is a mmio page, otherwise
	 * we will cache the incorrect access into mmio spte.
	 */
	if (fault->write && !(walker.pte_access & ACC_WRITE_MASK) &&
	    !is_cr0_wp(vcpu->arch.mmu) && !fault->user && fault->slot) {
		walker.pte_access |= ACC_WRITE_MASK;
		walker.pte_access &= ~ACC_USER_MASK;

		/*
		 * If we converted a user page to a kernel page,
		 * so that the kernel can write to it when cr0.wp=0,
		 * then we should prevent the kernel from executing it
		 * if SMEP is enabled.
		 */
		if (is_cr4_smep(vcpu->arch.mmu))
			walker.pte_access &= ~ACC_EXEC_MASK;
	}

	r = RET_PF_RETRY;
	write_lock(&vcpu->kvm->mmu_lock);

	if (is_page_fault_stale(vcpu, fault))
		goto out_unlock;

	r = make_mmu_pages_available(vcpu);
	if (r)
		goto out_unlock;
	r = klpp_ept_fetch(vcpu, fault, &walker);

out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(fault->pfn);
	return r;
}

/* klp-ccp: from arch/x86/kvm/mmu/mmu.c */
#undef PTTYPE
#define PTTYPE 64

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef guest_walker
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define guest_walker guest_walker64

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef FNAME
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define FNAME(name) paging##64_##name

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef PT_GUEST_DIRTY_SHIFT
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define PT_GUEST_DIRTY_SHIFT PT_DIRTY_SHIFT

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef PT_GUEST_ACCESSED_SHIFT
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define PT_GUEST_ACCESSED_SHIFT PT_ACCESSED_SHIFT

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef PT_HAVE_ACCESSED_DIRTY
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define PT_HAVE_ACCESSED_DIRTY(mmu) true

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

static gfn_t gpte_to_gfn_lvl(pt_element_t gpte, int lvl)
{
	return (gpte & PT_LVL_ADDR_MASK(lvl)) >> PAGE_SHIFT;
}

static inline void FNAME(protect_clean_gpte)(struct kvm_mmu *mmu, unsigned *access,
					     unsigned gpte)
{
	unsigned mask;

	/* dirty bit is not supported, so no need to track it */
	if (!PT_HAVE_ACCESSED_DIRTY(mmu))
		return;

	BUILD_BUG_ON(PT_WRITABLE_MASK != ACC_WRITE_MASK);

	mask = (unsigned)~ACC_WRITE_MASK;
	/* Allow write access to dirty gptes */
	mask |= (gpte >> (PT_GUEST_DIRTY_SHIFT - PT_WRITABLE_SHIFT)) &
		PT_WRITABLE_MASK;
	*access &= mask;
}

static inline int FNAME(is_present_gpte)(unsigned long pte)
{
#if PTTYPE != PTTYPE_EPT
	return pte & PT_PRESENT_MASK;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static bool FNAME(is_bad_mt_xwr)(struct rsvd_bits_validate *rsvd_check, u64 gpte)
{
#if PTTYPE != PTTYPE_EPT
	return false;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static bool FNAME(is_rsvd_bits_set)(struct kvm_mmu *mmu, u64 gpte, int level)
{
	return __is_rsvd_bits_set(&mmu->guest_rsvd_check, gpte, level) ||
	       FNAME(is_bad_mt_xwr)(&mmu->guest_rsvd_check, gpte);
}

static bool FNAME(prefetch_invalid_gpte)(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *spte,
				  u64 gpte)
{
	if (!FNAME(is_present_gpte)(gpte))
		goto no_present;

	/* Prefetch only accessed entries (unless A/D bits are disabled). */
	if (PT_HAVE_ACCESSED_DIRTY(vcpu->arch.mmu) &&
	    !(gpte & PT_GUEST_ACCESSED_MASK))
		goto no_present;

	if (FNAME(is_rsvd_bits_set)(vcpu->arch.mmu, gpte, PG_LEVEL_4K))
		goto no_present;

	return false;

no_present:
	drop_spte(vcpu->kvm, spte);
	return true;
}

static inline unsigned FNAME(gpte_access)(u64 gpte)
{
	unsigned access;
#if PTTYPE == PTTYPE_EPT
#error "klp-ccp: non-taken branch"
#else
	BUILD_BUG_ON(ACC_EXEC_MASK != PT_PRESENT_MASK);
	BUILD_BUG_ON(ACC_EXEC_MASK != 1);
	access = gpte & (PT_WRITABLE_MASK | PT_USER_MASK | PT_PRESENT_MASK);
	/* Combine NX with P (which is set here) to get ACC_EXEC_MASK.  */
	access ^= (gpte >> PT64_NX_SHIFT);
#endif
	return access;
}

extern int FNAME(walk_addr_generic)(struct guest_walker *walker,
				    struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				    gpa_t addr, u64 access);

static int FNAME(walk_addr)(struct guest_walker *walker,
			    struct kvm_vcpu *vcpu, gpa_t addr, u64 access)
{
	return FNAME(walk_addr_generic)(walker, vcpu, vcpu->arch.mmu, addr,
					access);
}

static bool
FNAME(prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     u64 *spte, pt_element_t gpte)
{
	struct kvm_memory_slot *slot;
	unsigned pte_access;
	gfn_t gfn;
	kvm_pfn_t pfn;

	if (FNAME(prefetch_invalid_gpte)(vcpu, sp, spte, gpte))
		return false;

	gfn = gpte_to_gfn(gpte);
	pte_access = sp->role.access & FNAME(gpte_access)(gpte);
	FNAME(protect_clean_gpte)(vcpu->arch.mmu, &pte_access, gpte);

	slot = gfn_to_memslot_dirty_bitmap(vcpu, gfn, pte_access & ACC_WRITE_MASK);
	if (!slot)
		return false;

	pfn = gfn_to_pfn_memslot_atomic(slot, gfn);
	if (is_error_pfn(pfn))
		return false;

	mmu_set_spte(vcpu, slot, spte, pte_access, gfn, pfn, NULL);
	kvm_release_pfn_clean(pfn);
	return true;
}

extern bool FNAME(gpte_changed)(struct kvm_vcpu *vcpu,
				struct guest_walker *gw, int level);

static void FNAME(pte_prefetch)(struct kvm_vcpu *vcpu, struct guest_walker *gw,
				u64 *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	u64 *spte;
	int i;

	sp = sptep_to_sp(sptep);

	if (sp->role.level > PG_LEVEL_4K)
		return;

	/*
	 * If addresses are being invalidated, skip prefetching to avoid
	 * accidentally prefetching those addresses.
	 */
	if (unlikely(vcpu->kvm->mmu_invalidate_in_progress))
		return;

	if (sp->role.direct)
		return __direct_pte_prefetch(vcpu, sp, sptep);

	i = spte_index(sptep) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (is_shadow_present_pte(*spte))
			continue;

		if (!FNAME(prefetch_gpte)(vcpu, sp, spte, gptep[i]))
			break;
	}
}

static int klpp_paging64_fetch(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			 struct guest_walker *gw)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	unsigned int direct_access, access;
	int top_level, ret;
	gfn_t base_gfn = fault->gfn;

	WARN_ON_ONCE(gw->gfn != base_gfn);
	direct_access = gw->pte_access;

	top_level = vcpu->arch.mmu->cpu_role.base.level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if (FNAME(gpte_changed)(vcpu, gw, top_level))
		return RET_PF_RETRY;

	if (WARN_ON_ONCE(!VALID_PAGE(vcpu->arch.mmu->root.hpa)))
		return RET_PF_RETRY;

	/*
	 * Load a new root and retry the faulting instruction in the extremely
	 * unlikely scenario that the guest root gfn became visible between
	 * loading a dummy root and handling the resulting page fault, e.g. if
	 * userspace create a memslot in the interim.
	 */
	if (unlikely(kvm_mmu_is_dummy_root(vcpu->arch.mmu->root.hpa))) {
		kvm_make_request(KVM_REQ_MMU_FREE_OBSOLETE_ROOTS, vcpu);
		return RET_PF_RETRY;
	}

	for_each_shadow_entry(vcpu, fault->addr, it) {
		gfn_t table_gfn;

		clear_sp_write_flooding_count(it.sptep);
		if (it.level == gw->level)
			break;

		table_gfn = gw->table_gfn[it.level - 2];
		access = gw->pt_access[it.level - 2];
		sp = klpp_kvm_mmu_get_child_sp(vcpu, it.sptep, table_gfn,
					  false, access);

		/*
		 * Synchronize the new page before linking it, as the CPU (KVM)
		 * is architecturally disallowed from inserting non-present
		 * entries into the TLB, i.e. the guest isn't required to flush
		 * the TLB when changing the gPTE from non-present to present.
		 *
		 * For PG_LEVEL_4K, kvm_mmu_find_shadow_page() has already
		 * synchronized the page via kvm_sync_page().
		 *
		 * For higher level pages, which cannot be unsync themselves
		 * but can have unsync children, synchronize via the slower
		 * mmu_sync_children().  If KVM needs to drop mmu_lock due to
		 * contention or to reschedule, instruct the caller to retry
		 * the #PF (mmu_sync_children() ensures forward progress will
		 * be made).
		 */
		if (sp != ERR_PTR(-EEXIST) && sp->unsync_children &&
		    mmu_sync_children(vcpu, sp, false))
			return RET_PF_RETRY;

		/*
		 * Verify that the gpte in the page, which is now either
		 * write-protected or unsync, wasn't modified between the fault
		 * and acquiring mmu_lock.  This needs to be done even when
		 * reusing an existing shadow page to ensure the information
		 * gathered by the walker matches the information stored in the
		 * shadow page (which could have been modified by a different
		 * vCPU even if the page was already linked).  Holding mmu_lock
		 * prevents the shadow page from changing after this point.
		 */
		if (FNAME(gpte_changed)(vcpu, gw, it.level - 1))
			return RET_PF_RETRY;

		if (sp != ERR_PTR(-EEXIST))
			klpr_link_shadow_page(vcpu, it.sptep, sp);

		if (fault->write && table_gfn == fault->gfn)
			fault->write_fault_to_shadow_pgtable = true;
	}

	/*
	 * Adjust the hugepage size _after_ resolving indirect shadow pages.
	 * KVM doesn't support mapping hugepages into the guest for gfns that
	 * are being shadowed by KVM, i.e. allocating a new shadow page may
	 * affect the allowed hugepage size.
	 */
	kvm_mmu_hugepage_adjust(vcpu, fault);

	trace_kvm_mmu_spte_requested(fault);

	for (; shadow_walk_okay(&it); shadow_walk_next(&it)) {
		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, *it.sptep, it.level);

		base_gfn = gfn_round_for_level(fault->gfn, it.level);
		if (it.level == fault->goal_level)
			break;

		validate_direct_spte(vcpu, it.sptep, direct_access);

		sp = klpp_kvm_mmu_get_child_sp(vcpu, it.sptep, base_gfn,
					  true, direct_access);
		if (sp == ERR_PTR(-EEXIST))
			continue;

		klpr_link_shadow_page(vcpu, it.sptep, sp);
		if (fault->huge_page_disallowed)
			account_nx_huge_page(vcpu->kvm, sp,
					     fault->req_level >= it.level);
	}

	if (WARN_ON_ONCE(it.level != fault->goal_level))
		return -EFAULT;

	ret = mmu_set_spte(vcpu, fault->slot, it.sptep, gw->pte_access,
			   base_gfn, fault->pfn, fault);
	if (ret == RET_PF_SPURIOUS)
		return ret;

	FNAME(pte_prefetch)(vcpu, gw, it.sptep);
	return ret;
}

int klpp_paging64_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct guest_walker walker;
	int r;

	WARN_ON_ONCE(fault->is_tdp);

	/*
	 * Look up the guest pte for the faulting address.
	 * If PFEC.RSVD is set, this is a shadow page fault.
	 * The bit needs to be cleared before walking guest page tables.
	 */
	r = FNAME(walk_addr)(&walker, vcpu, fault->addr,
			     fault->error_code & ~PFERR_RSVD_MASK);

	/*
	 * The page is not mapped by the guest.  Let the guest handle it.
	 */
	if (!r) {
		if (!fault->prefetch)
			kvm_inject_emulated_page_fault(vcpu, &walker.fault);

		return RET_PF_RETRY;
	}

	fault->gfn = walker.gfn;
	fault->max_level = walker.level;
	fault->slot = kvm_vcpu_gfn_to_memslot(vcpu, fault->gfn);

	if (page_fault_handle_page_track(vcpu, fault)) {
		shadow_page_table_clear_flood(vcpu, fault->addr);
		return RET_PF_WRITE_PROTECTED;
	}

	r = mmu_topup_memory_caches(vcpu, true);
	if (r)
		return r;

	r = kvm_faultin_pfn(vcpu, fault, walker.pte_access);
	if (r != RET_PF_CONTINUE)
		return r;

	/*
	 * Do not change pte_access if the pfn is a mmio page, otherwise
	 * we will cache the incorrect access into mmio spte.
	 */
	if (fault->write && !(walker.pte_access & ACC_WRITE_MASK) &&
	    !is_cr0_wp(vcpu->arch.mmu) && !fault->user && fault->slot) {
		walker.pte_access |= ACC_WRITE_MASK;
		walker.pte_access &= ~ACC_USER_MASK;

		/*
		 * If we converted a user page to a kernel page,
		 * so that the kernel can write to it when cr0.wp=0,
		 * then we should prevent the kernel from executing it
		 * if SMEP is enabled.
		 */
		if (is_cr4_smep(vcpu->arch.mmu))
			walker.pte_access &= ~ACC_EXEC_MASK;
	}

	r = RET_PF_RETRY;
	write_lock(&vcpu->kvm->mmu_lock);

	if (is_page_fault_stale(vcpu, fault))
		goto out_unlock;

	r = make_mmu_pages_available(vcpu);
	if (r)
		goto out_unlock;
	r = klpp_paging64_fetch(vcpu, fault, &walker);

out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(fault->pfn);
	return r;
}

/* klp-ccp: from arch/x86/kvm/mmu/mmu.c */
#undef PTTYPE
#define PTTYPE 32

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef pt_element_t
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define pt_element_t u32

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef guest_walker
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define guest_walker guest_walker32

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef FNAME
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define FNAME(name) paging##32_##name

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef PT_LEVEL_BITS
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#define PT_LEVEL_BITS 10

/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
#undef PT_MAX_FULL_LEVELS
/* klp-ccp: from arch/x86/kvm/mmu/paging_tmpl.h */
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

static gfn_t gpte_to_gfn_lvl(pt_element_t gpte, int lvl)
{
	return (gpte & PT_LVL_ADDR_MASK(lvl)) >> PAGE_SHIFT;
}

static inline void FNAME(protect_clean_gpte)(struct kvm_mmu *mmu, unsigned *access,
					     unsigned gpte)
{
	unsigned mask;

	/* dirty bit is not supported, so no need to track it */
	if (!PT_HAVE_ACCESSED_DIRTY(mmu))
		return;

	BUILD_BUG_ON(PT_WRITABLE_MASK != ACC_WRITE_MASK);

	mask = (unsigned)~ACC_WRITE_MASK;
	/* Allow write access to dirty gptes */
	mask |= (gpte >> (PT_GUEST_DIRTY_SHIFT - PT_WRITABLE_SHIFT)) &
		PT_WRITABLE_MASK;
	*access &= mask;
}

static inline int FNAME(is_present_gpte)(unsigned long pte)
{
#if PTTYPE != PTTYPE_EPT
	return pte & PT_PRESENT_MASK;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static bool FNAME(is_bad_mt_xwr)(struct rsvd_bits_validate *rsvd_check, u64 gpte)
{
#if PTTYPE != PTTYPE_EPT
	return false;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static bool FNAME(is_rsvd_bits_set)(struct kvm_mmu *mmu, u64 gpte, int level)
{
	return __is_rsvd_bits_set(&mmu->guest_rsvd_check, gpte, level) ||
	       FNAME(is_bad_mt_xwr)(&mmu->guest_rsvd_check, gpte);
}

static bool FNAME(prefetch_invalid_gpte)(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *spte,
				  u64 gpte)
{
	if (!FNAME(is_present_gpte)(gpte))
		goto no_present;

	/* Prefetch only accessed entries (unless A/D bits are disabled). */
	if (PT_HAVE_ACCESSED_DIRTY(vcpu->arch.mmu) &&
	    !(gpte & PT_GUEST_ACCESSED_MASK))
		goto no_present;

	if (FNAME(is_rsvd_bits_set)(vcpu->arch.mmu, gpte, PG_LEVEL_4K))
		goto no_present;

	return false;

no_present:
	drop_spte(vcpu->kvm, spte);
	return true;
}

static inline unsigned FNAME(gpte_access)(u64 gpte)
{
	unsigned access;
#if PTTYPE == PTTYPE_EPT
#error "klp-ccp: non-taken branch"
#else
	BUILD_BUG_ON(ACC_EXEC_MASK != PT_PRESENT_MASK);
	BUILD_BUG_ON(ACC_EXEC_MASK != 1);
	access = gpte & (PT_WRITABLE_MASK | PT_USER_MASK | PT_PRESENT_MASK);
	/* Combine NX with P (which is set here) to get ACC_EXEC_MASK.  */
	access ^= (gpte >> PT64_NX_SHIFT);
#endif
	return access;
}

extern int FNAME(walk_addr_generic)(struct guest_walker *walker,
				    struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				    gpa_t addr, u64 access);

static int FNAME(walk_addr)(struct guest_walker *walker,
			    struct kvm_vcpu *vcpu, gpa_t addr, u64 access)
{
	return FNAME(walk_addr_generic)(walker, vcpu, vcpu->arch.mmu, addr,
					access);
}

static bool
FNAME(prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     u64 *spte, pt_element_t gpte)
{
	struct kvm_memory_slot *slot;
	unsigned pte_access;
	gfn_t gfn;
	kvm_pfn_t pfn;

	if (FNAME(prefetch_invalid_gpte)(vcpu, sp, spte, gpte))
		return false;

	gfn = gpte_to_gfn(gpte);
	pte_access = sp->role.access & FNAME(gpte_access)(gpte);
	FNAME(protect_clean_gpte)(vcpu->arch.mmu, &pte_access, gpte);

	slot = gfn_to_memslot_dirty_bitmap(vcpu, gfn, pte_access & ACC_WRITE_MASK);
	if (!slot)
		return false;

	pfn = gfn_to_pfn_memslot_atomic(slot, gfn);
	if (is_error_pfn(pfn))
		return false;

	mmu_set_spte(vcpu, slot, spte, pte_access, gfn, pfn, NULL);
	kvm_release_pfn_clean(pfn);
	return true;
}

extern bool FNAME(gpte_changed)(struct kvm_vcpu *vcpu,
				struct guest_walker *gw, int level);

static void FNAME(pte_prefetch)(struct kvm_vcpu *vcpu, struct guest_walker *gw,
				u64 *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	u64 *spte;
	int i;

	sp = sptep_to_sp(sptep);

	if (sp->role.level > PG_LEVEL_4K)
		return;

	/*
	 * If addresses are being invalidated, skip prefetching to avoid
	 * accidentally prefetching those addresses.
	 */
	if (unlikely(vcpu->kvm->mmu_invalidate_in_progress))
		return;

	if (sp->role.direct)
		return __direct_pte_prefetch(vcpu, sp, sptep);

	i = spte_index(sptep) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (is_shadow_present_pte(*spte))
			continue;

		if (!FNAME(prefetch_gpte)(vcpu, sp, spte, gptep[i]))
			break;
	}
}

static int klpp_paging32_fetch(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			 struct guest_walker *gw)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	unsigned int direct_access, access;
	int top_level, ret;
	gfn_t base_gfn = fault->gfn;

	WARN_ON_ONCE(gw->gfn != base_gfn);
	direct_access = gw->pte_access;

	top_level = vcpu->arch.mmu->cpu_role.base.level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if (FNAME(gpte_changed)(vcpu, gw, top_level))
		return RET_PF_RETRY;

	if (WARN_ON_ONCE(!VALID_PAGE(vcpu->arch.mmu->root.hpa)))
		return RET_PF_RETRY;

	/*
	 * Load a new root and retry the faulting instruction in the extremely
	 * unlikely scenario that the guest root gfn became visible between
	 * loading a dummy root and handling the resulting page fault, e.g. if
	 * userspace create a memslot in the interim.
	 */
	if (unlikely(kvm_mmu_is_dummy_root(vcpu->arch.mmu->root.hpa))) {
		kvm_make_request(KVM_REQ_MMU_FREE_OBSOLETE_ROOTS, vcpu);
		return RET_PF_RETRY;
	}

	for_each_shadow_entry(vcpu, fault->addr, it) {
		gfn_t table_gfn;

		clear_sp_write_flooding_count(it.sptep);
		if (it.level == gw->level)
			break;

		table_gfn = gw->table_gfn[it.level - 2];
		access = gw->pt_access[it.level - 2];
		sp = klpp_kvm_mmu_get_child_sp(vcpu, it.sptep, table_gfn,
					  false, access);

		/*
		 * Synchronize the new page before linking it, as the CPU (KVM)
		 * is architecturally disallowed from inserting non-present
		 * entries into the TLB, i.e. the guest isn't required to flush
		 * the TLB when changing the gPTE from non-present to present.
		 *
		 * For PG_LEVEL_4K, kvm_mmu_find_shadow_page() has already
		 * synchronized the page via kvm_sync_page().
		 *
		 * For higher level pages, which cannot be unsync themselves
		 * but can have unsync children, synchronize via the slower
		 * mmu_sync_children().  If KVM needs to drop mmu_lock due to
		 * contention or to reschedule, instruct the caller to retry
		 * the #PF (mmu_sync_children() ensures forward progress will
		 * be made).
		 */
		if (sp != ERR_PTR(-EEXIST) && sp->unsync_children &&
		    mmu_sync_children(vcpu, sp, false))
			return RET_PF_RETRY;

		/*
		 * Verify that the gpte in the page, which is now either
		 * write-protected or unsync, wasn't modified between the fault
		 * and acquiring mmu_lock.  This needs to be done even when
		 * reusing an existing shadow page to ensure the information
		 * gathered by the walker matches the information stored in the
		 * shadow page (which could have been modified by a different
		 * vCPU even if the page was already linked).  Holding mmu_lock
		 * prevents the shadow page from changing after this point.
		 */
		if (FNAME(gpte_changed)(vcpu, gw, it.level - 1))
			return RET_PF_RETRY;

		if (sp != ERR_PTR(-EEXIST))
			klpr_link_shadow_page(vcpu, it.sptep, sp);

		if (fault->write && table_gfn == fault->gfn)
			fault->write_fault_to_shadow_pgtable = true;
	}

	/*
	 * Adjust the hugepage size _after_ resolving indirect shadow pages.
	 * KVM doesn't support mapping hugepages into the guest for gfns that
	 * are being shadowed by KVM, i.e. allocating a new shadow page may
	 * affect the allowed hugepage size.
	 */
	kvm_mmu_hugepage_adjust(vcpu, fault);

	trace_kvm_mmu_spte_requested(fault);

	for (; shadow_walk_okay(&it); shadow_walk_next(&it)) {
		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, *it.sptep, it.level);

		base_gfn = gfn_round_for_level(fault->gfn, it.level);
		if (it.level == fault->goal_level)
			break;

		validate_direct_spte(vcpu, it.sptep, direct_access);

		sp = klpp_kvm_mmu_get_child_sp(vcpu, it.sptep, base_gfn,
					  true, direct_access);
		if (sp == ERR_PTR(-EEXIST))
			continue;

		klpr_link_shadow_page(vcpu, it.sptep, sp);
		if (fault->huge_page_disallowed)
			account_nx_huge_page(vcpu->kvm, sp,
					     fault->req_level >= it.level);
	}

	if (WARN_ON_ONCE(it.level != fault->goal_level))
		return -EFAULT;

	ret = mmu_set_spte(vcpu, fault->slot, it.sptep, gw->pte_access,
			   base_gfn, fault->pfn, fault);
	if (ret == RET_PF_SPURIOUS)
		return ret;

	FNAME(pte_prefetch)(vcpu, gw, it.sptep);
	return ret;
}

int klpp_paging32_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct guest_walker walker;
	int r;

	WARN_ON_ONCE(fault->is_tdp);

	/*
	 * Look up the guest pte for the faulting address.
	 * If PFEC.RSVD is set, this is a shadow page fault.
	 * The bit needs to be cleared before walking guest page tables.
	 */
	r = FNAME(walk_addr)(&walker, vcpu, fault->addr,
			     fault->error_code & ~PFERR_RSVD_MASK);

	/*
	 * The page is not mapped by the guest.  Let the guest handle it.
	 */
	if (!r) {
		if (!fault->prefetch)
			kvm_inject_emulated_page_fault(vcpu, &walker.fault);

		return RET_PF_RETRY;
	}

	fault->gfn = walker.gfn;
	fault->max_level = walker.level;
	fault->slot = kvm_vcpu_gfn_to_memslot(vcpu, fault->gfn);

	if (page_fault_handle_page_track(vcpu, fault)) {
		shadow_page_table_clear_flood(vcpu, fault->addr);
		return RET_PF_WRITE_PROTECTED;
	}

	r = mmu_topup_memory_caches(vcpu, true);
	if (r)
		return r;

	r = kvm_faultin_pfn(vcpu, fault, walker.pte_access);
	if (r != RET_PF_CONTINUE)
		return r;

	/*
	 * Do not change pte_access if the pfn is a mmio page, otherwise
	 * we will cache the incorrect access into mmio spte.
	 */
	if (fault->write && !(walker.pte_access & ACC_WRITE_MASK) &&
	    !is_cr0_wp(vcpu->arch.mmu) && !fault->user && fault->slot) {
		walker.pte_access |= ACC_WRITE_MASK;
		walker.pte_access &= ~ACC_USER_MASK;

		/*
		 * If we converted a user page to a kernel page,
		 * so that the kernel can write to it when cr0.wp=0,
		 * then we should prevent the kernel from executing it
		 * if SMEP is enabled.
		 */
		if (is_cr4_smep(vcpu->arch.mmu))
			walker.pte_access &= ~ACC_EXEC_MASK;
	}

	r = RET_PF_RETRY;
	write_lock(&vcpu->kvm->mmu_lock);

	if (is_page_fault_stale(vcpu, fault))
		goto out_unlock;

	r = make_mmu_pages_available(vcpu);
	if (r)
		goto out_unlock;
	r = klpp_paging32_fetch(vcpu, fault, &walker);

out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(fault->pfn);
	return r;
}


#include <linux/livepatch.h>

extern typeof(shadow_present_mask) shadow_present_mask
	 KLP_RELOC_SYMBOL(kvm, kvm, shadow_present_mask);

extern typeof(__direct_pte_prefetch) __direct_pte_prefetch
	 KLP_RELOC_SYMBOL(kvm, kvm, __direct_pte_prefetch);
extern typeof(__kvm_mmu_get_shadow_page) __kvm_mmu_get_shadow_page
	 KLP_RELOC_SYMBOL(kvm, kvm, __kvm_mmu_get_shadow_page);
extern typeof(disallowed_hugepage_adjust) disallowed_hugepage_adjust
	 KLP_RELOC_SYMBOL(kvm, kvm, disallowed_hugepage_adjust);
extern typeof(drop_spte) drop_spte KLP_RELOC_SYMBOL(kvm, kvm, drop_spte);
extern typeof(ept_gpte_changed) ept_gpte_changed
	 KLP_RELOC_SYMBOL(kvm, kvm, ept_gpte_changed);
extern typeof(ept_walk_addr_generic) ept_walk_addr_generic
	 KLP_RELOC_SYMBOL(kvm, kvm, ept_walk_addr_generic);
extern typeof(fast_page_fault) fast_page_fault
	 KLP_RELOC_SYMBOL(kvm, kvm, fast_page_fault);
extern typeof(gfn_to_memslot_dirty_bitmap) gfn_to_memslot_dirty_bitmap
	 KLP_RELOC_SYMBOL(kvm, kvm, gfn_to_memslot_dirty_bitmap);
extern typeof(gfn_to_pfn_memslot_atomic) gfn_to_pfn_memslot_atomic
	 KLP_RELOC_SYMBOL(kvm, kvm, gfn_to_pfn_memslot_atomic);
extern typeof(is_page_fault_stale) is_page_fault_stale
	 KLP_RELOC_SYMBOL(kvm, kvm, is_page_fault_stale);
extern typeof(kvm_faultin_pfn) kvm_faultin_pfn
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_faultin_pfn);
extern typeof(kvm_flush_remote_tlbs_sptep) kvm_flush_remote_tlbs_sptep
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_flush_remote_tlbs_sptep);
extern typeof(kvm_gfn_is_write_tracked) kvm_gfn_is_write_tracked
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_gfn_is_write_tracked);
extern typeof(kvm_inject_emulated_page_fault) kvm_inject_emulated_page_fault
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_inject_emulated_page_fault);
extern typeof(kvm_mmu_child_role) kvm_mmu_child_role
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_mmu_child_role);
extern typeof(kvm_mmu_hugepage_adjust) kvm_mmu_hugepage_adjust
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_mmu_hugepage_adjust);
extern typeof(kvm_mmu_remote_flush_or_zap) kvm_mmu_remote_flush_or_zap
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_mmu_remote_flush_or_zap);
extern typeof(kvm_mmu_zap_oldest_mmu_pages) kvm_mmu_zap_oldest_mmu_pages
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_mmu_zap_oldest_mmu_pages);
extern typeof(kvm_release_pfn_clean) kvm_release_pfn_clean
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_release_pfn_clean);
extern typeof(kvm_vcpu_gfn_to_memslot) kvm_vcpu_gfn_to_memslot
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_vcpu_gfn_to_memslot);
extern typeof(make_nonleaf_spte) make_nonleaf_spte
	 KLP_RELOC_SYMBOL(kvm, kvm, make_nonleaf_spte);
extern typeof(mark_unsync) mark_unsync KLP_RELOC_SYMBOL(kvm, kvm, mark_unsync);
extern typeof(mmu_page_zap_pte) mmu_page_zap_pte
	 KLP_RELOC_SYMBOL(kvm, kvm, mmu_page_zap_pte);
extern typeof(mmu_set_spte) mmu_set_spte
	 KLP_RELOC_SYMBOL(kvm, kvm, mmu_set_spte);
extern typeof(mmu_sync_children) mmu_sync_children
	 KLP_RELOC_SYMBOL(kvm, kvm, mmu_sync_children);
extern typeof(mmu_topup_memory_caches) mmu_topup_memory_caches
	 KLP_RELOC_SYMBOL(kvm, kvm, mmu_topup_memory_caches);
extern typeof(paging32_gpte_changed) paging32_gpte_changed
	 KLP_RELOC_SYMBOL(kvm, kvm, paging32_gpte_changed);
extern typeof(paging32_walk_addr_generic) paging32_walk_addr_generic
	 KLP_RELOC_SYMBOL(kvm, kvm, paging32_walk_addr_generic);
extern typeof(paging64_gpte_changed) paging64_gpte_changed
	 KLP_RELOC_SYMBOL(kvm, kvm, paging64_gpte_changed);
extern typeof(paging64_walk_addr_generic) paging64_walk_addr_generic
	 KLP_RELOC_SYMBOL(kvm, kvm, paging64_walk_addr_generic);
extern typeof(pte_list_add) pte_list_add
	 KLP_RELOC_SYMBOL(kvm, kvm, pte_list_add);
extern typeof(pte_list_remove) pte_list_remove
	 KLP_RELOC_SYMBOL(kvm, kvm, pte_list_remove);
extern typeof(shadow_page_table_clear_flood) shadow_page_table_clear_flood
	 KLP_RELOC_SYMBOL(kvm, kvm, shadow_page_table_clear_flood);
extern typeof(shadow_walk_next) shadow_walk_next
	 KLP_RELOC_SYMBOL(kvm, kvm, shadow_walk_next);
extern typeof(trace_kvm_mmu_spte_requested) trace_kvm_mmu_spte_requested
	 KLP_RELOC_SYMBOL(kvm, kvm, trace_kvm_mmu_spte_requested);
extern typeof(track_possible_nx_huge_page) track_possible_nx_huge_page
	 KLP_RELOC_SYMBOL(kvm, kvm, track_possible_nx_huge_page);

#endif /* IS_ENABLED(CONFIG_X86) */
