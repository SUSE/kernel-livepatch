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

#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)

/* klp-ccp: from arch/x86/kvm/mmu/mmu_internal.h */
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <asm/kvm_host.h>

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

	bool has_mapped_host_mmio;

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

/* klp-ccp: from arch/x86/kvm/mmu/tdp_mmu.h */
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/mmu/spte.h */
#include <asm/vmx.h>

#define SPTE_MMU_PRESENT_MASK		BIT_ULL(11)

#define SPTE_BASE_ADDR_MASK (physical_mask & ~(u64)(PAGE_SIZE-1))

static inline struct kvm_mmu_page *to_shadow_page(hpa_t shadow_page)
{
	struct page *page = pfn_to_page((shadow_page) >> PAGE_SHIFT);

	return (struct kvm_mmu_page *)page_private(page);
}

static inline struct kvm_mmu_page *spte_to_child_sp(u64 spte)
{
	return to_shadow_page(spte & SPTE_BASE_ADDR_MASK);
}

static inline bool is_shadow_present_pte(u64 pte)
{
	return !!(pte & SPTE_MMU_PRESENT_MASK);
}

static inline bool is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

/* klp-ccp: from arch/x86/kvm/mmu/page_track.h */
#include <linux/kvm_host.h>

#include <asm/kvm_page_track.h>

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

/* klp-ccp: from arch/x86/kvm/mmu/mmu.c */
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

struct kvm_mmu_page *klpp_kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
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


#include <linux/livepatch.h>

extern typeof(__kvm_mmu_get_shadow_page) __kvm_mmu_get_shadow_page
	 KLP_RELOC_SYMBOL(kvm, kvm, __kvm_mmu_get_shadow_page);
extern typeof(kvm_mmu_child_role) kvm_mmu_child_role
	 KLP_RELOC_SYMBOL(kvm, kvm, kvm_mmu_child_role);

#endif /* IS_ENABLED(CONFIG_X86) */
