/*
 * livepatch_bsc1233019
 *
 * Fix for CVE-2024-50115, bsc#1233019
 *
 *  Upstream commit:
 *  f559b2e9c5c5 ("KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory")
 *
 *  SLE12-SP5 commit:
 *  0050d80e08e6b30f40ef743d375aa13e11669719
 *
 *  SLE15-SP3 commit:
 *  3b09191896a26fa81d7d13eb794c5070f1655405
 *
 *  SLE15-SP4 and -SP5 commit:
 *  4c6b1dad1cc37e4b1ac5f93f64eb936b9858afb0
 *
 *  SLE15-SP6 commit:
 *  b8f7c4d914478186686724a57cd396e0e4bad905
 *
 *  SLE MICRO-6-0 commit:
 *  b8f7c4d914478186686724a57cd396e0e4bad905
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

#if IS_ENABLED(CONFIG_KVM_AMD)

#if !IS_MODULE(CONFIG_KVM_AMD)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from arch/x86/kvm/svm/nested.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/kernel.h>

#include <asm/msr-index.h>

/* klp-ccp: from arch/x86/kvm/kvm_emulate.h */
#include <asm/desc_defs.h>
/* klp-ccp: from arch/x86/kvm/fpu.h */
#include <asm/fpu/api.h>

/* klp-ccp: from arch/x86/kvm/trace.h */
#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#include <asm/svm.h>
#include <asm/clocksource.h>
#include <asm/pvclock-abi.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_KVM_H */

#include <trace/define_trace.h>

/* klp-ccp: from arch/x86/kvm/mmu.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/kvm_cache_regs.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/x86.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/reverse_cpuid.h */
#include <uapi/asm/kvm.h>
#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>

/* klp-ccp: from arch/x86/kvm/cpuid.h */
#include <asm/processor.h>
#include <uapi/asm/kvm_para.h>
/* klp-ccp: from arch/x86/kvm/smm.h */
#include <linux/build_bug.h>
/* klp-ccp: from arch/x86/kvm/lapic.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/hyperv.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/svm/svm.h */
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/bits.h>

#include <asm/svm.h>

#define MAX_DIRECT_ACCESS_MSRS	48

struct kvm_vmcb_info {
	struct vmcb *ptr;
	unsigned long pa;
	int cpu;
	uint64_t asid_generation;
};

struct vmcb_save_area_cached {
	u64 efer;
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
};

struct vmcb_ctrl_area_cached {
	u32 intercepts[MAX_INTERCEPT];
	u16 pause_filter_thresh;
	u16 pause_filter_count;
	u64 iopm_base_pa;
	u64 msrpm_base_pa;
	u64 tsc_offset;
	u32 asid;
	u8 tlb_ctl;
	u32 int_ctl;
	u32 int_vector;
	u32 int_state;
	u32 exit_code;
	u32 exit_code_hi;
	u64 exit_info_1;
	u64 exit_info_2;
	u32 exit_int_info;
	u32 exit_int_info_err;
	u64 nested_ctl;
	u32 event_inj;
	u32 event_inj_err;
	u64 next_rip;
	u64 nested_cr3;
	u64 virt_ext;
	u32 clean;
	union {
#if IS_ENABLED(CONFIG_HYPERV) || IS_ENABLED(CONFIG_KVM_HYPERV)
		struct hv_vmcb_enlightenments hv_enlightenments;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		u8 reserved_sw[32];
	};
};

struct svm_nested_state {
	struct kvm_vmcb_info vmcb02;
	u64 hsave_msr;
	u64 vm_cr_msr;
	u64 vmcb12_gpa;
	u64 last_vmcb12_gpa;

	/* These are the merged vectors */
	u32 *msrpm;

	/* A VMRUN has started but has not yet been performed, so
	 * we cannot inject a nested vmexit yet.  */
	bool nested_run_pending;

	/* cache for control fields of the guest */
	struct vmcb_ctrl_area_cached ctl;

	/*
	 * Note: this struct is not kept up-to-date while L2 runs; it is only
	 * valid within nested_svm_vmrun.
	 */
	struct vmcb_save_area_cached save;

	bool initialized;

	/*
	 * Indicates whether MSR bitmap for L2 needs to be rebuilt due to
	 * changes in MSR bitmap for L1 or switching to a different L2. Note,
	 * this flag can only be used reliably in conjunction with a paravirt L1
	 * which informs L0 whether any changes to MSR bitmap for L2 were done
	 * on its side.
	 */
	bool force_msr_bitmap_recalc;
};

struct vcpu_sev_es_state {
	/* SEV-ES support */
	struct sev_es_save_area *vmsa;
	struct ghcb *ghcb;
	u8 valid_bitmap[16];
	struct kvm_host_map ghcb_map;
	bool received_first_sipi;

	/* SEV-ES scratch area support */
	u64 sw_scratch;
	void *ghcb_sa;
	u32 ghcb_sa_len;
	bool ghcb_sa_sync;
	bool ghcb_sa_free;
};

struct vcpu_svm {
	struct kvm_vcpu vcpu;
	/* vmcb always points at current_vmcb->ptr, it's purely a shorthand. */
	struct vmcb *vmcb;
	struct kvm_vmcb_info vmcb01;
	struct kvm_vmcb_info *current_vmcb;
	u32 asid;
	u32 sysenter_esp_hi;
	u32 sysenter_eip_hi;
	uint64_t tsc_aux;

	u64 msr_decfg;

	u64 next_rip;

	u64 spec_ctrl;

	u64 tsc_ratio_msr;
	/*
	 * Contains guest-controlled bits of VIRT_SPEC_CTRL, which will be
	 * translated into the appropriate L2_CFG bits on the host to
	 * perform speculative control.
	 */
	u64 virt_spec_ctrl;

	u32 *msrpm;

	ulong nmi_iret_rip;

	struct svm_nested_state nested;

	/* NMI mask value, used when vNMI is not enabled */
	bool nmi_masked;

	/*
	 * True when NMIs are still masked but guest IRET was just intercepted
	 * and KVM is waiting for RIP to change, which will signal that the
	 * intercepted IRET was retired and thus NMI can be unmasked.
	 */
	bool awaiting_iret_completion;

	/*
	 * Set when KVM is awaiting IRET completion and needs to inject NMIs as
	 * soon as the IRET completes (e.g. NMI is pending injection).  KVM
	 * temporarily steals RFLAGS.TF to single-step the guest in this case
	 * in order to regain control as soon as the NMI-blocking condition
	 * goes away.
	 */
	bool nmi_singlestep;
	u64 nmi_singlestep_guest_rflags;

	bool nmi_l1_to_l2;

	unsigned long soft_int_csbase;
	unsigned long soft_int_old_rip;
	unsigned long soft_int_next_rip;
	bool soft_int_injected;

	u32 ldr_reg;
	u32 dfr_reg;
	struct page *avic_backing_page;
	u64 *avic_physical_id_cache;

	/*
	 * Per-vcpu list of struct amd_svm_iommu_ir:
	 * This is used mainly to store interrupt remapping information used
	 * when update the vcpu affinity. This avoids the need to scan for
	 * IRTE and try to match ga_tag in the IOMMU driver.
	 */
	struct list_head ir_list;
	spinlock_t ir_list_lock;

	/* Save desired MSR intercept (read: pass-through) state */
	struct {
		DECLARE_BITMAP(read, MAX_DIRECT_ACCESS_MSRS);
		DECLARE_BITMAP(write, MAX_DIRECT_ACCESS_MSRS);
	} shadow_msr_intercept;

	struct vcpu_sev_es_state sev_es;

	bool guest_state_loaded;

	bool x2avic_msrs_intercepted;

	/* Guest GIF value, used when vGIF is not enabled */
	bool guest_gif;
};

static __always_inline struct vcpu_svm *to_svm(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_svm, vcpu);
}

/* klp-ccp: from arch/x86/kvm/svm/nested.c */
u64 klpp_nested_svm_get_tdp_pdptr(struct kvm_vcpu *vcpu, int index)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u64 cr3 = svm->nested.ctl.nested_cr3;
	u64 pdpte;
	int ret;

	/*
	 * Note, nCR3 is "assumed" to be 32-byte aligned, i.e. the CPU ignores
	 * nCR3[4:0] when loading PDPTEs from memory.
	 */
	ret = kvm_vcpu_read_guest_page(vcpu, gpa_to_gfn(cr3), &pdpte,
				       (cr3 & GENMASK(11, 5)) + index * 8, 8);
	if (ret)
		return 0;
	return pdpte;
}


#include "livepatch_bsc1233019.h"

#include <linux/livepatch.h>

extern typeof(kvm_vcpu_read_guest_page) kvm_vcpu_read_guest_page
	 KLP_RELOC_SYMBOL(kvm_amd, kvm, kvm_vcpu_read_guest_page);

#endif /* IS_ENABLED(CONFIG_KVM_AMD) */
