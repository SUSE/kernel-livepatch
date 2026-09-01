/*
 * livepatch_bsc1270303
 *
 * Fix for CVE-2026-53360, bsc#1270303
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

#if IS_ENABLED(CONFIG_KVM_AMD_SEV)

#include "livepatch_bsc1270303.h"

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/psp.h>
#include <linux/psp-sev.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/misc_cgroup.h>
#include <linux/processor.h>
#include <linux/trace_events.h>
#include <uapi/linux/sev-guest.h>
#include <asm/pkru.h>
#include <asm/trapnr.h>
#include <asm/fpu/xcr.h>
#include <asm/fpu/xstate.h>
#include <asm/debugreg.h>
#include <asm/sev.h>
/* klp-ccp: from arch/x86/kvm/mmu.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/kvm_cache_regs.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/x86.h */
#include <linux/kvm_host.h>
#include <asm/fpu/xstate.h>
#include <asm/mce.h>
#include <asm/pvclock.h>
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
/* klp-ccp: from arch/x86/kvm/svm/svm.h */
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/bits.h>
#include <asm/svm.h>
#include <asm/sev-common.h>

#define MAX_DIRECT_ACCESS_MSRS	48

struct kvm_sev_info {
	bool active;		/* SEV enabled guest */
	bool es_active;		/* SEV-ES enabled guest */
	bool need_init;		/* waiting for SEV_INIT2 */
	unsigned int asid;	/* ASID used for this guest */
	unsigned int handle;	/* SEV firmware handle */
	int fd;			/* SEV device fd */
	unsigned long pages_locked; /* Number of pages locked */
	struct list_head regions_list;  /* List of registered regions */
	u64 ap_jump_table;	/* SEV-ES AP Jump Table address */
	u64 vmsa_features;
	u16 ghcb_version;	/* Highest guest GHCB protocol version allowed */
	struct kvm *enc_context_owner; /* Owner of copied encryption context */
	struct list_head mirror_vms; /* List of VMs mirroring */
	struct list_head mirror_entry; /* Use as a list entry of mirrors */
	struct misc_cg *misc_cg; /* For misc cgroup accounting */
	atomic_t migration_in_progress;
	void *snp_context;      /* SNP guest context page */
	void *guest_req_buf;    /* Bounce buffer for SNP Guest Request input */
	void *guest_resp_buf;   /* Bounce buffer for SNP Guest Request output */
	struct mutex guest_req_mutex; /* Must acquire before using bounce buffers */
};

struct kvm_svm {
	struct kvm kvm;

	/* Struct members for AVIC */
	u32 avic_vm_id;
	struct page *avic_logical_id_table_page;
	struct page *avic_physical_id_table_page;
	struct hlist_node hnode;

	struct kvm_sev_info sev_info;
};

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
	unsigned int ap_reset_hold_type;

	/* SEV-ES scratch area support */
	u64 sw_scratch;
	void *ghcb_sa;
	u32 ghcb_sa_len;
	bool ghcb_sa_sync;
	bool ghcb_sa_free;

	/* SNP Page-State-Change buffer entries currently being processed */
	u16 psc_idx;
	u16 psc_inflight;
	bool psc_2m;

	u64 ghcb_registered_gpa;

	struct mutex snp_vmsa_mutex; /* Used to handle concurrent updates of VMSA. */
	gpa_t snp_vmsa_gpa;
	bool snp_ap_waiting_for_reset;
	bool snp_has_guest_vmsa;
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

static __always_inline struct kvm_svm *to_kvm_svm(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_svm, kvm);
}

static __always_inline struct kvm_sev_info *to_kvm_sev_info(struct kvm *kvm)
{
	return &to_kvm_svm(kvm)->sev_info;
}

/* klp-ccp: from arch/x86/kvm/svm/svm_ops.h */
#include <linux/compiler_types.h>

/* klp-ccp: from arch/x86/kvm/trace.h */
#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>
#include <asm/vmx.h>
#include <asm/svm.h>
#include <asm/clocksource.h>
#include <asm/pvclock-abi.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_KVM_H */

#include <trace/define_trace.h>

/* klp-ccp: from arch/x86/kvm/svm/sev.c */
#define GHCB_SCRATCH_AREA_LIMIT		(16ULL * PAGE_SIZE)
int klpp_setup_vmgexit_scratch(struct vcpu_svm *svm, bool sync, u64 len)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 ghcb_scratch_beg, ghcb_scratch_end;
	u64 scratch_gpa_beg, scratch_gpa_end;
	void *scratch_va;

	scratch_gpa_beg = svm->sev_es.sw_scratch;
	if (!scratch_gpa_beg) {
		pr_err("vmgexit: scratch gpa not provided\n");
		goto e_scratch;
	}

	scratch_gpa_end = scratch_gpa_beg + len;
	if (scratch_gpa_end < scratch_gpa_beg) {
		pr_err("vmgexit: scratch length (%#llx) not valid for scratch address (%#llx)\n",
		       len, scratch_gpa_beg);
		goto e_scratch;
	}

	if ((scratch_gpa_beg & PAGE_MASK) == control->ghcb_gpa) {
		/* Scratch area begins within GHCB */
		ghcb_scratch_beg = control->ghcb_gpa +
				   offsetof(struct ghcb, shared_buffer);
		ghcb_scratch_end = control->ghcb_gpa +
				   offsetof(struct ghcb, reserved_0xff0);

		/*
		 * If the scratch area begins within the GHCB, it must be
		 * completely contained in the GHCB shared buffer area.
		 */
		if (scratch_gpa_beg < ghcb_scratch_beg ||
		    scratch_gpa_end > ghcb_scratch_end) {
			pr_err("vmgexit: scratch area is outside of GHCB shared buffer area (%#llx - %#llx)\n",
			       scratch_gpa_beg, scratch_gpa_end);
			goto e_scratch;
		}

		scratch_va = (void *)svm->sev_es.ghcb;
		scratch_va += (scratch_gpa_beg - control->ghcb_gpa);
	} else {
		/* GHCB v2 requires the scratch area to be within the GHCB. */
		if (to_kvm_sev_info(svm->vcpu.kvm)->ghcb_version >= 2)
			goto e_scratch;

		/*
		 * The guest memory must be read into a kernel buffer, so
		 * limit the size
		 */
		if (len > GHCB_SCRATCH_AREA_LIMIT) {
			pr_err("vmgexit: scratch area exceeds KVM limits (%#llx requested, %#llx limit)\n",
			       len, GHCB_SCRATCH_AREA_LIMIT);
			goto e_scratch;
		}
		scratch_va = kvzalloc(len, GFP_KERNEL_ACCOUNT);
		if (!scratch_va)
			return -ENOMEM;

		if (kvm_read_guest(svm->vcpu.kvm, scratch_gpa_beg, scratch_va, len)) {
			/* Unable to copy scratch area from guest */
			pr_err("vmgexit: kvm_read_guest for scratch area failed\n");

			kvfree(scratch_va);
			return -EFAULT;
		}

		/*
		 * The scratch area is outside the GHCB. The operation will
		 * dictate whether the buffer needs to be synced before running
		 * the vCPU next time (i.e. a read was requested so the data
		 * must be written back to the guest memory).
		 */
		svm->sev_es.ghcb_sa_sync = sync;
		svm->sev_es.ghcb_sa_free = true;
	}

	svm->sev_es.ghcb_sa = scratch_va;
	svm->sev_es.ghcb_sa_len = len;

	return 0;

e_scratch:
	ghcb_set_sw_exit_info_1(svm->sev_es.ghcb, 2);
	ghcb_set_sw_exit_info_2(svm->sev_es.ghcb, GHCB_ERR_INVALID_SCRATCH_AREA);

	return 1;
}


#include <linux/livepatch.h>

extern typeof(kvm_read_guest) kvm_read_guest
	 KLP_RELOC_SYMBOL(kvm_amd, kvm, kvm_read_guest);

#endif /* IS_ENABLED(CONFIG_KVM_AMD_SEV) */
