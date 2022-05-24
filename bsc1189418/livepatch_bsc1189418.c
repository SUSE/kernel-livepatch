/*
 * livepatch_bsc1189418
 *
 * Fix for CVE-2021-3656, bsc#1189418 and for CVE-2021-3653, bsc#1189420
 *
 *  Upstream commits:
 *  c7dfa4009965 ("KVM: nSVM: always intercept VMLOAD/VMSAVE when nested
 *                 (CVE-2021-3656)")
 *  0f923e07124d ("KVM: nSVM: avoid picking up unsupported bits from L2 in
 *                 int_ctl (CVE-2021-3653)")
 *
 *  SLE12-SP3 commits:
 *  0f83408195dd943fde0b6a63e8c962af157a3627
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commits:
 *  f4931e99860c4a52d4f57ff6ce7f83419638c565
 *  9c35f8d4e13594b6cf0357e3d5aa5f4dbdf379b7
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commits:
 *  f4931e99860c4a52d4f57ff6ce7f83419638c565
 *  9c35f8d4e13594b6cf0357e3d5aa5f4dbdf379b7
 *  a1c39b14d6b74df84321ae691c82b622f343e68a
 *
 *  SLE15-SP2 and -SP3 commits:
 *  89ee512871d4be84dbcb3776e57fab48c6a9d489
 *  790261594034490f018538690ab890fad71a62f4
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

#if IS_ENABLED(CONFIG_KVM_AMD)

#if !IS_MODULE(CONFIG_KVM_AMD)
#error "Live patch supports only CONFIG_KVM_AMD=m"
#endif

/* klp-ccp: from arch/x86/kvm/svm.c */
#define pr_fmt(fmt) "SVM: " fmt

#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/include/asm/kvm_host.h */
static void (*klpe_kvm_mmu_reset_context)(struct kvm_vcpu *vcpu);

static int (*klpe_kvm_set_cr3)(struct kvm_vcpu *vcpu, unsigned long cr3);

static unsigned long (*klpe_kvm_get_rflags)(struct kvm_vcpu *vcpu);
static void (*klpe_kvm_set_rflags)(struct kvm_vcpu *vcpu, unsigned long rflags);

static void (*klpe_kvm_mmu_unload)(struct kvm_vcpu *vcpu);

/* klp-ccp: from include/linux/kvm_host.h */
static void (*klpe_kvm_release_page_dirty)(struct page *page);

/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>
/* klp-ccp: from arch/x86/kvm/ioapic.h */
#include <linux/kvm_host.h>
#include <kvm/iodev.h>
/* klp-ccp: from arch/x86/kvm/lapic.h */
#include <kvm/iodev.h>
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/mmu.h */
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/kvm_cache_regs.h */
static inline void kvm_register_write(struct kvm_vcpu *vcpu,
				      enum kvm_reg reg,
				      unsigned long val)
{
	vcpu->arch.regs[reg] = val;
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
}

static inline void enter_guest_mode(struct kvm_vcpu *vcpu)
{
	vcpu->arch.hflags |= HF_GUEST_MASK;
}

static inline bool is_guest_mode(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.hflags & HF_GUEST_MASK;
}

/* klp-ccp: from arch/x86/kvm/mmu.h */
#define PT64_ROOT_4LEVEL 4

static void
(*klpe_reset_shadow_zero_bits_mask)(struct kvm_vcpu *vcpu, struct kvm_mmu *context);

static void (*klpe_kvm_init_shadow_mmu)(struct kvm_vcpu *vcpu);

/* klp-ccp: from arch/x86/kvm/x86.h */
#include <asm/processor.h>
#include <linux/kvm_host.h>

static inline bool mmu_is_nested(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.walk_mmu == &vcpu->arch.nested_mmu;
}

/* klp-ccp: from arch/x86/kvm/cpuid.h */
#include <asm/processor.h>
/* klp-ccp: from arch/x86/kvm/pmu.h */
#include <linux/nospec.h>
/* klp-ccp: from arch/x86/kvm/svm.c */
#include <linux/mod_devicetable.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/frame.h>
#include <linux/swap.h>
#include <asm/apic.h>
#include <asm/perf_event.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/kvm_para.h>
#include <asm/virtext.h>

/* klp-ccp: from arch/x86/kvm/trace.h */
#include <linux/tracepoint.h>
#include <asm/vmx.h>
#include <asm/svm.h>
#include <asm/clocksource.h>
#include <asm/pvclock-abi.h>

/* klp-ccp: from arch/x86/kvm/svm.c */
static const u32 host_save_user_msrs[10];

#define NR_HOST_SAVE_USER_MSRS ARRAY_SIZE(host_save_user_msrs)

struct nested_state {
	struct vmcb *hsave;
	u64 hsave_msr;
	u64 vm_cr_msr;
	u64 vmcb;

	/* These are the merged vectors */
	u32 *msrpm;

	/* gpa pointers to the real vectors */
	u64 vmcb_msrpm;
	u64 vmcb_iopm;

	/* A VMEXIT is required but not yet emulated */
	bool exit_required;

	/* cache for intercepts of the guest */
	u32 intercept_cr;
	u32 intercept_dr;
	u32 intercept_exceptions;
	u64 intercept;

	/* Nested Paging related state */
	u64 nested_cr3;
};

struct vcpu_svm {
	struct kvm_vcpu vcpu;
	struct vmcb *vmcb;
	unsigned long vmcb_pa;
	struct svm_cpu_data *svm_data;
	uint64_t asid_generation;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t tsc_aux;

	u64 msr_decfg;

	u64 next_rip;

	u64 host_user_msrs[NR_HOST_SAVE_USER_MSRS];
	struct {
		u16 fs;
		u16 gs;
		u16 ldt;
		u64 gs_base;
	} host;

	u64 spec_ctrl;
	/*
	 * Contains guest-controlled bits of VIRT_SPEC_CTRL, which will be
	 * translated into the appropriate L2_CFG bits on the host to
	 * perform speculative control.
	 */
	u64 virt_spec_ctrl;

	u32 *msrpm;

	ulong nmi_iret_rip;

	struct nested_state nested;

	bool nmi_singlestep;
	u64 nmi_singlestep_guest_rflags;

	unsigned int3_injected;
	unsigned long int3_rip;

	/* cached guest cpuid flags for faster access */
	bool nrips_enabled	: 1;

	u32 ldr_reg;
	u32 dfr_reg;
	struct page *avic_backing_page;
	u64 *avic_physical_id_cache;
	bool avic_is_running;

	/*
	 * Per-vcpu list of struct amd_svm_iommu_ir:
	 * This is used mainly to store interrupt remapping information used
	 * when update the vcpu affinity. This avoids the need to scan for
	 * IRTE and try to match ga_tag in the IOMMU driver.
	 */
	struct list_head ir_list;
	spinlock_t ir_list_lock;

	/* which host CPU was used for running this vcpu */
	unsigned int last_cpu;
};

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
static bool (*klpe_npt_enabled);
#else
#error "klp-ccp: non-taken branch"
#endif

static void (*klpe_svm_set_cr0)(struct kvm_vcpu *vcpu, unsigned long cr0);
static void (*klpe_svm_flush_tlb)(struct kvm_vcpu *vcpu, bool invalidate_gpa);

enum {
	VMCB_INTERCEPTS, /* Intercept vectors, TSC offset,
			    pause filter count */
	VMCB_PERM_MAP,   /* IOPM Base and MSRPM Base */
	VMCB_ASID,	 /* ASID */
	VMCB_INTR,	 /* int_ctl, int_vector */
	VMCB_NPT,        /* npt_en, nCR3, gPAT */
	VMCB_CR,	 /* CR0, CR3, CR4, EFER */
	VMCB_DR,         /* DR6, DR7 */
	VMCB_DT,         /* GDT, IDT */
	VMCB_SEG,        /* CS, DS, SS, ES, CPL */
	VMCB_CR2,        /* CR2 only */
	VMCB_LBR,        /* DBGCTL, BR_FROM, BR_TO, LAST_EX_FROM, LAST_EX_TO */
	VMCB_AVIC,       /* AVIC APIC_BAR, AVIC APIC_BACKING_PAGE,
			  * AVIC PHYSICAL_TABLE pointer,
			  * AVIC LOGICAL_TABLE pointer
			  */
	VMCB_DIRTY_MAX,
};

static inline void mark_all_dirty(struct vmcb *vmcb)
{
	vmcb->control.clean = 0;
}

static inline void mark_dirty(struct vmcb *vmcb, int bit)
{
	vmcb->control.clean &= ~(1 << bit);
}

void klpp_recalc_intercepts(struct vcpu_svm *svm)
{
	struct vmcb_control_area *c, *h;
	struct nested_state *g;

	mark_dirty(svm->vmcb, VMCB_INTERCEPTS);

	if (!is_guest_mode(&svm->vcpu))
		return;

	c = &svm->vmcb->control;
	h = &svm->nested.hsave->control;
	g = &svm->nested;

	c->intercept_cr = h->intercept_cr | g->intercept_cr;
	c->intercept_dr = h->intercept_dr | g->intercept_dr;
	c->intercept_exceptions = h->intercept_exceptions | g->intercept_exceptions;
	c->intercept = h->intercept | g->intercept;

	/*
	 * Fix CVE-2021-3656
	 *  +2 lines
	 */
	c->intercept |= (1ULL << INTERCEPT_VMLOAD);
	c->intercept |= (1ULL << INTERCEPT_VMSAVE);

	/*
	 * Fix for CVE-2021-3653
	 *  +2 lines
	 *
	 * Livepatch specific deviation from upstream to also
	 * mitigate against another issue not directly related to the
	 * CVE, but still fixed silently by the stable backports of
	 * upstream commit 0f923e07124d ("KVM: nSVM: avoid picking up
	 * unsupported bits from L2 in int_ctl (CVE-2021-3653)") by
	 * means of folding in commit 91b7130cb660 ("KVM: SVM:
	 * preserve VGIF across VMCB switch"). Rationale:
	 * VGIF is not virtualized and not announced as a capability
	 * to L1. Hence, the vmcb12's ->int_ctl is expected to have
	 * V_GIF_*_MASK cleared. The vmcb02 will also have
	 * V_GIF_*_MASK clear, independent of whether
	 * V_GIF_ENABLE_MASK is set in vmcb01,
	 * c.f. enter_svm_guest_mode(). In conclusion, VGIF will not
	 * be active when L2 is being run and if stgi/clgi was not
	 * intercepted, then a clgi from L2 would operate directly on
	 * the HW GIF bit. This would enable L2 to block external
	 * IRQs, NMIs and the like for forever and thus hog the CPU
	 * and cause a DOS. We (L0) don't enable stgi/clgi intercepts
	 * if vgif is enabled, i.e. if V_GIF_ENABLE_MASK has been set
	 * for vmcb01. Any real-world L1 hypervisor *is* expected to
	 * have stgi/clgi intercepts enabled, but might fail to do so
	 * by mistake or with malicious intent. In this case,
	 * stgi/clgi intercepts are forced on below. If the L1 does
	 * not have stgi/clgi intercepts enabled, then any stgi/clgi
	 * event from L2 would cause a NESTED_EXIT_HOST return of
	 * handle_exit()->nested_svm_exit_handled() and handle_exit()
	 * would then proceed to invoke stgi_interception() resp.
	 * clgi_interception(). These would then clobber L0's view of
	 * L1's GIF status, but it's still better to mess up a
	 * broken/malicious L1 rather than a well-behaving L0.
	 */
	c->intercept |= (1ULL << INTERCEPT_STGI);
	c->intercept |= (1ULL << INTERCEPT_CLGI);
}

static inline struct vmcb *get_host_vmcb(struct vcpu_svm *svm)
{
	if (is_guest_mode(&svm->vcpu))
		return svm->nested.hsave;
	else
		return svm->vmcb;
}

static inline void klpr_clr_cr_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept_cr &= ~(1U << bit);

	klpp_recalc_intercepts(svm);
}

static inline void klpr_clr_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept &= ~(1ULL << bit);

	klpp_recalc_intercepts(svm);
}

static inline bool vgif_enabled(struct vcpu_svm *svm)
{
	return !!(svm->vmcb->control.int_ctl & V_GIF_ENABLE_MASK);
}

static inline void enable_gif(struct vcpu_svm *svm)
{
	if (vgif_enabled(svm))
		svm->vmcb->control.int_ctl |= V_GIF_MASK;
	else
		svm->vcpu.arch.hflags |= HF_GIF_MASK;
}

static int get_npt_level(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return PT64_ROOT_4LEVEL;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static void (*klpe_svm_set_efer)(struct kvm_vcpu *vcpu, u64 efer);

static void (*klpe_svm_set_cr0)(struct kvm_vcpu *vcpu, unsigned long cr0);

static int (*klpe_svm_set_cr4)(struct kvm_vcpu *vcpu, unsigned long cr4);

static unsigned long (*klpe_nested_svm_get_tdp_cr3)(struct kvm_vcpu *vcpu);

static u64 (*klpe_nested_svm_get_tdp_pdptr)(struct kvm_vcpu *vcpu, int index);

static void (*klpe_nested_svm_set_tdp_cr3)(struct kvm_vcpu *vcpu,
				   unsigned long root);

static void (*klpe_nested_svm_inject_npf_exit)(struct kvm_vcpu *vcpu,
				       struct x86_exception *fault);

static void klpr_nested_svm_init_mmu_context(struct kvm_vcpu *vcpu)
{
	WARN_ON(mmu_is_nested(vcpu));
	(*klpe_kvm_init_shadow_mmu)(vcpu);
	vcpu->arch.mmu.set_cr3           = (*klpe_nested_svm_set_tdp_cr3);
	vcpu->arch.mmu.get_cr3           = (*klpe_nested_svm_get_tdp_cr3);
	vcpu->arch.mmu.get_pdptr         = (*klpe_nested_svm_get_tdp_pdptr);
	vcpu->arch.mmu.inject_page_fault = (*klpe_nested_svm_inject_npf_exit);
	vcpu->arch.mmu.shadow_root_level = get_npt_level(vcpu);
	(*klpe_reset_shadow_zero_bits_mask)(vcpu, &vcpu->arch.mmu);
	vcpu->arch.walk_mmu              = &vcpu->arch.nested_mmu;
}

static void klpr_nested_svm_unmap(struct page *page)
{
	kunmap(page);
	(*klpe_kvm_release_page_dirty)(page);
}

/*
 * Fix CVE-2021-3653
 *  +1 line
 */
#define V_IRQ_INJECTION_BITS_MASK (V_IRQ_MASK | V_INTR_PRIO_MASK | V_IGN_TPR_MASK)

void klpp_enter_svm_guest_mode(struct vcpu_svm *svm, u64 vmcb_gpa,
				 struct vmcb *nested_vmcb, struct page *page)
{
	if ((*klpe_kvm_get_rflags)(&svm->vcpu) & X86_EFLAGS_IF)
		svm->vcpu.arch.hflags |= HF_HIF_MASK;
	else
		svm->vcpu.arch.hflags &= ~HF_HIF_MASK;

	if (nested_vmcb->control.nested_ctl & SVM_NESTED_CTL_NP_ENABLE) {
		(*klpe_kvm_mmu_unload)(&svm->vcpu);
		svm->nested.nested_cr3 = nested_vmcb->control.nested_cr3;
		klpr_nested_svm_init_mmu_context(&svm->vcpu);
	}

	/* Load the nested guest state */
	svm->vmcb->save.es = nested_vmcb->save.es;
	svm->vmcb->save.cs = nested_vmcb->save.cs;
	svm->vmcb->save.ss = nested_vmcb->save.ss;
	svm->vmcb->save.ds = nested_vmcb->save.ds;
	svm->vmcb->save.gdtr = nested_vmcb->save.gdtr;
	svm->vmcb->save.idtr = nested_vmcb->save.idtr;
	(*klpe_kvm_set_rflags)(&svm->vcpu, nested_vmcb->save.rflags);
	(*klpe_svm_set_efer)(&svm->vcpu, nested_vmcb->save.efer);
	(*klpe_svm_set_cr0)(&svm->vcpu, nested_vmcb->save.cr0);
	(*klpe_svm_set_cr4)(&svm->vcpu, nested_vmcb->save.cr4);
	if ((*klpe_npt_enabled)) {
		svm->vmcb->save.cr3 = nested_vmcb->save.cr3;
		svm->vcpu.arch.cr3 = nested_vmcb->save.cr3;
	} else
		(void)(*klpe_kvm_set_cr3)(&svm->vcpu, nested_vmcb->save.cr3);

	/* Guest paging mode is active - reset mmu */
	(*klpe_kvm_mmu_reset_context)(&svm->vcpu);

	svm->vmcb->save.cr2 = svm->vcpu.arch.cr2 = nested_vmcb->save.cr2;
	kvm_register_write(&svm->vcpu, VCPU_REGS_RAX, nested_vmcb->save.rax);
	kvm_register_write(&svm->vcpu, VCPU_REGS_RSP, nested_vmcb->save.rsp);
	kvm_register_write(&svm->vcpu, VCPU_REGS_RIP, nested_vmcb->save.rip);

	/* In case we don't even reach vcpu_run, the fields are not updated */
	svm->vmcb->save.rax = nested_vmcb->save.rax;
	svm->vmcb->save.rsp = nested_vmcb->save.rsp;
	svm->vmcb->save.rip = nested_vmcb->save.rip;
	svm->vmcb->save.dr7 = nested_vmcb->save.dr7;
	svm->vmcb->save.dr6 = nested_vmcb->save.dr6;
	svm->vmcb->save.cpl = nested_vmcb->save.cpl;

	svm->nested.vmcb_msrpm = nested_vmcb->control.msrpm_base_pa & ~0x0fffULL;
	svm->nested.vmcb_iopm  = nested_vmcb->control.iopm_base_pa  & ~0x0fffULL;

	/* cache intercepts */
	svm->nested.intercept_cr         = nested_vmcb->control.intercept_cr;
	svm->nested.intercept_dr         = nested_vmcb->control.intercept_dr;
	svm->nested.intercept_exceptions = nested_vmcb->control.intercept_exceptions;
	svm->nested.intercept            = nested_vmcb->control.intercept;

	(*klpe_svm_flush_tlb)(&svm->vcpu, true);
	/*
	 * Fix CVE-2021-3653
	 *  -1 line, +4 lines
	 *
	 * Livepatch specific deviation from upstream / resp. the
	 * stable backports: as V_GIF is not being virtualized and the
	 * capability not announced to L1, V_GIF_ENABLE_MASK and V_GIF
	 * are expected to always be unset in nested_vmcb. Thus, the
	 * additional mask below doesn't change anything
	 * wrt. V_GIF. Unlike upstream, don't take the V_GIF bits from
	 * L0, i.e. vmcb01, either: instead enable stgi/clgi
	 * intercepts in case the L1 hypervisor failed to do so,
	 * c.f. klpp_recalc_intercepts() from above.
	 */
	svm->vmcb->control.int_ctl = (nested_vmcb->control.int_ctl &
				      (V_TPR_MASK | V_IRQ_INJECTION_BITS_MASK));
	svm->vmcb->control.int_ctl |= V_INTR_MASKING_MASK;

	if (nested_vmcb->control.int_ctl & V_INTR_MASKING_MASK)
		svm->vcpu.arch.hflags |= HF_VINTR_MASK;
	else
		svm->vcpu.arch.hflags &= ~HF_VINTR_MASK;

	if (svm->vcpu.arch.hflags & HF_VINTR_MASK) {
		/* We only want the cr8 intercept bits of the guest */
		klpr_clr_cr_intercept(svm, INTERCEPT_CR8_READ);
		klpr_clr_cr_intercept(svm, INTERCEPT_CR8_WRITE);
	}

	/* We don't want to see VMMCALLs from a nested guest */
	klpr_clr_intercept(svm, INTERCEPT_VMMCALL);

	svm->vmcb->control.virt_ext = nested_vmcb->control.virt_ext;
	svm->vmcb->control.int_vector = nested_vmcb->control.int_vector;
	svm->vmcb->control.int_state = nested_vmcb->control.int_state;
	svm->vmcb->control.tsc_offset += nested_vmcb->control.tsc_offset;
	svm->vmcb->control.event_inj = nested_vmcb->control.event_inj;
	svm->vmcb->control.event_inj_err = nested_vmcb->control.event_inj_err;

	klpr_nested_svm_unmap(page);

	/* Enter Guest-Mode */
	enter_guest_mode(&svm->vcpu);

	/*
	 * Merge guest and host intercepts - must be called  with vcpu in
	 * guest-mode to take affect here
	 */
	klpp_recalc_intercepts(svm);

	svm->nested.vmcb = vmcb_gpa;

	enable_gif(svm);

	mark_all_dirty(svm->vmcb);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1189418.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "kvm_amd"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "npt_enabled", (void *)&klpe_npt_enabled, "kvm_amd" },
	{ "kvm_mmu_reset_context", (void *)&klpe_kvm_mmu_reset_context, "kvm" },
	{ "kvm_set_cr3", (void *)&klpe_kvm_set_cr3, "kvm" },
	{ "kvm_get_rflags", (void *)&klpe_kvm_get_rflags, "kvm" },
	{ "kvm_set_rflags", (void *)&klpe_kvm_set_rflags, "kvm" },
	{ "kvm_mmu_unload", (void *)&klpe_kvm_mmu_unload, "kvm" },
	{ "kvm_release_page_dirty", (void *)&klpe_kvm_release_page_dirty,
	  "kvm" },
	{ "reset_shadow_zero_bits_mask",
	  (void *)&klpe_reset_shadow_zero_bits_mask, "kvm" },
	{ "kvm_init_shadow_mmu", (void *)&klpe_kvm_init_shadow_mmu, "kvm" },
	{ "svm_set_efer", (void *)&klpe_svm_set_efer, "kvm_amd" },
	{ "svm_set_cr0", (void *)&klpe_svm_set_cr0, "kvm_amd" },
	{ "svm_flush_tlb", (void *)&klpe_svm_flush_tlb, "kvm_amd" },
	{ "nested_svm_inject_npf_exit",
	  (void *)&klpe_nested_svm_inject_npf_exit, "kvm_amd" },
	{ "nested_svm_get_tdp_cr3", (void *)&klpe_nested_svm_get_tdp_cr3,
	  "kvm_amd" },
	{ "nested_svm_get_tdp_pdptr", (void *)&klpe_nested_svm_get_tdp_pdptr,
	  "kvm_amd" },
	{ "nested_svm_set_tdp_cr3", (void *)&klpe_nested_svm_set_tdp_cr3,
	  "kvm_amd" },
	{ "svm_set_cr4", (void *)&klpe_svm_set_cr4, "kvm_amd" },
};

static int livepatch_bsc1189418_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1189418_module_nb = {
	.notifier_call = livepatch_bsc1189418_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1189418_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1189418_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1189418_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1189418_module_nb);
}

#endif /* IS_ENABLED(CONFIG_KVM_AMD) */
