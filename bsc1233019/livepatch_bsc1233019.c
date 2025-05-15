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

/* klp-ccp: from arch/x86/kvm/svm.c */
#define pr_fmt(fmt) "SVM: " fmt

#include <linux/kvm_host.h>

/* klp-ccp: from include/linux/kvm_host.h */
static int (*klpe_kvm_vcpu_read_guest_page)(struct kvm_vcpu *vcpu, gfn_t gfn, void *data, int offset,
			     int len);

/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>

/* klp-ccp: from include/kvm/iodev.h */
#define __KVM_IODEV_H__

/* klp-ccp: from arch/x86/kvm/ioapic.h */
#include <linux/kvm_host.h>
#include <kvm/iodev.h>

/* klp-ccp: from arch/x86/kvm/lapic.h */
#include <kvm/iodev.h>
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/mmu.h */
#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/x86.h */
#include <asm/processor.h>
#include <linux/kvm_host.h>

/* klp-ccp: from arch/x86/kvm/cpuid.h */
#include <asm/processor.h>
/* klp-ccp: from arch/x86/kvm/pmu.h */
#include <linux/nospec.h>
/* klp-ccp: from arch/x86/kvm/svm.c */
#include <linux/mod_devicetable.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

#include <linux/sched.h>

#include <linux/slab.h>

#include <linux/frame.h>

/* klp-ccp: from include/linux/swap.h */
#define _LINUX_SWAP_H

/* klp-ccp: from arch/x86/kvm/svm.c */
#include <linux/swap.h>

#include <asm/apic.h>
#include <asm/perf_event.h>

#include <asm/desc.h>

#include <asm/kvm_para.h>

#include <asm/nospec-branch.h>
#include <asm/processor.h>

/* klp-ccp: from arch/x86/include/asm/vmx.h */
#define VMX_H

/* klp-ccp: from arch/x86/include/asm/svm.h */
#define __SVM_H

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

/* klp-ccp: from arch/x86/kvm/svm.c */
static const u32 host_save_user_msrs[10]

#ifdef CONFIG_X86_64

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
;

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

static inline struct vcpu_svm *to_svm(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_svm, vcpu);
}

u64 klpp_nested_svm_get_tdp_pdptr(struct kvm_vcpu *vcpu, int index)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u64 cr3 = svm->nested.nested_cr3;
	u64 pdpte;
	int ret;

	/*
	 * Note, nCR3 is "assumed" to be 32-byte aligned, i.e. the CPU ignores
	 * nCR3[4:0] when loading PDPTEs from memory.
	 */
	ret = (*klpe_kvm_vcpu_read_guest_page)(vcpu, gpa_to_gfn(__sme_clr(cr3)), &pdpte,
				       (cr3 & GENMASK(11, 5)) + index * 8, 8);
	if (ret)
		return 0;
	return pdpte;
}


#include "livepatch_bsc1233019.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "kvm_amd"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "kvm_vcpu_read_guest_page", (void *)&klpe_kvm_vcpu_read_guest_page,
	  "kvm" },
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

int livepatch_bsc1233019_init(void)
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

void livepatch_bsc1233019_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_KVM_AMD) */
