/*
 * livepatch_bsc1271965
 *
 * Fix for CVE-2026-63794, bsc#1271965
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

#if IS_ENABLED(CONFIG_KVM_AMD)

#if !IS_MODULE(CONFIG_KVM_AMD)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1271965.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
#define CC_USING_FENTRY 1
/* klp-ccp: from arch/x86/kvm/svm.c */
#define pr_fmt(fmt) "SVM: " fmt

#include <linux/kvm_host.h>
/* klp-ccp: from arch/x86/kvm/irq.h */
#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
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
/* klp-ccp: from arch/x86/kvm/x86.h */
#include <asm/processor.h>
#include <asm/mwait.h>
#include <linux/kvm_host.h>
#include <asm/pvclock.h>
/* klp-ccp: from arch/x86/kvm/cpuid.h */
#include <asm/cpu.h>
#include <asm/processor.h>
/* klp-ccp: from arch/x86/kvm/pmu.h */
#include <linux/nospec.h>
/* klp-ccp: from arch/x86/kvm/svm.c */
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/trace_events.h>
#include <linux/slab.h>
#include <linux/amd-iommu.h>
#include <linux/hashtable.h>
#include <linux/frame.h>
#include <linux/psp-sev.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <asm/apic.h>
#include <asm/perf_event.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/kvm_para.h>
#include <asm/irq_remapping.h>
#include <asm/microcode.h>
#include <asm/spec-ctrl.h>
#include <asm/cpu_device_id.h>
#include <asm/nospec-branch.h>
#include <asm/processor.h>
#include <asm/virtext.h>

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
#define __sme_page_pa(x) __sme_set(page_to_pfn(x) << PAGE_SHIFT)

static inline bool sev_guest(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &kvm->arch.sev_info;

	return sev->active;
}

static struct page **(*klpe_sev_pin_memory)(struct kvm *kvm, unsigned long uaddr,
				    unsigned long ulen, unsigned long *n,
				    int write);

static void sev_unpin_memory(struct kvm *kvm, struct page **pages,
			     unsigned long npages)
{
	struct kvm_sev_info *sev = &kvm->arch.sev_info;

	release_pages(pages, npages);
	kvfree(pages);
	sev->pages_locked -= npages;
}

static void sev_clflush_pages(struct page *pages[], unsigned long npages)
{
	uint8_t *page_virtual;
	unsigned long i;

	if (npages == 0 || pages == NULL)
		return;

	for (i = 0; i < npages; i++) {
		page_virtual = kmap_atomic(pages[i]);
		clflush_cache_range(page_virtual, PAGE_SIZE);
		kunmap_atomic(page_virtual);
	}
}

static int (*klpe___sev_issue_dbg_cmd)(struct kvm *kvm, unsigned long src,
			       unsigned long dst, int size,
			       int *error, bool enc);

static int klpr___sev_dbg_decrypt(struct kvm *kvm, unsigned long src_paddr,
			     unsigned long dst_paddr, int sz, int *err)
{
	int offset;

	/*
	 * Its safe to read more than we are asked, caller should ensure that
	 * destination has enough space.
	 */
	src_paddr = round_down(src_paddr, 16);
	offset = src_paddr & 15;
	sz = round_up(sz + offset, 16);

	return (*klpe___sev_issue_dbg_cmd)(kvm, src_paddr, dst_paddr, sz, err, false);
}

static int klpr___sev_dbg_decrypt_user(struct kvm *kvm, unsigned long paddr,
				  unsigned long __user dst_uaddr,
				  unsigned long dst_paddr,
				  int size, int *err)
{
	struct page *tpage = NULL;
	int ret, offset;

	/* if inputs are not 16-byte then use intermediate buffer */
	if (!IS_ALIGNED(dst_paddr, 16) ||
	    !IS_ALIGNED(paddr,     16) ||
	    !IS_ALIGNED(size,      16)) {
		tpage = (void *)alloc_page(GFP_KERNEL);
		if (!tpage)
			return -ENOMEM;

		dst_paddr = __sme_page_pa(tpage);
	}

	ret = klpr___sev_dbg_decrypt(kvm, paddr, dst_paddr, size, err);
	if (ret)
		goto e_free;

	if (tpage) {
		offset = paddr & 15;
		if (copy_to_user((void __user *)(uintptr_t)dst_uaddr,
				 page_address(tpage) + offset, size))
			ret = -EFAULT;
	}

e_free:
	if (tpage)
		__free_page(tpage);

	return ret;
}

static int klpr___sev_dbg_encrypt_user(struct kvm *kvm, unsigned long paddr,
				  unsigned long __user vaddr,
				  unsigned long dst_paddr,
				  unsigned long __user dst_vaddr,
				  int size, int *error)
{
	struct page *src_tpage = NULL;
	struct page *dst_tpage = NULL;
	int ret, len = size;

	/* If source buffer is not aligned then use an intermediate buffer */
	if (!IS_ALIGNED(vaddr, 16)) {
		src_tpage = alloc_page(GFP_KERNEL);
		if (!src_tpage)
			return -ENOMEM;

		if (copy_from_user(page_address(src_tpage),
				(void __user *)(uintptr_t)vaddr, size)) {
			__free_page(src_tpage);
			return -EFAULT;
		}

		paddr = __sme_page_pa(src_tpage);
	}

	/*
	 *  If destination buffer or length is not aligned then do read-modify-write:
	 *   - decrypt destination in an intermediate buffer
	 *   - copy the source buffer in an intermediate buffer
	 *   - use the intermediate buffer as source buffer
	 */
	if (!IS_ALIGNED(dst_vaddr, 16) || !IS_ALIGNED(size, 16)) {
		int dst_offset;

		dst_tpage = alloc_page(GFP_KERNEL);
		if (!dst_tpage) {
			ret = -ENOMEM;
			goto e_free;
		}

		ret = klpr___sev_dbg_decrypt(kvm, dst_paddr,
					__sme_page_pa(dst_tpage), size, error);
		if (ret)
			goto e_free;

		/*
		 *  If source is kernel buffer then use memcpy() otherwise
		 *  copy_from_user().
		 */
		dst_offset = dst_paddr & 15;

		if (src_tpage)
			memcpy(page_address(dst_tpage) + dst_offset,
			       page_address(src_tpage), size);
		else {
			if (copy_from_user(page_address(dst_tpage) + dst_offset,
					   (void __user *)(uintptr_t)vaddr, size)) {
				ret = -EFAULT;
				goto e_free;
			}
		}

		paddr = __sme_page_pa(dst_tpage);
		dst_paddr = round_down(dst_paddr, 16);
		len = round_up(size, 16);
	}

	ret = (*klpe___sev_issue_dbg_cmd)(kvm, paddr, dst_paddr, len, error, true);

e_free:
	if (src_tpage)
		__free_page(src_tpage);
	if (dst_tpage)
		__free_page(dst_tpage);
	return ret;
}

int klpp_sev_dbg_crypt(struct kvm *kvm, struct kvm_sev_cmd *argp, bool dec)
{
	unsigned long vaddr, vaddr_end, next_vaddr;
	unsigned long dst_vaddr, dst_vaddr_end;
	struct page **src_p, **dst_p;
	struct kvm_sev_dbg debug;
	unsigned long n;
	int ret, size;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&debug, (void __user *)(uintptr_t)argp->data, sizeof(debug)))
		return -EFAULT;

	vaddr = debug.src_uaddr;
	size = debug.len;
	vaddr_end = vaddr + size;
	dst_vaddr = debug.dst_uaddr;
	dst_vaddr_end = dst_vaddr + size;

	for (; vaddr < vaddr_end; vaddr = next_vaddr) {
		int len, s_off, d_off;

		/* lock userspace source and destination page */
		src_p = (*klpe_sev_pin_memory)(kvm, vaddr & PAGE_MASK, PAGE_SIZE, &n, 0);
		if (!src_p)
			return -EFAULT;

		dst_p = (*klpe_sev_pin_memory)(kvm, dst_vaddr & PAGE_MASK, PAGE_SIZE, &n, 1);
		if (!dst_p) {
			sev_unpin_memory(kvm, src_p, n);
			return -EFAULT;
		}

		/*
		 * The DBG_{DE,EN}CRYPT commands will perform {dec,en}cryption of the
		 * memory content (i.e it will write the same memory region with C=1).
		 * It's possible that the cache may contain the data with C=0, i.e.,
		 * unencrypted so invalidate it first.
		 */
		sev_clflush_pages(src_p, 1);
		sev_clflush_pages(dst_p, 1);

		/*
		 * Since user buffer may not be page aligned, calculate the
		 * offset within the page.
		 */
		s_off = vaddr & ~PAGE_MASK;
		d_off = dst_vaddr & ~PAGE_MASK;
		len = min_t(size_t, (PAGE_SIZE - s_off), size);
		len = min_t(size_t, len, PAGE_SIZE - d_off);

		if (dec)
			ret = klpr___sev_dbg_decrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     dst_vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     len, &argp->error);
		else
			ret = klpr___sev_dbg_encrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     dst_vaddr,
						     len, &argp->error);

		sev_unpin_memory(kvm, src_p, 1);
		sev_unpin_memory(kvm, dst_p, 1);

		if (ret)
			goto err;

		next_vaddr = vaddr + len;
		dst_vaddr = dst_vaddr + len;
		size -= len;
	}
err:
	return ret;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "kvm_amd"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__sev_issue_dbg_cmd", (void *)&klpe___sev_issue_dbg_cmd,
	  "kvm_amd" },
	{ "sev_pin_memory", (void *)&klpe_sev_pin_memory, "kvm_amd" },
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

int livepatch_bsc1271965_init(void)
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

void livepatch_bsc1271965_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_KVM_AMD) */
