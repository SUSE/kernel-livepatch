/*
 * livepatch_bsc1186483
 *
 * Fix for CVE-2021-22543, bsc#1186483
 *
 *  Upstream commits:
 *  a340b3e229b2 ("kvm: Map PFN-type memory regions as writable (if possible)")
 *  bd2fae8da794 ("KVM: do not assume PTE is writable after follow_pfn")
 *  a9545779ee9e ("KVM: Use kvm_pfn_t for local PFN variable in
 *                 hva_to_pfn_remapped()")
 *  f8be156be163 ("KVM: do not allow mapping valid but non-reference-counted
 *                 pages")
 *
 *  SLE12-SP3 commits:
 *  none yet
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  36db64302a9c1dec6684c37495b3c8b7575a2942
 *  0cb353ee04d24a3c53321644b8f7e6d78047c9d3
 *  a85db6b5cf3f2d71980d43df155cfe10a81df99e
 *  9c4f9b4db4feb27416c78d73eb7765d4449d4191
 *
 *  SLE15-SP2 commits:
 *  745b87daa371068247915502518bd53bd5712981
 *  cfa71edbcb69c6d338a241e7a2c05f46d3225cb9
 *  37956690f265615e6354c8748889c787414b58de
 *
 *  SLE15-SP3 commits:
 *  0d715a8957776aecd90b83347cc06b3ebc0ca12c
 *  2343113f691496c0c121fb06df90eb8348a7df40
 *  50f4816a775cb83d09ad4f396fa3d88eef024a59
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

#if !IS_MODULE(CONFIG_KVM) && !IS_MODULE(CONFIG_KVM_BOOK3S_64)
#error "Live patch supports only CONFIG_KVM=m || CONFIG_KVM_BOOK3S_64=m"
#endif

/* klp-ccp: from virt/kvm/kvm_main.c */
#include <kvm/iodev.h>
#include <linux/kvm_host.h>

/* klp-ccp: from include/linux/kvm_host.h */
kvm_pfn_t klpp___gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool *async, bool write_fault,
			       bool *writable);

/* klp-ccp: from virt/kvm/kvm_main.c */
#include <linux/kvm.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/kvm_para.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/compat.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm/ioctl.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>

/* klp-ccp: from virt/kvm/coalesced_mmio.h */
#include <linux/list.h>

/* klp-ccp: from virt/kvm/kvm_main.c */
static bool (*klpe_kvm_is_reserved_pfn)(kvm_pfn_t pfn);

static bool memslot_is_readonly(struct kvm_memory_slot *slot)
{
	return slot->flags & KVM_MEM_READONLY;
}

static unsigned long (*klpe___gfn_to_hva_many)(struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write);

static int get_user_page_nowait(unsigned long start, int write,
		struct page **page)
{
	int flags = FOLL_NOWAIT | FOLL_HWPOISON;

	if (write)
		flags |= FOLL_WRITE;

	return get_user_pages(start, 1, flags, page, NULL);
}

static inline int check_user_page_hwpoison(unsigned long addr)
{
	int rc, flags = FOLL_HWPOISON | FOLL_WRITE;

	rc = get_user_pages(addr, 1, flags, NULL, NULL);
	return rc == -EHWPOISON;
}

static bool hva_to_pfn_fast(unsigned long addr, bool atomic, bool *async,
			    bool write_fault, bool *writable, kvm_pfn_t *pfn)
{
	struct page *page[1];
	int npages;

	if (!(async || atomic))
		return false;

	/*
	 * Fast pin a writable pfn only if it is a write fault request
	 * or the caller allows to map a writable pfn for a read fault
	 * request.
	 */
	if (!(write_fault || writable))
		return false;

	npages = __get_user_pages_fast(addr, 1, 1, page);
	if (npages == 1) {
		*pfn = page_to_pfn(page[0]);

		if (writable)
			*writable = true;
		return true;
	}

	return false;
}

static int hva_to_pfn_slow(unsigned long addr, bool *async, bool write_fault,
			   bool *writable, kvm_pfn_t *pfn)
{
	struct page *page[1];
	int npages = 0;

	might_sleep();

	if (writable)
		*writable = write_fault;

	if (async) {
		down_read(&current->mm->mmap_sem);
		npages = get_user_page_nowait(addr, write_fault, page);
		up_read(&current->mm->mmap_sem);
	} else {
		unsigned int flags = FOLL_HWPOISON;

		if (write_fault)
			flags |= FOLL_WRITE;

		npages = get_user_pages_unlocked(addr, 1, page, flags);
	}
	if (npages != 1)
		return npages;

	/* map read fault as writable if possible */
	if (unlikely(!write_fault) && writable) {
		struct page *wpage[1];

		npages = __get_user_pages_fast(addr, 1, 1, wpage);
		if (npages == 1) {
			*writable = true;
			put_page(page[0]);
			page[0] = wpage[0];
		}

		npages = 1;
	}
	*pfn = page_to_pfn(page[0]);
	return npages;
}

static bool vma_is_valid(struct vm_area_struct *vma, bool write_fault)
{
	if (unlikely(!(vma->vm_flags & VM_READ)))
		return false;

	if (write_fault && (unlikely(!(vma->vm_flags & VM_WRITE))))
		return false;

	return true;
}

/* New. */
static int klpp_kvm_try_get_pfn(kvm_pfn_t pfn)
{
	if ((*klpe_kvm_is_reserved_pfn)(pfn))
		return 1;
	return get_page_unless_zero(pfn_to_page(pfn));
}

static int klpp_hva_to_pfn_remapped(struct vm_area_struct *vma,
			       unsigned long addr, bool *async,
			       /*
				* Fix CVE-2021-22543
				*  -1 line, +2 lines
				*/
			       bool write_fault, bool *writable,
			       kvm_pfn_t *p_pfn)
{
	/*
	 * Fix CVE-2021-22543
	 *  -1 line, +1 line
	 */
	kvm_pfn_t pfn;
	/*
	 * Fix CVE-2021-22543
	 *  +2 lines
	 */
	pte_t *ptep;
	spinlock_t *ptl;
	int r;

	/*
	 * Fix CVE-2021-22543
	 *  -1 line, +1 line
	 */
	r = follow_pte_pmd(vma->vm_mm, addr, &ptep, NULL, &ptl);
	if (r) {
		/*
		 * get_user_pages fails for VM_IO and VM_PFNMAP vmas and does
		 * not call the fault handler, so do it here.
		 */
		bool unlocked = false;
		r = fixup_user_fault(current, current->mm, addr,
				     (write_fault ? FAULT_FLAG_WRITE : 0),
				     &unlocked);
		if (unlocked)
			return -EAGAIN;
		if (r)
			return r;

		/*
		 * Fix CVE-2021-22543
		 *  -1 line, +1 line
		 */
		r = follow_pte_pmd(vma->vm_mm, addr, &ptep, NULL, &ptl);
		if (r)
			return r;

	}

	/*
	 * Fix CVE-2021-22543
	 *  +4 lines
	 */
	if (write_fault && !pte_write(*ptep)) {
		pfn = KVM_PFN_ERR_RO_FAULT;
		goto out;
	}

	/*
	 * Fix CVE-2021-22543
	 *  +3 lines
	 */
	if (writable)
		*writable = pte_write(*ptep);
	pfn = pte_pfn(*ptep);

	/*
	 * Get a reference here because callers of *hva_to_pfn* and
	 * *gfn_to_pfn* ultimately call kvm_release_pfn_clean on the
	 * returned pfn.  This is only needed if the VMA has VM_MIXEDMAP
	 * set, but the kvm_get_pfn/kvm_release_pfn_clean pair will
	 * simply do nothing for reserved pfns.
	 *
	 * Whoever called remap_pfn_range is also going to call e.g.
	 * unmap_mapping_range before the underlying pages are freed,
	 * causing a call to our MMU notifier.
	 */ 
	/*
	 * Fix CVE-2021-22543
	 *  -1 line, +2 lines
	 */
	if (!klpp_kvm_try_get_pfn(pfn))
		r = -EFAULT;

/*
 * Fix CVE-2021-22543
 *  +2 lines
 */
out:
	pte_unmap_unlock(ptep, ptl);
	*p_pfn = pfn;
	/*
	 * Fix CVE-2021-22543
	 *  -1 line, +1 line
	 */
	return r;
}

static kvm_pfn_t klpp_hva_to_pfn(unsigned long addr, bool atomic, bool *async,
			bool write_fault, bool *writable)
{
	struct vm_area_struct *vma;
	kvm_pfn_t pfn = 0;
	int npages, r;

	/* we can do it either atomically or asynchronously, not both */
	BUG_ON(atomic && async);

	if (hva_to_pfn_fast(addr, atomic, async, write_fault, writable, &pfn))
		return pfn;

	if (atomic)
		return KVM_PFN_ERR_FAULT;

	npages = hva_to_pfn_slow(addr, async, write_fault, writable, &pfn);
	if (npages == 1)
		return pfn;

	down_read(&current->mm->mmap_sem);
	if (npages == -EHWPOISON ||
	      (!async && check_user_page_hwpoison(addr))) {
		pfn = KVM_PFN_ERR_HWPOISON;
		goto exit;
	}

retry:
	vma = find_vma_intersection(current->mm, addr, addr + 1);

	if (vma == NULL)
		pfn = KVM_PFN_ERR_FAULT;
	else if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		/*
		 * Fix CVE-2021-22543
		 *  -1 line, +1 line
		 */
		r = klpp_hva_to_pfn_remapped(vma, addr, async, write_fault, writable, &pfn);
		if (r == -EAGAIN)
			goto retry;
		if (r < 0)
			pfn = KVM_PFN_ERR_FAULT;
	} else {
		if (async && vma_is_valid(vma, write_fault))
			*async = true;
		pfn = KVM_PFN_ERR_FAULT;
	}
exit:
	up_read(&current->mm->mmap_sem);
	return pfn;
}

kvm_pfn_t klpp___gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool *async, bool write_fault,
			       bool *writable)
{
	unsigned long addr = (*klpe___gfn_to_hva_many)(slot, gfn, NULL, write_fault);

	if (addr == KVM_HVA_ERR_RO_BAD) {
		if (writable)
			*writable = false;
		return KVM_PFN_ERR_RO_FAULT;
	}

	if (kvm_is_error_hva(addr)) {
		if (writable)
			*writable = false;
		return KVM_PFN_NOSLOT;
	}

	/* Do not map writable pfn in the readonly memslot. */
	if (writable && memslot_is_readonly(slot)) {
		*writable = false;
		writable = NULL;
	}

	return klpp_hva_to_pfn(addr, atomic, async, write_fault,
			  writable);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1186483.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "kvm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "kvm_is_reserved_pfn", (void *)&klpe_kvm_is_reserved_pfn, "kvm" },
	{ "__gfn_to_hva_many", (void *)&klpe___gfn_to_hva_many, "kvm" },
};

static int livepatch_bsc1186483_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1186483_module_nb = {
	.notifier_call = livepatch_bsc1186483_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1186483_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1186483_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1186483_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1186483_module_nb);
}
