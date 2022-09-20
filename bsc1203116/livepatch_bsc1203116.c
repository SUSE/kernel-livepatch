/*
 * livepatch_bsc1203116
 *
 * Fix for CVE-2022-39188, bsc#1203116
 *
 *  Upstream commit:
 *  b67fbebd4cf9 ("mmu_gather: Force tlb-flush VM_PFNMAP vmas")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  7df62767050ce652de3694d15346c44ab14a5783
 *
 *  SLE15-SP2 and -SP3 commit:
 *  84aac5736c8eee01079a839fffadbc69f16ef8ad
 *
 *  SLE15-SP4 commit:
 *  3a89213bc2c0f5988a55fc4c223c0c1241a5e2ee
 *
 *
 *  Copyright (c) 2022 SUSE
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

/* klp-ccp: from mm/mmap.c */
#define pr_fmt(fmt) "mmap" ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>

/* klp-ccp: from include/linux/mm_types.h */
static void (*klpe_tlb_gather_mmu)(struct mmu_gather *tlb, struct mm_struct *mm,
				unsigned long start, unsigned long end);
static void (*klpe_tlb_finish_mmu)(struct mmu_gather *tlb,
				unsigned long start, unsigned long end);

/* klp-ccp: from include/linux/mm.h */
static void (*klpe_unmap_vmas)(struct mmu_gather *tlb, struct vm_area_struct *start_vma,
		unsigned long start, unsigned long end);

/* klp-ccp: from include/linux/swap.h */
static void (*klpe_lru_add_drain)(void);

/* klp-ccp: from mm/mmap.c */
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/profile.h>
#include <linux/export.h>
#include <linux/mempolicy.h>
#include <linux/mmdebug.h>
#include <linux/perf_event.h>
#include <linux/uprobes.h>
#include <linux/notifier.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>

#if defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
/* klp-ccp: from include/asm-generic/tlb.h */
static void (*klpe_tlb_flush_mmu)(struct mmu_gather *tlb);

#define klpr_tlb_flush_mmu (*klpe_tlb_flush_mmu)

#elif defined(CONFIG_S390)
/* klp-ccp: from arch/s390/include/asm/tlb.h */
static void (*klpe_tlb_table_flush)(struct mmu_gather *tlb);

static inline void klpr_tlb_flush_mmu_free(struct mmu_gather *tlb)
{
	(*klpe_tlb_table_flush)(tlb);
}

static inline void klpr_tlb_flush_mmu(struct mmu_gather *tlb)
{
	tlb_flush_mmu_tlbonly(tlb);
	klpr_tlb_flush_mmu_free(tlb);
}

#else
#error "support for architecture not implemented"
#endif

/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

static void (*klpe_free_pgtables)(struct mmu_gather *tlb, struct vm_area_struct *start_vma,
		unsigned long floor, unsigned long ceiling);

/* klp-ccp: from mm/mmap.c */
void klpp_unmap_region(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end)
{
	struct vm_area_struct *next = prev ? prev->vm_next : mm->mmap;
	struct mmu_gather tlb;

	(*klpe_lru_add_drain)();
	(*klpe_tlb_gather_mmu)(&tlb, mm, start, end);
	update_hiwater_rss(mm);
	(*klpe_unmap_vmas)(&tlb, vma, start, end);
	/*
	 * Fix CVE-2022-39188
	 *  +10 lines
	 */
	/*
	 * Ensure we have no stale TLB entries by the time this mapping is
	 * removed from the rmap.
	 * Note that we don't have to worry about nested flushes here because
	 * we're holding the mm semaphore for removing the mapping - so any
	 * concurrent flush in this region has to be coming through the rmap,
	 * and we synchronize against that using the rmap lock.
	 */
	if ((vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)) != 0)
		klpr_tlb_flush_mmu(&tlb);

	(*klpe_free_pgtables)(&tlb, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
				 next ? next->vm_start : USER_PGTABLES_CEILING);
	(*klpe_tlb_finish_mmu)(&tlb, start, end);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1203116.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "free_pgtables", (void *)&klpe_free_pgtables },
	{ "lru_add_drain", (void *)&klpe_lru_add_drain },
	{ "tlb_finish_mmu", (void *)&klpe_tlb_finish_mmu },
	{ "tlb_gather_mmu", (void *)&klpe_tlb_gather_mmu },
#if defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
	{ "tlb_flush_mmu", (void *)&klpe_tlb_flush_mmu },
#elif defined(CONFIG_S390)
	{ "tlb_table_flush", (void *)&klpe_tlb_table_flush },
#else
#error "support for architecture not implemented"
#endif
	{ "unmap_vmas", (void *)&klpe_unmap_vmas },
};

int livepatch_bsc1203116_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
