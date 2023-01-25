/*
 * bsc1204167_drivers_misc_sgi_gru_grufault
 *
 * Fix for CVE-2022-3424, bsc#1204167
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#if IS_ENABLED(CONFIG_SGI_GRU)

#if !IS_MODULE(CONFIG_SGI_GRU)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/misc/sgi-gru/grufault.c */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>

#include "gru.h"

/* klp-ccp: from drivers/misc/sgi-gru/gru.h */
#define GRU_CACHE_LINE_BYTES		64
#define GRU_HANDLE_STRIDE		256
#define GRU_CB_BASE			0

/* klp-ccp: from drivers/misc/sgi-gru/grutables.h */
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/mmu_notifier.h>

/* klp-ccp: from drivers/misc/sgi-gru/grulib.h */
enum {sco_gseg_owner, sco_cch_req_slice, sco_blade_chiplet};
struct gru_set_context_option_req {
	unsigned long	gseg;
	int		op;
	int		val0;
	long		val1;
};

/* klp-ccp: from drivers/misc/sgi-gru/gru_instructions.h */
#if defined(CONFIG_IA64)
#error "klp-ccp: non-taken branch"
#elif defined(CONFIG_X86_64)
#include <asm/cacheflush.h>
#define __flush_cache(p)		clflush(p)

#else
#error "klp-ccp: non-taken branch"
#endif

#define CBS_ACTIVE			2

struct gru_instruction_bits {
    /* DW 0  - low */
    unsigned int		icmd:      1;
    unsigned char		ima:	   3;	/* CB_DelRep, unmapped mode */
    unsigned char		reserved0: 4;
    unsigned int		xtype:     3;
    unsigned int		iaa0:      2;
    unsigned int		iaa1:      2;
    unsigned char		reserved1: 1;
    unsigned char		opc:       8;	/* opcode */
    unsigned char		exopc:     8;	/* extended opcode */
    /* DW 0  - high */
    unsigned int		idef2:    22;	/* TRi0 */
    unsigned char		reserved2: 2;
    unsigned char		istatus:   2;
    unsigned char		isubstatus:4;
    unsigned char		reserved3: 1;
    unsigned char		tlb_fault_color: 1;
    /* DW 1 */
    unsigned long		idef4;		/* 42 bits: TRi1, BufSize */
    /* DW 2-6 */
    unsigned long		idef1;		/* BAddr0 */
    unsigned long		idef5;		/* Nelem */
    unsigned long		idef6;		/* Stride, Operand1 */
    unsigned long		idef3;		/* BAddr1, Value, Operand2 */
    unsigned long		reserved4;
    /* DW 7 */
    unsigned long		avalue;		 /* AValue */
};

#define OP_BCOPY	0x01

static inline void gru_flush_cache(void *p)
{
	__flush_cache(p);
}

/* klp-ccp: from drivers/misc/sgi-gru/gruhandles.h */
#define GRU_GSEG0_BASE		0
#define GRU_MCS_BASE		(64 * 1024 * 1024)

#define GRU_NUM_CB		128

#define GRU_CBE_BASE		(GRU_MCS_BASE + 0x10000)
#define GRU_TFH_BASE		(GRU_MCS_BASE + 0x18000)

#define GRU_CHIPLETS_PER_HUB	2
#define GRU_HUBS_PER_BLADE	1
#define GRU_CHIPLETS_PER_BLADE	(GRU_HUBS_PER_BLADE * GRU_CHIPLETS_PER_HUB)

static inline void *get_gseg_base_address(void *base, int ctxnum)
{
	return (void *)(base + GRU_GSEG0_BASE + GRU_GSEG_STRIDE * ctxnum);
}

static inline void *get_gseg_base_address_cb(void *base, int ctxnum, int line)
{
	return (void *)(get_gseg_base_address(base, ctxnum) +
			GRU_CB_BASE + GRU_HANDLE_STRIDE * line);
}

static inline struct gru_tlb_fault_handle *get_tfh(void *base, int ctxnum)
{
	return (struct gru_tlb_fault_handle *)(base + GRU_TFH_BASE +
					ctxnum * GRU_HANDLE_STRIDE);
}

static inline unsigned long get_cb_number(void *cb)
{
	return (((unsigned long)cb - GRU_CB_BASE) % GRU_GSEG_PAGESIZE) /
					GRU_HANDLE_STRIDE;
}

static inline struct gru_control_block_extended *gru_tfh_to_cbe(
					struct gru_tlb_fault_handle *tfh)
{
	unsigned long cbe;

	cbe = (unsigned long)tfh - GRU_TFH_BASE + GRU_CBE_BASE;
	return (struct gru_control_block_extended*)cbe;
}

struct gru_tlb_fault_handle {
	unsigned int cmd:1;		/* DW 0 - low 32*/
	unsigned int delresp:1;
	unsigned int fill0:2;
	unsigned int opc:3;
	unsigned int fill1:9;

	unsigned int status:2;
	unsigned int fill2:2;
	unsigned int state:3;
	unsigned int fill3:1;

	unsigned int cause:6;
	unsigned int cb_int:1;
	unsigned int fill4:1;

	unsigned int indexway:12;	/* DW 0 - high 32 */
	unsigned int fill5:4;

	unsigned int ctxnum:4;
	unsigned int fill6:12;

	unsigned long missvaddr:64;	/* DW 1 */

	unsigned int missasid:24;	/* DW 2 */
	unsigned int fill7:8;
	unsigned int fillasid:24;
	unsigned int dirty:1;
	unsigned int gaa:2;
	unsigned long fill8:5;

	unsigned long pfn:41;		/* DW 3 */
	unsigned int fill9:7;
	unsigned int pagesize:5;
	unsigned int fill10:11;

	unsigned long fillvaddr:64;	/* DW 4 */

	unsigned long fill11[3];
};

enum tfh_status {
	TFHSTATUS_IDLE,
	TFHSTATUS_EXCEPTION,
	TFHSTATUS_ACTIVE,
};

enum tfh_state {
	TFHSTATE_INACTIVE,
	TFHSTATE_IDLE,
	TFHSTATE_MISS_UPM,
	TFHSTATE_MISS_FMM,
	TFHSTATE_HW_ERR,
	TFHSTATE_WRITE_TLB,
	TFHSTATE_RESTART_CBR,
};

enum tfh_cause {
	TFHCAUSE_NONE,
	TFHCAUSE_TLB_MISS,
	TFHCAUSE_TLB_MOD,
	TFHCAUSE_HW_ERROR_RR,
	TFHCAUSE_HW_ERROR_MAIN_ARRAY,
	TFHCAUSE_HW_ERROR_VALID,
	TFHCAUSE_HW_ERROR_PAGESIZE,
	TFHCAUSE_INSTRUCTION_EXCEPTION,
	TFHCAUSE_UNCORRECTIBLE_ERROR,
};

#define GAA_RAM				0x0

struct gru_control_block_extended {
	unsigned int reserved0:1;	/* DW 0  - low */
	unsigned int imacpy:3;
	unsigned int reserved1:4;
	unsigned int xtypecpy:3;
	unsigned int iaa0cpy:2;
	unsigned int iaa1cpy:2;
	unsigned int reserved2:1;
	unsigned int opccpy:8;
	unsigned int exopccpy:8;

	unsigned int idef2cpy:22;	/* DW 0  - high */
	unsigned int reserved3:10;

	unsigned int idef4cpy:22;	/* DW 1 */
	unsigned int reserved4:10;
	unsigned int idef4upd:22;
	unsigned int reserved5:10;

	unsigned long idef1upd:64;	/* DW 2 */

	unsigned long idef5cpy:64;	/* DW 3 */

	unsigned long idef6cpy:64;	/* DW 4 */

	unsigned long idef3upd:64;	/* DW 5 */

	unsigned long idef5upd:64;	/* DW 6 */

	unsigned int idef2upd:22;	/* DW 7 */
	unsigned int reserved6:10;

	unsigned int ecause:20;
	unsigned int cbrstate:4;
	unsigned int cbrexecstatus:8;
};

#define cbe_baddr0	idef1upd
#define cbe_baddr1	idef3upd
#define cbe_src_cl	idef6cpy
#define cbe_nelemcur	idef5upd

#define GRU_PAGESIZE(sh)	((((sh) > 20 ? (sh) + 2 : (sh)) >> 1) - 6)
#define GRU_SIZEAVAIL(sh)	(1UL << GRU_PAGESIZE(sh))

static int (*klpe_tfh_write_only)(struct gru_tlb_fault_handle *tfh, unsigned long paddr,
	int gaa, unsigned long vaddr, int asid, int dirty, int pagesize);
static void (*klpe_tfh_write_restart)(struct gru_tlb_fault_handle *tfh, unsigned long paddr,
	int gaa, unsigned long vaddr, int asid, int dirty, int pagesize);
static void (*klpe_tfh_user_polling_mode)(struct gru_tlb_fault_handle *tfh);
static void (*klpe_tfh_exception)(struct gru_tlb_fault_handle *tfh);

/* klp-ccp: from drivers/misc/sgi-gru/grutables.h */
static struct gru_stats_s (*klpe_gru_stats);
static struct gru_blade_state *(*klpe_gru_base)[];
static unsigned long (*klpe_gru_start_paddr);
static unsigned long (*klpe_gru_end_paddr);

#define GRU_MAX_BLADES		MAX_NUMNODES
#define GRU_MAX_GRUS		(GRU_MAX_BLADES * GRU_CHIPLETS_PER_BLADE)

struct gru_mm_tracker {				/* pack to reduce size */
	unsigned int		mt_asid_gen:24;	/* ASID wrap count */
	unsigned int		mt_asid:24;	/* current base ASID for gru */
	unsigned short		mt_ctxbitmap:16;/* bitmap of contexts using
						   asid */
} __attribute__ ((packed));

struct gru_mm_struct {
	struct mmu_notifier	ms_notifier;
	atomic_t		ms_refcnt;
	spinlock_t		ms_asid_lock;	/* protects ASID assignment */
	atomic_t		ms_range_active;/* num range_invals active */
	char			ms_released;
	wait_queue_head_t	ms_wait_queue;
	DECLARE_BITMAP(ms_asidmap, GRU_MAX_GRUS);
	struct gru_mm_tracker	ms_asids[GRU_MAX_GRUS];
};

#define get_tfh_by_index(g, i)						\
	((struct gru_tlb_fault_handle *)get_tfh((g)->gs_gru_base_vaddr, (i)))

#define thread_cbr_number(gts, n) ((gts)->ts_cbr_idx[(n) / GRU_CBR_AU_SIZE] \
				  * GRU_CBR_AU_SIZE + (n) % GRU_CBR_AU_SIZE)

static struct gru_thread_state *(*klpe_gru_alloc_thread_state)(struct vm_area_struct
				*vma, int tsid);

static int (*klpe_gru_update_cch)(struct gru_thread_state *gts);

static struct vm_area_struct *(*klpe_gru_find_vma)(unsigned long vaddr);

static unsigned long (*klpe_gru_options);

/* klp-ccp: from drivers/misc/sgi-gru/grufault.c */
#include <asm/uv/uv_hub.h>

#define VTOP_SUCCESS               0
#define VTOP_INVALID               -1
#define VTOP_RETRY                 -2

static inline int klpr_is_gru_paddr(unsigned long paddr)
{
	return paddr >= (*klpe_gru_start_paddr) && paddr < (*klpe_gru_end_paddr);
}

static struct gru_thread_state *(*klpe_gru_find_lock_gts)(unsigned long vaddr);

static struct gru_thread_state *klpr_gru_alloc_locked_gts(unsigned long vaddr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct gru_thread_state *gts = ERR_PTR(-EINVAL);

	down_write(&mm->mmap_sem);
	vma = (*klpe_gru_find_vma)(vaddr);
	if (!vma)
		goto err;

	gts = (*klpe_gru_alloc_thread_state)(vma, TSID(vaddr, vma));
	if (IS_ERR(gts))
		goto err;
	mutex_lock(&gts->ts_ctxlock);
	downgrade_write(&mm->mmap_sem);
	return gts;

err:
	up_write(&mm->mmap_sem);
	return gts;
}

static void (*klpe_gru_unlock_gts)(struct gru_thread_state *gts);
static void (*klpe_gru_unload_context)(struct gru_thread_state *gts, int savestate);

static void gru_cb_set_istatus_active(struct gru_instruction_bits *cbk)
{
	if (cbk) {
		cbk->istatus = CBS_ACTIVE;
	}
}

static int non_atomic_pte_lookup(struct vm_area_struct *vma,
				 unsigned long vaddr, int write,
				 unsigned long *paddr, int *pageshift)
{
	struct page *page;

#ifdef CONFIG_HUGETLB_PAGE
	*pageshift = is_vm_hugetlb_page(vma) ? HPAGE_SHIFT : PAGE_SHIFT;
#else
#error "klp-ccp: non-taken branch"
#endif
	if (get_user_pages(vaddr, 1, write ? FOLL_WRITE : 0, &page, NULL) <= 0)
		return -EFAULT;
	*paddr = page_to_phys(page);
	put_page(page);
	return 0;
}

static int atomic_pte_lookup(struct vm_area_struct *vma, unsigned long vaddr,
	int write, unsigned long *paddr, int *pageshift)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t pte;

	pgdp = pgd_offset(vma->vm_mm, vaddr);
	if (unlikely(pgd_none(*pgdp)))
		goto err;

	p4dp = p4d_offset(pgdp, vaddr);
	if (unlikely(p4d_none(*p4dp)))
		goto err;

	pudp = pud_offset(p4dp, vaddr);
	if (unlikely(pud_none(*pudp)))
		goto err;

	pmdp = pmd_offset(pudp, vaddr);
	if (unlikely(pmd_none(*pmdp)))
		goto err;
#ifdef CONFIG_X86_64
	if (unlikely(pmd_large(*pmdp)))
		pte = *(pte_t *) pmdp;
	else
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		pte = *pte_offset_kernel(pmdp, vaddr);

	if (unlikely(!pte_present(pte) ||
		     (write && (!pte_write(pte) || !pte_dirty(pte)))))
		return 1;

	*paddr = pte_pfn(pte) << PAGE_SHIFT;
#ifdef CONFIG_HUGETLB_PAGE
	*pageshift = is_vm_hugetlb_page(vma) ? HPAGE_SHIFT : PAGE_SHIFT;
#else
#error "klp-ccp: non-taken branch"
#endif
	return 0;

err:
	return 1;
}

static int klpr_gru_vtop(struct gru_thread_state *gts, unsigned long vaddr,
		    int write, int atomic, unsigned long *gpa, int *pageshift)
{
	struct mm_struct *mm = gts->ts_mm;
	struct vm_area_struct *vma;
	unsigned long paddr;
	int ret, ps;

	vma = find_vma(mm, vaddr);
	if (!vma)
		goto inval;

	/*
	 * Atomic lookup is faster & usually works even if called in non-atomic
	 * context.
	 */
	rmb();	/* Must/check ms_range_active before loading PTEs */
	ret = atomic_pte_lookup(vma, vaddr, write, &paddr, &ps);
	if (ret) {
		if (atomic)
			goto upm;
		if (non_atomic_pte_lookup(vma, vaddr, write, &paddr, &ps))
			goto inval;
	}
	if (klpr_is_gru_paddr(paddr))
		goto inval;
	paddr = paddr & ~((1UL << ps) - 1);
	*gpa = uv_soc_phys_ram_to_gpa(paddr);
	*pageshift = ps;
	return VTOP_SUCCESS;

inval:
	return VTOP_INVALID;
upm:
	return VTOP_RETRY;
}

static void gru_flush_cache_cbe(struct gru_control_block_extended *cbe)
{
	if (unlikely(cbe)) {
		cbe->cbrexecstatus = 0;         /* make CL dirty */
		gru_flush_cache(cbe);
	}
}

static void klpr_gru_preload_tlb(struct gru_state *gru,
			struct gru_thread_state *gts, int atomic,
			unsigned long fault_vaddr, int asid, int write,
			unsigned char tlb_preload_count,
			struct gru_tlb_fault_handle *tfh,
			struct gru_control_block_extended *cbe)
{
	unsigned long vaddr = 0, gpa;
	int ret, pageshift;

	if (cbe->opccpy != OP_BCOPY)
		return;

	if (fault_vaddr == cbe->cbe_baddr0)
		vaddr = fault_vaddr + GRU_CACHE_LINE_BYTES * cbe->cbe_src_cl - 1;
	else if (fault_vaddr == cbe->cbe_baddr1)
		vaddr = fault_vaddr + (1 << cbe->xtypecpy) * cbe->cbe_nelemcur - 1;

	fault_vaddr &= PAGE_MASK;
	vaddr &= PAGE_MASK;
	vaddr = min(vaddr, fault_vaddr + tlb_preload_count * PAGE_SIZE);

	while (vaddr > fault_vaddr) {
		ret = klpr_gru_vtop(gts, vaddr, write, atomic, &gpa, &pageshift);
		if (ret || (*klpe_tfh_write_only)(tfh, gpa, GAA_RAM, vaddr, asid, write,
					  GRU_PAGESIZE(pageshift)))
			return;
		gru_dbg(grudev,
			"%s: gid %d, gts 0x%p, tfh 0x%p, vaddr 0x%lx, asid 0x%x, rw %d, ps %d, gpa 0x%lx\n",
			atomic ? "atomic" : "non-atomic", gru->gs_gid, gts, tfh,
			vaddr, asid, write, pageshift, gpa);
		vaddr -= PAGE_SIZE;
		KLPR_STAT(tlb_preload_page);
	}
}

static int klpr_gru_try_dropin(struct gru_state *gru,
			  struct gru_thread_state *gts,
			  struct gru_tlb_fault_handle *tfh,
			  struct gru_instruction_bits *cbk)
{
	struct gru_control_block_extended *cbe = NULL;
	unsigned char tlb_preload_count = gts->ts_tlb_preload_count;
	int pageshift = 0, asid, write, ret, atomic = !cbk, indexway;
	unsigned long gpa = 0, vaddr = 0;

	/*
	 * NOTE: The GRU contains magic hardware that eliminates races between
	 * TLB invalidates and TLB dropins. If an invalidate occurs
	 * in the window between reading the TFH and the subsequent TLB dropin,
	 * the dropin is ignored. This eliminates the need for additional locks.
	 */

	/*
	 * Prefetch the CBE if doing TLB preloading
	 */
	if (unlikely(tlb_preload_count)) {
		cbe = gru_tfh_to_cbe(tfh);
		prefetchw(cbe);
	}

	/*
	 * Error if TFH state is IDLE or FMM mode & the user issuing a UPM call.
	 * Might be a hardware race OR a stupid user. Ignore FMM because FMM
	 * is a transient state.
	 */
	if (tfh->status != TFHSTATUS_EXCEPTION) {
		gru_flush_cache(tfh);
		sync_core();
		if (tfh->status != TFHSTATUS_EXCEPTION)
			goto failnoexception;
		KLPR_STAT(tfh_stale_on_fault);
	}
	if (tfh->state == TFHSTATE_IDLE)
		goto failidle;
	if (tfh->state == TFHSTATE_MISS_FMM && cbk)
		goto failfmm;

	write = (tfh->cause & TFHCAUSE_TLB_MOD) != 0;
	vaddr = tfh->missvaddr;
	asid = tfh->missasid;
	indexway = tfh->indexway;
	if (asid == 0)
		goto failnoasid;

	rmb();	/* TFH must be cache resident before reading ms_range_active */

	/*
	 * TFH is cache resident - at least briefly. Fail the dropin
	 * if a range invalidate is active.
	 */
	if (atomic_read(&gts->ts_gms->ms_range_active))
		goto failactive;

	ret = klpr_gru_vtop(gts, vaddr, write, atomic, &gpa, &pageshift);
	if (ret == VTOP_INVALID)
		goto failinval;
	if (ret == VTOP_RETRY)
		goto failupm;

	if (!(gts->ts_sizeavail & GRU_SIZEAVAIL(pageshift))) {
		gts->ts_sizeavail |= GRU_SIZEAVAIL(pageshift);
		if (atomic || !(*klpe_gru_update_cch)(gts)) {
			gts->ts_force_cch_reload = 1;
			goto failupm;
		}
	}

	if (unlikely(cbe) && pageshift == PAGE_SHIFT) {
		klpr_gru_preload_tlb(gru, gts, atomic, vaddr, asid, write, tlb_preload_count, tfh, cbe);
		gru_flush_cache_cbe(cbe);
	}

	gru_cb_set_istatus_active(cbk);
	gts->ustats.tlbdropin++;
	(*klpe_tfh_write_restart)(tfh, gpa, GAA_RAM, vaddr, asid, write,
			  GRU_PAGESIZE(pageshift));
	gru_dbg(grudev,
		"%s: gid %d, gts 0x%p, tfh 0x%p, vaddr 0x%lx, asid 0x%x, indexway 0x%x,"
		" rw %d, ps %d, gpa 0x%lx\n",
		atomic ? "atomic" : "non-atomic", gru->gs_gid, gts, tfh, vaddr, asid,
		indexway, write, pageshift, gpa);
	KLPR_STAT(tlb_dropin);
	return 0;

failnoasid:
	/* No asid (delayed unload). */
	KLPR_STAT(tlb_dropin_fail_no_asid);
	gru_dbg(grudev, "FAILED no_asid tfh: 0x%p, vaddr 0x%lx\n", tfh, vaddr);
	if (!cbk)
		(*klpe_tfh_user_polling_mode)(tfh);
	else
		gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	return -EAGAIN;

failupm:
	/* Atomic failure switch CBR to UPM */
	(*klpe_tfh_user_polling_mode)(tfh);
	gru_flush_cache_cbe(cbe);
	KLPR_STAT(tlb_dropin_fail_upm);
	gru_dbg(grudev, "FAILED upm tfh: 0x%p, vaddr 0x%lx\n", tfh, vaddr);
	return 1;

failfmm:
	/* FMM state on UPM call */
	gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	KLPR_STAT(tlb_dropin_fail_fmm);
	gru_dbg(grudev, "FAILED fmm tfh: 0x%p, state %d\n", tfh, tfh->state);
	return 0;

failnoexception:
	/* TFH status did not show exception pending */
	gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	if (cbk)
		gru_flush_cache(cbk);
	KLPR_STAT(tlb_dropin_fail_no_exception);
	gru_dbg(grudev, "FAILED non-exception tfh: 0x%p, status %d, state %d\n",
		tfh, tfh->status, tfh->state);
	return 0;

failidle:
	/* TFH state was idle  - no miss pending */
	gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	if (cbk)
		gru_flush_cache(cbk);
	KLPR_STAT(tlb_dropin_fail_idle);
	gru_dbg(grudev, "FAILED idle tfh: 0x%p, state %d\n", tfh, tfh->state);
	return 0;

failinval:
	/* All errors (atomic & non-atomic) switch CBR to EXCEPTION state */
	(*klpe_tfh_exception)(tfh);
	gru_flush_cache_cbe(cbe);
	KLPR_STAT(tlb_dropin_fail_invalid);
	gru_dbg(grudev, "FAILED inval tfh: 0x%p, vaddr 0x%lx\n", tfh, vaddr);
	return -EFAULT;

failactive:
	/* Range invalidate active. Switch to UPM iff atomic */
	if (!cbk)
		(*klpe_tfh_user_polling_mode)(tfh);
	else
		gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	KLPR_STAT(tlb_dropin_fail_range_active);
	gru_dbg(grudev, "FAILED range active: tfh 0x%p, vaddr 0x%lx\n",
		tfh, vaddr);
	return 1;
}

static int klpr_gru_user_dropin(struct gru_thread_state *gts,
			   struct gru_tlb_fault_handle *tfh,
			   void *cb)
{
	struct gru_mm_struct *gms = gts->ts_gms;
	int ret;

	gts->ustats.upm_tlbmiss++;
	while (1) {
		wait_event(gms->ms_wait_queue,
			   atomic_read(&gms->ms_range_active) == 0);
		prefetchw(tfh);	/* Helps on hdw, required for emulator */
		ret = klpr_gru_try_dropin(gts->ts_gru, gts, tfh, cb);
		if (ret <= 0)
			return ret;
		KLPR_STAT(call_os_wait_queue);
	}
}

int klpp_gru_handle_user_call_os(unsigned long cb)
{
	struct gru_tlb_fault_handle *tfh;
	struct gru_thread_state *gts;
	void *cbk;
	int ucbnum, cbrnum, ret = -EINVAL;

	KLPR_STAT(call_os);

	/* sanity check the cb pointer */
	ucbnum = get_cb_number((void *)cb);
	if ((cb & (GRU_HANDLE_STRIDE - 1)) || ucbnum >= GRU_NUM_CB)
		return -EINVAL;

again:
	gts = (*klpe_gru_find_lock_gts)(cb);
	if (!gts)
		return -EINVAL;
	gru_dbg(grudev, "address 0x%lx, gid %d, gts 0x%p\n", cb, gts->ts_gru ? gts->ts_gru->gs_gid : -1, gts);

	if (ucbnum >= gts->ts_cbr_au_count * GRU_CBR_AU_SIZE)
		goto exit;

	if (klpp_gru_check_context_placement(gts)) {
		(*klpe_gru_unlock_gts)(gts);
		(*klpe_gru_unload_context)(gts, 1);
		goto again;
	}

	/*
	 * CCH may contain stale data if ts_force_cch_reload is set.
	 */
	if (gts->ts_gru && gts->ts_force_cch_reload) {
		gts->ts_force_cch_reload = 0;
		(*klpe_gru_update_cch)(gts);
	}

	ret = -EAGAIN;
	cbrnum = thread_cbr_number(gts, ucbnum);
	if (gts->ts_gru) {
		tfh = get_tfh_by_index(gts->ts_gru, cbrnum);
		cbk = get_gseg_base_address_cb(gts->ts_gru->gs_gru_base_vaddr,
				gts->ts_ctxnum, ucbnum);
		ret = klpr_gru_user_dropin(gts, tfh, cbk);
	}
exit:
	(*klpe_gru_unlock_gts)(gts);
	return ret;
}

int klpp_gru_set_context_option(unsigned long arg)
{
	struct gru_thread_state *gts;
	struct gru_set_context_option_req req;
	int ret = 0;

	KLPR_STAT(set_context_option);
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	gru_dbg(grudev, "op %d, gseg 0x%lx, value1 0x%lx\n", req.op, req.gseg, req.val1);

	gts = (*klpe_gru_find_lock_gts)(req.gseg);
	if (!gts) {
		gts = klpr_gru_alloc_locked_gts(req.gseg);
		if (IS_ERR(gts))
			return PTR_ERR(gts);
	}

	switch (req.op) {
	case sco_blade_chiplet:
		/* Select blade/chiplet for GRU context */
		if (req.val0 < -1 || req.val0 >= GRU_CHIPLETS_PER_HUB ||
		    req.val1 < -1 || req.val1 >= GRU_MAX_BLADES ||
		    (req.val1 >= 0 && !(*klpe_gru_base)[req.val1])) {
			ret = -EINVAL;
		} else {
			gts->ts_user_blade_id = req.val1;
			gts->ts_user_chiplet_id = req.val0;
			if (klpp_gru_check_context_placement(gts)) {
				(*klpe_gru_unlock_gts)(gts);
				(*klpe_gru_unload_context)(gts, 1);
				return ret;
			}
		}
		break;
	case sco_gseg_owner:
 		/* Register the current task as the GSEG owner */
		gts->ts_tgid_owner = current->tgid;
		break;
	case sco_cch_req_slice:
 		/* Set the CCH slice option */
		gts->ts_cch_req_slice = req.val1 & 3;
		break;
	default:
		ret = -EINVAL;
	}
	(*klpe_gru_unlock_gts)(gts);

	return ret;
}



#define LP_MODULE "gru"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1204167.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "gru_alloc_thread_state", (void *)&klpe_gru_alloc_thread_state,
	  "gru" },
	{ "gru_base", (void *)&klpe_gru_base, "gru" },
	{ "gru_end_paddr", (void *)&klpe_gru_end_paddr, "gru" },
	{ "gru_find_lock_gts", (void *)&klpe_gru_find_lock_gts, "gru" },
	{ "gru_find_vma", (void *)&klpe_gru_find_vma, "gru" },
	{ "gru_options", (void *)&klpe_gru_options, "gru" },
	{ "gru_start_paddr", (void *)&klpe_gru_start_paddr, "gru" },
	{ "gru_stats", (void *)&klpe_gru_stats, "gru" },
	{ "gru_unlock_gts", (void *)&klpe_gru_unlock_gts, "gru" },
	{ "gru_unload_context", (void *)&klpe_gru_unload_context, "gru" },
	{ "gru_update_cch", (void *)&klpe_gru_update_cch, "gru" },
	{ "tfh_exception", (void *)&klpe_tfh_exception, "gru" },
	{ "tfh_user_polling_mode", (void *)&klpe_tfh_user_polling_mode,
	  "gru" },
	{ "tfh_write_only", (void *)&klpe_tfh_write_only, "gru" },
	{ "tfh_write_restart", (void *)&klpe_tfh_write_restart, "gru" },
};

static int bsc1204167_drivers_misc_sgi_gru_grufault_module_notify(struct notifier_block *nb,
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
	.notifier_call = bsc1204167_drivers_misc_sgi_gru_grufault_module_notify,
	.priority = INT_MIN+1,
};

int bsc1204167_drivers_misc_sgi_gru_grufault_init(void)
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

void bsc1204167_drivers_misc_sgi_gru_grufault_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SGI_GRU) */
