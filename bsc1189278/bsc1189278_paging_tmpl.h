/* klp-ccp: from arch/x86/kvm/paging_tmpl.h */
#if PTTYPE == 64
	#define pt_element_t u64
	#define klpp_guest_walker klpp_guest_walker64
	#define FNAME(name) paging##64_##name
	#define KLPP_FNAME(name) klpp_paging64_##name
	#define KLPR_FNAME(name) klpr_paging64_##name
	#define KLPE_FNAME(name) klpe_paging64_##name

	#define PT_LVL_ADDR_MASK(lvl) PT64_LVL_ADDR_MASK(lvl)
	#define PT_LVL_OFFSET_MASK(lvl) PT64_LVL_OFFSET_MASK(lvl)
	#define PT_INDEX(addr, level) PT64_INDEX(addr, level)

	#define PT_GUEST_DIRTY_SHIFT PT_DIRTY_SHIFT
	#define PT_GUEST_ACCESSED_SHIFT PT_ACCESSED_SHIFT
	#define PT_HAVE_ACCESSED_DIRTY(mmu) true
	#ifdef CONFIG_X86_64
	#define PT_MAX_FULL_LEVELS 4
	#define CMPXCHG cmpxchg
	#else
	#error "klp-ccp: non-taken branch"
	#endif
#elif PTTYPE == 32
	#define pt_element_t u32
	#define klpp_guest_walker klpp_guest_walker32
	#define FNAME(name) paging##32_##name
	#define KLPP_FNAME(name) klpp_paging32_##name
	#define KLPR_FNAME(name) klpr_paging32_##name
	#define KLPE_FNAME(name) klpe_paging32_##name

	#define PT_LVL_ADDR_MASK(lvl) PT32_LVL_ADDR_MASK(lvl)
	#define PT_LVL_OFFSET_MASK(lvl) PT32_LVL_OFFSET_MASK(lvl)
	#define PT_INDEX(addr, level) PT32_INDEX(addr, level)

	#define PT_MAX_FULL_LEVELS 2
	#define PT_GUEST_DIRTY_SHIFT PT_DIRTY_SHIFT
	#define PT_GUEST_ACCESSED_SHIFT PT_ACCESSED_SHIFT
	#define PT_HAVE_ACCESSED_DIRTY(mmu) true
	#define CMPXCHG cmpxchg
#elif PTTYPE == PTTYPE_EPT
	#define pt_element_t u64
	#define klpp_guest_walker klpp_guest_walkerEPT
	#define FNAME(name) ept_##name
	#define KLPP_FNAME(name) klpp_ept_##name
	#define KLPR_FNAME(name) klpr_ept_##name
	#define KLPE_FNAME(name) klpe_ept_##name

	#define PT_LVL_ADDR_MASK(lvl) PT64_LVL_ADDR_MASK(lvl)
	#define PT_LVL_OFFSET_MASK(lvl) PT64_LVL_OFFSET_MASK(lvl)
	#define PT_INDEX(addr, level) PT64_INDEX(addr, level)

	#define PT_GUEST_DIRTY_SHIFT 9
	#define PT_GUEST_ACCESSED_SHIFT 8
	#define PT_HAVE_ACCESSED_DIRTY(mmu) ((mmu)->ept_ad)
	#define CMPXCHG cmpxchg64
	#define PT_MAX_FULL_LEVELS 4
#else
	#error Invalid PTTYPE value
#endif

#define PT_GUEST_DIRTY_MASK    (1 << PT_GUEST_DIRTY_SHIFT)
#define PT_GUEST_ACCESSED_MASK (1 << PT_GUEST_ACCESSED_SHIFT)

#define gpte_to_gfn_lvl FNAME(gpte_to_gfn_lvl)
#define gpte_to_gfn(pte) gpte_to_gfn_lvl((pte), PT_PAGE_TABLE_LEVEL)

struct klpp_guest_walker {
	int level;
	unsigned max_level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t ptes[PT_MAX_FULL_LEVELS];
	pt_element_t prefetch_ptes[PTE_PREFETCH_NUM];
	gpa_t pte_gpa[PT_MAX_FULL_LEVELS];
	pt_element_t __user *ptep_user[PT_MAX_FULL_LEVELS];
	bool pte_writable[PT_MAX_FULL_LEVELS];
	/*
	 * Fix CVE-2021-38198
	 *  -2 lines, +2 lines
	 */
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
	return pte & 7;
#endif
}

static int KLPR_FNAME(cmpxchg_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			       pt_element_t __user *ptep_user, unsigned index,
			       pt_element_t orig_pte, pt_element_t new_pte)
{
	int npages;
	pt_element_t ret;
	pt_element_t *table;
	struct page *page;

	npages = get_user_pages_fast((unsigned long)ptep_user, 1, 1, &page);
	/* Check if the user is doing something meaningless. */
	if (unlikely(npages != 1))
		return -EFAULT;

	table = kmap_atomic(page);
	ret = CMPXCHG(&table[index], orig_pte, new_pte);
	kunmap_atomic(table);

	(*klpe_kvm_release_page_dirty)(page);

	return (ret != orig_pte);
}

static inline unsigned FNAME(gpte_access)(u64 gpte)
{
	unsigned access;
#if PTTYPE == PTTYPE_EPT
	access = ((gpte & VMX_EPT_WRITABLE_MASK) ? ACC_WRITE_MASK : 0) |
		((gpte & VMX_EPT_EXECUTABLE_MASK) ? ACC_EXEC_MASK : 0) |
		((gpte & VMX_EPT_READABLE_MASK) ? ACC_USER_MASK : 0);
#else
	BUILD_BUG_ON(ACC_EXEC_MASK != PT_PRESENT_MASK);
	BUILD_BUG_ON(ACC_EXEC_MASK != 1);
	access = gpte & (PT_WRITABLE_MASK | PT_USER_MASK | PT_PRESENT_MASK);
	/* Combine NX with P (which is set here) to get ACC_EXEC_MASK.  */
	access ^= (gpte >> PT64_NX_SHIFT);
#endif
	return access;
}

static int KLPP_FNAME(update_accessed_dirty_bits)(struct kvm_vcpu *vcpu,
					     struct kvm_mmu *mmu,
					     /*
					      * Fix CVE-2021-38198
					      *  -1 line, +1 line
					      */
					     struct klpp_guest_walker *walker,
					     int write_fault)
{
	unsigned level, index;
	pt_element_t pte, orig_pte;
	pt_element_t __user *ptep_user;
	gfn_t table_gfn;
	int ret;

	/* dirty/accessed bits are not supported, so no need to update them */
	if (!PT_HAVE_ACCESSED_DIRTY(mmu))
		return 0;

	for (level = walker->max_level; level >= walker->level; --level) {
		pte = orig_pte = walker->ptes[level - 1];
		table_gfn = walker->table_gfn[level - 1];
		ptep_user = walker->ptep_user[level - 1];
		index = offset_in_page(ptep_user) / sizeof(pt_element_t);
		if (!(pte & PT_GUEST_ACCESSED_MASK)) {
			(*klpe_trace_kvm_mmu_set_accessed_bit)(table_gfn, index, sizeof(pte));
			pte |= PT_GUEST_ACCESSED_MASK;
		}
		if (level == walker->level && write_fault &&
				!(pte & PT_GUEST_DIRTY_MASK)) {
			(*klpe_trace_kvm_mmu_set_dirty_bit)(table_gfn, index, sizeof(pte));
#if PTTYPE == PTTYPE_EPT
			if ((*klpe_kvm_arch_write_log_dirty)(vcpu))
				return -EINVAL;
#endif
			pte |= PT_GUEST_DIRTY_MASK;
		}
		if (pte == orig_pte)
			continue;

		/*
		 * If the slot is read-only, simply do not process the accessed
		 * and dirty bits.  This is the correct thing to do if the slot
		 * is ROM, and page tables in read-as-ROM/write-as-MMIO slots
		 * are only supported if the accessed and dirty bits are already
		 * set in the ROM (so that MMIO writes are never needed).
		 *
		 * Note that NPT does not allow this at all and faults, since
		 * it always wants nested page table entries for the guest
		 * page tables to be writable.  And EPT works but will simply
		 * overwrite the read-only memory to set the accessed and dirty
		 * bits.
		 */
		if (unlikely(!walker->pte_writable[level - 1]))
			continue;

		ret = KLPR_FNAME(cmpxchg_gpte)(vcpu, mmu, ptep_user, index, orig_pte, pte);
		if (ret)
			return ret;

		(*klpe_kvm_vcpu_mark_page_dirty)(vcpu, table_gfn);
		walker->ptes[level - 1] = pte;
	}
	return 0;
}

static inline unsigned FNAME(gpte_pkeys)(struct kvm_vcpu *vcpu, u64 gpte)
{
	unsigned pkeys = 0;
#if PTTYPE == 64
	pte_t pte = {.pte = gpte};

	pkeys = pte_flags_pkey(pte_flags(pte));
#endif
	return pkeys;
}

/*
 * Fix CVE-2021-38198
 *  -1 line, +1 line
 */
static int KLPP_FNAME(walk_addr_generic)(struct klpp_guest_walker *walker,
				    struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				    gva_t addr, u32 access)
{
	int ret;
	pt_element_t pte;
	pt_element_t __user *uninitialized_var(ptep_user);
	gfn_t table_gfn;
	u64 pt_access, pte_access;
	unsigned index, accessed_dirty, pte_pkey;
	unsigned nested_access;
	gpa_t pte_gpa;
	bool have_ad;
	int offset;
	u64 walk_nx_mask = 0;
	const int write_fault = access & PFERR_WRITE_MASK;
	const int user_fault  = access & PFERR_USER_MASK;
	const int fetch_fault = access & PFERR_FETCH_MASK;
	u16 errcode = 0;
	gpa_t real_gpa;
	gfn_t gfn;

	klpr_trace_kvm_mmu_pagetable_walk(addr, access);
retry_walk:
	walker->level = mmu->root_level;
	pte           = mmu->get_cr3(vcpu);
	have_ad       = PT_HAVE_ACCESSED_DIRTY(mmu);

#if PTTYPE == 64
	walk_nx_mask = 1ULL << PT64_NX_SHIFT;
	if (walker->level == PT32E_ROOT_LEVEL) {
		pte = mmu->get_pdptr(vcpu, (addr >> 30) & 3);
		klpr_trace_kvm_mmu_paging_element(pte, walker->level);
		if (!FNAME(is_present_gpte)(pte))
			goto error;
		--walker->level;
	}
#endif
	walker->max_level = walker->level;
	ASSERT(!(is_long_mode(vcpu) && !is_pae(vcpu)));

	/*
	 * FIXME: on Intel processors, loads of the PDPTE registers for PAE paging
	 * by the MOV to CR instruction are treated as reads and do not cause the
	 * processor to set the dirty flag in any EPT paging-structure entry.
	 */
	nested_access = (have_ad ? PFERR_WRITE_MASK : 0) | PFERR_USER_MASK;

	pte_access = ~0;
	++walker->level;

	do {
		gfn_t real_gfn;
		unsigned long host_addr;

		pt_access = pte_access;
		--walker->level;

		index = PT_INDEX(addr, walker->level);
		table_gfn = gpte_to_gfn(pte);
		offset    = index * sizeof(pt_element_t);
		pte_gpa   = gfn_to_gpa(table_gfn) + offset;

		BUG_ON(walker->level < 1);
		walker->table_gfn[walker->level - 1] = table_gfn;
		walker->pte_gpa[walker->level - 1] = pte_gpa;

		real_gfn = mmu->translate_gpa(vcpu, gfn_to_gpa(table_gfn),
					      nested_access,
					      &walker->fault);

		/*
		 * FIXME: This can happen if emulation (for of an INS/OUTS
		 * instruction) triggers a nested page fault.  The exit
		 * qualification / exit info field will incorrectly have
		 * "guest page access" as the nested page fault's cause,
		 * instead of "guest page structure access".  To fix this,
		 * the x86_exception struct should be augmented with enough
		 * information to fix the exit_qualification or exit_info_1
		 * fields.
		 */
		if (unlikely(real_gfn == UNMAPPED_GVA))
			return 0;

		real_gfn = gpa_to_gfn(real_gfn);

		host_addr = (*klpe_kvm_vcpu_gfn_to_hva_prot)(vcpu, real_gfn,
					    &walker->pte_writable[walker->level - 1]);
		if (unlikely(kvm_is_error_hva(host_addr)))
			goto error;

		ptep_user = (pt_element_t __user *)((void *)host_addr + offset);
		if (unlikely(__copy_from_user(&pte, ptep_user, sizeof(pte))))
			goto error;
		walker->ptep_user[walker->level - 1] = ptep_user;

		klpr_trace_kvm_mmu_paging_element(pte, walker->level);

		/*
		 * Inverting the NX it lets us AND it like other
		 * permission bits.
		 */
		pte_access = pt_access & (pte ^ walk_nx_mask);

		if (unlikely(!FNAME(is_present_gpte)(pte)))
			goto error;

		if (unlikely(is_rsvd_bits_set(mmu, pte, walker->level))) {
			errcode = PFERR_RSVD_MASK | PFERR_PRESENT_MASK;
			goto error;
		}

		walker->ptes[walker->level - 1] = pte;
		/*
		 * Fix CVE-2021-38198
		 *  +2 lines
		 */
		/* Convert to ACC_*_MASK flags for struct guest_walker.  */
		walker->pt_access[walker->level - 1] = FNAME(gpte_access)(pt_access ^ walk_nx_mask);
	} while (!is_last_gpte(mmu, walker->level, pte));

	pte_pkey = FNAME(gpte_pkeys)(vcpu, pte);
	accessed_dirty = have_ad ? pte_access & PT_GUEST_ACCESSED_MASK : 0;

	/* Convert to ACC_*_MASK flags for struct guest_walker.  */
	/*
	 * Fix CVE-2021-38198
	 *  -1 line
	 */
	walker->pte_access = FNAME(gpte_access)(pte_access ^ walk_nx_mask);
	errcode = klpr_permission_fault(vcpu, mmu, walker->pte_access, pte_pkey, access);
	if (unlikely(errcode))
		goto error;

	gfn = gpte_to_gfn_lvl(pte, walker->level);
	gfn += (addr & PT_LVL_OFFSET_MASK(walker->level)) >> PAGE_SHIFT;

	if (PTTYPE == 32 && walker->level == PT_DIRECTORY_LEVEL && is_cpuid_PSE36())
		gfn += pse36_gfn_delta(pte);

	real_gpa = mmu->translate_gpa(vcpu, gfn_to_gpa(gfn), access, &walker->fault);
	if (real_gpa == UNMAPPED_GVA)
		return 0;

	walker->gfn = real_gpa >> PAGE_SHIFT;

	if (!write_fault)
		FNAME(protect_clean_gpte)(mmu, &walker->pte_access, pte);
	else
		/*
		 * On a write fault, fold the dirty bit into accessed_dirty.
		 * For modes without A/D bits support accessed_dirty will be
		 * always clear.
		 */
		accessed_dirty &= pte >>
			(PT_GUEST_DIRTY_SHIFT - PT_GUEST_ACCESSED_SHIFT);

	if (unlikely(!accessed_dirty)) {
		ret = KLPP_FNAME(update_accessed_dirty_bits)(vcpu, mmu, walker, write_fault);
		if (unlikely(ret < 0))
			goto error;
		else if (ret)
			goto retry_walk;
	}

	pgprintk("%s: pte %llx pte_access %x pt_access %x\n",
		 /*
		  * Fix CVE-2021-38198
		  *  -1 line, +2 lines
		  */
		 __func__, (u64)pte, walker->pte_access,
		 walker->pt_access[walker->level - 1]);
	return 1;

error:
	errcode |= write_fault | user_fault;
	if (fetch_fault && (mmu->nx ||
			    klpr_kvm_read_cr4_bits(vcpu, X86_CR4_SMEP)))
		errcode |= PFERR_FETCH_MASK;

	walker->fault.vector = PF_VECTOR;
	walker->fault.error_code_valid = true;
	walker->fault.error_code = errcode;

#if PTTYPE == PTTYPE_EPT
	if (!(errcode & PFERR_RSVD_MASK)) {
		vcpu->arch.exit_qualification &= 0x187;
		vcpu->arch.exit_qualification |= (pte_access & 0x7) << 3;
	}
#endif
	walker->fault.address = addr;
	walker->fault.nested_page_fault = mmu != vcpu->arch.walk_mmu;

	klpr_trace_kvm_mmu_walker_error(walker->fault.error_code);
	return 0;
}

/*
 * Fix CVE-2021-38198
 *  -1 line, +1 line
 */
static int KLPP_FNAME(walk_addr)(struct klpp_guest_walker *walker,
			    struct kvm_vcpu *vcpu, gva_t addr, u32 access)
{
	return KLPP_FNAME(walk_addr_generic)(walker, vcpu, &vcpu->arch.mmu, addr,
					access);
}

static bool
(*KLPE_FNAME(prefetch_gpte))(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     u64 *spte, pt_element_t gpte, bool no_dirty_log);

static bool KLPP_FNAME(gpte_changed)(struct kvm_vcpu *vcpu,
				/*
				 * Fix CVE-2021-38198
				 *  -1 line, +1 line
				 */
				struct klpp_guest_walker *gw, int level)
{
	pt_element_t curr_pte;
	gpa_t base_gpa, pte_gpa = gw->pte_gpa[level - 1];
	u64 mask;
	int r, index;

	if (level == PT_PAGE_TABLE_LEVEL) {
		mask = PTE_PREFETCH_NUM * sizeof(pt_element_t) - 1;
		base_gpa = pte_gpa & ~mask;
		index = (pte_gpa - base_gpa) / sizeof(pt_element_t);

		r = (*klpe_kvm_vcpu_read_guest_atomic)(vcpu, base_gpa,
				gw->prefetch_ptes, sizeof(gw->prefetch_ptes));
		curr_pte = gw->prefetch_ptes[index];
	} else
		r = (*klpe_kvm_vcpu_read_guest_atomic)(vcpu, pte_gpa,
				  &curr_pte, sizeof(curr_pte));

	return r || curr_pte != gw->ptes[level - 1];
}

/*
 * Fix CVE-2021-38198
 *  -1 line, +1 line
 */
static void KLPP_FNAME(pte_prefetch)(struct kvm_vcpu *vcpu, struct klpp_guest_walker *gw,
				u64 *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	u64 *spte;
	int i;

	sp = page_header(__pa(sptep));

	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	if (sp->role.direct)
		return (*klpe___direct_pte_prefetch)(vcpu, sp, sptep);

	i = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (klpr_is_shadow_present_pte(*spte))
			continue;

		if (!(*KLPE_FNAME(prefetch_gpte))(vcpu, sp, spte, gptep[i], true))
			break;
	}
}

static int KLPP_FNAME(fetch)(struct kvm_vcpu *vcpu, gva_t addr,
			 /*
			  * Fix CVE-2021-38198
			  *  -1 line, +1 line
			  */
			 struct klpp_guest_walker *gw,
			 int write_fault, int hlevel,
			 kvm_pfn_t pfn, bool map_writable, bool prefault,
			 bool lpage_disallowed)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	/*
	 * Fix CVE-2021-38198
	 *  -1 line, +1 line
	 */
	unsigned int direct_access, access;
	int top_level, ret;
	gfn_t gfn, base_gfn;

	direct_access = gw->pte_access;

	top_level = vcpu->arch.mmu.root_level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if (KLPP_FNAME(gpte_changed)(vcpu, gw, top_level))
		goto out_gpte_changed;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		goto out_gpte_changed;

	for ((*klpe_shadow_walk_init)(&it, vcpu, addr);
	     shadow_walk_okay(&it) && it.level > gw->level;
	     (*klpe_shadow_walk_next)(&it)) {
		gfn_t table_gfn;

		clear_sp_write_flooding_count(it.sptep);
		klpr_drop_large_spte(vcpu, it.sptep);

		sp = NULL;
		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			table_gfn = gw->table_gfn[it.level - 2];
			/*
			 * Fix CVE-2021-38198
			 *  +1 line
			 */
			access = gw->pt_access[it.level - 2];
			sp = (*klpe_kvm_mmu_get_page)(vcpu, table_gfn, addr, it.level-1,
					      false, access);
		}

		/*
		 * Verify that the gpte in the page we've just write
		 * protected is still there.
		 */
		if (KLPP_FNAME(gpte_changed)(vcpu, gw, it.level - 1))
			goto out_gpte_changed;

		if (sp)
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
	}

	/*
	 * FNAME(page_fault) might have clobbered the bottom bits of
	 * gw->gfn, restore them from the virtual address.
	 */
	gfn = gw->gfn | ((addr & PT_LVL_OFFSET_MASK(gw->level)) >> PAGE_SHIFT);
	base_gfn = gfn;

	klpr_trace_kvm_mmu_spte_requested(addr, gw->level, pfn);

	for (; shadow_walk_okay(&it); (*klpe_shadow_walk_next)(&it)) {
		clear_sp_write_flooding_count(it.sptep);

		/*
		 * We cannot overwrite existing page tables with an NX
		 * large page, as the leaf could be executable.
		 */
		klpr_disallowed_hugepage_adjust(it, gfn, &pfn, &hlevel);

		base_gfn = gfn & ~(KVM_PAGES_PER_HPAGE(it.level) - 1);
		if (it.level == hlevel)
			break;

		klpr_validate_direct_spte(vcpu, it.sptep, direct_access);

		klpr_drop_large_spte(vcpu, it.sptep);

		if (!klpr_is_shadow_present_pte(*it.sptep)) {
			sp = (*klpe_kvm_mmu_get_page)(vcpu, base_gfn, addr,
					      it.level - 1, true, direct_access);
			(*klpe_link_shadow_page)(vcpu, it.sptep, sp);
			if (lpage_disallowed)
				account_huge_nx_page(vcpu->kvm, sp);
		}
	}

	ret = (*klpe_mmu_set_spte)(vcpu, it.sptep, gw->pte_access, write_fault,
			   it.level, base_gfn, pfn, prefault, map_writable);
	KLPP_FNAME(pte_prefetch)(vcpu, gw, it.sptep);
	++vcpu->stat.pf_fixed;
	return ret;

out_gpte_changed:
	return RET_PF_RETRY;
}

static bool
KLPP_FNAME(is_self_change_mapping)(struct kvm_vcpu *vcpu,
			      /*
			       * Fix CVE-2021-38198
			       *  -1 line, +1 line
			       */
			      struct klpp_guest_walker *walker, int user_fault,
			      bool *write_fault_to_shadow_pgtable)
{
	int level;
	gfn_t mask = ~(KVM_PAGES_PER_HPAGE(walker->level) - 1);
	bool self_changed = false;

	if (!(walker->pte_access & ACC_WRITE_MASK ||
	      (!klpr_is_write_protection(vcpu) && !user_fault)))
		return false;

	for (level = walker->level; level <= walker->max_level; level++) {
		gfn_t gfn = walker->gfn ^ walker->table_gfn[level - 1];

		self_changed |= !(gfn & mask);
		*write_fault_to_shadow_pgtable |= !gfn;
	}

	return self_changed;
}

int KLPP_FNAME(page_fault)(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code,
			     bool prefault)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	/*
	 * Fix CVE-2021-38198
	 *  -1 line, +1 line
	 */
	struct klpp_guest_walker walker;
	int r;
	kvm_pfn_t pfn;
	int level = PT_PAGE_TABLE_LEVEL;
	unsigned long mmu_seq;
	bool map_writable, is_self_change_mapping;
	bool lpage_disallowed = (error_code & PFERR_FETCH_MASK) &&
				klpr_is_nx_huge_page_enabled();
	bool force_pt_level = lpage_disallowed;

	pgprintk("%s: addr %lx err %x\n", __func__, addr, error_code);

	r = (*klpe_mmu_topup_memory_caches)(vcpu);
	if (r)
		return r;

	/*
	 * If PFEC.RSVD is set, this is a shadow page fault.
	 * The bit needs to be cleared before walking guest page tables.
	 */
	error_code &= ~PFERR_RSVD_MASK;

	/*
	 * Look up the guest pte for the faulting address.
	 */
	r = KLPP_FNAME(walk_addr)(&walker, vcpu, addr, error_code);

	/*
	 * The page is not mapped by the guest.  Let the guest handle it.
	 */
	if (!r) {
		pgprintk("%s: guest page fault\n", __func__);
		if (!prefault)
			inject_page_fault(vcpu, &walker.fault);

		return RET_PF_RETRY;
	}

	if ((*klpe_page_fault_handle_page_track)(vcpu, error_code, walker.gfn)) {
		klpr_shadow_page_table_clear_flood(vcpu, addr);
		return RET_PF_EMULATE;
	}

	vcpu->arch.write_fault_to_shadow_pgtable = false;

	is_self_change_mapping = KLPP_FNAME(is_self_change_mapping)(vcpu,
	      &walker, user_fault, &vcpu->arch.write_fault_to_shadow_pgtable);

	if (walker.level >= PT_DIRECTORY_LEVEL && !is_self_change_mapping) {
		level = (*klpe_mapping_level)(vcpu, walker.gfn, &force_pt_level);
		if (likely(!force_pt_level)) {
			level = min(walker.level, level);
			walker.gfn = walker.gfn & ~(KVM_PAGES_PER_HPAGE(level) - 1);
		}
	} else
		force_pt_level = true;

	mmu_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();

	if ((*klpe_try_async_pf)(vcpu, prefault, walker.gfn, addr, &pfn, write_fault,
			 &map_writable))
		return RET_PF_RETRY;

	if ((*klpe_handle_abnormal_pfn)(vcpu, addr, walker.gfn, pfn, walker.pte_access, &r))
		return r;

	/*
	 * Do not change pte_access if the pfn is a mmio page, otherwise
	 * we will cache the incorrect access into mmio spte.
	 */
	if (write_fault && !(walker.pte_access & ACC_WRITE_MASK) &&
	     !klpr_is_write_protection(vcpu) && !user_fault &&
	      !is_noslot_pfn(pfn)) {
		walker.pte_access |= ACC_WRITE_MASK;
		walker.pte_access &= ~ACC_USER_MASK;

		/*
		 * If we converted a user page to a kernel page,
		 * so that the kernel can write to it when cr0.wp=0,
		 * then we should prevent the kernel from executing it
		 * if SMEP is enabled.
		 */
		if (klpr_kvm_read_cr4_bits(vcpu, X86_CR4_SMEP))
			walker.pte_access &= ~ACC_EXEC_MASK;
	}

	r = RET_PF_RETRY;
	spin_lock(&vcpu->kvm->mmu_lock);
	if (mmu_notifier_retry(vcpu->kvm, mmu_seq))
		goto out_unlock;

	klpr_kvm_mmu_audit(vcpu, AUDIT_PRE_PAGE_FAULT);
	if (klpr_make_mmu_pages_available(vcpu) < 0)
		goto out_unlock;
	if (!force_pt_level)
		(*klpe_transparent_hugepage_adjust)(vcpu, walker.gfn, &pfn, &level);
	r = KLPP_FNAME(fetch)(vcpu, addr, &walker, write_fault,
			 level, pfn, map_writable, prefault, lpage_disallowed);
	klpr_kvm_mmu_audit(vcpu, AUDIT_POST_PAGE_FAULT);

out_unlock:
	spin_unlock(&vcpu->kvm->mmu_lock);
	(*klpe_kvm_release_pfn_clean)(pfn);
	return r;
}

#undef pt_element_t
#undef klpp_guest_walker
#undef FNAME
#undef KLPP_FNAME
#undef KLPR_FNAME
#undef KLPE_FNAME

#undef PT_INDEX
#undef PT_LVL_ADDR_MASK
#undef PT_LVL_OFFSET_MASK

#undef PT_MAX_FULL_LEVELS
#undef gpte_to_gfn
#undef gpte_to_gfn_lvl
#undef CMPXCHG
#undef PT_GUEST_ACCESSED_MASK
#undef PT_GUEST_DIRTY_MASK
#undef PT_GUEST_DIRTY_SHIFT
#undef PT_GUEST_ACCESSED_SHIFT
#undef PT_HAVE_ACCESSED_DIRTY
