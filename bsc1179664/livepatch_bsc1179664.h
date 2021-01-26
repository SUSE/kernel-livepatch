#ifndef _LIVEPATCH_BSC1179664_H
#define _LIVEPATCH_BSC1179664_H

int livepatch_bsc1179664_init(void);
static inline void livepatch_bsc1179664_cleanup(void) {}


#include <asm/pgtable.h>
struct vm_area_struct;
struct page;

int klpp_do_huge_pmd_wp_page(struct vm_fault *vmf, pmd_t orig_pmd);

void klpp___split_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct page *page);

#endif /* _LIVEPATCH_BSC1179664_H */
