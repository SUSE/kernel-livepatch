#ifndef _LIVEPATCH_BSC1203116_H
#define _LIVEPATCH_BSC1203116_H

int livepatch_bsc1203116_init(void);
static inline void livepatch_bsc1203116_cleanup(void) {}


struct mm_struct;
struct vm_area_struct;

void klpp_unmap_region(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end);

#endif /* _LIVEPATCH_BSC1203116_H */
