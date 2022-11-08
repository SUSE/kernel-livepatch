#ifndef _LIVEPATCH_BSC1204170_H
#define _LIVEPATCH_BSC1204170_H

int livepatch_bsc1204170_init(void);
static inline void livepatch_bsc1204170_cleanup(void) {}


struct vm_area_struct;

int klpp_anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src);

#endif /* _LIVEPATCH_BSC1204170_H */
