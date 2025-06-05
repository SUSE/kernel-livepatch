#ifndef _LIVEPATCH_BSC1238324_H
#define _LIVEPATCH_BSC1238324_H

int livepatch_bsc1238324_init(void);
static inline void livepatch_bsc1238324_cleanup(void) {}

int klpp_mpol_set_shared_policy(struct shared_policy *info,
			struct vm_area_struct *vma, struct mempolicy *npol);

#endif /* _LIVEPATCH_BSC1238324_H */
