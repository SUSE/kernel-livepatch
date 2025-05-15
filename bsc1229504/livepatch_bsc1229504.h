#ifndef _LIVEPATCH_BSC1229504_H
#define _LIVEPATCH_BSC1229504_H

int livepatch_bsc1229504_init(void);
static inline void livepatch_bsc1229504_cleanup(void) {}

int klpp_prepare_binprm(struct linux_binprm *bprm);

#endif /* _LIVEPATCH_BSC1229504_H */
