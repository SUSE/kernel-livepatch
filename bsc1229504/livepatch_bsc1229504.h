#ifndef _LIVEPATCH_BSC1229504_H
#define _LIVEPATCH_BSC1229504_H

static inline int livepatch_bsc1229504_init(void) { return 0; }
static inline void livepatch_bsc1229504_cleanup(void) {}

int klpp_begin_new_exec(struct linux_binprm * bprm);

#endif /* _LIVEPATCH_BSC1229504_H */
