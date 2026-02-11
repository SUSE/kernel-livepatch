#ifndef _LIVEPATCH_BSC1249480_H
#define _LIVEPATCH_BSC1249480_H

static inline int livepatch_bsc1249480_init(void) { return 0; }
static inline void livepatch_bsc1249480_cleanup(void) {}
int klpp_hfi1_get_proc_affinity(int node);

#endif /* _LIVEPATCH_BSC1249480_H */
