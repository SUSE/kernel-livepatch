#ifndef _LIVEPATCH_BSC1237930_H
#define _LIVEPATCH_BSC1237930_H

#include <linux/types.h>
#include <linux/mm_types.h>

static inline int livepatch_bsc1237930_init(void) { return 0; }
static inline void livepatch_bsc1237930_cleanup(void) {}

int klpp_tcmu_vma_fault(struct vm_fault *vmf);

#endif /* _LIVEPATCH_BSC1237930_H */
