#ifndef _LIVEPATCH_BSC1270303_H
#define _LIVEPATCH_BSC1270303_H

#include <linux/types.h>

static inline int livepatch_bsc1270303_init(void) { return 0; }
static inline void livepatch_bsc1270303_cleanup(void) {}

struct vcpu_svm;

int klpp_setup_vmgexit_scratch(struct vcpu_svm *svm, bool sync, u64 len);

#endif /* _LIVEPATCH_BSC1270303_H */
