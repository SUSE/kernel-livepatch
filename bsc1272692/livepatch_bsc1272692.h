#ifndef _LIVEPATCH_BSC1272692_H
#define _LIVEPATCH_BSC1272692_H

#include <linux/types.h>

static inline int livepatch_bsc1272692_init(void) { return 0; }
static inline void livepatch_bsc1272692_cleanup(void) {}

struct vcpu_svm;

int klpp_setup_vmgexit_scratch(struct vcpu_svm *svm, bool sync, u64 min_len);

#endif /* _LIVEPATCH_BSC1272692_H */
