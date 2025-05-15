#ifndef _LIVEPATCH_BSC1233019_H
#define _LIVEPATCH_BSC1233019_H

static inline int livepatch_bsc1233019_init(void) { return 0; }
static inline void livepatch_bsc1233019_cleanup(void) {}

u64 klpp_nested_svm_get_tdp_pdptr(struct kvm_vcpu *vcpu, int index);

#endif /* _LIVEPATCH_BSC1233019_H */
