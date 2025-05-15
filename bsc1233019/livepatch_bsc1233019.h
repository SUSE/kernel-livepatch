#ifndef _LIVEPATCH_BSC1233019_H
#define _LIVEPATCH_BSC1233019_H

#if IS_ENABLED(CONFIG_KVM_AMD)

int livepatch_bsc1233019_init(void);
void livepatch_bsc1233019_cleanup(void);

u64 klpp_nested_svm_get_tdp_pdptr(struct kvm_vcpu *vcpu, int index);

#else /* !IS_ENABLED(CONFIG_KVM_AMD) */

static inline int livepatch_bsc1233019_init(void) { return 0; }
static inline void livepatch_bsc1233019_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_KVM_AMD) */

#endif /* _LIVEPATCH_BSC1233019_H */
