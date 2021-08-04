#ifndef _LIVEPATCH_BSC1188842_H
#define _LIVEPATCH_BSC1188842_H

#if IS_ENABLED(CONFIG_KVM_BOOK3S_64)

int livepatch_bsc1188842_init(void);
void livepatch_bsc1188842_cleanup(void);


struct kvm_vcpu;

int klpp_kvmppc_rtas_hcall(struct kvm_vcpu *vcpu);

#else /* !IS_ENABLED(CONFIG_KVM_BOOK3S_64) */

static inline int livepatch_bsc1188842_init(void) { return 0; }

static inline void livepatch_bsc1188842_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_KVM_BOOK3S_64) */
#endif /* _LIVEPATCH_BSC1188842_H */
