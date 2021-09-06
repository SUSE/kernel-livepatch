#ifndef _LIVEPATCH_BSC1189418_H
#define _LIVEPATCH_BSC1189418_H

#if IS_ENABLED(CONFIG_KVM_AMD)

static inline int livepatch_bsc1189418_init(void) { return 0; }
static inline void livepatch_bsc1189418_cleanup(void) {}


struct vcpu_svm;

void klpp_recalc_intercepts(struct vcpu_svm *svm);


#else /* !IS_ENABLED(CONFIG_KVM_AMD) */

static inline int livepatch_bsc1189418_init(void) { return 0; }

static inline void livepatch_bsc1189418_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_KVM_AMD) */
#endif /* _LIVEPATCH_BSC1189418_H */
