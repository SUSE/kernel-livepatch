#ifndef _LIVEPATCH_BSC1189418_H
#define _LIVEPATCH_BSC1189418_H

#if IS_ENABLED(CONFIG_KVM_AMD)

int livepatch_bsc1189418_init(void);
void livepatch_bsc1189418_cleanup(void);


struct vcpu_svm;
struct vmcb;
struct page;

void klpp_recalc_intercepts(struct vcpu_svm *svm);

void klpp_enter_svm_guest_mode(struct vcpu_svm *svm, u64 vmcb_gpa,
				 struct vmcb *nested_vmcb, struct page *page);

#else /* !IS_ENABLED(CONFIG_KVM_AMD) */

static inline int livepatch_bsc1189418_init(void) { return 0; }

static inline void livepatch_bsc1189418_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_KVM_AMD) */
#endif /* _LIVEPATCH_BSC1189418_H */
