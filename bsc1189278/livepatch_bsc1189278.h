#ifndef _LIVEPATCH_BSC1189278_H
#define _LIVEPATCH_BSC1189278_H

#if IS_ENABLED(CONFIG_X86_64)

int livepatch_bsc1189278_init(void);
void livepatch_bsc1189278_cleanup(void);


#include <linux/kvm_types.h>

int klpp_ept_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code,
			     bool prefault);
int klpp_paging64_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code,
			     bool prefault);
int klpp_paging32_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code,
			     bool prefault);

#else /* !IS_ENABLED(CONFIG_X86_64) */

static inline int livepatch_bsc1189278_init(void) { return 0; }

static inline void livepatch_bsc1189278_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_X86_64) */
#endif /* _LIVEPATCH_BSC1189278_H */
