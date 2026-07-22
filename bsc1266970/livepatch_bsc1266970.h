#ifndef _LIVEPATCH_BSC1266970_H
#define _LIVEPATCH_BSC1266970_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_X86)

#include <linux/kvm_types.h>

int livepatch_bsc1266970_init(void);
void livepatch_bsc1266970_cleanup(void);

struct kvm_vcpu;

int klpp___direct_map(struct kvm_vcpu *vcpu, gpa_t gpa, int write, int map_writable, int level, kvm_pfn_t pfn, bool prefault, bool lpage_disallowed);
int klpp_ept_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code, bool prefault);
int klpp_paging32_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code, bool prefault);
int klpp_paging64_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code, bool prefault);
#else /* !IS_ENABLED(CONFIG_X86) */

static inline int livepatch_bsc1266970_init(void) { return 0; }
static inline void livepatch_bsc1266970_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_X86) */

#endif /* _LIVEPATCH_BSC1266970_H */
