#ifndef _LIVEPATCH_BSC1270060_H
#define _LIVEPATCH_BSC1270060_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_X86)

#include <linux/kvm_types.h>

int livepatch_bsc1270060_init(void);
void livepatch_bsc1270060_cleanup(void);

struct guest_walkerEPT;
struct guest_walker32;
struct guest_walker64;
struct kvm_vcpu;

int klpp___direct_map(struct kvm_vcpu *vcpu, gpa_t gpa, int write, int map_writable, int level, kvm_pfn_t pfn, bool prefault, bool lpage_disallowed);
int klpp_ept_fetch(struct kvm_vcpu *vcpu, gva_t addr, struct guest_walkerEPT *gw, int write_fault, int hlevel, kvm_pfn_t pfn, bool map_writable, bool prefault, bool lpage_disallowed);
int klpp_paging32_fetch(struct kvm_vcpu *vcpu, gva_t addr, struct guest_walker32 *gw, int write_fault, int hlevel, kvm_pfn_t pfn, bool map_writable, bool prefault, bool lpage_disallowed);
int klpp_paging64_fetch(struct kvm_vcpu *vcpu, gva_t addr, struct guest_walker64 *gw, int write_fault, int hlevel, kvm_pfn_t pfn, bool map_writable, bool prefault, bool lpage_disallowed);
#else /* !IS_ENABLED(CONFIG_X86) */

static inline int livepatch_bsc1270060_init(void) { return 0; }
static inline void livepatch_bsc1270060_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_X86) */

#endif /* _LIVEPATCH_BSC1270060_H */
