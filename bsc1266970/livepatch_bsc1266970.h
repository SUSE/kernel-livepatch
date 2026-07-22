#ifndef _LIVEPATCH_BSC1266970_H
#define _LIVEPATCH_BSC1266970_H

#include <linux/types.h>
#include <linux/kvm_types.h>

static inline int livepatch_bsc1266970_init(void) { return 0; }
static inline void livepatch_bsc1266970_cleanup(void) {}

struct kvm;
struct kvm_mmu_memory_cache;
struct kvm_mmu_page;
struct kvm_page_fault;
struct kvm_vcpu;

int klpp_direct_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
int klpp_ept_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
int klpp_paging32_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
int klpp_paging64_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
void klpp___link_shadow_page(struct kvm *kvm, struct kvm_mmu_memory_cache *cache, u64 *sptep, struct kvm_mmu_page *sp, bool flush);

#endif /* _LIVEPATCH_BSC1266970_H */
