#ifndef _LIVEPATCH_BSC1273232_H
#define _LIVEPATCH_BSC1273232_H

#include <linux/types.h>
#include <linux/kvm_types.h>

static inline int livepatch_bsc1273232_init(void) { return 0; }
static inline void livepatch_bsc1273232_cleanup(void) {}

struct kvm_page_fault;
struct kvm_vcpu;

int klpp_direct_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
int klpp_ept_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
int klpp_paging32_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
int klpp_paging64_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);

#endif /* _LIVEPATCH_BSC1273232_H */
