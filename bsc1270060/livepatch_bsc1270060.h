#ifndef _LIVEPATCH_BSC1270060_H
#define _LIVEPATCH_BSC1270060_H

#include <linux/types.h>

static inline int livepatch_bsc1270060_init(void) { return 0; }
static inline void livepatch_bsc1270060_cleanup(void) {}

#if IS_ENABLED(CONFIG_X86)

#include <linux/kvm_types.h>

struct kvm_mmu_page;
struct kvm_vcpu;

struct kvm_mmu_page *klpp_kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu, u64 *sptep, gfn_t gfn, bool direct, unsigned int access);

#endif /* IS_ENABLED(CONFIG_X86) */

#endif /* _LIVEPATCH_BSC1270060_H */
