#ifndef _LIVEPATCH_BSC1186483_H
#define _LIVEPATCH_BSC1186483_H

int livepatch_bsc1186483_init(void);
void livepatch_bsc1186483_cleanup(void);


#include <linux/kvm_types.h>

struct kvm_memory_slot;

kvm_pfn_t klpp___gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool *async, bool write_fault,
			       bool *writable);

#endif /* _LIVEPATCH_BSC1186483_H */
