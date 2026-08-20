#ifndef _LIVEPATCH_BSC1266668_H
#define _LIVEPATCH_BSC1266668_H

#include <linux/types.h>

static inline int livepatch_bsc1266668_init(void) { return 0; }
static inline void livepatch_bsc1266668_cleanup(void) {}

struct kfd_process;

int klpp_kfd_event_page_set(struct kfd_process *p, void *kernel_address, uint64_t size);


#endif /* _LIVEPATCH_BSC1266668_H */
