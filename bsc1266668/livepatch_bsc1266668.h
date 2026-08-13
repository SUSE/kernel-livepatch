#ifndef _LIVEPATCH_BSC1266668_H
#define _LIVEPATCH_BSC1266668_H

#include <linux/types.h>

static inline int livepatch_bsc1266668_init(void) { return 0; }
static inline void livepatch_bsc1266668_cleanup(void) {}

struct kfd_process;

int klpp_kfd_kmap_event_page(struct kfd_process *p, uint64_t event_page_offset);

#endif /* _LIVEPATCH_BSC1266668_H */
