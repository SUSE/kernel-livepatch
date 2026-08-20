#ifndef _LIVEPATCH_BSC1269822_H
#define _LIVEPATCH_BSC1269822_H

#include <linux/types.h>

static inline int livepatch_bsc1269822_init(void) { return 0; }
static inline void livepatch_bsc1269822_cleanup(void) {}

struct ib_block_iter;

bool klpp___rdma_block_iter_next(struct ib_block_iter *biter);

#endif /* _LIVEPATCH_BSC1269822_H */
