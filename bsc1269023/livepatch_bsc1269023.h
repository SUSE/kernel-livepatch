#ifndef _LIVEPATCH_BSC1269023_H
#define _LIVEPATCH_BSC1269023_H

#include <linux/types.h>

static inline int livepatch_bsc1269023_init(void) { return 0; }
static inline void livepatch_bsc1269023_cleanup(void) {}

struct sk_buff;

int klpp_pskb_carve(struct sk_buff *skb, const u32 off, gfp_t gfp);

#endif /* _LIVEPATCH_BSC1269023_H */
