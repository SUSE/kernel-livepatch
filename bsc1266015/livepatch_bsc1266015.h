#ifndef _LIVEPATCH_BSC1266015_H
#define _LIVEPATCH_BSC1266015_H

#include <linux/types.h>

static inline int livepatch_bsc1266015_init(void) { return 0; }
static inline void livepatch_bsc1266015_cleanup(void) {}

struct sk_buff;

int klpp_ipv6_rthdr_rcv(struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1266015_H */
