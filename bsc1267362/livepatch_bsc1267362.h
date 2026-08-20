#ifndef _LIVEPATCH_BSC1267362_H
#define _LIVEPATCH_BSC1267362_H

#include <linux/types.h>

static inline int livepatch_bsc1267362_init(void) { return 0; }
static inline void livepatch_bsc1267362_cleanup(void) {}

struct sk_buff;

int klpp_icmp_glue_bits(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1267362_H */
