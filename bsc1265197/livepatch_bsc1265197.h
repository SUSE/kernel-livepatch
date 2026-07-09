#ifndef _LIVEPATCH_BSC1265197_H
#define _LIVEPATCH_BSC1265197_H

#include <linux/types.h>

static inline int livepatch_bsc1265197_init(void) { return 0; }
static inline void livepatch_bsc1265197_cleanup(void) {}

struct inet6_skb_parm;
struct sk_buff;

int klpp_ip4ip6_err(struct sk_buff *skb, struct inet6_skb_parm *opt, u8 type, u8 code, int offset, __be32 info);

#endif /* _LIVEPATCH_BSC1265197_H */
