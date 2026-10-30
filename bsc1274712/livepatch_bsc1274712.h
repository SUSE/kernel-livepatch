#ifndef _LIVEPATCH_BSC1274712_H
#define _LIVEPATCH_BSC1274712_H

#include <linux/types.h>
#include <linux/netdev_features.h>

static inline int livepatch_bsc1274712_init(void) { return 0; }
static inline void livepatch_bsc1274712_cleanup(void) {}

struct sk_buff;

struct sk_buff *klpp_validate_xmit_xfrm(struct sk_buff *skb, netdev_features_t features, bool *again);

#endif /* _LIVEPATCH_BSC1274712_H */
