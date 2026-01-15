#ifndef _LIVEPATCH_BSC1248400_H
#define _LIVEPATCH_BSC1248400_H

#include <linux/types.h>

static inline int livepatch_bsc1248400_init(void) { return 0; }
static inline void livepatch_bsc1248400_cleanup(void) {}

struct sk_buff;

#include <linux/netdev_features.h>

struct sk_buff *klpp_ipv6_gso_segment(struct sk_buff *skb, netdev_features_t features);

#endif /* _LIVEPATCH_BSC1248400_H */
