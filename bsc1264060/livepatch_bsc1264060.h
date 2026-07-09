#ifndef _LIVEPATCH_BSC1264060_H
#define _LIVEPATCH_BSC1264060_H

#include <linux/types.h>
#include <linux/netdevice.h>

static inline int livepatch_bsc1264060_init(void) { return 0; }
static inline void livepatch_bsc1264060_cleanup(void) {}

struct net_device;
struct sk_buff;

netdev_tx_t klpp_vxlan_xmit(struct sk_buff *skb, struct net_device *dev);

#endif /* _LIVEPATCH_BSC1264060_H */
