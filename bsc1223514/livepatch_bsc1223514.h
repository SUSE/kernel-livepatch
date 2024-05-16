#ifndef _LIVEPATCH_BSC1223514_H
#define _LIVEPATCH_BSC1223514_H

int livepatch_bsc1223514_init(void);
void livepatch_bsc1223514_cleanup(void);

struct sk_buff;
struct net_device;

int klpp_ipvlan_queue_xmit(struct sk_buff *skb, struct net_device *dev);

#endif /* _LIVEPATCH_BSC1223514_H */
