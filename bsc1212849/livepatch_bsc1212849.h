#ifndef _LIVEPATCH_BSC1212849_H
#define _LIVEPATCH_BSC1212849_H

int livepatch_bsc1212849_init(void);
void livepatch_bsc1212849_cleanup(void);

struct sk_buff;
struct net_device;

int klpp_ipvlan_queue_xmit(struct sk_buff *skb, struct net_device *dev);

#endif /* _LIVEPATCH_BSC1212849_H */
