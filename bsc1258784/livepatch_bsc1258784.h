#ifndef _LIVEPATCH_BSC1258784_H
#define _LIVEPATCH_BSC1258784_H

#include <linux/types.h>

int livepatch_bsc1258784_init(void);
void livepatch_bsc1258784_cleanup(void);


struct net;
struct net_device;
struct netlink_ext_ack;
struct nlattr;

int klpp_macvlan_common_newlink(struct net *src_net, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack);
#endif /* _LIVEPATCH_BSC1258784_H */
