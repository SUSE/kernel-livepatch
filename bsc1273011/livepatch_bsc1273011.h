#ifndef _LIVEPATCH_BSC1273011_H
#define _LIVEPATCH_BSC1273011_H

#include <linux/types.h>

static inline int livepatch_bsc1273011_init(void) { return 0; }
static inline void livepatch_bsc1273011_cleanup(void) {}

struct __ip6_tnl_parm;
struct ifreq;
struct ip6_tnl;
struct net_device;
struct netlink_ext_ack;
struct nlattr;

int klpp_vti6_changelink(struct net_device *dev, struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack);
int klpp_vti6_siocdevprivate(struct net_device *dev, struct ifreq *ifr, void __user *data, int cmd);
int klpp_vti6_update(struct ip6_tnl *t, struct __ip6_tnl_parm *p, bool keep_mtu);

#endif /* _LIVEPATCH_BSC1273011_H */
