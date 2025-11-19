#ifndef _LIVEPATCH_BSC1248672_H
#define _LIVEPATCH_BSC1248672_H

struct net_device;
struct nlattr;
struct netlink_ext_ack;

static inline int livepatch_bsc1248672_init(void) { return 0; }
static inline void livepatch_bsc1248672_cleanup(void) {}

int klpp_xfrmi_changelink(struct net_device *dev, struct nlattr *tb[],
			  struct nlattr *data[],
			  struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1248672_H */
