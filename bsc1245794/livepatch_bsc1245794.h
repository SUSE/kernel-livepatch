#ifndef _LIVEPATCH_BSC1245794_H
#define _LIVEPATCH_BSC1245794_H

struct sk_buff;
struct nlmsghdr;
struct netlink_ext_ack;

int livepatch_bsc1245794_init(void);
static inline void livepatch_bsc1245794_cleanup(void) {}
int klpp_tc_ctl_tclass(struct sk_buff *skb, struct nlmsghdr *n,
			 struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1245794_H */
