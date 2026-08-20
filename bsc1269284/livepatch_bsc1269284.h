#ifndef _LIVEPATCH_BSC1269284_H
#define _LIVEPATCH_BSC1269284_H

#include <linux/types.h>

int livepatch_bsc1269284_init(void);
static inline void livepatch_bsc1269284_cleanup(void) {}


struct in_device;
struct in_ifaddr;
struct nlmsghdr;

void klpp___inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap, int destroy, struct nlmsghdr *nlh, u32 portid);
#endif /* _LIVEPATCH_BSC1269284_H */
