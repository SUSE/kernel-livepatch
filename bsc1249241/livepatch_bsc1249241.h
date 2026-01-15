#ifndef _LIVEPATCH_BSC1249241_H
#define _LIVEPATCH_BSC1249241_H

#include <linux/types.h>

static inline int livepatch_bsc1249241_init(void) { return 0; }
static inline void livepatch_bsc1249241_cleanup(void) {}

struct fib6_info;
struct fib6_node;
struct netlink_ext_ack;
struct nl_info;

int klpp_fib6_add(struct fib6_node *root, struct fib6_info *rt, struct nl_info *info, struct netlink_ext_ack *extack);
int klpp_fib6_del(struct fib6_info *rt, struct nl_info *info);
size_t klpp_rt6_nlmsg_size(struct fib6_info *f6i);

#endif /* _LIVEPATCH_BSC1249241_H */
