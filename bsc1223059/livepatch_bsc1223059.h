#ifndef _LIVEPATCH_BSC1223059_H
#define _LIVEPATCH_BSC1223059_H

int livepatch_bsc1223059_init(void);
static inline void livepatch_bsc1223059_cleanup(void) {}

struct fib6_config;
struct netlink_ext_ack;

int klpp_ip6_route_multipath_add(struct fib6_config *cfg,
				   struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1223059_H */
