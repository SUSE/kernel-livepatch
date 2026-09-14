#ifndef _LIVEPATCH_BSC1272208_H
#define _LIVEPATCH_BSC1272208_H

#include <linux/types.h>

static inline int livepatch_bsc1272208_init(void) { return 0; }
static inline void livepatch_bsc1272208_cleanup(void) {}

struct netlink_callback;
struct sk_buff;

int klpp_ip_set_dump_do(struct sk_buff *skb, struct netlink_callback *cb);
int klpp_ip_set_dump_done(struct netlink_callback *cb);

#endif /* _LIVEPATCH_BSC1272208_H */
