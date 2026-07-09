#ifndef _LIVEPATCH_BSC1263670_H
#define _LIVEPATCH_BSC1263670_H

#include <linux/types.h>

static inline int livepatch_bsc1263670_init(void) { return 0; }
static inline void livepatch_bsc1263670_cleanup(void) {}

struct sk_buff;
struct xt_action_param;

bool klpp_eui64_mt6(const struct sk_buff *skb, struct xt_action_param *par);

#endif /* _LIVEPATCH_BSC1263670_H */
