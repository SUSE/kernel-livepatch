#ifndef _LIVEPATCH_BSC1264849_H
#define _LIVEPATCH_BSC1264849_H

#include <linux/types.h>

static inline int livepatch_bsc1264849_init(void) { return 0; }
static inline void livepatch_bsc1264849_cleanup(void) {}

struct sk_buff;
struct xt_action_param;

bool klpp_tcpmss_mt(const struct sk_buff *skb, struct xt_action_param *par);

#endif /* _LIVEPATCH_BSC1264849_H */
