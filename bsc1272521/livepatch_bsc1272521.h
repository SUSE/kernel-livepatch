#ifndef _LIVEPATCH_BSC1272521_H
#define _LIVEPATCH_BSC1272521_H

#include <linux/types.h>

static inline int livepatch_bsc1272521_init(void) { return 0; }
static inline void livepatch_bsc1272521_cleanup(void) {}

struct fib6_result;
struct flowi6;
struct net;
struct sk_buff;

void klpp_fib6_select_path(const struct net *net, struct fib6_result *res, struct flowi6 *fl6, int oif, bool have_oif_match, const struct sk_buff *skb, int strict);

#endif /* _LIVEPATCH_BSC1272521_H */
