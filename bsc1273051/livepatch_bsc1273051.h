#ifndef _LIVEPATCH_BSC1273051_H
#define _LIVEPATCH_BSC1273051_H

#include <linux/types.h>

static inline int livepatch_bsc1273051_init(void) { return 0; }
static inline void livepatch_bsc1273051_cleanup(void) {}

struct dst_entry;
struct sk_buff;

int klpp_skb_tunnel_check_pmtu(struct sk_buff *skb, struct dst_entry *encap_dst, int headroom, bool reply);

#endif /* _LIVEPATCH_BSC1273051_H */
