#ifndef _LIVEPATCH_BSC1273052_H
#define _LIVEPATCH_BSC1273052_H

#include <linux/types.h>

static inline int livepatch_bsc1273052_init(void) { return 0; }
static inline void livepatch_bsc1273052_cleanup(void) {}

struct hsr_port;
struct sk_buff;

void klpp_hsr_forward_skb(struct sk_buff *skb, struct hsr_port *port);

#endif /* _LIVEPATCH_BSC1273052_H */
