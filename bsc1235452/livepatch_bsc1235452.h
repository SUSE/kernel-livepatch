#ifndef _LIVEPATCH_BSC1235452_H
#define _LIVEPATCH_BSC1235452_H

static inline int livepatch_bsc1235452_init(void) { return 0; }
static inline void livepatch_bsc1235452_cleanup(void) {}

struct sk_buff;
struct hsr_port;

void klpp_hsr_forward_skb(struct sk_buff *skb, struct hsr_port *port);

#endif /* _LIVEPATCH_BSC1235452_H */
