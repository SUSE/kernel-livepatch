#ifndef _LIVEPATCH_BSC1211395_H
#define _LIVEPATCH_BSC1211395_H

int livepatch_bsc1211395_init(void);
static inline void livepatch_bsc1211395_cleanup(void) {}

struct sk_buff;

int klpp_ipv6_rthdr_rcv(struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1211395_H */
