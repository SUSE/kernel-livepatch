#ifndef _LIVEPATCH_BSC1251203_H
#define _LIVEPATCH_BSC1251203_H

struct net;
struct sock;
struct sk_buff;

static inline int livepatch_bsc1251203_init(void) { return 0; }
static inline void livepatch_bsc1251203_cleanup(void) {}

int klpp_rpl_output(struct net *net, struct sock *sk, struct sk_buff *skb);
int klpp_rpl_input(struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1251203_H */
