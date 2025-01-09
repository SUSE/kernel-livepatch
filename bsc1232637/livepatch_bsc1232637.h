#ifndef _LIVEPATCH_BSC1232637_H
#define _LIVEPATCH_BSC1232637_H

int livepatch_bsc1232637_init(void);
static inline void livepatch_bsc1232637_cleanup(void) {}

struct net;
struct sock;
struct sk_buff;

int klpp_ip6_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		 int (*output)(struct net *, struct sock *, struct sk_buff *));

#endif /* _LIVEPATCH_BSC1232637_H */
