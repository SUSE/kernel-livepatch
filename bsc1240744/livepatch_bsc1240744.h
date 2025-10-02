#ifndef _LIVEPATCH_BSC1240744_H
#define _LIVEPATCH_BSC1240744_H

#include <linux/types.h>

int livepatch_bsc1240744_init(void);
void livepatch_bsc1240744_cleanup(void);

int bsc1240744_net_ipv6_ip6_output_init(void);
static inline void bsc1240744_net_ipv6_ip6_output_cleanup(void) {};

int bsc1240744_net_ipv6_raw_init(void);
static inline void bsc1240744_net_ipv6_raw_cleanup(void) {};

struct net;
struct sock;
struct sk_buff;
int klpp___ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);
struct flowi6;
struct ipv6_txoptions;
int klpp_ip6_xmit(const struct sock *sk, struct sk_buff *skb, struct flowi6 *fl6,
	     __u32 mark, struct ipv6_txoptions *opt, int tclass);
int klpp___ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);
struct msghdr;
int klpp_rawv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
#endif /* _LIVEPATCH_BSC1240744_H */
