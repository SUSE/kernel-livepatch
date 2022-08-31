#ifndef _LIVEPATCH_BSC1196867_H
#define _LIVEPATCH_BSC1196867_H

int livepatch_bsc1196867_init(void);
static inline void livepatch_bsc1196867_cleanup(void) {}


#include <linux/types.h>

struct sk_buff;
struct sock;
struct ip_options_rcu;
struct flowi;
struct flowi4;
struct sk_buff_head;
struct inet_cork;

int klpp_ip_build_and_send_pkt(struct sk_buff *skb, const struct sock *sk,
			  __be32 saddr, __be32 daddr,
			  struct ip_options_rcu *opt);

int klpp_ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl);

struct sk_buff *klpp___ip_make_skb(struct sock *sk,
			      struct flowi4 *fl4,
			      struct sk_buff_head *queue,
			      struct inet_cork *cork);

#endif /* _LIVEPATCH_BSC1196867_H */
