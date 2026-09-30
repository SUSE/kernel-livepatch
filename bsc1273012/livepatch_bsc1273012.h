#ifndef _LIVEPATCH_BSC1273012_H
#define _LIVEPATCH_BSC1273012_H

#include <linux/types.h>

static inline int livepatch_bsc1273012_init(void) { return 0; }
static inline void livepatch_bsc1273012_cleanup(void) {}

struct msghdr;
struct sk_buff;
struct sock;

void klpp_ip6_datagram_recv_specific_ctl(struct sock *sk, struct msghdr *msg, struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1273012_H */
