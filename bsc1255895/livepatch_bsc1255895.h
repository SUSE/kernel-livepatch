#ifndef _LIVEPATCH_BSC1255895_H
#define _LIVEPATCH_BSC1255895_H

#include <linux/types.h>
#include <linux/netdevice.h>

struct net;
struct sock;
struct sk_buff;

static inline int livepatch_bsc1255895_init(void) { return 0; }
static inline void livepatch_bsc1255895_cleanup(void) {}

int klpp_br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb);
rx_handler_result_t klpp_br_handle_frame(struct sk_buff **pskb);

#endif /* _LIVEPATCH_BSC1255895_H */
