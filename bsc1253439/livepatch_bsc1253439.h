#ifndef _LIVEPATCH_BSC1253439_H
#define _LIVEPATCH_BSC1253439_H

#include <linux/types.h>

static inline int livepatch_bsc1253439_init(void) { return 0; }
static inline void livepatch_bsc1253439_cleanup(void) {}

struct request_sock_ops;
struct sk_buff;
struct sock;
struct tcp_request_sock_ops;

int klpp_tcp_conn_request(struct request_sock_ops *rsk_ops, const struct tcp_request_sock_ops *af_ops, struct sock *sk, struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1253439_H */
