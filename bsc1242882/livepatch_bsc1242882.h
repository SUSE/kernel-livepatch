#ifndef _LIVEPATCH_BSC1242882_H
#define _LIVEPATCH_BSC1242882_H

static inline int livepatch_bsc1242882_init(void) { return 0; }
static inline void livepatch_bsc1242882_cleanup(void) {}

struct sock;
struct sk_buff;
struct request_sock;
struct dst_entry;
struct sock *klpp_subflow_syn_recv_sock(const struct sock *sk,
					  struct sk_buff *skb,
					  struct request_sock *req,
					  struct dst_entry *dst,
					  struct request_sock *req_unhash,
					  bool *own_req);
#endif /* _LIVEPATCH_BSC1242882_H */
