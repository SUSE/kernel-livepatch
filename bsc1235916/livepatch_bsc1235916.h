#ifndef _LIVEPATCH_BSC1235916_H
#define _LIVEPATCH_BSC1235916_H

static inline int livepatch_bsc1235916_init(void) { return 0; }
static inline void livepatch_bsc1235916_cleanup(void) {}

struct sock;
struct sk_buff;
struct mptcp_out_options;
bool klpp_mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct mptcp_out_options *opts);
#endif /* _LIVEPATCH_BSC1235916_H */
