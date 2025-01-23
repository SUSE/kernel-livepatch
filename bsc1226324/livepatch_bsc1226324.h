#ifndef _LIVEPATCH_BSC1226324_H
#define _LIVEPATCH_BSC1226324_H

#include <linux/types.h>

static inline int livepatch_bsc1226324_init(void) { return 0; }
static inline void livepatch_bsc1226324_cleanup(void) {}

struct sock;
int klpp_sk_setsockopt(struct sock *sk, int level, int optname,
		       sockptr_t optval, unsigned int optlen);
void klpp_tcp_retransmit_timer(struct sock *sk);

#endif /* _LIVEPATCH_BSC1226324_H */
