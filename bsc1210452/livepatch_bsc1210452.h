#ifndef _LIVEPATCH_BSC1210452_H
#define _LIVEPATCH_BSC1210452_H

static inline int livepatch_bsc1210452_init(void) { return 0; }
static inline void livepatch_bsc1210452_cleanup(void) {}

struct sock;

int klpp_tls_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen);

#endif /* _LIVEPATCH_BSC1210452_H */
