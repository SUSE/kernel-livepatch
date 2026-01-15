#ifndef _LIVEPATCH_BSC1250192_H
#define _LIVEPATCH_BSC1250192_H

static inline int livepatch_bsc1250192_init(void) { return 0; }
static inline void livepatch_bsc1250192_cleanup(void) {}

struct sock;
struct msghdr;
int klpp_tls_sw_recvmsg(struct sock *sk,
		   struct msghdr *msg,
		   size_t len,
		   int flags,
		   int *addr_len);
#endif /* _LIVEPATCH_BSC1250192_H */
