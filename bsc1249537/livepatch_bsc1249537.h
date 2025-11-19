#ifndef _LIVEPATCH_BSC1249537_H
#define _LIVEPATCH_BSC1249537_H

#include <linux/types.h>

static inline int livepatch_bsc1249537_init(void) { return 0; }
static inline void livepatch_bsc1249537_cleanup(void) {}

struct sk_psock;
struct sock;
struct tls_strparser;

bool klpp_tls_strp_msg_load(struct tls_strparser *strp, bool force_refresh);
int klpp_tls_rx_rec_wait(struct sock *sk, struct sk_psock *psock, bool nonblock, bool released);

#endif /* _LIVEPATCH_BSC1249537_H */
