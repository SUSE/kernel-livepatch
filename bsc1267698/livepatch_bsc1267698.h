#ifndef _LIVEPATCH_BSC1267698_H
#define _LIVEPATCH_BSC1267698_H

#include <linux/types.h>

static inline int livepatch_bsc1267698_init(void) { return 0; }
static inline void livepatch_bsc1267698_cleanup(void) {}

struct msghdr;
struct sock;

int klpp_sctp_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len);

#endif /* _LIVEPATCH_BSC1267698_H */
