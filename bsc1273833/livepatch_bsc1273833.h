#ifndef _LIVEPATCH_BSC1273833_H
#define _LIVEPATCH_BSC1273833_H

#include <linux/types.h>

int livepatch_bsc1273833_init(void);
static inline void livepatch_bsc1273833_cleanup(void) {}


struct msghdr;
struct sock;

int klpp_raw_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
#endif /* _LIVEPATCH_BSC1273833_H */
