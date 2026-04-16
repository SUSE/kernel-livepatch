#ifndef _LIVEPATCH_BSC1255066_H
#define _LIVEPATCH_BSC1255066_H

#include <linux/types.h>

static inline int livepatch_bsc1255066_init(void) { return 0; }
static inline void livepatch_bsc1255066_cleanup(void) {}

struct sock;

void klpp_sco_sock_kill(struct sock *sk);

#endif /* _LIVEPATCH_BSC1255066_H */
