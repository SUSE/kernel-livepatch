#ifndef _LIVEPATCH_BSC1228786_H
#define _LIVEPATCH_BSC1228786_H

static inline int livepatch_bsc1228786_init(void) { return 0; }
static inline void livepatch_bsc1228786_cleanup(void) {}

struct sock;

void klpp_sk_common_release(struct sock *sk);

#endif /* _LIVEPATCH_BSC1228786_H */
