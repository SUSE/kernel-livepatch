#ifndef _LIVEPATCH_BSC1225733_H
#define _LIVEPATCH_BSC1225733_H

static inline int livepatch_bsc1225733_init(void) { return 0; }
static inline void livepatch_bsc1225733_cleanup(void) {}

struct sock;

int klpp_tcp_twsk_unique(struct sock *sk, struct sock *sktw, void *twp);

#endif /* _LIVEPATCH_BSC1225733_H */
