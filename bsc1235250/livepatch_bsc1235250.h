#ifndef _LIVEPATCH_BSC1235250_H
#define _LIVEPATCH_BSC1235250_H

int livepatch_bsc1235250_init(void);
static inline void livepatch_bsc1235250_cleanup(void) {}

int klpp___sock_map_delete(struct bpf_stab *stab, struct sock *sk_test,
                           struct sock **psk);
#endif /* _LIVEPATCH_BSC1235250_H */
