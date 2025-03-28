#ifndef _LIVEPATCH_BSC1228714_H
#define _LIVEPATCH_BSC1228714_H

static inline int livepatch_bsc1228714_init(void) { return 0; }
static inline void livepatch_bsc1228714_cleanup(void) {}

int klpp_tap_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len);

#endif /* _LIVEPATCH_BSC1228714_H */
