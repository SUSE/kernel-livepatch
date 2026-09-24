#ifndef _LIVEPATCH_BSC1275228_H
#define _LIVEPATCH_BSC1275228_H

#include <linux/types.h>

static inline int livepatch_bsc1275228_init(void) { return 0; }
static inline void livepatch_bsc1275228_cleanup(void) {}

struct msghdr;
struct socket;

int klpp_pppoe_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len);

#endif /* _LIVEPATCH_BSC1275228_H */
