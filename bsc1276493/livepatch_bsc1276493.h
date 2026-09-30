#ifndef _LIVEPATCH_BSC1276493_H
#define _LIVEPATCH_BSC1276493_H

#include <linux/types.h>

static inline int livepatch_bsc1276493_init(void) { return 0; }
static inline void livepatch_bsc1276493_cleanup(void) {}

struct socket;

int klpp_llcp_sock_release(struct socket *sock);

#endif /* _LIVEPATCH_BSC1276493_H */
