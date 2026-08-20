#ifndef _LIVEPATCH_BSC1269196_H
#define _LIVEPATCH_BSC1269196_H

#include <linux/types.h>

static inline int livepatch_bsc1269196_init(void) { return 0; }
static inline void livepatch_bsc1269196_cleanup(void) {}

struct msghdr;
struct socket;

int klpp_af_alg_sendmsg(struct socket *sock, struct msghdr *msg, size_t size, unsigned int ivsize);

#endif /* _LIVEPATCH_BSC1269196_H */
