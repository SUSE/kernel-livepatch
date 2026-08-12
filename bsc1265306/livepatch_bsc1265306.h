#ifndef _LIVEPATCH_BSC1265306_H
#define _LIVEPATCH_BSC1265306_H

#include <linux/types.h>

static inline int livepatch_bsc1265306_init(void) { return 0; }
static inline void livepatch_bsc1265306_cleanup(void) {}

struct msghdr;
struct socket;

int klpp_aead_recvmsg(struct socket *sock, struct msghdr *msg, size_t ignored, int flags);

#endif /* _LIVEPATCH_BSC1265306_H */
