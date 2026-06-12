#ifndef _LIVEPATCH_BSC1263088_H
#define _LIVEPATCH_BSC1263088_H

struct socket;

static inline int livepatch_bsc1263088_init(void) { return 0; }
static inline void livepatch_bsc1263088_cleanup(void) {}

int klpp_packet_release(struct socket *sock);

#endif /* _LIVEPATCH_BSC1263088_H */
