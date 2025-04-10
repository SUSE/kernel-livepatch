#ifndef _LIVEPATCH_BSC1235218_H
#define _LIVEPATCH_BSC1235218_H

static inline int livepatch_bsc1235218_init(void) { return 0; }
static inline void livepatch_bsc1235218_cleanup(void) {}

struct net;
struct socket;

int klpp_inet6_create(struct net *net, struct socket *sock, int protocol,
		      int kern);

#endif /* _LIVEPATCH_BSC1235218_H */
