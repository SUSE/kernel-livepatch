#ifndef _LIVEPATCH_BSC1235231_H
#define _LIVEPATCH_BSC1235231_H

int livepatch_bsc1235231_init(void);
static inline void livepatch_bsc1235231_cleanup(void) {}

int klpp_inet_create(struct net *net, struct socket *sock, int protocol,
					int kern);

#endif /* _LIVEPATCH_BSC1235231_H */
