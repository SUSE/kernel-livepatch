#ifndef _LIVEPATCH_BSC1185901_H
#define _LIVEPATCH_BSC1185901_H

int livepatch_bsc1185901_init(void);
void livepatch_bsc1185901_cleanup(void);


struct net;
struct socket;
struct sock;

int klpp_inet_create(struct net *net, struct socket *sock, int protocol,
		       int kern);
int klpp_inet6_create(struct net *net, struct socket *sock, int protocol,
			int kern);

#endif /* _LIVEPATCH_BSC1185901_H */
