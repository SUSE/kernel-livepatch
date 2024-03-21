#ifndef _LIVEPATCH_BSC1208911_H
#define _LIVEPATCH_BSC1208911_H

struct sock;

int klpp_inet_csk_listen_start(struct sock *sk, int backlog);
int klpp_tcp_set_ulp(struct sock *sk, const char *name);

int bsc1208911_net_ipv4_inet_connection_sock_init(void);
int bsc1208911_net_ipv4_tcp_ulp_init(void);

int livepatch_bsc1208911_init(void);
static inline void livepatch_bsc1208911_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1208911_H */
