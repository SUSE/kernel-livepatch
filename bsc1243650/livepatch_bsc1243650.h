#ifndef _LIVEPATCH_BSC1243650_H
#define _LIVEPATCH_BSC1243650_H

int livepatch_bsc1243650_init(void);
void livepatch_bsc1243650_cleanup(void);

int bsc1243650_net_sunrpc_svcsock_init(void);
void bsc1243650_net_sunrpc_svcsock_cleanup(void);

int bsc1243650_net_sunrpc_xprtsock_init(void);
void bsc1243650_net_sunrpc_xprtsock_cleanup(void);

struct svc_serv;
struct net;
struct sockaddr;
struct work_struct;

struct svc_xprt *klpp_svc_create_socket(struct svc_serv *serv, int protocol,
                                        struct net *net, struct sockaddr *sin,
                                        int len, int flags);

void klpp_xs_tcp_setup_socket(struct work_struct *work);
void klpp_xs_udp_setup_socket(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1243650_H */
