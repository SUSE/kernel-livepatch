#ifndef _BSC1185901_COMMON_H
#define _BSC1185901_COMMON_H

int livepatch_bsc1185901_af_inet_init(void);
static inline void livepatch_bsc1185901_af_inet_cleanup(void) {}

int livepatch_bsc1185901_af_inet6_init(void);
static inline void livepatch_bsc1185901_af_inet6_cleanup(void) {}

int livepatch_bsc1185901_sctp_socket_init(void);
void livepatch_bsc1185901_sctp_socket_cleanup(void);


#include <linux/types.h>

struct sock;

bool klpp_is_sctp_sock(struct sock *sk);
void klpp_sctp_disable_asconf(struct sock *sk);

#endif
