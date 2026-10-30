#ifndef _LIVEPATCH_BSC1285686_H
#define _LIVEPATCH_BSC1285686_H

#include <linux/types.h>

static inline int livepatch_bsc1285686_init(void) { return 0; }
static inline void livepatch_bsc1285686_cleanup(void) {}

struct request_sock;
struct sock;

void klpp_inet_sock_destruct(struct sock *sk);
void klpp_tcp_v4_reqsk_destructor(struct request_sock *req);

#endif /* _LIVEPATCH_BSC1285686_H */
