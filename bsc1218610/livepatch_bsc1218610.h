#ifndef _LIVEPATCH_BSC1218610_H
#define _LIVEPATCH_BSC1218610_H

static inline int livepatch_bsc1218610_init(void) { return 0; }
static inline void livepatch_bsc1218610_cleanup(void) {}

#if IS_ENABLED(CONFIG_BT)

struct socket;
struct msghdr;

int klpp_bt_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
		    int flags);

#endif /* IS_ENABLED(CONFIG_BT) */

#endif /* _LIVEPATCH_BSC1218610_H */
