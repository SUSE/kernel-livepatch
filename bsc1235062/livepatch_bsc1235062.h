#ifndef _LIVEPATCH_BSC1235062_H
#define _LIVEPATCH_BSC1235062_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1235062_init(void);
void livepatch_bsc1235062_cleanup(void);

struct l2cap_chan *klpp_l2cap_sock_new_connection_cb(struct l2cap_chan *chan);
int klpp_l2cap_sock_create(struct net *net, struct socket *sock, int protocol,
			   int kern);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1235062_init(void) { return 0; }
static inline void livepatch_bsc1235062_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */

#endif /* _LIVEPATCH_BSC1235062_H */
