#ifndef _LIVEPATCH_BSC1228578_H
#define _LIVEPATCH_BSC1228578_H

static inline int livepatch_bsc1228578_init(void) { return 0; }
static inline void livepatch_bsc1228578_cleanup(void) {}

int klpp_l2cap_sock_recv_cb(struct l2cap_chan *chan, struct sk_buff *skb);
int klpp_l2cap_sock_release(struct socket *sock);
void klpp_l2cap_sock_cleanup_listen(struct sock *parent);
void klpp_l2cap_sock_close_cb(struct l2cap_chan *chan);

#endif /* _LIVEPATCH_BSC1228578_H */
