#ifndef _LIVEPATCH_BSC1188613_H
#define _LIVEPATCH_BSC1188613_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1188613_init(void);
void livepatch_bsc1188613_cleanup(void);


struct hci_conn;
struct sock;
struct socket;
struct msghdr;

void klpp_sco_conn_del(struct hci_conn *hcon, int err);
void klpp___sco_sock_close(struct sock *sk);
int klpp_sco_sock_sendmsg(struct socket *sock, struct msghdr *msg,
			    size_t len);
int klpp_sco_sock_recvmsg(struct socket *sock, struct msghdr *msg,
			    size_t len, int flags);
int klpp_sco_sock_getsockopt(struct socket *sock, int level, int optname,
			       char __user *optval, int __user *optlen);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1188613_init(void) { return 0; }

static inline void livepatch_bsc1188613_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */
#endif /* _LIVEPATCH_BSC1188613_H */
