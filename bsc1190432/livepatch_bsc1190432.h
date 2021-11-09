#ifndef _LIVEPATCH_BSC1190432_H
#define _LIVEPATCH_BSC1190432_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1190432_init(void);
void livepatch_bsc1190432_cleanup(void);

struct socket;
struct sockaddr;

int klpp_l2cap_sock_connect(struct socket *sock, struct sockaddr *addr,
			      int alen, int flags);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1190432_init(void) { return 0; }

static inline void livepatch_bsc1190432_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */
#endif /* _LIVEPATCH_BSC1190432_H */
