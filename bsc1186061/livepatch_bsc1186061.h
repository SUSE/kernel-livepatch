#ifndef _LIVEPATCH_BSC1186061_H
#define _LIVEPATCH_BSC1186061_H

#if IS_ENABLED(CONFIG_NFC)

int livepatch_bsc1186061_init(void);
void livepatch_bsc1186061_cleanup(void);


struct socket;
struct sockaddr;

int klpp_llcp_sock_bind(struct socket *sock, struct sockaddr *addr, int alen);
int klpp_llcp_sock_connect(struct socket *sock, struct sockaddr *_addr,
			     int len, int flags);

#else /* !IS_ENABLED(CONFIG_NFC) */

static inline int livepatch_bsc1186061_init(void) { return 0; }

static inline void livepatch_bsc1186061_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NFC) */
#endif /* _LIVEPATCH_BSC1186061_H */
