#ifndef _LIVEPATCH_BSC1188323_H
#define _LIVEPATCH_BSC1188323_H

#if IS_ENABLED(CONFIG_CAN_BCM)

int livepatch_bsc1188323_init(void);
void livepatch_bsc1188323_cleanup(void);


struct socket;
struct msghdr;

int klpp_bcm_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
int klpp_bcm_release(struct socket *sock);

#else /* !IS_ENABLED(CONFIG_CAN_BCM) */

static inline int livepatch_bsc1188323_init(void) { return 0; }

static inline void livepatch_bsc1188323_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_CAN_BCM) */
#endif /* _LIVEPATCH_BSC1188323_H */
