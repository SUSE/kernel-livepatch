#ifndef _LIVEPATCH_BSC1187054_H
#define _LIVEPATCH_BSC1187054_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1187054_init(void);
void livepatch_bsc1187054_cleanup(void);


struct socket;

int klpp_hci_sock_ioctl(struct socket *sock, unsigned int cmd,
			  unsigned long arg);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1187054_init(void) { return 0; }

static inline void livepatch_bsc1187054_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */
#endif /* _LIVEPATCH_BSC1187054_H */
