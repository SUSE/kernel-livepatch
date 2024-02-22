#ifndef _LIVEPATCH_BSC1218733_H
#define _LIVEPATCH_BSC1218733_H

#if IS_ENABLED(CONFIG_ATM)

struct socket;

int klpp_do_vcc_ioctl(struct socket *sock, unsigned int cmd,
			unsigned long arg, int compat);

int livepatch_bsc1218733_init(void);
void livepatch_bsc1218733_cleanup(void);

#else /* !IS_ENABLED(CONFIG_ATM) */

static inline int livepatch_bsc1218733_init(void) { return 0; }
static inline void livepatch_bsc1218733_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_ATM) */

#endif /* _LIVEPATCH_BSC1218733_H */
