#ifndef _LIVEPATCH_BSC1254755_H
#define _LIVEPATCH_BSC1254755_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_SMC)

int livepatch_bsc1254755_init(void);
void livepatch_bsc1254755_cleanup(void);

struct net;
struct socket;

int klpp_smc_create(struct net *net, struct socket *sock, int protocol, int kern);
#else /* !IS_ENABLED(CONFIG_SMC) */

static inline int livepatch_bsc1254755_init(void) { return 0; }
static inline void livepatch_bsc1254755_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_SMC) */

#endif /* _LIVEPATCH_BSC1254755_H */
