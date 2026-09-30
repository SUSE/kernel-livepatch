#ifndef _LIVEPATCH_BSC1276493_H
#define _LIVEPATCH_BSC1276493_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_NFC)

int livepatch_bsc1276493_init(void);
void livepatch_bsc1276493_cleanup(void);

struct socket;

int klpp_llcp_sock_release(struct socket *sock);
#else /* !IS_ENABLED(CONFIG_NFC) */

static inline int livepatch_bsc1276493_init(void) { return 0; }
static inline void livepatch_bsc1276493_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_NFC) */

#endif /* _LIVEPATCH_BSC1276493_H */
