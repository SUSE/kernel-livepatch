#ifndef _LIVEPATCH_BSC1227903_H
#define _LIVEPATCH_BSC1227903_H

#if IS_ENABLED(CONFIG_GVE)

struct gve_notify_block;

int livepatch_bsc1227903_init(void);
void livepatch_bsc1227903_cleanup(void);
int klpp_gve_rx_poll_dqo(struct gve_notify_block *block, int budget);

#else /* !IS_ENABLED(CONFIG_GVE) */

static inline int livepatch_bsc1227903_init(void) { return 0; }
static inline void livepatch_bsc1227903_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_GVE) */

#endif /* _LIVEPATCH_BSC1227903_H */
