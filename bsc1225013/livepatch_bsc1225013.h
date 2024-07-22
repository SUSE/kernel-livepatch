#ifndef _LIVEPATCH_BSC1225013_H
#define _LIVEPATCH_BSC1225013_H

#if IS_ENABLED(CONFIG_BT)

void klpp_sco_sock_timeout(struct work_struct *work);

#endif

static inline int livepatch_bsc1225013_init(void) { return 0; }
static inline void livepatch_bsc1225013_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1225013_H */
