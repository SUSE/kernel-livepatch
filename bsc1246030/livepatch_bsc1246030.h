#ifndef _LIVEPATCH_BSC1246030_H
#define _LIVEPATCH_BSC1246030_H

int livepatch_bsc1246030_init(void);
static inline void livepatch_bsc1246030_cleanup(void) {}

void klpp_shm_destroy_orphaned(struct ipc_namespace *ns);
#endif /* _LIVEPATCH_BSC1246030_H */
