#ifndef _LIVEPATCH_BSC1228585_H
#define _LIVEPATCH_BSC1228585_H

static inline int livepatch_bsc1228585_init(void) { return 0; }
static inline void livepatch_bsc1228585_cleanup(void) {}

irqreturn_t klpp_idxd_wq_thread(int irq, void *data);
#endif /* _LIVEPATCH_BSC1228585_H */
