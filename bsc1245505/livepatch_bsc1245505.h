#ifndef _LIVEPATCH_BSC1245505_H
#define _LIVEPATCH_BSC1245505_H

static inline int livepatch_bsc1245505_init(void) { return 0; }
static inline void livepatch_bsc1245505_cleanup(void) {}

struct notifier_block;
int klpp_taprio_dev_notifier(struct notifier_block *nb, unsigned long event,
                             void *ptr);
#endif /* _LIVEPATCH_BSC1245505_H */
