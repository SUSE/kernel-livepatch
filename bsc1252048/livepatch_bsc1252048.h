#ifndef _LIVEPATCH_BSC1252048_H
#define _LIVEPATCH_BSC1252048_H

static inline int livepatch_bsc1252048_init(void) { return 0; }
static inline void livepatch_bsc1252048_cleanup(void) {}

int klpp_futex_requeue(u32 __user *uaddr1, unsigned int flags, u32 __user *uaddr2,
		  int nr_wake, int nr_requeue, u32 *cmpval, int requeue_pi);
#endif /* _LIVEPATCH_BSC1252048_H */
