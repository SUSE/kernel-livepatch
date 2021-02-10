#ifndef _LIVEPATCH_BSC1181553_H
#define _LIVEPATCH_BSC1181553_H

int livepatch_bsc1181553_init(void);
static inline void livepatch_bsc1181553_cleanup(void) {}


long klpp_do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3);

#endif /* _LIVEPATCH_BSC1181553_H */
