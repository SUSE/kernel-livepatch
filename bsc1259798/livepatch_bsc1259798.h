#ifndef _LIVEPATCH_BSC1259798_H
#define _LIVEPATCH_BSC1259798_H

#include <linux/types.h>

static inline int livepatch_bsc1259798_init(void) { return 0; }
static inline void livepatch_bsc1259798_cleanup(void) {}

struct file;
ssize_t klpp_ib_umad_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *pos);
#endif /* _LIVEPATCH_BSC1259798_H */
