#ifndef _LIVEPATCH_BSC1259798_H
#define _LIVEPATCH_BSC1259798_H

#if IS_ENABLED(CONFIG_INFINIBAND_USER_MAD)

int livepatch_bsc1259798_init(void);
void livepatch_bsc1259798_cleanup(void);

struct file;
ssize_t klpp_ib_umad_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *pos);
#else /* !IS_ENABLED(CONFIG_INFINIBAND_USER_MAD) */

static inline int livepatch_bsc1259798_init(void) { return 0; }
static inline void livepatch_bsc1259798_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_INFINIBAND_USER_MAD) */

#endif /* _LIVEPATCH_BSC1259798_H */
