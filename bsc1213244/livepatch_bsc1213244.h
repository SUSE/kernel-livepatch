#ifndef _LIVEPATCH_BSC1213244_H
#define _LIVEPATCH_BSC1213244_H


struct file;

ssize_t
klpp_vcs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);

int livepatch_bsc1213244_init(void);
static inline void livepatch_bsc1213244_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1213244_H */
