#ifndef _LIVEPATCH_BSC1199697_H
#define _LIVEPATCH_BSC1199697_H

int livepatch_bsc1199697_init(void);
static inline void livepatch_bsc1199697_cleanup(void) {}


struct file_operations;

struct file *klpp_anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv, int flags);

#endif /* _LIVEPATCH_BSC1199697_H */
