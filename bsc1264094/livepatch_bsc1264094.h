#ifndef _LIVEPATCH_BSC1264094_H
#define _LIVEPATCH_BSC1264094_H

#include <linux/types.h>

static inline int livepatch_bsc1264094_init(void) { return 0; }
static inline void livepatch_bsc1264094_cleanup(void) {}

struct file;
struct inode;

int klpp_usbtmc_release(struct inode *inode, struct file *file);

#endif /* _LIVEPATCH_BSC1264094_H */
