#ifndef _LIVEPATCH_BSC1271837_H
#define _LIVEPATCH_BSC1271837_H

#include <linux/types.h>
#include <linux/fs.h>

static inline int livepatch_bsc1271837_init(void) { return 0; }
static inline void livepatch_bsc1271837_cleanup(void) {}

struct fuse_file;
struct inode;

void klpp_fuse_file_release(struct inode *inode, struct fuse_file *ff, unsigned int open_flags, fl_owner_t id, bool isdir);

#endif /* _LIVEPATCH_BSC1271837_H */
