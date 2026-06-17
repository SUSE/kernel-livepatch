#ifndef _LIVEPATCH_BSC1263902_H
#define _LIVEPATCH_BSC1263902_H

struct file;
struct dir_context;
struct fuse_dirent;

static inline int livepatch_bsc1263902_init(void) { return 0; }
static inline void livepatch_bsc1263902_cleanup(void) {}

bool klpp_fuse_emit(struct file *file, struct dir_context *ctx,
		      struct fuse_dirent *dirent);

#endif /* _LIVEPATCH_BSC1263902_H */
