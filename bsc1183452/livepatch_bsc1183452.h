#ifndef _LIVEPATCH_BSC1183452_H
#define _LIVEPATCH_BSC1183452_H

int livepatch_bsc1183452_init(void);
static inline void livepatch_bsc1183452_cleanup(void) {}


struct file_system_type;
struct kernfs_root;

struct dentry *klpp_kernfs_mount_ns(struct file_system_type *fs_type, int flags,
				struct kernfs_root *root, unsigned long magic,
				bool *new_sb_created, const void *ns);

#endif /* _LIVEPATCH_BSC1183452_H */
