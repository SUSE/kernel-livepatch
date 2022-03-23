#ifndef _LIVEPATCH_BSC1195908_H
#define _LIVEPATCH_BSC1195908_H

int livepatch_bsc1195908_init(void);
static inline void livepatch_bsc1195908_cleanup(void) {}

struct kernfs_open_file;
struct kernfs_root;
struct file_system_type;
struct cgroup_namespace;

ssize_t klpp_cgroup_release_agent_write(struct kernfs_open_file *of,
					  char *buf, size_t nbytes, loff_t off);

int klpp_cgroup1_remount(struct kernfs_root *kf_root, int *flags, char *data);

struct dentry *klpp_cgroup1_mount(struct file_system_type *fs_type, int flags,
			     void *data, unsigned long magic,
			     struct cgroup_namespace *ns);

#endif /* _LIVEPATCH_BSC1195908_H */
