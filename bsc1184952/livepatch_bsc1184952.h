#ifndef _LIVEPATCH_BSC1184952_H
#define _LIVEPATCH_BSC1184952_H

#include <linux/fs.h>

int livepatch_bsc1184952_init(void);
void livepatch_bsc1184952_cleanup(void);


struct fuse_io_priv;
struct fuse_attr;

struct posix_acl *klpp_fuse_get_acl(struct inode *inode, int type);
int klpp_fuse_set_acl(struct inode *inode, struct posix_acl *acl, int type);
int klpp_fuse_dentry_revalidate(struct dentry *entry, unsigned int flags);
struct dentry *klpp_fuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags);
int klpp_fuse_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened);
int klpp_fuse_mknod(struct inode *dir, struct dentry *entry, umode_t mode,
		      dev_t rdev);
int klpp_fuse_mkdir(struct inode *dir, struct dentry *entry, umode_t mode);
int klpp_fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link);
int klpp_fuse_unlink(struct inode *dir, struct dentry *entry);
int klpp_fuse_rmdir(struct inode *dir, struct dentry *entry);
int klpp_fuse_rename2(struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent,
			unsigned int flags);
int klpp_fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent);
int klpp_fuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file);
int klpp_fuse_permission(struct inode *inode, int mask);
int klpp_fuse_readdir(struct file *file, struct dir_context *ctx);
const char *klpp_fuse_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done);
int klpp_fuse_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file);
int klpp_fuse_setattr(struct dentry *entry, struct iattr *attr);
int klpp_fuse_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int flags);
int klpp_fuse_open_common(struct inode *inode, struct file *file, bool isdir);
int klpp_fuse_flush(struct file *file, fl_owner_t id);
int klpp_fuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir);
int klpp_fuse_readpage(struct file *file, struct page *page);
int klpp_fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages);
ssize_t klpp_fuse_perform_write(struct file *file,
				  struct address_space *mapping,
				  struct iov_iter *ii, loff_t pos);
ssize_t klpp_fuse_file_write_iter(struct kiocb *iocb, struct iov_iter *from);
ssize_t klpp___fuse_direct_read(struct fuse_io_priv *io,
				  struct iov_iter *iter,
				  loff_t *ppos);
ssize_t klpp_fuse_direct_write_iter(struct kiocb *iocb, struct iov_iter *from);
int klpp_fuse_writepages(struct address_space *mapping,
			   struct writeback_control *wbc);
long klpp_fuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);
struct inode *klpp_fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version);
ssize_t klpp_fuse_listxattr(struct dentry *entry, char *list, size_t size);
int klpp_fuse_xattr_get(const struct xattr_handler *handler,
			 struct dentry *dentry, struct inode *inode,
			 const char *name, void *value, size_t size);
int klpp_fuse_xattr_set(const struct xattr_handler *handler,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, const void *value, size_t size,
			  int flags);

#endif /* _LIVEPATCH_BSC1184952_H */
