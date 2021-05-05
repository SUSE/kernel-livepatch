/*
 * bsc1184952_fuse_dir
 *
 * Fix for CVE-2020-36322, bsc#1184952 (fs/fuse/dir.c part)
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "bsc1184952_common.h"

/* klp-ccp: from fs/fuse/fuse_i.h */
static int (*klpe_fuse_lookup_name)(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode);

static void (*klpe_fuse_queue_forget)(struct fuse_conn *fc, struct fuse_forget_link *forget,
		       u64 nodeid, u64 nlookup);

static struct fuse_forget_link *(*klpe_fuse_alloc_forget)(void);

static void (*klpe_fuse_force_forget)(struct file *file, u64 nodeid);

static void (*klpe_fuse_read_fill)(struct fuse_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

static void (*klpe_fuse_change_attributes)(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version);

static void (*klpe_fuse_change_attributes_common)(struct inode *inode, struct fuse_attr *attr,
				   u64 attr_valid);

static struct fuse_req *(*klpe_fuse_get_req)(struct fuse_conn *fc, unsigned npages);

static void (*klpe_fuse_put_request)(struct fuse_conn *fc, struct fuse_req *req);

static void (*klpe_fuse_request_send)(struct fuse_conn *fc, struct fuse_req *req);

static ssize_t (*klpe_fuse_simple_request)(struct fuse_conn *fc, struct fuse_args *args);

static void (*klpe_fuse_invalidate_attr)(struct inode *inode);

static void (*klpe_fuse_invalidate_entry_cache)(struct dentry *entry);

static void (*klpe_fuse_invalidate_atime)(struct inode *inode);

static bool (*klpe_fuse_invalid_attr)(struct fuse_attr *attr);

static int (*klpe_fuse_allow_current_process)(struct fuse_conn *fc);

static u64 (*klpe_fuse_lock_owner_id)(struct fuse_conn *fc, fl_owner_t id);

static void (*klpe_fuse_update_ctime)(struct inode *inode);

static int (*klpe_fuse_update_attributes)(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed);

static void (*klpe_fuse_flush_writepages)(struct inode *inode);

static void (*klpe_fuse_set_nowrite)(struct inode *inode);
static void (*klpe_fuse_release_nowrite)(struct inode *inode);

static u64 (*klpe_fuse_get_attr_version)(struct fuse_conn *fc);

int klpp_fuse_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file);

static void (*klpe_fuse_unlock_inode)(struct inode *inode, bool locked);
static bool (*klpe_fuse_lock_inode)(struct inode *inode);

/* klp-ccp: from fs/fuse/dir.c */
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>

static bool fuse_use_readdirplus(struct inode *dir, struct dir_context *ctx)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_inode *fi = get_fuse_inode(dir);

	if (!fc->do_readdirplus)
		return false;
	if (!fc->readdirplus_auto)
		return true;
	if (test_and_clear_bit(FUSE_I_ADVISE_RDPLUS, &fi->state))
		return true;
	if (ctx->pos == 0)
		return true;
	return false;
}

static void fuse_advise_use_readdirplus(struct inode *dir)
{
	struct fuse_inode *fi = get_fuse_inode(dir);

	set_bit(FUSE_I_ADVISE_RDPLUS, &fi->state);
}

union fuse_dentry {
	u64 time;
	struct rcu_head rcu;
};

static inline void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	((union fuse_dentry *) entry->d_fsdata)->time = time;
}

static inline u64 fuse_dentry_time(struct dentry *entry)
{
	return ((union fuse_dentry *) entry->d_fsdata)->time;
}

static u64 time_to_jiffies(u64 sec, u32 nsec)
{
	if (sec || nsec) {
		struct timespec64 ts = {
			sec,
			min_t(u32, nsec, NSEC_PER_SEC - 1)
		};

		return get_jiffies_64() + timespec64_to_jiffies(&ts);
	} else
		return 0;
}

static void fuse_change_entry_timeout(struct dentry *entry,
				      struct fuse_entry_out *o)
{
	fuse_dentry_settime(entry,
		time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

static u64 attr_timeout(struct fuse_attr_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static u64 entry_attr_timeout(struct fuse_entry_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static void klpr_fuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	(*klpe_fuse_invalidate_entry_cache)(entry);
}

static void fuse_lookup_init(struct fuse_conn *fc, struct fuse_args *args,
			     u64 nodeid, const struct qstr *name,
			     struct fuse_entry_out *outarg)
{
	memset(outarg, 0, sizeof(struct fuse_entry_out));
	args->in.h.opcode = FUSE_LOOKUP;
	args->in.h.nodeid = nodeid;
	args->in.numargs = 1;
	args->in.args[0].size = name->len + 1;
	args->in.args[0].value = name->name;
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(struct fuse_entry_out);
	args->out.args[0].value = outarg;
}

int klpp_fuse_dentry_revalidate(struct dentry *entry, unsigned int flags)
{
	struct inode *inode;
	struct dentry *parent;
	struct fuse_conn *fc;
	struct fuse_inode *fi;
	int ret;

	inode = d_inode_rcu(entry);
	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (inode && klpp_fuse_is_bad(inode))
		goto invalid;
	else if (time_before64(fuse_dentry_time(entry), get_jiffies_64()) ||
		 (flags & LOOKUP_REVAL)) {
		struct fuse_entry_out outarg;
		FUSE_ARGS(args);
		struct fuse_forget_link *forget;
		u64 attr_version;

		/* For negative dentries, always do a fresh lookup */
		if (!inode)
			goto invalid;

		ret = -ECHILD;
		if (flags & LOOKUP_RCU)
			goto out;

		fc = get_fuse_conn(inode);

		forget = (*klpe_fuse_alloc_forget)();
		ret = -ENOMEM;
		if (!forget)
			goto out;

		attr_version = (*klpe_fuse_get_attr_version)(fc);

		parent = dget_parent(entry);
		fuse_lookup_init(fc, &args, get_node_id(d_inode(parent)),
				 &entry->d_name, &outarg);
		ret = (*klpe_fuse_simple_request)(fc, &args);
		dput(parent);
		/* Zero nodeid is same as -ENOENT */
		if (!ret && !outarg.nodeid)
			ret = -ENOENT;
		if (!ret) {
			fi = get_fuse_inode(inode);
			if (outarg.nodeid != get_node_id(inode)) {
				(*klpe_fuse_queue_forget)(fc, forget, outarg.nodeid, 1);
				goto invalid;
			}
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);
		}
		kfree(forget);
		if (ret == -ENOMEM)
			goto out;
		if (ret || (*klpe_fuse_invalid_attr)(&outarg.attr) ||
		    (outarg.attr.mode ^ inode->i_mode) & S_IFMT)
			goto invalid;

		forget_all_cached_acls(inode);
		(*klpe_fuse_change_attributes)(inode, &outarg.attr,
				       entry_attr_timeout(&outarg),
				       attr_version);
		fuse_change_entry_timeout(entry, &outarg);
	} else if (inode) {
		fi = get_fuse_inode(inode);
		if (flags & LOOKUP_RCU) {
			if (test_bit(FUSE_I_INIT_RDPLUS, &fi->state))
				return -ECHILD;
		} else if (test_and_clear_bit(FUSE_I_INIT_RDPLUS, &fi->state)) {
			parent = dget_parent(entry);
			fuse_advise_use_readdirplus(d_inode(parent));
			dput(parent);
		}
	}
	ret = 1;
out:
	return ret;

invalid:
	ret = 0;
	goto out;
}

static int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == FUSE_ROOT_ID;
}

struct dentry *klpp_fuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct fuse_entry_out outarg;
	struct inode *inode;
	struct dentry *newent;
	bool outarg_valid = true;
	bool locked;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(dir))
		return ERR_PTR(-EIO);

	locked = (*klpe_fuse_lock_inode)(dir);
	err = (*klpe_fuse_lookup_name)(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode);
	(*klpe_fuse_unlock_inode)(dir, locked);
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	newent = d_splice_alias(inode, entry);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;
	if (outarg_valid)
		fuse_change_entry_timeout(entry, &outarg);
	else
		(*klpe_fuse_invalidate_entry_cache)(entry);

	fuse_advise_use_readdirplus(dir);
	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

static int (*klpe_fuse_create_open)(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened);

int klpp_fuse_mknod(struct inode *, struct dentry *, umode_t, dev_t);
int klpp_fuse_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct dentry *res = NULL;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(dir))
		return -EIO;

	if (d_in_lookup(entry)) {
		res = klpp_fuse_lookup(dir, entry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			entry = res;
	}

	if (!(flags & O_CREAT) || d_really_is_positive(entry))
		goto no_open;

	/* Only creates */
	*opened |= FILE_CREATED;

	if (fc->no_create)
		goto mknod;

	err = (*klpe_fuse_create_open)(dir, entry, file, flags, mode, opened);
	if (err == -ENOSYS) {
		fc->no_create = 1;
		goto mknod;
	}
out_dput:
	dput(res);
	return err;

mknod:
	err = klpp_fuse_mknod(dir, entry, mode, 0);
	if (err)
		goto out_dput;
no_open:
	return finish_no_open(file, res);
}

static int klpp_create_new_entry(struct fuse_conn *fc, struct fuse_args *args,
			    struct inode *dir, struct dentry *entry,
			    umode_t mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	int err;
	struct fuse_forget_link *forget;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(dir))
		return -EIO;

	forget = (*klpe_fuse_alloc_forget)();
	if (!forget)
		return -ENOMEM;

	memset(&outarg, 0, sizeof(outarg));
	args->in.h.nodeid = get_node_id(dir);
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(outarg);
	args->out.args[0].value = &outarg;
	err = (*klpe_fuse_simple_request)(fc, args);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid) || (*klpe_fuse_invalid_attr)(&outarg.attr))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = klpp_fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, entry_attr_timeout(&outarg), 0);
	if (!inode) {
		(*klpe_fuse_queue_forget)(fc, forget, outarg.nodeid, 1);
		return -ENOMEM;
	}
	kfree(forget);

	err = d_instantiate_no_diralias(entry, inode);
	if (err)
		return err;

	fuse_change_entry_timeout(entry, &outarg);
	(*klpe_fuse_invalidate_attr)(dir);
	return 0;

 out_put_forget_req:
	kfree(forget);
	return err;
}

int klpp_fuse_mknod(struct inode *dir, struct dentry *entry, umode_t mode,
		      dev_t rdev)
{
	struct fuse_mknod_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKNOD;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return klpp_create_new_entry(fc, &args, dir, entry, mode);
}

int klpp_fuse_mkdir(struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_mkdir_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKDIR;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return klpp_create_new_entry(fc, &args, dir, entry, S_IFDIR);
}

int klpp_fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	unsigned len = strlen(link) + 1;
	FUSE_ARGS(args);

	args.in.h.opcode = FUSE_SYMLINK;
	args.in.numargs = 2;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	args.in.args[1].size = len;
	args.in.args[1].value = link;
	return klpp_create_new_entry(fc, &args, dir, entry, S_IFLNK);
}

int klpp_fuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(dir))
		return -EIO;

	args.in.h.opcode = FUSE_UNLINK;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 1;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	err = (*klpe_fuse_simple_request)(fc, &args);
	if (!err) {
		struct inode *inode = d_inode(entry);
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		/*
		 * If i_nlink == 0 then unlink doesn't make sense, yet this can
		 * happen if userspace filesystem is careless.  It would be
		 * difficult to enforce correct nlink usage so just ignore this
		 * condition here
		 */
		if (inode->i_nlink > 0)
			drop_nlink(inode);
		spin_unlock(&fc->lock);
		(*klpe_fuse_invalidate_attr)(inode);
		(*klpe_fuse_invalidate_attr)(dir);
		(*klpe_fuse_invalidate_entry_cache)(entry);
		(*klpe_fuse_update_ctime)(inode);
	} else if (err == -EINTR)
		klpr_fuse_invalidate_entry(entry);
	return err;
}

int klpp_fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(dir))
		return -EIO;

	args.in.h.opcode = FUSE_RMDIR;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 1;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	err = (*klpe_fuse_simple_request)(fc, &args);
	if (!err) {
		clear_nlink(d_inode(entry));
		(*klpe_fuse_invalidate_attr)(dir);
		(*klpe_fuse_invalidate_entry_cache)(entry);
	} else if (err == -EINTR)
		klpr_fuse_invalidate_entry(entry);
	return err;
}

static int (*klpe_fuse_rename_common)(struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent,
			      unsigned int flags, int opcode, size_t argsize);

int klpp_fuse_rename2(struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent,
			unsigned int flags)
{
	struct fuse_conn *fc = get_fuse_conn(olddir);
	int err;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(olddir))
		return -EIO;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EINVAL;

	if (flags) {
		if (fc->no_rename2 || fc->minor < 23)
			return -EINVAL;

		err = (*klpe_fuse_rename_common)(olddir, oldent, newdir, newent, flags,
					 FUSE_RENAME2,
					 sizeof(struct fuse_rename2_in));
		if (err == -ENOSYS) {
			fc->no_rename2 = 1;
			err = -EINVAL;
		}
	} else {
		err = (*klpe_fuse_rename_common)(olddir, oldent, newdir, newent, 0,
					 FUSE_RENAME,
					 sizeof(struct fuse_rename_in));
	}

	return err;
}

int klpp_fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	args.in.h.opcode = FUSE_LINK;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = newent->d_name.len + 1;
	args.in.args[1].value = newent->d_name.name;
	err = klpp_create_new_entry(fc, &args, newdir, newent, inode->i_mode);
	/* Contrary to "normal" filesystems it can happen that link
	   makes two "logical" inodes point to the same "physical"
	   inode.  We invalidate the attributes of the old one, so it
	   will reflect changes in the backing inode (link count,
	   etc.)
	*/
	if (!err) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		if (likely(inode->i_nlink < UINT_MAX))
			inc_nlink(inode);
		spin_unlock(&fc->lock);
		(*klpe_fuse_invalidate_attr)(inode);
		(*klpe_fuse_update_ctime)(inode);
	} else if (err == -EINTR) {
		(*klpe_fuse_invalidate_attr)(inode);
	}
	return err;
}

static void fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat)
{
	unsigned int blkbits;
	struct fuse_conn *fc = get_fuse_conn(inode);

	/* see the comment in fuse_change_attributes() */
	if (fc->writeback_cache && S_ISREG(inode->i_mode)) {
		attr->size = i_size_read(inode);
		attr->mtime = inode->i_mtime.tv_sec;
		attr->mtimensec = inode->i_mtime.tv_nsec;
		attr->ctime = inode->i_ctime.tv_sec;
		attr->ctimensec = inode->i_ctime.tv_nsec;
	}

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(&init_user_ns, attr->uid);
	stat->gid = make_kgid(&init_user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

int klpp_fuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	u64 attr_version;

	attr_version = (*klpe_fuse_get_attr_version)(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (file && S_ISREG(inode->i_mode)) {
		struct fuse_file *ff = file->private_data;

		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	args.in.h.opcode = FUSE_GETATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = (*klpe_fuse_simple_request)(fc, &args);
	if (!err) {
		if ((*klpe_fuse_invalid_attr)(&outarg.attr) ||
		    (inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
			/*
			 * Fix CVE-2020-36322
			 *  -1 line, +1 line
			 */
			klpp_fuse_make_bad(inode);
			err = -EIO;
		} else {
			(*klpe_fuse_change_attributes)(inode, &outarg.attr,
					       attr_timeout(&outarg),
					       attr_version);
			if (stat)
				fuse_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

static int (*klpe_fuse_access)(struct inode *inode, int mask);

static int (*klpe_fuse_perm_getattr)(struct inode *inode, int mask);

int klpp_fuse_permission(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	bool refreshed = false;
	int err = 0;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (!(*klpe_fuse_allow_current_process)(fc))
		return -EACCES;

	/*
	 * If attributes are needed, refresh them before proceeding
	 */
	if (fc->default_permissions ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		if (time_before64(fi->i_time, get_jiffies_64())) {
			refreshed = true;

			err = (*klpe_fuse_perm_getattr)(inode, mask);
			if (err)
				return err;
		}
	}

	if (fc->default_permissions) {
		err = generic_permission(inode, mask);

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */
		if (err == -EACCES && !refreshed) {
			err = (*klpe_fuse_perm_getattr)(inode, mask);
			if (!err)
				err = generic_permission(inode, mask);
		}

		/* Note: the opposite of the above test does not
		   exist.  So if permissions are revoked this won't be
		   noticed immediately, only after the attribute
		   timeout has expired */
	} else if (mask & (MAY_ACCESS | MAY_CHDIR)) {
		err = (*klpe_fuse_access)(inode, mask);
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = (*klpe_fuse_perm_getattr)(inode, mask);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 struct dir_context *ctx)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!dir_emit(ctx, dirent->name, dirent->namelen,
			       dirent->ino, dirent->type))
			break;

		buf += reclen;
		nbytes -= reclen;
		ctx->pos = dirent->off;
	}

	return 0;
}

static int klpp_fuse_direntplus_link(struct file *file,
				struct fuse_direntplus *direntplus,
				u64 attr_version)
{
	struct fuse_entry_out *o = &direntplus->entry_out;
	struct fuse_dirent *dirent = &direntplus->dirent;
	struct dentry *parent = file->f_path.dentry;
	struct qstr name = QSTR_INIT(dirent->name, dirent->namelen);
	struct dentry *dentry;
	struct dentry *alias;
	struct inode *dir = d_inode(parent);
	struct fuse_conn *fc;
	struct inode *inode;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	if (!o->nodeid) {
		/*
		 * Unlike in the case of fuse_lookup, zero nodeid does not mean
		 * ENOENT. Instead, it only means the userspace filesystem did
		 * not want to return attributes/handle for this entry.
		 *
		 * So do nothing.
		 */
		return 0;
	}

	if (name.name[0] == '.') {
		/*
		 * We could potentially refresh the attributes of the directory
		 * and its parent?
		 */
		if (name.len == 1)
			return 0;
		if (name.name[1] == '.' && name.len == 2)
			return 0;
	}

	if (invalid_nodeid(o->nodeid))
		return -EIO;
	if ((*klpe_fuse_invalid_attr)(&o->attr))
		return -EIO;

	fc = get_fuse_conn(dir);

	name.hash = full_name_hash(parent, name.name, name.len);
	dentry = d_lookup(parent, &name);
	if (!dentry) {
retry:
		dentry = d_alloc_parallel(parent, &name, &wq);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}
	if (!d_in_lookup(dentry)) {
		struct fuse_inode *fi;
		inode = d_inode(dentry);
		if (!inode ||
		    get_node_id(inode) != o->nodeid ||
		    ((o->attr.mode ^ inode->i_mode) & S_IFMT)) {
			d_invalidate(dentry);
			dput(dentry);
			goto retry;
		}
		/*
		 * Fix CVE-2020-36322
		 *  -1 line, +1 line
		 */
		if (klpp_fuse_is_bad(inode)) {
			dput(dentry);
			return -EIO;
		}

		fi = get_fuse_inode(inode);
		spin_lock(&fc->lock);
		fi->nlookup++;
		spin_unlock(&fc->lock);

		forget_all_cached_acls(inode);
		(*klpe_fuse_change_attributes)(inode, &o->attr,
				       entry_attr_timeout(o),
				       attr_version);
		/*
		 * The other branch comes via fuse_iget()
		 * which bumps nlookup inside
		 */
	} else {
		inode = klpp_fuse_iget(dir->i_sb, o->nodeid, o->generation,
				  &o->attr, entry_attr_timeout(o),
				  attr_version);
		if (!inode)
			inode = ERR_PTR(-ENOMEM);

		alias = d_splice_alias(inode, dentry);
		d_lookup_done(dentry);
		if (alias) {
			dput(dentry);
			dentry = alias;
		}
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}
	if (fc->readdirplus_auto)
		set_bit(FUSE_I_INIT_RDPLUS, &get_fuse_inode(inode)->state);
	fuse_change_entry_timeout(dentry, o);

	dput(dentry);
	return 0;
}

static int klpp_parse_dirplusfile(char *buf, size_t nbytes, struct file *file,
			     struct dir_context *ctx, u64 attr_version)
{
	struct fuse_direntplus *direntplus;
	struct fuse_dirent *dirent;
	size_t reclen;
	int over = 0;
	int ret;

	while (nbytes >= FUSE_NAME_OFFSET_DIRENTPLUS) {
		direntplus = (struct fuse_direntplus *) buf;
		dirent = &direntplus->dirent;
		reclen = FUSE_DIRENTPLUS_SIZE(direntplus);

		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!over) {
			/* We fill entries into dstbuf only as much as
			   it can hold. But we still continue iterating
			   over remaining entries to link them. If not,
			   we need to send a FORGET for each of those
			   which we did not link.
			*/
			over = !dir_emit(ctx, dirent->name, dirent->namelen,
				       dirent->ino, dirent->type);
			if (!over)
				ctx->pos = dirent->off;
		}

		buf += reclen;
		nbytes -= reclen;

		ret = klpp_fuse_direntplus_link(file, direntplus, attr_version);
		if (ret)
			(*klpe_fuse_force_forget)(file, direntplus->entry_out.nodeid);
	}

	return 0;
}

int klpp_fuse_readdir(struct file *file, struct dir_context *ctx)
{
	int plus, err;
	size_t nbytes;
	struct page *page;
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version = 0;
	bool locked;

	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	req = (*klpe_fuse_get_req)(fc, 1);
	if (IS_ERR(req))
		return PTR_ERR(req);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		(*klpe_fuse_put_request)(fc, req);
		return -ENOMEM;
	}

	plus = fuse_use_readdirplus(inode, ctx);
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = PAGE_SIZE;
	if (plus) {
		attr_version = (*klpe_fuse_get_attr_version)(fc);
		(*klpe_fuse_read_fill)(req, file, ctx->pos, PAGE_SIZE,
			       FUSE_READDIRPLUS);
	} else {
		(*klpe_fuse_read_fill)(req, file, ctx->pos, PAGE_SIZE,
			       FUSE_READDIR);
	}
	locked = (*klpe_fuse_lock_inode)(inode);
	(*klpe_fuse_request_send)(fc, req);
	(*klpe_fuse_unlock_inode)(inode, locked);
	nbytes = req->out.args[0].size;
	err = req->out.h.error;
	(*klpe_fuse_put_request)(fc, req);
	if (!err) {
		if (plus) {
			err = klpp_parse_dirplusfile(page_address(page), nbytes,
						file, ctx,
						attr_version);
		} else {
			err = parse_dirfile(page_address(page), nbytes, file,
					    ctx);
		}
	}

	__free_page(page);
	(*klpe_fuse_invalidate_atime)(inode);
	return err;
}

const char *klpp_fuse_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	char *link;
	ssize_t ret;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return ERR_PTR(-EIO);

	if (!dentry)
		return ERR_PTR(-ECHILD);

	link = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	args.in.h.opcode = FUSE_READLINK;
	args.in.h.nodeid = get_node_id(inode);
	args.out.argvar = 1;
	args.out.numargs = 1;
	args.out.args[0].size = PAGE_SIZE - 1;
	args.out.args[0].value = link;
	ret = (*klpe_fuse_simple_request)(fc, &args);
	if (ret < 0) {
		kfree(link);
		link = ERR_PTR(ret);
	} else {
		link[ret] = '\0';
		set_delayed_call(done, kfree_link, link);
	}
	(*klpe_fuse_invalidate_atime)(inode);
	return link;
}

static bool update_mtime(unsigned ivalid, bool trust_local_mtime)
{
	/* Always update if mtime is explicitly set  */
	if (ivalid & ATTR_MTIME_SET)
		return true;

	/* Or if kernel i_mtime is the official one */
	if (trust_local_mtime)
		return true;

	/* If it's an open(O_TRUNC) or an ftruncate(), don't update */
	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	/* In all other cases update */
	return true;
}

static void iattr_to_fattr(struct iattr *iattr, struct fuse_setattr_in *arg,
			   bool trust_local_cmtime)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = from_kuid(&init_user_ns, iattr->ia_uid);
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = from_kgid(&init_user_ns, iattr->ia_gid);
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && update_mtime(ivalid, trust_local_cmtime)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET) && !trust_local_cmtime)
			arg->valid |= FATTR_MTIME_NOW;
	}
	if ((ivalid & ATTR_CTIME) && trust_local_cmtime) {
		arg->valid |= FATTR_CTIME;
		arg->ctime = iattr->ia_ctime.tv_sec;
		arg->ctimensec = iattr->ia_ctime.tv_nsec;
	}
}

static void klpr___fuse_release_nowrite(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(fi->writectr != FUSE_NOWRITE);
	fi->writectr = 0;
	(*klpe_fuse_flush_writepages)(inode);
}

static void fuse_setattr_fill(struct fuse_conn *fc, struct fuse_args *args,
			      struct inode *inode,
			      struct fuse_setattr_in *inarg_p,
			      struct fuse_attr_out *outarg_p)
{
	args->in.h.opcode = FUSE_SETATTR;
	args->in.h.nodeid = get_node_id(inode);
	args->in.numargs = 1;
	args->in.args[0].size = sizeof(*inarg_p);
	args->in.args[0].value = inarg_p;
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(*outarg_p);
	args->out.args[0].value = outarg_p;
}

int klpp_fuse_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file)
{
	struct inode *inode = d_inode(dentry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	FUSE_ARGS(args);
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	bool is_truncate = false;
	bool is_wb = fc->writeback_cache;
	loff_t oldsize;
	int err;
	bool trust_local_cmtime = is_wb && S_ISREG(inode->i_mode);

	if (!fc->default_permissions)
		attr->ia_valid |= ATTR_FORCE;

	err = setattr_prepare(dentry, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_OPEN) {
		/* This is coming from open(..., ... | O_TRUNC); */
		WARN_ON(!(attr->ia_valid & ATTR_SIZE));
		WARN_ON(attr->ia_size != 0);
		if (fc->atomic_o_trunc) {
			/*
			 * No need to send request to userspace, since actual
			 * truncation has already been done by OPEN.  But still
			 * need to truncate page cache.
			 */
			i_size_write(inode, 0);
			truncate_pagecache(inode, 0);
			return 0;
		}
		file = NULL;
	}

	if (attr->ia_valid & ATTR_SIZE)
		is_truncate = true;

	/* Flush dirty data/metadata before non-truncate SETATTR */
	if (is_wb && S_ISREG(inode->i_mode) &&
	    attr->ia_valid &
			(ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_MTIME_SET |
			 ATTR_TIMES_SET)) {
		err = write_inode_now(inode, true);
		if (err)
			return err;

		(*klpe_fuse_set_nowrite)(inode);
		(*klpe_fuse_release_nowrite)(inode);
	}

	if (is_truncate) {
		(*klpe_fuse_set_nowrite)(inode);
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
		if (trust_local_cmtime && attr->ia_size != inode->i_size)
			attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(attr, &inarg, trust_local_cmtime);
	if (file) {
		struct fuse_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	if (attr->ia_valid & ATTR_SIZE) {
		/* For mandatory locking in truncate */
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = (*klpe_fuse_lock_owner_id)(fc, current->files);
	}
	fuse_setattr_fill(fc, &args, inode, &inarg, &outarg);
	err = (*klpe_fuse_simple_request)(fc, &args);
	if (err) {
		if (err == -EINTR)
			(*klpe_fuse_invalidate_attr)(inode);
		goto error;
	}

	if ((*klpe_fuse_invalid_attr)(&outarg.attr) ||
	    (inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
		/*
		 * Fix CVE-2020-36322
		 *  -1 line, +1 line
		 */
		klpp_fuse_make_bad(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fc->lock);
	/* the kernel maintains i_mtime locally */
	if (trust_local_cmtime) {
		if (attr->ia_valid & ATTR_MTIME)
			inode->i_mtime = attr->ia_mtime;
		if (attr->ia_valid & ATTR_CTIME)
			inode->i_ctime = attr->ia_ctime;
		/* FIXME: clear I_DIRTY_SYNC? */
	}

	(*klpe_fuse_change_attributes_common)(inode, &outarg.attr,
				      attr_timeout(&outarg));
	oldsize = inode->i_size;
	/* see the comment in fuse_change_attributes() */
	if (!is_wb || is_truncate || !S_ISREG(inode->i_mode))
		i_size_write(inode, outarg.attr.size);

	if (is_truncate) {
		/* NOTE: this may release/reacquire fc->lock */
		klpr___fuse_release_nowrite(inode);
	}
	spin_unlock(&fc->lock);

	/*
	 * Only call invalidate_inode_pages2() after removing
	 * FUSE_NOWRITE, otherwise fuse_launder_page() would deadlock.
	 */
	if ((is_truncate || !is_wb) &&
	    S_ISREG(inode->i_mode) && oldsize != outarg.attr.size) {
		truncate_pagecache(inode, outarg.attr.size);
		invalidate_inode_pages2(inode->i_mapping);
	}

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return 0;

error:
	if (is_truncate)
		(*klpe_fuse_release_nowrite)(inode);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return err;
}

int klpp_fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct file *file = (attr->ia_valid & ATTR_FILE) ? attr->ia_file : NULL;
	int ret;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (!(*klpe_fuse_allow_current_process)(get_fuse_conn(inode)))
		return -EACCES;

	if (attr->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID)) {
		attr->ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID |
				    ATTR_MODE);

		/*
		 * The only sane way to reliably kill suid/sgid is to do it in
		 * the userspace filesystem
		 *
		 * This should be done on write(), truncate() and chown().
		 */
		if (!fc->handle_killpriv) {
			/*
			 * ia_mode calculation may have used stale i_mode.
			 * Refresh and recalculate.
			 */
			ret = klpp_fuse_do_getattr(inode, NULL, file);
			if (ret)
				return ret;

			attr->ia_mode = inode->i_mode;
			if (inode->i_mode & S_ISUID) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISUID;
			}
			if ((inode->i_mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISGID;
			}
		}
	}
	if (!attr->ia_valid)
		return 0;

	ret = klpp_fuse_do_setattr(entry, attr, file);
	if (!ret) {
		/*
		 * If filesystem supports acls it may have updated acl xattrs in
		 * the filesystem, so forget cached acls for the inode.
		 */
		if (fc->posix_acl)
			forget_all_cached_acls(inode);

		/* Directory mode changed, may need to revalidate access */
		if (d_is_dir(entry) && (attr->ia_valid & ATTR_MODE))
			(*klpe_fuse_invalidate_entry_cache)(entry);
	}
	return ret;
}

int klpp_fuse_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct fuse_conn *fc = get_fuse_conn(inode);

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (!(*klpe_fuse_allow_current_process)(fc))
		return -EACCES;

	return (*klpe_fuse_update_attributes)(inode, stat, NULL, NULL);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1184952.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "fuse"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_lookup_name", (void *)&klpe_fuse_lookup_name, "fuse" },
	{ "fuse_queue_forget", (void *)&klpe_fuse_queue_forget, "fuse" },
	{ "fuse_alloc_forget", (void *)&klpe_fuse_alloc_forget, "fuse" },
	{ "fuse_force_forget", (void *)&klpe_fuse_force_forget, "fuse" },
	{ "fuse_read_fill", (void *)&klpe_fuse_read_fill, "fuse" },
	{ "fuse_change_attributes", (void *)&klpe_fuse_change_attributes,
	  "fuse" },
	{ "fuse_change_attributes_common",
	  (void *)&klpe_fuse_change_attributes_common, "fuse" },
	{ "fuse_get_req", (void *)&klpe_fuse_get_req, "fuse" },
	{ "fuse_put_request", (void *)&klpe_fuse_put_request, "fuse" },
	{ "fuse_request_send", (void *)&klpe_fuse_request_send, "fuse" },
	{ "fuse_simple_request", (void *)&klpe_fuse_simple_request, "fuse" },
	{ "fuse_invalidate_attr", (void *)&klpe_fuse_invalidate_attr, "fuse" },
	{ "fuse_invalidate_entry_cache",
	  (void *)&klpe_fuse_invalidate_entry_cache, "fuse" },
	{ "fuse_invalidate_atime", (void *)&klpe_fuse_invalidate_atime,
	  "fuse" },
	{ "fuse_invalid_attr", (void *)&klpe_fuse_invalid_attr, "fuse" },
	{ "fuse_allow_current_process",
	  (void *)&klpe_fuse_allow_current_process, "fuse" },
	{ "fuse_lock_owner_id", (void *)&klpe_fuse_lock_owner_id, "fuse" },
	{ "fuse_update_ctime", (void *)&klpe_fuse_update_ctime, "fuse" },
	{ "fuse_update_attributes", (void *)&klpe_fuse_update_attributes,
	  "fuse" },
	{ "fuse_flush_writepages", (void *)&klpe_fuse_flush_writepages,
	  "fuse" },
	{ "fuse_set_nowrite", (void *)&klpe_fuse_set_nowrite, "fuse" },
	{ "fuse_release_nowrite", (void *)&klpe_fuse_release_nowrite, "fuse" },
	{ "fuse_get_attr_version", (void *)&klpe_fuse_get_attr_version,
	  "fuse" },
	{ "fuse_unlock_inode", (void *)&klpe_fuse_unlock_inode, "fuse" },
	{ "fuse_lock_inode", (void *)&klpe_fuse_lock_inode, "fuse" },
	{ "fuse_create_open", (void *)&klpe_fuse_create_open, "fuse" },
	{ "fuse_rename_common", (void *)&klpe_fuse_rename_common, "fuse" },
	{ "fuse_access", (void *)&klpe_fuse_access, "fuse" },
	{ "fuse_perm_getattr", (void *)&klpe_fuse_perm_getattr, "fuse" },
};

static int livepatch_bsc1184952_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1184952_module_nb = {
	.notifier_call = livepatch_bsc1184952_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1184952_fuse_dir_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1184952_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1184952_fuse_dir_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1184952_module_nb);
}
