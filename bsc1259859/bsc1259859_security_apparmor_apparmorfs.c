/*
 * bsc1259859_security_apparmor_apparmorfs
 *
 * Fix for CVE-2026-23268, bsc#1259859
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


#include "livepatch_bsc1259859.h"


/* klp-ccp: from security/apparmor/apparmorfs.c */
#include <linux/ctype.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/capability.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/poll.h>
#include <linux/zstd.h>
#include <uapi/linux/major.h>
#include <uapi/linux/magic.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_DBUS		32

#define AA_CLASS_LAST		AA_CLASS_DBUS

/* klp-ccp: from security/apparmor/include/apparmorfs.h */
enum aafs_ns_type {
	AAFS_NS_DIR,
	AAFS_NS_PROFS,
	AAFS_NS_NS,
	AAFS_NS_RAW_DATA,
	AAFS_NS_LOAD,
	AAFS_NS_REPLACE,
	AAFS_NS_REMOVE,
	AAFS_NS_REVISION,
	AAFS_NS_COUNT,
	AAFS_NS_MAX_COUNT,
	AAFS_NS_SIZE,
	AAFS_NS_MAX_SIZE,
	AAFS_NS_OWNER,
	AAFS_NS_SIZEOF,
};

enum aafs_prof_type {
	AAFS_PROF_DIR,
	AAFS_PROF_PROFS,
	AAFS_PROF_NAME,
	AAFS_PROF_MODE,
	AAFS_PROF_ATTACH,
	AAFS_PROF_HASH,
	AAFS_PROF_RAW_DATA,
	AAFS_PROF_RAW_HASH,
	AAFS_PROF_RAW_ABI,
	AAFS_PROF_SIZEOF,
};

#define ns_dir(X) ((X)->dents[AAFS_NS_DIR])
#define ns_subns_dir(X) ((X)->dents[AAFS_NS_NS])

/* klp-ccp: from security/apparmor/include/audit.h */
#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/lsm_audit.h>
#include <linux/sched.h>
#include <linux/slab.h>
/* klp-ccp: from security/apparmor/include/file.h */
#include <linux/spinlock.h>
/* klp-ccp: from security/apparmor/include/domain.h */
#include <linux/binfmts.h>
#include <linux/types.h>
/* klp-ccp: from security/apparmor/include/label.h */
#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
/* klp-ccp: from security/apparmor/include/lib.h */
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
/* klp-ccp: from security/apparmor/include/match.h */
#include <linux/kref.h>

#define aa_state_t unsigned int

/* klp-ccp: from security/apparmor/include/lib.h */
#define AA_BUG(X, args...)						    \
	do {								    \
		_Pragma("GCC diagnostic ignored \"-Wformat-zero-length\""); \
		AA_BUG_FMT((X), "" args);				    \
		_Pragma("GCC diagnostic warning \"-Wformat-zero-length\""); \
	} while (0)

#define AA_BUG_FMT(X, fmt, args...) no_printk(fmt, ##args)

extern struct lsm_blob_sizes apparmor_blob_sizes;

static inline bool aa_strneq(const char *str, const char *sub, int len)
{
	return !strncmp(str, sub, len) && !str[len];
}

struct aa_str_table {
	int size;
	char **table;
};

#define __counted	/* atm just a notation */

struct aa_policy {
	const char *name;
	__counted char *hname;
	struct list_head list;
	struct list_head profiles;
};

static inline struct aa_policy *__policy_strn_find(struct list_head *head,
					    const char *str, int len)
{
	struct aa_policy *policy;

	list_for_each_entry_rcu(policy, head, list) {
		if (aa_strneq(policy->name, str, len))
			return policy;
	}

	return NULL;
}

/* klp-ccp: from security/apparmor/include/label.h */
struct aa_labelset {
	rwlock_t lock;

	struct rb_root root;
};

enum label_flags {
	FLAG_HAT = 1,			/* profile is a hat */
	FLAG_UNCONFINED = 2,		/* label unconfined only if all */
	FLAG_NULL = 4,			/* profile is null learning profile */
	FLAG_IX_ON_NAME_ERROR = 8,	/* fallback to ix on name lookup fail */
	FLAG_IMMUTIBLE = 0x10,		/* don't allow changes/replacement */
	FLAG_USER_DEFINED = 0x20,	/* user based profile - lower privs */
	FLAG_NO_LIST_REF = 0x40,	/* list doesn't keep profile ref */
	FLAG_NS_COUNT = 0x80,		/* carries NS ref count */
	FLAG_IN_TREE = 0x100,		/* label is in tree */
	FLAG_PROFILE = 0x200,		/* label is a profile */
	FLAG_EXPLICIT = 0x400,		/* explicit static label */
	FLAG_STALE = 0x800,		/* replaced/removed */
	FLAG_RENAMED = 0x1000,		/* label has renaming in it */
	FLAG_REVOKED = 0x2000,		/* label has revocation in it */
	FLAG_DEBUG1 = 0x4000,
	FLAG_DEBUG2 = 0x8000,

	/* These flags must correspond with PATH_flags */
	/* TODO: add new path flags */
};

struct aa_proxy {
	struct kref count;
	struct aa_label __rcu *label;
};

struct aa_label {
	struct kref count;
	struct rb_node node;
	struct rcu_head rcu;
	struct aa_proxy *proxy;
	__counted char *hname;
	long flags;
	u32 secid;
	int size;
	struct aa_profile *vec[];
};

#define label_is_stale(X) ((X)->flags & FLAG_STALE)

void aa_label_kref(struct kref *kref);

static inline struct aa_label *aa_get_label(struct aa_label *l)
{
	if (l)
		kref_get(&(l->count));

	return l;
}

static inline struct aa_label *aa_get_label_rcu(struct aa_label __rcu **l)
{
	struct aa_label *c;

	rcu_read_lock();
	do {
		c = rcu_dereference(*l);
	} while (c && !kref_get_unless_zero(&c->count));
	rcu_read_unlock();

	return c;
}

static inline struct aa_label *aa_get_newest_label(struct aa_label *l)
{
	if (!l)
		return NULL;

	if (label_is_stale(l)) {
		struct aa_label *tmp;

		AA_BUG(!l->proxy);
		AA_BUG(!l->proxy->label);
		/* BUG: only way this can happen is @l ref count and its
		 * replacement count have gone to 0 and are on their way
		 * to destruction. ie. we have a refcounting error
		 */
		tmp = aa_get_label_rcu(&l->proxy->label);
		AA_BUG(!tmp);

		return tmp;
	}

	return aa_get_label(l);
}

static inline void aa_put_label(struct aa_label *l)
{
	if (l)
		kref_put(&l->count, aa_label_kref);
}

/* klp-ccp: from security/apparmor/include/perms.h */
#include <linux/fs.h>

#define AA_MAY_WRITE		MAY_WRITE

#define AA_MAY_APPEND		MAY_APPEND

#define AA_MAY_DELETE		0x0020

/* klp-ccp: from security/apparmor/include/audit.h */
enum audit_mode {
	AUDIT_NORMAL,		/* follow normal auditing of accesses */
	AUDIT_QUIET_DENIED,	/* quiet all denied access messages */
	AUDIT_QUIET,		/* quiet all messages */
	AUDIT_NOQUIET,		/* do not quiet audit messages */
	AUDIT_ALL		/* audit all accesses */
};

/* klp-ccp: from security/apparmor/include/cred.h */
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/policy_ns.h */
#include <linux/kref.h>
/* klp-ccp: from security/apparmor/include/policy.h */
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kref.h>
#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>
/* klp-ccp: from security/apparmor/include/capability.h */
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/domain.h */
#include <linux/binfmts.h>
#include <linux/types.h>
/* klp-ccp: from security/apparmor/include/net.h */
#include <net/sock.h>
#include <linux/path.h>
/* klp-ccp: from security/apparmor/include/resource.h */
#include <linux/resource.h>
#include <linux/sched.h>

/* klp-ccp: from security/apparmor/include/policy.h */
struct aa_policydb {
	struct aa_dfa *dfa;
	struct {
		struct aa_perms *perms;
		u32 size;
	};
	struct aa_str_table trans;
	aa_state_t start[AA_CLASS_LAST + 1];
};

struct aa_attachment {
	const char *xmatch_str;
	struct aa_policydb xmatch;
	unsigned int xmatch_len;
	int xattr_count;
	char **xattrs;
};

struct aa_profile {
	struct aa_policy base;
	struct aa_profile __rcu *parent;

	struct aa_ns *ns;
	const char *rename;

	enum audit_mode audit;
	long mode;
	u32 path_flags;
	const char *disconnected;

	struct aa_attachment attach;
	struct list_head rules;

	struct aa_loaddata *rawdata;
	unsigned char *hash;
	char *dirname;
	struct dentry *dents[AAFS_PROF_SIZEOF];
	struct rhashtable *data;
	struct aa_label label;
};

#define AA_MAY_LOAD_POLICY	AA_MAY_APPEND
#define AA_MAY_REPLACE_POLICY	AA_MAY_WRITE
#define AA_MAY_REMOVE_POLICY	AA_MAY_DELETE

ssize_t aa_replace_profiles(struct aa_ns *view, struct aa_label *label,
			    u32 mask, struct aa_loaddata *udata);
ssize_t aa_remove_profiles(struct aa_ns *view, struct aa_label *label,
			   char *name, size_t size);

static inline struct aa_profile *aa_get_profile(struct aa_profile *p)
{
	if (p)
		kref_get(&(p->label.count));

	return p;
}

static inline void aa_put_profile(struct aa_profile *p)
{
	if (p)
		kref_put(&p->label.count, aa_label_kref);
}

int klpp_aa_may_manage_policy(struct aa_label *label, struct aa_ns *ns,
			 const struct cred *ocred, u32 mask);

/* klp-ccp: from security/apparmor/include/policy_ns.h */
struct aa_ns_acct {
	int max_size;
	int max_count;
	int size;
	int count;
};

struct aa_ns {
	struct aa_policy base;
	struct aa_ns *parent;
	struct mutex lock;
	struct aa_ns_acct acct;
	struct aa_profile *unconfined;
	struct list_head sub_ns;
	atomic_t uniq_null;
	long uniq_id;
	int level;
	long revision;
	wait_queue_head_t wait;

	struct aa_labelset labels;
	struct list_head rawdata_list;

	struct dentry *dents[AAFS_NS_SIZEOF];
};

struct aa_ns *__aa_find_or_create_ns(struct aa_ns *parent, const char *name,
				     struct dentry *dir);

void __aa_remove_ns(struct aa_ns *ns);

static inline struct aa_ns *aa_get_ns(struct aa_ns *ns)
{
	if (ns)
		aa_get_profile(ns->unconfined);

	return ns;
}

static inline void aa_put_ns(struct aa_ns *ns)
{
	if (ns)
		aa_put_profile(ns->unconfined);
}

static inline struct aa_ns *__aa_findn_ns(struct list_head *head,
					  const char *name, size_t n)
{
	return (struct aa_ns *)__policy_strn_find(head, name, n);
}

/* klp-ccp: from security/apparmor/include/task.h */
int aa_replace_current_label(struct aa_label *label);

/* klp-ccp: from security/apparmor/include/cred.h */
static inline struct aa_label *cred_label(const struct cred *cred)
{
	struct aa_label **blob = cred->security + apparmor_blob_sizes.lbs_cred;

	AA_BUG(!blob);
	return *blob;
}

static inline struct aa_label *aa_cred_raw_label(const struct cred *cred)
{
	struct aa_label *label = cred_label(cred);

	AA_BUG(!label);
	return label;
}

static inline struct aa_label *aa_current_raw_label(void)
{
	return aa_cred_raw_label(current_cred());
}

static inline void end_current_label_crit_section(struct aa_label *label)
{
	if (label != aa_current_raw_label())
		aa_put_label(label);
}

static inline struct aa_label *begin_current_label_crit_section(void)
{
	struct aa_label *label = aa_current_raw_label();

	might_sleep();

	if (label_is_stale(label)) {
		label = aa_get_newest_label(label);
		if (aa_replace_current_label(label) == 0)
			/* task cred will keep the reference */
			aa_put_label(label);
	}

	return label;
}

/* klp-ccp: from security/apparmor/include/ipc.h */
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/policy_unpack.h */
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/dcache.h>
#include <linux/workqueue.h>

enum {
	AAFS_LOADDATA_ABI = 0,
	AAFS_LOADDATA_REVISION,
	AAFS_LOADDATA_HASH,
	AAFS_LOADDATA_DATA,
	AAFS_LOADDATA_COMPRESSED_SIZE,
	AAFS_LOADDATA_DIR,		/* must be last actual entry */
	AAFS_LOADDATA_NDENTS		/* count of entries */
};

struct aa_loaddata {
	struct kref count;
	struct list_head list;
	struct work_struct work;
	struct dentry *dents[AAFS_LOADDATA_NDENTS];
	struct aa_ns *ns;
	char *name;
	size_t size;			/* the original size of the payload */
	size_t compressed_size;		/* the compressed size of the payload */
	long revision;			/* the ns policy revision this caused */
	int abi;
	unsigned char *hash;

	/* Pointer to payload. If @compressed_size > 0, then this is the
	 * compressed version of the payload, else it is the uncompressed
	 * version (with the size indicated by @size).
	 */
	char *data;
};

void aa_loaddata_kref(struct kref *kref);
struct aa_loaddata *aa_loaddata_alloc(size_t size);
static inline void aa_put_loaddata(struct aa_loaddata *data)
{
	if (data)
		kref_put(&data->count, aa_loaddata_kref);
}

/* klp-ccp: from security/apparmor/apparmorfs.c */
extern struct vfsmount *aafs_mnt;
extern int aafs_count;

extern struct file_system_type aafs_ops;

static int __aafs_setup_d_inode(struct inode *dir, struct dentry *dentry,
			       umode_t mode, void *data, char *link,
			       const struct file_operations *fops,
			       const struct inode_operations *iops)
{
	struct inode *inode = new_inode(dir->i_sb);

	AA_BUG(!dir);
	AA_BUG(!dentry);

	if (!inode)
		return -ENOMEM;

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_private = data;
	if (S_ISDIR(mode)) {
		inode->i_op = iops ? iops : &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
		inc_nlink(dir);
	} else if (S_ISLNK(mode)) {
		inode->i_op = iops ? iops : &simple_symlink_inode_operations;
		inode->i_link = link;
	} else {
		inode->i_fop = fops;
	}
	d_instantiate(dentry, inode);
	dget(dentry);

	return 0;
}

static struct aa_loaddata *aa_simple_write_to_buffer(const char __user *userbuf,
						     size_t alloc_size,
						     size_t copy_size,
						     loff_t *pos)
{
	struct aa_loaddata *data;

	AA_BUG(copy_size > alloc_size);

	if (*pos != 0)
		/* only writes from pos 0, that is complete writes */
		return ERR_PTR(-ESPIPE);

	/* freed by caller to simple_write_to_buffer */
	data = aa_loaddata_alloc(alloc_size);
	if (IS_ERR(data))
		return data;

	data->size = copy_size;
	if (copy_from_user(data->data, userbuf, copy_size)) {
		aa_put_loaddata(data);
		return ERR_PTR(-EFAULT);
	}

	return data;
}

static ssize_t klpp_policy_update(u32 mask, const char __user *buf, size_t size,
			     loff_t *pos, struct aa_ns *ns,
			     const struct cred *ocred)
{
	struct aa_loaddata *data;
	struct aa_label *label;
	ssize_t error;

	label = begin_current_label_crit_section();

	/* high level check about policy management - fine grained in
	 * below after unpack
	 */
	error = klpp_aa_may_manage_policy(label, ns, ocred, mask);
	if (error)
		goto end_section;

	data = aa_simple_write_to_buffer(buf, size, size, pos);
	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		error = aa_replace_profiles(ns, label, mask, data);
		aa_put_loaddata(data);
	}
end_section:
	end_current_label_crit_section(label);

	return error;
}

ssize_t klpp_profile_load(struct file *f, const char __user *buf, size_t size,
			    loff_t *pos)
{
	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);
	int error = klpp_policy_update(AA_MAY_LOAD_POLICY, buf, size, pos, ns,
				  f->f_cred);

	aa_put_ns(ns);

	return error;
}

ssize_t klpp_profile_replace(struct file *f, const char __user *buf,
			       size_t size, loff_t *pos)
{
	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);
	int error = klpp_policy_update(AA_MAY_LOAD_POLICY | AA_MAY_REPLACE_POLICY,
				  buf, size, pos, ns, f->f_cred);
	aa_put_ns(ns);

	return error;
}

ssize_t klpp_profile_remove(struct file *f, const char __user *buf,
			      size_t size, loff_t *pos)
{
	struct aa_loaddata *data;
	struct aa_label *label;
	ssize_t error;
	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);

	label = begin_current_label_crit_section();
	/* high level check about policy management - fine grained in
	 * below after unpack
	 */
	error = klpp_aa_may_manage_policy(label, ns, f->f_cred,
				     AA_MAY_REMOVE_POLICY);
	if (error)
		goto out;

	/*
	 * aa_remove_profile needs a null terminated string so 1 extra
	 * byte is allocated and the copied data is null terminated.
	 */
	data = aa_simple_write_to_buffer(buf, size + 1, size, pos);

	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		data->data[size] = 0;
		error = aa_remove_profiles(ns, label, data->data, size);
		aa_put_loaddata(data);
	}
 out:
	end_current_label_crit_section(label);
	aa_put_ns(ns);
	return error;
}

int klpp_ns_mkdir_op(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	struct aa_ns *ns, *parent;
	/* TODO: improve permission check */
	struct aa_label *label;
	int error;

	label = begin_current_label_crit_section();
	error = klpp_aa_may_manage_policy(label, NULL, NULL, AA_MAY_LOAD_POLICY);
	end_current_label_crit_section(label);
	if (error)
		return error;

	parent = aa_get_ns(dir->i_private);
	AA_BUG(d_inode(ns_subns_dir(parent)) != dir);

	/* we have to unlock and then relock to get locking order right
	 * for pin_fs
	 */
	inode_unlock(dir);
	error = simple_pin_fs(&aafs_ops, &aafs_mnt, &aafs_count);
	mutex_lock_nested(&parent->lock, parent->level);
	inode_lock_nested(dir, I_MUTEX_PARENT);
	if (error)
		goto out;

	error = __aafs_setup_d_inode(dir, dentry, mode | S_IFDIR,  NULL,
				     NULL, NULL, NULL);
	if (error)
		goto out_pin;

	ns = __aa_find_or_create_ns(parent, READ_ONCE(dentry->d_name.name),
				    dentry);
	if (IS_ERR(ns)) {
		error = PTR_ERR(ns);
		ns = NULL;
	}

	aa_put_ns(ns);		/* list ref remains */
out_pin:
	if (error)
		simple_release_fs(&aafs_mnt, &aafs_count);
out:
	mutex_unlock(&parent->lock);
	aa_put_ns(parent);

	return error;
}

int klpp_ns_rmdir_op(struct inode *dir, struct dentry *dentry)
{
	struct aa_ns *ns, *parent;
	/* TODO: improve permission check */
	struct aa_label *label;
	int error;

	label = begin_current_label_crit_section();
	error = klpp_aa_may_manage_policy(label, NULL, NULL, AA_MAY_LOAD_POLICY);
	end_current_label_crit_section(label);
	if (error)
		return error;

	parent = aa_get_ns(dir->i_private);
	/* rmdir calls the generic securityfs functions to remove files
	 * from the apparmor dir. It is up to the apparmor ns locking
	 * to avoid races.
	 */
	inode_unlock(dir);
	inode_unlock(dentry->d_inode);

	mutex_lock_nested(&parent->lock, parent->level);
	ns = aa_get_ns(__aa_findn_ns(&parent->sub_ns, dentry->d_name.name,
				     dentry->d_name.len));
	if (!ns) {
		error = -ENOENT;
		goto out;
	}
	AA_BUG(ns_dir(ns) != dentry);

	__aa_remove_ns(ns);
	aa_put_ns(ns);

out:
	mutex_unlock(&parent->lock);
	inode_lock_nested(dir, I_MUTEX_PARENT);
	inode_lock(dentry->d_inode);
	aa_put_ns(parent);

	return error;
}


#include <linux/livepatch.h>

extern typeof(__aa_find_or_create_ns) __aa_find_or_create_ns
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aa_find_or_create_ns);
extern typeof(__aa_remove_ns) __aa_remove_ns
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aa_remove_ns);
extern typeof(aa_label_kref) aa_label_kref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_label_kref);
extern typeof(aa_loaddata_alloc) aa_loaddata_alloc
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_loaddata_alloc);
extern typeof(aa_loaddata_kref) aa_loaddata_kref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_loaddata_kref);
extern typeof(aa_remove_profiles) aa_remove_profiles
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_remove_profiles);
extern typeof(aa_replace_current_label) aa_replace_current_label
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_replace_current_label);
extern typeof(aa_replace_profiles) aa_replace_profiles
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_replace_profiles);
extern typeof(aafs_count) aafs_count
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aafs_count);
extern typeof(aafs_mnt) aafs_mnt KLP_RELOC_SYMBOL(vmlinux, vmlinux, aafs_mnt);
extern typeof(aafs_ops) aafs_ops KLP_RELOC_SYMBOL(vmlinux, vmlinux, aafs_ops);
extern typeof(apparmor_blob_sizes) apparmor_blob_sizes
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, apparmor_blob_sizes);
