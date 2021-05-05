/*
 * livepatch_bsc1183452
 *
 * Fix for bsc#1183452
 *
 *  Upstream commit:
 *  82382acec0c9 ("kernfs: deal with kernfs_fill_super() failures")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  none
 *
 *  SLE12-SP4 commit:
 *  none
 *
 *  SLE12-SP5 commit:
 *  d6f9eec330265c2e066e500a2977e151b49ad6d4
 *
 *  SLE15 commit:
 *  none
 *
 *  SLE15-SP1 commit:
 *  2955da86d8c1db026be00d02c78b987aa6dd1137
 *
 *  SLE15-SP2 commit:
 *  not affected
 *
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

/* klp-ccp: from fs/kernfs/mount.c */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/pagemap.h>

/* klp-ccp: from include/linux/kernfs.h */
static struct inode *(*klpe_kernfs_get_inode)(struct super_block *sb, struct kernfs_node *kn);

struct dentry *klpp_kernfs_mount_ns(struct file_system_type *fs_type, int flags,
			       struct kernfs_root *root, unsigned long magic,
			       bool *new_sb_created, const void *ns);

/* klp-ccp: from fs/kernfs/mount.c */
#include <linux/seq_file.h>
#include <linux/exportfs.h>
/* klp-ccp: from fs/kernfs/kernfs-internal.h */
#include <linux/lockdep.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/kernfs.h>

struct kernfs_super_info {
	struct super_block	*sb;

	/*
	 * The root associated with this super_block.  Each super_block is
	 * identified by the root and ns it's associated with.
	 */
	struct kernfs_root	*root;

	/*
	 * Each sb is associated with one namespace tag, currently the
	 * network namespace of the task which mounted this kernfs
	 * instance.  If multiple tags become necessary, make the following
	 * an array and compare kernfs_node tag against every entry.
	 */
	const void		*ns;

	/* anchored at kernfs_root->supers, protected by kernfs_mutex */
	struct list_head	node;
};
#define kernfs_info(SB) ((struct kernfs_super_info *)(SB->s_fs_info))

static const struct super_operations (*klpe_kernfs_sops);

static const struct xattr_handler *(*klpe_kernfs_xattr_handlers)[];

static struct mutex (*klpe_kernfs_mutex);
static const struct dentry_operations (*klpe_kernfs_dops);

/* klp-ccp: from fs/kernfs/mount.c */
static const struct export_operations (*klpe_kernfs_export_ops);

static int klpr_kernfs_fill_super(struct super_block *sb, unsigned long magic)
{
	struct kernfs_super_info *info = kernfs_info(sb);
	struct inode *inode;
	struct dentry *root;

	info->sb = sb;
	/* Userspace would break if executables or devices appear on sysfs */
	sb->s_iflags |= SB_I_NOEXEC | SB_I_NODEV;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = magic;
	sb->s_op = &(*klpe_kernfs_sops);
	sb->s_xattr = (*klpe_kernfs_xattr_handlers);
	if (info->root->flags & KERNFS_ROOT_SUPPORT_EXPORTOP)
		sb->s_export_op = &(*klpe_kernfs_export_ops);
	sb->s_time_gran = 1;

	/* get root inode, initialize and unlock it */
	mutex_lock(&(*klpe_kernfs_mutex));
	inode = (*klpe_kernfs_get_inode)(sb, info->root->kn);
	mutex_unlock(&(*klpe_kernfs_mutex));
	if (!inode) {
		pr_debug("kernfs: could not get root inode\n");
		return -ENOMEM;
	}

	/* instantiate and link root dentry */
	root = d_make_root(inode);
	if (!root) {
		pr_debug("%s: could not get root dentry!\n", __func__);
		return -ENOMEM;
	}
	sb->s_root = root;
	sb->s_d_op = &(*klpe_kernfs_dops);
	return 0;
}

static int (*klpe_kernfs_test_super)(struct super_block *sb, void *data);

static int (*klpe_kernfs_set_super)(struct super_block *sb, void *data);

struct dentry *klpp_kernfs_mount_ns(struct file_system_type *fs_type, int flags,
				struct kernfs_root *root, unsigned long magic,
				bool *new_sb_created, const void *ns)
{
	struct super_block *sb;
	struct kernfs_super_info *info;
	int error;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->root = root;
	info->ns = ns;
	/*
	 * Fix bsc#1183452
	 *  +1 line
	 */
	INIT_LIST_HEAD(&info->node);

	sb = sget_userns(fs_type, (*klpe_kernfs_test_super), (*klpe_kernfs_set_super), flags,
			 &init_user_ns, info);
	if (IS_ERR(sb) || sb->s_fs_info != info)
		kfree(info);
	if (IS_ERR(sb))
		return ERR_CAST(sb);

	if (new_sb_created)
		*new_sb_created = !sb->s_root;

	if (!sb->s_root) {
		struct kernfs_super_info *info = kernfs_info(sb);

		error = klpr_kernfs_fill_super(sb, magic);
		if (error) {
			deactivate_locked_super(sb);
			return ERR_PTR(error);
		}
		sb->s_flags |= MS_ACTIVE;

		mutex_lock(&(*klpe_kernfs_mutex));
		list_add(&info->node, &root->supers);
		mutex_unlock(&(*klpe_kernfs_mutex));
	}

	return dget(sb->s_root);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1183452.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "kernfs_mutex", (void *)&klpe_kernfs_mutex },
	{ "kernfs_dops", (void *)&klpe_kernfs_dops },
	{ "kernfs_export_ops", (void *)&klpe_kernfs_export_ops },
	{ "kernfs_sops", (void *)&klpe_kernfs_sops },
	{ "kernfs_xattr_handlers", (void *)&klpe_kernfs_xattr_handlers },
	{ "kernfs_get_inode", (void *)&klpe_kernfs_get_inode },
	{ "kernfs_test_super", (void *)&klpe_kernfs_test_super },
	{ "kernfs_set_super", (void *)&klpe_kernfs_set_super },
};

int livepatch_bsc1183452_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
