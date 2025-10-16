/*
 * bsc1247158_fs_anon_inodes
 *
 * Fix for CVE-2025-38396, bsc#1247158
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from fs/anon_inodes.c */
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/pseudo_fs.h>
#include <linux/uaccess.h>

extern struct vfsmount *anon_inode_mnt __read_mostly;
extern struct inode *anon_inode_inode;

struct inode *klpp_anon_inode_make_secure_inode(struct super_block *sb, const char *name,
					   const struct inode *context_inode)
{
	struct inode *inode;
	const struct qstr qname = QSTR_INIT(name, strlen(name));
	int error;

	inode = alloc_anon_inode(sb);
	if (IS_ERR(inode))
		return inode;
	inode->i_flags &= ~S_PRIVATE;
	error =	security_inode_init_security_anon(inode, &qname, context_inode);
	if (error) {
		iput(inode);
		return ERR_PTR(error);
	}
	return inode;
}

struct file *klpp___anon_inode_getfile(const char *name,
					 const struct file_operations *fops,
					 void *priv, int flags,
					 const struct inode *context_inode,
					 bool make_inode)
{
	struct inode *inode;
	struct file *file;

	if (fops->owner && !try_module_get(fops->owner))
		return ERR_PTR(-ENOENT);

	if (make_inode) {
		inode =	klpp_anon_inode_make_secure_inode(anon_inode_mnt->mnt_sb,
						     name, context_inode);
		if (IS_ERR(inode)) {
			file = ERR_CAST(inode);
			goto err;
		}
	} else {
		inode =	anon_inode_inode;
		if (IS_ERR(inode)) {
			file = ERR_PTR(-ENODEV);
			goto err;
		}
		/*
		 * We know the anon_inode inode count is always
		 * greater than zero, so ihold() is safe.
		 */
		ihold(inode);
	}

	file = alloc_file_pseudo(inode, anon_inode_mnt, name,
				 flags & (O_ACCMODE | O_NONBLOCK), fops);
	if (IS_ERR(file))
		goto err_iput;

	file->f_mapping = inode->i_mapping;

	file->private_data = priv;

	return file;

err_iput:
	iput(inode);
err:
	module_put(fops->owner);
	return file;
}


#include "livepatch_bsc1247158.h"

#include <linux/livepatch.h>

extern typeof(anon_inode_inode) anon_inode_inode
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, anon_inode_inode);
extern typeof(anon_inode_mnt) anon_inode_mnt
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, anon_inode_mnt);
extern typeof(security_inode_init_security_anon)
	 security_inode_init_security_anon
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_inode_init_security_anon);
