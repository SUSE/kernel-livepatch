/*
 * bsc1247158_mm_secretmem
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

#if defined(CONFIG_SECRETMEM)

/* klp-ccp: from mm/secretmem.c */
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/swap.h>
#include <linux/mount.h>
#include <linux/memfd.h>
#include <linux/bitops.h>
#include <linux/printk.h>
#include <linux/pagemap.h>
#include <linux/secretmem.h>
#include <linux/sched/signal.h>
#include <uapi/linux/magic.h>
#include <asm/tlbflush.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

#include "livepatch_bsc1247158.h"

/* klp-ccp: from mm/secretmem.c */
#define SECRETMEM_MODE_MASK	(0x0)
#define SECRETMEM_FLAGS_MASK	SECRETMEM_MODE_MASK

extern bool secretmem_enable __ro_after_init;
extern atomic_t secretmem_users;
extern const struct file_operations secretmem_fops;
extern const struct address_space_operations secretmem_aops;
extern const struct inode_operations secretmem_iops;
extern struct vfsmount *secretmem_mnt;

static struct file *klpp_secretmem_file_create(unsigned long flags)
{
	struct file *file;
	struct inode *inode;
	const char *anon_name = "[secretmem]";

	inode = klpp_anon_inode_make_secure_inode(secretmem_mnt->mnt_sb, anon_name, NULL);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	file = alloc_file_pseudo(inode, secretmem_mnt, "secretmem",
				 O_RDWR, &secretmem_fops);
	if (IS_ERR(file))
		goto err_free_inode;

	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_unevictable(inode->i_mapping);

	inode->i_op = &secretmem_iops;
	inode->i_mapping->a_ops = &secretmem_aops;

	/* pretend we are a normal file with zero size */
	inode->i_mode |= S_IFREG;
	inode->i_size = 0;

	return file;

err_free_inode:
	iput(inode);
	return file;
}


#include <linux/syscalls.h>

__SYSCALL_DEFINEx(1, _klpp_memfd_secret, unsigned int, flags)
{
	struct file *file;
	int fd, err;

	/* make sure local flags do not confict with global fcntl.h */
	BUILD_BUG_ON(SECRETMEM_FLAGS_MASK & O_CLOEXEC);

	if (!secretmem_enable)
		return -ENOSYS;

	if (flags & ~(SECRETMEM_FLAGS_MASK | O_CLOEXEC))
		return -EINVAL;
	if (atomic_read(&secretmem_users) < 0)
		return -ENFILE;

	fd = get_unused_fd_flags(flags & O_CLOEXEC);
	if (fd < 0)
		return fd;

	file = klpp_secretmem_file_create(flags);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_put_fd;
	}

	file->f_flags |= O_LARGEFILE;

	atomic_inc(&secretmem_users);
	fd_install(fd, file);
	return fd;

err_put_fd:
	put_unused_fd(fd);
	return err;
}



#include <linux/livepatch.h>

extern typeof(secretmem_aops) secretmem_aops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, secretmem_aops);
extern typeof(secretmem_enable) secretmem_enable
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, secretmem_enable);
extern typeof(secretmem_fops) secretmem_fops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, secretmem_fops);
extern typeof(secretmem_iops) secretmem_iops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, secretmem_iops);
extern typeof(secretmem_mnt) secretmem_mnt
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, secretmem_mnt);
extern typeof(secretmem_users) secretmem_users
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, secretmem_users);

#endif /* CONFIG_SECRETMEM */
