/*
 * bsc1216644_fs_read_write
 *
 * Fix for CVE-2023-5717, bsc#1216644
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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


/* klp-ccp: from fs/read_write.c */
#include <linux/stat.h>
#include <linux/sched/xacct.h>
#include <linux/fsnotify.h>

/* klp-ccp: from include/linux/fsnotify_backend.h */
#ifdef __KERNEL__

/* klp-ccp: from include/linux/fs.h */
ssize_t klpp_vfs_read(struct file *, char __user *, size_t, loff_t *);

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from include/linux/fsnotify_backend.h */
#endif	/* __KERNEL __ */

/* klp-ccp: from fs/read_write.c */
#include <linux/export.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

int (*klpe_rw_verify_area)(int read_write, struct file *file, const loff_t *ppos, size_t count);

static ssize_t (*klpe_new_sync_read)(struct file *filp, char __user *buf, size_t len, loff_t *ppos);

#include "livepatch_bsc1216644.h"

ssize_t klpp_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = (*klpe_rw_verify_area)(READ, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;

	if (file->f_op->read) {
		if (file->f_op->read == klpe_perf_fops->read)
			return klpp_perf_read(file, buf, count, pos);
		ret = file->f_op->read(file, buf, count, pos);
	}
	else if (file->f_op->read_iter)
		ret = (*klpe_new_sync_read)(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_access(file);
		add_rchar(current, ret);
	}
	inc_syscr(current);
	return ret;
}

static ssize_t (*klpe_do_iter_readv_writev)(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, int type, rwf_t flags);

static ssize_t klpp_do_loop_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, int type, rwf_t flags)
{
	ssize_t ret = 0;

	if (flags & ~RWF_HIPRI)
		return -EOPNOTSUPP;

	while (iov_iter_count(iter)) {
		struct iovec iovec = iov_iter_iovec(iter);
		ssize_t nr;

		if (type == READ) {
			if (filp->f_op->read == klpe_perf_fops->read)
				nr = klpp_perf_read(filp, iovec.iov_base,
							  iovec.iov_len, ppos);
			else
				nr = filp->f_op->read(filp, iovec.iov_base,
							  iovec.iov_len, ppos);
		} else {
			nr = filp->f_op->write(filp, iovec.iov_base,
					       iovec.iov_len, ppos);
		}

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (nr != iovec.iov_len)
			break;
		iov_iter_advance(iter, nr);
	}

	return ret;
}

ssize_t klpp_do_iter_read(struct file *file, struct iov_iter *iter,
		loff_t *pos, int __bitwise flags)
{
	size_t tot_len;
	ssize_t ret = 0;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;

	tot_len = iov_iter_count(iter);
	if (!tot_len)
		goto out;
	ret = (*klpe_rw_verify_area)(READ, file, pos, tot_len);
	if (ret < 0)
		return ret;

	if (file->f_op->read_iter)
		ret = (*klpe_do_iter_readv_writev)(file, iter, pos, READ, flags);
	else
		ret = klpp_do_loop_readv_writev(file, iter, pos, READ, flags);
out:
	if (ret >= 0)
		fsnotify_access(file);
	return ret;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "do_iter_readv_writev", (void *)&klpe_do_iter_readv_writev },
	{ "new_sync_read", (void *)&klpe_new_sync_read },
	{ "rw_verify_area", (void *)&klpe_rw_verify_area },
};

int bsc1216644_fs_read_write_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

