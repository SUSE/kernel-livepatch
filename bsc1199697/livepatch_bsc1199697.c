/*
 * livepatch_bsc1199697
 *
 * Fix for CVE-2022-1729, bsc#1199697
 *
 *  Upstream commit:
 *  3ac6487e584a ("perf: Fix sys_perf_event_open() race against self")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  fc77f1c1260a902bfa20e59a5da0d117fd854371
 *
 *  SLE15-SP2 and -SP3 commit:
 *  feaf8f1191abcbfe64612b24d277895b9eca211d
 *
 *  SLE15-SP4 commit:
 *  25fb71630781f0084b21a40f5413f3ae16460285
 *
 *
 *  Copyright (c) 2022 SUSE
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


/* klp-ccp: from kernel/events/core.c */
#include <linux/perf_event.h>
static const struct file_operations (*klpe_perf_fops);

/* New. */
static bool klpp_perf_is_move_group_event(struct perf_event *event)
{
	struct perf_event * const group_leader = event->group_leader;

	/* Should always be set, but play safe. */
	if (!group_leader)
		return false;

	return (!is_software_event(event) &&
		is_software_event(group_leader) &&
		(group_leader->group_caps & PERF_EV_CAP_SOFTWARE));
}

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

/* klp-ccp: from include/linux/anon_inodes.h */
struct file *klpp_anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv, int flags);

/* klp-ccp: from fs/anon_inodes.c */
#include <linux/uaccess.h>

static struct vfsmount *(*klpe_anon_inode_mnt);
static struct inode *(*klpe_anon_inode_inode);

struct file *klpp_anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv, int flags)
{
	struct qstr this;
	struct path path;
	struct file *file;

	if (IS_ERR((*klpe_anon_inode_inode)))
		return ERR_PTR(-ENODEV);

	/*
	 * Fix CVE-2022-1729
	 *  +5 lines
	 */
	if (fops == &(*klpe_perf_fops) && !capable(CAP_SYS_ADMIN) &&
	    klpp_perf_is_move_group_event((struct perf_event *)priv)) {
		pr_warn_ratelimited("livepatch: CVE-2022-1729: rejecting unsafe perf_event_open(2) usage pattern");
		return ERR_PTR(-EPERM);
	}

	if (fops->owner && !try_module_get(fops->owner))
		return ERR_PTR(-ENOENT);

	/*
	 * Link the inode to a directory entry by creating a unique name
	 * using the inode sequence number.
	 */
	file = ERR_PTR(-ENOMEM);
	this.name = name;
	this.len = strlen(name);
	this.hash = 0;
	path.dentry = d_alloc_pseudo((*klpe_anon_inode_mnt)->mnt_sb, &this);
	if (!path.dentry)
		goto err_module;

	path.mnt = mntget((*klpe_anon_inode_mnt));
	/*
	 * We know the anon_inode inode count is always greater than zero,
	 * so ihold() is safe.
	 */
	ihold((*klpe_anon_inode_inode));

	d_instantiate(path.dentry, (*klpe_anon_inode_inode));

	file = alloc_file(&path, OPEN_FMODE(flags), fops);
	if (IS_ERR(file))
		goto err_dput;
	file->f_mapping = (*klpe_anon_inode_inode)->i_mapping;

	file->f_flags = flags & (O_ACCMODE | O_NONBLOCK);
	file->private_data = priv;

	return file;

err_dput:
	path_put(&path);
err_module:
	module_put(fops->owner);
	return file;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1199697.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "anon_inode_inode", (void *)&klpe_anon_inode_inode },
	{ "anon_inode_mnt", (void *)&klpe_anon_inode_mnt },
	{ "perf_fops", (void *)&klpe_perf_fops },
};

int livepatch_bsc1199697_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
