/*
 * bsc1184952_fuse_inode
 *
 * Fix for CVE-2020-36322, bsc#1184952 (fs/fuse/inode.c part)
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
static int (*klpe_fuse_inode_eq)(struct inode *inode, void *_nodeidp);

struct inode *klpp_fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version);

static void (*klpe_fuse_init_file_inode)(struct inode *inode);

static void (*klpe_fuse_init_common)(struct inode *inode);

static void (*klpe_fuse_init_dir)(struct inode *inode);

static void (*klpe_fuse_init_symlink)(struct inode *inode);

static void (*klpe_fuse_change_attributes)(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version);

/* klp-ccp: from fs/fuse/inode.c */
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>

static void klpr_fuse_init_inode(struct inode *inode, struct fuse_attr *attr)
{
	inode->i_mode = attr->mode & S_IFMT;
	inode->i_size = attr->size;
	inode->i_mtime.tv_sec  = attr->mtime;
	inode->i_mtime.tv_nsec = attr->mtimensec;
	inode->i_ctime.tv_sec  = attr->ctime;
	inode->i_ctime.tv_nsec = attr->ctimensec;
	if (S_ISREG(inode->i_mode)) {
		(*klpe_fuse_init_common)(inode);
		(*klpe_fuse_init_file_inode)(inode);
	} else if (S_ISDIR(inode->i_mode))
		(*klpe_fuse_init_dir)(inode);
	else if (S_ISLNK(inode->i_mode))
		(*klpe_fuse_init_symlink)(inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		(*klpe_fuse_init_common)(inode);
		init_special_inode(inode, inode->i_mode,
				   new_decode_dev(attr->rdev));
	} else
		BUG();
}

static int (*klpe_fuse_inode_set)(struct inode *inode, void *_nodeidp);

struct inode *klpp_fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version)
{
	struct inode *inode;
	struct fuse_inode *fi;
	struct fuse_conn *fc = get_fuse_conn_super(sb);

 retry:
	inode = iget5_locked(sb, nodeid, (*klpe_fuse_inode_eq), (*klpe_fuse_inode_set), &nodeid);
	if (!inode)
		return NULL;

	if ((inode->i_state & I_NEW)) {
		inode->i_flags |= S_NOATIME;
		if (!fc->writeback_cache || !S_ISREG(attr->mode))
			inode->i_flags |= S_NOCMTIME;
		inode->i_generation = generation;
		klpr_fuse_init_inode(inode, attr);
		unlock_new_inode(inode);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		/* Inode has changed type, any I/O on the old should fail */
		/*
		 * Fix CVE-2020-36322
		 *  -1 line, +1 line
		 */
		klpp_fuse_make_bad(inode);
		iput(inode);
		goto retry;
	}

	fi = get_fuse_inode(inode);
	spin_lock(&fc->lock);
	fi->nlookup++;
	spin_unlock(&fc->lock);
	(*klpe_fuse_change_attributes)(inode, attr, attr_valid, attr_version);

	return inode;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1184952.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "fuse"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_inode_eq", (void *)&klpe_fuse_inode_eq, "fuse" },
	{ "fuse_init_file_inode", (void *)&klpe_fuse_init_file_inode, "fuse" },
	{ "fuse_init_common", (void *)&klpe_fuse_init_common, "fuse" },
	{ "fuse_init_dir", (void *)&klpe_fuse_init_dir, "fuse" },
	{ "fuse_init_symlink", (void *)&klpe_fuse_init_symlink, "fuse" },
	{ "fuse_change_attributes", (void *)&klpe_fuse_change_attributes,
	  "fuse" },
	{ "fuse_inode_set", (void *)&klpe_fuse_inode_set, "fuse" },
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

int livepatch_bsc1184952_fuse_inode_init(void)
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

void livepatch_bsc1184952_fuse_inode_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1184952_module_nb);
}
