/*
 * livepatch_bsc1250280
 *
 * Fix for CVE-2022-50367, bsc#1250280
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



#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1

/* klp-ccp: from fs/inode.c */
#include <linux/export.h>
#include <linux/fs.h>

/* klp-ccp: from include/linux/fs.h */
int klpp_inode_init_always(struct super_block *, struct inode *);

/* klp-ccp: from fs/inode.c */
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/hash.h>
#include <linux/swap.h>
#include <linux/security.h>

/* klp-ccp: from include/linux/security.h */
#ifdef CONFIG_SECURITY

static int (*klpe_security_inode_alloc)(struct inode *inode);

#else /* CONFIG_SECURITY */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_SECURITY */

/* klp-ccp: from fs/inode.c */
#include <linux/cdev.h>
#include <linux/bootmem.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/posix_acl.h>
#include <linux/prefetch.h>
#include <linux/buffer_head.h> /* for inode_has_buffers */
#include <linux/ratelimit.h>
#include <linux/list_lru.h>
#include <linux/iversion.h>
#include <trace/events/writeback.h>

static struct inode_operations *empty_iops;
static struct file_operations  *no_open_fops;

extern const struct address_space_operations empty_aops;

extern typeof(empty_aops) empty_aops;

static unsigned long __percpu (*klpe_nr_inodes);

static int (*klpe_no_open)(struct inode *inode, struct file *file);

int klpp_inode_init_always(struct super_block *sb, struct inode *inode)
{
	struct address_space *const mapping = &inode->i_data;

	inode->i_sb = sb;
	inode->i_blkbits = sb->s_blocksize_bits;
	inode->i_flags = 0;
	atomic_set(&inode->i_count, 1);
	inode->i_op = empty_iops;
	inode->i_fop = no_open_fops;
	inode->__i_nlink = 1;
	inode->i_opflags = 0;
	if (sb->s_xattr)
		inode->i_opflags |= IOP_XATTR;
	i_uid_write(inode, 0);
	i_gid_write(inode, 0);
	atomic_set(&inode->i_writecount, 0);
	inode->i_size = 0;
	inode->i_write_hint = WRITE_LIFE_NOT_SET;
	inode->i_blocks = 0;
	inode->i_bytes = 0;
	inode->i_generation = 0;
	inode->i_pipe = NULL;
	inode->i_bdev = NULL;
	inode->i_cdev = NULL;
	inode->i_link = NULL;
	inode->i_dir_seq = 0;
	inode->i_rdev = 0;
	inode->dirtied_when = 0;

#ifdef CONFIG_CGROUP_WRITEBACK
	inode->i_wb_frn_winner = 0;
	inode->i_wb_frn_avg_time = 0;
	inode->i_wb_frn_history = 0;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	spin_lock_init(&inode->i_lock);
	lockdep_set_class(&inode->i_lock, &sb->s_type->i_lock_key);

	init_rwsem(&inode->i_rwsem);
	lockdep_set_class(&inode->i_rwsem, &sb->s_type->i_mutex_key);

	atomic_set(&inode->i_dio_count, 0);

	mapping->a_ops = &empty_aops;
	mapping->host = inode;
	mapping->flags = 0;
	mapping->wb_err = 0;
	atomic_set(&mapping->i_mmap_writable, 0);
	mapping_set_gfp_mask(mapping, GFP_HIGHUSER_MOVABLE);
	mapping->private_data = NULL;
	mapping->writeback_index = 0;
	inode->i_private = NULL;
	inode->i_mapping = mapping;
	INIT_HLIST_HEAD(&inode->i_dentry);	/* buggered by rcu freeing */
#ifdef CONFIG_FS_POSIX_ACL
	inode->i_acl = inode->i_default_acl = ACL_NOT_CACHED;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_FSNOTIFY
	inode->i_fsnotify_mask = 0;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	inode->i_flctx = NULL;

	if (unlikely((*klpe_security_inode_alloc)(inode)))
		return -ENOMEM;
	this_cpu_inc((*klpe_nr_inodes));

	return 0;
}

typeof(klpp_inode_init_always) klpp_inode_init_always;


#include <linux/module.h>
static void *previous_livepatch_module_base;

void __weak klpp_module_memfree(void *module_region)
{
	if (previous_livepatch_module_base &&
	    previous_livepatch_module_base == module_region) {
		return;
	}

	vfree(module_region);
}

#include "livepatch_bsc1250280.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nr_inodes", (void *)&klpe_nr_inodes },
	{ "security_inode_alloc", (void *)&klpe_security_inode_alloc },
	{ "no_open", (void *)&klpe_no_open },
};

// Defined in kallsyms_relocs.c.
extern int (*klp_module_kallsyms_on_each_symbol)(int (*fn)(void *, const char *,
							   struct module *,
							   unsigned long),
						 void *data);

static int
__find_previous_livepatch_module(void *data, const char *name,
					 struct module *mod, unsigned long addr)
{
	static struct module *previous_livepatch_module = NULL;

	// We're looking for the previous previous buggy livepatch module. It contains
	// "empty_iops" and "no_open_fops", defined as static locally, Local statics
	// have a symbol name pattern of "<C-DECL-NAME>.[0-9]+".
	if (!is_livepatch_module(mod) || !module_is_live(mod) || addr == 0) {
	  return 0;
	}

	if ((!strncmp(name, "empty_iops", 10) &&
	     strlen(name) >= 12 && name[10] == '.') ||
	    (!strncmp(name, "no_open_fops", 12) &&
	     strlen(name) >= 14 && name[12] == '.')) {
		// All found symbols are expected to be defined in the same mod.
		if (previous_livepatch_module &&
		    previous_livepatch_module != mod) {
			return 1;
		}
		previous_livepatch_module = mod;
		previous_livepatch_module_base = mod->core_layout.base;
	}

	return 0;
}

int livepatch_bsc1250280_init(void)
{
	int ret;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	if (ret)
		return ret;

	empty_iops = kzalloc(sizeof(*empty_iops), GFP_KERNEL);
	if (!empty_iops)
		return -ENOMEM;

	no_open_fops = kzalloc(sizeof(*no_open_fops), GFP_KERNEL);
	if (!no_open_fops) {
		kfree(empty_iops);
		return -ENOMEM;
	}
	no_open_fops->open = klpe_no_open;

	mutex_lock(&module_mutex);
	ret = klp_module_kallsyms_on_each_symbol
		(__find_previous_livepatch_module, NULL);

	if (ret) {
		pr_warn("livepatch: bsc#1250280: previous livepatch module search returned inconsistent results\n");
		previous_livepatch_module_base = NULL;
	}

	mutex_unlock(&module_mutex);

	return 0;
}
