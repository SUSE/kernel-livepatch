/*
 * bsc1242579_fs_proc_inode
 *
 * Fix for CVE-2025-21999, bsc#1242579
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

/* klp-ccp: from fs/proc/inode.c */
#include <linux/cache.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>

/* klp-ccp: from fs/proc/inode.c */
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/completion.h>

#include <linux/printk.h>

#include <linux/limits.h>
#include <linux/init.h>

#include <linux/sysctl.h>

#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/bug.h>

/* klp-ccp: from fs/proc/internal.h */
#include <linux/proc_fs.h>

#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#include <linux/sched/coredump.h>
#include <linux/sched/task.h>

struct proc_dir_entry {
    /*
     * number of callers into module in progress;
     * negative -> it's going away RSN
     */
    atomic_t in_use;
    refcount_t refcnt;
    struct list_head pde_openers;    /* who did ->open, but not ->release */
    /* protects ->pde_openers and all struct pde_opener instances */
    spinlock_t pde_unload_lock;
    struct completion *pde_unload_completion;
    const struct inode_operations *proc_iops;
    union {
        const struct proc_ops *proc_ops;
        const struct file_operations *proc_dir_ops;
    };
    const struct dentry_operations *proc_dops;
    union {
        const struct seq_operations *seq_ops;
        int (*single_show)(struct seq_file *, void *);
    };
    proc_write_t write;
    void *data;
    unsigned int state_size;
    unsigned int low_ino;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    char *name;
    umode_t mode;
    u8 flags;
    u8 namelen;
    char inline_name[];
} __randomize_layout;

#include "livepatch_bsc1242579_common.h"

static inline bool pde_has_proc_read_iter(const struct proc_dir_entry *pde)
{
    return pde->flags & PROC_ENTRY_proc_read_iter;
}

static inline bool pde_has_proc_compat_ioctl(const struct proc_dir_entry *pde)
{
#ifdef CONFIG_COMPAT
    return pde->flags & PROC_ENTRY_proc_compat_ioctl;
#else
    return false;
#endif
}

union proc_op {
    int (*proc_get_link)(struct dentry *, struct path *);
    int (*proc_show)(struct seq_file *m,
        struct pid_namespace *ns, struct pid *pid,
        struct task_struct *task);
    const char *lsm;
};

struct proc_inode {
    struct pid *pid;
    unsigned int fd;
    union proc_op op;
    struct proc_dir_entry *pde;
    struct ctl_table_header *sysctl;
    struct ctl_table *sysctl_entry;
    struct hlist_node sibling_inodes;
    const struct proc_ns_operations *ns_ops;
    struct inode vfs_inode;
} __randomize_layout;

static inline struct proc_inode *PROC_I(const struct inode *inode)
{
    return container_of(inode, struct proc_inode, vfs_inode);
}

extern void pde_put(struct proc_dir_entry *);

static inline bool is_empty_pde(const struct proc_dir_entry *pde)
{
    return S_ISDIR(pde->mode) && !pde->proc_iops;
}

/* klp-ccp: from fs/proc/inode.c */
extern const struct file_operations proc_reg_file_ops;

extern const struct file_operations proc_iter_file_ops;

#ifdef CONFIG_COMPAT
extern const struct file_operations proc_reg_file_ops_compat;
extern const struct file_operations proc_iter_file_ops_compat;
#endif

struct inode *klpp_proc_get_inode(struct super_block *sb, struct proc_dir_entry *de)
{
    struct inode *inode = new_inode(sb);

    if (!inode) {
        pde_put(de);
        return NULL;
    }

    inode->i_private = de->data;
    inode->i_ino = de->low_ino;
    inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
    PROC_I(inode)->pde = de;
    if (is_empty_pde(de)) {
        make_empty_dir_inode(inode);
        return inode;
    }

    if (de->mode) {
        inode->i_mode = de->mode;
        inode->i_uid = de->uid;
        inode->i_gid = de->gid;
    }
    if (de->size)
        inode->i_size = de->size;
    if (de->nlink)
        set_nlink(inode, de->nlink);

    if (S_ISREG(inode->i_mode)) {
        inode->i_op = de->proc_iops;
        if (pde_is_new_proc(de)) {
            if (pde_has_proc_read_iter(de))
                inode->i_fop = &proc_iter_file_ops;
            else
                inode->i_fop = &proc_reg_file_ops;
        } else {
            if (de->proc_ops->proc_read_iter)
                inode->i_fop = &proc_iter_file_ops;
            else
                inode->i_fop = &proc_reg_file_ops;
        }
#ifdef CONFIG_COMPAT
        if (pde_is_new_proc(de)) {
            if (pde_has_proc_compat_ioctl(de)) {
                if (pde_has_proc_read_iter(de))
                    inode->i_fop = &proc_iter_file_ops_compat;
                else
                    inode->i_fop = &proc_reg_file_ops_compat;
            }
        } else {
            if (de->proc_ops->proc_compat_ioctl) {
                if (de->proc_ops->proc_read_iter)
                    inode->i_fop = &proc_iter_file_ops_compat;
                else
                    inode->i_fop = &proc_reg_file_ops_compat;
            }
        }
#endif
    } else if (S_ISDIR(inode->i_mode)) {
        inode->i_op = de->proc_iops;
        inode->i_fop = de->proc_dir_ops;
    } else if (S_ISLNK(inode->i_mode)) {
        inode->i_op = de->proc_iops;
        inode->i_fop = NULL;
    } else {
        BUG();
    }
    return inode;
}


#include "livepatch_bsc1242579.h"

#include <linux/livepatch.h>

extern typeof(make_empty_dir_inode) make_empty_dir_inode
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, make_empty_dir_inode);
extern typeof(pde_put) pde_put KLP_RELOC_SYMBOL(vmlinux, vmlinux, pde_put);
extern typeof(proc_iter_file_ops) proc_iter_file_ops
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_iter_file_ops);
extern typeof(proc_reg_file_ops) proc_reg_file_ops
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_reg_file_ops);

#ifdef CONFIG_COMPAT
extern typeof(proc_iter_file_ops_compat) proc_iter_file_ops_compat
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_iter_file_ops_compat);
extern typeof(proc_reg_file_ops_compat) proc_reg_file_ops_compat
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_reg_file_ops_compat);
#endif
