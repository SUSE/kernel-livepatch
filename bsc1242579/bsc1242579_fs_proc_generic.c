/*
 * bsc1242579_fs_proc_generic
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

/* klp-ccp: from fs/proc/generic.c */
#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>

/* klp-ccp: from fs/proc/generic.c */
#include <linux/stat.h>

/* klp-ccp: from fs/proc/generic.c */
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/uaccess.h>

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

struct proc_dir_entry *proc_create_reg(const char *name, umode_t mode,
        struct proc_dir_entry **parent, void *data);
struct proc_dir_entry *proc_register(struct proc_dir_entry *dir,
        struct proc_dir_entry *dp);

/* klp-ccp: from fs/proc/generic.c */
struct proc_dir_entry *proc_register(struct proc_dir_entry *dir,
        struct proc_dir_entry *dp);

struct proc_dir_entry *proc_create_reg(const char *name, umode_t mode,
        struct proc_dir_entry **parent, void *data);

static void pde_set_flags(struct proc_dir_entry *pde)
{
    pde->flags |= PROC_ENTRY_bsc1242579;

    if (pde->proc_ops->proc_flags & PROC_ENTRY_PERMANENT)
        pde->flags |= PROC_ENTRY_PERMANENT;
    if (pde->proc_ops->proc_read_iter)
        pde->flags |= PROC_ENTRY_proc_read_iter;
#ifdef CONFIG_COMPAT
    if (pde->proc_ops->proc_compat_ioctl)
        pde->flags |= PROC_ENTRY_proc_compat_ioctl;
#endif
}

extern const struct proc_ops proc_seq_ops;

struct proc_dir_entry *klpp_proc_create_seq_private(const char *name, umode_t mode,
        struct proc_dir_entry *parent, const struct seq_operations *ops,
        unsigned int state_size, void *data)
{
    struct proc_dir_entry *p;

    p = proc_create_reg(name, mode, &parent, data);
    if (!p)
        return NULL;
    p->proc_ops = &proc_seq_ops;
    p->seq_ops = ops;
    p->state_size = state_size;
    pde_set_flags(p);
    return proc_register(parent, p);
}

typeof(klpp_proc_create_seq_private) klpp_proc_create_seq_private;

extern const struct proc_ops proc_single_ops;

struct proc_dir_entry *klpp_proc_create_single_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *), void *data)
{
    struct proc_dir_entry *p;

    p = proc_create_reg(name, mode, &parent, data);
    if (!p)
        return NULL;
    p->proc_ops = &proc_single_ops;
    p->single_show = show;
    pde_set_flags(p);
    return proc_register(parent, p);
}

typeof(klpp_proc_create_single_data) klpp_proc_create_single_data;


#include "livepatch_bsc1242579.h"

#include <linux/livepatch.h>

extern typeof(proc_create_reg) proc_create_reg
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_create_reg);
extern typeof(proc_register) proc_register
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_register);
extern typeof(proc_seq_ops) proc_seq_ops
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_seq_ops);
extern typeof(proc_single_ops) proc_single_ops
     KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_single_ops);
