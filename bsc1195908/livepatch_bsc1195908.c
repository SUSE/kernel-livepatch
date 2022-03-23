/*
 * livepatch_bsc1195908
 *
 * Fix for CVE-2022-0492, bsc#1195908
 *
 *  Upstream commit:
 *  24f600856418 ("cgroup-v1: Require capabilities to set release_agent")
 *
 *  SLE12-SP3 commit:
 *  50d93c2591da9e4228629449979e6fc8dc453c5b
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  25a96a7112ab07894c6387ebb67592db9ee16315
 *
 *  SLE15-SP2 and -SP3 commit:
 *  413d689eb818bd67df51d4da49daa164e47bc89d
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

/* klp-ccp: from kernel/cgroup/cgroup-internal.h */
#include <linux/cgroup.h>

static struct super_block *(*klpe_kernfs_pin_sb)(struct kernfs_root *root, const void *ns);

/* klp-ccp: from include/linux/cgroup.h */
static struct cgroup_namespace (*klpe_init_cgroup_ns);

/* klp-ccp: from kernel/cgroup/cgroup-internal.h */
#include <linux/kernfs.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

struct cgroup_sb_opts {
	u16 subsys_mask;
	unsigned int flags;
	char *release_agent;
	bool cpuset_clone_children;
	char *name;
	/* User explicitly requested empty subsystem */
	bool none;
};

static struct mutex (*klpe_cgroup_mutex);

static struct cgroup_subsys *(*klpe_cgroup_subsys)[];
static struct list_head (*klpe_cgroup_roots);
static struct file_system_type (*klpe_cgroup_fs_type);

static struct cgroup_root *(*klpe_cgroup_root_from_kf)(struct kernfs_root *kf_root);

static struct cgroup *(*klpe_cgroup_kn_lock_live)(struct kernfs_node *kn, bool drain_offline);
static void (*klpe_cgroup_kn_unlock)(struct kernfs_node *kn);

static void (*klpe_cgroup_free_root)(struct cgroup_root *root);
static void (*klpe_init_cgroup_root)(struct cgroup_root *root, struct cgroup_sb_opts *opts);
static int (*klpe_cgroup_setup_root)(struct cgroup_root *root, u16 ss_mask, int ref_flags);
static int (*klpe_rebind_subsystems)(struct cgroup_root *dst_root, u16 ss_mask);
static struct dentry *(*klpe_cgroup_do_mount)(struct file_system_type *fs_type, int flags,
			       struct cgroup_root *root, unsigned long magic,
			       struct cgroup_namespace *ns);

static void (*klpe_cgroup_lock_and_drain_offline)(struct cgroup *cgrp);

/* klp-ccp: from kernel/cgroup/cgroup-v1.c */
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/cgroupstats.h>

#include <linux/tracepoint.h>

/* klp-ccp: from include/linux/tracepoint.h */
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static struct tracepoint (*klpe___tracepoint_##name);		\
	static inline void klpr_trace_##name(proto)			\
	{								\
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key))) \
			__DO_TRACE(&(*klpe___tracepoint_##name),	\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond), 0);		\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs); \
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\

#define KLPR_DECLARE_TRACE(name, proto, args)				\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),	\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KLPR_DEFINE_EVENT(template, name, proto, args)		\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

/* klp-ccp: from include/trace/events/cgroup.h */
KLPR_DEFINE_EVENT(cgroup_root, cgroup_remount,
   TP_PROTO(struct cgroup_root *root),
   TP_ARGS(root))


/* klp-ccp: from kernel/cgroup/cgroup-internal.h */
#define klpr_for_each_root(root)					\
	list_for_each_entry((root), klpe_cgroup_roots, root_list)

#define klpr_for_each_subsys(ss, ssid)					\
	for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT &&		\
	     (((ss) = (*klpe_cgroup_subsys)[ssid]) || true); (ssid)++)

/* klp-ccp: from kernel/cgroup/cgroup-v1.c */
static spinlock_t (*klpe_release_agent_path_lock);

ssize_t klpp_cgroup_release_agent_write(struct kernfs_open_file *of,
					  char *buf, size_t nbytes, loff_t off)
{
	struct cgroup *cgrp;

	BUILD_BUG_ON(sizeof(cgrp->root->release_agent_path) < PATH_MAX);


	/*
	 * Release agent gets called with all capabilities,
	 * require capabilities to set release agent.
	 */
	if ((of->file->f_cred->user_ns != &init_user_ns) ||
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;

	cgrp = (*klpe_cgroup_kn_lock_live)(of->kn, false);
	if (!cgrp)
		return -ENODEV;
	spin_lock(&(*klpe_release_agent_path_lock));
	strlcpy(cgrp->root->release_agent_path, strstrip(buf),
		sizeof(cgrp->root->release_agent_path));
	spin_unlock(&(*klpe_release_agent_path_lock));
	(*klpe_cgroup_kn_unlock)(of->kn);
	return nbytes;
}

static int (*klpe_parse_cgroupfs_options)(char *data, struct cgroup_sb_opts *opts);

int klpp_cgroup1_remount(struct kernfs_root *kf_root, int *flags, char *data)
{
	int ret = 0;
	struct cgroup_root *root = (*klpe_cgroup_root_from_kf)(kf_root);
	struct cgroup_namespace *ns = current->nsproxy->cgroup_ns;
	struct cgroup_sb_opts opts;
	u16 added_mask, removed_mask;

	(*klpe_cgroup_lock_and_drain_offline)(&cgrp_dfl_root.cgrp);

	/* See what subsystems are wanted */
	ret = (*klpe_parse_cgroupfs_options)(data, &opts);
	if (ret)
		goto out_unlock;

	if (opts.subsys_mask != root->subsys_mask || opts.release_agent)
		pr_warn("option changes via remount are deprecated (pid=%d comm=%s)\n",
			task_tgid_nr(current), current->comm);

	/* See cgroup1_mount release_agent handling */
	if (opts.release_agent &&
		((ns->user_ns != &init_user_ns) || !capable(CAP_SYS_ADMIN))) {
		ret = -EINVAL;
		goto out_unlock;
	}

	added_mask = opts.subsys_mask & ~root->subsys_mask;
	removed_mask = root->subsys_mask & ~opts.subsys_mask;

	/* Don't allow flags or name to change at remount */
	if ((opts.flags ^ root->flags) ||
	    (opts.name && strcmp(opts.name, root->name))) {
		pr_err("option or name mismatch, new: 0x%x \"%s\", old: 0x%x \"%s\"\n",
		       opts.flags, opts.name ?: "", root->flags, root->name);
		ret = -EINVAL;
		goto out_unlock;
	}

	/* remounting is not allowed for populated hierarchies */
	if (!list_empty(&root->cgrp.self.children)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = (*klpe_rebind_subsystems)(root, added_mask);
	if (ret)
		goto out_unlock;

	WARN_ON((*klpe_rebind_subsystems)(&cgrp_dfl_root, removed_mask));

	if (opts.release_agent) {
		spin_lock(&(*klpe_release_agent_path_lock));
		strcpy(root->release_agent_path, opts.release_agent);
		spin_unlock(&(*klpe_release_agent_path_lock));
	}

	klpr_trace_cgroup_remount(root);

 out_unlock:
	kfree(opts.release_agent);
	kfree(opts.name);
	mutex_unlock(&(*klpe_cgroup_mutex));
	return ret;
}

struct dentry *klpp_cgroup1_mount(struct file_system_type *fs_type, int flags,
			     void *data, unsigned long magic,
			     struct cgroup_namespace *ns)
{
	struct super_block *pinned_sb = NULL;
	struct cgroup_sb_opts opts;
	struct cgroup_root *root;
	struct cgroup_subsys *ss;
	struct dentry *dentry;
	int i, ret;
	bool new_root = false;

	(*klpe_cgroup_lock_and_drain_offline)(&cgrp_dfl_root.cgrp);

	/* First find the desired set of subsystems */
	ret = (*klpe_parse_cgroupfs_options)(data, &opts);
	if (ret)
		goto out_unlock;

	/*
	 * Release agent gets called with all capabilities,
	 * require capabilities to set release agent.
	 */
	if (opts.release_agent &&
			((ns->user_ns != &init_user_ns) || !capable(CAP_SYS_ADMIN))) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/*
	 * Destruction of cgroup root is asynchronous, so subsystems may
	 * still be dying after the previous unmount.  Let's drain the
	 * dying subsystems.  We just need to ensure that the ones
	 * unmounted previously finish dying and don't care about new ones
	 * starting.  Testing ref liveliness is good enough.
	 */
	klpr_for_each_subsys(ss, i) {
		if (!(opts.subsys_mask & (1 << i)) ||
		    ss->root == &cgrp_dfl_root)
			continue;

		if (!percpu_ref_tryget_live(&ss->root->cgrp.self.refcnt)) {
			mutex_unlock(&(*klpe_cgroup_mutex));
			msleep(10);
			ret = restart_syscall();
			goto out_free;
		}
		cgroup_put(&ss->root->cgrp);
	}

	klpr_for_each_root(root) {
		bool name_match = false;

		if (root == &cgrp_dfl_root)
			continue;

		/*
		 * If we asked for a name then it must match.  Also, if
		 * name matches but sybsys_mask doesn't, we should fail.
		 * Remember whether name matched.
		 */
		if (opts.name) {
			if (strcmp(opts.name, root->name))
				continue;
			name_match = true;
		}

		/*
		 * If we asked for subsystems (or explicitly for no
		 * subsystems) then they must match.
		 */
		if ((opts.subsys_mask || opts.none) &&
		    (opts.subsys_mask != root->subsys_mask)) {
			if (!name_match)
				continue;
			ret = -EBUSY;
			goto out_unlock;
		}

		if (root->flags ^ opts.flags)
			pr_warn("new mount options do not match the existing superblock, will be ignored\n");

		/*
		 * We want to reuse @root whose lifetime is governed by its
		 * ->cgrp.  Let's check whether @root is alive and keep it
		 * that way.  As cgroup_kill_sb() can happen anytime, we
		 * want to block it by pinning the sb so that @root doesn't
		 * get killed before mount is complete.
		 *
		 * With the sb pinned, tryget_live can reliably indicate
		 * whether @root can be reused.  If it's being killed,
		 * drain it.  We can use wait_queue for the wait but this
		 * path is super cold.  Let's just sleep a bit and retry.
		 */
		pinned_sb = (*klpe_kernfs_pin_sb)(root->kf_root, NULL);
		if (IS_ERR(pinned_sb) ||
		    !percpu_ref_tryget_live(&root->cgrp.self.refcnt)) {
			mutex_unlock(&(*klpe_cgroup_mutex));
			if (!IS_ERR_OR_NULL(pinned_sb))
				deactivate_super(pinned_sb);
			msleep(10);
			ret = restart_syscall();
			goto out_free;
		}

		ret = 0;
		goto out_unlock;
	}

	/*
	 * No such thing, create a new one.  name= matching without subsys
	 * specification is allowed for already existing hierarchies but we
	 * can't create new one without subsys specification.
	 */
	if (!opts.subsys_mask && !opts.none) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Hierarchies may only be created in the initial cgroup namespace. */
	if (ns != &(*klpe_init_cgroup_ns)) {
		ret = -EPERM;
		goto out_unlock;
	}

	root = kzalloc(sizeof(*root), GFP_KERNEL);
	if (!root) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	new_root = true;

	(*klpe_init_cgroup_root)(root, &opts);

	ret = (*klpe_cgroup_setup_root)(root, opts.subsys_mask, PERCPU_REF_INIT_DEAD);
	if (ret)
		(*klpe_cgroup_free_root)(root);

out_unlock:
	mutex_unlock(&(*klpe_cgroup_mutex));
out_free:
	kfree(opts.release_agent);
	kfree(opts.name);

	if (ret)
		return ERR_PTR(ret);

	dentry = (*klpe_cgroup_do_mount)(&(*klpe_cgroup_fs_type), flags, root,
				 CGROUP_SUPER_MAGIC, ns);

	/*
	 * There's a race window after we release cgroup_mutex and before
	 * allocating a superblock. Make sure a concurrent process won't
	 * be able to re-use the root during this window by delaying the
	 * initialization of root refcnt.
	 */
	if (new_root) {
		mutex_lock(&(*klpe_cgroup_mutex));
		percpu_ref_reinit(&root->cgrp.self.refcnt);
		mutex_unlock(&(*klpe_cgroup_mutex));
	}

	/*
	 * If @pinned_sb, we're reusing an existing root and holding an
	 * extra ref on its sb.  Mount is complete.  Put the extra ref.
	 */
	if (pinned_sb)
		deactivate_super(pinned_sb);

	return dentry;
}




#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1195908.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cgroup_do_mount", (void *)&klpe_cgroup_do_mount },
	{ "cgroup_free_root", (void *)&klpe_cgroup_free_root },
	{ "cgroup_kn_lock_live", (void *)&klpe_cgroup_kn_lock_live },
	{ "cgroup_kn_unlock", (void *)&klpe_cgroup_kn_unlock },
	{ "cgroup_lock_and_drain_offline",
	  (void *)&klpe_cgroup_lock_and_drain_offline },
	{ "cgroup_root_from_kf", (void *)&klpe_cgroup_root_from_kf },
	{ "cgroup_setup_root", (void *)&klpe_cgroup_setup_root },
	{ "init_cgroup_root", (void *)&klpe_init_cgroup_root },
	{ "kernfs_pin_sb", (void *)&klpe_kernfs_pin_sb },
	{ "parse_cgroupfs_options", (void *)&klpe_parse_cgroupfs_options },
	{ "rebind_subsystems", (void *)&klpe_rebind_subsystems },
	{ "__tracepoint_cgroup_remount",
	  (void *)&klpe___tracepoint_cgroup_remount },
	{ "cgroup_fs_type", (void *)&klpe_cgroup_fs_type },
	{ "cgroup_mutex", (void *)&klpe_cgroup_mutex },
	{ "cgroup_roots", (void *)&klpe_cgroup_roots },
	{ "cgroup_subsys", (void *)&klpe_cgroup_subsys },
	{ "init_cgroup_ns", (void *)&klpe_init_cgroup_ns },
	{ "release_agent_path_lock", (void *)&klpe_release_agent_path_lock },
};

int livepatch_bsc1195908_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
