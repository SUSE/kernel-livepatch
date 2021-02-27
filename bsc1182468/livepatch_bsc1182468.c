/*
 * livepatch_bsc1182468
 *
 * Fix for bsc#1182468
 *
 *  Upstream commit:
 *  none yet
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4 commit:
 *  1f6b5b157260410dd6d5319049b0160fff513e3e
 *
 *  SLE15 commit:
 *  none yet
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  20e5a61cd705e0d4a736aa54ec8c33c48ae18678
 *
 *  SLE15-SP2 commit:
 *  f10a9960dcfa3a24b33f513fb22a38d0ede1e6e5
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

#if !IS_MODULE(CONFIG_NFS_FS)
#error "Live patch supports only CONFIG_NFS_FS=m"
#endif

#include <linux/tracepoint.h>

/* from include/linux/tracepoint.h */
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
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KLPR_DEFINE_EVENT(template, name, proto, args)		\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

/* klp-ccp: from fs/nfs/dir.c */
#include <linux/module.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sunrpc/clnt.h>

/* klp-ccp: from include/linux/sunrpc/debug.h */
#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)

static unsigned int		(*klpe_nfs_debug);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from fs/nfs/dir.c */
#include <linux/nfs_fs.h>

/* klp-ccp: from include/linux/nfs_fs.h */
static void (*klpe_nfs_zap_caches)(struct inode *);

#  define klpr_ifdebug(fac)		if (unlikely((*klpe_nfs_debug) & NFSDBG_##fac))

/* klp-ccp: from include/linux/sunrpc/debug.h */
# define klpr_dfprintk(fac, fmt, ...)					\
do {									\
	klpr_ifdebug(fac)							\
		printk(KERN_DEFAULT fmt, ##__VA_ARGS__);		\
} while (0)

/* klp-ccp: from fs/nfs/dir.c */
#include <uapi/linux/nfs_mount.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/swap.h>
#include <linux/sched.h>
#include <linux/kmemleak.h>
/* klp-ccp: from fs/nfs/iostat.h */
#include <linux/percpu.h>
#include <linux/cache.h>
#include <linux/nfs_iostat.h>

struct nfs_iostats {
	unsigned long long	bytes[__NFSIOS_BYTESMAX];
#ifdef CONFIG_NFS_FSCACHE
	unsigned long long	fscache[__NFSIOS_FSCACHEMAX];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	unsigned long		events[__NFSIOS_COUNTSMAX];
} ____cacheline_aligned;

static inline void nfs_inc_server_stats(const struct nfs_server *server,
					enum nfs_stat_eventcounters stat)
{
	this_cpu_inc(server->io_stats->events[stat]);
}

static inline void nfs_inc_stats(const struct inode *inode,
				 enum nfs_stat_eventcounters stat)
{
	nfs_inc_server_stats(NFS_SERVER(inode), stat);
}

/* klp-ccp: from fs/nfs/nfs4_fs.h */
#include <linux/seqlock.h>

/* klp-ccp: from fs/nfs/internal.h */
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/wait_bit.h>

static void (*klpe_nfs_advise_use_readdirplus)(struct inode *dir);

/* klp-ccp: from fs/nfs/fscache.h */
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>

/* klp-ccp: from fs/nfs/nfstrace.h */
#define KLPR_DEFINE_NFS_LOOKUP_EVENT(name) \
	KLPR_DEFINE_EVENT(nfs_lookup_event, name, \
			TP_PROTO( \
				const struct inode *dir, \
				const struct dentry *dentry, \
				unsigned int flags \
			), \
			TP_ARGS(dir, dentry, flags))

#define KLPR_DEFINE_NFS_LOOKUP_EVENT_DONE(name) \
	KLPR_DEFINE_EVENT(nfs_lookup_event_done, name, \
			TP_PROTO( \
				const struct inode *dir, \
				const struct dentry *dentry, \
				unsigned int flags, \
				int error \
			), \
			TP_ARGS(dir, dentry, flags, error))

KLPR_DEFINE_NFS_LOOKUP_EVENT(nfs_lookup_revalidate_enter);
KLPR_DEFINE_NFS_LOOKUP_EVENT_DONE(nfs_lookup_revalidate_exit);

/* klp-ccp: from fs/nfs/dir.c */
static int (*klpe_nfs_check_verifier)(struct inode *dir, struct dentry *dentry,
			      int rcu_walk);

static
int (*klpe_nfs_lookup_verify_inode)(struct inode *inode, unsigned int flags);

/* klp-ccp: from fs/nfs/dir.c */
static inline
int klpr_nfs_neg_need_reval(struct inode *dir, struct dentry *dentry,
		       unsigned int flags)
{
	if (flags & (LOOKUP_CREATE | LOOKUP_RENAME_TARGET))
		return 0;
	if (NFS_SERVER(dir)->flags & NFS_MOUNT_LOOKUP_CACHE_NONEG)
		return 1;
	return !(*klpe_nfs_check_verifier)(dir, dentry, flags & LOOKUP_RCU);
}

static int
(*klpe_nfs_lookup_revalidate_done)(struct inode *dir, struct dentry *dentry,
			   struct inode *inode, int error);

static int
klpr_nfs_lookup_revalidate_negative(struct inode *dir, struct dentry *dentry,
			       unsigned int flags)
{
	int ret = 1;
	if (klpr_nfs_neg_need_reval(dir, dentry, flags)) {
		if (flags & LOOKUP_RCU)
			return -ECHILD;
		ret = 0;
	}
	return (*klpe_nfs_lookup_revalidate_done)(dir, dentry, NULL, ret);
}

static int
klpr_nfs_lookup_revalidate_delegated(struct inode *dir, struct dentry *dentry,
				struct inode *inode)
{
	nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
	return (*klpe_nfs_lookup_revalidate_done)(dir, dentry, inode, 1);
}

static int
(*klpe_nfs_lookup_revalidate_dentry)(struct inode *dir, struct dentry *dentry,
			     struct inode *inode);

int
klpp_nfs_do_lookup_revalidate(struct inode *dir, struct dentry *dentry,
			 unsigned int flags)
{
	struct inode *inode;
	/*
	 * Fix bsc#1182468
	 *  -1 line, +1 line
	 */
	int error = 0;

	nfs_inc_stats(dir, NFSIOS_DENTRYREVALIDATE);
	inode = d_inode(dentry);

	if (!inode)
		return klpr_nfs_lookup_revalidate_negative(dir, dentry, flags);

	if (is_bad_inode(inode)) {
		klpr_dfprintk(LOOKUPCACHE, "%s: %pd2 has dud inode\n",
				__func__, dentry);
		goto out_bad;
	}

	if (NFS_PROTO(dir)->have_delegation(inode, FMODE_READ))
		return klpr_nfs_lookup_revalidate_delegated(dir, dentry, inode);

	/* Force a full look up iff the parent directory has changed */
	if (!(flags & (LOOKUP_EXCL | LOOKUP_REVAL)) &&
	    (*klpe_nfs_check_verifier)(dir, dentry, flags & LOOKUP_RCU)) {
		error = (*klpe_nfs_lookup_verify_inode)(inode, flags);
		if (error) {
			/*
			 * Fix bsc#1182468
			 *  -2 lines, +4 lines
			 */
			if (error == -ESTALE) {
				(*klpe_nfs_zap_caches)(dir);
				error = 0;
			}
			goto out_bad;
		}
		(*klpe_nfs_advise_use_readdirplus)(dir);
		goto out_valid;
	}

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	if (NFS_STALE(inode))
		goto out_bad;

	klpr_trace_nfs_lookup_revalidate_enter(dir, dentry, flags);
	error = (*klpe_nfs_lookup_revalidate_dentry)(dir, dentry, inode);
	klpr_trace_nfs_lookup_revalidate_exit(dir, dentry, flags, error);
	return error;
out_valid:
	return (*klpe_nfs_lookup_revalidate_done)(dir, dentry, inode, 1);
out_bad:
	if (flags & LOOKUP_RCU)
		return -ECHILD;
	/*
	 * Fix bsc#1182468
	 *  -1 line, +1 line
	 */
	return (*klpe_nfs_lookup_revalidate_done)(dir, dentry, inode, error);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1182468.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfs_debug", (void *)&klpe_nfs_debug, "sunrpc" },
	{ "__tracepoint_nfs_lookup_revalidate_exit",
	  (void *)&klpe___tracepoint_nfs_lookup_revalidate_exit, "nfs" },
	{ "__tracepoint_nfs_lookup_revalidate_enter",
	  (void *)&klpe___tracepoint_nfs_lookup_revalidate_enter, "nfs" },
	{ "nfs_zap_caches", (void *)&klpe_nfs_zap_caches, "nfs" },
	{ "nfs_advise_use_readdirplus",
	  (void *)&klpe_nfs_advise_use_readdirplus, "nfs" },
	{ "nfs_check_verifier", (void *)&klpe_nfs_check_verifier, "nfs" },
	{ "nfs_lookup_verify_inode", (void *)&klpe_nfs_lookup_verify_inode,
	  "nfs" },
	{ "nfs_lookup_revalidate_done",
	  (void *)&klpe_nfs_lookup_revalidate_done, "nfs" },
	{ "nfs_lookup_revalidate_dentry",
	  (void *)&klpe_nfs_lookup_revalidate_dentry, "nfs" },
};

static int livepatch_bsc1182468_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1182468_module_nb = {
	.notifier_call = livepatch_bsc1182468_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1182468_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1182468_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1182468_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1182468_module_nb);
}
