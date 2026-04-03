/*
 * bsc1259859_security_apparmor_policy_ns
 *
 * Fix for CVE-2026-23268, bsc#1259859
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1259859.h"


/* klp-ccp: from security/apparmor/policy_ns.c */
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_DBUS		32

#define AA_CLASS_LAST		AA_CLASS_DBUS

/* klp-ccp: from security/apparmor/include/cred.h */
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/label.h */
#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
/* klp-ccp: from security/apparmor/include/lib.h */
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
/* klp-ccp: from security/apparmor/include/match.h */
#include <linux/kref.h>

#define aa_state_t unsigned int

/* klp-ccp: from security/apparmor/include/lib.h */
#define AA_BUG(X, args...)						    \
	do {								    \
		_Pragma("GCC diagnostic ignored \"-Wformat-zero-length\""); \
		AA_BUG_FMT((X), "" args);				    \
		_Pragma("GCC diagnostic warning \"-Wformat-zero-length\""); \
	} while (0)

#define AA_BUG_FMT(X, fmt, args...) no_printk(fmt, ##args)

#define AA_ERROR(fmt, args...)						\
	pr_err_ratelimited("AppArmor: " fmt, ##args)

struct aa_str_table {
	int size;
	char **table;
};

#define __counted	/* atm just a notation */

struct aa_policy {
	const char *name;
	__counted char *hname;
	struct list_head list;
	struct list_head profiles;
};

/* klp-ccp: from security/apparmor/include/label.h */
struct aa_ns;

struct aa_labelset {
	rwlock_t lock;

	struct rb_root root;
};

struct aa_label {
	struct kref count;
	struct rb_node node;
	struct rcu_head rcu;
	struct aa_proxy *proxy;
	__counted char *hname;
	long flags;
	u32 secid;
	int size;
	struct aa_profile *vec[];
};

/* klp-ccp: from security/apparmor/include/policy_ns.h */
#include <linux/kref.h>

/* klp-ccp: from security/apparmor/include/apparmorfs.h */
enum aafs_ns_type {
	AAFS_NS_DIR,
	AAFS_NS_PROFS,
	AAFS_NS_NS,
	AAFS_NS_RAW_DATA,
	AAFS_NS_LOAD,
	AAFS_NS_REPLACE,
	AAFS_NS_REMOVE,
	AAFS_NS_REVISION,
	AAFS_NS_COUNT,
	AAFS_NS_MAX_COUNT,
	AAFS_NS_SIZE,
	AAFS_NS_MAX_SIZE,
	AAFS_NS_OWNER,
	AAFS_NS_SIZEOF,
};

enum aafs_prof_type {
	AAFS_PROF_DIR,
	AAFS_PROF_PROFS,
	AAFS_PROF_NAME,
	AAFS_PROF_MODE,
	AAFS_PROF_ATTACH,
	AAFS_PROF_HASH,
	AAFS_PROF_RAW_DATA,
	AAFS_PROF_RAW_HASH,
	AAFS_PROF_RAW_ABI,
	AAFS_PROF_SIZEOF,
};

#define ns_subns_dir(X) ((X)->dents[AAFS_NS_NS])

int __aafs_ns_mkdir(struct aa_ns *ns, struct dentry *parent, const char *name,
		     struct dentry *dent);

/* klp-ccp: from security/apparmor/include/policy.h */
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kref.h>
#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>
/* klp-ccp: from security/apparmor/include/audit.h */
#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/lsm_audit.h>
#include <linux/sched.h>
#include <linux/slab.h>
/* klp-ccp: from security/apparmor/include/file.h */
#include <linux/spinlock.h>
/* klp-ccp: from security/apparmor/include/domain.h */
#include <linux/binfmts.h>
#include <linux/types.h>
/* klp-ccp: from security/apparmor/include/perms.h */
#include <linux/fs.h>

/* klp-ccp: from security/apparmor/include/audit.h */
enum audit_mode {
	AUDIT_NORMAL,		/* follow normal auditing of accesses */
	AUDIT_QUIET_DENIED,	/* quiet all denied access messages */
	AUDIT_QUIET,		/* quiet all messages */
	AUDIT_NOQUIET,		/* do not quiet audit messages */
	AUDIT_ALL		/* audit all accesses */
};

/* klp-ccp: from security/apparmor/include/capability.h */
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/domain.h */
#include <linux/binfmts.h>
#include <linux/types.h>
/* klp-ccp: from security/apparmor/include/net.h */
#include <net/sock.h>
#include <linux/path.h>
/* klp-ccp: from security/apparmor/include/resource.h */
#include <linux/resource.h>
#include <linux/sched.h>

/* klp-ccp: from security/apparmor/include/policy.h */
struct aa_policydb {
	struct aa_dfa *dfa;
	struct {
		struct aa_perms *perms;
		u32 size;
	};
	struct aa_str_table trans;
	aa_state_t start[AA_CLASS_LAST + 1];
};

struct aa_attachment {
	const char *xmatch_str;
	struct aa_policydb xmatch;
	unsigned int xmatch_len;
	int xattr_count;
	char **xattrs;
};

struct aa_profile {
	struct aa_policy base;
	struct aa_profile __rcu *parent;

	struct aa_ns *ns;
	const char *rename;

	enum audit_mode audit;
	long mode;
	u32 path_flags;
	const char *disconnected;

	struct aa_attachment attach;
	struct list_head rules;

	struct aa_loaddata *rawdata;
	unsigned char *hash;
	char *dirname;
	struct dentry *dents[AAFS_PROF_SIZEOF];
	struct rhashtable *data;
	struct aa_label label;
};

static inline struct aa_profile *aa_get_profile(struct aa_profile *p)
{
	if (p)
		kref_get(&(p->label.count));

	return p;
}

/* klp-ccp: from security/apparmor/include/policy_ns.h */
#define MAX_NS_DEPTH 32

struct aa_ns_acct {
	int max_size;
	int max_count;
	int size;
	int count;
};

struct aa_ns {
	struct aa_policy base;
	struct aa_ns *parent;
	struct mutex lock;
	struct aa_ns_acct acct;
	struct aa_profile *unconfined;
	struct list_head sub_ns;
	atomic_t uniq_null;
	long uniq_id;
	int level;
	long revision;
	wait_queue_head_t wait;

	struct aa_labelset labels;
	struct list_head rawdata_list;

	struct dentry *dents[AAFS_NS_SIZEOF];
};

void aa_free_ns(struct aa_ns *ns);

static inline struct aa_ns *aa_get_ns(struct aa_ns *ns)
{
	if (ns)
		aa_get_profile(ns->unconfined);

	return ns;
}

/* klp-ccp: from security/apparmor/policy_ns.c */
extern struct aa_ns *alloc_ns(const char *prefix, const char *name);

void aa_free_ns(struct aa_ns *ns);

struct aa_ns *klpp___aa_create_ns(struct aa_ns *parent, const char *name,
				    struct dentry *dir)
{
	struct aa_ns *ns;
	int error;

	AA_BUG(!parent);
	AA_BUG(!name);
	AA_BUG(!mutex_is_locked(&parent->lock));

	if (parent->level > MAX_NS_DEPTH)
		return ERR_PTR(-ENOSPC);
	ns = alloc_ns(parent->base.hname, name);
	if (!ns)
		return ERR_PTR(-ENOMEM);
	ns->level = parent->level + 1;
	mutex_lock_nested(&ns->lock, ns->level);
	error = __aafs_ns_mkdir(ns, ns_subns_dir(parent), name, dir);
	if (error) {
		AA_ERROR("Failed to create interface for ns %s\n",
			 ns->base.name);
		mutex_unlock(&ns->lock);
		aa_free_ns(ns);
		return ERR_PTR(error);
	}
	ns->parent = aa_get_ns(parent);
	list_add_rcu(&ns->base.list, &parent->sub_ns);
	/* add list ref */
	aa_get_ns(ns);
	mutex_unlock(&ns->lock);

	return ns;
}


#include <linux/livepatch.h>

extern typeof(__aafs_ns_mkdir) __aafs_ns_mkdir
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aafs_ns_mkdir);
extern typeof(aa_free_ns) aa_free_ns
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_free_ns);
extern typeof(alloc_ns) alloc_ns KLP_RELOC_SYMBOL(vmlinux, vmlinux, alloc_ns);
