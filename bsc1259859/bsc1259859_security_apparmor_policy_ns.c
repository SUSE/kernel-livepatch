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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1

/* klp-ccp: from security/apparmor/policy_ns.c */
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_DOMAIN		6

#define AA_CLASS_LAST		AA_CLASS_DOMAIN

/* klp-ccp: from security/apparmor/include/context.h */
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>
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
/* klp-ccp: from security/apparmor/include/domain.h */
#include <linux/binfmts.h>
#include <linux/types.h>

#ifndef __AA_DOMAIN_H

struct aa_domain {
	int size;
	char **table;
};

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __AA_DOMAIN_H */

/* klp-ccp: from security/apparmor/include/match.h */
#include <linux/kref.h>

/* klp-ccp: from security/apparmor/include/file.h */
struct aa_file_rules {
	unsigned int start;
	struct aa_dfa *dfa;
	/* struct perms perms; */
	struct aa_domain trans;
	/* TODO: add delegate table */
};

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

/* klp-ccp: from security/apparmor/include/apparmorfs.h */
struct aa_ns;

enum aafs_ns_type {
	AAFS_NS_DIR,
	AAFS_NS_PROFS,
	AAFS_NS_NS,
	AAFS_NS_RAW_DATA,
	AAFS_NS_LOAD,
	AAFS_NS_REPLACE,
	AAFS_NS_REMOVE,
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

static int (*klpe___aa_fs_ns_mkdir)(struct aa_ns *ns, struct dentry *parent,
		     const char *name);

/* klp-ccp: from security/apparmor/include/capability.h */
struct aa_caps {
	kernel_cap_t allow;
	kernel_cap_t audit;
	kernel_cap_t quiet;
	kernel_cap_t kill;
	kernel_cap_t extended;
};

/* klp-ccp: from security/apparmor/include/domain.h */
#include <linux/binfmts.h>
#include <linux/types.h>
/* klp-ccp: from security/apparmor/include/net.h */
#include <net/sock.h>

struct aa_net {
	u16 allow[AF_MAX];
	u16 audit[AF_MAX];
	u16 quiet[AF_MAX];
};

/* klp-ccp: from security/apparmor/include/lib.h */
#include <linux/slab.h>
#include <linux/fs.h>

#define AA_BUG(X, args...) AA_BUG_FMT((X), "" args)

#define AA_BUG_FMT(X, fmt, args...)

#define AA_ERROR(fmt, args...)						\
	pr_err_ratelimited("AppArmor: " fmt, ##args)

static inline bool aa_strneq(const char *str, const char *sub, int len)
{
	return !strncmp(str, sub, len) && !str[len];
}

struct aa_policy {
	const char *name;
	const char *hname;
	struct list_head list;
	struct list_head profiles;
};

static inline struct aa_policy *__policy_strn_find(struct list_head *head,
					    const char *str, int len)
{
	struct aa_policy *policy;

	list_for_each_entry_rcu(policy, head, list) {
		if (aa_strneq(policy->name, str, len))
			return policy;
	}

	return NULL;
}

/* klp-ccp: from security/apparmor/include/resource.h */
#include <linux/resource.h>
#include <linux/sched.h>

struct aa_rlimit {
	unsigned int mask;
	struct rlimit limits[RLIM_NLIMITS];
};

/* klp-ccp: from security/apparmor/include/policy.h */
struct aa_policydb {
	/* Generic policy DFA specific rule types will be subsections of it */
	struct aa_dfa *dfa;
	unsigned int start[AA_CLASS_LAST + 1];

};

struct aa_profile {
	struct aa_policy base;
	struct kref count;
	struct rcu_head rcu;
	struct aa_profile __rcu *parent;

	struct aa_ns *ns;
	struct aa_proxy *proxy;
	const char *rename;

	const char *attach;
	struct aa_dfa *xmatch;
	int xmatch_len;
	enum audit_mode audit;
	long mode;
	long flags;
	u32 path_flags;
	int size;

	struct aa_policydb policy;
	struct aa_file_rules file;
	struct aa_caps caps;
	struct aa_net net;
	struct aa_rlimit rlimits;

	struct aa_loaddata *rawdata;
	unsigned char *hash;
	char *dirname;
	struct dentry *dents[AAFS_PROF_SIZEOF];
	struct rhashtable *data;
};

static inline struct aa_profile *aa_get_profile(struct aa_profile *p)
{
	if (p)
		kref_get(&(p->count));

	return p;
}

/* klp-ccp: from security/apparmor/include/policy_ns.h */
#include <linux/kref.h>

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

	struct dentry *dents[AAFS_NS_SIZEOF];
};

static void (*klpe_aa_free_ns)(struct aa_ns *ns);

struct aa_ns *klpp___aa_find_or_create_ns(struct aa_ns *parent, const char *name,
				     struct dentry *dir);
struct aa_ns *klpp_aa_prepare_ns(struct aa_ns *root, const char *name);

static inline struct aa_ns *aa_get_ns(struct aa_ns *ns)
{
	if (ns)
		aa_get_profile(ns->unconfined);

	return ns;
}

static inline struct aa_ns *__aa_findn_ns(struct list_head *head,
					  const char *name, size_t n)
{
	return (struct aa_ns *)__policy_strn_find(head, name, n);
}

static inline struct aa_ns *__aa_find_ns(struct list_head *head,
					 const char *name)
{
	return __aa_findn_ns(head, name, strlen(name));
}

/* klp-ccp: from security/apparmor/policy_ns.c */
static struct aa_ns *(*klpe_alloc_ns)(const char *prefix, const char *name);
static struct aa_ns *klpp___aa_create_ns(struct aa_ns *parent, const char *name,
				    struct dentry *dir)
{
	struct aa_ns *ns;
	int error;

	AA_BUG(!parent);
	AA_BUG(!name);
	AA_BUG(!mutex_is_locked(&parent->lock));

	if (parent->level > MAX_NS_DEPTH)
		return ERR_PTR(-ENOSPC);
	ns = (*klpe_alloc_ns)(parent->base.hname, name);
	if (!ns)
		return NULL;
	mutex_lock(&ns->lock);
	error = (*klpe___aa_fs_ns_mkdir)(ns, ns_subns_dir(parent), name);
	if (error) {
		AA_ERROR("Failed to create interface for ns %s\n",
			 ns->base.name);
		mutex_unlock(&ns->lock);
		(*klpe_aa_free_ns)(ns);
		return ERR_PTR(error);
	}
	ns->parent = aa_get_ns(parent);
	ns->level = parent->level + 1;
	list_add_rcu(&ns->base.list, &parent->sub_ns);
	/* add list ref */
	aa_get_ns(ns);
	mutex_unlock(&ns->lock);

	return ns;
}

struct aa_ns *klpp___aa_find_or_create_ns(struct aa_ns *parent, const char *name,
				     struct dentry *dir)
{
	struct aa_ns *ns;

	AA_BUG(!mutex_is_locked(&parent->lock));

	/* try and find the specified ns */
	/* released by caller */
	ns = aa_get_ns(__aa_find_ns(&parent->sub_ns, name));
	if (!ns)
		ns = klpp___aa_create_ns(parent, name, dir);
	else
		ns = ERR_PTR(-EEXIST);

	/* return ref */
	return ns;
}

struct aa_ns *klpp_aa_prepare_ns(struct aa_ns *parent, const char *name)
{
	struct aa_ns *ns;

	mutex_lock(&parent->lock);
	/* try and find the specified ns and if it doesn't exist create it */
	/* released by caller */
	ns = aa_get_ns(__aa_find_ns(&parent->sub_ns, name));
	if (!ns)
		ns = klpp___aa_create_ns(parent, name, NULL);
	mutex_unlock(&parent->lock);

	/* return ref */
	return ns;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__aa_fs_ns_mkdir", (void *)&klpe___aa_fs_ns_mkdir },
	{ "aa_free_ns", (void *)&klpe_aa_free_ns },
	{ "alloc_ns", (void *)&klpe_alloc_ns },
};

int bsc1259859_security_apparmor_policy_ns_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

