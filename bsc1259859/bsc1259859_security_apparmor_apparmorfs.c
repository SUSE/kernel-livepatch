/*
 * bsc1259859_security_apparmor_apparmorfs
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

/* klp-ccp: from security/apparmor/apparmorfs.c */
#include <linux/ctype.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/capability.h>
#include <linux/rcupdate.h>
#include <uapi/linux/major.h>
#include <linux/fs.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_DOMAIN		6

#define AA_CLASS_LAST		AA_CLASS_DOMAIN

/* klp-ccp: from security/apparmor/include/apparmorfs.h */
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

#define OP_PROF_REPL "profile_replace"
#define OP_PROF_LOAD "profile_load"
#define OP_PROF_RM "profile_remove"

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
/* klp-ccp: from security/apparmor/include/capability.h */
#include <linux/sched.h>

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

struct aa_policy {
	const char *name;
	const char *hname;
	struct list_head list;
	struct list_head profiles;
};

/* klp-ccp: from security/apparmor/include/resource.h */
#include <linux/resource.h>
#include <linux/sched.h>

struct aa_rlimit {
	unsigned int mask;
	struct rlimit limits[RLIM_NLIMITS];
};

/* klp-ccp: from security/apparmor/include/policy.h */
#define profile_is_stale(_profile) ((_profile)->flags & PFLAG_STALE)

enum profile_flags {
	PFLAG_HAT = 1,			/* profile is a hat */
	PFLAG_NULL = 4,			/* profile is null learning profile */
	PFLAG_IX_ON_NAME_ERROR = 8,	/* fallback to ix on name lookup fail */
	PFLAG_IMMUTABLE = 0x10,		/* don't allow changes/replacement */
	PFLAG_USER_DEFINED = 0x20,	/* user based profile - lower privs */
	PFLAG_NO_LIST_REF = 0x40,	/* list doesn't keep profile ref */
	PFLAG_OLD_NULL_TRANS = 0x100,	/* use // as the null transition */
	PFLAG_STALE = 0x200,		/* profile replaced/removed */
	PFLAG_NS_COUNT = 0x400,		/* carries NS ref count */

	/* These flags must correspond with PATH_flags */
	PFLAG_MEDIATE_DELETED = 0x10000, /* mediate instead delegate deleted */
};

struct aa_policydb {
	/* Generic policy DFA specific rule types will be subsections of it */
	struct aa_dfa *dfa;
	unsigned int start[AA_CLASS_LAST + 1];

};

struct aa_proxy {
	struct kref count;
	struct aa_profile __rcu *profile;
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

static void (*klpe_aa_free_profile_kref)(struct kref *kref);

static ssize_t (*klpe_aa_replace_profiles)(struct aa_ns *view, struct aa_profile *profile,
			    bool noreplace, struct aa_loaddata *udata);
static ssize_t (*klpe_aa_remove_profiles)(struct aa_ns *view, struct aa_profile *profile,
			    char *name, size_t size);

#define PROF_ADD 1
#define PROF_REPLACE 0

static inline struct aa_profile *aa_get_profile(struct aa_profile *p)
{
	if (p)
		kref_get(&(p->count));

	return p;
}

static inline struct aa_profile *aa_get_profile_rcu(struct aa_profile __rcu **p)
{
	struct aa_profile *c;

	rcu_read_lock();
	do {
		c = rcu_dereference(*p);
	} while (c && !kref_get_unless_zero(&c->count));
	rcu_read_unlock();

	return c;
}

static inline struct aa_profile *aa_get_newest_profile(struct aa_profile *p)
{
	if (!p)
		return NULL;

	if (profile_is_stale(p))
		return aa_get_profile_rcu(&p->proxy->profile);

	return aa_get_profile(p);
}

static inline void klpr_aa_put_profile(struct aa_profile *p)
{
	if (p)
		kref_put(&p->count, (*klpe_aa_free_profile_kref));
}

int klpp_aa_may_manage_policy(struct aa_profile *profile, struct aa_ns *ns,
			 const struct cred *ocred, const char *op);

/* klp-ccp: from security/apparmor/include/policy_ns.h */
#include <linux/kref.h>

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

static inline struct aa_ns *aa_get_ns(struct aa_ns *ns)
{
	if (ns)
		aa_get_profile(ns->unconfined);

	return ns;
}

static inline void klpr_aa_put_ns(struct aa_ns *ns)
{
	if (ns)
		klpr_aa_put_profile(ns->unconfined);
}

/* klp-ccp: from security/apparmor/include/context.h */
#define cred_ctx(X) ((X)->security)
#define current_ctx() cred_ctx(current_cred())

struct aa_task_ctx {
	struct aa_profile *profile;
	struct aa_profile *onexec;
	struct aa_profile *previous;
	u64 token;
};

static int (*klpe_aa_replace_current_profile)(struct aa_profile *profile);

static inline struct aa_profile *klpr_aa_current_profile(void)
{
	const struct aa_task_ctx *ctx = current_ctx();
	struct aa_profile *profile;

	AA_BUG(!ctx || !ctx->profile);

	if (profile_is_stale(ctx->profile)) {
		profile = aa_get_newest_profile(ctx->profile);
		(*klpe_aa_replace_current_profile)(profile);
		klpr_aa_put_profile(profile);
		ctx = current_ctx();
	}

	return ctx->profile;
}

/* klp-ccp: from security/apparmor/include/policy_unpack.h */
#include <linux/list.h>
#include <linux/kref.h>

struct aa_loaddata {
	struct kref count;
	size_t size;
	int abi;
	unsigned char *hash;
	char data[];
};

static void (*klpe_aa_loaddata_kref)(struct kref *kref);
static inline void klpr_aa_put_loaddata(struct aa_loaddata *data)
{
	if (data)
		kref_put(&data->count, (*klpe_aa_loaddata_kref));
}

/* klp-ccp: from security/apparmor/apparmorfs.c */
static struct aa_loaddata *aa_simple_write_to_buffer(const char __user *userbuf,
						     size_t alloc_size,
						     size_t copy_size,
						     loff_t *pos)
{
	struct aa_loaddata *data;

	AA_BUG(copy_size > alloc_size);

	if (*pos != 0)
		/* only writes from pos 0, that is complete writes */
		return ERR_PTR(-ESPIPE);

	/* freed by caller to simple_write_to_buffer */
	data = kvmalloc(sizeof(*data) + alloc_size, GFP_KERNEL);
	if (data == NULL)
		return ERR_PTR(-ENOMEM);
	kref_init(&data->count);
	data->size = copy_size;
	data->hash = NULL;
	data->abi = 0;

	if (copy_from_user(data->data, userbuf, copy_size)) {
		kvfree(data);
		return ERR_PTR(-EFAULT);
	}

	return data;
}

static ssize_t klpp_policy_update(int binop, const char __user *buf, size_t size,
			     loff_t *pos, struct aa_ns *ns,
			     const struct cred *ocred)
{
	ssize_t error;
	struct aa_loaddata *data;
	struct aa_profile *profile = klpr_aa_current_profile();
	const char *op = binop == PROF_ADD ? OP_PROF_LOAD : OP_PROF_REPL;
	/* high level check about policy management - fine grained in
	 * below after unpack
	 */
	error = klpp_aa_may_manage_policy(profile, ns, ocred, op);
	if (error)
		return error;

	data = aa_simple_write_to_buffer(buf, size, size, pos);
	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		error = (*klpe_aa_replace_profiles)(ns ? ns : profile->ns, profile,
					    binop, data);
		klpr_aa_put_loaddata(data);
	}

	return error;
}

ssize_t klpp_profile_load(struct file *f, const char __user *buf, size_t size,
			    loff_t *pos)
{
	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);
	int error = klpp_policy_update(PROF_ADD, buf, size, pos, ns, f->f_cred);

	klpr_aa_put_ns(ns);

	return error;
}

ssize_t klpp_profile_replace(struct file *f, const char __user *buf,
			       size_t size, loff_t *pos)
{
	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);
	int error = klpp_policy_update(PROF_REPLACE, buf, size, pos, ns, f->f_cred);

	klpr_aa_put_ns(ns);

	return error;
}

ssize_t klpp_profile_remove(struct file *f, const char __user *buf,
			      size_t size, loff_t *pos)
{
	struct aa_loaddata *data;
	struct aa_profile *profile;
	ssize_t error;
	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);

	profile = klpr_aa_current_profile();
	/* high level check about policy management - fine grained in
	 * below after unpack
	 */
	error = klpp_aa_may_manage_policy(profile, ns, f->f_cred, OP_PROF_RM);
	if (error)
		goto out;

	/*
	 * aa_remove_profile needs a null terminated string so 1 extra
	 * byte is allocated and the copied data is null terminated.
	 */
	data = aa_simple_write_to_buffer(buf, size + 1, size, pos);

	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		data->data[size] = 0;
		error = (*klpe_aa_remove_profiles)(ns ? ns : profile->ns, profile,
					   data->data, size);
		klpr_aa_put_loaddata(data);
	}
 out:
	klpr_aa_put_ns(ns);
	return error;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "aa_free_profile_kref", (void *)&klpe_aa_free_profile_kref },
	{ "aa_loaddata_kref", (void *)&klpe_aa_loaddata_kref },
	{ "aa_remove_profiles", (void *)&klpe_aa_remove_profiles },
	{ "aa_replace_current_profile",
	  (void *)&klpe_aa_replace_current_profile },
	{ "aa_replace_profiles", (void *)&klpe_aa_replace_profiles },
};

int bsc1259859_security_apparmor_apparmorfs_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

