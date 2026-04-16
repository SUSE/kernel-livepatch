/*
 * bsc1259859_security_apparmor_policy
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

/* klp-ccp: from security/apparmor/policy.c */
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/rculist.h>
#include <linux/user_namespace.h>
#include <linux/printk.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_DOMAIN		6

#define AA_CLASS_LAST		AA_CLASS_DOMAIN

static bool (*klpe_aa_g_lock_policy);

/* klp-ccp: from security/apparmor/include/capability.h */
#include <linux/sched.h>

/* klp-ccp: from security/apparmor/include/apparmorfs.h */
struct aa_profile;

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

#define ns_subprofs_dir(X) ((X)->dents[AAFS_NS_PROFS])

#define prof_child_dir(X) ((X)->dents[AAFS_PROF_PROFS])

static void (*klpe___aa_fs_profile_rmdir)(struct aa_profile *profile);

static int (*klpe___aa_fs_profile_mkdir)(struct aa_profile *profile, struct dentry *parent);

/* klp-ccp: from security/apparmor/include/capability.h */
struct aa_caps {
	kernel_cap_t allow;
	kernel_cap_t audit;
	kernel_cap_t quiet;
	kernel_cap_t kill;
	kernel_cap_t extended;
};

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

#define OP_PROF_REPL "profile_replace"
#define OP_PROF_LOAD "profile_load"

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

static inline const char *basename(const char *hname)
{
	char *split;

	hname = strim((char *)hname);
	for (split = strstr(hname, "//"); split; split = strstr(hname, "//"))
		hname = split + 2;

	return hname;
}

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

static void (*klpe___aa_update_proxy)(struct aa_profile *orig, struct aa_profile *new);

static void (*klpe_aa_free_profile_kref)(struct kref *kref);

ssize_t klpp_aa_replace_profiles(struct aa_ns *view, struct aa_profile *profile,
			    bool noreplace, struct aa_loaddata *udata);

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

static bool (*klpe_policy_admin_capable)(struct aa_ns *ns);
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

static struct aa_ns *(*klpe_aa_prepare_ns)(struct aa_ns *root, const char *name);

static inline struct aa_profile *aa_deref_parent(struct aa_profile *p)
{
	return rcu_dereference_protected(p->parent,
					 mutex_is_locked(&p->ns->lock));
}

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

/* klp-ccp: from security/apparmor/include/ipc.h */
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/path.h */
#include <linux/percpu.h>
#include <linux/preempt.h>
/* klp-ccp: from security/apparmor/include/policy_unpack.h */
#include <linux/list.h>
#include <linux/kref.h>

struct aa_load_ent {
	struct list_head list;
	struct aa_profile *new;
	struct aa_profile *old;
	struct aa_profile *rename;
	const char *ns_name;
};

static void (*klpe_aa_load_ent_free)(struct aa_load_ent *ent);

struct aa_loaddata {
	struct kref count;
	size_t size;
	int abi;
	unsigned char *hash;
	char data[];
};

static int (*klpe_aa_unpack)(struct aa_loaddata *udata, struct list_head *lh, const char **ns);

static inline struct aa_loaddata *
aa_get_loaddata(struct aa_loaddata *data)
{
	if (data)
		kref_get(&(data->count));
	return data;
}

/* klp-ccp: from security/apparmor/policy.c */
static void __list_add_profile(struct list_head *list,
			       struct aa_profile *profile)
{
	list_add_rcu(&profile->base.list, list);
	/* get list reference */
	aa_get_profile(profile);
}

static void klpr___list_remove_profile(struct aa_profile *profile)
{
	list_del_rcu(&profile->base.list);
	klpr_aa_put_profile(profile);
}

void klpp___remove_profile(struct aa_profile *profile)
{
	struct aa_profile *curr, *to_remove;

	/* release any children lists first */
	if (!list_empty(&profile->base.profiles)) {
		curr = list_first_entry(&profile->base.profiles, struct aa_profile, base.list);

		while (curr != profile) {

			while (!list_empty(&curr->base.profiles))
				curr = list_first_entry(&curr->base.profiles,
							struct aa_profile, base.list);

			to_remove = curr;
			if (!list_is_last(&to_remove->base.list,
					  &aa_deref_parent(curr)->base.profiles))
				curr = list_next_entry(to_remove, base.list);
			else
				curr = aa_deref_parent(curr);

			/* released by free_profile */
			(*klpe___aa_update_proxy)(to_remove, to_remove->ns->unconfined);
			(*klpe___aa_fs_profile_rmdir)(to_remove);
			klpr___list_remove_profile(to_remove);
		}
	}

	/* released by free_profile */
	(*klpe___aa_update_proxy)(profile, profile->ns->unconfined);
	(*klpe___aa_fs_profile_rmdir)(profile);
	klpr___list_remove_profile(profile);
}
static struct aa_profile *__strn_find_child(struct list_head *head,
					    const char *name, int len)
{
	return (struct aa_profile *)__policy_strn_find(head, name, len);
}

static struct aa_policy *__lookup_parent(struct aa_ns *ns,
					 const char *hname)
{
	struct aa_policy *policy;
	struct aa_profile *profile = NULL;
	char *split;

	policy = &ns->base;

	for (split = strstr(hname, "//"); split;) {
		profile = __strn_find_child(&policy->profiles, hname,
					    split - hname);
		if (!profile)
			return NULL;
		policy = &profile->base;
		hname = split + 2;
		split = strstr(hname, "//");
	}
	if (!profile)
		return &ns->base;
	return &profile->base;
}

static int (*klpe_audit_policy)(struct aa_profile *profile, const char *op,
			const char *nsname, const char *name,
			const char *info, int error);

bool klpp_is_subset_of_obj_privilege(const struct cred *cred,
				       const struct cred *ocred)
{
	if (cred == ocred)
		return true;

	/* don't allow crossing userns for now */
	if (cred->user_ns != ocred->user_ns)
		return false;
	if (!cap_issubset(cred->cap_inheritable, ocred->cap_inheritable))
		return false;
	if (!cap_issubset(cred->cap_permitted, ocred->cap_permitted))
		return false;
	if (!cap_issubset(cred->cap_effective, ocred->cap_effective))
		return false;
	if (!cap_issubset(cred->cap_bset, ocred->cap_bset))
		return false;
	if (!cap_issubset(cred->cap_ambient, ocred->cap_ambient))
		return false;
	return true;
}

int klpp_aa_may_manage_policy(struct aa_profile *profile, struct aa_ns *ns,
			 const struct cred *ocred, const char *op)
{
	/* check if loading policy is locked out */
	if ((*klpe_aa_g_lock_policy))
		return (*klpe_audit_policy)(profile, op, NULL, NULL,
			     "policy_locked", -EACCES);

	if (ocred && !klpp_is_subset_of_obj_privilege(current_cred(), ocred))
		return (*klpe_audit_policy)(profile, op, NULL, NULL,
				    "not privileged for target profile",
				    -EACCES);

	if (!(*klpe_policy_admin_capable)(ns))
		return (*klpe_audit_policy)(profile, op, NULL, NULL,
				    "not policy admin", -EACCES);

	/* TODO: add fine grained mediation of policy loads */
	return 0;
}

static struct aa_profile *__list_lookup_parent(struct list_head *lh,
					       struct aa_profile *profile)
{
	const char *base = basename(profile->base.hname);
	long len = base - profile->base.hname;
	struct aa_load_ent *ent;

	/* parent won't have trailing // so remove from len */
	if (len <= 2)
		return NULL;
	len -= 2;

	list_for_each_entry(ent, lh, list) {
		if (ent->new == profile)
			continue;
		if (strncmp(ent->new->base.hname, profile->base.hname, len) ==
		    0 && ent->new->base.hname[len] == 0)
			return ent->new;
	}

	return NULL;
}

static void (*klpe___replace_profile)(struct aa_profile *old, struct aa_profile *new,
			      bool share_proxy);

static int (*klpe___lookup_replace)(struct aa_ns *ns, const char *hname,
			    bool noreplace, struct aa_profile **p,
			    const char **info);

ssize_t klpp_aa_replace_profiles(struct aa_ns *view, struct aa_profile *profile,
			    bool noreplace, struct aa_loaddata *udata)
{
	const char *ns_name, *info = NULL;
	struct aa_ns *ns = NULL;
	struct aa_load_ent *ent, *tmp;
	const char *op = OP_PROF_REPL;
	ssize_t count, error;
	LIST_HEAD(lh);

	/* released below */
	error = (*klpe_aa_unpack)(udata, &lh, &ns_name);
	if (error)
		goto out;

	/* ensure that profiles are all for the same ns
	 * TODO: update locking to remove this constaint. All profiles in
	 *       the load set must succeed as a set or the load will
	 *       fail. Sort ent list and take ns locks in hierarchy order
	 */
	count = 0;
	list_for_each_entry(ent, &lh, list) {
		if (ns_name) {
			if (ent->ns_name &&
			    strcmp(ent->ns_name, ns_name) != 0) {
				info = "policy load has mixed namespaces";
				error = -EACCES;
				goto fail;
			}
		} else if (ent->ns_name) {
			if (count) {
				info = "policy load has mixed namespaces";
				error = -EACCES;
				goto fail;
			}
			ns_name = ent->ns_name;
			ent->ns_name = NULL;
		} else
			count++;
	}
	if (ns_name) {
		ns = (*klpe_aa_prepare_ns)(view, ns_name);
		if (IS_ERR(ns)) {
			op = OP_PROF_LOAD;
			info = "failed to prepare namespace";
			error = PTR_ERR(ns);
			ns = NULL;
			ent = NULL;
			goto fail;
		}
	} else
		ns = aa_get_ns(view);

	mutex_lock(&ns->lock);
	/* setup parent and ns info */
	list_for_each_entry(ent, &lh, list) {
		struct aa_policy *policy;
		ent->new->rawdata = aa_get_loaddata(udata);
		error = (*klpe___lookup_replace)(ns, ent->new->base.hname, noreplace,
					 &ent->old, &info);
		if (error)
			goto fail_lock;

		if (ent->new->rename) {
			error = (*klpe___lookup_replace)(ns, ent->new->rename,
						 noreplace, &ent->rename,
						 &info);
			if (error)
				goto fail_lock;
		}

		/* released when @new is freed */
		ent->new->ns = aa_get_ns(ns);

		if (ent->old || ent->rename)
			continue;

		/* no ref on policy only use inside lock */
		policy = __lookup_parent(ns, ent->new->base.hname);
		if (!policy) {
			struct aa_profile *p;
			p = __list_lookup_parent(&lh, ent->new);
			if (!p) {
				error = -ENOENT;
				info = "parent does not exist";
				goto fail_lock;
			}
			rcu_assign_pointer(ent->new->parent, aa_get_profile(p));
		} else if (policy != &ns->base) {
			/* released on profile replacement or free_profile */
			struct aa_profile *p = (struct aa_profile *) policy;
			rcu_assign_pointer(ent->new->parent, aa_get_profile(p));
		}
	}

	/* create new fs entries for introspection if needed */
	list_for_each_entry(ent, &lh, list) {
		if (ent->old) {
			/* inherit old interface files */

			/* if (ent->rename)
				TODO: support rename */
		/* } else if (ent->rename) {
			TODO: support rename */
		} else {
			struct dentry *parent;
			if (rcu_access_pointer(ent->new->parent)) {
				struct aa_profile *p;
				p = aa_deref_parent(ent->new);
				parent = prof_child_dir(p);
			} else
				parent = ns_subprofs_dir(ent->new->ns);
			error = (*klpe___aa_fs_profile_mkdir)(ent->new, parent);
		}

		if (error) {
			info = "failed to create ";
			goto fail_lock;
		}
	}

	/* Done with checks that may fail - do actual replacement */
	list_for_each_entry_safe(ent, tmp, &lh, list) {
		list_del_init(&ent->list);
		op = (!ent->old && !ent->rename) ? OP_PROF_LOAD : OP_PROF_REPL;

		(*klpe_audit_policy)(profile, op, NULL, ent->new->base.hname,
			     NULL, error);

		if (ent->old) {
			(*klpe___replace_profile)(ent->old, ent->new, 1);
			if (ent->rename) {
				/* aafs interface uses proxy */
				struct aa_proxy *r = ent->new->proxy;
				rcu_assign_pointer(r->profile,
						   aa_get_profile(ent->new));
				(*klpe___replace_profile)(ent->rename, ent->new, 0);
			}
		} else if (ent->rename) {
			/* aafs interface uses proxy */
			rcu_assign_pointer(ent->new->proxy->profile,
					   aa_get_profile(ent->new));
			(*klpe___replace_profile)(ent->rename, ent->new, 0);
		} else if (ent->new->parent) {
			struct aa_profile *parent, *newest;
			parent = aa_deref_parent(ent->new);
			newest = aa_get_newest_profile(parent);

			/* parent replaced in this atomic set? */
			if (newest != parent) {
				aa_get_profile(newest);
				rcu_assign_pointer(ent->new->parent, newest);
				klpr_aa_put_profile(parent);
			}
			/* aafs interface uses proxy */
			rcu_assign_pointer(ent->new->proxy->profile,
					   aa_get_profile(ent->new));
			__list_add_profile(&newest->base.profiles, ent->new);
			klpr_aa_put_profile(newest);
		} else {
			/* aafs interface uses proxy */
			rcu_assign_pointer(ent->new->proxy->profile,
					   aa_get_profile(ent->new));
			__list_add_profile(&ns->base.profiles, ent->new);
		}
		(*klpe_aa_load_ent_free)(ent);
	}
	mutex_unlock(&ns->lock);

out:
	klpr_aa_put_ns(ns);

	if (error)
		return error;
	return udata->size;

fail_lock:
	mutex_unlock(&ns->lock);

	/* audit cause of failure */
	op = (!ent->old) ? OP_PROF_LOAD : OP_PROF_REPL;
fail:
	(*klpe_audit_policy)(profile, op, ns_name, ent ? ent->new->base.hname : NULL,
		     info, error);
	/* audit status that rest of profiles in the atomic set failed too */
	info = "valid profile in failed atomic policy load";
	list_for_each_entry(tmp, &lh, list) {
		if (tmp == ent) {
			info = "unchecked profile in failed atomic policy load";
			/* skip entry that caused failure */
			continue;
		}
		op = (!tmp->old) ? OP_PROF_LOAD : OP_PROF_REPL;
		(*klpe_audit_policy)(profile, op, ns_name,
			     tmp->new->base.hname, info, error);
	}
	list_for_each_entry_safe(ent, tmp, &lh, list) {
		list_del_init(&ent->list);
		(*klpe_aa_load_ent_free)(ent);
	}

	goto out;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__aa_fs_profile_mkdir", (void *)&klpe___aa_fs_profile_mkdir },
	{ "__aa_fs_profile_rmdir", (void *)&klpe___aa_fs_profile_rmdir },
	{ "__aa_update_proxy", (void *)&klpe___aa_update_proxy },
	{ "__lookup_replace", (void *)&klpe___lookup_replace },
	{ "__replace_profile", (void *)&klpe___replace_profile },
	{ "aa_free_profile_kref", (void *)&klpe_aa_free_profile_kref },
	{ "aa_g_lock_policy", (void *)&klpe_aa_g_lock_policy },
	{ "aa_load_ent_free", (void *)&klpe_aa_load_ent_free },
	{ "aa_prepare_ns", (void *)&klpe_aa_prepare_ns },
	{ "aa_unpack", (void *)&klpe_aa_unpack },
	{ "audit_policy", (void *)&klpe_audit_policy },
	{ "policy_admin_capable", (void *)&klpe_policy_admin_capable },
};

int bsc1259859_security_apparmor_policy_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

