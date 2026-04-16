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


/* klp-ccp: from security/apparmor/policy.c */
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/rculist.h>
#include <linux/user_namespace.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_DBUS		32

#define AA_CLASS_LAST		AA_CLASS_DBUS

extern bool aa_g_export_binary;

extern bool aa_g_lock_policy;

/* klp-ccp: from security/apparmor/include/capability.h */
#include <linux/sched.h>

/* klp-ccp: from security/apparmor/include/apparmorfs.h */
struct aa_profile;
struct aa_ns;

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

#define ns_subprofs_dir(X) ((X)->dents[AAFS_NS_PROFS])

#define prof_child_dir(X) ((X)->dents[AAFS_PROF_PROFS])

void __aa_bump_ns_revision(struct aa_ns *ns);
void __aafs_profile_rmdir(struct aa_profile *profile);

int __aafs_profile_mkdir(struct aa_profile *profile, struct dentry *parent);

struct aa_loaddata;

#ifdef CONFIG_SECURITY_APPARMOR_EXPORT_BINARY

int __aa_fs_create_rawdata(struct aa_ns *ns, struct aa_loaddata *rawdata);
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SECURITY_APPARMOR_EXPORT_BINARY */

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

extern struct lsm_blob_sizes apparmor_blob_sizes;

static inline bool aa_strneq(const char *str, const char *sub, int len)
{
	return !strncmp(str, sub, len) && !str[len];
}

struct aa_str_table {
	int size;
	char **table;
};

struct counted_str {
	struct kref count;
	char name[];
};

#define str_to_counted(str) \
	((struct counted_str *)(str - offsetof(struct counted_str, name)))

#define __counted	/* atm just a notation */

void aa_str_kref(struct kref *kref);

static inline __counted char *aa_get_str(__counted char *str)
{
	if (str)
		kref_get(&(str_to_counted(str)->count));

	return str;
}

static inline void aa_put_str(__counted char *str)
{
	if (str)
		kref_put(&str_to_counted(str)->count, aa_str_kref);
}

struct aa_policy {
	const char *name;
	__counted char *hname;
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

/* klp-ccp: from security/apparmor/include/label.h */
#define vec_last(VEC, SIZE) ((VEC)[(SIZE) - 1])
#define vec_ns(VEC, SIZE) (vec_last((VEC), (SIZE))->ns)

struct aa_labelset {
	rwlock_t lock;

	struct rb_root root;
};

enum label_flags {
	FLAG_HAT = 1,			/* profile is a hat */
	FLAG_UNCONFINED = 2,		/* label unconfined only if all */
	FLAG_NULL = 4,			/* profile is null learning profile */
	FLAG_IX_ON_NAME_ERROR = 8,	/* fallback to ix on name lookup fail */
	FLAG_IMMUTIBLE = 0x10,		/* don't allow changes/replacement */
	FLAG_USER_DEFINED = 0x20,	/* user based profile - lower privs */
	FLAG_NO_LIST_REF = 0x40,	/* list doesn't keep profile ref */
	FLAG_NS_COUNT = 0x80,		/* carries NS ref count */
	FLAG_IN_TREE = 0x100,		/* label is in tree */
	FLAG_PROFILE = 0x200,		/* label is a profile */
	FLAG_EXPLICIT = 0x400,		/* explicit static label */
	FLAG_STALE = 0x800,		/* replaced/removed */
	FLAG_RENAMED = 0x1000,		/* label has renaming in it */
	FLAG_REVOKED = 0x2000,		/* label has revocation in it */
	FLAG_DEBUG1 = 0x4000,
	FLAG_DEBUG2 = 0x8000,

	/* These flags must correspond with PATH_flags */
	/* TODO: add new path flags */
};

struct aa_proxy {
	struct kref count;
	struct aa_label __rcu *label;
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

#define label_is_stale(X) ((X)->flags & FLAG_STALE)

#define labels_ns(X) (vec_ns(&((X)->vec[0]), (X)->size))

#define labels_profile(X) ((X)->vec[(X)->size - 1])

void __aa_labelset_update_subtree(struct aa_ns *ns);

void aa_label_kref(struct kref *kref);

bool aa_label_is_subset(struct aa_label *set, struct aa_label *sub);

bool aa_label_remove(struct aa_label *label);

static inline struct aa_label *aa_get_label(struct aa_label *l)
{
	if (l)
		kref_get(&(l->count));

	return l;
}

static inline struct aa_label *aa_get_label_rcu(struct aa_label __rcu **l)
{
	struct aa_label *c;

	rcu_read_lock();
	do {
		c = rcu_dereference(*l);
	} while (c && !kref_get_unless_zero(&c->count));
	rcu_read_unlock();

	return c;
}

static inline struct aa_label *aa_get_newest_label(struct aa_label *l)
{
	if (!l)
		return NULL;

	if (label_is_stale(l)) {
		struct aa_label *tmp;

		AA_BUG(!l->proxy);
		AA_BUG(!l->proxy->label);
		/* BUG: only way this can happen is @l ref count and its
		 * replacement count have gone to 0 and are on their way
		 * to destruction. ie. we have a refcounting error
		 */
		tmp = aa_get_label_rcu(&l->proxy->label);
		AA_BUG(!tmp);

		return tmp;
	}

	return aa_get_label(l);
}

void aa_proxy_kref(struct kref *kref);

static inline void aa_put_proxy(struct aa_proxy *proxy)
{
	if (proxy)
		kref_put(&proxy->count, aa_proxy_kref);
}

/* klp-ccp: from security/apparmor/include/policy_ns.h */
#include <linux/kref.h>
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

#define AA_MAY_WRITE		MAY_WRITE

#define AA_MAY_DELETE		0x0020

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

#define AA_MAY_REPLACE_POLICY	AA_MAY_WRITE
#define AA_MAY_REMOVE_POLICY	AA_MAY_DELETE

struct aa_profile *aa_alloc_null(struct aa_profile *parent, const char *name,
				 gfp_t gfp);

ssize_t klpp_aa_replace_profiles(struct aa_ns *view, struct aa_label *label,
			    u32 mask, struct aa_loaddata *udata);

static inline struct aa_profile *aa_get_newest_profile(struct aa_profile *p)
{
	return labels_profile(aa_get_newest_label(&p->label));
}

static inline struct aa_profile *aa_get_profile(struct aa_profile *p)
{
	if (p)
		kref_get(&(p->label.count));

	return p;
}

static inline void aa_put_profile(struct aa_profile *p)
{
	if (p)
		kref_put(&p->label.count, aa_label_kref);
}

bool aa_policy_admin_capable(struct aa_label *label, struct aa_ns *ns);
int klpp_aa_may_manage_policy(struct aa_label *label, struct aa_ns *ns,
			 const struct cred *ocred, u32 mask);

/* klp-ccp: from security/apparmor/include/policy_ns.h */
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

struct aa_ns *aa_prepare_ns(struct aa_ns *root, const char *name);

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

static inline void aa_put_ns(struct aa_ns *ns)
{
	if (ns)
		aa_put_profile(ns->unconfined);
}

/* klp-ccp: from security/apparmor/include/cred.h */
static inline struct aa_label *cred_label(const struct cred *cred)
{
	struct aa_label **blob = cred->security + apparmor_blob_sizes.lbs_cred;

	AA_BUG(!blob);
	return *blob;
}

/* klp-ccp: from security/apparmor/include/ipc.h */
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/policy_unpack.h */
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/dcache.h>
#include <linux/workqueue.h>

struct aa_load_ent {
	struct list_head list;
	struct aa_profile *new;
	struct aa_profile *old;
	struct aa_profile *rename;
	const char *ns_name;
};

void aa_load_ent_free(struct aa_load_ent *ent);

enum {
	AAFS_LOADDATA_ABI = 0,
	AAFS_LOADDATA_REVISION,
	AAFS_LOADDATA_HASH,
	AAFS_LOADDATA_DATA,
	AAFS_LOADDATA_COMPRESSED_SIZE,
	AAFS_LOADDATA_DIR,		/* must be last actual entry */
	AAFS_LOADDATA_NDENTS		/* count of entries */
};

struct aa_loaddata {
	struct kref count;
	struct list_head list;
	struct work_struct work;
	struct dentry *dents[AAFS_LOADDATA_NDENTS];
	struct aa_ns *ns;
	char *name;
	size_t size;			/* the original size of the payload */
	size_t compressed_size;		/* the compressed size of the payload */
	long revision;			/* the ns policy revision this caused */
	int abi;
	unsigned char *hash;

	/* Pointer to payload. If @compressed_size > 0, then this is the
	 * compressed version of the payload, else it is the uncompressed
	 * version (with the size indicated by @size).
	 */
	char *data;
};

int aa_unpack(struct aa_loaddata *udata, struct list_head *lh, const char **ns);

static inline struct aa_loaddata *
__aa_get_loaddata(struct aa_loaddata *data)
{
	if (data && kref_get_unless_zero(&(data->count)))
		return data;

	return NULL;
}

static inline struct aa_loaddata *
aa_get_loaddata(struct aa_loaddata *data)
{
	struct aa_loaddata *tmp = __aa_get_loaddata(data);

	AA_BUG(data && !tmp);

	return tmp;
}

void __aa_loaddata_update(struct aa_loaddata *data, long revision);
bool aa_rawdata_eq(struct aa_loaddata *l, struct aa_loaddata *r);
void aa_loaddata_kref(struct kref *kref);

static inline void aa_put_loaddata(struct aa_loaddata *data)
{
	if (data)
		kref_put(&data->count, aa_loaddata_kref);
}

/* klp-ccp: from security/apparmor/policy.c */
extern void __add_profile(struct list_head *list, struct aa_profile *profile);

static void __list_remove_profile(struct aa_profile *profile)
{
	AA_BUG(!profile);
	AA_BUG(!profile->ns);
	AA_BUG(!mutex_is_locked(&profile->ns->lock));

	list_del_rcu(&profile->base.list);
	aa_put_profile(profile);
}

void klpp___remove_profile(struct aa_profile *profile)
{
	struct aa_profile *curr, *to_remove;

	AA_BUG(!profile);
	AA_BUG(!profile->ns);
	AA_BUG(!mutex_is_locked(&profile->ns->lock));

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
			aa_label_remove(&to_remove->label);
			__aafs_profile_rmdir(to_remove);
			__list_remove_profile(to_remove);
		}
	}

	/* released by free_profile */
	aa_label_remove(&profile->label);
	__aafs_profile_rmdir(profile);
	__list_remove_profile(profile);
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

static struct aa_policy *__create_missing_ancestors(struct aa_ns *ns,
						    const char *hname,
						    gfp_t gfp)
{
	struct aa_policy *policy;
	struct aa_profile *parent, *profile = NULL;
	char *split;

	AA_BUG(!ns);
	AA_BUG(!hname);

	policy = &ns->base;

	for (split = strstr(hname, "//"); split;) {
		parent = profile;
		profile = __strn_find_child(&policy->profiles, hname,
					    split - hname);
		if (!profile) {
			const char *name = kstrndup(hname, split - hname,
						    gfp);
			if (!name)
				return NULL;
			profile = aa_alloc_null(parent, name, gfp);
			kfree(name);
			if (!profile)
				return NULL;
			if (!parent)
				profile->ns = aa_get_ns(ns);
		}
		policy = &profile->base;
		hname = split + 2;
		split = strstr(hname, "//");
	}
	if (!profile)
		return &ns->base;
	return &profile->base;
}

extern struct aa_profile *__lookup_profile(struct aa_policy *base,
					   const char *hname);

struct aa_profile *aa_alloc_null(struct aa_profile *parent, const char *name,
				 gfp_t gfp);

static int replacement_allowed(struct aa_profile *profile, int noreplace,
			       const char **info)
{
	if (profile) {
		if (profile->label.flags & FLAG_IMMUTIBLE) {
			*info = "cannot replace immutable profile";
			return -EPERM;
		} else if (noreplace) {
			*info = "profile already exists";
			return -EEXIST;
		}
	}
	return 0;
}

extern int audit_policy(struct aa_label *label, const char *op,
			const char *ns_name, const char *name,
			const char *info, int error);

bool aa_policy_admin_capable(struct aa_label *label, struct aa_ns *ns);

bool klpp_is_subset_of_obj_privilege(const struct cred *cred,
				       struct aa_label *label,
				       const struct cred *ocred)
{
	if (cred == ocred)
		return true;

	if (!aa_label_is_subset(label, cred_label(ocred)))
		return false;
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

int klpp_aa_may_manage_policy(struct aa_label *label, struct aa_ns *ns,
			 const struct cred *ocred, u32 mask)
{
	const char *op;

	if (mask & AA_MAY_REMOVE_POLICY)
		op = OP_PROF_RM;
	else if (mask & AA_MAY_REPLACE_POLICY)
		op = OP_PROF_REPL;
	else
		op = OP_PROF_LOAD;

	/* check if loading policy is locked out */
	if (aa_g_lock_policy)
		return audit_policy(label, op, NULL, NULL, "policy_locked",
				    -EACCES);

	if (ocred && !klpp_is_subset_of_obj_privilege(current_cred(), label, ocred))
		return audit_policy(label, op, NULL, NULL,
				    "not privileged for target profile",
				    -EACCES);

	if (!aa_policy_admin_capable(label, ns))
		return audit_policy(label, op, NULL, NULL, "not policy admin",
				    -EACCES);

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

extern void __replace_profile(struct aa_profile *old, struct aa_profile *new);

static int __lookup_replace(struct aa_ns *ns, const char *hname,
			    bool noreplace, struct aa_profile **p,
			    const char **info)
{
	*p = aa_get_profile(__lookup_profile(&ns->base, hname));
	if (*p) {
		int error = replacement_allowed(*p, noreplace, info);
		if (error) {
			*info = "profile can not be replaced";
			return error;
		}
	}

	return 0;
}

static void share_name(struct aa_profile *old, struct aa_profile *new)
{
	aa_put_str(new->base.hname);
	aa_get_str(old->base.hname);
	new->base.hname = old->base.hname;
	new->base.name = old->base.name;
	new->label.hname = old->label.hname;
}

static struct aa_profile *update_to_newest_parent(struct aa_profile *new)
{
	struct aa_profile *parent, *newest;

	parent = rcu_dereference_protected(new->parent,
					   mutex_is_locked(&new->ns->lock));
	newest = aa_get_newest_profile(parent);

	/* parent replaced in this atomic set? */
	if (newest != parent) {
		aa_put_profile(parent);
		rcu_assign_pointer(new->parent, newest);
	} else
		aa_put_profile(newest);

	return newest;
}

ssize_t klpp_aa_replace_profiles(struct aa_ns *policy_ns, struct aa_label *label,
			    u32 mask, struct aa_loaddata *udata)
{
	const char *ns_name = NULL, *info = NULL;
	struct aa_ns *ns = NULL;
	struct aa_load_ent *ent, *tmp;
	struct aa_loaddata *rawdata_ent;
	const char *op;
	ssize_t count, error;
	LIST_HEAD(lh);

	op = mask & AA_MAY_REPLACE_POLICY ? OP_PROF_REPL : OP_PROF_LOAD;
	aa_get_loaddata(udata);
	/* released below */
	error = aa_unpack(udata, &lh, &ns_name);
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
		ns = aa_prepare_ns(policy_ns ? policy_ns : labels_ns(label),
				   ns_name);
		if (IS_ERR(ns)) {
			op = OP_PROF_LOAD;
			info = "failed to prepare namespace";
			error = PTR_ERR(ns);
			ns = NULL;
			ent = NULL;
			goto fail;
		}
	} else
		ns = aa_get_ns(policy_ns ? policy_ns : labels_ns(label));

	mutex_lock_nested(&ns->lock, ns->level);
	/* check for duplicate rawdata blobs: space and file dedup */
	if (!list_empty(&ns->rawdata_list)) {
		list_for_each_entry(rawdata_ent, &ns->rawdata_list, list) {
			if (aa_rawdata_eq(rawdata_ent, udata)) {
				struct aa_loaddata *tmp;

				tmp = __aa_get_loaddata(rawdata_ent);
				/* check we didn't fail the race */
				if (tmp) {
					aa_put_loaddata(udata);
					udata = tmp;
					break;
				}
			}
		}
	}
	/* setup parent and ns info */
	list_for_each_entry(ent, &lh, list) {
		struct aa_policy *policy;
		struct aa_profile *p;

		if (aa_g_export_binary)
			ent->new->rawdata = aa_get_loaddata(udata);
		error = __lookup_replace(ns, ent->new->base.hname,
					 !(mask & AA_MAY_REPLACE_POLICY),
					 &ent->old, &info);
		if (error)
			goto fail_lock;

		if (ent->new->rename) {
			error = __lookup_replace(ns, ent->new->rename,
						!(mask & AA_MAY_REPLACE_POLICY),
						&ent->rename, &info);
			if (error)
				goto fail_lock;
		}

		/* released when @new is freed */
		ent->new->ns = aa_get_ns(ns);

		if (ent->old || ent->rename)
			continue;

		/* no ref on policy only use inside lock */
		p = NULL;
		policy = __lookup_parent(ns, ent->new->base.hname);
		if (!policy) {
			/* first check for parent in the load set */
			p = __list_lookup_parent(&lh, ent->new);
			if (!p) {
				/*
				 * fill in missing parent with null
				 * profile that doesn't have
				 * permissions. This allows for
				 * individual profile loading where
				 * the child is loaded before the
				 * parent, and outside of the current
				 * atomic set. This unfortunately can
				 * happen with some userspaces.  The
				 * null profile will be replaced once
				 * the parent is loaded.
				 */
				policy = __create_missing_ancestors(ns,
							ent->new->base.hname,
							GFP_KERNEL);
				if (!policy) {
					error = -ENOENT;
					info = "parent does not exist";
					goto fail_lock;
				}
			}
		}
		if (!p && policy != &ns->base)
			/* released on profile replacement or free_profile */
			p = (struct aa_profile *) policy;
		rcu_assign_pointer(ent->new->parent, aa_get_profile(p));
	}

	/* create new fs entries for introspection if needed */
	if (!udata->dents[AAFS_LOADDATA_DIR] && aa_g_export_binary) {
		error = __aa_fs_create_rawdata(ns, udata);
		if (error) {
			info = "failed to create raw_data dir and files";
			ent = NULL;
			goto fail_lock;
		}
	}
	list_for_each_entry(ent, &lh, list) {
		if (!ent->old) {
			struct dentry *parent;
			if (rcu_access_pointer(ent->new->parent)) {
				struct aa_profile *p;
				p = aa_deref_parent(ent->new);
				parent = prof_child_dir(p);
			} else
				parent = ns_subprofs_dir(ent->new->ns);
			error = __aafs_profile_mkdir(ent->new, parent);
		}

		if (error) {
			info = "failed to create";
			goto fail_lock;
		}
	}

	/* Done with checks that may fail - do actual replacement */
	__aa_bump_ns_revision(ns);
	if (aa_g_export_binary)
		__aa_loaddata_update(udata, ns->revision);
	list_for_each_entry_safe(ent, tmp, &lh, list) {
		list_del_init(&ent->list);
		op = (!ent->old && !ent->rename) ? OP_PROF_LOAD : OP_PROF_REPL;

		if (ent->old && ent->old->rawdata == ent->new->rawdata &&
		    ent->new->rawdata) {
			/* dedup actual profile replacement */
			audit_policy(label, op, ns_name, ent->new->base.hname,
				     "same as current profile, skipping",
				     error);
			/* break refcount cycle with proxy. */
			aa_put_proxy(ent->new->label.proxy);
			ent->new->label.proxy = NULL;
			goto skip;
		}

		/*
		 * TODO: finer dedup based on profile range in data. Load set
		 * can differ but profile may remain unchanged
		 */
		audit_policy(label, op, ns_name, ent->new->base.hname, NULL,
			     error);

		if (ent->old) {
			share_name(ent->old, ent->new);
			__replace_profile(ent->old, ent->new);
		} else {
			struct list_head *lh;

			if (rcu_access_pointer(ent->new->parent)) {
				struct aa_profile *parent;

				parent = update_to_newest_parent(ent->new);
				lh = &parent->base.profiles;
			} else
				lh = &ns->base.profiles;
			__add_profile(lh, ent->new);
		}
	skip:
		aa_load_ent_free(ent);
	}
	__aa_labelset_update_subtree(ns);
	mutex_unlock(&ns->lock);

out:
	aa_put_ns(ns);
	aa_put_loaddata(udata);
	kfree(ns_name);

	if (error)
		return error;
	return udata->size;

fail_lock:
	mutex_unlock(&ns->lock);

	/* audit cause of failure */
	op = (ent && !ent->old) ? OP_PROF_LOAD : OP_PROF_REPL;
fail:
	  audit_policy(label, op, ns_name, ent ? ent->new->base.hname : NULL,
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
		audit_policy(label, op, ns_name, tmp->new->base.hname, info,
			     error);
	}
	list_for_each_entry_safe(ent, tmp, &lh, list) {
		list_del_init(&ent->list);
		aa_load_ent_free(ent);
	}

	goto out;
}


#include <linux/livepatch.h>

extern typeof(__aa_bump_ns_revision) __aa_bump_ns_revision
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aa_bump_ns_revision);
extern typeof(__aa_fs_create_rawdata) __aa_fs_create_rawdata
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aa_fs_create_rawdata);
extern typeof(__aa_labelset_update_subtree) __aa_labelset_update_subtree
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aa_labelset_update_subtree);
extern typeof(__aa_loaddata_update) __aa_loaddata_update
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aa_loaddata_update);
extern typeof(__aafs_profile_mkdir) __aafs_profile_mkdir
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aafs_profile_mkdir);
extern typeof(__aafs_profile_rmdir) __aafs_profile_rmdir
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __aafs_profile_rmdir);
extern typeof(__add_profile) __add_profile
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __add_profile);
extern typeof(__lookup_profile) __lookup_profile
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __lookup_profile);
extern typeof(__replace_profile) __replace_profile
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __replace_profile);
extern typeof(aa_alloc_null) aa_alloc_null
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_alloc_null);
extern typeof(aa_g_export_binary) aa_g_export_binary
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_g_export_binary);
extern typeof(aa_g_lock_policy) aa_g_lock_policy
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_g_lock_policy);
extern typeof(aa_label_is_subset) aa_label_is_subset
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_label_is_subset);
extern typeof(aa_label_kref) aa_label_kref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_label_kref);
extern typeof(aa_label_remove) aa_label_remove
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_label_remove);
extern typeof(aa_load_ent_free) aa_load_ent_free
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_load_ent_free);
extern typeof(aa_loaddata_kref) aa_loaddata_kref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_loaddata_kref);
extern typeof(aa_policy_admin_capable) aa_policy_admin_capable
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_policy_admin_capable);
extern typeof(aa_prepare_ns) aa_prepare_ns
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_prepare_ns);
extern typeof(aa_proxy_kref) aa_proxy_kref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_proxy_kref);
extern typeof(aa_rawdata_eq) aa_rawdata_eq
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_rawdata_eq);
extern typeof(aa_str_kref) aa_str_kref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_str_kref);
extern typeof(aa_unpack) aa_unpack KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_unpack);
extern typeof(apparmor_blob_sizes) apparmor_blob_sizes
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, apparmor_blob_sizes);
extern typeof(audit_policy) audit_policy
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, audit_policy);
