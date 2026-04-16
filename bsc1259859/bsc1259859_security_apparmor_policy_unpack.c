/*
 * bsc1259859_security_apparmor_policy_unpack
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

/* klp-ccp: from security/apparmor/policy_unpack.c */
#include <asm/unaligned.h>
#include <linux/ctype.h>
#include <linux/errno.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_FILE		2

#define AA_CLASS_DOMAIN		6

#define AA_CLASS_LAST		AA_CLASS_DOMAIN

static bool (*klpe_aa_g_hash_policy);

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

static void (*klpe_aa_free_domain_entries)(struct aa_domain *domain);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __AA_DOMAIN_H */

/* klp-ccp: from security/apparmor/include/match.h */
#include <linux/kref.h>

#define DFA_START			1

#define	YYTD_ID_ACCEPT	0
#define YYTD_ID_BASE	1

#define YYTD_ID_TSIZE	8

struct table_header {
	u16 td_id;
	u16 td_flags;
	u32 td_hilen;
	u32 td_lolen;
	char td_data[];
};

#define ACCEPT_TABLE(DFA) ((u32 *)((DFA)->tables[YYTD_ID_ACCEPT]->td_data))

struct aa_dfa {
	struct kref count;
	u16 flags;
	struct table_header *tables[YYTD_ID_TSIZE];
};

static struct aa_dfa *(*klpe_nulldfa);

static unsigned int (*klpe_aa_dfa_next)(struct aa_dfa *dfa, unsigned int state,
			 const char c);

static inline struct aa_dfa *aa_get_dfa(struct aa_dfa *dfa)
{
	if (dfa)
		kref_get(&(dfa->count));

	return dfa;
}

/* klp-ccp: from security/apparmor/include/file.h */
#define AA_X_INDEX_MASK		0x03ff

#define AA_X_TYPE_MASK		0x0c00

#define AA_X_NAME		0x0400	/* use executable name px */
#define AA_X_TABLE		0x0800	/* use a specified name ->n# */

#define AA_X_UNSAFE		0x1000
#define AA_X_CHILD		0x2000	/* make >AA_X_NONE apply to children */
#define AA_X_INHERIT		0x4000
#define AA_X_UNCONFINED		0x8000

static inline u16 dfa_map_xindex(u16 mask)
{
	u16 old_index = (mask >> 10) & 0xf;
	u16 index = 0;

	if (mask & 0x100)
		index |= AA_X_UNSAFE;
	if (mask & 0x200)
		index |= AA_X_INHERIT;
	if (mask & 0x80)
		index |= AA_X_UNCONFINED;

	if (old_index == 1) {
		index |= AA_X_UNCONFINED;
	} else if (old_index == 2) {
		index |= AA_X_NAME;
	} else if (old_index == 3) {
		index |= AA_X_NAME | AA_X_CHILD;
	} else if (old_index) {
		index |= AA_X_TABLE;
		index |= old_index - 4;
	}

	return index;
}

#define dfa_user_xindex(dfa, state) \
	(dfa_map_xindex(ACCEPT_TABLE(dfa)[state] & 0x3fff))

#define dfa_other_xindex(dfa, state) \
	dfa_map_xindex((ACCEPT_TABLE(dfa)[state] >> 14) & 0x3fff)

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

enum audit_type {
	AUDIT_APPARMOR_AUDIT,
	AUDIT_APPARMOR_ALLOWED,
	AUDIT_APPARMOR_DENIED,
	AUDIT_APPARMOR_HINT,
	AUDIT_APPARMOR_STATUS,
	AUDIT_APPARMOR_ERROR,
	AUDIT_APPARMOR_KILL,
	AUDIT_APPARMOR_AUTO
};

struct apparmor_audit_data {
	int error;
	const char *op;
	int type;
	void *profile;
	const char *name;
	const char *info;
	union {
		/* these entries require a custom callback fn */
		struct {
			struct aa_profile *peer;
			struct {
				const char *target;
				u32 request;
				u32 denied;
				kuid_t ouid;
			} fs;
			struct {
				int type, protocol;
				struct sock *sk;
			} net;
		};
		struct {
			const char *name;
			long pos;
			const char *ns;
		} iface;
		struct {
			int rlim;
			unsigned long max;
		} rlim;
	};
};

#define aad(SA) ((SA)->apparmor_audit_data)
#define DEFINE_AUDIT_DATA(NAME, T, X)					\
	/* TODO: cleanup audit init so we don't need _aad = {0,} */	\
	struct apparmor_audit_data NAME ## _aad = { .op = (X), };	\
	struct common_audit_data NAME =					\
	{								\
	.type = (T),							\
	.u.tsk = NULL,							\
	};								\
	NAME.apparmor_audit_data = &(NAME ## _aad)

static int (*klpe_aa_audit)(int type, struct aa_profile *profile, struct common_audit_data *sa,
	     void (*cb) (struct audit_buffer *, void *));

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

/* klp-ccp: from security/apparmor/include/apparmorfs.h */
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

static const char *(*klpe_aa_splitn_fqname)(const char *fqname, size_t n, const char **ns_name,
			     size_t *ns_len);

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

static int (*klpe_aa_map_resource)(int resource);

/* klp-ccp: from security/apparmor/include/policy.h */
enum profile_mode {
	APPARMOR_ENFORCE,	/* enforce access rules */
	APPARMOR_COMPLAIN,	/* allow and log access violations */
	APPARMOR_KILL,		/* kill task on access violation */
	APPARMOR_UNCONFINED,	/* profile set to unconfined */
};

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

struct aa_data {
	char *key;
	u32 size;
	char *data;
	struct rhash_head head;
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

static struct aa_profile *(*klpe_aa_alloc_profile)(const char *name, gfp_t gfp);

static void (*klpe_aa_free_profile)(struct aa_profile *profile);
static void (*klpe_aa_free_profile_kref)(struct kref *kref);

static inline void klpr_aa_put_profile(struct aa_profile *p)
{
	if (p)
		kref_put(&p->count, (*klpe_aa_free_profile_kref));
}

/* klp-ccp: from security/apparmor/include/policy_ns.h */
#include <linux/kref.h>

/* klp-ccp: from security/apparmor/include/context.h */
#define cred_ctx(X) ((X)->security)

struct aa_task_ctx {
	struct aa_profile *profile;
	struct aa_profile *onexec;
	struct aa_profile *previous;
	u64 token;
};

static inline struct aa_profile *aa_cred_profile(const struct cred *cred)
{
	struct aa_task_ctx *ctx = cred_ctx(cred);

	AA_BUG(!ctx || !ctx->profile);
	return ctx->profile;
}

static inline struct aa_profile *__aa_current_profile(void)
{
	return aa_cred_profile(current_cred());
}

/* klp-ccp: from security/apparmor/include/crypto.h */
#ifdef CONFIG_SECURITY_APPARMOR_HASH

static char *(*klpe_aa_calc_hash)(void *data, size_t len);
static int (*klpe_aa_calc_profile_hash)(struct aa_profile *profile, u32 version, void *start,
			 size_t len);
#else
#error "klp-ccp: non-taken branch"
#endif

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
static struct aa_load_ent *(*klpe_aa_load_ent_alloc)(void);

#define PACKED_FLAG_HAT		1

#define PACKED_MODE_COMPLAIN	1
#define PACKED_MODE_KILL	2
#define PACKED_MODE_UNCONFINED	3

struct aa_loaddata {
	struct kref count;
	size_t size;
	int abi;
	unsigned char *hash;
	char data[];
};

int klpp_aa_unpack(struct aa_loaddata *udata, struct list_head *lh, const char **ns);

/* klp-ccp: from security/apparmor/policy_unpack.c */
#define K_ABI_MASK 0x3ff
#define FORCE_COMPLAIN_FLAG 0x800
#define VERSION_LT(X, Y) (((X) & K_ABI_MASK) < ((Y) & K_ABI_MASK))
#define VERSION_GT(X, Y) (((X) & K_ABI_MASK) > ((Y) & K_ABI_MASK))

#define v5	5	/* base version */

#define v7	7	/* full network masking */

enum aa_code {
	AA_U8,
	AA_U16,
	AA_U32,
	AA_U64,
	AA_NAME,		/* same as string except it is items name */
	AA_STRING,
	AA_BLOB,
	AA_STRUCT,
	AA_STRUCTEND,
	AA_LIST,
	AA_LISTEND,
	AA_ARRAY,
	AA_ARRAYEND,
};

struct aa_ext {
	void *start;
	void *end;
	void *pos;		/* pointer to current position in the buffer */
	u32 version;
};

static void (*klpe_audit_cb)(struct audit_buffer *ab, void *va);

static int klpr_audit_iface(struct aa_profile *new, const char *ns_name,
		       const char *name, const char *info, struct aa_ext *e,
		       int error)
{
	struct aa_profile *profile = __aa_current_profile();
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, NULL);
	if (e)
		aad(&sa)->iface.pos = e->pos - e->start;
	aad(&sa)->iface.ns = ns_name;
	if (new)
		aad(&sa)->iface.name = new->base.hname;
	else
		aad(&sa)->iface.name = name;
	aad(&sa)->info = info;
	aad(&sa)->error = error;

	return (*klpe_aa_audit)(AUDIT_APPARMOR_STATUS, profile, &sa, (*klpe_audit_cb));
}

static bool inbounds(struct aa_ext *e, size_t size)
{
	return (size <= e->end - e->pos);
}

static bool (*klpe_unpack_nameX)(struct aa_ext *e, enum aa_code code, const char *name);

static bool klpr_unpack_u16(struct aa_ext *e, u16 *data, const char *name)
{
	if ((*klpe_unpack_nameX)(e, AA_U16, name)) {
		if (!inbounds(e, sizeof(u16)))
			return 0;
		if (data)
			*data = le16_to_cpu(get_unaligned((u16 *) e->pos));
		e->pos += sizeof(u16);
		return 1;
	}
	return 0;
}

static bool (*klpe_unpack_u32)(struct aa_ext *e, u32 *data, const char *name);

static bool klpr_unpack_u64(struct aa_ext *e, u64 *data, const char *name)
{
	if ((*klpe_unpack_nameX)(e, AA_U64, name)) {
		if (!inbounds(e, sizeof(u64)))
			return 0;
		if (data)
			*data = le64_to_cpu(get_unaligned((__le64 *) e->pos));
		e->pos += sizeof(u64);
		return 1;
	}
	return 0;
}

static size_t (*klpe_unpack_array)(struct aa_ext *e, const char *name);

static size_t klpr_unpack_blob(struct aa_ext *e, char **blob, const char *name)
{
	if ((*klpe_unpack_nameX)(e, AA_BLOB, name)) {
		u32 size;
		if (!inbounds(e, sizeof(u32)))
			return 0;
		size = le32_to_cpu(get_unaligned((__le32 *) e->pos));
		e->pos += sizeof(u32);
		if (inbounds(e, (size_t) size)) {
			*blob = e->pos;
			e->pos += size;
			return size;
		}
	}
	return 0;
}

static int (*klpe_unpack_str)(struct aa_ext *e, const char **string, const char *name);

static int klpr_unpack_strdup(struct aa_ext *e, char **string, const char *name)
{
	const char *tmp;
	void *pos = e->pos;
	int res = (*klpe_unpack_str)(e, &tmp, name);
	*string = NULL;

	if (!res)
		return 0;

	*string = kmemdup(tmp, res, GFP_KERNEL);
	if (!*string) {
		e->pos = pos;
		return 0;
	}

	return res;
}

static struct aa_dfa *(*klpe_unpack_dfa)(struct aa_ext *e);

static bool klpr_unpack_trans_table(struct aa_ext *e, struct aa_profile *profile)
{
	void *pos = e->pos;

	/* exec table is optional */
	if ((*klpe_unpack_nameX)(e, AA_STRUCT, "xtable")) {
		int i, size;

		size = (*klpe_unpack_array)(e, NULL);
		/* currently 4 exec bits and entries 0-3 are reserved iupcx */
		if (size > 16 - 4)
			goto fail;
		profile->file.trans.table = kzalloc(sizeof(char *) * size,
						    GFP_KERNEL);
		if (!profile->file.trans.table)
			goto fail;

		profile->file.trans.size = size;
		for (i = 0; i < size; i++) {
			char *str;
			int c, j, size2 = klpr_unpack_strdup(e, &str, NULL);
			/* unpack_strdup verifies that the last character is
			 * null termination byte.
			 */
			if (!size2)
				goto fail;
			profile->file.trans.table[i] = str;
			/* verify that name doesn't start with space */
			if (isspace(*str))
				goto fail;

			/* count internal #  of internal \0 */
			for (c = j = 0; j < size2 - 2; j++) {
				if (!str[j])
					c++;
			}
			if (*str == ':') {
				/* beginning with : requires an embedded \0,
				 * verify that exactly 1 internal \0 exists
				 * trailing \0 already verified by unpack_strdup
				 */
				if (c != 1)
					goto fail;
				/* first character after : must be valid */
				if (!str[1])
					goto fail;
			} else if (c)
				/* fail - all other cases with embedded \0 */
				goto fail;
		}
		if (!(*klpe_unpack_nameX)(e, AA_ARRAYEND, NULL))
			goto fail;
		if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
			goto fail;
	}
	return 1;

fail:
	(*klpe_aa_free_domain_entries)(&profile->file.trans);
	e->pos = pos;
	return 0;
}

static bool klpr_unpack_rlimits(struct aa_ext *e, struct aa_profile *profile)
{
	void *pos = e->pos;

	/* rlimits are optional */
	if ((*klpe_unpack_nameX)(e, AA_STRUCT, "rlimits")) {
		int i, size;
		u32 tmp = 0;
		if (!(*klpe_unpack_u32)(e, &tmp, NULL))
			goto fail;
		profile->rlimits.mask = tmp;

		size = (*klpe_unpack_array)(e, NULL);
		if (size > RLIM_NLIMITS)
			goto fail;
		for (i = 0; i < size; i++) {
			u64 tmp2 = 0;
			int a = (*klpe_aa_map_resource)(i);
			if (!klpr_unpack_u64(e, &tmp2, NULL))
				goto fail;
			profile->rlimits.limits[a].rlim_max = tmp2;
		}
		if (!(*klpe_unpack_nameX)(e, AA_ARRAYEND, NULL))
			goto fail;
		if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
			goto fail;
	}
	return 1;

fail:
	e->pos = pos;
	return 0;
}

static void *kvmemdup(const void *src, size_t len)
{
	void *p = kvmalloc(len, GFP_KERNEL);

	if (p)
		memcpy(p, src, len);
	return p;
}

static u32 (*klpe_strhash)(const void *data, u32 len, u32 seed);

static int (*klpe_datacmp)(struct rhashtable_compare_arg *arg, const void *obj);

struct aa_profile *klpp_unpack_profile(struct aa_ext *e, char **ns_name)
{
	struct aa_profile *profile = NULL;
	const char *tmpname, *tmpns = NULL, *name = NULL;
	size_t ns_len;
	struct rhashtable_params params = { 0 };
	char *key = NULL;
	struct aa_data *data;
	int i, error = -EPROTO;
	kernel_cap_t tmpcap;
	u32 tmp;
	size_t size = 0;

	*ns_name = NULL;

	/* check that we have the right struct being passed */
	if (!(*klpe_unpack_nameX)(e, AA_STRUCT, "profile"))
		goto fail;
	if (!(*klpe_unpack_str)(e, &name, NULL))
		goto fail;
	if (*name == '\0')
		goto fail;

	tmpname = (*klpe_aa_splitn_fqname)(name, strlen(name), &tmpns, &ns_len);
	if (tmpns) {
		if (!tmpname) {
			goto fail;
		}
		*ns_name = kstrndup(tmpns, ns_len, GFP_KERNEL);
		if (!*ns_name)
			goto fail;
		name = tmpname;
	}

	profile = (*klpe_aa_alloc_profile)(name, GFP_KERNEL);
	if (!profile)
		return ERR_PTR(-ENOMEM);

	/* profile renaming is optional */
	(void) (*klpe_unpack_str)(e, &profile->rename, "rename");

	/* attachment string is optional */
	(void) (*klpe_unpack_str)(e, &profile->attach, "attach");

	/* xmatch is optional and may be NULL */
	profile->xmatch = (*klpe_unpack_dfa)(e);
	if (IS_ERR(profile->xmatch)) {
		error = PTR_ERR(profile->xmatch);
		profile->xmatch = NULL;
		goto fail;
	}
	/* xmatch_len is not optional if xmatch is set */
	if (profile->xmatch) {
		if (!(*klpe_unpack_u32)(e, &tmp, NULL))
			goto fail;
		profile->xmatch_len = tmp;
	}

	/* per profile debug flags (complain, audit) */
	if (!(*klpe_unpack_nameX)(e, AA_STRUCT, "flags"))
		goto fail;
	if (!(*klpe_unpack_u32)(e, &tmp, NULL))
		goto fail;
	if (tmp & PACKED_FLAG_HAT)
		profile->flags |= PFLAG_HAT;
	if (!(*klpe_unpack_u32)(e, &tmp, NULL))
		goto fail;
	if (tmp == PACKED_MODE_COMPLAIN || (e->version & FORCE_COMPLAIN_FLAG))
		profile->mode = APPARMOR_COMPLAIN;
	else if (tmp == PACKED_MODE_KILL)
		profile->mode = APPARMOR_KILL;
	else if (tmp == PACKED_MODE_UNCONFINED)
		profile->mode = APPARMOR_UNCONFINED;
	if (!(*klpe_unpack_u32)(e, &tmp, NULL))
		goto fail;
	if (tmp)
		profile->audit = AUDIT_ALL;

	if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
		goto fail;

	/* path_flags is optional */
	if ((*klpe_unpack_u32)(e, &profile->path_flags, "path_flags"))
		profile->path_flags |= profile->flags & PFLAG_MEDIATE_DELETED;
	else
		/* set a default value if path_flags field is not present */
		profile->path_flags = PFLAG_MEDIATE_DELETED;

	if (!(*klpe_unpack_u32)(e, &(profile->caps.allow.cap[0]), NULL))
		goto fail;
	if (!(*klpe_unpack_u32)(e, &(profile->caps.audit.cap[0]), NULL))
		goto fail;
	if (!(*klpe_unpack_u32)(e, &(profile->caps.quiet.cap[0]), NULL))
		goto fail;
	if (!(*klpe_unpack_u32)(e, &tmpcap.cap[0], NULL))
		goto fail;

	if ((*klpe_unpack_nameX)(e, AA_STRUCT, "caps64")) {
		/* optional upper half of 64 bit caps */
		if (!(*klpe_unpack_u32)(e, &(profile->caps.allow.cap[1]), NULL))
			goto fail;
		if (!(*klpe_unpack_u32)(e, &(profile->caps.audit.cap[1]), NULL))
			goto fail;
		if (!(*klpe_unpack_u32)(e, &(profile->caps.quiet.cap[1]), NULL))
			goto fail;
		if (!(*klpe_unpack_u32)(e, &(tmpcap.cap[1]), NULL))
			goto fail;
		if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
			goto fail;
	}

	if ((*klpe_unpack_nameX)(e, AA_STRUCT, "capsx")) {
		/* optional extended caps mediation mask */
		if (!(*klpe_unpack_u32)(e, &(profile->caps.extended.cap[0]), NULL))
			goto fail;
		if (!(*klpe_unpack_u32)(e, &(profile->caps.extended.cap[1]), NULL))
			goto fail;
		if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
			goto fail;
	}

	if (!klpr_unpack_rlimits(e, profile))
		goto fail;

	size = (*klpe_unpack_array)(e, "net_allowed_af");
	if (size) {

		for (i = 0; i < size; i++) {
			/* discard extraneous rules that this kernel will
			 * never request
			 */
			if (i >= AF_MAX) {
				u16 tmp;
				if (!klpr_unpack_u16(e, &tmp, NULL) ||
				    !klpr_unpack_u16(e, &tmp, NULL) ||
				    !klpr_unpack_u16(e, &tmp, NULL))
					goto fail;
				continue;
			}
			if (!klpr_unpack_u16(e, &profile->net.allow[i], NULL))
				goto fail;
			if (!klpr_unpack_u16(e, &profile->net.audit[i], NULL))
				goto fail;
			if (!klpr_unpack_u16(e, &profile->net.quiet[i], NULL))
				goto fail;
		}
		if (!(*klpe_unpack_nameX)(e, AA_ARRAYEND, NULL))
			goto fail;
	}
	/*
	 * allow unix domain and netlink sockets they are handled
	 * by IPC
	 */
	profile->net.allow[AF_UNIX] = 0xffff;
	profile->net.allow[AF_NETLINK] = 0xffff;

	if ((*klpe_unpack_nameX)(e, AA_STRUCT, "policydb")) {
		/* generic policy dfa - optional and may be NULL */
		profile->policy.dfa = (*klpe_unpack_dfa)(e);
		if (IS_ERR(profile->policy.dfa)) {
			error = PTR_ERR(profile->policy.dfa);
			profile->policy.dfa = NULL;
			goto fail;
		} else if (!profile->policy.dfa) {
			error = -EPROTO;
			goto fail;
		}
		if (!(*klpe_unpack_u32)(e, &profile->policy.start[0], "start"))
			/* default start state */
			profile->policy.start[0] = DFA_START;

		if (profile->policy.start[0] >=
		    profile->policy.dfa->tables[YYTD_ID_BASE]->td_lolen) {
			error = -EPROTO;
			goto fail;
		}

		/* setup class index */
		for (i = AA_CLASS_FILE; i <= AA_CLASS_LAST; i++) {
			profile->policy.start[i] =
				(*klpe_aa_dfa_next)(profile->policy.dfa,
					    profile->policy.start[0],
					    i);
		}
		if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
			goto fail;
	} else
		profile->policy.dfa = aa_get_dfa((*klpe_nulldfa));

	/* get file rules */
	profile->file.dfa = (*klpe_unpack_dfa)(e);
	if (IS_ERR(profile->file.dfa)) {
		error = PTR_ERR(profile->file.dfa);
		profile->file.dfa = NULL;
		goto fail;
	} else if (profile->file.dfa) {
		if (!(*klpe_unpack_u32)(e, &profile->file.start, "dfa_start"))
			/* default start state */
			profile->file.start = DFA_START;
	} else if (profile->policy.dfa &&
		   profile->policy.start[AA_CLASS_FILE]) {
		profile->file.dfa = aa_get_dfa(profile->policy.dfa);
		profile->file.start = profile->policy.start[AA_CLASS_FILE];
	} else
		profile->file.dfa = aa_get_dfa((*klpe_nulldfa));

	if (!klpr_unpack_trans_table(e, profile))
		goto fail;

	if ((*klpe_unpack_nameX)(e, AA_STRUCT, "data")) {
		profile->data = kzalloc(sizeof(*profile->data), GFP_KERNEL);
		if (!profile->data)
			goto fail;

		params.nelem_hint = 3;
		params.key_len = sizeof(void *);
		params.key_offset = offsetof(struct aa_data, key);
		params.head_offset = offsetof(struct aa_data, head);
		params.hashfn = (*klpe_strhash);
		params.obj_cmpfn = (*klpe_datacmp);

		if (rhashtable_init(profile->data, &params))
			goto fail;

		while (klpr_unpack_strdup(e, &key, NULL)) {
			data = kzalloc(sizeof(*data), GFP_KERNEL);
			if (!data) {
				kzfree(key);
				goto fail;
			}

			data->key = key;
			data->size = klpr_unpack_blob(e, &data->data, NULL);
			data->data = kvmemdup(data->data, data->size);
			if (data->size && !data->data) {
				kzfree(data->key);
				kzfree(data);
				goto fail;
			}

			rhashtable_insert_fast(profile->data, &data->head,
					       profile->data->p);
		}

		if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
			goto fail;
	}

	if (!(*klpe_unpack_nameX)(e, AA_STRUCTEND, NULL))
		goto fail;

	return profile;

fail:
	if (profile)
		name = NULL;
	else if (!name)
		name = "unknown";
	klpr_audit_iface(profile, NULL, name, "failed to unpack profile", e,
		    error);
	(*klpe_aa_free_profile)(profile);

	return ERR_PTR(error);
}

static int klpp_verify_header(struct aa_ext *e, int required, const char **ns)
{
	int error = -EPROTONOSUPPORT;
	const char *name = NULL;

	/* get the interface version */
	if (!(*klpe_unpack_u32)(e, &e->version, "version")) {
		if (required) {
			klpr_audit_iface(NULL, NULL, NULL, "invalid profile format",
				    e, error);
			return error;
		}
	}

	/* Check that the interface version is currently supported.
	 * if not specified use previous version
	 * Mask off everything that is not kernel abi version
	 */
	if (VERSION_LT(e->version, v5) && VERSION_GT(e->version, v7)) {
		klpr_audit_iface(NULL, NULL, NULL, "unsupported interface version",
			    e, error);
		return error;
	}

	/* read the namespace if present */
	if ((*klpe_unpack_str)(e, &name, "namespace")) {
		if (*name == '\0') {
			klpr_audit_iface(NULL, NULL, NULL, "invalid namespace name",
				    e, error);
			return error;
		}
		if (*ns && strcmp(*ns, name))
			klpr_audit_iface(NULL, NULL, NULL, "invalid ns change", e,
				    error);
		else if (!*ns)
			*ns = name;
	}

	return 0;
}

static bool verify_xindex(int xindex, int table_size)
{
	int index, xtype;
	xtype = xindex & AA_X_TYPE_MASK;
	index = xindex & AA_X_INDEX_MASK;
	if (xtype == AA_X_TABLE && index >= table_size)
		return 0;
	return 1;
}

static bool verify_dfa_xindex(struct aa_dfa *dfa, int table_size)
{
	int i;
	for (i = 0; i < dfa->tables[YYTD_ID_ACCEPT]->td_lolen; i++) {
		if (!verify_xindex(dfa_user_xindex(dfa, i), table_size))
			return 0;
		if (!verify_xindex(dfa_other_xindex(dfa, i), table_size))
			return 0;
	}
	return 1;
}

static int klpr_verify_profile(struct aa_profile *profile)
{
	if (profile->file.dfa &&
	    !verify_dfa_xindex(profile->file.dfa,
			       profile->file.trans.size)) {
		klpr_audit_iface(profile, NULL, NULL, "Invalid named transition",
			    NULL, -EPROTO);
		return -EPROTO;
	}

	return 0;
}
int klpp_aa_unpack(struct aa_loaddata *udata, struct list_head *lh,
	      const char **ns)
{
	struct aa_load_ent *tmp, *ent;
	struct aa_profile *profile = NULL;
	int error;
	struct aa_ext e = {
		.start = udata->data,
		.end = udata->data + udata->size,
		.pos = udata->data,
	};

	*ns = NULL;
	while (e.pos < e.end) {
		char *ns_name = NULL;
		void *start;
		error = klpp_verify_header(&e, e.pos == e.start, ns);
		if (error)
			goto fail;

		start = e.pos;
		profile = klpp_unpack_profile(&e, &ns_name);
		if (IS_ERR(profile)) {
			error = PTR_ERR(profile);
			goto fail;
		}

		error = klpr_verify_profile(profile);
		if (error)
			goto fail_profile;

		if ((*klpe_aa_g_hash_policy))
			error = (*klpe_aa_calc_profile_hash)(profile, e.version, start,
						     e.pos - start);
		if (error)
			goto fail_profile;

		ent = (*klpe_aa_load_ent_alloc)();
		if (!ent) {
			error = -ENOMEM;
			goto fail_profile;
		}

		ent->new = profile;
		ent->ns_name = ns_name;
		list_add_tail(&ent->list, lh);
	}
	udata->abi = e.version & K_ABI_MASK;
	if ((*klpe_aa_g_hash_policy)) {
		udata->hash = (*klpe_aa_calc_hash)(udata->data, udata->size);
		if (IS_ERR(udata->hash)) {
			error = PTR_ERR(udata->hash);
			udata->hash = NULL;
			goto fail;
		}
	}
	return 0;

fail_profile:
	klpr_aa_put_profile(profile);

fail:
	list_for_each_entry_safe(ent, tmp, lh, list) {
		list_del_init(&ent->list);
		(*klpe_aa_load_ent_free)(ent);
	}

	return error;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "aa_alloc_profile", (void *)&klpe_aa_alloc_profile },
	{ "aa_audit", (void *)&klpe_aa_audit },
	{ "aa_calc_hash", (void *)&klpe_aa_calc_hash },
	{ "aa_calc_profile_hash", (void *)&klpe_aa_calc_profile_hash },
	{ "aa_dfa_next", (void *)&klpe_aa_dfa_next },
	{ "aa_free_domain_entries", (void *)&klpe_aa_free_domain_entries },
	{ "aa_free_profile", (void *)&klpe_aa_free_profile },
	{ "aa_free_profile_kref", (void *)&klpe_aa_free_profile_kref },
	{ "aa_g_hash_policy", (void *)&klpe_aa_g_hash_policy },
	{ "aa_load_ent_alloc", (void *)&klpe_aa_load_ent_alloc },
	{ "aa_load_ent_free", (void *)&klpe_aa_load_ent_free },
	{ "aa_map_resource", (void *)&klpe_aa_map_resource },
	{ "aa_splitn_fqname", (void *)&klpe_aa_splitn_fqname },
	{ "audit_cb", (void *)&klpe_audit_cb, NULL, 4 },
	{ "datacmp", (void *)&klpe_datacmp },
	{ "nulldfa", (void *)&klpe_nulldfa },
	{ "strhash", (void *)&klpe_strhash },
	{ "unpack_array", (void *)&klpe_unpack_array },
	{ "unpack_dfa", (void *)&klpe_unpack_dfa },
	{ "unpack_nameX", (void *)&klpe_unpack_nameX },
	{ "unpack_str", (void *)&klpe_unpack_str },
	{ "unpack_u32", (void *)&klpe_unpack_u32 },
};

int bsc1259859_security_apparmor_policy_unpack_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

