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


/* klp-ccp: from security/apparmor/policy_unpack.c */
#include <asm/unaligned.h>
#include <kunit/visibility.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/zstd.h>
/* klp-ccp: from security/apparmor/include/apparmor.h */
#include <linux/types.h>

#define AA_CLASS_NONE		0

#define AA_CLASS_FILE		2

#define AA_CLASS_DBUS		32

#define AA_CLASS_LAST		AA_CLASS_DBUS

extern bool aa_g_hash_policy;
extern bool aa_g_export_binary;
extern int aa_g_rawdata_compression_level;

extern bool aa_g_paranoid_load;

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

#define DFA_START			1

#define	YYTD_ID_ACCEPT	0
#define YYTD_ID_BASE	1

#define YYTD_ID_ACCEPT2 6

#define YYTD_ID_TSIZE	8

#define YYTD_DATA32	4

#define ACCEPT1_FLAGS(X) ((X) & 0x3f)

#define TO_ACCEPT1_FLAG(X) ACCEPT1_FLAGS(X)
#define TO_ACCEPT2_FLAG(X) (ACCEPT1_FLAGS(X) << YYTD_ID_ACCEPT2)
#define DFA_FLAG_VERIFY_STATES 0x1000

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
	u32 max_oob;
	struct table_header *tables[YYTD_ID_TSIZE];
};

#define aa_state_t unsigned int

struct aa_dfa *aa_dfa_unpack(void *blob, size_t size, int flags);

aa_state_t aa_dfa_next(struct aa_dfa *dfa, aa_state_t state, const char c);

/* klp-ccp: from security/apparmor/include/lib.h */
#define AA_BUG(X, args...)						    \
	do {								    \
		_Pragma("GCC diagnostic ignored \"-Wformat-zero-length\""); \
		AA_BUG_FMT((X), "" args);				    \
		_Pragma("GCC diagnostic warning \"-Wformat-zero-length\""); \
	} while (0)

#define AA_BUG_FMT(X, fmt, args...) no_printk(fmt, ##args)

extern struct lsm_blob_sizes apparmor_blob_sizes;

struct aa_str_table {
	int size;
	char **table;
};

void aa_free_str_table(struct aa_str_table *table);

#define __counted	/* atm just a notation */

struct aa_policy {
	const char *name;
	__counted char *hname;
	struct list_head list;
	struct list_head profiles;
};

/* klp-ccp: from security/apparmor/include/label.h */
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

#define labels_profile(X) ((X)->vec[(X)->size - 1])

void aa_label_kref(struct kref *kref);

/* klp-ccp: from security/apparmor/include/perms.h */
#include <linux/fs.h>

struct aa_perms {
	u32 allow;
	u32 deny;	/* explicit deny, or conflict if allow also set */

	u32 subtree;	/* allow perm on full subtree only when allow is set */
	u32 cond;	/* set only when ~allow and ~deny */

	u32 kill;	/* set only when ~allow | deny */
	u32 complain;	/* accumulates only used when ~allow & ~deny */
	u32 prompt;	/* accumulates only used when ~allow & ~deny */

	u32 audit;	/* set only when allow is set */
	u32 quiet;	/* set only when ~allow | deny */
	u32 hide;	/* set only when  ~allow | deny */
	u32 xindex;
	u32 tag;	/* tag string index, if present */
	u32 label;	/* label string index, if present */
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
	int type;
	u16 class;
	const char *op;
	struct aa_label *label;
	const char *name;
	const char *info;
	u32 request;
	u32 denied;
	union {
		/* these entries require a custom callback fn */
		struct {
			struct aa_label *peer;
			union {
				struct {
					const char *target;
					kuid_t ouid;
				} fs;
				struct {
					int rlim;
					unsigned long max;
				} rlim;
				struct {
					int signal;
					int unmappedsig;
				};
				struct {
					int type, protocol;
					struct sock *peer_sk;
					void *addr;
					int addrlen;
				} net;
			};
		};
		struct {
			struct aa_profile *profile;
			const char *ns;
			long pos;
		} iface;
		struct {
			const char *src_name;
			const char *type;
			const char *trans;
			const char *data;
			unsigned long flags;
		} mnt;
	};
};

#define aad(SA) ((SA)->apparmor_audit_data)
#define DEFINE_AUDIT_DATA(NAME, T, C, X)				\
	/* TODO: cleanup audit init so we don't need _aad = {0,} */	\
	struct apparmor_audit_data NAME ## _aad = {                     \
		.class = (C),						\
		.op = (X),                                              \
	};                                                              \
	struct common_audit_data NAME =					\
	{								\
	.type = (T),							\
	.u.tsk = NULL,							\
	};								\
	NAME.apparmor_audit_data = &(NAME ## _aad)

int aa_audit(int type, struct aa_profile *profile, struct common_audit_data *sa,
	     void (*cb) (struct audit_buffer *, void *));

/* klp-ccp: from security/apparmor/include/cred.h */
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>
/* klp-ccp: from security/apparmor/include/policy_ns.h */
#include <linux/kref.h>

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
	kernel_cap_t denied;
	kernel_cap_t quiet;
	kernel_cap_t kill;
	kernel_cap_t extended;
};

/* klp-ccp: from security/apparmor/include/domain.h */
#include <linux/binfmts.h>
#include <linux/types.h>
/* klp-ccp: from security/apparmor/include/net.h */
#include <net/sock.h>
#include <linux/path.h>
/* klp-ccp: from security/apparmor/include/resource.h */
#include <linux/resource.h>
#include <linux/sched.h>

struct aa_rlimit {
	unsigned int mask;
	struct rlimit limits[RLIM_NLIMITS];
};

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

struct aa_ruleset {
	struct list_head list;

	int size;

	/* TODO: merge policy and file */
	struct aa_policydb policy;
	struct aa_policydb file;
	struct aa_caps caps;

	struct aa_rlimit rlimits;

	int secmark_count;
	struct aa_secmark *secmark;
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

static inline void aa_put_profile(struct aa_profile *p)
{
	if (p)
		kref_put(&p->label.count, aa_label_kref);
}

/* klp-ccp: from security/apparmor/include/cred.h */
static inline struct aa_label *cred_label(const struct cred *cred)
{
	struct aa_label **blob = cred->security + apparmor_blob_sizes.lbs_cred;

	AA_BUG(!blob);
	return *blob;
}

static inline struct aa_label *aa_cred_raw_label(const struct cred *cred)
{
	struct aa_label *label = cred_label(cred);

	AA_BUG(!label);
	return label;
}

static inline struct aa_label *aa_current_raw_label(void)
{
	return aa_cred_raw_label(current_cred());
}

/* klp-ccp: from security/apparmor/include/crypto.h */
#ifdef CONFIG_SECURITY_APPARMOR_HASH

char *aa_calc_hash(void *data, size_t len);
int aa_calc_profile_hash(struct aa_profile *profile, u32 version, void *start,
			 size_t len);
#else
#error "klp-ccp: non-taken branch"
#endif

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
struct aa_load_ent *aa_load_ent_alloc(void);

enum {
	AAFS_LOADDATA_ABI = 0,
	AAFS_LOADDATA_REVISION,
	AAFS_LOADDATA_HASH,
	AAFS_LOADDATA_DATA,
	AAFS_LOADDATA_COMPRESSED_SIZE,
	AAFS_LOADDATA_DIR,		/* must be last actual entry */
	AAFS_LOADDATA_NDENTS		/* count of entries */
};

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

int klpp_aa_unpack(struct aa_loaddata *udata, struct list_head *lh, const char **ns);

/* klp-ccp: from security/apparmor/include/policy_compat.h */
#define K_ABI_MASK 0x3ff

#define VERSION_LT(X, Y) (((X) & K_ABI_MASK) < ((Y) & K_ABI_MASK))

#define VERSION_GT(X, Y) (((X) & K_ABI_MASK) > ((Y) & K_ABI_MASK))

#define v5	5	/* base version */

#define v9	9	/* xbits are used as permission bits in policydb */

/* klp-ccp: from security/apparmor/policy_unpack.c */
extern void audit_cb(struct audit_buffer *ab, void *va);

static int audit_iface(struct aa_profile *new, const char *ns_name,
		       const char *name, const char *info, struct aa_ext *e,
		       int error)
{
	struct aa_profile *profile = labels_profile(aa_current_raw_label());
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, AA_CLASS_NONE, NULL);
	if (e)
		aad(&sa)->iface.pos = e->pos - e->start;
	aad(&sa)->iface.ns = ns_name;
	if (new)
		aad(&sa)->name = new->base.hname;
	else
		aad(&sa)->name = name;
	aad(&sa)->info = info;
	aad(&sa)->error = error;

	return aa_audit(AUDIT_APPARMOR_STATUS, profile, &sa, audit_cb);
}

VISIBLE_IF_KUNIT bool aa_inbounds(struct aa_ext *e, size_t size)
{
	return (size <= e->end - e->pos);
}

extern bool aa_unpack_nameX(struct aa_ext *e, enum aa_code code, const char *name);

extern bool aa_unpack_u32(struct aa_ext *e, u32 *data, const char *name);

VISIBLE_IF_KUNIT bool aa_unpack_array(struct aa_ext *e, const char *name, u16 *size)
{
	void *pos = e->pos;

	if (aa_unpack_nameX(e, AA_ARRAY, name)) {
		if (!aa_inbounds(e, sizeof(u16)))
			goto fail;
		*size = le16_to_cpu(get_unaligned((__le16 *) e->pos));
		e->pos += sizeof(u16);
		return true;
	}

fail:
	e->pos = pos;
	return false;
}

extern size_t aa_unpack_blob(struct aa_ext *e, char **blob, const char *name);

extern int aa_unpack_str(struct aa_ext *e, const char **string, const char *name);

extern int aa_unpack_strdup(struct aa_ext *e, char **string, const char *name);

static struct aa_dfa *unpack_dfa(struct aa_ext *e, int flags)
{
	char *blob = NULL;
	size_t size;
	struct aa_dfa *dfa = NULL;

	size = aa_unpack_blob(e, &blob, "aadfa");
	if (size) {
		/*
		 * The dfa is aligned with in the blob to 8 bytes
		 * from the beginning of the stream.
		 * alignment adjust needed by dfa unpack
		 */
		size_t sz = blob - (char *) e->start -
			((e->pos - e->start) & 7);
		size_t pad = ALIGN(sz, 8) - sz;
		if (aa_g_paranoid_load)
			flags |= DFA_FLAG_VERIFY_STATES;
		dfa = aa_dfa_unpack(blob + pad, size - pad, flags);

		if (IS_ERR(dfa))
			return dfa;

	}

	return dfa;
}

static bool unpack_trans_table(struct aa_ext *e, struct aa_str_table *strs)
{
	void *saved_pos = e->pos;
	char **table = NULL;

	/* exec table is optional */
	if (aa_unpack_nameX(e, AA_STRUCT, "xtable")) {
		u16 size;
		int i;

		if (!aa_unpack_array(e, NULL, &size))
			/*
			 * Note: index into trans table array is a max
			 * of 2^24, but unpack array can only unpack
			 * an array of 2^16 in size atm so no need
			 * for size check here
			 */
			goto fail;
		table = kcalloc(size, sizeof(char *), GFP_KERNEL);
		if (!table)
			goto fail;

		strs->table = table;
		strs->size = size;
		for (i = 0; i < size; i++) {
			char *str;
			int c, j, pos, size2 = aa_unpack_strdup(e, &str, NULL);
			/* aa_unpack_strdup verifies that the last character is
			 * null termination byte.
			 */
			if (!size2)
				goto fail;
			table[i] = str;
			/* verify that name doesn't start with space */
			if (isspace(*str))
				goto fail;

			/* count internal #  of internal \0 */
			for (c = j = 0; j < size2 - 1; j++) {
				if (!str[j]) {
					pos = j;
					c++;
				}
			}
			if (*str == ':') {
				/* first character after : must be valid */
				if (!str[1])
					goto fail;
				/* beginning with : requires an embedded \0,
				 * verify that exactly 1 internal \0 exists
				 * trailing \0 already verified by aa_unpack_strdup
				 *
				 * convert \0 back to : for label_parse
				 */
				if (c == 1)
					str[pos] = ':';
				else if (c > 1)
					goto fail;
			} else if (c)
				/* fail - all other cases with embedded \0 */
				goto fail;
		}
		if (!aa_unpack_nameX(e, AA_ARRAYEND, NULL))
			goto fail;
		if (!aa_unpack_nameX(e, AA_STRUCTEND, NULL))
			goto fail;
	}
	return true;

fail:
	aa_free_str_table(strs);
	e->pos = saved_pos;
	return false;
}

static bool unpack_perm(struct aa_ext *e, u32 version, struct aa_perms *perm)
{
	if (version != 1)
		return false;

	return	aa_unpack_u32(e, &perm->allow, NULL) &&
		aa_unpack_u32(e, &perm->allow, NULL) &&
		aa_unpack_u32(e, &perm->deny, NULL) &&
		aa_unpack_u32(e, &perm->subtree, NULL) &&
		aa_unpack_u32(e, &perm->cond, NULL) &&
		aa_unpack_u32(e, &perm->kill, NULL) &&
		aa_unpack_u32(e, &perm->complain, NULL) &&
		aa_unpack_u32(e, &perm->prompt, NULL) &&
		aa_unpack_u32(e, &perm->audit, NULL) &&
		aa_unpack_u32(e, &perm->quiet, NULL) &&
		aa_unpack_u32(e, &perm->hide, NULL) &&
		aa_unpack_u32(e, &perm->xindex, NULL) &&
		aa_unpack_u32(e, &perm->tag, NULL) &&
		aa_unpack_u32(e, &perm->label, NULL);
}

static ssize_t unpack_perms_table(struct aa_ext *e, struct aa_perms **perms)
{
	void *pos = e->pos;
	u16 size = 0;

	AA_BUG(!perms);
	/*
	 * policy perms are optional, in which case perms are embedded
	 * in the dfa accept table
	 */
	if (aa_unpack_nameX(e, AA_STRUCT, "perms")) {
		int i;
		u32 version;

		if (!aa_unpack_u32(e, &version, "version"))
			goto fail_reset;
		if (!aa_unpack_array(e, NULL, &size))
			goto fail_reset;
		*perms = kcalloc(size, sizeof(struct aa_perms), GFP_KERNEL);
		if (!*perms)
			goto fail_reset;
		for (i = 0; i < size; i++) {
			if (!unpack_perm(e, version, &(*perms)[i]))
				goto fail;
		}
		if (!aa_unpack_nameX(e, AA_ARRAYEND, NULL))
			goto fail;
		if (!aa_unpack_nameX(e, AA_STRUCTEND, NULL))
			goto fail;
	} else
		*perms = NULL;

	return size;

fail:
	kfree(*perms);
fail_reset:
	e->pos = pos;
	return -EPROTO;
}

int klpp_unpack_pdb(struct aa_ext *e, struct aa_policydb *policy,
		      bool required_dfa, bool required_trans,
		      const char **info)
{
	void *pos = e->pos;
	int i, flags, error = -EPROTO;
	ssize_t size;

	size = unpack_perms_table(e, &policy->perms);
	if (size < 0) {
		error = size;
		policy->perms = NULL;
		*info = "failed to unpack - perms";
		goto fail;
	}
	policy->size = size;

	if (policy->perms) {
		/* perms table present accept is index */
		flags = TO_ACCEPT1_FLAG(YYTD_DATA32);
	} else {
		/* packed perms in accept1 and accept2 */
		flags = TO_ACCEPT1_FLAG(YYTD_DATA32) |
			TO_ACCEPT2_FLAG(YYTD_DATA32);
	}

	policy->dfa = unpack_dfa(e, flags);
	if (IS_ERR(policy->dfa)) {
		error = PTR_ERR(policy->dfa);
		policy->dfa = NULL;
		*info = "failed to unpack - dfa";
		goto fail;
	} else if (!policy->dfa) {
		if (required_dfa) {
			*info = "missing required dfa";
			goto fail;
		}
	} else {
		/*
		 * only unpack the following if a dfa is present
		 *
		 * sadly start was given different names for file and policydb
		 * but since it is optional we can try both
		 */
		if (!aa_unpack_u32(e, &policy->start[0], "start"))
			/* default start state */
			policy->start[0] = DFA_START;
		if (!aa_unpack_u32(e, &policy->start[AA_CLASS_FILE], "dfa_start")) {
			/* default start state for xmatch and file dfa */
			policy->start[AA_CLASS_FILE] = DFA_START;
		}

		size_t state_count = policy->dfa->tables[YYTD_ID_BASE]->td_lolen;

		if (policy->start[0] >= state_count ||
		    policy->start[AA_CLASS_FILE] >= state_count) {
			*info = "invalid dfa start state";
			goto fail;
		}

		/* setup class index */
		for (i = AA_CLASS_FILE + 1; i <= AA_CLASS_LAST; i++) {
			policy->start[i] = aa_dfa_next(policy->dfa, policy->start[0],
						       i);
		}
	}

	/*
	 * Unfortunately due to a bug in earlier userspaces, a
	 * transition table may be present even when the dfa is
	 * not. For compatibility reasons unpack and discard.
	 */
	if (!unpack_trans_table(e, &policy->trans) && required_trans) {
		*info = "failed to unpack profile transition table";
		goto fail;
	}

	if (!policy->dfa && policy->trans.table)
		aa_free_str_table(&policy->trans);

	/* TODO: move compat mapping here, requires dfa merging first */
	/* TODO: move verify here, it has to be done after compat mappings */

	return 0;

fail:
	e->pos = pos;
	return error;
}

extern struct aa_profile *unpack_profile(struct aa_ext *e, char **ns_name);

static int klpp_verify_header(struct aa_ext *e, int required, const char **ns)
{
	int error = -EPROTONOSUPPORT;
	const char *name = NULL;

	/* get the interface version */
	if (!aa_unpack_u32(e, &e->version, "version")) {
		if (required) {
			audit_iface(NULL, NULL, NULL, "invalid profile format",
				    e, error);
			return error;
		}
	}

	/* Check that the interface version is currently supported.
	 * if not specified use previous version
	 * Mask off everything that is not kernel abi version
	 */
	if (VERSION_LT(e->version, v5) || VERSION_GT(e->version, v9)) {
		audit_iface(NULL, NULL, NULL, "unsupported interface version",
			    e, error);
		return error;
	}

	/* read the namespace if present */
	if (aa_unpack_str(e, &name, "namespace")) {
		if (*name == '\0') {
			audit_iface(NULL, NULL, NULL, "invalid namespace name",
				    e, error);
			return error;
		}
		if (*ns && strcmp(*ns, name)) {
			audit_iface(NULL, NULL, NULL, "invalid ns change", e,
				    error);
		} else if (!*ns) {
			*ns = kstrdup(name, GFP_KERNEL);
			if (!*ns)
				return -ENOMEM;
		}
	}

	return 0;
}

static bool verify_dfa_accept_index(struct aa_dfa *dfa, int table_size)
{
	int i;
	for (i = 0; i < dfa->tables[YYTD_ID_ACCEPT]->td_lolen; i++) {
		if (ACCEPT_TABLE(dfa)[i] >= table_size)
			return false;
	}
	return true;
}

extern bool verify_perms(struct aa_policydb *pdb);

static int verify_profile(struct aa_profile *profile)
{
	struct aa_ruleset *rules = list_first_entry(&profile->rules,
						    typeof(*rules), list);
	if (!rules)
		return 0;

	if ((rules->file.dfa && !verify_dfa_accept_index(rules->file.dfa,
							 rules->file.size)) ||
	    (rules->policy.dfa &&
	     !verify_dfa_accept_index(rules->policy.dfa, rules->policy.size))) {
		audit_iface(profile, NULL, NULL,
			    "Unpack: Invalid named transition", NULL, -EPROTO);
		return -EPROTO;
	}

	if (!verify_perms(&rules->file)) {
		audit_iface(profile, NULL, NULL,
			    "Unpack: Invalid perm index", NULL, -EPROTO);
		return -EPROTO;
	}
	if (!verify_perms(&rules->policy)) {
		audit_iface(profile, NULL, NULL,
			    "Unpack: Invalid perm index", NULL, -EPROTO);
		return -EPROTO;
	}
	if (!verify_perms(&profile->attach.xmatch)) {
		audit_iface(profile, NULL, NULL,
			    "Unpack: Invalid perm index", NULL, -EPROTO);
		return -EPROTO;
	}

	return 0;
}

void aa_load_ent_free(struct aa_load_ent *ent);

struct aa_load_ent *aa_load_ent_alloc(void);

static int compress_zstd(const char *src, size_t slen, char **dst, size_t *dlen)
{
#ifdef CONFIG_SECURITY_APPARMOR_EXPORT_BINARY
	const zstd_parameters params =
		zstd_get_params(aa_g_rawdata_compression_level, slen);
	const size_t wksp_len = zstd_cctx_workspace_bound(&params.cParams);
	void *wksp = NULL;
	zstd_cctx *ctx = NULL;
	size_t out_len = zstd_compress_bound(slen);
	void *out = NULL;
	int ret = 0;

	out = kvzalloc(out_len, GFP_KERNEL);
	if (!out) {
		ret = -ENOMEM;
		goto cleanup;
	}

	wksp = kvzalloc(wksp_len, GFP_KERNEL);
	if (!wksp) {
		ret = -ENOMEM;
		goto cleanup;
	}

	ctx = zstd_init_cctx(wksp, wksp_len);
	if (!ctx) {
		ret = -EINVAL;
		goto cleanup;
	}

	out_len = zstd_compress_cctx(ctx, out, out_len, src, slen, &params);
	if (zstd_is_error(out_len) || out_len >= slen) {
		ret = -EINVAL;
		goto cleanup;
	}

	if (is_vmalloc_addr(out)) {
		*dst = kvzalloc(out_len, GFP_KERNEL);
		if (*dst) {
			memcpy(*dst, out, out_len);
			kvfree(out);
			out = NULL;
		}
	} else {
		/*
		 * If the staging buffer was kmalloc'd, then using krealloc is
		 * probably going to be faster. The destination buffer will
		 * always be smaller, so it's just shrunk, avoiding a memcpy
		 */
		*dst = krealloc(out, out_len, GFP_KERNEL);
	}

	if (!*dst) {
		ret = -ENOMEM;
		goto cleanup;
	}

	*dlen = out_len;

cleanup:
	if (ret) {
		kvfree(out);
		*dst = NULL;
	}

	kvfree(wksp);
	return ret;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static int compress_loaddata(struct aa_loaddata *data)
{
	AA_BUG(data->compressed_size > 0);

	/*
	 * Shortcut the no compression case, else we increase the amount of
	 * storage required by a small amount
	 */
	if (aa_g_rawdata_compression_level != 0) {
		void *udata = data->data;
		int error = compress_zstd(udata, data->size, &data->data,
					  &data->compressed_size);
		if (error) {
			data->compressed_size = data->size;
			return error;
		}
		if (udata != data->data)
			kvfree(udata);
	} else
		data->compressed_size = data->size;

	return 0;
}

int klpp_aa_unpack(struct aa_loaddata *udata, struct list_head *lh,
	      const char **ns)
{
	struct aa_load_ent *tmp, *ent;
	struct aa_profile *profile = NULL;
	char *ns_name = NULL;
	int error;
	struct aa_ext e = {
		.start = udata->data,
		.end = udata->data + udata->size,
		.pos = udata->data,
	};

	*ns = NULL;
	while (e.pos < e.end) {
		void *start;
		error = klpp_verify_header(&e, e.pos == e.start, ns);
		if (error)
			goto fail;

		start = e.pos;
		profile = unpack_profile(&e, &ns_name);
		if (IS_ERR(profile)) {
			error = PTR_ERR(profile);
			goto fail;
		}

		error = verify_profile(profile);
		if (error)
			goto fail_profile;

		if (aa_g_hash_policy)
			error = aa_calc_profile_hash(profile, e.version, start,
						     e.pos - start);
		if (error)
			goto fail_profile;

		ent = aa_load_ent_alloc();
		if (!ent) {
			error = -ENOMEM;
			goto fail_profile;
		}

		ent->new = profile;
		ent->ns_name = ns_name;
		ns_name = NULL;
		list_add_tail(&ent->list, lh);
	}
	udata->abi = e.version & K_ABI_MASK;
	if (aa_g_hash_policy) {
		udata->hash = aa_calc_hash(udata->data, udata->size);
		if (IS_ERR(udata->hash)) {
			error = PTR_ERR(udata->hash);
			udata->hash = NULL;
			goto fail;
		}
	}

	if (aa_g_export_binary) {
		error = compress_loaddata(udata);
		if (error)
			goto fail;
	}
	return 0;

fail_profile:
	kfree(ns_name);
	aa_put_profile(profile);

fail:
	list_for_each_entry_safe(ent, tmp, lh, list) {
		list_del_init(&ent->list);
		aa_load_ent_free(ent);
	}

	return error;
}


#include <linux/livepatch.h>

extern typeof(aa_audit) aa_audit KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_audit);
extern typeof(aa_calc_hash) aa_calc_hash
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_calc_hash);
extern typeof(aa_calc_profile_hash) aa_calc_profile_hash
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_calc_profile_hash);
extern typeof(aa_dfa_next) aa_dfa_next
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_dfa_next);
extern typeof(aa_dfa_unpack) aa_dfa_unpack
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_dfa_unpack);
extern typeof(aa_free_str_table) aa_free_str_table
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_free_str_table);
extern typeof(aa_g_export_binary) aa_g_export_binary
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_g_export_binary);
extern typeof(aa_g_hash_policy) aa_g_hash_policy
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_g_hash_policy);
extern typeof(aa_g_paranoid_load) aa_g_paranoid_load
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_g_paranoid_load);
extern typeof(aa_g_rawdata_compression_level) aa_g_rawdata_compression_level
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_g_rawdata_compression_level);
extern typeof(aa_label_kref) aa_label_kref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_label_kref);
extern typeof(aa_load_ent_alloc) aa_load_ent_alloc
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_load_ent_alloc);
extern typeof(aa_load_ent_free) aa_load_ent_free
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_load_ent_free);
extern typeof(aa_unpack_blob) aa_unpack_blob
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_unpack_blob);
extern typeof(aa_unpack_nameX) aa_unpack_nameX
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_unpack_nameX);
extern typeof(aa_unpack_str) aa_unpack_str
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_unpack_str);
extern typeof(aa_unpack_strdup) aa_unpack_strdup
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_unpack_strdup);
extern typeof(aa_unpack_u32) aa_unpack_u32
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, aa_unpack_u32);
extern typeof(apparmor_blob_sizes) apparmor_blob_sizes
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, apparmor_blob_sizes);
extern typeof(audit_cb) audit_cb KLP_RELOC_SYMBOL_POS(vmlinux, vmlinux, audit_cb, 3);
extern typeof(unpack_profile) unpack_profile
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, unpack_profile);
extern typeof(verify_perms) verify_perms
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, verify_perms);
