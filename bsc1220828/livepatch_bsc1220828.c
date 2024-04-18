/*
 * livepatch_bsc1220828
 *
 * Fix for CVE-2024-26622, bsc#1220828
 *
 *  Upstream commit:
 *  2f03fc340cac ("tomoyo: fix UAF write bug in tomoyo_write_control()")
 *
 *  SLE12-SP5 commit:
 *  e9342590808639abe7ffd00ba703b892909132f2
 *
 *  SLE15-SP2 and -SP3 commit:
 *  6d24f8e53565d0ab511d31b61cd3388bab978043
 *
 *  SLE15-SP4 and -SP5 commit:
 *  c8e5b386023a5c47cf82dff7ff2ac9d2e444f540
 *
 *  Copyright (c) 2024 SUSE
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

#if IS_ENABLED(CONFIG_SECURITY_TOMOYO)

#include <linux/types.h>
#include <linux/pid_namespace.h>

static struct task_struct *(*klpe_find_task_by_vpid)(pid_t nr);
static struct task_struct *(*klpe_find_task_by_pid_ns)(pid_t nr, struct pid_namespace *ns);

/* klp-ccp: from security/tomoyo/common.h */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/lsm_hooks.h>

/* klp-ccp: from security/tomoyo/common.h */
#include <net/ipv6.h>

#define TOMOYO_MAX_PROFILES 256

#define TOMOYO_MAX_ACL_GROUPS 256

enum tomoyo_policy_id {
	TOMOYO_ID_GROUP,
	TOMOYO_ID_ADDRESS_GROUP,
	TOMOYO_ID_PATH_GROUP,
	TOMOYO_ID_NUMBER_GROUP,
	TOMOYO_ID_TRANSITION_CONTROL,
	TOMOYO_ID_AGGREGATOR,
	TOMOYO_ID_MANAGER,
	TOMOYO_ID_CONDITION,
	TOMOYO_ID_NAME,
	TOMOYO_ID_ACL,
	TOMOYO_ID_DOMAIN,
	TOMOYO_MAX_POLICY
};

enum tomoyo_domain_info_flags_index {
	/* Quota warnning flag.   */
	TOMOYO_DIF_QUOTA_WARNED,
	/*
	 * This domain was unable to create a new domain at
	 * tomoyo_find_next_domain() because the name of the domain to be
	 * created was too long or it could not allocate memory.
	 * More than one process continued execve() without domain transition.
	 */
	TOMOYO_DIF_TRANSITION_FAILED,
	TOMOYO_MAX_DOMAIN_INFO_FLAGS
};

enum tomoyo_group_id {
	TOMOYO_PATH_GROUP,
	TOMOYO_NUMBER_GROUP,
	TOMOYO_ADDRESS_GROUP,
	TOMOYO_MAX_GROUP
};

enum tomoyo_securityfs_interface_index {
	TOMOYO_DOMAINPOLICY,
	TOMOYO_EXCEPTIONPOLICY,
	TOMOYO_PROCESS_STATUS,
	TOMOYO_STAT,
	TOMOYO_AUDIT,
	TOMOYO_VERSION,
	TOMOYO_PROFILE,
	TOMOYO_QUERY,
	TOMOYO_MANAGER
};

enum tomoyo_policy_stat_type {
	/* Do not change this order. */
	TOMOYO_STAT_POLICY_UPDATES,
	TOMOYO_STAT_POLICY_LEARNING,   /* == TOMOYO_CONFIG_LEARNING */
	TOMOYO_STAT_POLICY_PERMISSIVE, /* == TOMOYO_CONFIG_PERMISSIVE */
	TOMOYO_STAT_POLICY_ENFORCING,  /* == TOMOYO_CONFIG_ENFORCING */
	TOMOYO_MAX_POLICY_STAT
};

struct tomoyo_acl_head {
	struct list_head list;
	s8 is_deleted; /* true or false or TOMOYO_GC_IN_PROGRESS */
} __packed;

struct tomoyo_path_info {
	const char *name;
	u32 hash;          /* = full_name_hash(name, strlen(name)) */
	u16 const_len;     /* = tomoyo_const_part_length(name)     */
	bool is_dir;       /* = tomoyo_strendswith(name, "/")      */
	bool is_patterned; /* = tomoyo_path_contains_pattern(name) */
};

struct tomoyo_domain_info {
	struct list_head list;
	struct list_head acl_info_list;
	/* Name of this domain. Never NULL.          */
	const struct tomoyo_path_info *domainname;
	/* Namespace for this domain. Never NULL. */
	struct tomoyo_policy_namespace *ns;
	/* Group numbers to use.   */
	unsigned long group[TOMOYO_MAX_ACL_GROUPS / BITS_PER_LONG];
	u8 profile;        /* Profile number to use. */
	bool is_deleted;   /* Delete flag.           */
	bool flags[TOMOYO_MAX_DOMAIN_INFO_FLAGS];
	atomic_t users; /* Number of referring tasks. */
};

#define TOMOYO_MAX_IO_READ_QUEUE 64

struct tomoyo_io_buffer {
	void (*read)(struct tomoyo_io_buffer *head);
	int (*write)(struct tomoyo_io_buffer *head);
	__poll_t (*poll)(struct file *file, poll_table *wait);
	/* Exclusive lock for this structure.   */
	struct mutex io_sem;
	char __user *read_user_buf;
	size_t read_user_buf_avail;
	struct {
		struct list_head *ns;
		struct list_head *domain;
		struct list_head *group;
		struct list_head *acl;
		size_t avail;
		unsigned int step;
		unsigned int query_index;
		u16 index;
		u16 cond_index;
		u8 acl_group_index;
		u8 cond_step;
		u8 bit;
		u8 w_pos;
		bool eof;
		bool print_this_domain_only;
		bool print_transition_related_only;
		bool print_cond_part;
		const char *w[TOMOYO_MAX_IO_READ_QUEUE];
	} r;
	struct {
		struct tomoyo_policy_namespace *ns;
		/* The position currently writing to.   */
		struct tomoyo_domain_info *domain;
		/* Bytes available for writing.         */
		size_t avail;
		bool is_delete;
	} w;
	/* Buffer for reading.                  */
	char *read_buf;
	/* Size of read buffer.                 */
	size_t readbuf_size;
	/* Buffer for writing.                  */
	char *write_buf;
	/* Size of write buffer.                */
	size_t writebuf_size;
	/* Type of this interface.              */
	enum tomoyo_securityfs_interface_index type;
	/* Users counter protected by tomoyo_io_buffer_list_lock. */
	u8 users;
	/* List for telling GC not to kfree() elements. */
	struct list_head list;
};

struct tomoyo_manager {
	struct tomoyo_acl_head head;
	/* A path to program or a domainname. */
	const struct tomoyo_path_info *manager;
};

struct tomoyo_policy_namespace {
	/* Profile table. Memory is allocated as needed. */
	struct tomoyo_profile *profile_ptr[TOMOYO_MAX_PROFILES];
	/* List of "struct tomoyo_group". */
	struct list_head group_list[TOMOYO_MAX_GROUP];
	/* List of policy. */
	struct list_head policy_list[TOMOYO_MAX_POLICY];
	/* The global ACL referred by "use_group" keyword. */
	struct list_head acl_group[TOMOYO_MAX_ACL_GROUPS];
	/* List for connecting to tomoyo_namespace_list list. */
	struct list_head namespace_list;
	/* Profile version. Currently only 20150505 is defined. */
	unsigned int profile_version;
	/* Name of this namespace (e.g. "<kernel>", "</usr/sbin/httpd>" ). */
	const char *name;
};

struct tomoyo_task {
	struct tomoyo_domain_info *domain_info;
	struct tomoyo_domain_info *old_domain_info;
};

static bool (*klpe_tomoyo_domain_def)(const unsigned char *buffer);

static const char *(*klpe_tomoyo_get_exe)(void);

static struct tomoyo_domain_info *(*klpe_tomoyo_domain)(void);
static struct tomoyo_domain_info *(*klpe_tomoyo_find_domain)(const char *domainname);

static void (*klpe_tomoyo_normalize_line)(unsigned char *buffer);

static void (*klpe_tomoyo_update_stat)(const u8 index);

static bool (*klpe_tomoyo_policy_loaded);

static struct srcu_struct (*klpe_tomoyo_ss);

static struct tomoyo_policy_namespace (*klpe_tomoyo_kernel_namespace);

static struct lsm_blob_sizes (*klpe_tomoyo_blob_sizes);

static inline int klpr_tomoyo_read_lock(void)
{
	return srcu_read_lock(&(*klpe_tomoyo_ss));
}

static inline void klpr_tomoyo_read_unlock(int idx)
{
	srcu_read_unlock(&(*klpe_tomoyo_ss), idx);
}

static inline bool tomoyo_pathcmp(const struct tomoyo_path_info *a,
				  const struct tomoyo_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

static inline struct tomoyo_task *klpr_tomoyo_task(struct task_struct *task)
{
	return task->security + (*klpe_tomoyo_blob_sizes).lbs_task;
}

/* klp-ccp: from security/tomoyo/common.c */
static bool (*klpe_tomoyo_manage_by_non_root);

static void (*klpe_tomoyo_io_printf)(struct tomoyo_io_buffer *head, const char *fmt,
			     ...) __printf(2, 3);

static bool klpr_tomoyo_manager(void)
{
	struct tomoyo_manager *ptr;
	const char *exe;
	const struct task_struct *task = current;
	const struct tomoyo_path_info *domainname = (*klpe_tomoyo_domain)()->domainname;
	bool found = IS_ENABLED(CONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING);

	if (!(*klpe_tomoyo_policy_loaded))
		return true;
	if (!(*klpe_tomoyo_manage_by_non_root) &&
	    (!uid_eq(task->cred->uid,  GLOBAL_ROOT_UID) ||
	     !uid_eq(task->cred->euid, GLOBAL_ROOT_UID)))
		return false;
	exe = (*klpe_tomoyo_get_exe)();
	if (!exe)
		return false;
	list_for_each_entry_rcu(ptr, &(*klpe_tomoyo_kernel_namespace).policy_list[TOMOYO_ID_MANAGER], head.list,
				srcu_read_lock_held(&tomoyo_ss)) {
		if (!ptr->head.is_deleted &&
		    (!tomoyo_pathcmp(domainname, ptr->manager) ||
		     !strcmp(exe, ptr->manager->name))) {
			found = true;
			break;
		}
	}
	if (!found) { /* Reduce error messages. */
		static pid_t last_pid;
		const pid_t pid = current->pid;

		if (last_pid != pid) {
			pr_warn("%s ( %s ) is not permitted to update policies.\n",
				domainname->name, exe);
			last_pid = pid;
		}
	}
	kfree(exe);
	return found;
}

static struct tomoyo_domain_info *klpr_tomoyo_find_domain_by_qid
(unsigned int serial);

static bool klpr_tomoyo_select_domain(struct tomoyo_io_buffer *head,
				 const char *data)
{
	unsigned int pid;
	struct tomoyo_domain_info *domain = NULL;
	bool global_pid = false;

	if (strncmp(data, "select ", 7))
		return false;
	data += 7;
	if (sscanf(data, "pid=%u", &pid) == 1 ||
	    (global_pid = true, sscanf(data, "global-pid=%u", &pid) == 1)) {
		struct task_struct *p;

		rcu_read_lock();
		if (global_pid)
			p = (*klpe_find_task_by_pid_ns)(pid, &init_pid_ns);
		else
			p = (*klpe_find_task_by_vpid)(pid);
		if (p)
			domain = klpr_tomoyo_task(p)->domain_info;
		rcu_read_unlock();
	} else if (!strncmp(data, "domain=", 7)) {
		if ((*klpe_tomoyo_domain_def)(data + 7))
			domain = (*klpe_tomoyo_find_domain)(data + 7);
	} else if (sscanf(data, "Q=%u", &pid) == 1) {
		domain = klpr_tomoyo_find_domain_by_qid(pid);
	} else
		return false;
	head->w.domain = domain;
	/* Accessing read_buf is safe because head->io_sem is held. */
	if (!head->read_buf)
		return true; /* Do nothing if open(O_WRONLY). */
	memset(&head->r, 0, sizeof(head->r));
	head->r.print_this_domain_only = true;
	if (domain)
		head->r.domain = &domain->list;
	else
		head->r.eof = true;
	(*klpe_tomoyo_io_printf)(head, "# select %s\n", data);
	if (domain && domain->is_deleted)
		(*klpe_tomoyo_io_printf)(head, "# This is a deleted domain.\n");
	return true;
}

struct tomoyo_query {
	struct list_head list;
	struct tomoyo_domain_info *domain;
	char *query;
	size_t query_len;
	unsigned int serial;
	u8 timer;
	u8 answer;
	u8 retry;
};

static struct list_head (*klpe_tomoyo_query_list);

static spinlock_t (*klpe_tomoyo_query_list_lock);

static struct tomoyo_domain_info *klpr_tomoyo_find_domain_by_qid
(unsigned int serial)
{
	struct tomoyo_query *ptr;
	struct tomoyo_domain_info *domain = NULL;

	spin_lock(&(*klpe_tomoyo_query_list_lock));
	list_for_each_entry(ptr, &(*klpe_tomoyo_query_list), list) {
		if (ptr->serial != serial)
			continue;
		domain = ptr->domain;
		break;
	}
	spin_unlock(&(*klpe_tomoyo_query_list_lock));
	return domain;
}

static int (*klpe_tomoyo_parse_policy)(struct tomoyo_io_buffer *head, char *line);

ssize_t klpp_tomoyo_write_control(struct tomoyo_io_buffer *head,
			     const char __user *buffer, const int buffer_len)
{
	int error = buffer_len;
	size_t avail_len = buffer_len;
	char *cp0;
	int idx;

	if (!head->write)
		return -EINVAL;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	cp0 = head->write_buf;
	head->read_user_buf_avail = 0;
	idx = klpr_tomoyo_read_lock();
	/* Read a line and dispatch it to the policy handler. */
	while (avail_len > 0) {
		char c;

		if (head->w.avail >= head->writebuf_size - 1) {
			const int len = head->writebuf_size * 2;
			char *cp = kzalloc(len, GFP_NOFS);

			if (!cp) {
				error = -ENOMEM;
				break;
			}
			memmove(cp, cp0, head->w.avail);
			kfree(cp0);
			head->write_buf = cp;
			cp0 = cp;
			head->writebuf_size = len;
		}
		if (get_user(c, buffer)) {
			error = -EFAULT;
			break;
		}
		buffer++;
		avail_len--;
		cp0[head->w.avail++] = c;
		if (c != '\n')
			continue;
		cp0[head->w.avail - 1] = '\0';
		head->w.avail = 0;
		(*klpe_tomoyo_normalize_line)(cp0);
		if (!strcmp(cp0, "reset")) {
			head->w.ns = &(*klpe_tomoyo_kernel_namespace);
			head->w.domain = NULL;
			memset(&head->r, 0, sizeof(head->r));
			continue;
		}
		/* Don't allow updating policies by non manager programs. */
		switch (head->type) {
		case TOMOYO_PROCESS_STATUS:
			/* This does not write anything. */
			break;
		case TOMOYO_DOMAINPOLICY:
			if (klpr_tomoyo_select_domain(head, cp0))
				continue;
			fallthrough;
		case TOMOYO_EXCEPTIONPOLICY:
			if (!strcmp(cp0, "select transition_only")) {
				head->r.print_transition_related_only = true;
				continue;
			}
			fallthrough;
		default:
			if (!klpr_tomoyo_manager()) {
				error = -EPERM;
				goto out;
			}
		}
		switch ((*klpe_tomoyo_parse_policy)(head, cp0)) {
		case -EPERM:
			error = -EPERM;
			goto out;
		case 0:
			switch (head->type) {
			case TOMOYO_DOMAINPOLICY:
			case TOMOYO_EXCEPTIONPOLICY:
			case TOMOYO_STAT:
			case TOMOYO_PROFILE:
			case TOMOYO_MANAGER:
				(*klpe_tomoyo_update_stat)(TOMOYO_STAT_POLICY_UPDATES);
				break;
			default:
				break;
			}
			break;
		}
	}
out:
	klpr_tomoyo_read_unlock(idx);
	mutex_unlock(&head->io_sem);
	return error;
}



#include "livepatch_bsc1220828.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "find_task_by_pid_ns", (void *)&klpe_find_task_by_pid_ns },
	{ "find_task_by_vpid", (void *)&klpe_find_task_by_vpid },
	{ "tomoyo_blob_sizes", (void *)&klpe_tomoyo_blob_sizes },
	{ "tomoyo_domain", (void *)&klpe_tomoyo_domain },
	{ "tomoyo_domain_def", (void *)&klpe_tomoyo_domain_def },
	{ "tomoyo_find_domain", (void *)&klpe_tomoyo_find_domain },
	{ "tomoyo_get_exe", (void *)&klpe_tomoyo_get_exe },
	{ "tomoyo_io_printf", (void *)&klpe_tomoyo_io_printf },
	{ "tomoyo_kernel_namespace", (void *)&klpe_tomoyo_kernel_namespace },
	{ "tomoyo_manage_by_non_root",
	  (void *)&klpe_tomoyo_manage_by_non_root },
	{ "tomoyo_normalize_line", (void *)&klpe_tomoyo_normalize_line },
	{ "tomoyo_parse_policy", (void *)&klpe_tomoyo_parse_policy },
	{ "tomoyo_policy_loaded", (void *)&klpe_tomoyo_policy_loaded },
	{ "tomoyo_query_list", (void *)&klpe_tomoyo_query_list },
	{ "tomoyo_query_list_lock", (void *)&klpe_tomoyo_query_list_lock },
	{ "tomoyo_ss", (void *)&klpe_tomoyo_ss },
	{ "tomoyo_update_stat", (void *)&klpe_tomoyo_update_stat },
};

int livepatch_bsc1220828_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_SECURITY_TOMOYO) */
