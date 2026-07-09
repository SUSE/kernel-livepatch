/*
 * livepatch_bsc1266265
 *
 * Fix for CVE-2026-46243, bsc#1266265
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1266265.h"


/* klp-ccp: from security/keys/key.c */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/poison.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/security.h>

/* klp-ccp: from include/linux/key.h */
#ifdef __KERNEL__

#ifdef CONFIG_KEYS

struct key *klpp_key_alloc(struct key_type *type,
			     const char *desc,
			     kuid_t uid, kgid_t gid,
			     const struct cred *cred,
			     key_perm_t perm,
			     unsigned long flags,
			     struct key_restriction *restrict_link);

#else /* CONFIG_KEYS */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_KEYS */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __KERNEL__ */

/* klp-ccp: from include/linux/security.h */
#ifdef CONFIG_KEYS
#ifdef CONFIG_SECURITY

static int (*klpe_security_key_alloc)(struct key *key, const struct cred *cred, unsigned long flags);

#else
#error "klp-ccp: non-taken branch"
#endif
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_KEYS */

/* klp-ccp: from security/keys/key.c */
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/err.h>
/* klp-ccp: from security/keys/internal.h */
#include <linux/sched.h>
#include <linux/wait_bit.h>
#include <linux/cred.h>
#include <linux/key-type.h>
#include <linux/task_work.h>
#include <linux/keyctl.h>
#include <linux/refcount.h>
#include <linux/compat.h>

struct key_user {
	struct rb_node		node;
	struct mutex		cons_lock;	/* construction initiation lock */
	spinlock_t		lock;
	refcount_t		usage;		/* for accessing qnkeys & qnbytes */
	atomic_t		nkeys;		/* number of keys */
	atomic_t		nikeys;		/* number of instantiated keys */
	kuid_t			uid;
	int			qnkeys;		/* number of keys allocated to this user */
	int			qnbytes;	/* number of bytes allocated to this user */
};

static struct key_user *(*klpe_key_user_lookup)(kuid_t uid);
static void (*klpe_key_user_put)(struct key_user *user);

static unsigned (*klpe_key_quota_root_maxkeys);
static unsigned (*klpe_key_quota_root_maxbytes);
static unsigned (*klpe_key_quota_maxkeys);
static unsigned (*klpe_key_quota_maxbytes);

static struct kmem_cache *(*klpe_key_jar);
static struct rb_root (*klpe_key_serial_tree);
static spinlock_t (*klpe_key_serial_lock);

/* klp-ccp: from security/keys/key.c */
static inline void klpr_key_alloc_serial(struct key *key)
{
	struct rb_node *parent, **p;
	struct key *xkey;

	/* propose a random serial number and look for a hole for it in the
	 * serial number tree */
	do {
		get_random_bytes(&key->serial, sizeof(key->serial));

		key->serial >>= 1; /* negative numbers are not permitted */
	} while (key->serial < 3);

	spin_lock(&(*klpe_key_serial_lock));

attempt_insertion:
	parent = NULL;
	p = &(*klpe_key_serial_tree).rb_node;

	while (*p) {
		parent = *p;
		xkey = rb_entry(parent, struct key, serial_node);

		if (key->serial < xkey->serial)
			p = &(*p)->rb_left;
		else if (key->serial > xkey->serial)
			p = &(*p)->rb_right;
		else
			goto serial_exists;
	}

	/* we've found a suitable hole - arrange for this key to occupy it */
	rb_link_node(&key->serial_node, parent, p);
	rb_insert_color(&key->serial_node, &(*klpe_key_serial_tree));

	spin_unlock(&(*klpe_key_serial_lock));
	return;

	/* we found a key with the proposed serial number - walk the tree from
	 * that point looking for the next unused serial number */
serial_exists:
	for (;;) {
		key->serial++;
		if (key->serial < 3) {
			key->serial = 3;
			goto attempt_insertion;
		}

		parent = rb_next(parent);
		if (!parent)
			goto attempt_insertion;

		xkey = rb_entry(parent, struct key, serial_node);
		if (key->serial < xkey->serial)
			goto attempt_insertion;
	}
}

static struct cred * (*klpe_spnego_cred);

static int
cifs_spnego_key_vet_description(const char *description)
{
	/*
	 * cifs.spnego descriptions are authority-bearing inputs to cifs.upcall.
	 * They are only valid when produced by CIFS while using the private
	 * spnego_cred installed below.  Do not let userspace create this type
	 * of key through request_key(2)/add_key(2), since the helper treats
	 * pid/uid/creduid/upcall_target as kernel-originating fields.
	 */
	if (!klpe_spnego_cred || current_cred() != *klpe_spnego_cred)
		return -EPERM;
	return 0;
}

struct key *klpp_key_alloc(struct key_type *type, const char *desc,
		      kuid_t uid, kgid_t gid, const struct cred *cred,
		      key_perm_t perm, unsigned long flags,
		      struct key_restriction *restrict_link)
{
	struct key_user *user = NULL;
	struct key *key;
	size_t desclen, quotalen;
	int ret;

	key = ERR_PTR(-EINVAL);
	if (!desc || !*desc)
		goto error;

	if (!strncmp(type->name, "cifs.spnego", 11)) {
		/*
		 * Do not let the compiler reorder the load of spnego_cred
		 * before checking if cifs module is loaded.
		 */
		barrier();

		ret = cifs_spnego_key_vet_description(desc);
		if (ret < 0) {
			key = ERR_PTR(ret);
			goto error;
		}

	} else if (type->vet_description) {
		ret = type->vet_description(desc);
		if (ret < 0) {
			key = ERR_PTR(ret);
			goto error;
		}
	}

	desclen = strlen(desc);
	quotalen = desclen + 1 + type->def_datalen;

	/* get hold of the key tracking for this user */
	user = (*klpe_key_user_lookup)(uid);
	if (!user)
		goto no_memory_1;

	/* check that the user's quota permits allocation of another key and
	 * its description */
	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA)) {
		unsigned maxkeys = uid_eq(uid, GLOBAL_ROOT_UID) ?
			(*klpe_key_quota_root_maxkeys) : (*klpe_key_quota_maxkeys);
		unsigned maxbytes = uid_eq(uid, GLOBAL_ROOT_UID) ?
			(*klpe_key_quota_root_maxbytes) : (*klpe_key_quota_maxbytes);

		spin_lock(&user->lock);
		if (!(flags & KEY_ALLOC_QUOTA_OVERRUN)) {
			if (user->qnkeys + 1 > maxkeys ||
			    user->qnbytes + quotalen > maxbytes ||
			    user->qnbytes + quotalen < user->qnbytes)
				goto no_quota;
		}

		user->qnkeys++;
		user->qnbytes += quotalen;
		spin_unlock(&user->lock);
	}

	/* allocate and initialise the key and its description */
	key = kmem_cache_zalloc((*klpe_key_jar), GFP_KERNEL);
	if (!key)
		goto no_memory_2;

	key->index_key.desc_len = desclen;
	key->index_key.description = kmemdup(desc, desclen + 1, GFP_KERNEL);
	if (!key->index_key.description)
		goto no_memory_3;

	refcount_set(&key->usage, 1);
	init_rwsem(&key->sem);
	lockdep_set_class(&key->sem, &type->lock_class);
	key->index_key.type = type;
	key->user = user;
	key->quotalen = quotalen;
	key->datalen = type->def_datalen;
	key->uid = uid;
	key->gid = gid;
	key->perm = perm;
	key->restrict_link = restrict_link;
	key->last_used_at = ktime_get_real_seconds();

	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA))
		key->flags |= 1 << KEY_FLAG_IN_QUOTA;
	if (flags & KEY_ALLOC_BUILT_IN)
		key->flags |= 1 << KEY_FLAG_BUILTIN;
	if (flags & KEY_ALLOC_UID_KEYRING)
		key->flags |= 1 << KEY_FLAG_UID_KEYRING;

#ifdef KEY_DEBUGGING
#error "klp-ccp: non-taken branch"
#endif
	ret = (*klpe_security_key_alloc)(key, cred, flags);
	if (ret < 0)
		goto security_error;

	/* publish the key by giving it a serial number */
	atomic_inc(&user->nkeys);
	klpr_key_alloc_serial(key);

error:
	return key;

security_error:
	kfree(key->description);
	kmem_cache_free((*klpe_key_jar), key);
	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA)) {
		spin_lock(&user->lock);
		user->qnkeys--;
		user->qnbytes -= quotalen;
		spin_unlock(&user->lock);
	}
	(*klpe_key_user_put)(user);
	key = ERR_PTR(ret);
	goto error;

no_memory_3:
	kmem_cache_free((*klpe_key_jar), key);
no_memory_2:
	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA)) {
		spin_lock(&user->lock);
		user->qnkeys--;
		user->qnbytes -= quotalen;
		spin_unlock(&user->lock);
	}
	(*klpe_key_user_put)(user);
no_memory_1:
	key = ERR_PTR(-ENOMEM);
	goto error;

no_quota:
	spin_unlock(&user->lock);
	(*klpe_key_user_put)(user);
	key = ERR_PTR(-EDQUOT);
	goto error;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "key_jar", (void *)&klpe_key_jar },
	{ "key_quota_maxbytes", (void *)&klpe_key_quota_maxbytes },
	{ "key_quota_maxkeys", (void *)&klpe_key_quota_maxkeys },
	{ "key_quota_root_maxbytes", (void *)&klpe_key_quota_root_maxbytes },
	{ "key_quota_root_maxkeys", (void *)&klpe_key_quota_root_maxkeys },
	{ "key_serial_lock", (void *)&klpe_key_serial_lock },
	{ "key_serial_tree", (void *)&klpe_key_serial_tree },
	{ "key_user_lookup", (void *)&klpe_key_user_lookup },
	{ "key_user_put", (void *)&klpe_key_user_put },
	{ "security_key_alloc", (void *)&klpe_security_key_alloc },
};

static struct klp_kallsyms_reloc klp_funcs_cifs[] = {
	{ "spnego_cred", (void *)&klpe_spnego_cred, "cifs" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs_cifs, ARRAY_SIZE(klp_funcs_cifs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1266265_init(void)
{
	int ret;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
	if (ret)
		return ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs_cifs,
					    ARRAY_SIZE(klp_funcs_cifs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1266265_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
