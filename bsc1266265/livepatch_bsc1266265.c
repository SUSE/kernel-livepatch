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
#include <linux/export.h>
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

/* klp-ccp: from security/keys/key.c */
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/ima.h>
#include <linux/err.h>
/* klp-ccp: from security/keys/internal.h */
#include <linux/sched.h>
#include <linux/wait_bit.h>
#include <linux/cred.h>
#include <linux/key-type.h>
#include <linux/task_work.h>
#include <linux/keyctl.h>
#include <linux/refcount.h>
#include <linux/watch_queue.h>
#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

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

extern struct key_user *key_user_lookup(kuid_t uid);
extern void key_user_put(struct key_user *user);

extern unsigned key_quota_root_maxkeys;
extern unsigned key_quota_root_maxbytes;
extern unsigned key_quota_maxkeys;
extern unsigned key_quota_maxbytes;

extern struct kmem_cache *key_jar;
extern struct rb_root key_serial_tree;
extern spinlock_t key_serial_lock;

extern void key_set_index_key(struct keyring_index_key *index_key);

/* klp-ccp: from security/keys/key.c */
extern struct kmem_cache *key_jar;
extern struct rb_root		key_serial_tree;
extern spinlock_t key_serial_lock;

extern unsigned int key_quota_root_maxkeys;
extern unsigned int key_quota_root_maxbytes;
extern unsigned int key_quota_maxkeys;
extern unsigned int key_quota_maxbytes;

struct key_user *key_user_lookup(kuid_t uid);

void key_user_put(struct key_user *user);

static inline void key_alloc_serial(struct key *key)
{
	struct rb_node *parent, **p;
	struct key *xkey;

	/* propose a random serial number and look for a hole for it in the
	 * serial number tree */
	do {
		get_random_bytes(&key->serial, sizeof(key->serial));

		key->serial >>= 1; /* negative numbers are not permitted */
	} while (key->serial < 3);

	spin_lock(&key_serial_lock);

attempt_insertion:
	parent = NULL;
	p = &key_serial_tree.rb_node;

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
	rb_insert_color(&key->serial_node, &key_serial_tree);

	spin_unlock(&key_serial_lock);
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

extern struct cred *spnego_cred;

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
	if (current_cred() != spnego_cred)
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
	unsigned long irqflags;

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
	user = key_user_lookup(uid);
	if (!user)
		goto no_memory_1;

	/* check that the user's quota permits allocation of another key and
	 * its description */
	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA)) {
		unsigned maxkeys = uid_eq(uid, GLOBAL_ROOT_UID) ?
			key_quota_root_maxkeys : key_quota_maxkeys;
		unsigned maxbytes = uid_eq(uid, GLOBAL_ROOT_UID) ?
			key_quota_root_maxbytes : key_quota_maxbytes;

		spin_lock_irqsave(&user->lock, irqflags);
		if (!(flags & KEY_ALLOC_QUOTA_OVERRUN)) {
			if (user->qnkeys + 1 > maxkeys ||
			    user->qnbytes + quotalen > maxbytes ||
			    user->qnbytes + quotalen < user->qnbytes)
				goto no_quota;
		}

		user->qnkeys++;
		user->qnbytes += quotalen;
		spin_unlock_irqrestore(&user->lock, irqflags);
	}

	/* allocate and initialise the key and its description */
	key = kmem_cache_zalloc(key_jar, GFP_KERNEL);
	if (!key)
		goto no_memory_2;

	key->index_key.desc_len = desclen;
	key->index_key.description = kmemdup(desc, desclen + 1, GFP_KERNEL);
	if (!key->index_key.description)
		goto no_memory_3;
	key->index_key.type = type;
	key_set_index_key(&key->index_key);

	refcount_set(&key->usage, 1);
	init_rwsem(&key->sem);
	lockdep_set_class(&key->sem, &type->lock_class);
	key->user = user;
	key->quotalen = quotalen;
	key->datalen = type->def_datalen;
	key->uid = uid;
	key->gid = gid;
	key->perm = perm;
	key->expiry = TIME64_MAX;
	key->restrict_link = restrict_link;
	key->last_used_at = ktime_get_real_seconds();

	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA))
		key->flags |= 1 << KEY_FLAG_IN_QUOTA;
	if (flags & KEY_ALLOC_BUILT_IN)
		key->flags |= 1 << KEY_FLAG_BUILTIN;
	if (flags & KEY_ALLOC_UID_KEYRING)
		key->flags |= 1 << KEY_FLAG_UID_KEYRING;
	if (flags & KEY_ALLOC_SET_KEEP)
		key->flags |= 1 << KEY_FLAG_KEEP;

#ifdef KEY_DEBUGGING
#error "klp-ccp: non-taken branch"
#endif
	ret = security_key_alloc(key, cred, flags);
	if (ret < 0)
		goto security_error;

	/* publish the key by giving it a serial number */
	refcount_inc(&key->domain_tag->usage);
	atomic_inc(&user->nkeys);
	key_alloc_serial(key);

error:
	return key;

security_error:
	kfree(key->description);
	kmem_cache_free(key_jar, key);
	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA)) {
		spin_lock_irqsave(&user->lock, irqflags);
		user->qnkeys--;
		user->qnbytes -= quotalen;
		spin_unlock_irqrestore(&user->lock, irqflags);
	}
	key_user_put(user);
	key = ERR_PTR(ret);
	goto error;

no_memory_3:
	kmem_cache_free(key_jar, key);
no_memory_2:
	if (!(flags & KEY_ALLOC_NOT_IN_QUOTA)) {
		spin_lock_irqsave(&user->lock, irqflags);
		user->qnkeys--;
		user->qnbytes -= quotalen;
		spin_unlock_irqrestore(&user->lock, irqflags);
	}
	key_user_put(user);
no_memory_1:
	key = ERR_PTR(-ENOMEM);
	goto error;

no_quota:
	spin_unlock_irqrestore(&user->lock, irqflags);
	key_user_put(user);
	key = ERR_PTR(-EDQUOT);
	goto error;
}


#include <linux/livepatch.h>

extern typeof(key_jar) key_jar KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_jar);
extern typeof(key_quota_maxbytes) key_quota_maxbytes
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_quota_maxbytes);
extern typeof(key_quota_maxkeys) key_quota_maxkeys
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_quota_maxkeys);
extern typeof(key_quota_root_maxbytes) key_quota_root_maxbytes
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_quota_root_maxbytes);
extern typeof(key_quota_root_maxkeys) key_quota_root_maxkeys
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_quota_root_maxkeys);
extern typeof(key_serial_lock) key_serial_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_serial_lock);
extern typeof(key_serial_tree) key_serial_tree
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_serial_tree);
extern typeof(key_set_index_key) key_set_index_key
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_set_index_key);
extern typeof(key_user_lookup) key_user_lookup
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_user_lookup);
extern typeof(key_user_put) key_user_put
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, key_user_put);
extern typeof(security_key_alloc) security_key_alloc
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_key_alloc);
extern typeof(spnego_cred) spnego_cred
	 KLP_RELOC_SYMBOL(cifs, cifs, spnego_cred);
