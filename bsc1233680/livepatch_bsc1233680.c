/*
 * livepatch_bsc1233680
 *
 * Fix for CVE-2024-50301, bsc#1233680
 *
 *  Upstream commit:
 *  4a74da044ec9 ("security/keys: fix slab-out-of-bounds in key_task_permission")
 *
 *  SLE12-SP5 commit:
 *  6e6d2aa845dc48795801322ca0c053f58a32b1dd
 *
 *  SLE15-SP3 commit:
 *  7b5321adde65f3e91bc281b80da7a7768364ddc0
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b8c1415baa04c3785319caddffae864fd63fab23
 *
 *  SLE15-SP6 commit:
 *  277fa5f1a2ea54432bdd98dadf04996b7909ac7b
 *
 *  SLE MICRO-6-0 commit:
 *  277fa5f1a2ea54432bdd98dadf04996b7909ac7b
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.com>
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


/* klp-ccp: from security/keys/keyring.c */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/security.h>

/* klp-ccp: from include/linux/assoc_array.h */
#ifdef CONFIG_ASSOCIATIVE_ARRAY

static int (*klpe_assoc_array_iterate)(const struct assoc_array *array,
			       int (*iterator)(const void *object,
					       void *iterator_data),
			       void *iterator_data);
static void *(*klpe_assoc_array_find)(const struct assoc_array *array,
			      const struct assoc_array_ops *ops,
			      const void *index_key);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_ASSOCIATIVE_ARRAY */

/* klp-ccp: from include/linux/cred.h */
#define _LINUX_CRED_H

/* klp-ccp: from security/keys/keyring.c */
#include <linux/err.h>
#include <keys/keyring-type.h>

#include <linux/assoc_array_priv.h>

/* klp-ccp: from security/keys/internal.h */
#include <linux/sched.h>
#include <linux/wait_bit.h>
#include <linux/cred.h>
#include <linux/key-type.h>

#include <linux/refcount.h>

#define kenter(FMT, ...) \
	no_printk(KERN_DEBUG "==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	no_printk(KERN_DEBUG "<== %s()"FMT"\n", __func__, ##__VA_ARGS__)
#define kdebug(FMT, ...) \
	no_printk(KERN_DEBUG FMT"\n", ##__VA_ARGS__)

struct keyring_search_context {
	struct keyring_index_key index_key;
	const struct cred	*cred;
	struct key_match_data	match_data;
	unsigned		flags;
#define KEYRING_SEARCH_NO_STATE_CHECK	0x0001	/* Skip state checks */
#define KEYRING_SEARCH_DO_STATE_CHECK	0x0002	/* Override NO_STATE_CHECK */
#define KEYRING_SEARCH_NO_UPDATE_TIME	0x0004	/* Don't update times */
#define KEYRING_SEARCH_NO_CHECK_PERM	0x0008	/* Don't check permissions */
#define KEYRING_SEARCH_DETECT_TOO_DEEP	0x0010	/* Give an error on excessive depth */
	int (*iterator)(const void *object, void *iterator_data);

	/* Internal stuff */
	int			skipped_ret;
	bool			possessed;
	key_ref_t		result;
	struct timespec		now;
};

extern int key_task_permission(const key_ref_t key_ref,
			       const struct cred *cred,
			       key_perm_t perm);

#define key_check(key) do {} while(0)

/* klp-ccp: from security/keys/keyring.c */
#define KEYRING_SEARCH_MAX_DEPTH 6

#define KEYRING_PTR_SUBTYPE	0x2UL

static inline bool keyring_ptr_is_keyring(const struct assoc_array_ptr *x)
{
	return (unsigned long)x & KEYRING_PTR_SUBTYPE;
}
static inline struct key *keyring_ptr_to_key(const struct assoc_array_ptr *x)
{
	void *object = assoc_array_ptr_to_leaf(x);
	return (struct key *)((unsigned long)object & ~KEYRING_PTR_SUBTYPE);
}
static inline void *keyring_key_to_ptr(struct key *key)
{
	if (key->type == &key_type_keyring)
		return (void *)((unsigned long)key | KEYRING_PTR_SUBTYPE);
	return key;
}

extern struct key_type key_type_keyring;

extern typeof(key_type_keyring) key_type_keyring;

static bool (*klpe_keyring_compare_object)(const void *object, const void *data);

static const struct assoc_array_ops (*klpe_keyring_assoc_array_ops);

static int klpr_search_keyring(struct key *keyring, struct keyring_search_context *ctx)
{
	if (ctx->match_data.lookup_type == KEYRING_SEARCH_LOOKUP_DIRECT) {
		const void *object;

		object = (*klpe_assoc_array_find)(&keyring->keys,
					  &(*klpe_keyring_assoc_array_ops),
					  &ctx->index_key);
		return object ? ctx->iterator(object, ctx) : 0;
	}
	return (*klpe_assoc_array_iterate)(&keyring->keys, ctx->iterator, ctx);
}

bool klpp_search_nested_keyrings(struct key *keyring,
				   struct keyring_search_context *ctx)
{
	struct {
		struct key *keyring;
		struct assoc_array_node *node;
		int slot;
	} stack[KEYRING_SEARCH_MAX_DEPTH];

	struct assoc_array_shortcut *shortcut;
	struct assoc_array_node *node;
	struct assoc_array_ptr *ptr;
	struct key *key;
	int sp = 0, slot;

	kenter("{%d},{%s,%s}",
	       keyring->serial,
	       ctx->index_key.type->name,
	       ctx->index_key.description);

#define STATE_CHECKS (KEYRING_SEARCH_NO_STATE_CHECK | KEYRING_SEARCH_DO_STATE_CHECK)
	BUG_ON((ctx->flags & STATE_CHECKS) == 0 ||
	       (ctx->flags & STATE_CHECKS) == STATE_CHECKS);

	/* Check to see if this top-level keyring is what we are looking for
	 * and whether it is valid or not.
	 */
	if (ctx->match_data.lookup_type == KEYRING_SEARCH_LOOKUP_ITERATE ||
	    (*klpe_keyring_compare_object)(keyring, &ctx->index_key)) {
		ctx->skipped_ret = 2;
		switch (ctx->iterator(keyring_key_to_ptr(keyring), ctx)) {
		case 1:
			goto found;
		case 2:
			return false;
		default:
			break;
		}
	}

	ctx->skipped_ret = 0;

	/* Start processing a new keyring */
descend_to_keyring:
	kdebug("descend to %d", keyring->serial);
	if (keyring->flags & ((1 << KEY_FLAG_INVALIDATED) |
			      (1 << KEY_FLAG_REVOKED)))
		goto not_this_keyring;

	/* Search through the keys in this keyring before its searching its
	 * subtrees.
	 */
	if (klpr_search_keyring(keyring, ctx))
		goto found;

	/* Then manually iterate through the keyrings nested in this one.
	 *
	 * Start from the root node of the index tree.  Because of the way the
	 * hash function has been set up, keyrings cluster on the leftmost
	 * branch of the root node (root slot 0) or in the root node itself.
	 * Non-keyrings avoid the leftmost branch of the root entirely (root
	 * slots 1-15).
	 */
	ptr = READ_ONCE(keyring->keys.root);
	if (!ptr)
		goto not_this_keyring;

	if (assoc_array_ptr_is_shortcut(ptr)) {
		/* If the root is a shortcut, either the keyring only contains
		 * keyring pointers (everything clusters behind root slot 0) or
		 * doesn't contain any keyring pointers.
		 */
		shortcut = assoc_array_ptr_to_shortcut(ptr);
		smp_read_barrier_depends();
		if ((shortcut->index_key[0] & ASSOC_ARRAY_FAN_MASK) != 0)
			goto not_this_keyring;

		ptr = READ_ONCE(shortcut->next_node);
		node = assoc_array_ptr_to_node(ptr);
		goto begin_node;
	}

	node = assoc_array_ptr_to_node(ptr);
	smp_read_barrier_depends();

	ptr = node->slots[0];
	if (!assoc_array_ptr_is_meta(ptr))
		goto begin_node;

descend_to_node:
	/* Descend to a more distal node in this keyring's content tree and go
	 * through that.
	 */
	kdebug("descend");
	if (assoc_array_ptr_is_shortcut(ptr)) {
		shortcut = assoc_array_ptr_to_shortcut(ptr);
		smp_read_barrier_depends();
		ptr = READ_ONCE(shortcut->next_node);
		BUG_ON(!assoc_array_ptr_is_node(ptr));
	}
	node = assoc_array_ptr_to_node(ptr);

begin_node:
	kdebug("begin_node");
	smp_read_barrier_depends();
	slot = 0;
ascend_to_node:
	/* Go through the slots in a node */
	for (; slot < ASSOC_ARRAY_FAN_OUT; slot++) {
		ptr = READ_ONCE(node->slots[slot]);

		if (assoc_array_ptr_is_meta(ptr)) {
			if (node->back_pointer ||
			    assoc_array_ptr_is_shortcut(ptr))
				goto descend_to_node;
		}

		if (!keyring_ptr_is_keyring(ptr))
			continue;

		key = keyring_ptr_to_key(ptr);

		if (sp >= KEYRING_SEARCH_MAX_DEPTH) {
			if (ctx->flags & KEYRING_SEARCH_DETECT_TOO_DEEP) {
				ctx->result = ERR_PTR(-ELOOP);
				return false;
			}
			goto not_this_keyring;
		}

		/* Search a nested keyring */
		if (!(ctx->flags & KEYRING_SEARCH_NO_CHECK_PERM) &&
		    key_task_permission(make_key_ref(key, ctx->possessed),
					ctx->cred, KEY_NEED_SEARCH) < 0)
			continue;

		/* stack the current position */
		stack[sp].keyring = keyring;
		stack[sp].node = node;
		stack[sp].slot = slot;
		sp++;

		/* begin again with the new keyring */
		keyring = key;
		goto descend_to_keyring;
	}

	/* We've dealt with all the slots in the current node, so now we need
	 * to ascend to the parent and continue processing there.
	 */
	ptr = READ_ONCE(node->back_pointer);
	slot = node->parent_slot;

	if (ptr && assoc_array_ptr_is_shortcut(ptr)) {
		shortcut = assoc_array_ptr_to_shortcut(ptr);
		smp_read_barrier_depends();
		ptr = READ_ONCE(shortcut->back_pointer);
		slot = shortcut->parent_slot;
	}
	if (!ptr)
		goto not_this_keyring;
	node = assoc_array_ptr_to_node(ptr);
	smp_read_barrier_depends();
	slot++;

	/* If we've ascended to the root (zero backpointer), we must have just
	 * finished processing the leftmost branch rather than the root slots -
	 * so there can't be any more keyrings for us to find.
	 */
	if (node->back_pointer) {
		kdebug("ascend %d", slot);
		goto ascend_to_node;
	}

	/* The keyring we're looking at was disqualified or didn't contain a
	 * matching key.
	 */
not_this_keyring:
	kdebug("not_this_keyring %d", sp);
	if (sp <= 0) {
		kleave(" = false");
		return false;
	}

	/* Resume the processing of a keyring higher up in the tree */
	sp--;
	keyring = stack[sp].keyring;
	node = stack[sp].node;
	slot = stack[sp].slot + 1;
	kdebug("ascend to %d [%d]", keyring->serial, slot);
	goto ascend_to_node;

	/* We found a viable match */
found:
	key = key_ref_to_ptr(ctx->result);
	key_check(key);
	if (!(ctx->flags & KEYRING_SEARCH_NO_UPDATE_TIME)) {
		key->last_used_at = ctx->now.tv_sec;
		keyring->last_used_at = ctx->now.tv_sec;
		while (sp > 0)
			stack[--sp].keyring->last_used_at = ctx->now.tv_sec;
	}
	kleave(" = true");
	return true;
}


#include "livepatch_bsc1233680.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "assoc_array_find", (void *)&klpe_assoc_array_find },
	{ "assoc_array_iterate", (void *)&klpe_assoc_array_iterate },
	{ "keyring_assoc_array_ops", (void *)&klpe_keyring_assoc_array_ops },
	{ "keyring_compare_object", (void *)&klpe_keyring_compare_object },
};

int livepatch_bsc1233680_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

