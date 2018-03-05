/*
 * shadow.c - Shadow Variables
 *
 * Copyright (C) 2014 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2017 Joe Lawrence <joe.lawrence@redhat.com>
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

/**
 * DOC: Shadow variable API concurrency notes:
 *
 * The shadow variable API provides a simple relationship between an
 * <obj, id> pair and a pointer value.  It is the responsibility of the
 * caller to provide any mutual exclusion required of the shadow data.
 *
 * Once a shadow variable is attached to its parent object via the
 * klp_shadow_*alloc() API calls, it is considered live: any subsequent
 * call to klp_shadow_get() may then return the shadow variable's data
 * pointer.  Callers of klp_shadow_*alloc() should prepare shadow data
 * accordingly.
 *
 * The klp_shadow_*alloc() API calls may allocate memory for new shadow
 * variable structures.  Their implementation does not call kmalloc
 * inside any spinlocks, but API callers should pass GFP flags according
 * to their specific needs.
 *
 * The kgr_shadow_hash is an RCU-enabled hashtable and is safe against
 * concurrent klp_shadow_free() and klp_shadow_get() operations.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/stringify.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include "shadow.h"


#define __concat_1(a, b) a ## b
#define __concat(a, b) __concat_1(a, b)

#define KGR_SHADOW_HASH_BITS 12
#define KGR_SHADOW_HASH_SIZE (1 << KGR_SHADOW_HASH_BITS)

/*
 * The following __concat() game is a safety measure: if anybody ever
 * happens to modify KGR_SHADOW_BITS, then this will ensure that we're
 * using a new symbol and will thus be operating on a different instance.
 */
#define kgr_shadow_hash __concat(kgr_shadow_hash, KGR_SHADOW_HASH_BITS)
#define kgr_shadow_lock __concat(kgr_shadow_lock, KGR_SHADOW_HASH_BITS)

static struct hlist_head (*kgr_shadow_hash)[KGR_SHADOW_HASH_SIZE];

/*
 * kgr_shadow_lock provides exclusive access to the kgr_shadow_hash and
 * the shadow variables it references.
 */
static spinlock_t *kgr_shadow_lock;


/**
 * struct klp_shadow - shadow variable structure
 * @node:	kgr_shadow_hash hash table node
 * @rcu_head:	RCU is used to safely free this structure
 * @obj:	pointer to parent object
 * @id:		data identifier
 * @data:	data area
 */
struct klp_shadow {
	struct hlist_node node;
	struct rcu_head rcu_head;
	void *obj;
	unsigned long id;
	char data[];
};

/**
 * klp_shadow_match() - verify a shadow variable matches given <obj, id>
 * @shadow:	shadow variable to match
 * @obj:	pointer to parent object
 * @id:		data identifier
 *
 * Return: true if the shadow variable matches.
 */
static inline bool klp_shadow_match(struct klp_shadow *shadow, void *obj,
				unsigned long id)
{
	return shadow->obj == obj && shadow->id == id;
}

/**
 * klp_shadow_get() - retrieve a shadow variable data pointer
 * @obj:	pointer to parent object
 * @id:		data identifier
 *
 * Return: the shadow variable data element, NULL on failure.
 */
void *klp_shadow_get(void *obj, unsigned long id)
{
	struct klp_shadow *shadow;

	rcu_read_lock();

	hash_for_each_possible_rcu((*kgr_shadow_hash), shadow, node,
				   (unsigned long)obj) {

		if (klp_shadow_match(shadow, obj, id)) {
			rcu_read_unlock();
			return shadow->data;
		}
	}

	rcu_read_unlock();

	return NULL;
}

static void *__klp_shadow_get_or_alloc(void *obj, unsigned long id,
		       klp_shadow_init_t init, void *init_data,
		       size_t size, gfp_t gfp_flags, bool warn_on_exist)
{
	struct klp_shadow *new_shadow;
	void *shadow_data;
	unsigned long flags;

	/* Check if the shadow variable already exists */
	shadow_data = klp_shadow_get(obj, id);
	if (shadow_data)
		goto exists;

	/* Allocate a new shadow variable for use inside the lock below */
	new_shadow = kzalloc(size + sizeof(*new_shadow), gfp_flags);
	if (!new_shadow)
		return NULL;

	new_shadow->obj = obj;
	new_shadow->id = id;

	/* Initialize the shadow variable if initializer provided */
	if (init && init(new_shadow->data, init_data)) {
		kfree(new_shadow);
		return NULL;
	}

	/* Look for <obj, id> again under the lock */
	spin_lock_irqsave(kgr_shadow_lock, flags);
	shadow_data = klp_shadow_get(obj, id);
	if (unlikely(shadow_data)) {
		/*
		 * Shadow variable was found, throw away speculative
		 * allocation.
		 */
		spin_unlock_irqrestore(kgr_shadow_lock, flags);
		kfree(new_shadow);
		goto exists;
	}

	/* No <obj, id> found, so attach the newly allocated one */
	hash_add_rcu((*kgr_shadow_hash), &new_shadow->node,
		     (unsigned long)new_shadow->obj);
	spin_unlock_irqrestore(kgr_shadow_lock, flags);

	return new_shadow->data;

exists:
	if (warn_on_exist) {
		WARN(1, "Duplicate shadow variable <%p, %lx>\n", obj, id);
		return NULL;
	}

	return shadow_data;
}

struct __klp_shadow_memcpy_init_data
{
	const void *src;
	size_t size;
};

static int __klp_shadow_memcpy_init(void *new_shadow_data, void *init_data)
{
	struct __klp_shadow_memcpy_init_data *memcpy_init_data = init_data;

	if (!memcpy_init_data->src)
		return 0;

	memcpy(new_shadow_data, memcpy_init_data->src, memcpy_init_data->size);
	return 0;
}

/**
 * klp_shadow_alloc() - allocate and add a new shadow variable
 * @obj:	pointer to parent object
 * @id:		data identifier
 * @data:	pointer to data to attach to parent
 * @size:	size of attached data
 * @gfp_flags:	GFP mask for allocation
 *
 * Allocates @size bytes for new shadow variable data using @gfp_flags
 * and copies @size bytes from @data into the new shadow variable's own
 * data space.  If @data is NULL, @size bytes are still allocated, but
 * no copy is performed.  The new shadow variable is then added to the
 * global hashtable.
 *
 * If an existing <obj, id> shadow variable can be found, this routine
 * will issue a WARN, exit early and return NULL.
 *
 * Return: the shadow variable data element, NULL on duplicate or
 * failure.
 */
void *klp_shadow_alloc(void *obj, unsigned long id, void *data,
		       size_t size, gfp_t gfp_flags)
{
	struct __klp_shadow_memcpy_init_data memcpy_init_data = {
		.src = data,
		.size = size,
	};

	return __klp_shadow_get_or_alloc(obj, id,
					 __klp_shadow_memcpy_init,
					 &memcpy_init_data, size, gfp_flags,
					 true);
}

/**
 * klp_shadow_get_or_alloc() - get existing or allocate a new shadow variable
 * @obj:	pointer to parent object
 * @id:		data identifier
 * @data:	pointer to data to attach to parent
 * @size:	size of attached data
 * @gfp_flags:	GFP mask for allocation
 *
 * Returns a pointer to existing shadow data if an <obj, id> shadow
 * variable is already present.  Otherwise, it creates a new shadow
 * variable like klp_shadow_alloc().
 *
 * This function guarantees that only one shadow variable exists with
 * the given @id for the given @obj.  It also guarantees that the shadow
 * variable will be initialized by the given @data only when it did not
 * exist before.
 *
 * Return: the shadow variable data element, NULL on failure.
 */
void *klp_shadow_get_or_alloc(void *obj, unsigned long id, void *data,
			       size_t size, gfp_t gfp_flags)
{
	struct __klp_shadow_memcpy_init_data memcpy_init_data = {
		.src = data,
		.size = size,
	};

	return __klp_shadow_get_or_alloc(obj, id,
					 __klp_shadow_memcpy_init,
					 &memcpy_init_data, size, gfp_flags,
					 false);
}

void *klp_shadow_alloc_with_init(void *obj, unsigned long id,
				 klp_shadow_init_t init, void *init_data,
				 size_t size, gfp_t gfp_flags)
{
	return __klp_shadow_get_or_alloc(obj, id, init, init_data,
					 size, gfp_flags, true);
}

void *klp_shadow_get_or_alloc_with_init(void *obj, unsigned long id,
					klp_shadow_init_t init, void *init_data,
					size_t size, gfp_t gfp_flags)
{
	return __klp_shadow_get_or_alloc(obj, id, init, init_data,
					 size, gfp_flags, false);
}

/**
 * klp_shadow_free() - detach and free a <obj, id> shadow variable
 * @obj:	pointer to parent object
 * @id:		data identifier
 *
 * This function releases the memory for this <obj, id> shadow variable
 * instance, callers should stop referencing it accordingly.
 */
void klp_shadow_free(void *obj, unsigned long id)
{
	struct klp_shadow *shadow;
	unsigned long flags;

	spin_lock_irqsave(kgr_shadow_lock, flags);

	/* Delete <obj, id> from hash */
	hash_for_each_possible((*kgr_shadow_hash), shadow, node,
			       (unsigned long)obj) {

		if (klp_shadow_match(shadow, obj, id)) {
			hash_del_rcu(&shadow->node);
			kfree_rcu(shadow, rcu_head);
			break;
		}
	}

	spin_unlock_irqrestore(kgr_shadow_lock, flags);
}

/**
 * klp_shadow_free_all() - detach and free all <*, id> shadow variables
 * @id:		data identifier
 *
 * This function releases the memory for all <*, id> shadow variable
 * instances, callers should stop referencing them accordingly.
 */
void klp_shadow_free_all(unsigned long id)
{
	struct klp_shadow *shadow;
	unsigned long flags;
	int i;

	spin_lock_irqsave(kgr_shadow_lock, flags);

	/* Delete all <*, id> from hash */
	hash_for_each((*kgr_shadow_hash), i, shadow, node) {
		if (klp_shadow_match(shadow, shadow->obj, id)) {
			hash_del_rcu(&shadow->node);
			kfree_rcu(shadow, rcu_head);
		}
	}

	spin_unlock_irqrestore(kgr_shadow_lock, flags);
}

static int __kgr_find_other_module_shadow(void *data, const char *name,
					  struct module *mod,
					  unsigned long addr)
{
	spinlock_t **lock_addr;
	struct hlist_head (**hash_addr)[KGR_SHADOW_HASH_SIZE];
	char symname[MODULE_NAME_LEN + 1 +
		     sizeof(__stringify(kgr_shadow_hash))];

	if (!mod || mod == THIS_MODULE)
		return 0;

	if (strcmp(__stringify(kgr_shadow_lock), name))
		return 0;

	lock_addr = (spinlock_t **)addr;
	if (!*lock_addr)
		return 0;

	snprintf(symname, sizeof(symname), "%s:" __stringify(kgr_shadow_hash),
		 mod->name);
	hash_addr = (struct hlist_head (**)[KGR_SHADOW_HASH_SIZE])
		      kallsyms_lookup_name(symname);
	if (!hash_addr || !*hash_addr) {
		WARN(1, "Module %s has a %s but no %s\n", mod->name,
			__stringify(kgr_shadow_lock),
			__stringify(kgr_shadow_hash));
		return 0;
	}

	kgr_shadow_lock = *lock_addr;
	kgr_shadow_hash = *hash_addr;

	return 1;
}

int kgr_shadow_init(void)
{
	int ret = 0;

	if (kgr_shadow_lock)
		return 0;

	mutex_lock(&module_mutex);
	if (kallsyms_on_each_symbol(__kgr_find_other_module_shadow, NULL))
		goto out;

	kgr_shadow_hash = kmalloc(sizeof(*kgr_shadow_hash), GFP_KERNEL);
	if (!kgr_shadow_hash) {
		pr_err("kgraft-patch: failed to allocate shadow management data\n");
		ret = -ENOMEM;
		goto out;
	}

	kgr_shadow_lock = kmalloc(sizeof(*kgr_shadow_lock), GFP_KERNEL);
	if (!kgr_shadow_lock) {
		pr_err("kgraft-patch: failed to allocate shadow management data\n");
		kfree(kgr_shadow_hash);
		kgr_shadow_hash = NULL;
		ret = -ENOMEM;
		goto out;
	}

	hash_init(*kgr_shadow_hash);
	spin_lock_init(kgr_shadow_lock);

out:
	mutex_unlock(&module_mutex);
	return ret;
}

void kgr_shadow_cleanup(void)
{
	struct hlist_head (*shadow_hash)[KGR_SHADOW_HASH_SIZE];
	spinlock_t *shadow_lock;
	int found_other = 0;
	struct klp_shadow *shadow;
	struct hlist_node *tmp;
	int i;

	if (!kgr_shadow_lock)
		return;

	shadow_hash = kgr_shadow_hash;
	shadow_lock = kgr_shadow_lock;
	mutex_lock(&module_mutex);
	found_other = kallsyms_on_each_symbol(__kgr_find_other_module_shadow,
					      NULL);

	/*
	 * Clear out our references to the data structures with
	 * module_mutex being held such that other modules won't
	 * consider us being an active user anymore.
	 */
	kgr_shadow_hash = NULL;
	kgr_shadow_lock = NULL;
	mutex_unlock(&module_mutex);

	if (found_other)
		return;

	hash_for_each_safe((*shadow_hash), i, tmp, shadow, node) {
		hash_del(&shadow->node);
		kfree(shadow);
	}
	kfree(shadow_hash);
	kfree(shadow_lock);
}
