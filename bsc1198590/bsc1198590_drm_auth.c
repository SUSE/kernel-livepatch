/*
 * bsc1198590_drm_auth
 *
 * Fix for CVE-2022-1280, bsc#1198590 (drivers/gpu/drm/drm_auth.c part)
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_DRM)
#error "Live patch supports only CONFIG=m"
#endif

#include <linux/spinlock_types.h>

/* New. */
static spinlock_t *klpp_drm_file_master_lookup_lock;

/* klp-ccp: from drivers/gpu/drm/drm_auth.c */
#include <drm/drmP.h>

/* klp-ccp: from include/drm/drm_lease.h */
static struct drm_master *(*klpe_drm_lease_owner)(struct drm_master *master);

static void (*klpe_drm_lease_revoke)(struct drm_master *master);

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe_drm_dbg)(unsigned int category, const char *format, ...);

#define KLPR_DRM_DEBUG_LEASE(fmt, ...)					\
	(*klpe_drm_dbg)(DRM_UT_LEASE, fmt, ##__VA_ARGS__)


/* klp-ccp: from drivers/gpu/drm/drm_internal.h */
int klpp_drm_setmaster_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int klpp_drm_dropmaster_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);
int klpp_drm_master_open(struct drm_file *file_priv);
void klpp_drm_master_release(struct drm_file *file_priv);

/* klp-ccp: from drivers/gpu/drm/drm_legacy.h */
#include <linux/list.h>
#include <drm/drm_legacy.h>

/* klp-ccp: from include/drm/drm_auth.h */
static struct drm_master *(*klpe_drm_master_get)(struct drm_master *master);
static void (*klpe_drm_master_put)(struct drm_master **master);
bool klpp_drm_is_current_master(struct drm_file *fpriv);

static struct drm_master *(*klpe_drm_master_create)(struct drm_device *dev);

/* klp-ccp: from drivers/gpu/drm/drm_auth.c */
#include <drm/drm_lease.h>

static int (*klpe_drm_set_master)(struct drm_device *dev, struct drm_file *fpriv,
			  bool new_master);

/* New. */
static bool klpp_drm_is_current_master_locked(struct drm_file *fpriv)
{
	/* Either drm_device.master_mutex or drm_file.master_lookup_lock
	 * should be held here.
	 */
	return fpriv->is_master && (*klpe_drm_lease_owner)(fpriv->master) == fpriv->minor->dev->master;
}

bool klpp_drm_is_current_master(struct drm_file *fpriv)
{
	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +7 lines
	 */
	bool ret;

	spin_lock(klpp_drm_file_master_lookup_lock);
	ret = klpp_drm_is_current_master_locked(fpriv);
	spin_unlock(klpp_drm_file_master_lookup_lock);

	return ret;
}

static int klpp_drm_new_set_master(struct drm_device *dev, struct drm_file *fpriv)
{
	struct drm_master *old_master;
	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	struct drm_master *new_master;
	int ret;

	lockdep_assert_held_once(&dev->master_mutex);

	WARN_ON(fpriv->is_master);
	old_master = fpriv->master;
	/*
	 * Fix CVE-2022-1280
	 *  -5 lines, +6 lines
	 */
	new_master = (*klpe_drm_master_create)(dev);
	if (!new_master)
		return -ENOMEM;
	spin_lock(klpp_drm_file_master_lookup_lock);
	fpriv->master = new_master;
	spin_unlock(klpp_drm_file_master_lookup_lock);

	if (dev->driver->master_create) {
		ret = dev->driver->master_create(dev, fpriv->master);
		if (ret)
			goto out_err;
	}
	fpriv->is_master = 1;
	fpriv->authenticated = 1;

	ret = (*klpe_drm_set_master)(dev, fpriv, true);
	if (ret)
		goto out_err;

	if (old_master)
		(*klpe_drm_master_put)(&old_master);

	return 0;

out_err:
	/* drop references and restore old master on failure */
	(*klpe_drm_master_put)(&fpriv->master);
	fpriv->master = old_master;
	fpriv->is_master = 0;

	return ret;
}

int klpp_drm_setmaster_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	int ret = 0;

	mutex_lock(&dev->master_mutex);
	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	if (klpp_drm_is_current_master_locked(file_priv))
		goto out_unlock;

	if (dev->master) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!file_priv->master) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!file_priv->is_master) {
		ret = klpp_drm_new_set_master(dev, file_priv);
		goto out_unlock;
	}

	if (file_priv->master->lessor != NULL) {
		KLPR_DRM_DEBUG_LEASE("Attempt to set lessee %d as master\n", file_priv->master->lessee_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = (*klpe_drm_set_master)(dev, file_priv, false);
out_unlock:
	mutex_unlock(&dev->master_mutex);
	return ret;
}

static void (*klpe_drm_drop_master)(struct drm_device *dev,
			    struct drm_file *fpriv);

int klpp_drm_dropmaster_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	int ret = -EINVAL;

	mutex_lock(&dev->master_mutex);
	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	if (!klpp_drm_is_current_master_locked(file_priv))
		goto out_unlock;

	if (!dev->master)
		goto out_unlock;

	if (file_priv->master->lessor != NULL) {
		KLPR_DRM_DEBUG_LEASE("Attempt to drop lessee %d as master\n", file_priv->master->lessee_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = 0;
	(*klpe_drm_drop_master)(dev, file_priv);
out_unlock:
	mutex_unlock(&dev->master_mutex);
	return ret;
}

int klpp_drm_master_open(struct drm_file *file_priv)
{
	struct drm_device *dev = file_priv->minor->dev;
	int ret = 0;

	/* if there is no current master make this fd it, but do not create
	 * any master object for render clients */
	mutex_lock(&dev->master_mutex);
	/*
	 * Fix CVE-2022-1280
	 *  -4 lines, +7 lines
	 */
	if (!dev->master) {
		ret = klpp_drm_new_set_master(dev, file_priv);
	} else {
		spin_lock(klpp_drm_file_master_lookup_lock);
		file_priv->master = (*klpe_drm_master_get)(dev->master);
		spin_unlock(klpp_drm_file_master_lookup_lock);
	}
	mutex_unlock(&dev->master_mutex);

	return ret;
}

void klpp_drm_master_release(struct drm_file *file_priv)
{
	struct drm_device *dev = file_priv->minor->dev;
	struct drm_master *master;

	mutex_lock(&dev->master_mutex);
	master = file_priv->master;
	if (file_priv->magic)
		idr_remove(&file_priv->master->magic_map, file_priv->magic);

	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	if (!klpp_drm_is_current_master_locked(file_priv))
		goto out;

	if (drm_core_check_feature(dev, DRIVER_LEGACY)) {
		/*
		 * Since the master is disappearing, so is the
		 * possibility to lock.
		 */
		mutex_lock(&dev->struct_mutex);
		if (master->lock.hw_lock) {
			if (dev->sigdata.lock == master->lock.hw_lock)
				dev->sigdata.lock = NULL;
			master->lock.hw_lock = NULL;
			master->lock.file_priv = NULL;
			wake_up_interruptible_all(&master->lock.lock_queue);
		}
		mutex_unlock(&dev->struct_mutex);
	}

	if (dev->master == file_priv->master)
		(*klpe_drm_drop_master)(dev, file_priv);
out:
	if (drm_core_check_feature(dev, DRIVER_MODESET) && file_priv->is_master) {
		/* Revoke any leases held by this or lessees, but only if
		 * this is the "real" master
		 */
		(*klpe_drm_lease_revoke)(master);
	}

	/* drop the master reference held by the file priv */
	if (file_priv->master)
		(*klpe_drm_master_put)(&file_priv->master);
	mutex_unlock(&dev->master_mutex);
}

/* New. */
struct drm_master *klpp_drm_file_get_master(struct drm_file *file_priv)
{
	struct drm_master *master = NULL;

	spin_lock(klpp_drm_file_master_lookup_lock);
	if (!file_priv->master)
		goto unlock;
	master = (*klpe_drm_master_get)(file_priv->master);

unlock:
	spin_unlock(klpp_drm_file_master_lookup_lock);
	return master;
}



#define LP_MODULE "drm"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/livepatch.h>
#include "livepatch_bsc1198590.h"
#include "bsc1198590_common.h"
#include "../kallsyms_relocs.h"
#include "../shadow.h"

struct klp_bsc1198590_shared_state
{
	unsigned long refcount;
	spinlock_t drm_file_master_lookup_lock;
};

static struct klp_bsc1198590_shared_state *klp_bsc1198590_shared_state;

#define KLP_BSC1198590_SHARED_STATE_ID KLP_SHADOW_ID(1198590, 0)

static int klp_bsc1198590_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	struct klp_bsc1198590_shared_state *s = shadow_data;

	memset(s, 0, sizeof(*s));
	spin_lock_init(&s->drm_file_master_lookup_lock);

	return 0;
}

/* Must be called with module_mutex held. */
static int __klp_bsc1198590_get_shared_state(void)
{
	klp_bsc1198590_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1198590_SHARED_STATE_ID,
					sizeof(*klp_bsc1198590_shared_state),
					GFP_KERNEL,
					klp_bsc1198590_init_shared_state, NULL);
	if (!klp_bsc1198590_shared_state)
		return -ENOMEM;

	++klp_bsc1198590_shared_state->refcount;

	klpp_drm_file_master_lookup_lock =
		&klp_bsc1198590_shared_state->drm_file_master_lookup_lock;

	return 0;
}

/* Must be called with module_mutex held. */
static void __klp_bsc1198590_put_shared_state(void)
{
	--klp_bsc1198590_shared_state->refcount;

	if (!klp_bsc1198590_shared_state->refcount)
		klp_shadow_free(NULL, KLP_BSC1198590_SHARED_STATE_ID, NULL);

	klpp_drm_file_master_lookup_lock = NULL;
	klp_bsc1198590_shared_state = NULL;
}

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_dbg", (void *)&klpe_drm_dbg, "drm" },
	{ "drm_drop_master", (void *)&klpe_drm_drop_master, "drm" },
	{ "drm_lease_owner", (void *)&klpe_drm_lease_owner, "drm" },
	{ "drm_lease_revoke", (void *)&klpe_drm_lease_revoke, "drm" },
	{ "drm_master_create", (void *)&klpe_drm_master_create, "drm" },
	{ "drm_master_get", (void *)&klpe_drm_master_get, "drm" },
	{ "drm_master_put", (void *)&klpe_drm_master_put, "drm" },
	{ "drm_set_master", (void *)&klpe_drm_set_master, "drm" },
};

static int bsc1198590_drm_auth_module_notify(struct notifier_block *nb,
					unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block bsc1198590_drm_auth_module_nb = {
	.notifier_call = bsc1198590_drm_auth_module_notify,
	.priority = INT_MIN+1,
};

int bsc1198590_drm_auth_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	ret = __klp_bsc1198590_get_shared_state();
	if (ret)
		goto out;
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret) {
			__klp_bsc1198590_put_shared_state();
			goto out;
		}
	}

	ret = register_module_notifier(&bsc1198590_drm_auth_module_nb);
	if (ret)
		__klp_bsc1198590_put_shared_state();
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1198590_drm_auth_cleanup(void)
{
	unregister_module_notifier(&bsc1198590_drm_auth_module_nb);
	mutex_lock(&module_mutex);
	__klp_bsc1198590_put_shared_state();
	mutex_unlock(&module_mutex);
}
