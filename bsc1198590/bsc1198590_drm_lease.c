/*
 * bsc1198590_drm_lease
 *
 * Fix for CVE-2022-1280, bsc#1198590  (drivers/gpu/drm/drm_lease.c part)
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

#include "bsc1198590_common.h"

/* klp-ccp: from drivers/gpu/drm/drm_lease.c */
#include <drm/drmP.h>

/* klp-ccp: from include/drm/drm_lease.h */
static struct drm_master *(*klpe_drm_lease_owner)(struct drm_master *master);

bool klpp_drm_lease_held(struct drm_file *file_priv, int id);

bool klpp__drm_lease_held(struct drm_file *file_priv, int id);

uint32_t klpp_drm_lease_filter_crtcs(struct drm_file *file_priv, uint32_t crtcs);

int klpp_drm_mode_create_lease_ioctl(struct drm_device *dev,
				void *data, struct drm_file *file_priv);

int klpp_drm_mode_list_lessees_ioctl(struct drm_device *dev,
				void *data, struct drm_file *file_priv);

int klpp_drm_mode_get_lease_ioctl(struct drm_device *dev,
			     void *data, struct drm_file *file_priv);

int klpp_drm_mode_revoke_lease_ioctl(struct drm_device *dev,
				void *data, struct drm_file *file_priv);

/* klp-ccp: from include/drm/drm_mode_object.h */
static struct drm_mode_object *(*klpe_drm_mode_object_find)(struct drm_device *dev,
					     struct drm_file *file_priv,
					     uint32_t id, uint32_t type);

static void (*klpe_drm_mode_object_put)(struct drm_mode_object *obj);

static bool (*klpe_drm_mode_object_lease_required)(uint32_t type);

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe_drm_dbg)(unsigned int category, const char *format, ...);

#define KLPR_DRM_DEBUG(fmt, ...)						\
	(*klpe_drm_dbg)(DRM_UT_CORE, fmt, ##__VA_ARGS__)

#define KLPR_DRM_DEBUG_LEASE(fmt, ...)					\
	(*klpe_drm_dbg)(DRM_UT_LEASE, fmt, ##__VA_ARGS__)

/* klp-ccp: from drivers/gpu/drm/drm_legacy.h */
#include <linux/list.h>
#include <drm/drm_legacy.h>

/* klp-ccp: from include/drm/drm_auth.h */
static struct drm_master *(*klpe_drm_master_get)(struct drm_master *master);
static void (*klpe_drm_master_put)(struct drm_master **master);

static struct drm_master *(*klpe_drm_master_create)(struct drm_device *dev);

/* klp-ccp: from drivers/gpu/drm/drm_lease.c */
#include <drm/drm_lease.h>
#include <drm/drm_auth.h>

#define drm_for_each_lessee(lessee, lessor) \
	list_for_each_entry((lessee), &(lessor)->lessees, lessee_list)

static uint64_t (*klpe_drm_lease_idr_object);

static struct drm_master*
klpr__drm_find_lessee(struct drm_master *master, int lessee_id)
{
	lockdep_assert_held(&master->dev->mode_config.idr_mutex);
	return idr_find(&(*klpe_drm_lease_owner)(master)->lessee_idr, lessee_id);
}

static int _drm_lease_held_master(struct drm_master *master, int id)
{
	lockdep_assert_held(&master->dev->mode_config.idr_mutex);
	if (master->lessor)
		return idr_find(&master->leases, id) != NULL;
	return true;
}

static bool _drm_has_leased(struct drm_master *master, int id)
{
	struct drm_master *lessee;

	lockdep_assert_held(&master->dev->mode_config.idr_mutex);
	drm_for_each_lessee(lessee, master)
		if (_drm_lease_held_master(lessee, id))
			return true;
	return false;
}

bool klpp__drm_lease_held(struct drm_file *file_priv, int id)
{
	/*
	 * Fix CVE-2022-1280
	 *  -4 lines, +13 lines
	 */
	bool ret;
	struct drm_master *master;

	if (!file_priv)
		return true;

	master = klpp_drm_file_get_master(file_priv);
	if (!master)
		return true;
	ret = _drm_lease_held_master(master, id);
	(*klpe_drm_master_put)(&master);

	return ret;
}

bool klpp_drm_lease_held(struct drm_file *file_priv, int id)
{
	struct drm_master *master;
	bool ret;

	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	if (!file_priv)
		return true;

	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +7 lines
	 */
	master = klpp_drm_file_get_master(file_priv);
	if (!master)
		return true;
	if (!master->lessor) {
		ret = true;
		goto out;
	}
	mutex_lock(&master->dev->mode_config.idr_mutex);
	ret = _drm_lease_held_master(master, id);
	mutex_unlock(&master->dev->mode_config.idr_mutex);

/*
 * Fix CVE-2022-1280
 *  +2 lines
 */
out:
	(*klpe_drm_master_put)(&master);
	return ret;
}

uint32_t klpp_drm_lease_filter_crtcs(struct drm_file *file_priv, uint32_t crtcs_in)
{
	struct drm_master *master;
	struct drm_device *dev;
	struct drm_crtc *crtc;
	int count_in, count_out;
	uint32_t crtcs_out = 0;

	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	if (!file_priv)
		return crtcs_in;

	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +7 lines
	 */
	master = klpp_drm_file_get_master(file_priv);
	if (!master)
		return crtcs_in;
	if (!master->lessor) {
		crtcs_out = crtcs_in;
		goto out;
	}
	dev = master->dev;

	count_in = count_out = 0;
	mutex_lock(&master->dev->mode_config.idr_mutex);
	list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
		if (_drm_lease_held_master(master, crtc->base.id)) {
			uint32_t mask_in = 1ul << count_in;
			if ((crtcs_in & mask_in) != 0) {
				uint32_t mask_out = 1ul << count_out;
				crtcs_out |= mask_out;
			}
			count_out++;
		}
		count_in++;
	}
	mutex_unlock(&master->dev->mode_config.idr_mutex);

/*
 * Fix CVE-2022-1280
 *  +2 lines
 */
out:
	(*klpe_drm_master_put)(&master);
	return crtcs_out;
}

static struct drm_master *klpr_drm_lease_create(struct drm_master *lessor, struct idr *leases)
{
	struct drm_device *dev = lessor->dev;
	int error;
	struct drm_master *lessee;
	int object;
	int id;
	void *entry;

	KLPR_DRM_DEBUG_LEASE("lessor %d\n", lessor->lessee_id);

	lessee = (*klpe_drm_master_create)(lessor->dev);
	if (!lessee) {
		KLPR_DRM_DEBUG_LEASE("drm_master_create failed\n");
		return ERR_PTR(-ENOMEM);
	}

	mutex_lock(&dev->mode_config.idr_mutex);

	idr_for_each_entry(leases, entry, object) {
		error = 0;
		if (!idr_find(&dev->mode_config.crtc_idr, object))
			error = -ENOENT;
		else if (!_drm_lease_held_master(lessor, object))
			error = -EACCES;
		else if (_drm_has_leased(lessor, object))
			error = -EBUSY;

		if (error != 0) {
			KLPR_DRM_DEBUG_LEASE("object %d failed %d\n", object, error);
			goto out_lessee;
		}
	}

	/* Insert the new lessee into the tree */
	id = idr_alloc(&((*klpe_drm_lease_owner)(lessor)->lessee_idr), lessee, 1, 0, GFP_KERNEL);
	if (id < 0) {
		error = id;
		goto out_lessee;
	}

	lessee->lessee_id = id;
	lessee->lessor = (*klpe_drm_master_get)(lessor);
	list_add_tail(&lessee->lessee_list, &lessor->lessees);

	/* Move the leases over */
	lessee->leases = *leases;
	KLPR_DRM_DEBUG_LEASE("new lessee %d %p, lessor %d %p\n", lessee->lessee_id, lessee, lessor->lessee_id, lessor);

	mutex_unlock(&dev->mode_config.idr_mutex);
	return lessee;

out_lessee:
	mutex_unlock(&dev->mode_config.idr_mutex);

	(*klpe_drm_master_put)(&lessee);

	return ERR_PTR(error);
}

static void (*klpe__drm_lease_revoke)(struct drm_master *top);

static int validate_lease(struct drm_device *dev,
			  struct drm_file *lessor_priv,
			  int object_count,
			  struct drm_mode_object **objects)
{
	int o;
	int has_crtc = -1;
	int has_connector = -1;
	int has_plane = -1;

	/* we want to confirm that there is at least one crtc, plane
	   connector object. */

	for (o = 0; o < object_count; o++) {
		if (objects[o]->type == DRM_MODE_OBJECT_CRTC && has_crtc == -1) {
			has_crtc = o;
		}
		if (objects[o]->type == DRM_MODE_OBJECT_CONNECTOR && has_connector == -1)
			has_connector = o;

		if (lessor_priv->universal_planes) {
			if (objects[o]->type == DRM_MODE_OBJECT_PLANE && has_plane == -1)
				has_plane = o;
		}
	}
	if (has_crtc == -1 || has_connector == -1)
		return -EINVAL;
	if (lessor_priv->universal_planes && has_plane == -1)
		return -EINVAL;
	return 0;
}

static int klpr_fill_object_idr(struct drm_device *dev,
			   struct drm_file *lessor_priv,
			   struct idr *leases,
			   int object_count,
			   u32 *object_ids)
{
	struct drm_mode_object **objects;
	u32 o;
	int ret;
	objects = kcalloc(object_count, sizeof(struct drm_mode_object *),
			  GFP_KERNEL);
	if (!objects)
		return -ENOMEM;

	/* step one - get references to all the mode objects
	   and check for validity. */
	for (o = 0; o < object_count; o++) {
		if ((int) object_ids[o] < 0) {
			ret = -EINVAL;
			goto out_free_objects;
		}

		objects[o] = (*klpe_drm_mode_object_find)(dev, lessor_priv,
						  object_ids[o],
						  DRM_MODE_OBJECT_ANY);
		if (!objects[o]) {
			ret = -ENOENT;
			goto out_free_objects;
		}

		if (!(*klpe_drm_mode_object_lease_required)(objects[o]->type)) {
			ret = -EINVAL;
			goto out_free_objects;
		}
	}

	ret = validate_lease(dev, lessor_priv, object_count, objects);
	if (ret)
		goto out_free_objects;

	/* add their IDs to the lease request - taking into account
	   universal planes */
	for (o = 0; o < object_count; o++) {
		struct drm_mode_object *obj = objects[o];
		u32 object_id = objects[o]->id;
		KLPR_DRM_DEBUG_LEASE("Adding object %d to lease\n", object_id);

		/*
		 * We're using an IDR to hold the set of leased
		 * objects, but we don't need to point at the object's
		 * data structure from the lease as the main crtc_idr
		 * will be used to actually find that. Instead, all we
		 * really want is a 'leased/not-leased' result, for
		 * which any non-NULL pointer will work fine.
		 */
		ret = idr_alloc(leases, &(*klpe_drm_lease_idr_object) , object_id, object_id + 1, GFP_KERNEL);
		if (ret < 0) {
			KLPR_DRM_DEBUG_LEASE("Object %d cannot be inserted into leases (%d)\n",
					object_id, ret);
			goto out_free_objects;
		}
		if (obj->type == DRM_MODE_OBJECT_CRTC && !lessor_priv->universal_planes) {
			struct drm_crtc *crtc = obj_to_crtc(obj);
			ret = idr_alloc(leases, &(*klpe_drm_lease_idr_object), crtc->primary->base.id, crtc->primary->base.id + 1, GFP_KERNEL);
			if (ret < 0) {
				KLPR_DRM_DEBUG_LEASE("Object primary plane %d cannot be inserted into leases (%d)\n",
						object_id, ret);
				goto out_free_objects;
			}
			if (crtc->cursor) {
				ret = idr_alloc(leases, &(*klpe_drm_lease_idr_object), crtc->cursor->base.id, crtc->cursor->base.id + 1, GFP_KERNEL);
				if (ret < 0) {
					KLPR_DRM_DEBUG_LEASE("Object cursor plane %d cannot be inserted into leases (%d)\n",
							object_id, ret);
					goto out_free_objects;
				}
			}
		}
	}

	ret = 0;
out_free_objects:
	for (o = 0; o < object_count; o++) {
		if (objects[o])
			(*klpe_drm_mode_object_put)(objects[o]);
	}
	kfree(objects);
	return ret;
}

int klpp_drm_mode_create_lease_ioctl(struct drm_device *dev,
				void *data, struct drm_file *lessor_priv)
{
	struct drm_mode_create_lease *cl = data;
	size_t object_count;
	int ret = 0;
	struct idr leases;
	/*
	 * Fix CVE-2022-1280
	 *  -1 line
	 */
	struct drm_master *lessor;
	struct drm_master *lessee = NULL;
	struct file *lessee_file = NULL;
	struct file *lessor_file = lessor_priv->filp;
	struct drm_file *lessee_priv;
	int fd = -1;
	uint32_t *object_ids;

	/* Can't lease without MODESET */
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	/*
	 * Fix CVE-2022-1280
	 *  -3 lines
	 */

	/* need some objects */
	if (cl->object_count == 0)
		return -EINVAL;

	if (cl->flags && (cl->flags & ~(O_CLOEXEC | O_NONBLOCK)))
		return -EINVAL;

	/*
	 * Fix CVE-2022-1280
	 *  +7 lines
	 */
	lessor = klpp_drm_file_get_master(lessor_priv);
	/* Do not allow sub-leases */
	if (lessor->lessor) {
		KLPR_DRM_DEBUG_LEASE("recursive leasing not allowed\n");
		ret = -EINVAL;
		goto out_lessor;
	}

	object_count = cl->object_count;

	object_ids = memdup_user(u64_to_user_ptr(cl->object_ids),
			array_size(object_count, sizeof(__u32)));
	/*
	 * Fix CVE-2022-1280
	 *  -2 lines, +4 lines
	 */
	if (IS_ERR(object_ids)) {
		ret = PTR_ERR(object_ids);
		goto out_lessor;
	}

	idr_init(&leases);

	/* fill and validate the object idr */
	ret = klpr_fill_object_idr(dev, lessor_priv, &leases,
			      object_count, object_ids);
	kfree(object_ids);
	if (ret) {
		idr_destroy(&leases);
		/*
		 * Fix CVE-2022-1280
		 *  -1 line, +1 line
		 */
		goto out_lessor;
	}

	/* Allocate a file descriptor for the lease */
	fd = get_unused_fd_flags(cl->flags & (O_CLOEXEC | O_NONBLOCK));
	if (fd < 0) {
		idr_destroy(&leases);
		/*
		 * Fix CVE-2022-1280
		 *  -1 line, +2 lines
		 */
		ret = fd;
		goto out_lessor;
	}

	KLPR_DRM_DEBUG_LEASE("Creating lease\n");
	/* lessee will take the ownership of leases */
	lessee = klpr_drm_lease_create(lessor, &leases);

	if (IS_ERR(lessee)) {
		ret = PTR_ERR(lessee);
		idr_destroy(&leases);
		goto out_leases;
	}

	/* Clone the lessor file to create a new file for us */
	KLPR_DRM_DEBUG_LEASE("Allocating lease file\n");
	lessee_file = filp_clone_open(lessor_file);
	if (IS_ERR(lessee_file)) {
		ret = PTR_ERR(lessee_file);
		goto out_lessee;
	}

	lessee_priv = lessee_file->private_data;
	/* Change the file to a master one */
	(*klpe_drm_master_put)(&lessee_priv->master);
	lessee_priv->master = lessee;
	lessee_priv->is_master = 1;
	lessee_priv->authenticated = 1;

	/* Pass fd back to userspace */
	KLPR_DRM_DEBUG_LEASE("Returning fd %d id %d\n", fd, lessee->lessee_id);
	cl->fd = fd;
	cl->lessee_id = lessee->lessee_id;

	/* Hook up the fd */
	fd_install(fd, lessee_file);

	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	(*klpe_drm_master_put)(&lessor);
	KLPR_DRM_DEBUG_LEASE("drm_mode_create_lease_ioctl succeeded\n");
	return 0;

out_lessee:
	(*klpe_drm_master_put)(&lessee);

out_leases:
	put_unused_fd(fd);
/*
 * Fix CVE-2022-1280
 *  +2 lines
 */
out_lessor:
	(*klpe_drm_master_put)(&lessor);
	KLPR_DRM_DEBUG_LEASE("drm_mode_create_lease_ioctl failed: %d\n", ret);
	return ret;
}

int klpp_drm_mode_list_lessees_ioctl(struct drm_device *dev,
			       void *data, struct drm_file *lessor_priv)
{
	struct drm_mode_list_lessees *arg = data;
	__u32 __user *lessee_ids = (__u32 __user *) (uintptr_t) (arg->lessees_ptr);
	__u32 count_lessees = arg->count_lessees;
	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	struct drm_master *lessor, *lessee;
	int count;
	int ret = 0;

	if (arg->pad)
		return -EINVAL;

	/* Can't lease without MODESET */
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	lessor = klpp_drm_file_get_master(lessor_priv);
	KLPR_DRM_DEBUG_LEASE("List lessees for %d\n", lessor->lessee_id);

	mutex_lock(&dev->mode_config.idr_mutex);

	count = 0;
	drm_for_each_lessee(lessee, lessor) {
		/* Only list un-revoked leases */
		if (!idr_is_empty(&lessee->leases)) {
			if (count_lessees > count) {
				KLPR_DRM_DEBUG_LEASE("Add lessee %d\n", lessee->lessee_id);
				ret = put_user(lessee->lessee_id, lessee_ids + count);
				if (ret)
					break;
			}
			count++;
		}
	}

	KLPR_DRM_DEBUG_LEASE("Lessor leases to %d\n", count);
	if (ret == 0)
		arg->count_lessees = count;

	mutex_unlock(&dev->mode_config.idr_mutex);
	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	(*klpe_drm_master_put)(&lessor);

	return ret;
}

int klpp_drm_mode_get_lease_ioctl(struct drm_device *dev,
			     void *data, struct drm_file *lessee_priv)
{
	struct drm_mode_get_lease *arg = data;
	__u32 __user *object_ids = (__u32 __user *) (uintptr_t) (arg->objects_ptr);
	__u32 count_objects = arg->count_objects;
	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	struct drm_master *lessee;
	struct idr *object_idr;
	int count;
	void *entry;
	int object;
	int ret = 0;

	if (arg->pad)
		return -EINVAL;

	/* Can't lease without MODESET */
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	lessee = klpp_drm_file_get_master(lessee_priv);
	KLPR_DRM_DEBUG_LEASE("get lease for %d\n", lessee->lessee_id);

	mutex_lock(&dev->mode_config.idr_mutex);

	if (lessee->lessor == NULL)
		/* owner can use all objects */
		object_idr = &lessee->dev->mode_config.crtc_idr;
	else
		/* lessee can only use allowed object */
		object_idr = &lessee->leases;

	count = 0;
	idr_for_each_entry(object_idr, entry, object) {
		if (count_objects > count) {
			KLPR_DRM_DEBUG_LEASE("adding object %d\n", object);
			ret = put_user(object, object_ids + count);
			if (ret)
				break;
		}
		count++;
	}

	KLPR_DRM_DEBUG("lease holds %d objects\n", count);
	if (ret == 0)
		arg->count_objects = count;

	mutex_unlock(&dev->mode_config.idr_mutex);
	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	(*klpe_drm_master_put)(&lessee);

	return ret;
}

int klpp_drm_mode_revoke_lease_ioctl(struct drm_device *dev,
				void *data, struct drm_file *lessor_priv)
{
	struct drm_mode_revoke_lease *arg = data;
	/*
	 * Fix CVE-2022-1280
	 *  -1 line, +1 line
	 */
	struct drm_master *lessor;
	struct drm_master *lessee;
	int ret = 0;

	KLPR_DRM_DEBUG_LEASE("revoke lease for %d\n", arg->lessee_id);

	/* Can't lease without MODESET */
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	lessor = klpp_drm_file_get_master(lessor_priv);
	mutex_lock(&dev->mode_config.idr_mutex);

	lessee = klpr__drm_find_lessee(lessor, arg->lessee_id);

	/* No such lessee */
	if (!lessee) {
		ret = -ENOENT;
		goto fail;
	}

	/* Lease is not held by lessor */
	if (lessee->lessor != lessor) {
		ret = -EACCES;
		goto fail;
	}

	(*klpe__drm_lease_revoke)(lessee);

fail:
	mutex_unlock(&dev->mode_config.idr_mutex);
	/*
	 * Fix CVE-2022-1280
	 *  +1 line
	 */
	(*klpe_drm_master_put)(&lessor);

	return ret;
}



#define LP_MODULE "drm"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1198590.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "_drm_lease_revoke", (void *)&klpe__drm_lease_revoke, "drm" },
	{ "drm_dbg", (void *)&klpe_drm_dbg, "drm" },
	{ "drm_lease_idr_object", (void *)&klpe_drm_lease_idr_object, "drm" },
	{ "drm_lease_owner", (void *)&klpe_drm_lease_owner, "drm" },
	{ "drm_master_create", (void *)&klpe_drm_master_create, "drm" },
	{ "drm_master_get", (void *)&klpe_drm_master_get, "drm" },
	{ "drm_master_put", (void *)&klpe_drm_master_put, "drm" },
	{ "drm_mode_object_find", (void *)&klpe_drm_mode_object_find, "drm" },
	{ "drm_mode_object_lease_required",
	  (void *)&klpe_drm_mode_object_lease_required, "drm" },
	{ "drm_mode_object_put", (void *)&klpe_drm_mode_object_put, "drm" },
};

static int bsc1198590_drm_lease_module_notify(struct notifier_block *nb,
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

static struct notifier_block bsc1198590_drm_lease_module_nb = {
	.notifier_call = bsc1198590_drm_lease_module_notify,
	.priority = INT_MIN+1,
};

int bsc1198590_drm_lease_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&bsc1198590_drm_lease_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1198590_drm_lease_cleanup(void)
{
	unregister_module_notifier(&bsc1198590_drm_lease_module_nb);
}
