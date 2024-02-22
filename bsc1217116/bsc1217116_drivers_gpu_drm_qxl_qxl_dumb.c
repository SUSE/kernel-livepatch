/*
 * bsc1217116_drivers_gpu_drm_qxl_qxl_dumb
 *
 * Fix for CVE-2023-39198, bsc#1217116
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

#if IS_ENABLED(CONFIG_DRM_QXL)

#if !IS_MODULE(CONFIG_DRM_QXL)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <linux/iosys-map.h>
#include <linux/dma-fence.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <drm/drm_crtc.h>

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/drm_gem_ttm_helper.h>

/* klp-ccp: from include/drm/drm_gem.h */
static void (*klpe_drm_gem_object_free)(struct kref *kref);

__attribute__((nonnull))
static inline void
klpr___drm_gem_object_put(struct drm_gem_object *obj)
{
	kref_put(&obj->refcount, (*klpe_drm_gem_object_free));
}

static inline void
klpr_drm_gem_object_put(struct drm_gem_object *obj)
{
	if (obj)
		klpr___drm_gem_object_put(obj);
}

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/drm_gem.h>

/* klp-ccp: from include/uapi/drm/qxl_drm.h */
#define QXL_GEM_DOMAIN_CPU 0

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/ttm/ttm_bo_api.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <drm/ttm/ttm_placement.h>
/* klp-ccp: from drivers/gpu/drm/qxl/qxl_dev.h */
#include <linux/types.h>

#include "livepatch_bsc1217116.h"

enum SpiceSurfaceFmt {
	SPICE_SURFACE_FMT_INVALID,
	SPICE_SURFACE_FMT_1_A,
	SPICE_SURFACE_FMT_8_A = 8,
	SPICE_SURFACE_FMT_16_555 = 16,
	SPICE_SURFACE_FMT_32_xRGB = 32,
	SPICE_SURFACE_FMT_16_565 = 80,
	SPICE_SURFACE_FMT_32_ARGB = 96,

	SPICE_SURFACE_FMT_ENUM_END
};

typedef uint64_t QXLPHYSICAL;

struct qxl_surface {
	uint32_t format;
	uint32_t width;
	uint32_t height;
	int32_t stride;
	QXLPHYSICAL data;
};

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#define QXL_DEBUGFS_MAX_COMPONENTS		32

struct qxl_bo {
	struct ttm_buffer_object	tbo;

	/* Protected by gem.mutex */
	struct list_head		list;
	/* Protected by tbo.reserved */
	struct ttm_place		placements[3];
	struct ttm_placement		placement;
	struct iosys_map		map;
	void				*kptr;
	unsigned int                    map_count;
	int                             type;

	/* Constant after initialization */
	unsigned int is_primary:1; /* is this now a primary surface */
	unsigned int is_dumb:1;
	struct qxl_bo *shadow;
	unsigned int hw_surf_alloc:1;
	struct qxl_surface surf;
	uint32_t surface_id;
	struct qxl_release *surf_create;
};
#define gem_to_qxl_bo(gobj) container_of((gobj), struct qxl_bo, tbo.base)

struct qxl_gem {
	struct mutex		mutex;
	struct list_head	objects;
};

struct qxl_mman {
	struct ttm_device		bdev;
};

struct qxl_memslot {
	int             index;
	const char      *name;
	uint8_t		generation;
	uint64_t	start_phys_addr;
	uint64_t	size;
	uint64_t	high_bits;
};

struct qxl_debugfs {
	struct drm_info_list	*files;
	unsigned int num_files;
};

struct qxl_device {
	struct drm_device ddev;

	resource_size_t vram_base, vram_size;
	resource_size_t surfaceram_base, surfaceram_size;
	resource_size_t rom_base, rom_size;
	struct qxl_rom *rom;

	struct qxl_mode *modes;
	struct qxl_bo *monitors_config_bo;
	struct qxl_monitors_config *monitors_config;

	/* last received client_monitors_config */
	struct qxl_monitors_config *client_monitors_config;

	int io_base;
	void *ram;
	struct qxl_mman		mman;
	struct qxl_gem		gem;

	void *ram_physical;

	struct qxl_ring *release_ring;
	struct qxl_ring *command_ring;
	struct qxl_ring *cursor_ring;

	struct qxl_ram_header *ram_header;

	struct qxl_bo *primary_bo;
	struct qxl_bo *dumb_shadow_bo;
	struct qxl_head *dumb_heads;

	struct qxl_memslot main_slot;
	struct qxl_memslot surfaces_slot;

	spinlock_t	release_lock;
	struct idr	release_idr;
	uint32_t	release_seqno;
	atomic_t	release_count;
	wait_queue_head_t release_event;
	spinlock_t release_idr_lock;
	struct mutex	async_io_mutex;
	unsigned int last_sent_io_cmd;

	/* interrupt handling */
	atomic_t irq_received;
	atomic_t irq_received_display;
	atomic_t irq_received_cursor;
	atomic_t irq_received_io_cmd;
	unsigned int irq_received_error;
	wait_queue_head_t display_event;
	wait_queue_head_t cursor_event;
	wait_queue_head_t io_cmd_event;
	struct work_struct client_monitors_config_work;

	/* debugfs */
	struct qxl_debugfs	debugfs[QXL_DEBUGFS_MAX_COMPONENTS];
	unsigned int debugfs_count;

	struct mutex		update_area_mutex;

	struct idr	surf_id_idr;
	spinlock_t surf_id_idr_lock;
	int last_alloced_surf_id;

	struct mutex surf_evict_mutex;
	struct io_mapping *vram_mapping;
	struct io_mapping *surface_mapping;

	/* */
	struct mutex release_mutex;
	struct qxl_bo *current_release_bo[3];
	int current_release_bo_offset[3];

	struct work_struct gc_work;

	struct drm_property *hotplug_mode_update_property;
	int monitors_config_width;
	int monitors_config_height;
};

#define to_qxl(dev) container_of(dev, struct qxl_device, ddev)

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_dumb.c */
int klpp_qxl_mode_dumb_create(struct drm_file *file_priv,
			    struct drm_device *dev,
			    struct drm_mode_create_dumb *args)
{
	struct qxl_device *qdev = to_qxl(dev);
	struct qxl_bo *qobj;
	struct drm_gem_object *gobj;
	uint32_t handle;
	int r;
	struct qxl_surface surf;
	uint32_t pitch, format;

	pitch = args->width * ((args->bpp + 1) / 8);
	args->size = pitch * args->height;
	args->size = ALIGN(args->size, PAGE_SIZE);

	switch (args->bpp) {
	case 16:
		format = SPICE_SURFACE_FMT_16_565;
		break;
	case 32:
		format = SPICE_SURFACE_FMT_32_xRGB;
		break;
	default:
		return -EINVAL;
	}

	surf.width = args->width;
	surf.height = args->height;
	surf.stride = pitch;
	surf.format = format;
	surf.data = 0;

	r = klpp_qxl_gem_object_create_with_handle(qdev, file_priv,
					      QXL_GEM_DOMAIN_CPU,
					      args->size, &surf, &gobj,
					      &handle);
	if (r)
		return r;
	qobj = gem_to_qxl_bo(gobj);
	qobj->is_dumb = true;
	klpr_drm_gem_object_put(gobj);
	args->pitch = pitch;
	args->handle = handle;
	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "qxl"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_gem_object_free", (void *)&klpe_drm_gem_object_free, "drm" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_QXL) */
