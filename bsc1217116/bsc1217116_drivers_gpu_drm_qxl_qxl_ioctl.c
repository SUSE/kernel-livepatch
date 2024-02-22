/*
 * bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl
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

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_ioctl.c */
#include <linux/pci.h>
#include <linux/uaccess.h>
/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <linux/iosys-map.h>
#include <linux/dma-fence.h>
#include <linux/workqueue.h>
#include <drm/drm_crtc.h>

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/drm_gem_ttm_helper.h>

/* klp-ccp: from include/drm/drm_print.h */
static __printf(1, 2)
void (*klpe___drm_err)(const char *format, ...);

#define KLPR_DRM_ERROR(fmt, ...) \
	(*klpe___drm_err)(fmt, ##__VA_ARGS__)

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/drm_gem.h>
#include <drm/qxl_drm.h>
#include <drm/ttm/ttm_bo_api.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <drm/ttm/ttm_placement.h>
/* klp-ccp: from drivers/gpu/drm/qxl/qxl_dev.h */
#include <linux/types.h>

#include "livepatch_bsc1217116.h"

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

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_ioctl.c */
int klpp_qxl_alloc_ioctl(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct qxl_device *qdev = to_qxl(dev);
	struct drm_qxl_alloc *qxl_alloc = data;
	int ret;
	uint32_t handle;
	u32 domain = QXL_GEM_DOMAIN_VRAM;

	if (qxl_alloc->size == 0) {
		KLPR_DRM_ERROR("invalid size %d\n",qxl_alloc->size);
		return -EINVAL;
	}
	ret = klpp_qxl_gem_object_create_with_handle(qdev, file_priv,
						domain,
						qxl_alloc->size,
						NULL,
						NULL, &handle);
	if (ret) {
		KLPR_DRM_ERROR("%s: failed to create gem ret=%d\n",__func__, ret);
		return -ENOMEM;
	}
	qxl_alloc->handle = handle;
	return 0;
}

int klpp_qxl_alloc_surf_ioctl(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct qxl_device *qdev = to_qxl(dev);
	struct drm_qxl_alloc_surf *param = data;
	int handle;
	int ret;
	int size, actual_stride;
	struct qxl_surface surf;

	/* work out size allocate bo with handle */
	actual_stride = param->stride < 0 ? -param->stride : param->stride;
	size = actual_stride * param->height + actual_stride;

	surf.format = param->format;
	surf.width = param->width;
	surf.height = param->height;
	surf.stride = param->stride;
	surf.data = 0;

	ret = klpp_qxl_gem_object_create_with_handle(qdev, file,
						QXL_GEM_DOMAIN_SURFACE,
						size,
						&surf,
						NULL, &handle);
	if (ret) {
		KLPR_DRM_ERROR("%s: failed to create gem ret=%d\n",__func__, ret);
		return -ENOMEM;
	} else
		param->handle = handle;
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "qxl"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__drm_err", (void *)&klpe___drm_err, "drm" },
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

int bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_init(void)
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

void bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_QXL) */
