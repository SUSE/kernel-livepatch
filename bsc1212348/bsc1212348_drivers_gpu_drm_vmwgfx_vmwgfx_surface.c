/*
 * bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_surface
 *
 * Fix for CVE-2023-33952, bsc#1212348
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_DRM_VMWGFX)

#if !IS_MODULE(CONFIG_DRM_VMWGFX)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1212348.h"

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <linux/suspend.h>
#include <linux/sync_file.h>

struct drm_file;

static struct drm_master *(*klpe_drm_file_get_master)(struct drm_file *file_priv);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/ttm/ttm_bo_driver.h>

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe___drm_dbg)(enum drm_debug_category category, const char *format, ...);
static __printf(1, 2)
void (*klpe___drm_err)(const char *format, ...);

/* klp-ccp: from include/drm/drm_gem.h */
static void (*klpe_drm_gem_object_free)(struct kref *kref);

/* klp-ccp: from include/drm/ttm/ttm_bo_api.h */
static void (*klpe_ttm_bo_put)(struct ttm_buffer_object *bo);

static void (*klpe_ttm_bo_move_to_lru_tail)(struct ttm_buffer_object *bo);

/* klp-ccp: from include/drm/ttm/ttm_bo_driver.h */
static inline void
klpr_ttm_bo_move_to_lru_tail_unlocked(struct ttm_buffer_object *bo)
{
	spin_lock(&bo->bdev->lru_lock);
	(*klpe_ttm_bo_move_to_lru_tail)(bo);
	spin_unlock(&bo->bdev->lru_lock);
}

static inline void klpr_ttm_bo_unreserve(struct ttm_buffer_object *bo)
{
	klpr_ttm_bo_move_to_lru_tail_unlocked(bo);
	dma_resv_unlock(bo->base.resv);
}

struct ttm_validate_buffer;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/ttm_object.h */
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_hashtab.h */
#include <linux/list.h>

struct vmwgfx_open_hash {
	struct hlist_head *table;
	u8 order;
};

/* klp-ccp: from drivers/gpu/drm/vmwgfx/ttm_object.h */
enum ttm_object_type {
	ttm_fence_type,
	ttm_lock_type,
	ttm_prime_type,
	ttm_driver_type0 = 256,
	ttm_driver_type1,
	ttm_driver_type2,
	ttm_driver_type3,
	ttm_driver_type4,
	ttm_driver_type5
};

struct ttm_base_object {
	struct rcu_head rhead;
	struct ttm_object_file *tfile;
	struct kref refcount;
	void (*refcount_release) (struct ttm_base_object **base);
	u32 handle;
	enum ttm_object_type object_type;
	u32 shareable;
};

struct ttm_prime_object {
	struct ttm_base_object base;
	struct mutex mutex;
	size_t size;
	enum ttm_object_type real_type;
	struct dma_buf *dma_buf;
	void (*refcount_release) (struct ttm_base_object **);
};

static int (*klpe_ttm_prime_object_init)(struct ttm_object_file *tfile,
				 size_t size,
				 struct ttm_prime_object *prime,
				 bool shareable,
				 enum ttm_object_type type,
				 void (*refcount_release)
				 (struct ttm_base_object **));

#define ttm_prime_object_kfree(__obj, __prime)			kfree_rcu(__obj, __prime.base.rhead)

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_fence.h */
#ifndef _VMWGFX_FENCE_H_

#include <linux/dma-fence.h>
#include <linux/dma-fence-array.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _VMWGFX_FENCE_H_ */

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_reg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vm_basic_types.h */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/page.h>

typedef u64 uint64;

typedef u8  uint8;

#define CONST64U(x) x##ULL

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_types.h */
#define SVGA3D_INVALID_ID ((uint32)-1)

typedef enum SVGA3dSurfaceFormat {
	SVGA3D_FORMAT_INVALID = 0,

	SVGA3D_X8R8G8B8 = 1,
	SVGA3D_FORMAT_MIN = 1,

	SVGA3D_A8R8G8B8 = 2,

	SVGA3D_R5G6B5 = 3,
	SVGA3D_X1R5G5B5 = 4,
	SVGA3D_A1R5G5B5 = 5,
	SVGA3D_A4R4G4B4 = 6,

	SVGA3D_Z_D32 = 7,
	SVGA3D_Z_D16 = 8,
	SVGA3D_Z_D24S8 = 9,
	SVGA3D_Z_D15S1 = 10,

	SVGA3D_LUMINANCE8 = 11,
	SVGA3D_LUMINANCE4_ALPHA4 = 12,
	SVGA3D_LUMINANCE16 = 13,
	SVGA3D_LUMINANCE8_ALPHA8 = 14,

	SVGA3D_DXT1 = 15,
	SVGA3D_DXT2 = 16,
	SVGA3D_DXT3 = 17,
	SVGA3D_DXT4 = 18,
	SVGA3D_DXT5 = 19,

	SVGA3D_BUMPU8V8 = 20,
	SVGA3D_BUMPL6V5U5 = 21,
	SVGA3D_BUMPX8L8V8U8 = 22,
	SVGA3D_FORMAT_DEAD1 = 23,

	SVGA3D_ARGB_S10E5 = 24,
	SVGA3D_ARGB_S23E8 = 25,

	SVGA3D_A2R10G10B10 = 26,

	SVGA3D_V8U8 = 27,
	SVGA3D_Q8W8V8U8 = 28,
	SVGA3D_CxV8U8 = 29,

	SVGA3D_X8L8V8U8 = 30,
	SVGA3D_A2W10V10U10 = 31,

	SVGA3D_ALPHA8 = 32,

	SVGA3D_R_S10E5 = 33,
	SVGA3D_R_S23E8 = 34,
	SVGA3D_RG_S10E5 = 35,
	SVGA3D_RG_S23E8 = 36,

	SVGA3D_BUFFER = 37,

	SVGA3D_Z_D24X8 = 38,

	SVGA3D_V16U16 = 39,

	SVGA3D_G16R16 = 40,
	SVGA3D_A16B16G16R16 = 41,

	SVGA3D_UYVY = 42,
	SVGA3D_YUY2 = 43,

	SVGA3D_NV12 = 44,

	SVGA3D_FORMAT_DEAD2 = 45,

	SVGA3D_R32G32B32A32_TYPELESS = 46,
	SVGA3D_R32G32B32A32_UINT = 47,
	SVGA3D_R32G32B32A32_SINT = 48,
	SVGA3D_R32G32B32_TYPELESS = 49,
	SVGA3D_R32G32B32_FLOAT = 50,
	SVGA3D_R32G32B32_UINT = 51,
	SVGA3D_R32G32B32_SINT = 52,
	SVGA3D_R16G16B16A16_TYPELESS = 53,
	SVGA3D_R16G16B16A16_UINT = 54,
	SVGA3D_R16G16B16A16_SNORM = 55,
	SVGA3D_R16G16B16A16_SINT = 56,
	SVGA3D_R32G32_TYPELESS = 57,
	SVGA3D_R32G32_UINT = 58,
	SVGA3D_R32G32_SINT = 59,
	SVGA3D_R32G8X24_TYPELESS = 60,
	SVGA3D_D32_FLOAT_S8X24_UINT = 61,
	SVGA3D_R32_FLOAT_X8X24 = 62,
	SVGA3D_X32_G8X24_UINT = 63,
	SVGA3D_R10G10B10A2_TYPELESS = 64,
	SVGA3D_R10G10B10A2_UINT = 65,
	SVGA3D_R11G11B10_FLOAT = 66,
	SVGA3D_R8G8B8A8_TYPELESS = 67,
	SVGA3D_R8G8B8A8_UNORM = 68,
	SVGA3D_R8G8B8A8_UNORM_SRGB = 69,
	SVGA3D_R8G8B8A8_UINT = 70,
	SVGA3D_R8G8B8A8_SINT = 71,
	SVGA3D_R16G16_TYPELESS = 72,
	SVGA3D_R16G16_UINT = 73,
	SVGA3D_R16G16_SINT = 74,
	SVGA3D_R32_TYPELESS = 75,
	SVGA3D_D32_FLOAT = 76,
	SVGA3D_R32_UINT = 77,
	SVGA3D_R32_SINT = 78,
	SVGA3D_R24G8_TYPELESS = 79,
	SVGA3D_D24_UNORM_S8_UINT = 80,
	SVGA3D_R24_UNORM_X8 = 81,
	SVGA3D_X24_G8_UINT = 82,
	SVGA3D_R8G8_TYPELESS = 83,
	SVGA3D_R8G8_UNORM = 84,
	SVGA3D_R8G8_UINT = 85,
	SVGA3D_R8G8_SINT = 86,
	SVGA3D_R16_TYPELESS = 87,
	SVGA3D_R16_UNORM = 88,
	SVGA3D_R16_UINT = 89,
	SVGA3D_R16_SNORM = 90,
	SVGA3D_R16_SINT = 91,
	SVGA3D_R8_TYPELESS = 92,
	SVGA3D_R8_UNORM = 93,
	SVGA3D_R8_UINT = 94,
	SVGA3D_R8_SNORM = 95,
	SVGA3D_R8_SINT = 96,
	SVGA3D_P8 = 97,
	SVGA3D_R9G9B9E5_SHAREDEXP = 98,
	SVGA3D_R8G8_B8G8_UNORM = 99,
	SVGA3D_G8R8_G8B8_UNORM = 100,
	SVGA3D_BC1_TYPELESS = 101,
	SVGA3D_BC1_UNORM_SRGB = 102,
	SVGA3D_BC2_TYPELESS = 103,
	SVGA3D_BC2_UNORM_SRGB = 104,
	SVGA3D_BC3_TYPELESS = 105,
	SVGA3D_BC3_UNORM_SRGB = 106,
	SVGA3D_BC4_TYPELESS = 107,
	SVGA3D_ATI1 = 108,
	SVGA3D_BC4_SNORM = 109,
	SVGA3D_BC5_TYPELESS = 110,
	SVGA3D_ATI2 = 111,
	SVGA3D_BC5_SNORM = 112,
	SVGA3D_R10G10B10_XR_BIAS_A2_UNORM = 113,
	SVGA3D_B8G8R8A8_TYPELESS = 114,
	SVGA3D_B8G8R8A8_UNORM_SRGB = 115,
	SVGA3D_B8G8R8X8_TYPELESS = 116,
	SVGA3D_B8G8R8X8_UNORM_SRGB = 117,

	SVGA3D_Z_DF16 = 118,
	SVGA3D_Z_DF24 = 119,
	SVGA3D_Z_D24S8_INT = 120,

	SVGA3D_YV12 = 121,

	SVGA3D_R32G32B32A32_FLOAT = 122,
	SVGA3D_R16G16B16A16_FLOAT = 123,
	SVGA3D_R16G16B16A16_UNORM = 124,
	SVGA3D_R32G32_FLOAT = 125,
	SVGA3D_R10G10B10A2_UNORM = 126,
	SVGA3D_R8G8B8A8_SNORM = 127,
	SVGA3D_R16G16_FLOAT = 128,
	SVGA3D_R16G16_UNORM = 129,
	SVGA3D_R16G16_SNORM = 130,
	SVGA3D_R32_FLOAT = 131,
	SVGA3D_R8G8_SNORM = 132,
	SVGA3D_R16_FLOAT = 133,
	SVGA3D_D16_UNORM = 134,
	SVGA3D_A8_UNORM = 135,
	SVGA3D_BC1_UNORM = 136,
	SVGA3D_BC2_UNORM = 137,
	SVGA3D_BC3_UNORM = 138,
	SVGA3D_B5G6R5_UNORM = 139,
	SVGA3D_B5G5R5A1_UNORM = 140,
	SVGA3D_B8G8R8A8_UNORM = 141,
	SVGA3D_B8G8R8X8_UNORM = 142,
	SVGA3D_BC4_UNORM = 143,
	SVGA3D_BC5_UNORM = 144,
	SVGA3D_B4G4R4A4_UNORM = 145,

	SVGA3D_BC6H_TYPELESS = 146,
	SVGA3D_BC6H_UF16 = 147,
	SVGA3D_BC6H_SF16 = 148,
	SVGA3D_BC7_TYPELESS = 149,
	SVGA3D_BC7_UNORM = 150,
	SVGA3D_BC7_UNORM_SRGB = 151,

	SVGA3D_AYUV = 152,

	SVGA3D_R11G11B10_TYPELESS = 153,

	SVGA3D_FORMAT_MAX
} SVGA3dSurfaceFormat;

#define SVGA3D_SURFACE_MULTISAMPLE (CONST64U(1) << 32)

typedef uint64 SVGA3dSurfaceAllFlags;

enum {
	SVGA3D_TEX_FILTER_NONE = 0,
	SVGA3D_TEX_FILTER_MIN = 0,
	SVGA3D_TEX_FILTER_NEAREST = 1,
	SVGA3D_TEX_FILTER_LINEAR = 2,
	SVGA3D_TEX_FILTER_ANISOTROPIC = 3,
	SVGA3D_TEX_FILTER_FLATCUBIC = 4,
	SVGA3D_TEX_FILTER_GAUSSIANCUBIC = 5,
	SVGA3D_TEX_FILTER_PYRAMIDALQUAD = 6,
	SVGA3D_TEX_FILTER_GAUSSIANQUAD = 7,
	SVGA3D_TEX_FILTER_MAX
};

typedef struct {
	uint32 width;
	uint32 height;
	uint32 depth;
} SVGA3dSize;

enum SVGA3dMSPattern {
	SVGA3D_MS_PATTERN_NONE = 0,
	SVGA3D_MS_PATTERN_MIN = 0,
	SVGA3D_MS_PATTERN_STANDARD = 1,
	SVGA3D_MS_PATTERN_CENTER = 2,
	SVGA3D_MS_PATTERN_MAX = 3,
};

enum SVGA3dMSQualityLevel {
	SVGA3D_MS_QUALITY_NONE = 0,
	SVGA3D_MS_QUALITY_MIN = 0,
	SVGA3D_MS_QUALITY_FULL = 1,
	SVGA3D_MS_QUALITY_RESOLVED = 2,
	SVGA3D_MS_QUALITY_MAX = 3,
};

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_validation.h */
#include <linux/list.h>
#include <linux/ww_mutex.h>
#include <drm/ttm/ttm_execbuf_util.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/vmwgfx_drm.h>

#define VMWGFX_MAX_NUM_IRQS 6

#define VMW_RES_SURFACE ttm_driver_type1

#define MKSSTAT_CAPACITY_LOG2 5U
#define MKSSTAT_CAPACITY (1U << MKSSTAT_CAPACITY_LOG2)

struct vmw_fpriv {
	struct ttm_object_file *tfile;
	bool gb_aware; /* user-space is guest-backed aware */
};

struct vmw_buffer_object {
	struct ttm_buffer_object base;
	struct rb_root res_tree;
	/* For KMS atomic helpers: ttm bo mapping count */
	atomic_t base_mapped_count;

	atomic_t cpu_writers;
	/* Not ref-counted.  Protected by binding_mutex */
	struct vmw_resource *dx_query_ctx;
	/* Protected by reservation */
	struct ttm_bo_kmap_obj map;
	u32 res_prios[TTM_MAX_BO_PRIORITY];
	struct vmw_bo_dirty *dirty;
};

struct vmw_resource {
	struct kref kref;
	struct vmw_private *dev_priv;
	int id;
	u32 used_prio;
	unsigned long backup_size;
	u32 res_dirty : 1;
	u32 backup_dirty : 1;
	u32 coherent : 1;
	struct vmw_buffer_object *backup;
	unsigned long backup_offset;
	unsigned long pin_count;
	const struct vmw_res_func *func;
	struct rb_node mob_node;
	struct list_head lru_head;
	struct list_head binding_head;
	struct vmw_resource_dirty *dirty;
	void (*res_free) (struct vmw_resource *res);
	void (*hw_destroy) (struct vmw_resource *res);
};

enum vmw_res_type {
	vmw_res_context,
	vmw_res_surface,
	vmw_res_stream,
	vmw_res_shader,
	vmw_res_dx_context,
	vmw_res_cotable,
	vmw_res_view,
	vmw_res_streamoutput,
	vmw_res_max
};

struct vmw_cursor_snooper {
	size_t age;
	uint32_t *image;
};

struct vmw_surface_metadata {
	u64 flags;
	u32 format;
	u32 mip_levels[DRM_VMW_MAX_SURFACE_FACES];
	u32 multisample_count;
	u32 multisample_pattern;
	u32 quality_level;
	u32 autogen_filter;
	u32 array_size;
	u32 num_sizes;
	u32 buffer_byte_stride;
	struct drm_vmw_size base_size;
	struct drm_vmw_size *sizes;
	bool scanout;
};

struct vmw_surface {
	struct vmw_resource res;
	struct vmw_surface_metadata metadata;
	struct vmw_cursor_snooper snooper;
	struct vmw_surface_offset *offsets;
	struct list_head view_list;
};

struct vmw_res_cache_entry {
	uint32_t handle;
	struct vmw_resource *res;
	void *private;
	unsigned short valid_handle;
	unsigned short valid;
};

enum vmw_dma_map_mode {
	vmw_dma_alloc_coherent, /* Use TTM coherent pages */
	vmw_dma_map_populate,   /* Unmap from DMA just after unpopulate */
	vmw_dma_map_bind,       /* Unmap from DMA just before unbind */
	vmw_dma_map_max
};

enum vmw_display_unit_type {
	vmw_du_invalid = 0,
	vmw_du_legacy,
	vmw_du_screen_object,
	vmw_du_screen_target,
	vmw_du_max
};

struct vmw_sw_context{
	struct vmwgfx_open_hash res_ht;
	bool res_ht_initialized;
	bool kernel;
	struct vmw_fpriv *fp;
	struct drm_file *filp;
	uint32_t *cmd_bounce;
	uint32_t cmd_bounce_size;
	struct vmw_buffer_object *cur_query_bo;
	struct list_head bo_relocations;
	struct list_head res_relocations;
	uint32_t *buf_start;
	struct vmw_res_cache_entry res_cache[vmw_res_max];
	struct vmw_resource *last_query_ctx;
	bool needs_post_query_barrier;
	struct vmw_ctx_binding_state *staged_bindings;
	bool staged_bindings_inuse;
	struct list_head staged_cmd_res;
	struct list_head ctx_list;
	struct vmw_ctx_validation_info *dx_ctx_node;
	struct vmw_buffer_object *dx_query_mob;
	struct vmw_resource *dx_query_ctx;
	struct vmw_cmdbuf_res_manager *man;
	struct vmw_validation_context *ctx;
};

struct vmw_otable_batch {
	unsigned num_otables;
	struct vmw_otable *otables;
	struct vmw_resource *context;
	struct ttm_buffer_object *otable_bo;
};

enum {
	VMW_IRQTHREAD_FENCE,
	VMW_IRQTHREAD_CMDBUF,
	VMW_IRQTHREAD_MAX
};

enum vmw_sm_type {
	VMW_SM_LEGACY = 0,
	VMW_SM_4,
	VMW_SM_4_1,
	VMW_SM_5,
	VMW_SM_5_1X,
	VMW_SM_MAX
};

struct vmw_private {
	struct drm_device drm;
	struct ttm_device bdev;

	struct drm_vma_offset_manager vma_manager;
	u32 pci_id;
	resource_size_t io_start;
	resource_size_t vram_start;
	resource_size_t vram_size;
	resource_size_t max_primary_mem;
	u32 __iomem *rmmio;
	u32 *fifo_mem;
	resource_size_t fifo_mem_size;
	uint32_t fb_max_width;
	uint32_t fb_max_height;
	uint32_t texture_max_width;
	uint32_t texture_max_height;
	uint32_t stdu_max_width;
	uint32_t stdu_max_height;
	uint32_t initial_width;
	uint32_t initial_height;
	uint32_t capabilities;
	uint32_t capabilities2;
	uint32_t max_gmr_ids;
	uint32_t max_gmr_pages;
	uint32_t max_mob_pages;
	uint32_t max_mob_size;
	uint32_t memory_size;
	bool has_gmr;
	bool has_mob;
	spinlock_t hw_lock;
	bool assume_16bpp;
	u32 irqs[VMWGFX_MAX_NUM_IRQS];
	u32 num_irq_vectors;

	enum vmw_sm_type sm_type;

	/*
	 * Framebuffer info.
	 */

	void *fb_info;
	enum vmw_display_unit_type active_display_unit;
	struct vmw_legacy_display *ldu_priv;
	struct vmw_overlay *overlay_priv;
	struct drm_property *hotplug_mode_update_property;
	struct drm_property *implicit_placement_property;
	spinlock_t cursor_lock;
	struct drm_atomic_state *suspend_state;

	/*
	 * Context and surface management.
	 */

	spinlock_t resource_lock;
	struct idr res_idr[vmw_res_max];

	/*
	 * A resource manager for kernel-only surfaces and
	 * contexts.
	 */

	struct ttm_object_device *tdev;

	/*
	 * Fencing and IRQs.
	 */

	atomic_t marker_seq;
	wait_queue_head_t fence_queue;
	wait_queue_head_t fifo_queue;
	spinlock_t waiter_lock;
	int fence_queue_waiters; /* Protected by waiter_lock */
	int goal_queue_waiters; /* Protected by waiter_lock */
	int cmdbuf_waiters; /* Protected by waiter_lock */
	int error_waiters; /* Protected by waiter_lock */
	int fifo_queue_waiters; /* Protected by waiter_lock */
	uint32_t last_read_seqno;
	struct vmw_fence_manager *fman;
	uint32_t irq_mask; /* Updates protected by waiter_lock */

	/*
	 * Device state
	 */

	uint32_t traces_state;
	uint32_t enable_state;
	uint32_t config_done_state;

	/**
	 * Execbuf
	 */
	/**
	 * Protected by the cmdbuf mutex.
	 */

	struct vmw_sw_context ctx;
	struct mutex cmdbuf_mutex;
	struct mutex binding_mutex;

	bool enable_fb;

	/**
	 * PM management.
	 */
	struct notifier_block pm_nb;
	bool refuse_hibernation;
	bool suspend_locked;

	atomic_t num_fifo_resources;

	/*
	 * Query processing. These members
	 * are protected by the cmdbuf mutex.
	 */

	struct vmw_buffer_object *dummy_query_bo;
	struct vmw_buffer_object *pinned_bo;
	uint32_t query_cid;
	uint32_t query_cid_valid;
	bool dummy_query_bo_pinned;

	/*
	 * Surface swapping. The "surface_lru" list is protected by the
	 * resource lock in order to be able to destroy a surface and take
	 * it off the lru atomically. "used_memory_size" is currently
	 * protected by the cmdbuf mutex for simplicity.
	 */

	struct list_head res_lru[vmw_res_max];
	uint32_t used_memory_size;

	/*
	 * DMA mapping stuff.
	 */
	enum vmw_dma_map_mode map_mode;

	/*
	 * Guest Backed stuff
	 */
	struct vmw_otable_batch otable_batch;

	struct vmw_fifo_state *fifo;
	struct vmw_cmdbuf_man *cman;
	DECLARE_BITMAP(irqthread_pending, VMW_IRQTHREAD_MAX);

	uint32 *devcaps;

	/*
	 * mksGuestStat instance-descriptor and pid arrays
	 */
	struct page *mksstat_user_pages[MKSSTAT_CAPACITY];
	atomic_t mksstat_user_pids[MKSSTAT_CAPACITY];

#if IS_ENABLED(CONFIG_DRM_VMWGFX_MKSSTATS)
#error "klp-ccp: non-taken branch"
#endif
};

static inline struct vmw_private *vmw_priv(struct drm_device *dev)
{
	return (struct vmw_private *)dev->dev_private;
}

static inline struct vmw_fpriv *vmw_fpriv(struct drm_file *file_priv)
{
	return (struct vmw_fpriv *)file_priv->driver_priv;
}

static inline bool has_sm4_context(const struct vmw_private *dev_priv)
{
	return (dev_priv->sm_type >= VMW_SM_4);
}

static inline bool has_sm4_1_context(const struct vmw_private *dev_priv)
{
	return (dev_priv->sm_type >= VMW_SM_4_1);
}

static inline bool has_sm5_context(const struct vmw_private *dev_priv)
{
	return (dev_priv->sm_type >= VMW_SM_5);
}

static void (*klpe_vmw_resource_unreference)(struct vmw_resource **p_res);
static struct vmw_resource *(*klpe_vmw_resource_reference)(struct vmw_resource *res);

static int (*klpe_vmw_gem_object_create_with_handle)(struct vmw_private *dev_priv,
					     struct drm_file *filp,
					     uint32_t size,
					     uint32_t *handle,
					     struct vmw_buffer_object **p_vbo);

static int (*klpe_vmw_gb_surface_define)(struct vmw_private *dev_priv,
			  const struct vmw_surface_metadata *req,
			  struct vmw_surface **srf_out);

static int (*klpe_vmw_bo_dirty_add)(struct vmw_buffer_object *vbo);

static inline void klpr_vmw_bo_unreference(struct vmw_buffer_object **buf)
{
	struct vmw_buffer_object *tmp_buf = *buf;

	*buf = NULL;
	if (tmp_buf != NULL)
		(*klpe_ttm_bo_put)(&tmp_buf->base);
}

static inline struct vmw_buffer_object *
vmw_bo_reference(struct vmw_buffer_object *buf)
{
	ttm_bo_get(&buf->base);
	return buf;
}

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_resource_priv.h */
enum vmw_cmdbuf_res_state;

struct vmw_res_func {
	enum vmw_res_type res_type;
	bool needs_backup;
	const char *type_name;
	struct ttm_placement *backup_placement;
	bool may_evict;
	u32 prio;
	u32 dirty_prio;

	int (*create) (struct vmw_resource *res);
	int (*destroy) (struct vmw_resource *res);
	int (*bind) (struct vmw_resource *res,
		     struct ttm_validate_buffer *val_buf);
	int (*unbind) (struct vmw_resource *res,
		       bool readback,
		       struct ttm_validate_buffer *val_buf);
	void (*commit_notify)(struct vmw_resource *res,
			      enum vmw_cmdbuf_res_state state);
	int (*dirty_alloc)(struct vmw_resource *res);
	void (*dirty_free)(struct vmw_resource *res);
	int (*dirty_sync)(struct vmw_resource *res);
	void (*dirty_range_add)(struct vmw_resource *res, size_t start,
				 size_t end);
	int (*clean)(struct vmw_resource *res);
};

static int (*klpe_vmw_resource_init)(struct vmw_private *dev_priv, struct vmw_resource *res,
		      bool delay_id,
		      void (*res_free) (struct vmw_resource *res),
		      const struct vmw_res_func *func);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_binding.h */
#include <linux/list.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_surfacedefs.h */
#define STATIC_CONST static const

typedef enum SVGA3dBlockDesc {

	SVGA3DBLOCKDESC_NONE = 0,

	SVGA3DBLOCKDESC_BLUE = 1 << 0,
	SVGA3DBLOCKDESC_W = 1 << 0,
	SVGA3DBLOCKDESC_BUMP_L = 1 << 0,

	SVGA3DBLOCKDESC_GREEN = 1 << 1,
	SVGA3DBLOCKDESC_V = 1 << 1,

	SVGA3DBLOCKDESC_RED = 1 << 2,
	SVGA3DBLOCKDESC_U = 1 << 2,
	SVGA3DBLOCKDESC_LUMINANCE = 1 << 2,

	SVGA3DBLOCKDESC_ALPHA = 1 << 3,
	SVGA3DBLOCKDESC_Q = 1 << 3,

	SVGA3DBLOCKDESC_BUFFER = 1 << 4,

	SVGA3DBLOCKDESC_COMPRESSED = 1 << 5,

	SVGA3DBLOCKDESC_FP = 1 << 6,

	SVGA3DBLOCKDESC_PLANAR_YUV = 1 << 7,

	SVGA3DBLOCKDESC_2PLANAR_YUV = 1 << 8,

	SVGA3DBLOCKDESC_3PLANAR_YUV = 1 << 9,

	SVGA3DBLOCKDESC_STENCIL = 1 << 11,

	SVGA3DBLOCKDESC_TYPELESS = 1 << 12,

	SVGA3DBLOCKDESC_SINT = 1 << 13,

	SVGA3DBLOCKDESC_UINT = 1 << 14,

	SVGA3DBLOCKDESC_NORM = 1 << 15,

	SVGA3DBLOCKDESC_SRGB = 1 << 16,

	SVGA3DBLOCKDESC_EXP = 1 << 17,

	SVGA3DBLOCKDESC_COLOR = 1 << 18,

	SVGA3DBLOCKDESC_DEPTH = 1 << 19,

	SVGA3DBLOCKDESC_BUMP = 1 << 20,

	SVGA3DBLOCKDESC_YUV_VIDEO = 1 << 21,

	SVGA3DBLOCKDESC_MIXED = 1 << 22,

	SVGA3DBLOCKDESC_CX = 1 << 23,

	SVGA3DBLOCKDESC_BC1 = 1 << 24,
	SVGA3DBLOCKDESC_BC2 = 1 << 25,
	SVGA3DBLOCKDESC_BC3 = 1 << 26,
	SVGA3DBLOCKDESC_BC4 = 1 << 27,
	SVGA3DBLOCKDESC_BC5 = 1 << 28,
	SVGA3DBLOCKDESC_BC6H = 1 << 29,
	SVGA3DBLOCKDESC_BC7 = 1 << 30,
	SVGA3DBLOCKDESC_COMPRESSED_MASK =
		SVGA3DBLOCKDESC_BC1 | SVGA3DBLOCKDESC_BC2 |
		SVGA3DBLOCKDESC_BC3 | SVGA3DBLOCKDESC_BC4 |
		SVGA3DBLOCKDESC_BC5 | SVGA3DBLOCKDESC_BC6H |
		SVGA3DBLOCKDESC_BC7,

	SVGA3DBLOCKDESC_A_UINT = SVGA3DBLOCKDESC_ALPHA | SVGA3DBLOCKDESC_UINT |
				 SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_A_UNORM = SVGA3DBLOCKDESC_A_UINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_R_UINT = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_UINT |
				 SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_R_UNORM = SVGA3DBLOCKDESC_R_UINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_R_SINT = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_SINT |
				 SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_R_SNORM = SVGA3DBLOCKDESC_R_SINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_G_UINT = SVGA3DBLOCKDESC_GREEN | SVGA3DBLOCKDESC_UINT |
				 SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RG_UINT = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
				  SVGA3DBLOCKDESC_UINT | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RG_UNORM =
		SVGA3DBLOCKDESC_RG_UINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_RG_SINT = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
				  SVGA3DBLOCKDESC_SINT | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RG_SNORM =
		SVGA3DBLOCKDESC_RG_SINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_RGB_UINT = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
				   SVGA3DBLOCKDESC_BLUE | SVGA3DBLOCKDESC_UINT |
				   SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RGB_SINT = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
				   SVGA3DBLOCKDESC_BLUE | SVGA3DBLOCKDESC_SINT |
				   SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RGB_UNORM =
		SVGA3DBLOCKDESC_RGB_UINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_RGB_UNORM_SRGB =
		SVGA3DBLOCKDESC_RGB_UNORM | SVGA3DBLOCKDESC_SRGB,
	SVGA3DBLOCKDESC_RGBA_UINT =
		SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
		SVGA3DBLOCKDESC_BLUE | SVGA3DBLOCKDESC_ALPHA |
		SVGA3DBLOCKDESC_UINT | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RGBA_UNORM =
		SVGA3DBLOCKDESC_RGBA_UINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_RGBA_UNORM_SRGB =
		SVGA3DBLOCKDESC_RGBA_UNORM | SVGA3DBLOCKDESC_SRGB,
	SVGA3DBLOCKDESC_RGBA_SINT =
		SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
		SVGA3DBLOCKDESC_BLUE | SVGA3DBLOCKDESC_ALPHA |
		SVGA3DBLOCKDESC_SINT | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RGBA_SNORM =
		SVGA3DBLOCKDESC_RGBA_SINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_RGBA_FP = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
				  SVGA3DBLOCKDESC_BLUE | SVGA3DBLOCKDESC_ALPHA |
				  SVGA3DBLOCKDESC_FP | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_UV =
		SVGA3DBLOCKDESC_U | SVGA3DBLOCKDESC_V | SVGA3DBLOCKDESC_BUMP,
	SVGA3DBLOCKDESC_UVL = SVGA3DBLOCKDESC_UV | SVGA3DBLOCKDESC_BUMP_L |
			      SVGA3DBLOCKDESC_MIXED | SVGA3DBLOCKDESC_BUMP,
	SVGA3DBLOCKDESC_UVW =
		SVGA3DBLOCKDESC_UV | SVGA3DBLOCKDESC_W | SVGA3DBLOCKDESC_BUMP,
	SVGA3DBLOCKDESC_UVWA = SVGA3DBLOCKDESC_UVW | SVGA3DBLOCKDESC_ALPHA |
			       SVGA3DBLOCKDESC_MIXED | SVGA3DBLOCKDESC_BUMP,
	SVGA3DBLOCKDESC_UVWQ = SVGA3DBLOCKDESC_U | SVGA3DBLOCKDESC_V |
			       SVGA3DBLOCKDESC_W | SVGA3DBLOCKDESC_Q |
			       SVGA3DBLOCKDESC_BUMP,
	SVGA3DBLOCKDESC_L_UNORM = SVGA3DBLOCKDESC_LUMINANCE |
				  SVGA3DBLOCKDESC_UINT | SVGA3DBLOCKDESC_NORM |
				  SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_LA_UNORM = SVGA3DBLOCKDESC_LUMINANCE |
				   SVGA3DBLOCKDESC_ALPHA |
				   SVGA3DBLOCKDESC_UINT | SVGA3DBLOCKDESC_NORM |
				   SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_R_FP = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_FP |
			       SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RG_FP = SVGA3DBLOCKDESC_R_FP | SVGA3DBLOCKDESC_GREEN |
				SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RGB_FP = SVGA3DBLOCKDESC_RG_FP | SVGA3DBLOCKDESC_BLUE |
				 SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_YUV = SVGA3DBLOCKDESC_YUV_VIDEO | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_AYUV = SVGA3DBLOCKDESC_ALPHA |
			       SVGA3DBLOCKDESC_YUV_VIDEO |
			       SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_RGB_EXP = SVGA3DBLOCKDESC_RED | SVGA3DBLOCKDESC_GREEN |
				  SVGA3DBLOCKDESC_BLUE | SVGA3DBLOCKDESC_EXP |
				  SVGA3DBLOCKDESC_COLOR,

	SVGA3DBLOCKDESC_COMP_TYPELESS =
		SVGA3DBLOCKDESC_COMPRESSED | SVGA3DBLOCKDESC_TYPELESS,
	SVGA3DBLOCKDESC_COMP_UNORM =
		SVGA3DBLOCKDESC_COMPRESSED | SVGA3DBLOCKDESC_UINT |
		SVGA3DBLOCKDESC_NORM | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_COMP_SNORM =
		SVGA3DBLOCKDESC_COMPRESSED | SVGA3DBLOCKDESC_SINT |
		SVGA3DBLOCKDESC_NORM | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_COMP_UNORM_SRGB =
		SVGA3DBLOCKDESC_COMP_UNORM | SVGA3DBLOCKDESC_SRGB,
	SVGA3DBLOCKDESC_BC1_COMP_TYPELESS =
		SVGA3DBLOCKDESC_BC1 | SVGA3DBLOCKDESC_COMP_TYPELESS,
	SVGA3DBLOCKDESC_BC1_COMP_UNORM =
		SVGA3DBLOCKDESC_BC1 | SVGA3DBLOCKDESC_COMP_UNORM,
	SVGA3DBLOCKDESC_BC1_COMP_UNORM_SRGB =
		SVGA3DBLOCKDESC_BC1_COMP_UNORM | SVGA3DBLOCKDESC_SRGB,
	SVGA3DBLOCKDESC_BC2_COMP_TYPELESS =
		SVGA3DBLOCKDESC_BC2 | SVGA3DBLOCKDESC_COMP_TYPELESS,
	SVGA3DBLOCKDESC_BC2_COMP_UNORM =
		SVGA3DBLOCKDESC_BC2 | SVGA3DBLOCKDESC_COMP_UNORM,
	SVGA3DBLOCKDESC_BC2_COMP_UNORM_SRGB =
		SVGA3DBLOCKDESC_BC2_COMP_UNORM | SVGA3DBLOCKDESC_SRGB,
	SVGA3DBLOCKDESC_BC3_COMP_TYPELESS =
		SVGA3DBLOCKDESC_BC3 | SVGA3DBLOCKDESC_COMP_TYPELESS,
	SVGA3DBLOCKDESC_BC3_COMP_UNORM =
		SVGA3DBLOCKDESC_BC3 | SVGA3DBLOCKDESC_COMP_UNORM,
	SVGA3DBLOCKDESC_BC3_COMP_UNORM_SRGB =
		SVGA3DBLOCKDESC_BC3_COMP_UNORM | SVGA3DBLOCKDESC_SRGB,
	SVGA3DBLOCKDESC_BC4_COMP_TYPELESS =
		SVGA3DBLOCKDESC_BC4 | SVGA3DBLOCKDESC_COMP_TYPELESS,
	SVGA3DBLOCKDESC_BC4_COMP_UNORM =
		SVGA3DBLOCKDESC_BC4 | SVGA3DBLOCKDESC_COMP_UNORM,
	SVGA3DBLOCKDESC_BC4_COMP_SNORM =
		SVGA3DBLOCKDESC_BC4 | SVGA3DBLOCKDESC_COMP_SNORM,
	SVGA3DBLOCKDESC_BC5_COMP_TYPELESS =
		SVGA3DBLOCKDESC_BC5 | SVGA3DBLOCKDESC_COMP_TYPELESS,
	SVGA3DBLOCKDESC_BC5_COMP_UNORM =
		SVGA3DBLOCKDESC_BC5 | SVGA3DBLOCKDESC_COMP_UNORM,
	SVGA3DBLOCKDESC_BC5_COMP_SNORM =
		SVGA3DBLOCKDESC_BC5 | SVGA3DBLOCKDESC_COMP_SNORM,
	SVGA3DBLOCKDESC_BC6H_COMP_TYPELESS =
		SVGA3DBLOCKDESC_BC6H | SVGA3DBLOCKDESC_COMP_TYPELESS,
	SVGA3DBLOCKDESC_BC6H_COMP_UF16 =
		SVGA3DBLOCKDESC_BC6H | SVGA3DBLOCKDESC_COMPRESSED,
	SVGA3DBLOCKDESC_BC6H_COMP_SF16 =
		SVGA3DBLOCKDESC_BC6H | SVGA3DBLOCKDESC_COMPRESSED,
	SVGA3DBLOCKDESC_BC7_COMP_TYPELESS =
		SVGA3DBLOCKDESC_BC7 | SVGA3DBLOCKDESC_COMP_TYPELESS,
	SVGA3DBLOCKDESC_BC7_COMP_UNORM =
		SVGA3DBLOCKDESC_BC7 | SVGA3DBLOCKDESC_COMP_UNORM,
	SVGA3DBLOCKDESC_BC7_COMP_UNORM_SRGB =
		SVGA3DBLOCKDESC_BC7_COMP_UNORM | SVGA3DBLOCKDESC_SRGB,

	SVGA3DBLOCKDESC_NV12 =
		SVGA3DBLOCKDESC_YUV_VIDEO | SVGA3DBLOCKDESC_PLANAR_YUV |
		SVGA3DBLOCKDESC_2PLANAR_YUV | SVGA3DBLOCKDESC_COLOR,
	SVGA3DBLOCKDESC_YV12 =
		SVGA3DBLOCKDESC_YUV_VIDEO | SVGA3DBLOCKDESC_PLANAR_YUV |
		SVGA3DBLOCKDESC_3PLANAR_YUV | SVGA3DBLOCKDESC_COLOR,

	SVGA3DBLOCKDESC_DEPTH_UINT =
		SVGA3DBLOCKDESC_DEPTH | SVGA3DBLOCKDESC_UINT,
	SVGA3DBLOCKDESC_DEPTH_UNORM =
		SVGA3DBLOCKDESC_DEPTH_UINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_DS = SVGA3DBLOCKDESC_DEPTH | SVGA3DBLOCKDESC_STENCIL,
	SVGA3DBLOCKDESC_DS_UINT = SVGA3DBLOCKDESC_DEPTH |
				  SVGA3DBLOCKDESC_STENCIL |
				  SVGA3DBLOCKDESC_UINT,
	SVGA3DBLOCKDESC_DS_UNORM =
		SVGA3DBLOCKDESC_DS_UINT | SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_DEPTH_FP = SVGA3DBLOCKDESC_DEPTH | SVGA3DBLOCKDESC_FP,

	SVGA3DBLOCKDESC_UV_UINT = SVGA3DBLOCKDESC_UV | SVGA3DBLOCKDESC_UINT,
	SVGA3DBLOCKDESC_UV_SNORM = SVGA3DBLOCKDESC_UV | SVGA3DBLOCKDESC_SINT |
				   SVGA3DBLOCKDESC_NORM,
	SVGA3DBLOCKDESC_UVCX_SNORM =
		SVGA3DBLOCKDESC_UV_SNORM | SVGA3DBLOCKDESC_CX,
	SVGA3DBLOCKDESC_UVWQ_SNORM = SVGA3DBLOCKDESC_UVWQ |
				     SVGA3DBLOCKDESC_SINT |
				     SVGA3DBLOCKDESC_NORM,
} SVGA3dBlockDesc;

typedef struct SVGA3dChannelDef {
	union {
		uint8 blue;
		uint8 w_bump;
		uint8 l_bump;
		uint8 uv_video;
		uint8 u_video;
	};
	union {
		uint8 green;
		uint8 stencil;
		uint8 v_bump;
		uint8 v_video;
	};
	union {
		uint8 red;
		uint8 u_bump;
		uint8 luminance;
		uint8 y_video;
		uint8 depth;
		uint8 data;
	};
	union {
		uint8 alpha;
		uint8 q_bump;
		uint8 exp;
	};
} SVGA3dChannelDef;

typedef struct SVGA3dSurfaceDesc {
	SVGA3dSurfaceFormat format;
	SVGA3dBlockDesc blockDesc;

	SVGA3dSize blockSize;
	uint32 bytesPerBlock;
	uint32 pitchBytesPerBlock;

	SVGA3dChannelDef bitDepth;
	SVGA3dChannelDef bitOffset;
} SVGA3dSurfaceDesc;

STATIC_CONST SVGA3dSurfaceDesc (*klpe_g_SVGA3dSurfaceDescs)[154];

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmw_surface_cache.h */
#include <drm/vmwgfx_drm.h>

static inline u32 clamped_umul32(u32 a, u32 b)
{
	uint64_t tmp = (uint64_t) a*b;
	return (tmp > (uint64_t) ((u32) -1)) ? (u32) -1 : tmp;
}

static inline const SVGA3dSurfaceDesc *
klpr_vmw_surface_get_desc(SVGA3dSurfaceFormat format)
{
	if (format < ARRAY_SIZE((*klpe_g_SVGA3dSurfaceDescs)))
		return &(*klpe_g_SVGA3dSurfaceDescs)[format];

	return &(*klpe_g_SVGA3dSurfaceDescs)[SVGA3D_FORMAT_INVALID];
}

static inline void
vmw_surface_get_size_in_blocks(const SVGA3dSurfaceDesc *desc,
				 const struct drm_vmw_size *pixel_size,
				 SVGA3dSize *block_size)
{
	block_size->width = __KERNEL_DIV_ROUND_UP(pixel_size->width,
						  desc->blockSize.width);
	block_size->height = __KERNEL_DIV_ROUND_UP(pixel_size->height,
						   desc->blockSize.height);
	block_size->depth = __KERNEL_DIV_ROUND_UP(pixel_size->depth,
						  desc->blockSize.depth);
}

static inline bool
vmw_surface_is_planar_surface(const SVGA3dSurfaceDesc *desc)
{
	return (desc->blockDesc & SVGA3DBLOCKDESC_PLANAR_YUV) != 0;
}

static inline u32
vmw_surface_calculate_pitch(const SVGA3dSurfaceDesc *desc,
			      const struct drm_vmw_size *size)
{
	u32 pitch;
	SVGA3dSize blocks;

	vmw_surface_get_size_in_blocks(desc, size, &blocks);

	pitch = blocks.width * desc->pitchBytesPerBlock;

	return pitch;
}

static inline u32
vmw_surface_get_image_buffer_size(const SVGA3dSurfaceDesc *desc,
				    const struct drm_vmw_size *size,
				    u32 pitch)
{
	SVGA3dSize image_blocks;
	u32 slice_size, total_size;

	vmw_surface_get_size_in_blocks(desc, size, &image_blocks);

	if (vmw_surface_is_planar_surface(desc)) {
		total_size = clamped_umul32(image_blocks.width,
					    image_blocks.height);
		total_size = clamped_umul32(total_size, image_blocks.depth);
		total_size = clamped_umul32(total_size, desc->bytesPerBlock);
		return total_size;
	}

	if (pitch == 0)
		pitch = vmw_surface_calculate_pitch(desc, size);

	slice_size = clamped_umul32(image_blocks.height, pitch);
	total_size = clamped_umul32(slice_size, image_blocks.depth);

	return total_size;
}

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_surface.c */
#define SVGA3D_FLAGS_64(upper32, lower32) (((uint64_t)upper32 << 32) | lower32)

struct vmw_user_surface {
	struct ttm_prime_object prime;
	struct vmw_surface srf;
	struct drm_master *master;
};

struct vmw_surface_offset {
	uint32_t face;
	uint32_t mip;
	uint32_t bo_offset;
};

static void (*klpe_vmw_user_surface_free)(struct vmw_resource *res);

static const struct vmw_res_func (*klpe_vmw_legacy_surface_func);

static const struct vmw_res_func (*klpe_vmw_gb_surface_func);

static void (*klpe_vmw_hw_surface_destroy)(struct vmw_resource *res);

static int klpr_vmw_surface_init(struct vmw_private *dev_priv,
			    struct vmw_surface *srf,
			    void (*res_free) (struct vmw_resource *res))
{
	int ret;
	struct vmw_resource *res = &srf->res;

	BUG_ON(!res_free);
	ret = (*klpe_vmw_resource_init)(dev_priv, res, true, res_free,
				(dev_priv->has_mob) ? &(*klpe_vmw_gb_surface_func) :
				&(*klpe_vmw_legacy_surface_func));

	if (unlikely(ret != 0)) {
		res_free(res);
		return ret;
	}

	/*
	 * The surface won't be visible to hardware until a
	 * surface validate.
	 */

	INIT_LIST_HEAD(&srf->view_list);
	res->hw_destroy = (*klpe_vmw_hw_surface_destroy);
	return ret;
}

static void (*klpe_vmw_user_surface_free)(struct vmw_resource *res);

void klpp_vmw_user_surface_base_release(struct ttm_base_object **p_base)
{
	struct ttm_base_object *base = *p_base;
	struct vmw_user_surface *user_srf =
	    container_of(base, struct vmw_user_surface, prime.base);
	struct vmw_resource *res = &user_srf->srf.res;

	if (res && res->backup)
		klpr_drm_gem_object_put(&res->backup->base.base);

	*p_base = NULL;
	(*klpe_vmw_resource_unreference)(&res);
}

static int (*klpe_drm_gem_handle_delete)(struct drm_file *filp, u32 handle);

int klpp_vmw_surface_define_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct vmw_user_surface *user_srf;
	struct vmw_surface *srf;
	struct vmw_surface_metadata *metadata;
	struct vmw_resource *res;
	struct vmw_resource *tmp;
	union drm_vmw_surface_create_arg *arg =
	    (union drm_vmw_surface_create_arg *)data;
	struct drm_vmw_surface_create_req *req = &arg->req;
	struct drm_vmw_surface_arg *rep = &arg->rep;
	struct ttm_object_file *tfile = vmw_fpriv(file_priv)->tfile;
	int ret;
	int i, j;
	uint32_t cur_bo_offset;
	struct drm_vmw_size *cur_size;
	struct vmw_surface_offset *cur_offset;
	uint32_t num_sizes;
	const SVGA3dSurfaceDesc *desc;

	num_sizes = 0;
	for (i = 0; i < DRM_VMW_MAX_SURFACE_FACES; ++i) {
		if (req->mip_levels[i] > DRM_VMW_MAX_MIP_LEVELS)
			return -EINVAL;
		num_sizes += req->mip_levels[i];
	}

	if (num_sizes > DRM_VMW_MAX_SURFACE_FACES * DRM_VMW_MAX_MIP_LEVELS ||
	    num_sizes == 0)
		return -EINVAL;

	desc = klpr_vmw_surface_get_desc(req->format);
	if (unlikely(desc->blockDesc == SVGA3DBLOCKDESC_NONE)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Invalid format %d for surface creation.\n",req->format);
		return -EINVAL;
	}

	user_srf = kzalloc(sizeof(*user_srf), GFP_KERNEL);
	if (unlikely(!user_srf)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	srf = &user_srf->srf;
	metadata = &srf->metadata;
	res = &srf->res;

	/* Driver internally stores as 64-bit flags */
	metadata->flags = (SVGA3dSurfaceAllFlags)req->flags;
	metadata->format = req->format;
	metadata->scanout = req->scanout;

	memcpy(metadata->mip_levels, req->mip_levels,
	       sizeof(metadata->mip_levels));
	metadata->num_sizes = num_sizes;
	metadata->sizes =
		memdup_user((struct drm_vmw_size __user *)(unsigned long)
			    req->size_addr,
			    sizeof(*metadata->sizes) * metadata->num_sizes);
	if (IS_ERR(metadata->sizes)) {
		ret = PTR_ERR(metadata->sizes);
		goto out_no_sizes;
	}
	srf->offsets = kmalloc_array(metadata->num_sizes, sizeof(*srf->offsets),
				     GFP_KERNEL);
	if (unlikely(!srf->offsets)) {
		ret = -ENOMEM;
		goto out_no_offsets;
	}

	metadata->base_size = *srf->metadata.sizes;
	metadata->autogen_filter = SVGA3D_TEX_FILTER_NONE;
	metadata->multisample_count = 0;
	metadata->multisample_pattern = SVGA3D_MS_PATTERN_NONE;
	metadata->quality_level = SVGA3D_MS_QUALITY_NONE;

	cur_bo_offset = 0;
	cur_offset = srf->offsets;
	cur_size = metadata->sizes;

	for (i = 0; i < DRM_VMW_MAX_SURFACE_FACES; ++i) {
		for (j = 0; j < metadata->mip_levels[i]; ++j) {
			uint32_t stride = vmw_surface_calculate_pitch(
						  desc, cur_size);

			cur_offset->face = i;
			cur_offset->mip = j;
			cur_offset->bo_offset = cur_bo_offset;
			cur_bo_offset += vmw_surface_get_image_buffer_size
				(desc, cur_size, stride);
			++cur_offset;
			++cur_size;
		}
	}
	res->backup_size = cur_bo_offset;
	if (metadata->scanout &&
	    metadata->num_sizes == 1 &&
	    metadata->sizes[0].width == 64 &&
	    metadata->sizes[0].height == 64 &&
	    metadata->format == SVGA3D_A8R8G8B8) {

		srf->snooper.image = kzalloc(64 * 64 * 4, GFP_KERNEL);
		if (!srf->snooper.image) {
			(*klpe___drm_err)("Failed to allocate cursor_image\n");
			ret = -ENOMEM;
			goto out_no_copy;
		}
	} else {
		srf->snooper.image = NULL;
	}

	user_srf->prime.base.shareable = false;
	user_srf->prime.base.tfile = NULL;
	if (drm_is_primary_client(file_priv))
		user_srf->master = (*klpe_drm_file_get_master)(file_priv);

	/**
	 * From this point, the generic resource management functions
	 * destroy the object on failure.
	 */

	ret = klpr_vmw_surface_init(dev_priv, srf, (*klpe_vmw_user_surface_free));
	if (unlikely(ret != 0))
		goto out_unlock;

	/*
	 * A gb-aware client referencing a shared surface will
	 * expect a backup buffer to be present.
	 */
	if (dev_priv->has_mob && req->shareable) {
		uint32_t backup_handle;

		ret = (*klpe_vmw_gem_object_create_with_handle)(dev_priv,
							file_priv,
							res->backup_size,
							&backup_handle,
							&res->backup);
		if (unlikely(ret != 0)) {
			(*klpe_vmw_resource_unreference)(&res);
			goto out_unlock;
		}
		vmw_bo_reference(res->backup);
		/*
		 * We don't expose the handle to the userspace and surface
		 * already holds a gem reference
		 */
		(*klpe_drm_gem_handle_delete)(file_priv, backup_handle);
	}

	tmp = (*klpe_vmw_resource_reference)(&srf->res);
	ret = (*klpe_ttm_prime_object_init)(tfile, res->backup_size, &user_srf->prime,
				    req->shareable, VMW_RES_SURFACE,
				    &klpp_vmw_user_surface_base_release);

	if (unlikely(ret != 0)) {
		(*klpe_vmw_resource_unreference)(&tmp);
		(*klpe_vmw_resource_unreference)(&res);
		goto out_unlock;
	}

	rep->sid = user_srf->prime.base.handle;
	(*klpe_vmw_resource_unreference)(&res);

	return 0;
out_no_copy:
	kfree(srf->offsets);
out_no_offsets:
	kfree(metadata->sizes);
out_no_sizes:
	ttm_prime_object_kfree(user_srf, prime);
out_unlock:
	return ret;
}

int
klpp_vmw_gb_surface_define_internal(struct drm_device *dev,
			       struct drm_vmw_gb_surface_create_ext_req *req,
			       struct drm_vmw_gb_surface_create_rep *rep,
			       struct drm_file *file_priv)
{
	struct ttm_object_file *tfile = vmw_fpriv(file_priv)->tfile;
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct vmw_user_surface *user_srf;
	struct vmw_surface_metadata metadata = {0};
	struct vmw_surface *srf;
	struct vmw_resource *res;
	struct vmw_resource *tmp;
	int ret = 0;
	uint32_t backup_handle = 0;
	SVGA3dSurfaceAllFlags svga3d_flags_64 =
		SVGA3D_FLAGS_64(req->svga3d_flags_upper_32_bits,
				req->base.svga3d_flags);

	/* array_size must be null for non-GL3 host. */
	if (req->base.array_size > 0 && !has_sm4_context(dev_priv)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "SM4 surface not supported.\n");
		return -EINVAL;
	}

	if (!has_sm4_1_context(dev_priv)) {
		if (req->svga3d_flags_upper_32_bits != 0)
			ret = -EINVAL;

		if (req->base.multisample_count != 0)
			ret = -EINVAL;

		if (req->multisample_pattern != SVGA3D_MS_PATTERN_NONE)
			ret = -EINVAL;

		if (req->quality_level != SVGA3D_MS_QUALITY_NONE)
			ret = -EINVAL;

		if (ret) {
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "SM4.1 surface not supported.\n");
			return ret;
		}
	}

	if (req->buffer_byte_stride > 0 && !has_sm5_context(dev_priv)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "SM5 surface not supported.\n");
		return -EINVAL;
	}

	if ((svga3d_flags_64 & SVGA3D_SURFACE_MULTISAMPLE) &&
	    req->base.multisample_count == 0) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Invalid sample count.\n");
		return -EINVAL;
	}

	if (req->base.mip_levels > DRM_VMW_MAX_MIP_LEVELS) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Invalid mip level.\n");
		return -EINVAL;
	}

	metadata.flags = svga3d_flags_64;
	metadata.format = req->base.format;
	metadata.mip_levels[0] = req->base.mip_levels;
	metadata.multisample_count = req->base.multisample_count;
	metadata.multisample_pattern = req->multisample_pattern;
	metadata.quality_level = req->quality_level;
	metadata.array_size = req->base.array_size;
	metadata.buffer_byte_stride = req->buffer_byte_stride;
	metadata.num_sizes = 1;
	metadata.base_size = req->base.base_size;
	metadata.scanout = req->base.drm_surface_flags &
		drm_vmw_surface_flag_scanout;

	/* Define a surface based on the parameters. */
	ret = (*klpe_vmw_gb_surface_define)(dev_priv, &metadata, &srf);
	if (ret != 0) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Failed to define surface.\n");
		return ret;
	}

	user_srf = container_of(srf, struct vmw_user_surface, srf);
	if (drm_is_primary_client(file_priv))
		user_srf->master = (*klpe_drm_file_get_master)(file_priv);

	res = &user_srf->srf.res;

	if (req->base.buffer_handle != SVGA3D_INVALID_ID) {
		ret = klpp_vmw_user_bo_lookup(file_priv, req->base.buffer_handle,
					 &res->backup);
		if (ret == 0) {
			if (res->backup->base.base.size < res->backup_size) {
				(*klpe___drm_dbg)(DRM_UT_DRIVER, "Surface backup buffer too small.\n");
				klpr_vmw_bo_unreference(&res->backup);
				ret = -EINVAL;
				goto out_unlock;
			} else {
				backup_handle = req->base.buffer_handle;
			}
		}
	} else if (req->base.drm_surface_flags &
		   (drm_vmw_surface_flag_create_buffer |
		    drm_vmw_surface_flag_coherent)) {
		ret = (*klpe_vmw_gem_object_create_with_handle)(dev_priv, file_priv,
							res->backup_size,
							&backup_handle,
							&res->backup);
		if (ret == 0)
			vmw_bo_reference(res->backup);
	}

	if (unlikely(ret != 0)) {
		(*klpe_vmw_resource_unreference)(&res);
		goto out_unlock;
	}

	if (req->base.drm_surface_flags & drm_vmw_surface_flag_coherent) {
		struct vmw_buffer_object *backup = res->backup;

		ttm_bo_reserve(&backup->base, false, false, NULL);
		if (!res->func->dirty_alloc)
			ret = -EINVAL;
		if (!ret)
			ret = (*klpe_vmw_bo_dirty_add)(backup);
		if (!ret) {
			res->coherent = true;
			ret = res->func->dirty_alloc(res);
		}
		klpr_ttm_bo_unreserve(&backup->base);
		if (ret) {
			(*klpe_vmw_resource_unreference)(&res);
			goto out_unlock;
		}

	}

	tmp = (*klpe_vmw_resource_reference)(res);
	ret = (*klpe_ttm_prime_object_init)(tfile, res->backup_size, &user_srf->prime,
				    req->base.drm_surface_flags &
				    drm_vmw_surface_flag_shareable,
				    VMW_RES_SURFACE,
				    &klpp_vmw_user_surface_base_release);

	if (unlikely(ret != 0)) {
		(*klpe_vmw_resource_unreference)(&tmp);
		(*klpe_vmw_resource_unreference)(&res);
		goto out_unlock;
	}

	rep->handle      = user_srf->prime.base.handle;
	rep->backup_size = res->backup_size;
	if (res->backup) {
		rep->buffer_map_handle =
			drm_vma_node_offset_addr(&res->backup->base.base.vma_node);
		rep->buffer_size = res->backup->base.base.size;
		rep->buffer_handle = backup_handle;
	} else {
		rep->buffer_map_handle = 0;
		rep->buffer_size = 0;
		rep->buffer_handle = SVGA3D_INVALID_ID;
	}
	(*klpe_vmw_resource_unreference)(&res);

out_unlock:
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vmwgfx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__drm_dbg", (void *)&klpe___drm_dbg, "drm" },
	{ "__drm_err", (void *)&klpe___drm_err, "drm" },
	{ "drm_file_get_master", (void *)&klpe_drm_file_get_master, "drm" },
	{ "drm_gem_handle_delete", (void *)&klpe_drm_gem_handle_delete, "drm" },
	{ "drm_gem_object_free", (void *)&klpe_drm_gem_object_free, "drm" },
	{ "ttm_bo_move_to_lru_tail", (void *)&klpe_ttm_bo_move_to_lru_tail,
	  "ttm" },
	{ "ttm_bo_put", (void *)&klpe_ttm_bo_put, "ttm" },
	{ "g_SVGA3dSurfaceDescs", (void *)&klpe_g_SVGA3dSurfaceDescs,
	  "vmwgfx" },
	{ "ttm_prime_object_init", (void *)&klpe_ttm_prime_object_init,
	  "vmwgfx" },
	{ "vmw_bo_dirty_add", (void *)&klpe_vmw_bo_dirty_add, "vmwgfx" },
	{ "vmw_gb_surface_define", (void *)&klpe_vmw_gb_surface_define,
	  "vmwgfx" },
	{ "vmw_gb_surface_func", (void *)&klpe_vmw_gb_surface_func, "vmwgfx" },
	{ "vmw_gem_object_create_with_handle",
	  (void *)&klpe_vmw_gem_object_create_with_handle, "vmwgfx" },
	{ "vmw_hw_surface_destroy", (void *)&klpe_vmw_hw_surface_destroy,
	  "vmwgfx" },
	{ "vmw_legacy_surface_func", (void *)&klpe_vmw_legacy_surface_func,
	  "vmwgfx" },
	{ "vmw_resource_init", (void *)&klpe_vmw_resource_init, "vmwgfx" },
	{ "vmw_resource_reference", (void *)&klpe_vmw_resource_reference,
	  "vmwgfx" },
	{ "vmw_resource_unreference", (void *)&klpe_vmw_resource_unreference,
	  "vmwgfx" },
	{ "vmw_user_surface_free", (void *)&klpe_vmw_user_surface_free,
	  "vmwgfx" },
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

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_surface_init(void)
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

void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_surface_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
