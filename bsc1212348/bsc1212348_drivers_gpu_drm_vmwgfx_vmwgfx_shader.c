/*
 * bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader
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

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_shader.c */
#include <drm/ttm/ttm_placement.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <linux/suspend.h>
#include <linux/sync_file.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/ttm/ttm_bo_driver.h>

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe___drm_dbg)(enum drm_debug_category category, const char *format, ...);

/* klp-ccp: from include/drm/ttm/ttm_bo_api.h */
static void (*klpe_ttm_bo_put)(struct ttm_buffer_object *bo);

struct ttm_validate_buffer;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/ttm_object.h */
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_hashtab.h */
#include <linux/list.h>

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

static int (*klpe_ttm_base_object_init)(struct ttm_object_file *tfile,
				struct ttm_base_object *base,
				bool shareable,
				enum ttm_object_type type,
				void (*refcount_release) (struct ttm_base_object
							  **));

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

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_types.h */
#define SVGA3D_INVALID_ID ((uint32)-1)

typedef enum {
	SVGA3D_SHADERTYPE_INVALID = 0,
	SVGA3D_SHADERTYPE_MIN = 1,
	SVGA3D_SHADERTYPE_VS = 1,
	SVGA3D_SHADERTYPE_PS = 2,
	SVGA3D_SHADERTYPE_PREDX_MAX = 3,
	SVGA3D_SHADERTYPE_GS = 3,
	SVGA3D_SHADERTYPE_DX10_MAX = 4,
	SVGA3D_SHADERTYPE_HS = 4,
	SVGA3D_SHADERTYPE_DS = 5,
	SVGA3D_SHADERTYPE_CS = 6,
	SVGA3D_SHADERTYPE_MAX = 7
} SVGA3dShaderType;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_validation.h */
#include <linux/list.h>
#include <linux/ww_mutex.h>
#include <drm/ttm/ttm_execbuf_util.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/vmwgfx_drm.h>

#define VMW_RES_SHADER ttm_driver_type4

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

static inline struct vmw_private *vmw_priv(struct drm_device *dev)
{
	return (struct vmw_private *)dev->dev_private;
}

static inline struct vmw_fpriv *vmw_fpriv(struct drm_file *file_priv)
{
	return (struct vmw_fpriv *)file_priv->driver_priv;
}

static void (*klpe_vmw_resource_unreference)(struct vmw_resource **p_res);
static struct vmw_resource *(*klpe_vmw_resource_reference)(struct vmw_resource *res);

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

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_shader.c */
struct vmw_shader {
	struct vmw_resource res;
	SVGA3dShaderType type;
	uint32_t size;
	uint8_t num_input_sig;
	uint8_t num_output_sig;
};

struct vmw_user_shader {
	struct ttm_base_object base;
	struct vmw_shader shader;
};

static void (*klpe_vmw_user_shader_free)(struct vmw_resource *res);

static const struct vmw_res_func (*klpe_vmw_gb_shader_func);

static inline struct vmw_shader *
vmw_res_to_shader(struct vmw_resource *res)
{
	return container_of(res, struct vmw_shader, res);
}

static void (*klpe_vmw_hw_shader_destroy)(struct vmw_resource *res);

static int klpr_vmw_gb_shader_init(struct vmw_private *dev_priv,
			      struct vmw_resource *res,
			      uint32_t size,
			      uint64_t offset,
			      SVGA3dShaderType type,
			      uint8_t num_input_sig,
			      uint8_t num_output_sig,
			      struct vmw_buffer_object *byte_code,
			      void (*res_free) (struct vmw_resource *res))
{
	struct vmw_shader *shader = vmw_res_to_shader(res);
	int ret;

	ret = (*klpe_vmw_resource_init)(dev_priv, res, true, res_free,
				&(*klpe_vmw_gb_shader_func));

	if (unlikely(ret != 0)) {
		if (res_free)
			res_free(res);
		else
			kfree(res);
		return ret;
	}

	res->backup_size = size;
	if (byte_code) {
		res->backup = vmw_bo_reference(byte_code);
		res->backup_offset = offset;
	}
	shader->size = size;
	shader->type = type;
	shader->num_input_sig = num_input_sig;
	shader->num_output_sig = num_output_sig;

	res->hw_destroy = (*klpe_vmw_hw_shader_destroy);
	return 0;
}

static void (*klpe_vmw_user_shader_free)(struct vmw_resource *res);

static void (*klpe_vmw_user_shader_base_release)(struct ttm_base_object **p_base);

static int klpr_vmw_user_shader_alloc(struct vmw_private *dev_priv,
				 struct vmw_buffer_object *buffer,
				 size_t shader_size,
				 size_t offset,
				 SVGA3dShaderType shader_type,
				 uint8_t num_input_sig,
				 uint8_t num_output_sig,
				 struct ttm_object_file *tfile,
				 u32 *handle)
{
	struct vmw_user_shader *ushader;
	struct vmw_resource *res, *tmp;
	int ret;

	ushader = kzalloc(sizeof(*ushader), GFP_KERNEL);
	if (unlikely(!ushader)) {
		ret = -ENOMEM;
		goto out;
	}

	res = &ushader->shader.res;
	ushader->base.shareable = false;
	ushader->base.tfile = NULL;

	/*
	 * From here on, the destructor takes over resource freeing.
	 */

	ret = klpr_vmw_gb_shader_init(dev_priv, res, shader_size,
				 offset, shader_type, num_input_sig,
				 num_output_sig, buffer,
				 (*klpe_vmw_user_shader_free));
	if (unlikely(ret != 0))
		goto out;

	tmp = (*klpe_vmw_resource_reference)(res);
	ret = (*klpe_ttm_base_object_init)(tfile, &ushader->base, false,
				   VMW_RES_SHADER,
				   &(*klpe_vmw_user_shader_base_release));

	if (unlikely(ret != 0)) {
		(*klpe_vmw_resource_unreference)(&tmp);
		goto out_err;
	}

	if (handle)
		*handle = ushader->base.handle;
out_err:
	(*klpe_vmw_resource_unreference)(&res);
out:
	return ret;
}

static int klpp_vmw_shader_define(struct drm_device *dev, struct drm_file *file_priv,
			     enum drm_vmw_shader_type shader_type_drm,
			     u32 buffer_handle, size_t size, size_t offset,
			     uint8_t num_input_sig, uint8_t num_output_sig,
			     uint32_t *shader_handle)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct ttm_object_file *tfile = vmw_fpriv(file_priv)->tfile;
	struct vmw_buffer_object *buffer = NULL;
	SVGA3dShaderType shader_type;
	int ret;

	if (buffer_handle != SVGA3D_INVALID_ID) {
		ret = klpp_vmw_user_bo_lookup(file_priv, buffer_handle, &buffer);
		if (unlikely(ret != 0)) {
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Couldn't find buffer for shader creation.\n");
			return ret;
		}

		if ((u64)buffer->base.base.size < (u64)size + (u64)offset) {
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Illegal buffer- or shader size.\n");
			ret = -EINVAL;
			goto out_bad_arg;
		}
	}

	switch (shader_type_drm) {
	case drm_vmw_shader_type_vs:
		shader_type = SVGA3D_SHADERTYPE_VS;
		break;
	case drm_vmw_shader_type_ps:
		shader_type = SVGA3D_SHADERTYPE_PS;
		break;
	default:
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Illegal shader type.\n");
		ret = -EINVAL;
		goto out_bad_arg;
	}

	ret = klpr_vmw_user_shader_alloc(dev_priv, buffer, size, offset,
				    shader_type, num_input_sig,
				    num_output_sig, tfile, shader_handle);
out_bad_arg:
	klpr_vmw_bo_unreference(&buffer);
	klpr_drm_gem_object_put(&buffer->base.base);
	return ret;
}

int klpp_vmw_shader_define_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv)
{
	struct drm_vmw_shader_create_arg *arg =
		(struct drm_vmw_shader_create_arg *)data;

	return klpp_vmw_shader_define(dev, file_priv, arg->shader_type,
				 arg->buffer_handle,
				 arg->size, arg->offset,
				 0, 0,
				 &arg->shader_handle);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vmwgfx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__drm_dbg", (void *)&klpe___drm_dbg, "drm" },
	{ "ttm_bo_put", (void *)&klpe_ttm_bo_put, "ttm" },
	{ "ttm_base_object_init", (void *)&klpe_ttm_base_object_init,
	  "vmwgfx" },
	{ "vmw_gb_shader_func", (void *)&klpe_vmw_gb_shader_func, "vmwgfx" },
	{ "vmw_hw_shader_destroy", (void *)&klpe_vmw_hw_shader_destroy,
	  "vmwgfx" },
	{ "vmw_resource_init", (void *)&klpe_vmw_resource_init, "vmwgfx" },
	{ "vmw_resource_reference", (void *)&klpe_vmw_resource_reference,
	  "vmwgfx" },
	{ "vmw_resource_unreference", (void *)&klpe_vmw_resource_unreference,
	  "vmwgfx" },
	{ "vmw_user_shader_base_release",
	  (void *)&klpe_vmw_user_shader_base_release, "vmwgfx" },
	{ "vmw_user_shader_free", (void *)&klpe_vmw_user_shader_free,
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

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader_init(void)
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

void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
