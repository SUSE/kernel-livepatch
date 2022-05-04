/*
 * bsc1195950_i915_gem
 *
 * Fix for CVE-2022-0330, bsc#1195950 (drivers/gpu/drm/i915/i915_gem.c part)
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

#if IS_ENABLED(CONFIG_DRM_I915)

#if !IS_MODULE(CONFIG_DRM_I915)
#error "Live patch supports only CONFIG_DRM_I915=m"
#endif

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem.c */
#include <drm/drmP.h>
#include <drm/drm_vma_manager.h>
#include <drm/i915_drm.h>

#include "bsc1195950_common.h"

/* from include/drm/drm_print.h */
static
void (*klpe_drm_dev_printk)(const struct device *dev, const char *level,
		    const char *format, ...);

#define KLPR_DRM_DEV_ERROR(dev, fmt, ...)					\
	(*klpe_drm_dev_printk)(dev, KERN_ERR, "*ERROR* " fmt, ##__VA_ARGS__)

#define KLPR_DRM_DEV_ERROR_RATELIMITED(dev, fmt, ...)			\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		KLPR_DRM_DEV_ERROR(dev, fmt, ##__VA_ARGS__);			\
})

#define KLPR_DRM_ERROR_RATELIMITED(fmt, ...)					\
	KLPR_DRM_DEV_ERROR_RATELIMITED(NULL, fmt, ##__VA_ARGS__)

/* klp-ccp: from drivers/gpu/drm/i915/intel_uncore.h */
static void (*klpe_intel_uncore_forcewake_get)(struct drm_i915_private *dev_priv,
				enum forcewake_domains domains);
static void (*klpe_intel_uncore_forcewake_put)(struct drm_i915_private *dev_priv,
				enum forcewake_domains domains);
static int (*klpe___intel_wait_for_register_fw)(struct drm_i915_private *dev_priv,
				 i915_reg_t reg,
				 u32 mask,
				 u32 value,
				 unsigned int fast_timeout_us,
				 unsigned int slow_timeout_ms,
				 u32 *out_value);

/* klp-ccp: from driver/gpu/drm/i915/i915_drv.h */
static bool (*klpe_intel_runtime_pm_get_if_in_use)(struct drm_i915_private *dev_priv);

static void (*klpe_intel_runtime_pm_put)(struct drm_i915_private *dev_priv);

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem.c */
#include <linux/kthread.h>
#include <linux/reservation.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/pci.h>

static struct sg_table *
(*klpe___i915_gem_object_unset_pages)(struct drm_i915_gem_object *obj);

/* New. */
static struct mutex *klpp_tlb_invalidate_lock;

/* New. */
struct reg_and_bit {
	i915_reg_t reg;
	u32 bit;
};

/* New. */
static struct reg_and_bit
klpp_get_reg_and_bit(const struct intel_engine_cs *engine,
		const i915_reg_t *regs, const unsigned int num)
{
	const unsigned int class = engine->class;
	struct reg_and_bit rb = { .bit = 1 };

	if (WARN_ON_ONCE(class >= num || !regs[class].reg))
		return rb;

	rb.reg = regs[class];
	if (class == VIDEO_DECODE_CLASS)
		rb.reg.reg += 4 * engine->instance; /* GEN8_M2TCR */

	return rb;
}

static void klpp_invalidate_tlbs(struct drm_i915_private *dev_priv)
{
	static const i915_reg_t gen8_regs[] = {
		[RENDER_CLASS]                  = KLPP_GEN8_RTCR,
		[VIDEO_DECODE_CLASS]            = KLPP_GEN8_M1TCR, /* , GEN8_M2TCR */
		[VIDEO_ENHANCEMENT_CLASS]       = KLPP_GEN8_VTCR,
		[COPY_ENGINE_CLASS]             = KLPP_GEN8_BTCR,
	};
	const unsigned int num = ARRAY_SIZE(gen8_regs);
	const i915_reg_t *regs = gen8_regs;
	struct intel_engine_cs *engine;
	enum intel_engine_id id;

	if (INTEL_GEN(dev_priv) < 8)
		return;

	assert_rpm_wakelock_held(dev_priv);

	mutex_lock(klpp_tlb_invalidate_lock);
	(*klpe_intel_uncore_forcewake_get)(dev_priv, FORCEWAKE_ALL);

	for_each_engine(engine, dev_priv, id) {
		/*
		 * HW architecture suggest typical invalidation time at 40us,
		 * with pessimistic cases up to 100us and a recommendation to
		 * cap at 1ms. We go a bit higher just in case.
		 */
		const unsigned int timeout_us = 100;
		const unsigned int timeout_ms = 4;
		struct reg_and_bit rb;

		rb = klpp_get_reg_and_bit(engine, regs, num);
		if (!i915_mmio_reg_offset(rb.reg))
			continue;

		I915_WRITE_FW(rb.reg, rb.bit);
		if ((*klpe___intel_wait_for_register_fw)(dev_priv,
						 rb.reg, rb.bit, 0,
						 timeout_us, timeout_ms,
						 NULL))
			KLPR_DRM_ERROR_RATELIMITED("%s TLB invalidation did not complete in %ums!\n",
					      engine->name, timeout_ms);
	}

	(*klpe_intel_uncore_forcewake_put)(dev_priv, FORCEWAKE_ALL);
	mutex_unlock(klpp_tlb_invalidate_lock);
}

void klpp___i915_gem_object_put_pages(struct drm_i915_gem_object *obj,
				 enum i915_mm_subclass subclass)
{
	struct sg_table *pages;

	if (i915_gem_object_has_pinned_pages(obj))
		return;

	GEM_BUG_ON(obj->bind_count);
	if (!i915_gem_object_has_pages(obj))
		return;

	/* May be called by shrinker from within get_pages() (on another bo) */
	mutex_lock_nested(&obj->mm.lock, subclass);
	if (unlikely(atomic_read(&obj->mm.pages_pin_count)))
		goto unlock;

	/*
	 * ->put_pages might need to allocate memory for the bit17 swizzle
	 * array, hence protect them from being reaped by removing them from gtt
	 * lists early.
	 */
	pages = (*klpe___i915_gem_object_unset_pages)(obj);
	/*
	 * Fix CVE-2022-0330
	 *  -2 lines, +12 lines
	 */
	if (!IS_ERR(pages)) {
		if (test_and_clear_bit(KLPP_I915_BO_WAS_BOUND_BIT, &obj->flags)) {
			struct drm_i915_private *i915 = to_i915(obj->base.dev);

			if ((*klpe_intel_runtime_pm_get_if_in_use)(i915)) {
				klpp_invalidate_tlbs(i915);
				(*klpe_intel_runtime_pm_put)(i915);
			}
		}

		obj->ops->put_pages(obj, pages);
	}

unlock:
	mutex_unlock(&obj->mm.lock);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/livepatch.h>
#include "livepatch_bsc1195950.h"
#include "../kallsyms_relocs.h"
#include "../shadow.h"

struct klp_bsc1195950_shared_state
{
	unsigned long refcount;
	struct mutex tlb_invalidate_lock;
};

static struct klp_bsc1195950_shared_state *klp_bsc1195950_shared_state;

#define KLP_BSC1195950_SHARED_STATE_ID KLP_SHADOW_ID(1195950, 0)

static int klp_bsc1195950_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	struct klp_bsc1195950_shared_state *s = shadow_data;

	memset(s, 0, sizeof(*s));
	mutex_init(&s->tlb_invalidate_lock);

	return 0;
}

/* Must be called with module_mutex held. */
static int __klp_bsc1195950_get_shared_state(void)
{
	klp_bsc1195950_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1195950_SHARED_STATE_ID,
					sizeof(*klp_bsc1195950_shared_state),
					GFP_KERNEL,
					klp_bsc1195950_init_shared_state, NULL);
	if (!klp_bsc1195950_shared_state)
		return -ENOMEM;

	++klp_bsc1195950_shared_state->refcount;

	klpp_tlb_invalidate_lock =
		&klp_bsc1195950_shared_state->tlb_invalidate_lock;

	return 0;
}

/* Must be called with module_mutex held. */
static void __klp_bsc1195950_put_shared_state(void)
{
	--klp_bsc1195950_shared_state->refcount;

	if (!klp_bsc1195950_shared_state->refcount) {
		mutex_destroy(&klp_bsc1195950_shared_state->tlb_invalidate_lock);
		klp_shadow_free(NULL, KLP_BSC1195950_SHARED_STATE_ID, NULL);
	}

	klp_bsc1195950_shared_state = NULL;
}

#define LIVEPATCHED_MODULE "i915"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_dev_printk", (void *)&klpe_drm_dev_printk, "drm" },
	{ "__i915_gem_object_unset_pages",
	  (void *)&klpe___i915_gem_object_unset_pages, "i915" },
	{ "__intel_wait_for_register_fw",
	  (void *)&klpe___intel_wait_for_register_fw, "i915" },
	{ "intel_runtime_pm_get_if_in_use",
	  (void *)&klpe_intel_runtime_pm_get_if_in_use, "i915" },
	{ "intel_runtime_pm_put",
	  (void *)&klpe_intel_runtime_pm_put, "i915" },
	{ "intel_uncore_forcewake_get",
	  (void *)&klpe_intel_uncore_forcewake_get, "i915" },
	{ "intel_uncore_forcewake_put",
	  (void *)&klpe_intel_uncore_forcewake_put, "i915" },
};

static int livepatch_bsc1195950_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1195950_module_nb = {
	.notifier_call = livepatch_bsc1195950_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1195950_i915_gem_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	ret = __klp_bsc1195950_get_shared_state();
	if (ret)
		goto out;
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret) {
			__klp_bsc1195950_put_shared_state();
			goto out;
		}
	}

	ret = register_module_notifier(&livepatch_bsc1195950_module_nb);
	if (ret)
		__klp_bsc1195950_put_shared_state();
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1195950_i915_gem_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1195950_module_nb);
	mutex_lock(&module_mutex);
	__klp_bsc1195950_put_shared_state();
	mutex_unlock(&module_mutex);
}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
