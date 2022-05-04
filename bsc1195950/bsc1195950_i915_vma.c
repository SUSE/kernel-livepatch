/*
 * bsc1195950_i915_vma
 *
 * Fix for CVE-2022-0330, bsc#1195950 (drivers/gpu/drm/i915/i915_vma.c part)
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

#include <linux/tracepoint.h>

/* from include/linux/tracepoint.h */
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static struct tracepoint (*klpe___tracepoint_##name);		\
	static inline void klpr_trace_##name(proto)			\
	{								\
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key))) \
			__DO_TRACE(&(*klpe___tracepoint_##name),	\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond), 0);		\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs); \
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\

#define KLPR_DECLARE_TRACE(name, proto, args)				\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KLPR_TRACE_EVENT(name, proto, args)	\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma.c */
#include "bsc1195950_common.h"

/* klp-ccp: from drivers/gpu/drm/i915/i915_trace.h */
KLPR_TRACE_EVENT(i915_vma_bind,
	    TP_PROTO(struct i915_vma *vma, unsigned flags),
	    TP_ARGS(vma, flags)
);

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma.c */
#include <drm/drm_gem.h>

int klpp_i915_vma_bind(struct i915_vma *vma, enum i915_cache_level cache_level,
		  u32 flags)
{
	u32 bind_flags;
	u32 vma_flags;
	int ret;

	GEM_BUG_ON(!drm_mm_node_allocated(&vma->node));
	GEM_BUG_ON(vma->size > vma->node.size);

	if (GEM_WARN_ON(range_overflows(vma->node.start,
					vma->node.size,
					vma->vm->total)))
		return -ENODEV;

	if (GEM_WARN_ON(!flags))
		return -EINVAL;

	bind_flags = 0;
	if (flags & PIN_GLOBAL)
		bind_flags |= I915_VMA_GLOBAL_BIND;
	if (flags & PIN_USER)
		bind_flags |= I915_VMA_LOCAL_BIND;

	vma_flags = vma->flags & (I915_VMA_GLOBAL_BIND | I915_VMA_LOCAL_BIND);
	if (flags & PIN_UPDATE)
		bind_flags |= vma_flags;
	else
		bind_flags &= ~vma_flags;
	if (bind_flags == 0)
		return 0;

	GEM_BUG_ON(!vma->pages);

	klpr_trace_i915_vma_bind(vma, bind_flags);
	ret = vma->ops->bind_vma(vma, cache_level, bind_flags);
	if (ret)
		return ret;

	vma->flags |= bind_flags;

	/*
	 * Fix CVE-2022-0330
	 *  +2 lines
	 */
	if (vma->obj)
		set_bit(KLPP_I915_BO_WAS_BOUND_BIT, &vma->obj->flags);

	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1195950.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "i915"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__tracepoint_i915_vma_bind",
	  (void *)&klpe___tracepoint_i915_vma_bind, "i915" },
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

int livepatch_bsc1195950_i915_vma_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1195950_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1195950_i915_vma_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1195950_module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
