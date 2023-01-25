/*
 * bsc1204167_drivers_misc_sgi_gru_grumain
 *
 * Fix for CVE-2022-3424, bsc#1204167
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

#if IS_ENABLED(CONFIG_SGI_GRU)

#if !IS_MODULE(CONFIG_SGI_GRU)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/misc/sgi-gru/grumain.c */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/err.h>
#include <asm/uv/uv_hub.h>

#include "gru.h"

/* klp-ccp: from arch/x86/include/asm/cacheflush.h */
#define _ASM_X86_CACHEFLUSH_H

/* klp-ccp: from drivers/misc/sgi-gru/grutables.h */
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/wait.h>

/* klp-ccp: from drivers/misc/sgi-gru/gru_instructions.h */
#if defined(CONFIG_IA64)
#error "klp-ccp: non-taken branch"
#elif defined(CONFIG_X86_64)
#include <asm/cacheflush.h>

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from drivers/misc/sgi-gru/grutables.h */
static struct gru_stats_s (*klpe_gru_stats);

#define GRU_ASSIGN_DELAY	((HZ * 20) / 1000)

#define GRU_STEAL_DELAY		((HZ * 200) / 1000)

#define gseg_physical_address(gru, ctxnum)				\
		((gru)->gs_gru_base_paddr + ctxnum * GRU_GSEG_STRIDE)

static struct gru_thread_state *(*klpe_gru_find_thread_state)(struct vm_area_struct
				*vma, int tsid);

static struct gru_state *(*klpe_gru_assign_gru_context)(struct gru_thread_state *gts);
static void (*klpe_gru_load_context)(struct gru_thread_state *gts);
static void (*klpe_gru_steal_context)(struct gru_thread_state *gts);
static void (*klpe_gru_unload_context)(struct gru_thread_state *gts, int savestate);
static int (*klpe_gru_update_cch)(struct gru_thread_state *gts);

static int (*klpe_gru_cpu_fault_map_id)(void);

static unsigned long (*klpe_gru_options);

static int klpr_gru_retarget_intr(struct gru_thread_state *gts)
{
	if (gts->ts_tlb_int_select < 0
	    || gts->ts_tlb_int_select == (*klpe_gru_cpu_fault_map_id)())
		return 0;

	gru_dbg(grudev, "retarget from %d to %d\n", gts->ts_tlb_int_select,
		gru_cpu_fault_map_id());
	return (*klpe_gru_update_cch)(gts);
}

static int gru_check_chiplet_assignment(struct gru_state *gru,
					struct gru_thread_state *gts)
{
	int blade_id;
	int chiplet_id;

	blade_id = gts->ts_user_blade_id;
	if (blade_id < 0)
		blade_id = uv_numa_blade_id();

	chiplet_id = gts->ts_user_chiplet_id;
	return gru->gs_blade_id == blade_id &&
		(chiplet_id < 0 || chiplet_id == gru->gs_chiplet_id);
}

int klpp_gru_check_context_placement(struct gru_thread_state *gts)
{
	struct gru_state *gru;
	int ret = 0;

	/*
	 * If the current task is the context owner, verify that the
	 * context is correctly placed. This test is skipped for non-owner
	 * references. Pthread apps use non-owner references to the CBRs.
	 */
	gru = gts->ts_gru;
	if (!gru || gts->ts_tgid_owner != current->tgid)
		return ret;

	if (!gru_check_chiplet_assignment(gru, gts)) {
		KLPR_STAT(check_context_unload);
		ret = -EINVAL;
	} else if (klpr_gru_retarget_intr(gts)) {
		KLPR_STAT(check_context_retarget_intr);
	}

	return ret;
}

int klpp_gru_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct gru_thread_state *gts;
	unsigned long paddr, vaddr;
	unsigned long expires;

	vaddr = vmf->address;
	gru_dbg(grudev, "vma %p, vaddr 0x%lx (0x%lx)\n",
		vma, vaddr, GSEG_BASE(vaddr));
	KLPR_STAT(nopfn);

	/* The following check ensures vaddr is a valid address in the VMA */
	gts = (*klpe_gru_find_thread_state)(vma, TSID(vaddr, vma));
	if (!gts)
		return VM_FAULT_SIGBUS;

again:
	mutex_lock(&gts->ts_ctxlock);
	preempt_disable();

	if (klpp_gru_check_context_placement(gts)) {
		preempt_enable();
		mutex_unlock(&gts->ts_ctxlock);
		(*klpe_gru_unload_context)(gts, 1);
		return VM_FAULT_NOPAGE;
	}

	if (!gts->ts_gru) {
		KLPR_STAT(load_user_context);
		if (!(*klpe_gru_assign_gru_context)(gts)) {
			preempt_enable();
			mutex_unlock(&gts->ts_ctxlock);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(GRU_ASSIGN_DELAY);  /* true hack ZZZ */
			expires = gts->ts_steal_jiffies + GRU_STEAL_DELAY;
			if (time_before(expires, jiffies))
				(*klpe_gru_steal_context)(gts);
			goto again;
		}
		(*klpe_gru_load_context)(gts);
		paddr = gseg_physical_address(gts->ts_gru, gts->ts_ctxnum);
		remap_pfn_range(vma, vaddr & ~(GRU_GSEG_PAGESIZE - 1),
				paddr >> PAGE_SHIFT, GRU_GSEG_PAGESIZE,
				vma->vm_page_prot);
	}

	preempt_enable();
	mutex_unlock(&gts->ts_ctxlock);

	return VM_FAULT_NOPAGE;
}



#define LP_MODULE "gru"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1204167.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "gru_assign_gru_context", (void *)&klpe_gru_assign_gru_context,
	  "gru" },
	{ "gru_cpu_fault_map_id", (void *)&klpe_gru_cpu_fault_map_id, "gru" },
	{ "gru_find_thread_state", (void *)&klpe_gru_find_thread_state,
	  "gru" },
	{ "gru_load_context", (void *)&klpe_gru_load_context, "gru" },
	{ "gru_options", (void *)&klpe_gru_options, "gru" },
	{ "gru_stats", (void *)&klpe_gru_stats, "gru" },
	{ "gru_steal_context", (void *)&klpe_gru_steal_context, "gru" },
	{ "gru_unload_context", (void *)&klpe_gru_unload_context, "gru" },
	{ "gru_update_cch", (void *)&klpe_gru_update_cch, "gru" },
};

static int bsc1204167_drivers_misc_sgi_gru_grumain_module_notify(struct notifier_block *nb,
					unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = bsc1204167_drivers_misc_sgi_gru_grumain_module_notify,
	.priority = INT_MIN+1,
};

int bsc1204167_drivers_misc_sgi_gru_grumain_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1204167_drivers_misc_sgi_gru_grumain_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SGI_GRU) */
