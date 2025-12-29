/*
 * livepatch_bsc1235815
 *
 * Fix for CVE-2024-57849, bsc#1235815
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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

#if defined(CONFIG_S390)

#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/perf_event.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <asm/cpu_mf.h>
#include <asm/irq.h>
#include <asm/debug.h>
#include <asm/timex.h>

struct sf_buffer {
	unsigned long	 *sdbt;	    /* Sample-data-block-table origin */
	/* buffer characteristics (required for buffer increments) */
	unsigned long  num_sdb;	    /* Number of sample-data-blocks */
	unsigned long num_sdbt;	    /* Number of sample-data-block-tables */
	unsigned long	 *tail;	    /* last sample-data-block-table */
};

struct cpu_hw_sf {
	/* CPU-measurement sampling information block */
	struct hws_qsi_info_block qsi;
	/* CPU-measurement sampling control block */
	struct hws_lsctl_request_block lsctl;
	struct sf_buffer sfb;	    /* Sampling buffer */
	unsigned int flags;	    /* Status flags */
	struct perf_event *event;   /* Scheduled perf event */
	struct perf_output_handle handle; /* AUX buffer output handle */
};

static struct cpu_hw_sf __percpu (*klpe_cpu_hw_sf);
static void (*klpe_perf_pmu_disable)(struct pmu *pmu);
static void (*klpe_perf_pmu_enable)(struct pmu *pmu);
static void (*klpe_hw_perf_event_update)(struct perf_event *event, int flush_all);

void klpp_cpumsf_pmu_stop(struct perf_event *event, int flags)
{
	struct cpu_hw_sf *cpuhw = this_cpu_ptr(klpe_cpu_hw_sf);

	if (event->hw.state & PERF_HES_STOPPED)
		return;

	(*klpe_perf_pmu_disable)(event->pmu);
	cpuhw->lsctl.cs = 0;
	cpuhw->lsctl.cd = 0;
	event->hw.state |= PERF_HES_STOPPED;

	if ((flags & PERF_EF_UPDATE) && !(event->hw.state & PERF_HES_UPTODATE)) {
		/* CPU hotplug off removes SDBs. No samples to extract. */
		if (cpuhw->flags & PMU_F_RESERVED)
			(*klpe_hw_perf_event_update)(event, 1);
		event->hw.state |= PERF_HES_UPTODATE;
	}
	(*klpe_perf_pmu_enable)(event->pmu);
}

#include "livepatch_bsc1235815.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "perf_pmu_disable", (void *)&klpe_perf_pmu_disable },
	{ "perf_pmu_enable", (void *)&klpe_perf_pmu_enable },
	{ "hw_perf_event_update", (void *)&klpe_hw_perf_event_update },
	{ "cpu_hw_sf", (void *)&klpe_cpu_hw_sf },
};

int livepatch_bsc1235815_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif
