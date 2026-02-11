/*
 * livepatch_bsc1249480
 *
 * Fix for CVE-2025-39742, bsc#1249480
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

#if IS_ENABLED(CONFIG_INFINIBAND_HFI1)

#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/completion.h>
#include <linux/kref.h>
#include <linux/sched.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/hfi.h */
#include <linux/xarray.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/opfn.h */
#include <linux/workqueue.h>
#include <rdma/ib_verbs.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/verbs.h */
#include <linux/types.h>
#include <linux/seqlock.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/kref.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_hdrs.h>
#include <rdma/rdma_vt.h>
#include <rdma/rdmavt_qp.h>
#include <rdma/rdmavt_cq.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/iowait.h */
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/sched.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/affinity.h */
struct cpu_mask_set {
	struct cpumask mask;
	struct cpumask used;
	uint gen;
};

struct hfi1_affinity_node {
	int node;
	u16 __percpu *comp_vect_affinity;
	struct cpu_mask_set def_intr;
	struct cpu_mask_set rcv_intr;
	struct cpumask general_intr_mask;
	struct cpumask comp_vect_mask;
	struct list_head list;
};

struct hfi1_affinity_node_list {
	struct list_head list;
	struct cpumask real_cpu_mask;
	struct cpu_mask_set proc;
	int num_core_siblings;
	int num_possible_nodes;
	int num_online_nodes;
	int num_online_cpus;
	struct mutex lock; /* protects affinity nodes */
};

extern struct hfi1_affinity_node_list node_affinity;

/* klp-ccp: from drivers/infiniband/hw/hfi1/trace_dbg.h */
#if !defined(__HFI1_TRACE_EXTRA_H) || defined(TRACE_HEADER_MULTI_READ)
/* klp-ccp: from drivers/infiniband/hw/hfi1/trace_dbg.h */
void __attribute__((__format__(printf, 2, 3))) __hfi1_trace_PROC(const char *funct, char *fmt, ...);

#define hfi1_cdbg(which, fmt, ...) \
	__hfi1_trace_##which(__func__, fmt, ##__VA_ARGS__)

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __HFI1_TRACE_EXTRA_H */

/* klp-ccp: from drivers/infiniband/hw/hfi1/affinity.c */
extern struct hfi1_affinity_node_list node_affinity;

extern void _cpu_mask_set_gen_inc(struct cpu_mask_set *set);

static struct hfi1_affinity_node *node_affinity_lookup(int node)
{
	struct hfi1_affinity_node *entry;

	list_for_each_entry(entry, &node_affinity.list, list) {
		if (entry->node == node)
			return entry;
	}

	return NULL;
}

static void find_hw_thread_mask(uint hw_thread_no, cpumask_var_t hw_thread_mask,
				struct hfi1_affinity_node_list *affinity)
{
	int possible, curr_cpu, i;
	uint num_cores_per_socket;

	cpumask_copy(hw_thread_mask, &affinity->proc.mask);

	if (affinity->num_core_siblings == 0)
		return;

	num_cores_per_socket = node_affinity.num_online_cpus /
					affinity->num_core_siblings /
						node_affinity.num_online_nodes;

	/* Removing other siblings not needed for now */
	possible = cpumask_weight(hw_thread_mask);
	curr_cpu = cpumask_first(hw_thread_mask);
	for (i = 0;
	     i < num_cores_per_socket * node_affinity.num_online_nodes;
	     i++)
		curr_cpu = cpumask_next(curr_cpu, hw_thread_mask);

	for (; i < possible; i++) {
		cpumask_clear_cpu(curr_cpu, hw_thread_mask);
		curr_cpu = cpumask_next(curr_cpu, hw_thread_mask);
	}

	/* Identifying correct HW threads within physical cores */
	cpumask_shift_left(hw_thread_mask, hw_thread_mask,
			   num_cores_per_socket *
			   node_affinity.num_online_nodes *
			   hw_thread_no);
}

#include "livepatch_bsc1249480.h"

int klpp_hfi1_get_proc_affinity(int node)
{
	int cpu = -1, ret, i;
	struct hfi1_affinity_node *entry;
	cpumask_var_t diff, hw_thread_mask, available_mask, intrs_mask;
	const struct cpumask *node_mask,
		*proc_mask = current->cpus_ptr;
	struct hfi1_affinity_node_list *affinity = &node_affinity;
	struct cpu_mask_set *set = &affinity->proc;

	/*
	 * check whether process/context affinity has already
	 * been set
	 */
	if (current->nr_cpus_allowed == 1) {
		hfi1_cdbg(PROC, "PID %u %s affinity set to CPU %*pbl",
			  current->pid, current->comm,
			  cpumask_pr_args(proc_mask));
		/*
		 * Mark the pre-set CPU as used. This is atomic so we don't
		 * need the lock
		 */
		cpu = cpumask_first(proc_mask);
		cpumask_set_cpu(cpu, &set->used);
		goto done;
	} else if (current->nr_cpus_allowed < cpumask_weight(&set->mask)) {
		hfi1_cdbg(PROC, "PID %u %s affinity set to CPU set(s) %*pbl",
			  current->pid, current->comm,
			  cpumask_pr_args(proc_mask));
		goto done;
	}

	/*
	 * The process does not have a preset CPU affinity so find one to
	 * recommend using the following algorithm:
	 *
	 * For each user process that is opening a context on HFI Y:
	 *  a) If all cores are filled, reinitialize the bitmask
	 *  b) Fill real cores first, then HT cores (First set of HT
	 *     cores on all physical cores, then second set of HT core,
	 *     and, so on) in the following order:
	 *
	 *     1. Same NUMA node as HFI Y and not running an IRQ
	 *        handler
	 *     2. Same NUMA node as HFI Y and running an IRQ handler
	 *     3. Different NUMA node to HFI Y and not running an IRQ
	 *        handler
	 *     4. Different NUMA node to HFI Y and running an IRQ
	 *        handler
	 *  c) Mark core as filled in the bitmask. As user processes are
	 *     done, clear cores from the bitmask.
	 */

	ret = zalloc_cpumask_var(&diff, GFP_KERNEL);
	if (!ret)
		goto done;
	ret = zalloc_cpumask_var(&hw_thread_mask, GFP_KERNEL);
	if (!ret)
		goto free_diff;
	ret = zalloc_cpumask_var(&available_mask, GFP_KERNEL);
	if (!ret)
		goto free_hw_thread_mask;
	ret = zalloc_cpumask_var(&intrs_mask, GFP_KERNEL);
	if (!ret)
		goto free_available_mask;

	mutex_lock(&affinity->lock);
	/*
	 * If we've used all available HW threads, clear the mask and start
	 * overloading.
	 */
	_cpu_mask_set_gen_inc(set);

	/*
	 * If NUMA node has CPUs used by interrupt handlers, include them in the
	 * interrupt handler mask.
	 */
	entry = node_affinity_lookup(node);
	if (entry) {
		cpumask_copy(intrs_mask, (entry->def_intr.gen ?
					  &entry->def_intr.mask :
					  &entry->def_intr.used));
		cpumask_or(intrs_mask, intrs_mask, (entry->rcv_intr.gen ?
						    &entry->rcv_intr.mask :
						    &entry->rcv_intr.used));
		cpumask_or(intrs_mask, intrs_mask, &entry->general_intr_mask);
	}
	hfi1_cdbg(PROC, "CPUs used by interrupts: %*pbl",
		  cpumask_pr_args(intrs_mask));

	cpumask_copy(hw_thread_mask, &set->mask);

	/*
	 * If HT cores are enabled, identify which HW threads within the
	 * physical cores should be used.
	 */
	if (affinity->num_core_siblings > 0) {
		for (i = 0; i < affinity->num_core_siblings; i++) {
			find_hw_thread_mask(i, hw_thread_mask, affinity);

			/*
			 * If there's at least one available core for this HW
			 * thread number, stop looking for a core.
			 *
			 * diff will always be not empty at least once in this
			 * loop as the used mask gets reset when
			 * (set->mask == set->used) before this loop.
			 */
			cpumask_andnot(diff, hw_thread_mask, &set->used);
			if (!cpumask_empty(diff))
				break;
		}
	}
	hfi1_cdbg(PROC, "Same available HW thread on all physical CPUs: %*pbl",
		  cpumask_pr_args(hw_thread_mask));

	node_mask = cpumask_of_node(node);
	hfi1_cdbg(PROC, "Device on NUMA %u, CPUs %*pbl", node,
		  cpumask_pr_args(node_mask));

	/* Get cpumask of available CPUs on preferred NUMA */
	cpumask_and(available_mask, hw_thread_mask, node_mask);
	cpumask_andnot(available_mask, available_mask, &set->used);
	hfi1_cdbg(PROC, "Available CPUs on NUMA %u: %*pbl", node,
		  cpumask_pr_args(available_mask));

	/*
	 * At first, we don't want to place processes on the same
	 * CPUs as interrupt handlers. Then, CPUs running interrupt
	 * handlers are used.
	 *
	 * 1) If diff is not empty, then there are CPUs not running
	 *    non-interrupt handlers available, so diff gets copied
	 *    over to available_mask.
	 * 2) If diff is empty, then all CPUs not running interrupt
	 *    handlers are taken, so available_mask contains all
	 *    available CPUs running interrupt handlers.
	 * 3) If available_mask is empty, then all CPUs on the
	 *    preferred NUMA node are taken, so other NUMA nodes are
	 *    used for process assignments using the same method as
	 *    the preferred NUMA node.
	 */
	cpumask_andnot(diff, available_mask, intrs_mask);
	if (!cpumask_empty(diff))
		cpumask_copy(available_mask, diff);

	/* If we don't have CPUs on the preferred node, use other NUMA nodes */
	if (cpumask_empty(available_mask)) {
		cpumask_andnot(available_mask, hw_thread_mask, &set->used);
		/* Excluding preferred NUMA cores */
		cpumask_andnot(available_mask, available_mask, node_mask);
		hfi1_cdbg(PROC,
			  "Preferred NUMA node cores are taken, cores available in other NUMA nodes: %*pbl",
			  cpumask_pr_args(available_mask));

		/*
		 * At first, we don't want to place processes on the same
		 * CPUs as interrupt handlers.
		 */
		cpumask_andnot(diff, available_mask, intrs_mask);
		if (!cpumask_empty(diff))
			cpumask_copy(available_mask, diff);
	}
	hfi1_cdbg(PROC, "Possible CPUs for process: %*pbl",
		  cpumask_pr_args(available_mask));

	cpu = cpumask_first(available_mask);
	if (cpu >= nr_cpu_ids) /* empty */
		cpu = -1;
	else
		cpumask_set_cpu(cpu, &set->used);

	mutex_unlock(&affinity->lock);
	hfi1_cdbg(PROC, "Process assigned to CPU %d", cpu);

	free_cpumask_var(intrs_mask);
free_available_mask:
	free_cpumask_var(available_mask);
free_hw_thread_mask:
	free_cpumask_var(hw_thread_mask);
free_diff:
	free_cpumask_var(diff);
done:
	return cpu;
}

#include <linux/livepatch.h>

extern typeof(__hfi1_trace_PROC) __hfi1_trace_PROC
	 KLP_RELOC_SYMBOL(hfi1, hfi1, __hfi1_trace_PROC);
extern typeof(_cpu_mask_set_gen_inc) _cpu_mask_set_gen_inc
	 KLP_RELOC_SYMBOL(hfi1, hfi1, _cpu_mask_set_gen_inc);
extern typeof(node_affinity) node_affinity
	 KLP_RELOC_SYMBOL(hfi1, hfi1, node_affinity);

#endif /* IS_ENABLED(CONFIG_INFINIBAND_HFI1) */
