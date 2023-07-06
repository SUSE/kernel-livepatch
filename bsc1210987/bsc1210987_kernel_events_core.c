/*
 * bsc1210987_kernel_events_core
 *
 * Fix for CVE-2023-2235, bsc#1210987
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

/* klp-ccp: from kernel/events/core.c */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/idr.h>

/* klp-ccp: from kernel/events/core.c */
#include <linux/poll.h>

/* klp-ccp: from kernel/events/core.c */
#include <linux/hash.h>

/* klp-ccp: from kernel/events/core.c */
#include <linux/sysfs.h>
#include <linux/dcache.h>
#include <linux/percpu.h>
#include <linux/ptrace.h>
#include <linux/vmstat.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/vmalloc.h>

/* klp-ccp: from kernel/events/core.c */
#include <linux/hugetlb.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>

/* klp-ccp: from kernel/events/core.c */
#include <linux/kernel_stat.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>
#include <linux/trace_events.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/compat.h>

/* klp-ccp: from kernel/events/core.c */
#include <linux/sched/clock.h>
#include <linux/sched/mm.h>
#include <linux/mount.h>
#include <linux/highmem.h>
#include <linux/pgtable.h>
#include <linux/buildid.h>
/* klp-ccp: from kernel/events/internal.h */
#include <linux/hardirq.h>
#include <linux/uaccess.h>
#include <linux/refcount.h>

static void (*klpe_perf_event_wakeup)(struct perf_event *event);

/* klp-ccp: from kernel/events/core.c */
static inline struct perf_cpu_context *
__get_cpu_context(struct perf_event_context *ctx)
{
	return this_cpu_ptr(ctx->pmu->pmu_cpu_context);
}

static void perf_ctx_lock(struct perf_cpu_context *cpuctx,
			  struct perf_event_context *ctx)
{
	raw_spin_lock(&cpuctx->ctx.lock);
	if (ctx)
		raw_spin_lock(&ctx->lock);
}

static void perf_ctx_unlock(struct perf_cpu_context *cpuctx,
			    struct perf_event_context *ctx)
{
	if (ctx)
		raw_spin_unlock(&ctx->lock);
	raw_spin_unlock(&cpuctx->ctx.lock);
}

#define TASK_TOMBSTONE ((void *)-1L)

static bool is_kernel_event(struct perf_event *event)
{
	return READ_ONCE(event->owner) == TASK_TOMBSTONE;
}

enum event_type_t {
	EVENT_FLEXIBLE = 0x1,
	EVENT_PINNED = 0x2,
	EVENT_TIME = 0x4,
	/* see ctx_resched() for details */
	EVENT_CPU = 0x8,
	EVENT_ALL = EVENT_FLEXIBLE | EVENT_PINNED,
};

static void (*klpe_perf_event_update_time)(struct perf_event *event);

static void klpr_perf_event_update_sibling_time(struct perf_event *leader)
{
	struct perf_event *sibling;

	for_each_sibling_event(sibling, leader)
		(*klpe_perf_event_update_time)(sibling);
}

static void
klpr_perf_event_set_state(struct perf_event *event, enum perf_event_state state)
{
	if (event->state == state)
		return;

	(*klpe_perf_event_update_time)(event);
	/*
	 * If a group leader gets enabled/disabled all its siblings
	 * are affected too.
	 */
	if ((event->state < 0) ^ (state < 0))
		klpr_perf_event_update_sibling_time(event);

	WRITE_ONCE(event->state, state);
}

#ifdef CONFIG_CGROUP_PERF

static inline bool
perf_cgroup_match(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	struct perf_cpu_context *cpuctx = __get_cpu_context(ctx);

	/* @event doesn't care about cgroup */
	if (!event->cgrp)
		return true;

	/* wants specific cgroup scope but @cpuctx isn't associated with any */
	if (!cpuctx->cgrp)
		return false;

	/*
	 * Cgroup scoping is recursive.  An event enabled for a cgroup is
	 * also enabled for all its descendant cgroups.  If @cpuctx's
	 * cgroup is a descendant of @event's (the test covers identity
	 * case), it's a match.
	 */
	return cgroup_is_descendant(cpuctx->cgrp->css.cgroup,
				    event->cgrp->css.cgroup);
}

#else /* !CONFIG_CGROUP_PERF */
#error "klp-ccp: non-taken branch"
#endif

static void (*klpe_put_ctx)(struct perf_event_context *ctx);

static __must_check struct perf_event_context *
unclone_ctx(struct perf_event_context *ctx)
{
	struct perf_event_context *parent_ctx = ctx->parent_ctx;

	lockdep_assert_held(&ctx->lock);

	if (parent_ctx)
		ctx->parent_ctx = NULL;
	ctx->generation++;

	return parent_ctx;
}

static struct perf_event_context *
(*klpe_perf_pin_task_context)(struct task_struct *task, int ctxn);

static enum event_type_t get_event_type(struct perf_event *event)
{
	struct perf_event_context *ctx = event->ctx;
	enum event_type_t event_type;

	lockdep_assert_held(&ctx->lock);

	/*
	 * It's 'group type', really, because if our group leader is
	 * pinned, so are we.
	 */
	if (event->group_leader != event)
		event = event->group_leader;

	event_type = event->attr.pinned ? EVENT_PINNED : EVENT_FLEXIBLE;
	if (!ctx->task)
		event_type |= EVENT_CPU;

	return event_type;
}

static void klpr_put_event(struct perf_event *event);

static inline int __pmu_filter_match(struct perf_event *event)
{
	struct pmu *pmu = event->pmu;
	return pmu->filter_match ? pmu->filter_match(event) : 1;
}

static inline int pmu_filter_match(struct perf_event *event)
{
	struct perf_event *sibling;

	if (!__pmu_filter_match(event))
		return 0;

	for_each_sibling_event(sibling, event) {
		if (!__pmu_filter_match(sibling))
			return 0;
	}

	return 1;
}

static inline int
event_filter_match(struct perf_event *event)
{
	return (event->cpu == -1 || event->cpu == smp_processor_id()) &&
	       perf_cgroup_match(event) && pmu_filter_match(event);
}

#define DETACH_GROUP	0x01UL
#define DETACH_CHILD	0x02UL

static void (*klpe_perf_remove_from_context)(struct perf_event *event, unsigned long flags);

static void (*klpe_ctx_sched_out)(struct perf_event_context *ctx,
			  struct perf_cpu_context *cpuctx,
			  enum event_type_t event_type);
static void
(*klpe_ctx_sched_in)(struct perf_event_context *ctx,
	     struct perf_cpu_context *cpuctx,
	     enum event_type_t event_type);

static void (*klpe_ctx_resched)(struct perf_cpu_context *cpuctx,
			struct perf_event_context *task_ctx,
			enum event_type_t event_type);

static int (*klpe_perf_event_stop)(struct perf_event *event, int restart);

#define for_each_task_context_nr(ctxn)					\
	for ((ctxn) = 0; (ctxn) < perf_nr_task_contexts; (ctxn)++)

static int klpr_event_enable_on_exec(struct perf_event *event,
				struct perf_event_context *ctx)
{
	if (!event->attr.enable_on_exec)
		return 0;

	event->attr.enable_on_exec = 0;
	if (event->state >= PERF_EVENT_STATE_INACTIVE)
		return 0;

	klpr_perf_event_set_state(event, PERF_EVENT_STATE_INACTIVE);

	return 1;
}

static void klpr_perf_event_enable_on_exec(int ctxn)
{
	struct perf_event_context *ctx, *clone_ctx = NULL;
	enum event_type_t event_type = 0;
	struct perf_cpu_context *cpuctx;
	struct perf_event *event;
	unsigned long flags;
	int enabled = 0;

	local_irq_save(flags);
	ctx = current->perf_event_ctxp[ctxn];
	if (!ctx || !ctx->nr_events)
		goto out;

	cpuctx = __get_cpu_context(ctx);
	perf_ctx_lock(cpuctx, ctx);
	(*klpe_ctx_sched_out)(ctx, cpuctx, EVENT_TIME);
	list_for_each_entry(event, &ctx->event_list, event_entry) {
		enabled |= klpr_event_enable_on_exec(event, ctx);
		event_type |= get_event_type(event);
	}

	/*
	 * Unclone and reschedule this context if we enabled any event.
	 */
	if (enabled) {
		clone_ctx = unclone_ctx(ctx);
		(*klpe_ctx_resched)(cpuctx, ctx, event_type);
	} else {
		(*klpe_ctx_sched_in)(ctx, cpuctx, EVENT_TIME);
	}
	perf_ctx_unlock(cpuctx, ctx);

out:
	local_irq_restore(flags);

	if (clone_ctx)
		(*klpe_put_ctx)(clone_ctx);
}

static void (*klpe_perf_remove_from_owner)(struct perf_event *event);
static void klpp_perf_event_exit_event(struct perf_event *event,
				  struct perf_event_context *ctx);

static void klpp_perf_event_remove_on_exec(int ctxn)
{
	struct perf_event_context *ctx, *clone_ctx = NULL;
	struct perf_event *event, *next;
	LIST_HEAD(free_list);
	unsigned long flags;
	bool modified = false;

	ctx = (*klpe_perf_pin_task_context)(current, ctxn);
	if (!ctx)
		return;

	mutex_lock(&ctx->mutex);

	if (WARN_ON_ONCE(ctx->task != current))
		goto unlock;

	list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
		if (!event->attr.remove_on_exec)
			continue;

		if (!is_kernel_event(event))
			(*klpe_perf_remove_from_owner)(event);

		modified = true;

		klpp_perf_event_exit_event(event, ctx);
	}

	raw_spin_lock_irqsave(&ctx->lock, flags);
	if (modified)
		clone_ctx = unclone_ctx(ctx);
	--ctx->pin_count;
	raw_spin_unlock_irqrestore(&ctx->lock, flags);

unlock:
	mutex_unlock(&ctx->mutex);

	(*klpe_put_ctx)(ctx);
	if (clone_ctx)
		(*klpe_put_ctx)(clone_ctx);
}

static void (*klpe__free_event)(struct perf_event *event);

static void (*klpe_free_event)(struct perf_event *event);

static void (*klpe_perf_remove_from_owner)(struct perf_event *event);

static void klpr_put_event(struct perf_event *event)
{
	if (!atomic_long_dec_and_test(&event->refcount))
		return;

	(*klpe__free_event)(event);
}

typedef void (perf_iterate_f)(struct perf_event *event, void *data);

static void
perf_iterate_ctx(struct perf_event_context *ctx,
		   perf_iterate_f output,
		   void *data, bool all)
{
	struct perf_event *event;

	list_for_each_entry_rcu(event, &ctx->event_list, event_entry) {
		if (!all) {
			if (event->state < PERF_EVENT_STATE_INACTIVE)
				continue;
			if (!event_filter_match(event))
				continue;
		}

		output(event, data);
	}
}

static void klpr_perf_event_addr_filters_exec(struct perf_event *event, void *data)
{
	struct perf_addr_filters_head *ifh = perf_event_addr_filters(event);
	struct perf_addr_filter *filter;
	unsigned int restart = 0, count = 0;
	unsigned long flags;

	if (!has_addr_filter(event))
		return;

	raw_spin_lock_irqsave(&ifh->lock, flags);
	list_for_each_entry(filter, &ifh->list, entry) {
		if (filter->path.dentry) {
			event->addr_filter_ranges[count].start = 0;
			event->addr_filter_ranges[count].size = 0;
			restart++;
		}

		count++;
	}

	if (restart)
		event->addr_filters_gen++;
	raw_spin_unlock_irqrestore(&ifh->lock, flags);

	if (restart)
		(*klpe_perf_event_stop)(event, 1);
}

void klpp_perf_event_exec(void)
{
	struct perf_event_context *ctx;
	int ctxn;

	for_each_task_context_nr(ctxn) {
		klpr_perf_event_enable_on_exec(ctxn);
		klpp_perf_event_remove_on_exec(ctxn);

		rcu_read_lock();
		ctx = rcu_dereference(current->perf_event_ctxp[ctxn]);
		if (ctx) {
			perf_iterate_ctx(ctx, klpr_perf_event_addr_filters_exec,
					 NULL, true);
		}
		rcu_read_unlock();
	}
}

void
klpp_perf_event_exit_event(struct perf_event *event, struct perf_event_context *ctx)
{
	struct perf_event *parent_event = event->parent;
	unsigned long detach_flags = 0;

	if (parent_event) {
		/*
		 * Do not destroy the 'original' grouping; because of the
		 * context switch optimization the original events could've
		 * ended up in a random child task.
		 *
		 * If we were to destroy the original group, all group related
		 * operations would cease to function properly after this
		 * random child dies.
		 *
		 * Do destroy all inherited groups, we don't care about those
		 * and being thorough is better.
		 */
		detach_flags = DETACH_GROUP | DETACH_CHILD;
		mutex_lock(&parent_event->child_mutex);
	}

	/*
	 * Set DETACH_GROUP flag if the current event is not a group
	 * leader, and if the group_leader of the current event doesn't
	 * have the remove_on_exec flag set.
	 *
	 * By setting DETACH_GROUP, function __perf_remove_from_context will call
	 * perf_group_detach, which will be able to remove the event from the
	 * siblings_list before calling list_del_event.
	 *
	 * Function list_del_event removes the event from the group_node RB, and
	 * unset PERF_ATTACH_CONTEXT flag. Later perf_group_detach can be called
	 * from a group leader of the event del-ed before. The deleted event is
	 * still in the siblings_list, which makes perf_group_detach to
	 * create singleton groups for each sibling event of the group leader.
	 * When the sibling event is finally freed (ref counts reaches zero),
	 * list_del_event will be called again, but as it was called before it
	 * will now do nothing now, and so a dangling pointer will exists in the
	 * group_node RB after the event was removed.
	 */
	if (event->group_leader != event &&
	    !event->group_leader->attr.remove_on_exec) {
		detach_flags |= DETACH_GROUP;
	}

	(*klpe_perf_remove_from_context)(event, detach_flags);

	raw_spin_lock_irq(&ctx->lock);
	if (event->state > PERF_EVENT_STATE_EXIT)
		klpr_perf_event_set_state(event, PERF_EVENT_STATE_EXIT);
	raw_spin_unlock_irq(&ctx->lock);

	/*
	 * Child events can be freed.
	 */
	if (parent_event) {
		mutex_unlock(&parent_event->child_mutex);
		/*
		 * Kick perf_poll() for is_event_hup();
		 */
		(*klpe_perf_event_wakeup)(parent_event);
		(*klpe_free_event)(event);
		klpr_put_event(parent_event);
		return;
	}

	/*
	 * Parent events are governed by their filedesc, retain them.
	 */
	(*klpe_perf_event_wakeup)(event);
}


#include <linux/kernel.h>
#include "livepatch_bsc1210987.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "_free_event", (void *)&klpe__free_event },
	{ "ctx_resched", (void *)&klpe_ctx_resched },
	{ "ctx_sched_in", (void *)&klpe_ctx_sched_in },
	{ "ctx_sched_out", (void *)&klpe_ctx_sched_out },
	{ "free_event", (void *)&klpe_free_event },
	{ "perf_event_stop", (void *)&klpe_perf_event_stop },
	{ "perf_event_update_time", (void *)&klpe_perf_event_update_time },
	{ "perf_event_wakeup", (void *)&klpe_perf_event_wakeup },
	{ "perf_pin_task_context", (void *)&klpe_perf_pin_task_context },
	{ "perf_remove_from_context", (void *)&klpe_perf_remove_from_context },
	{ "perf_remove_from_owner", (void *)&klpe_perf_remove_from_owner },
	{ "put_ctx", (void *)&klpe_put_ctx },
};

int bsc1210987_kernel_events_core_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
