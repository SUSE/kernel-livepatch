/*
 * bsc1218259_kernel_events_core
 *
 * Fix for CVE-2023-6931, bsc#1218259
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/idr.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/sysfs.h>
#include <linux/dcache.h>
#include <linux/percpu.h>
#include <linux/ptrace.h>
#include <linux/vmstat.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <linux/hugetlb.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>

/* klp-ccp: from include/linux/security.h */
#ifdef CONFIG_PERF_EVENTS

#ifdef CONFIG_SECURITY

static int (*klpe_security_perf_event_read)(struct perf_event *event);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SECURITY */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_PERF_EVENTS */

/* klp-ccp: from kernel/events/core.c */
#include <linux/kernel_stat.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>
#include <linux/trace_events.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/compat.h>
#include <linux/sched/clock.h>
#include <linux/sched/mm.h>
#include <linux/mount.h>
#include <linux/highmem.h>
#include <linux/pgtable.h>
#include <linux/buildid.h>

const struct file_operations *klpe_perf_fops;

/* klp-ccp: from kernel/events/core.c */
static void (*klpe_put_ctx)(struct perf_event_context *ctx);

static struct perf_event_context *
klpr_perf_event_ctx_lock_nested(struct perf_event *event, int nesting)
{
	struct perf_event_context *ctx;

again:
	rcu_read_lock();
	ctx = READ_ONCE(event->ctx);
	if (!refcount_inc_not_zero(&ctx->refcount)) {
		rcu_read_unlock();
		goto again;
	}
	rcu_read_unlock();

	mutex_lock_nested(&ctx->mutex, nesting);
	if (event->ctx != ctx) {
		mutex_unlock(&ctx->mutex);
		(*klpe_put_ctx)(ctx);
		goto again;
	}

	return ctx;
}

static inline struct perf_event_context *
klpr_perf_event_ctx_lock(struct perf_event *event)
{
	return klpr_perf_event_ctx_lock_nested(event, 0);
}

static void klpr_perf_event_ctx_unlock(struct perf_event *event,
				  struct perf_event_context *ctx)
{
	mutex_unlock(&ctx->mutex);
	(*klpe_put_ctx)(ctx);
}

static u64 primary_event_id(struct perf_event *event)
{
	u64 id = event->id;

	if (event->parent)
		id = event->parent->id;

	return id;
}

static inline u64 perf_event_count(struct perf_event *event)
{
	return local64_read(&event->count) + atomic64_read(&event->child_count);
}

static int (*klpe_perf_event_read)(struct perf_event *event, bool group);

static u64 (*klpe___perf_event_read_value)(struct perf_event *event, u64 *enabled, u64 *running);

static int klpp___perf_read_group_add(struct perf_event *leader,
					u64 read_format, u64 *values)
{
	struct perf_event_context *ctx = leader->ctx;
	struct perf_event *sub, *parent;
	unsigned long flags;
	int n = 1; /* skip @nr */
	int ret;

	ret = (*klpe_perf_event_read)(leader, true);
	if (ret)
		return ret;

	raw_spin_lock_irqsave(&ctx->lock, flags);
	/*
	 * Verify the grouping between the parent and child (inherited)
	 * events is still in tact.
	 *
	 * Specifically:
	 *  - leader->ctx->lock pins leader->sibling_list
	 *  - parent->child_mutex pins parent->child_list
	 *  - parent->ctx->mutex pins parent->sibling_list
	 *
	 * Because parent->ctx != leader->ctx (and child_list nests inside
	 * ctx->mutex), group destruction is not atomic between children, also
	 * see perf_event_release_kernel(). Additionally, parent can grow the
	 * group.
	 *
	 * Therefore it is possible to have parent and child groups in a
	 * different configuration and summing over such a beast makes no sense
	 * what so ever.
	 *
	 * Reject this.
	 */
	parent = leader->parent;
	if (parent &&
	    (parent->group_generation != leader->group_generation ||
	     parent->nr_siblings != leader->nr_siblings)) {
		ret = -ECHILD;
		goto unlock;
	}

	/*
	 * Since we co-schedule groups, {enabled,running} times of siblings
	 * will be identical to those of the leader, so we only publish one
	 * set.
	 */
	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) {
		values[n++] += leader->total_time_enabled +
			atomic64_read(&leader->child_total_time_enabled);
	}

	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) {
		values[n++] += leader->total_time_running +
			atomic64_read(&leader->child_total_time_running);
	}

	/*
	 * Write {count,id} tuples for every sibling.
	 */
	values[n++] += perf_event_count(leader);
	if (read_format & PERF_FORMAT_ID)
		values[n++] = primary_event_id(leader);
	if (read_format & PERF_FORMAT_LOST)
		values[n++] = atomic64_read(&leader->lost_samples);

	for_each_sibling_event(sub, leader) {
		values[n++] += perf_event_count(sub);
		if (read_format & PERF_FORMAT_ID)
			values[n++] = primary_event_id(sub);
		if (read_format & PERF_FORMAT_LOST)
			values[n++] = atomic64_read(&sub->lost_samples);
	}

unlock:
	raw_spin_unlock_irqrestore(&ctx->lock, flags);
	return ret;
}

static int klpp___perf_event_read_size(u64 read_format, int nr_siblings)
{
	int entry = sizeof(u64); /* value */
	u64 size = 0;
	u64 nr = 1;

	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		size += sizeof(u64);

	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		size += sizeof(u64);

	if (read_format & PERF_FORMAT_ID)
		entry += sizeof(u64);

	if (read_format & PERF_FORMAT_LOST)
		entry += sizeof(u64);

	if (read_format & PERF_FORMAT_GROUP) {
		nr += nr_siblings;
		size += sizeof(u64);
	}

	size += nr * entry;
	if (size > INT_MAX)
		size = INT_MAX;

	return size;
}

static int klpr_perf_read_group(struct perf_event *event,
				   u64 read_format, char __user *buf)
{
	struct perf_event *leader = event->group_leader, *child;
	struct perf_event_context *ctx = leader->ctx;
	int ret;
	u64 *values;

	lockdep_assert_held(&ctx->mutex);

	if (klpp___perf_event_read_size(event->attr.read_format,
					   leader->nr_siblings) > 16*1024)
		return -E2BIG;

	values = kzalloc(event->read_size, GFP_KERNEL);
	if (!values)
		return -ENOMEM;

	values[0] = 1 + leader->nr_siblings;

	mutex_lock(&leader->child_mutex);

	ret = klpp___perf_read_group_add(leader, read_format, values);
	if (ret)
		goto unlock;

	list_for_each_entry(child, &leader->child_list, child_list) {
		ret = klpp___perf_read_group_add(child, read_format, values);
		if (ret)
			goto unlock;
	}

	mutex_unlock(&leader->child_mutex);

	ret = event->read_size;
	if (copy_to_user(buf, values, event->read_size))
		ret = -EFAULT;
	goto out;

unlock:
	mutex_unlock(&leader->child_mutex);
out:
	kfree(values);
	return ret;
}

static int klpr_perf_read_one(struct perf_event *event,
				 u64 read_format, char __user *buf)
{
	u64 enabled, running;
	u64 values[5];
	int n = 0;

	values[n++] = (*klpe___perf_event_read_value)(event, &enabled, &running);
	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		values[n++] = enabled;
	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		values[n++] = running;
	if (read_format & PERF_FORMAT_ID)
		values[n++] = primary_event_id(event);
	if (read_format & PERF_FORMAT_LOST)
		values[n++] = atomic64_read(&event->lost_samples);

	if (copy_to_user(buf, values, n * sizeof(u64)))
		return -EFAULT;

	return n * sizeof(u64);
}

static ssize_t
klpr___perf_read(struct perf_event *event, char __user *buf, size_t count)
{
	u64 read_format = event->attr.read_format;
	int ret;

	/*
	 * Return end-of-file for a read on an event that is in
	 * error state (i.e. because it was pinned but it couldn't be
	 * scheduled on to the CPU at some point).
	 */
	if (event->state == PERF_EVENT_STATE_ERROR)
		return 0;

	if (count < event->read_size)
		return -ENOSPC;

	WARN_ON_ONCE(event->ctx->parent_ctx);
	if (read_format & PERF_FORMAT_GROUP)
		ret = klpr_perf_read_group(event, read_format, buf);
	else
		ret = klpr_perf_read_one(event, read_format, buf);

	return ret;
}

ssize_t
klpp_perf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct perf_event *event = file->private_data;
	struct perf_event_context *ctx;
	int ret;

	ret = (*klpe_security_perf_event_read)(event);
	if (ret)
		return ret;

	ctx = klpr_perf_event_ctx_lock(event);
	ret = klpr___perf_read(event, buf, count);
	klpr_perf_event_ctx_unlock(event, ctx);

	return ret;
}


#include "livepatch_bsc1218259.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__perf_event_read_value", (void *)&klpe___perf_event_read_value },
	{ "perf_event_read", (void *)&klpe_perf_event_read },
	{ "put_ctx", (void *)&klpe_put_ctx },
	{ "security_perf_event_read", (void *)&klpe_security_perf_event_read },
	{ "perf_fops", (void *)&klpe_perf_fops },
};

int bsc1218259_kernel_events_core_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

