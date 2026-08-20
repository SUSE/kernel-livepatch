/*
 * livepatch_bsc1268624
 *
 * Fix for CVE-2026-46274, bsc#1268624
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


#include "livepatch_bsc1268624.h"


/* klp-ccp: from io_uring/io-wq.c */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/rculist_nulls.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/task_work.h>
#include <linux/audit.h>
#include <linux/mmu_context.h>
#include <uapi/linux/io_uring.h>

/* klp-ccp: from io_uring/io-wq.h */
#include <linux/refcount.h>
#include <linux/io_uring_types.h>

enum {
	IO_WQ_WORK_CANCEL	= 1,
	IO_WQ_WORK_HASHED	= 2,
	IO_WQ_WORK_UNBOUND	= 4,
	IO_WQ_WORK_CONCURRENT	= 16,

	IO_WQ_HASH_SHIFT	= 24,	/* upper 8 bits are used for hash key */
};

typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
typedef void (io_wq_work_fn)(struct io_wq_work *);

static inline bool io_wq_is_hashed(struct io_wq_work *work)
{
	return atomic_read(&work->flags) & IO_WQ_WORK_HASHED;
}

typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

/* klp-ccp: from io_uring/slist.h */
#include <linux/io_uring_types.h>

#define wq_list_for_each(pos, prv, head)			\
	for (pos = (head)->first, prv = NULL; pos; prv = pos, pos = (pos)->next)

static inline void wq_list_cut(struct io_wq_work_list *list,
			       struct io_wq_work_node *last,
			       struct io_wq_work_node *prev)
{
	/* first in the list, if prev==NULL */
	if (!prev)
		WRITE_ONCE(list->first, last->next);
	else
		prev->next = last->next;

	if (last == list->last)
		list->last = prev;
	last->next = NULL;
}

static inline void wq_list_del(struct io_wq_work_list *list,
			       struct io_wq_work_node *node,
			       struct io_wq_work_node *prev)
{
	wq_list_cut(list, node, prev);
}

/* klp-ccp: from io_uring/io_uring.h */
#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/kasan.h>
#include <linux/poll.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/eventpoll.h>

/* klp-ccp: from io_uring/filetable.h */
#include <linux/file.h>
#include <linux/io_uring_types.h>

/* klp-ccp: from io_uring/io_uring.h */
#ifndef CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from io_uring/io-wq.c */
#define IO_WQ_HASH_ORDER	6

#define IO_WQ_NR_HASH_BUCKETS	(1u << IO_WQ_HASH_ORDER)

struct io_wq_acct {
	unsigned nr_workers;
	unsigned max_workers;
	int index;
	atomic_t nr_running;
	raw_spinlock_t lock;
	struct io_wq_work_list work_list;
	unsigned long flags;
};

enum {
	IO_WQ_ACCT_BOUND,
	IO_WQ_ACCT_UNBOUND,
	IO_WQ_ACCT_NR,
};

struct io_wq {
	unsigned long state;

	free_work_fn *free_work;
	io_wq_work_fn *do_work;

	struct io_wq_hash *hash;

	atomic_t worker_refs;
	struct completion worker_done;

	struct hlist_node cpuhp_node;

	struct task_struct *task;

	struct io_wq_acct acct[IO_WQ_ACCT_NR];

	/* lock protects access to elements below */
	raw_spinlock_t lock;

	struct hlist_nulls_head free_list;
	struct list_head all_list;

	struct wait_queue_entry wait;

	struct io_wq_work *hash_tail[IO_WQ_NR_HASH_BUCKETS];

	cpumask_var_t cpu_mask;
};

struct io_cb_cancel_data {
	work_cancel_fn *fn;
	void *data;
	int nr_running;
	int nr_pending;
	bool cancel_all;
};

bool klpp_io_acct_cancel_pending_work(struct io_wq *wq,
					struct io_wq_acct *acct,
					struct io_cb_cancel_data *match);

static inline struct io_wq_acct *io_get_acct(struct io_wq *wq, bool bound)
{
	return &wq->acct[bound ? IO_WQ_ACCT_BOUND : IO_WQ_ACCT_UNBOUND];
}

static inline struct io_wq_acct *io_work_get_acct(struct io_wq *wq,
						  struct io_wq_work *work)
{
	return io_get_acct(wq, !(atomic_read(&work->flags) & IO_WQ_WORK_UNBOUND));
}

static inline unsigned int io_get_work_hash(struct io_wq_work *work)
{
	return atomic_read(&work->flags) >> IO_WQ_HASH_SHIFT;
}

static void io_run_cancel(struct io_wq_work *work, struct io_wq *wq)
{
	do {
		atomic_or(IO_WQ_WORK_CANCEL, &work->flags);
		wq->do_work(work);
		work = wq->free_work(work);
	} while (work);
}

static inline void klpp_io_wq_remove_pending(struct io_wq *wq,
					 struct io_wq_work *work,
					 struct io_wq_work_node *prev)
{
	struct io_wq_acct *acct = io_work_get_acct(wq, work);
	unsigned int hash = io_get_work_hash(work);
	struct io_wq_work *prev_work = NULL;

	if (io_wq_is_hashed(work) && work == wq->hash_tail[hash]) {
		if (prev)
			prev_work = container_of(prev, struct io_wq_work, list);
		if (prev_work && io_wq_is_hashed(prev_work) &&
		    io_get_work_hash(prev_work) == hash)
			wq->hash_tail[hash] = prev_work;
		else
			wq->hash_tail[hash] = NULL;
	}
	wq_list_del(&acct->work_list, &work->list, prev);
}

bool klpp_io_acct_cancel_pending_work(struct io_wq *wq,
					struct io_wq_acct *acct,
					struct io_cb_cancel_data *match)
{
	struct io_wq_work_node *node, *prev;
	struct io_wq_work *work;

	raw_spin_lock(&acct->lock);
	wq_list_for_each(node, prev, &acct->work_list) {
		work = container_of(node, struct io_wq_work, list);
		if (!match->fn(work, match->data))
			continue;
		klpp_io_wq_remove_pending(wq, work, prev);
		raw_spin_unlock(&acct->lock);
		io_run_cancel(work, wq);
		match->nr_pending++;
		/* not safe to continue after unlock */
		return true;
	}
	raw_spin_unlock(&acct->lock);

	return false;
}


