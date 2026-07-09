/*
 * livepatch_bsc1265117
 *
 * Fix for CVE-2026-43366, bsc#1265117
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


#include "livepatch_bsc1265117.h"


/* klp-ccp: from io_uring/kbuf.c */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/vmalloc.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

/* klp-ccp: from io_uring/io_uring.h */
#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/kasan.h>
#include <linux/poll.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/eventpoll.h>

/* klp-ccp: from io_uring/io-wq.h */
#include <linux/refcount.h>
#include <linux/io_uring_types.h>

/* klp-ccp: from io_uring/slist.h */
#include <linux/io_uring_types.h>

/* klp-ccp: from io_uring/filetable.h */
#include <linux/file.h>
#include <linux/io_uring_types.h>

/* klp-ccp: from io_uring/io_uring.h */
#ifndef CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static inline void io_ring_submit_unlock(struct io_ring_ctx *ctx,
					 unsigned issue_flags)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (unlikely(issue_flags & IO_URING_F_UNLOCKED))
		mutex_unlock(&ctx->uring_lock);
}

static inline void io_ring_submit_lock(struct io_ring_ctx *ctx,
				       unsigned issue_flags)
{
	/*
	 * "Normal" inline submissions always hold the uring_lock, since we
	 * grab it from the system call. Same is true for the SQPOLL offload.
	 * The only exception is when we've detached the request and issue it
	 * from an async worker thread, grab the lock for that case.
	 */
	if (unlikely(issue_flags & IO_URING_F_UNLOCKED))
		mutex_lock(&ctx->uring_lock);
	lockdep_assert_held(&ctx->uring_lock);
}

/* klp-ccp: from io_uring/kbuf.h */
#include <uapi/linux/io_uring.h>

struct io_buffer_list {
	/*
	 * If ->buf_nr_pages is set, then buf_pages/buf_ring are used. If not,
	 * then these are classic provided buffers and ->buf_list is used.
	 */
	union {
		struct list_head buf_list;
		struct {
			struct page **buf_pages;
			struct io_uring_buf_ring *buf_ring;
		};
		struct rcu_head rcu;
	};
	__u16 bgid;

	/* below is for ring provided buffers */
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;

	__u16 flags;

	atomic_t refs;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

bool klpp_io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);

/* klp-ccp: from io_uring/kbuf.c */
static inline struct io_buffer_list *io_buffer_get_list(struct io_ring_ctx *ctx,
							unsigned int bgid)
{
	lockdep_assert_held(&ctx->uring_lock);

	return xa_load(&ctx->io_bl_xa, bgid);
}

bool klpp_io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	struct io_buffer *buf;

	io_ring_submit_lock(ctx, issue_flags);

	buf = req->kbuf;
	bl = io_buffer_get_list(ctx, buf->bgid);
	/*
	 * If the buffer list was upgraded to a ring-based one, or removed,
	 * while the request was in-flight in io-wq, drop it.
	 */
	if (bl && !bl->buf_nr_pages) {
		list_add(&buf->list, &bl->buf_list);
	}

	req->flags &= ~REQ_F_BUFFER_SELECTED;
	req->buf_index = buf->bgid;
	req->kbuf = NULL;

	io_ring_submit_unlock(ctx, issue_flags);
	return true;
}


