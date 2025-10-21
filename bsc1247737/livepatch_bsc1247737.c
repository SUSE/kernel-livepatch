/*
 * livepatch_bsc1247737
 *
 * Fix for CVE-2025-38453, bsc#1247737
 *
 *  Copyright (c) 2025 SUSE
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

#include <linux/slab.h>
#include <linux/nospec.h>

/* klp-ccp: from io_uring/msg_ring.c */
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

/* klp-ccp: from io_uring/io_uring.h */
#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/kasan.h>

/* klp-ccp: from include/uapi/linux/eventpoll.h */
#define _UAPI_LINUX_EVENTPOLL_H

/* klp-ccp: from io_uring/io_uring.h */
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

static inline struct io_fixed_file *
io_fixed_file_slot(struct io_file_table *table, unsigned i)
{
	return &table->files[i];
}

#define FFS_NOWAIT		0x1UL
#define FFS_ISREG		0x2UL
#define FFS_MASK		~(FFS_NOWAIT|FFS_ISREG)

static inline struct file *io_slot_file(struct io_fixed_file *slot)
{
	return (struct file *)(slot->file_ptr & FFS_MASK);
}

static inline struct file *io_file_from_index(struct io_file_table *table,
					      int index)
{
	return io_slot_file(io_fixed_file_slot(table, index));
}

/* klp-ccp: from io_uring/io_uring.h */
enum {
	IOU_OK			= 0,
	IOU_ISSUE_SKIP_COMPLETE	= -EIOCBQUEUED,

	/*
	 * Requeue the task_work to restart operations on this request. The
	 * actual value isn't important, should just be not an otherwise
	 * valid error code, yet less than -MAX_ERRNO and valid internally.
	 */
	IOU_REQUEUE             = -3072,

	/*
	 * Intended only when both IO_URING_F_MULTISHOT is passed
	 * to indicate to the poll runner that multishot should be
	 * removed and the result is set on req->cqe.res.
	 */
	IOU_STOP_MULTISHOT	= -ECANCELED,
};

struct bsc1247737_io_kiocb {
	union {
		/*
		 * NOTE! Each of the io_kiocb union members has the file pointer
		 * as the first entry in their struct definition. So you can
		 * access the file pointer through any of the sub-structs,
		 * or directly as just 'file' in this struct.
		 */
		struct file		*file;
		struct io_cmd_data	cmd;
	};

	u8				opcode;
	/* polled IO has completed */
	u8				iopoll_completed;
	/*
	 * Can be either a fixed buffer index, or used with provided buffers.
	 * For the latter, before issue it points to the buffer group ID,
	 * and after selection it points to the buffer ID itself.
	 */
	u16				buf_index;

	unsigned			nr_tw;

	/* REQ_F_* flags */
	io_req_flags_t			flags;

	struct io_cqe			cqe;

	struct io_ring_ctx		*ctx;
	struct task_struct		*task;

	union {
		/* store used ubuf, so we can prevent reloading */
		struct io_mapped_ubuf	*imu;

		/* stores selected buf, valid IFF REQ_F_BUFFER_SELECTED is set */
		struct io_buffer	*kbuf;

		/*
		 * stores buffer ID for ring provided buffers, valid IFF
		 * REQ_F_BUFFER_RING is set.
		 */
		struct io_buffer_list	*buf_list;
	};

	union {
		/* used by request caches, completion batching and iopoll */
		struct io_wq_work_node	comp_list;
		/* cache ->apoll->events */
		__poll_t apoll_events;
	};

	struct io_rsrc_node		*rsrc_node;

	atomic_t			refs;
	bool				cancel_seq_set;
	struct io_task_work		io_task_work;
	union {
		struct hlist_node		hash_node;
		/* for polled requests, i.e. IORING_OP_POLL_ADD and async armed poll */
		struct rcu_head                 rcu_head;
	};
	/* internal polling, see IORING_FEAT_FAST_POLL */
	struct async_poll		*apoll;
	/* opcode allocated if it needs to store data for async defer */
	void				*async_data;
	/* linked requests, IFF REQ_F_HARDLINK or REQ_F_LINK are set */
	atomic_t			poll_refs;
	struct bsc1247737_io_kiocb	*link;
	/* custom credentials, valid IFF REQ_F_CREDS is set */
	const struct cred		*creds;
	struct io_wq_work		work;

	struct {
		u64			extra1;
		u64			extra2;
	} big_cqe;
};

bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);
void io_add_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);

void io_req_task_work_add_remote(struct io_kiocb *req, struct io_ring_ctx *ctx,
				 unsigned flags);

static inline void req_set_fail(struct io_kiocb *req)
{
	req->flags |= REQ_F_FAIL;
	if (req->flags & REQ_F_CQE_SKIP) {
		req->flags &= ~REQ_F_CQE_SKIP;
		req->flags |= REQ_F_SKIP_LINK_CQES;
	}
}

static inline void io_req_set_res(struct io_kiocb *req, s32 res, u32 cflags)
{
	req->cqe.res = res;
	req->cqe.flags = cflags;
}

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

extern struct kmem_cache *req_cachep;

/* klp-ccp: from io_uring/alloc_cache.h */
static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
				      void *entry)
{
	if (cache->nr_cached < cache->max_cached) {
		/* KASAN poisons object */
		kasan_slab_free_mempool(entry);
		cache->entries[cache->nr_cached++] = entry;
		return true;
	}
	return false;
}

static inline void *io_alloc_cache_get(struct io_alloc_cache *cache)
{
	if (cache->nr_cached) {
		void *entry = cache->entries[--cache->nr_cached];
		kasan_unpoison_range(entry, cache->elem_size);
		return entry;
	}
	return NULL;
}

/* klp-ccp: from io_uring/msg_ring.c */
struct io_msg {
	struct file			*file;
	struct file			*src_file;
	struct callback_head		tw;
	u64 user_data;
	u32 len;
	u32 cmd;
	u32 src_fd;
	union {
		u32 dst_fd;
		u32 cqe_flags;
	};
	u32 flags;
};

static void io_double_unlock_ctx(struct io_ring_ctx *octx)
{
	mutex_unlock(&octx->uring_lock);
}

static int io_double_lock_ctx(struct io_ring_ctx *octx,
			      unsigned int issue_flags)
{
	/*
	 * To ensure proper ordering between the two ctxs, we can only
	 * attempt a trylock on the target. If that fails and we already have
	 * the source ctx lock, punt to io-wq.
	 */
	if (!(issue_flags & IO_URING_F_UNLOCKED)) {
		if (!mutex_trylock(&octx->uring_lock))
			return -EAGAIN;
		return 0;
	}
	mutex_lock(&octx->uring_lock);
	return 0;
}

static inline bool io_msg_need_remote(struct io_ring_ctx *target_ctx)
{
	return target_ctx->task_complete;
}

void klpp_io_msg_tw_complete(struct io_kiocb *req, struct io_tw_state *ts)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_add_aux_cqe(ctx, req->cqe.user_data, req->cqe.res, req->cqe.flags);
	if (spin_trylock(&ctx->msg_lock)) {
		if (io_alloc_cache_put(&ctx->msg_cache, req))
			req = NULL;
		spin_unlock(&ctx->msg_lock);
	}
	if (req) {
		struct bsc1247737_io_kiocb *req1 = (struct bsc1247737_io_kiocb*)req;
		kfree_rcu(req1, rcu_head);
	}
	percpu_ref_put(&ctx->refs);
}

static int io_msg_remote_post(struct io_ring_ctx *ctx, struct io_kiocb *req,
			      int res, u32 cflags, u64 user_data)
{
	req->task = READ_ONCE(ctx->submitter_task);
	if (!req->task) {
		struct bsc1247737_io_kiocb *req1 = (struct bsc1247737_io_kiocb*)req;
		kfree_rcu(req1, rcu_head);
		return -EOWNERDEAD;
	}
	req->cqe.user_data = user_data;
	io_req_set_res(req, res, cflags);
	percpu_ref_get(&ctx->refs);
	req->ctx = ctx;
	req->io_task_work.func = klpp_io_msg_tw_complete;
	io_req_task_work_add_remote(req, ctx, IOU_F_TWQ_LAZY_WAKE);
	return 0;
}

static struct io_kiocb *io_msg_get_kiocb(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req = NULL;

	if (spin_trylock(&ctx->msg_lock)) {
		req = io_alloc_cache_get(&ctx->msg_cache);
		spin_unlock(&ctx->msg_lock);
		if (req)
			return req;
	}
	return kmem_cache_alloc(req_cachep, GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
}

static int io_msg_data_remote(struct io_kiocb *req)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct io_kiocb *target;
	u32 flags = 0;

	target = io_msg_get_kiocb(req->ctx);
	if (unlikely(!target))
		return -ENOMEM;

	if (msg->flags & IORING_MSG_RING_FLAGS_PASS)
		flags = msg->cqe_flags;

	return io_msg_remote_post(target_ctx, target, msg->len, flags,
					msg->user_data);
}

static int io_msg_ring_data(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	u32 flags = 0;
	int ret;

	if (msg->src_fd || msg->flags & ~IORING_MSG_RING_FLAGS_PASS)
		return -EINVAL;
	if (!(msg->flags & IORING_MSG_RING_FLAGS_PASS) && msg->dst_fd)
		return -EINVAL;
	if (target_ctx->flags & IORING_SETUP_R_DISABLED)
		return -EBADFD;

	if (io_msg_need_remote(target_ctx))
		return io_msg_data_remote(req);

	if (msg->flags & IORING_MSG_RING_FLAGS_PASS)
		flags = msg->cqe_flags;

	ret = -EOVERFLOW;
	if (target_ctx->flags & IORING_SETUP_IOPOLL) {
		if (unlikely(io_double_lock_ctx(target_ctx, issue_flags)))
			return -EAGAIN;
	}
	if (io_post_aux_cqe(target_ctx, msg->user_data, msg->len, flags))
		ret = 0;
	if (target_ctx->flags & IORING_SETUP_IOPOLL)
		io_double_unlock_ctx(target_ctx);
	return ret;
}

static struct file *io_msg_grab_file(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct io_ring_ctx *ctx = req->ctx;
	struct file *file = NULL;
	int idx = msg->src_fd;

	io_ring_submit_lock(ctx, issue_flags);
	if (likely(idx < ctx->nr_user_files)) {
		idx = array_index_nospec(idx, ctx->nr_user_files);
		file = io_file_from_index(&ctx->file_table, idx);
		if (file)
			get_file(file);
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return file;
}

extern int io_msg_install_complete(struct io_kiocb *req, unsigned int issue_flags);

extern void io_msg_tw_fd_complete(struct callback_head *head);

static int io_msg_fd_remote(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct task_struct *task = READ_ONCE(ctx->submitter_task);

	if (unlikely(!task))
		return -EOWNERDEAD;

	init_task_work(&msg->tw, io_msg_tw_fd_complete);
	if (task_work_add(task, &msg->tw, TWA_SIGNAL))
		return -EOWNERDEAD;

	return IOU_ISSUE_SKIP_COMPLETE;
}

static int io_msg_send_fd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct io_ring_ctx *ctx = req->ctx;
	struct file *src_file = msg->src_file;

	if (msg->len)
		return -EINVAL;
	if (target_ctx == ctx)
		return -EINVAL;
	if (target_ctx->flags & IORING_SETUP_R_DISABLED)
		return -EBADFD;
	if (!src_file) {
		src_file = io_msg_grab_file(req, issue_flags);
		if (!src_file)
			return -EBADF;
		msg->src_file = src_file;
		req->flags |= REQ_F_NEED_CLEANUP;
	}

	if (io_msg_need_remote(target_ctx))
		return io_msg_fd_remote(req);
	return io_msg_install_complete(req, issue_flags);
}

int klpp_io_msg_ring(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	int ret;

	ret = -EBADFD;
	if (!io_is_uring_fops(req->file))
		goto done;

	switch (msg->cmd) {
	case IORING_MSG_DATA:
		ret = io_msg_ring_data(req, issue_flags);
		break;
	case IORING_MSG_SEND_FD:
		ret = io_msg_send_fd(req, issue_flags);
		break;
	default:
		ret = -EINVAL;
		break;
	}

done:
	if (ret < 0) {
		if (ret == -EAGAIN || ret == IOU_ISSUE_SKIP_COMPLETE)
			return ret;
		req_set_fail(req);
	}
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}


#include "livepatch_bsc1247737.h"

#include <linux/livepatch.h>

extern typeof(io_add_aux_cqe) io_add_aux_cqe
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, io_add_aux_cqe);
extern typeof(io_is_uring_fops) io_is_uring_fops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, io_is_uring_fops);
extern typeof(io_msg_install_complete) io_msg_install_complete
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, io_msg_install_complete);
extern typeof(io_msg_tw_fd_complete) io_msg_tw_fd_complete
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, io_msg_tw_fd_complete);
extern typeof(io_post_aux_cqe) io_post_aux_cqe
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, io_post_aux_cqe);
extern typeof(io_req_task_work_add_remote) io_req_task_work_add_remote
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, io_req_task_work_add_remote);
extern typeof(req_cachep) req_cachep
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, req_cachep);
extern typeof(task_work_add) task_work_add
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, task_work_add);
