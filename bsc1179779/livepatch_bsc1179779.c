/*
 * livepatch_bsc1179779
 *
 * Fix for CVE-2020-29373, bsc#1179779
 *
 *  Upstream commit:
 *  cac68d12c531 ("io_uring: grab ->fs as part of async offload") stable-5.4
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  not affected
 *
 *  SLE15-SP2 commit:
 *  b260e715fad82b3f4547530e15c7bed6e13467df
 *
 *
 *  Copyright (c) 2021 SUSE
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

/* klp-ccp: from fs/io_uring.c */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/refcount.h>
#include <linux/uio.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/nospec.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/bvec.h>
#include <net/scm.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>
#include <linux/sizes.h>
#include <uapi/linux/io_uring.h>

struct async_list {
	spinlock_t		lock;
	atomic_t		cnt;
	struct list_head	list;

	struct file		*file;
	off_t			io_end;
	size_t			io_len;
};

struct io_ring_ctx {
	struct {
		struct percpu_ref	refs;
	} ____cacheline_aligned_in_smp;

	struct {
		unsigned int		flags;
		bool			compat;
		bool			account_mem;

		/* SQ ring */
		struct io_sq_ring	*sq_ring;
		unsigned		cached_sq_head;
		unsigned		sq_entries;
		unsigned		sq_mask;
		unsigned		sq_thread_idle;
		unsigned		cached_sq_dropped;
		struct io_uring_sqe	*sq_sqes;

		struct list_head	defer_list;
	} ____cacheline_aligned_in_smp;

	/* IO offload */
	struct workqueue_struct	*sqo_wq;
	struct task_struct	*sqo_thread;	/* if using sq thread polling */
	struct mm_struct	*sqo_mm;
	wait_queue_head_t	sqo_wait;
	struct completion	sqo_thread_started;

	struct {
		/* CQ ring */
		struct io_cq_ring	*cq_ring;
		unsigned		cached_cq_tail;
		atomic_t		cached_cq_overflow;
		unsigned		cq_entries;
		unsigned		cq_mask;
		struct wait_queue_head	cq_wait;
		struct fasync_struct	*cq_fasync;
		struct eventfd_ctx	*cq_ev_fd;
	} ____cacheline_aligned_in_smp;

	/*
	 * If used, fixed file set. Writers must ensure that ->refs is dead,
	 * readers must ensure that ->refs is alive as long as the file* is
	 * used. Only updated through io_uring_register(2).
	 */
	struct file		**user_files;
	unsigned		nr_user_files;

	/* if used, fixed mapped user buffers */
	unsigned		nr_user_bufs;
	struct io_mapped_ubuf	*user_bufs;

	struct user_struct	*user;

	const struct cred	*creds;

	struct completion	ctx_done;

	struct {
		struct mutex		uring_lock;
		wait_queue_head_t	wait;
	} ____cacheline_aligned_in_smp;

	struct {
		spinlock_t		completion_lock;
		bool			poll_multi_file;
		/*
		 * ->poll_list is protected by the ctx->uring_lock for
		 * io_uring instances that don't use IORING_SETUP_SQPOLL.
		 * For SQPOLL, only the single threaded io_sq_thread() will
		 * manipulate the list, hence no extra locking is needed there.
		 */
		struct list_head	poll_list;
		struct list_head	cancel_list;
	} ____cacheline_aligned_in_smp;

	struct async_list	pending_async[2];

#if defined(CONFIG_UNIX)
	struct socket		*ring_sock;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct sqe_submit {
	const struct io_uring_sqe	*sqe;
	unsigned short			index;
	u32				sequence;
	bool				has_user;
	bool				needs_lock;
	bool				needs_fixed_file;
};

struct io_poll_iocb {
	struct file			*file;
	struct wait_queue_head		*head;
	__poll_t			events;
	bool				done;
	bool				canceled;
	struct wait_queue_entry		wait;
};

struct io_kiocb {
	union {
		struct file		*file;
		struct kiocb		rw;
		struct io_poll_iocb	poll;
	};

	struct sqe_submit	submit;

	struct io_ring_ctx	*ctx;
	struct list_head	list;
	struct list_head	link_list;
	unsigned int		flags;
	refcount_t		refs;

#define REQ_F_IO_DRAINED	32	/* drain done */

#define REQ_F_LINK_DONE		128	/* linked sqes done */
	unsigned long		fsize;
	u64			user_data;
	u32			result;
	u32			sequence;

	struct work_struct	work;
};

void klpp_io_sq_wq_submit_work(struct work_struct *work);

static void (*klpe_io_cqring_add_event)(struct io_ring_ctx *ctx, u64 user_data,
				long res);

static void (*klpe_io_put_req)(struct io_kiocb *req);

static int (*klpe___io_submit_sqe)(struct io_ring_ctx *ctx, struct io_kiocb *req,
			   const struct sqe_submit *s, bool force_nonblock);

static struct async_list *io_async_list_from_sqe(struct io_ring_ctx *ctx,
						 const struct io_uring_sqe *sqe)
{
	switch (sqe->opcode) {
	case IORING_OP_READV:
	case IORING_OP_READ_FIXED:
		return &ctx->pending_async[READ];
	case IORING_OP_WRITEV:
	case IORING_OP_WRITE_FIXED:
		return &ctx->pending_async[WRITE];
	default:
		return NULL;
	}
}

/*
 * Fix CVE-2020-29373
 *  -1 line, +1 line
 */
static inline bool klpp_io_sqe_needs_user(const u8 opcode)
{
	/*
	 * Fix CVE-2020-29373
	 *  -1 line
	 */
	return !(opcode == IORING_OP_READ_FIXED ||
		 opcode == IORING_OP_WRITE_FIXED);
}

#include <linux/fs_struct.h>

/* New. */
static struct fs_struct *
klpp_get_fs_for_ctx(struct io_ring_ctx const * const ctx)
{
	struct mm_struct *mm;
	struct task_struct *owner;
	struct fs_struct *fs;

	/*
	 * That's safe, ->sqo_mm gets initialized unconditionally at ctx
	 * creation and io_sq_wq_submit_work() already attempts to get a
	 * hold of the mm_struct as well.
	 */
	mm = ctx->sqo_mm;
	if (!mmget_not_zero(mm))
		 return ERR_PTR(-EFAULT);

	rcu_read_lock();
	owner = rcu_dereference(mm->owner);
	if (!owner) {
		/* mm_update_next_owner() found no suitable successor. */
		rcu_read_unlock();
		mmput(mm);
		return ERR_PTR(-EFAULT);
	}

	task_lock(owner);
	if (owner->mm != mm) {
		/* owner is being detached from mm */
		fs = ERR_PTR(-EAGAIN);
		goto unlock_owner;
	}

	/* task_lock() protects owner->fs */
	fs = owner->fs;
	if (!fs) {
		/* owner is exiting or unsharing */
		fs = ERR_PTR(-EAGAIN);
		goto unlock_owner;
	}

	spin_lock(&fs->lock);
	/* That's the logic from the upstream patch. */
	if (fs->in_exec) {
		spin_unlock(&fs->lock);
		fs = ERR_PTR(-EAGAIN);
		goto unlock_owner;
	}
	fs->users++;
	spin_unlock(&fs->lock);

unlock_owner:
	task_unlock(owner);
	rcu_read_unlock();
	mmput(mm);
	return fs;
}

static void (*klpe_free_fs_struct)(struct fs_struct *fs);

void klpp_io_sq_wq_submit_work(struct work_struct *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	/*
	 * Fix CVE-2020-29373
	 *  +2 lines
	 */
	struct fs_struct *old_fs_struct = current->fs;
	struct fs_struct *cur_fs_struct = NULL;
	struct io_ring_ctx *ctx = req->ctx;
	struct mm_struct *cur_mm = NULL;
	struct async_list *async_list;
	const struct cred *old_cred;
	LIST_HEAD(req_list);
	mm_segment_t old_fs;
	int ret;

	old_cred = override_creds(ctx->creds);
	async_list = io_async_list_from_sqe(ctx, req->submit.sqe);
restart:
	do {
		struct sqe_submit *s = &req->submit;
		const struct io_uring_sqe *sqe = s->sqe;
		unsigned int flags = req->flags;
		/*
		 * Fix CVE-2020-29373
		 *  +1 line
		 */
		 const u8 opcode = READ_ONCE(sqe->opcode);

		/* Ensure we clear previously set non-block flag */
		req->rw.ki_flags &= ~IOCB_NOWAIT;

		ret = 0;
		/*
		 * Fix CVE-2020-29373
		 *  -1 line, +1 line
		 */
		if (klpp_io_sqe_needs_user(opcode) && !cur_mm) {
			if (!mmget_not_zero(ctx->sqo_mm)) {
				ret = -EFAULT;
			} else {
				cur_mm = ctx->sqo_mm;
				kthread_use_mm(cur_mm);
				old_fs = get_fs();
				set_fs(USER_DS);
			}
		}

		/*
		 * Fix CVE-2020-29373
		 *  +25 lines
		 */
		if ((opcode == IORING_OP_SENDMSG ||
		     opcode == IORING_OP_RECVMSG) &&
		     !ret && !cur_fs_struct) {
			do {
				cur_fs_struct = klpp_get_fs_for_ctx(ctx);
				if (IS_ERR(cur_fs_struct)) {
					ret = PTR_ERR(cur_fs_struct);
					cur_fs_struct = NULL;

					if (ret != -EAGAIN)
						break;

					ret = 0;
					cond_resched();
				} else {
					break;
				}
			} while (1);

			if (cur_fs_struct) {
				task_lock(current);
				current->fs = cur_fs_struct;
				task_unlock(current);
			}
		}

		if (!ret) {
			s->has_user = cur_mm != NULL;
			s->needs_lock = true;
			do {
				ret = (*klpe___io_submit_sqe)(ctx, req, s, false);
				/*
				 * We can get EAGAIN for polled IO even though
				 * we're forcing a sync submission from here,
				 * since we can't wait for request slots on the
				 * block side.
				 */
				if (ret != -EAGAIN)
					break;
				cond_resched();
			} while (1);
		}

		/* drop submission reference */
		(*klpe_io_put_req)(req);

		if (ret) {
			(*klpe_io_cqring_add_event)(ctx, sqe->user_data, ret);
			(*klpe_io_put_req)(req);
		}

		/* async context always use a copy of the sqe */
		kfree(sqe);

		/* req from defer and link list needn't decrease async cnt */
		if (flags & (REQ_F_IO_DRAINED | REQ_F_LINK_DONE))
			goto out;

		if (!async_list)
			break;
		if (!list_empty(&req_list)) {
			req = list_first_entry(&req_list, struct io_kiocb,
						list);
			list_del(&req->list);
			continue;
		}
		if (list_empty(&async_list->list))
			break;

		req = NULL;
		spin_lock(&async_list->lock);
		if (list_empty(&async_list->list)) {
			spin_unlock(&async_list->lock);
			break;
		}
		list_splice_init(&async_list->list, &req_list);
		spin_unlock(&async_list->lock);

		req = list_first_entry(&req_list, struct io_kiocb, list);
		list_del(&req->list);
	} while (req);

	/*
	 * Rare case of racing with a submitter. If we find the count has
	 * dropped to zero AND we have pending work items, then restart
	 * the processing. This is a tiny race window.
	 */
	if (async_list) {
		ret = atomic_dec_return(&async_list->cnt);
		while (!ret && !list_empty(&async_list->list)) {
			spin_lock(&async_list->lock);
			atomic_inc(&async_list->cnt);
			list_splice_init(&async_list->list, &req_list);
			spin_unlock(&async_list->lock);

			if (!list_empty(&req_list)) {
				req = list_first_entry(&req_list,
							struct io_kiocb, list);
				list_del(&req->list);
				goto restart;
			}
			ret = atomic_dec_return(&async_list->cnt);
		}
	}

out:
	/*
	 * Fix CVE-2020-29373
	 *  +13 lines
	 */
	if (cur_fs_struct) {
		bool free_fs;

		task_lock(current);
		current->fs = old_fs_struct;
		task_unlock(current);

		spin_lock(&cur_fs_struct->lock);
		free_fs = !--cur_fs_struct->users;
		spin_unlock(&cur_fs_struct->lock);
		if (free_fs)
			(*klpe_free_fs_struct)(cur_fs_struct);
	}

	if (cur_mm) {
		set_fs(old_fs);
		kthread_unuse_mm(cur_mm);
		mmput(cur_mm);
	}
	revert_creds(old_cred);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1179779.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "io_cqring_add_event", (void *)&klpe_io_cqring_add_event },
	{ "io_put_req", (void *)&klpe_io_put_req },
	{ "__io_submit_sqe", (void *)&klpe___io_submit_sqe },
	{ "free_fs_struct", (void *)&klpe_free_fs_struct },
};

int livepatch_bsc1179779_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
