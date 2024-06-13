/*
 * bsc1218259_fs_io_uring
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


/* klp-ccp: from fs/io_uring.c */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/refcount.h>
#include <linux/uio.h>
#include <linux/bits.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/bvec.h>
#include <net/scm.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>
#include <linux/sizes.h>
#include <linux/highmem.h>
#include <linux/fadvise.h>
#include <linux/splice.h>
#include <linux/pagemap.h>
#include <linux/io_uring.h>
#include <linux/refcount.h>

struct io_wq_work_node {
	struct io_wq_work_node *next;
};

struct io_wq_work {
	struct io_wq_work_node list;
	unsigned flags;
	int cancel_seq;
};

/* klp-ccp: from fs/io_uring.c */
struct io_submit_link {
	struct io_kiocb		*head;
	struct io_kiocb		*last;
};

struct io_poll_iocb {
	struct file			*file;
	struct wait_queue_head		*head;
	__poll_t			events;
	struct wait_queue_entry		wait;
};

struct io_poll_update {
	struct file			*file;
	u64				old_user_data;
	u64				new_user_data;
	__poll_t			events;
	bool				update_events;
	bool				update_user_data;
};

struct io_close {
	struct file			*file;
	int				fd;
	u32				file_slot;
};

struct io_accept {
	struct file			*file;
	struct sockaddr __user		*addr;
	int __user			*addr_len;
	int				flags;
	u32				file_slot;
	unsigned long			nofile;
};

struct io_sync {
	struct file			*file;
	loff_t				len;
	loff_t				off;
	int				flags;
	int				mode;
};

struct io_cancel {
	struct file			*file;
	u64				addr;
	u32				flags;
	s32				fd;
};

struct io_timeout {
	struct file			*file;
	u32				off;
	u32				target_seq;
	struct list_head		list;
	/* head of the link, used by linked timeouts only */
	struct io_kiocb			*head;
	/* for linked completions */
	struct io_kiocb			*prev;
};

struct io_timeout_rem {
	struct file			*file;
	u64				addr;

	/* timeout update */
	struct timespec64		ts;
	u32				flags;
	bool				ltimeout;
};

struct io_rw {
	/* NOTE: kiocb has the file as the first member, so don't do it here */
	struct kiocb			kiocb;
	u64				addr;
	u32				len;
	rwf_t				flags;
};

struct io_connect {
	struct file			*file;
	struct sockaddr __user		*addr;
	int				addr_len;
};

struct io_sr_msg {
	struct file			*file;
	union {
		struct compat_msghdr __user	*umsg_compat;
		struct user_msghdr __user	*umsg;
		void __user			*buf;
	};
	int				msg_flags;
	size_t				len;
	size_t				done_io;
	unsigned int			flags;
};

struct io_open {
	struct file			*file;
	int				dfd;
	u32				file_slot;
	struct filename			*filename;
	struct open_how			how;
	unsigned long			nofile;
};

struct io_rsrc_update {
	struct file			*file;
	u64				arg;
	u32				nr_args;
	u32				offset;
};

struct io_fadvise {
	struct file			*file;
	u64				offset;
	u32				len;
	u32				advice;
};

struct io_madvise {
	struct file			*file;
	u64				addr;
	u32				len;
	u32				advice;
};

struct io_epoll {
	struct file			*file;
	int				epfd;
	int				op;
	int				fd;
	struct epoll_event		event;
};

struct io_splice {
	struct file			*file_out;
	loff_t				off_out;
	loff_t				off_in;
	u64				len;
	int				splice_fd_in;
	unsigned int			flags;
};

struct io_provide_buf {
	struct file			*file;
	__u64				addr;
	__u32				len;
	__u32				bgid;
	__u16				nbufs;
	__u16				bid;
};

struct io_statx {
	struct file			*file;
	int				dfd;
	unsigned int			mask;
	unsigned int			flags;
	struct filename			*filename;
	struct statx __user		*buffer;
};

struct io_shutdown {
	struct file			*file;
	int				how;
};

struct io_rename {
	struct file			*file;
	int				old_dfd;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
	int				flags;
};

struct io_unlink {
	struct file			*file;
	int				dfd;
	int				flags;
	struct filename			*filename;
};

struct io_mkdir {
	struct file			*file;
	int				dfd;
	umode_t				mode;
	struct filename			*filename;
};

struct io_symlink {
	struct file			*file;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
};

struct io_hardlink {
	struct file			*file;
	int				old_dfd;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
	int				flags;
};

struct io_msg {
	struct file			*file;
	u64 user_data;
	u32 len;
};

typedef void (*io_req_tw_func_t)(struct io_kiocb *req, bool *locked);

struct io_task_work {
	union {
		struct io_wq_work_node	node;
		struct llist_node	fallback_node;
	};
	io_req_tw_func_t		func;
};

struct io_cqe {
	__u64	user_data;
	__s32	res;
	/* fd initially, then cflags for completion */
	union {
		__u32	flags;
		int	fd;
	};
};

struct io_kiocb {
	union {
		struct file		*file;
		struct io_rw		rw;
		struct io_poll_iocb	poll;
		struct io_poll_update	poll_update;
		struct io_accept	accept;
		struct io_sync		sync;
		struct io_cancel	cancel;
		struct io_timeout	timeout;
		struct io_timeout_rem	timeout_rem;
		struct io_connect	connect;
		struct io_sr_msg	sr_msg;
		struct io_open		open;
		struct io_close		close;
		struct io_rsrc_update	rsrc_update;
		struct io_fadvise	fadvise;
		struct io_madvise	madvise;
		struct io_epoll		epoll;
		struct io_splice	splice;
		struct io_provide_buf	pbuf;
		struct io_statx		statx;
		struct io_shutdown	shutdown;
		struct io_rename	rename;
		struct io_unlink	unlink;
		struct io_mkdir		mkdir;
		struct io_symlink	symlink;
		struct io_hardlink	hardlink;
		struct io_msg		msg;
		struct io_uring_cmd     uring_cmd;
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
	unsigned int			flags;

	struct io_cqe			cqe;

	struct io_ring_ctx		*ctx;
	struct task_struct		*task;

	struct io_rsrc_node		*rsrc_node;

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
	atomic_t			refs;
	atomic_t			poll_refs;
	struct io_task_work		io_task_work;
	/* for polled requests, i.e. IORING_OP_POLL_ADD and async armed poll */
	union {
		struct hlist_node	hash_node;
		struct {
			u64		extra1;
			u64		extra2;
		};
	};
	/* internal polling, see IORING_FEAT_FAST_POLL */
	struct async_poll		*apoll;
	/* opcode allocated if it needs to store data for async defer */
	void				*async_data;
	/* linked requests, IFF REQ_F_HARDLINK or REQ_F_LINK are set */
	struct io_kiocb			*link;
	/* custom credentials, valid IFF REQ_F_CREDS is set */
	const struct cred		*creds;
	struct io_wq_work		work;
};

static inline loff_t *io_kiocb_ppos(struct kiocb *kiocb)
{
	return (kiocb->ki_filp->f_mode & FMODE_STREAM) ? NULL : &kiocb->ki_pos;
}

#include "livepatch_bsc1218259.h"

ssize_t klpp_loop_rw_iter(int rw, struct io_kiocb *req, struct iov_iter *iter)
{
	struct kiocb *kiocb = &req->rw.kiocb;
	struct file *file = req->file;
	ssize_t ret = 0;
	loff_t *ppos;

	/*
	 * Don't support polled IO through this interface, and we can't
	 * support non-blocking either. For the latter, this just causes
	 * the kiocb to be handled from an async context.
	 */
	if (kiocb->ki_flags & IOCB_HIPRI)
		return -EOPNOTSUPP;
	if ((kiocb->ki_flags & IOCB_NOWAIT) &&
	    !(kiocb->ki_filp->f_flags & O_NONBLOCK))
		return -EAGAIN;

	ppos = io_kiocb_ppos(kiocb);

	while (iov_iter_count(iter)) {
		struct iovec iovec;
		ssize_t nr;

		if (!iov_iter_is_bvec(iter)) {
			iovec = iov_iter_iovec(iter);
		} else {
			iovec.iov_base = u64_to_user_ptr(req->rw.addr);
			iovec.iov_len = req->rw.len;
		}

		if (rw == READ) {
			if (file->f_op->read == klpe_perf_fops->read)
				nr = klpp_perf_read(file, iovec.iov_base,
							  iovec.iov_len, ppos);
			else
				nr = file->f_op->read(file, iovec.iov_base,
							  iovec.iov_len, ppos);
		} else {
			nr = file->f_op->write(file, iovec.iov_base,
					       iovec.iov_len, ppos);
		}

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (!iov_iter_is_bvec(iter)) {
			iov_iter_advance(iter, nr);
		} else {
			req->rw.addr += nr;
			req->rw.len -= nr;
			if (!req->rw.len)
				break;
		}
		if (nr != iovec.iov_len)
			break;
	}

	return ret;
}

