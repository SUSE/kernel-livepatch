/*
 * livepatch_bsc1270300
 *
 * Fix for CVE-2026-46242, bsc#1270300
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1270300.h"


#define CC_USING_FENTRY 1
/* klp-ccp: from fs/eventpoll.c */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/compat.h>
#include <linux/rculist.h>
#include <net/busy_poll.h>

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;

struct eppoll_entry {
	/* List header used to link this structure to the "struct epitem" */
	struct eppoll_entry *next;

	/* The "base" pointer is set to the container "struct epitem" */
	struct epitem *base;

	/*
	 * Wait queue item that will be linked to the target file wait
	 * queue head.
	 */
	wait_queue_entry_t wait;

	/* The wait queue head that linked the "wait" wait queue item */
	wait_queue_head_t *whead;
};

struct epitem {
	union {
		/* RB tree node links this structure to the eventpoll RB tree */
		struct rb_node rbn;
		/* Used to free the struct epitem */
		struct rcu_head rcu;
	};

	/* List header used to link this structure to the eventpoll ready list */
	struct list_head rdllink;

	/*
	 * Works together "struct eventpoll"->ovflist in keeping the
	 * single linked chain of items.
	 */
	struct epitem *next;

	/* The file descriptor information this item refers to */
	struct epoll_filefd ffd;

	/*
	 * Protected by file->f_lock, true for to-be-released epitem already
	 * removed from the "struct file" items list; together with
	 * eventpoll->refcount orchestrates "struct eventpoll" disposal
	 */
	bool dying;

	/* List containing poll wait queues */
	struct eppoll_entry *pwqlist;

	/* The "container" of this item */
	struct eventpoll *ep;

	/* List header used to link this item to the "struct file" items list */
	struct hlist_node fllink;

	/* wakeup_source used when EPOLLWAKEUP is set */
	struct wakeup_source __rcu *ws;

	/* The structure that describe the interested events and the source fd */
	struct epoll_event event;
};

struct eventpoll {
	/*
	 * This mutex is used to ensure that files are not removed
	 * while epoll is using them. This is held during the event
	 * collection loop, the file cleanup path, the epoll file exit
	 * code and the ctl operations.
	 */
	struct mutex mtx;

	/* Wait queue used by sys_epoll_wait() */
	wait_queue_head_t wq;

	/* Wait queue used by file->poll() */
	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	struct list_head rdllist;

	/* Lock which protects rdllist and ovflist */
	rwlock_t lock;

	/* RB tree root used to store monitored fd structs */
	struct rb_root_cached rbr;

	/*
	 * This is a single linked list that chains all the "struct epitem" that
	 * happened while transferring ready events to userspace w/out
	 * holding ->lock.
	 */
	struct epitem *ovflist;

	/* wakeup_source used when ep_scan_ready_list is running */
	struct wakeup_source *ws;

	/* The user that created the eventpoll descriptor */
	struct user_struct *user;

	struct file *file;

	/* used to optimize loop detection check */
	u64 gen;
	struct hlist_head refs;
	u8 loop_check_depth;

	/*
	 * usage count, used together with epitem->dying to
	 * orchestrate the disposal of this struct
	 */
	refcount_t refcount;

#ifdef CONFIG_NET_RX_BUSY_POLL
	unsigned int napi_id;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#error "klp-ccp: non-taken branch"
#endif
};

extern struct kmem_cache *pwq_cache __read_mostly;

struct epitems_head {
	struct hlist_head epitems;
	struct epitems_head *next;
};

extern struct kmem_cache *ephead_cache __read_mostly;

static inline void free_ephead(struct epitems_head *head)
{
	if (head)
		kmem_cache_free(ephead_cache, head);
}

#ifdef CONFIG_SYSCTL

#include <linux/sysctl.h>

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SYSCTL */

extern const struct file_operations eventpoll_fops;

static inline int is_file_epoll(struct file *f)
{
	return f->f_op == &eventpoll_fops;
}

static inline int ep_is_linked(struct epitem *epi)
{
	return !list_empty(&epi->rdllink);
}

static void ep_remove_wait_queue(struct eppoll_entry *pwq)
{
	wait_queue_head_t *whead;

	rcu_read_lock();
	/*
	 * If it is cleared by POLLFREE, it should be rcu-safe.
	 * If we read NULL we need a barrier paired with
	 * smp_store_release() in ep_poll_callback(), otherwise
	 * we rely on whead->lock.
	 */
	whead = smp_load_acquire(&pwq->whead);
	if (whead)
		remove_wait_queue(whead, &pwq->wait);
	rcu_read_unlock();
}

static void ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi)
{
	struct eppoll_entry **p = &epi->pwqlist;
	struct eppoll_entry *pwq;

	while ((pwq = *p) != NULL) {
		*p = pwq->next;
		ep_remove_wait_queue(pwq);
		kmem_cache_free(pwq_cache, pwq);
	}
}

static inline struct wakeup_source *ep_wakeup_source(struct epitem *epi)
{
	return rcu_dereference_check(epi->ws, lockdep_is_held(&epi->ep->mtx));
}

extern void epi_rcu_free(struct rcu_head *head);

static struct file *epi_fget(const struct epitem *epi)
{
	struct file *file;

	file = epi->ffd.file;
	if (!atomic_long_inc_not_zero(&file->f_count))
		file = NULL;
	return file;
}

bool klpp___ep_remove(struct eventpoll *ep, struct epitem *epi, bool force)
{
	struct file *file = epi->ffd.file;
	struct epitems_head *to_free;
	struct file *pinned = NULL;
	struct hlist_head *head;

	lockdep_assert_irqs_enabled();

	/*
	 * Removes poll wait queue hooks.
	 */
	ep_unregister_pollwait(ep, epi);

	if (!force) {
		pinned = epi_fget(epi);
		if (!pinned)
			return false;
	}

	/* Remove the current item from the list of epoll hooks */
	spin_lock(&file->f_lock);

	to_free = NULL;
	head = file->f_ep;
	if (head->first == &epi->fllink && !epi->fllink.next) {
		file->f_ep = NULL;
		if (!is_file_epoll(file)) {
			struct epitems_head *v;
			v = container_of(head, struct epitems_head, epitems);
			if (!smp_load_acquire(&v->next))
				to_free = v;
		}
	}
	hlist_del_rcu(&epi->fllink);
	spin_unlock(&file->f_lock);
	free_ephead(to_free);

	rb_erase_cached(&epi->rbn, &ep->rbr);

	write_lock_irq(&ep->lock);
	if (ep_is_linked(epi))
		list_del_init(&epi->rdllink);
	write_unlock_irq(&ep->lock);

	wakeup_source_unregister(ep_wakeup_source(epi));
	/*
	 * At this point it is safe to free the eventpoll item. Use the union
	 * field epi->rcu, since we are trying to minimize the size of
	 * 'struct epitem'. The 'rbn' field is no longer in use. Protected by
	 * ep->mtx. The rcu read side, reverse_path_check_proc(), does not make
	 * use of the rbn field.
	 */
	call_rcu(&epi->rcu, epi_rcu_free);

	if (pinned)
		fput(pinned);

	percpu_counter_dec(&ep->user->epoll_watches);
	return true;
}

extern const struct file_operations eventpoll_fops

#ifdef CONFIG_PROC_FS

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
;


#include <linux/livepatch.h>

extern typeof(ephead_cache) ephead_cache
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ephead_cache);
extern typeof(epi_rcu_free) epi_rcu_free
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, epi_rcu_free);
extern typeof(eventpoll_fops) eventpoll_fops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, eventpoll_fops);
extern typeof(pwq_cache) pwq_cache KLP_RELOC_SYMBOL_POS(vmlinux, vmlinux, pwq_cache, 1);
