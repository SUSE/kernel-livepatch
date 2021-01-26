/*
 * livepatch_bsc1180032
 *
 * Fix for CVE-2020-0466, bsc#1180032
 *
 *  Upstream commits:
 *  a9ed4a6560b8 ("epoll: Keep a reference on files added to the check list")
 *  52c479697c9b ("do_epoll_ctl(): clean the failure exits up a bit")
 *  77f4689de17c ('fix regression in "epoll: Keep a reference on files added to
 *                 the check list"')
 *
 *  SLE12-SP2 and -SP3 commits:
 *  6eb35ff0e822f86168c7a5faad011855759b0762
 *  1a639774a5b4443d245d0cc7179663e733f21bab
 *  f6204370de84459f377653aab1e33d923f74aeaf
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  0cdb1cd0694c3538b925779657239a0b857c4654
 *  e792e5dc238e6399c7f4ffee95046c1a55a14ce3
 *  d9c444f8b09bfc8333b76f94aed77cff6965bbd6
 *
 *  SLE15-SP2 commits:
 *  0b5e02e1cee898609ff591b26f92f2c4f5d5f4c4
 *  5e9b787a21be738e68cf9074bc33ef063d533c96
 *  775fe316b733168590c5382ba7ed12764b4a6336
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
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <linux/atomic.h>
#include <linux/seq_file.h>
#include <linux/compat.h>
#include <linux/rculist.h>
#include <net/busy_poll.h>

/* klp-ccp: from include/net/busy_poll.h */
#ifdef CONFIG_NET_RX_BUSY_POLL

static unsigned int (*klpe_sysctl_net_busy_poll) __read_mostly;

static inline bool klpr_net_busy_loop_on(void)
{
	return (*klpe_sysctl_net_busy_poll);
}

#else /* CONFIG_NET_RX_BUSY_POLL */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_NET_RX_BUSY_POLL */

/* klp-ccp: from fs/eventpoll.c */
#define EPOLLINOUT_BITS (POLLIN | POLLOUT)

#define EPOLLEXCLUSIVE_OK_BITS (EPOLLINOUT_BITS | POLLERR | POLLHUP | \
				EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE)

#define EP_MAX_NESTS 4

#define EP_UNACTIVE_PTR ((void *) -1L)

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;

struct nested_call_node {
	struct list_head llink;
	void *cookie;
	void *ctx;
};

struct nested_calls {
	struct list_head tasks_call_list;
	spinlock_t lock;
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

	/* Number of active wait queue attached to poll operations */
	int nwait;

	/* List containing poll wait queues */
	struct list_head pwqlist;

	/* The "container" of this item */
	struct eventpoll *ep;

	/* List header used to link this item to the "struct file" items list */
	struct list_head fllink;

	/* wakeup_source used when EPOLLWAKEUP is set */
	struct wakeup_source __rcu *ws;

	/* The structure that describe the interested events and the source fd */
	struct epoll_event event;
};

struct eventpoll {
	/* Protect the access to this structure */
	spinlock_t lock;

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
	int visited;
	struct list_head visited_list_link;

#ifdef CONFIG_NET_RX_BUSY_POLL
	unsigned int napi_id;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct eppoll_entry {
	/* List header used to link this structure to the "struct epitem" */
	struct list_head llink;

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

struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};

static long (*klpe_max_user_watches) __read_mostly;

static struct mutex (*klpe_epmutex);

static struct nested_calls (*klpe_poll_loop_ncalls);

static struct kmem_cache *(*klpe_epi_cache) __read_mostly;

static struct kmem_cache *(*klpe_pwq_cache) __read_mostly;

static struct list_head (*klpe_visited_list);

static struct list_head (*klpe_tfile_check_list);

#ifdef CONFIG_SYSCTL

#include <linux/sysctl.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SYSCTL */

static const struct file_operations (*klpe_eventpoll_fops);

static inline int klpr_is_file_epoll(struct file *f)
{
	return f->f_op == &(*klpe_eventpoll_fops);
}

static inline void ep_set_ffd(struct epoll_filefd *ffd,
			      struct file *file, int fd)
{
	ffd->file = file;
	ffd->fd = fd;
}

static inline int ep_cmp_ffd(struct epoll_filefd *p1,
			     struct epoll_filefd *p2)
{
	return (p1->file > p2->file ? +1:
	        (p1->file < p2->file ? -1 : p1->fd - p2->fd));
}

static inline int ep_is_linked(struct list_head *p)
{
	return !list_empty(p);
}

static inline int ep_op_has_event(int op)
{
	return op != EPOLL_CTL_DEL;
}

static inline void klpr_ep_set_busy_poll_napi_id(struct epitem *epi)
{
#ifdef CONFIG_NET_RX_BUSY_POLL
	struct eventpoll *ep;
	unsigned int napi_id;
	struct socket *sock;
	struct sock *sk;
	int err;

	if (!klpr_net_busy_loop_on())
		return;

	sock = sock_from_file(epi->ffd.file, &err);
	if (!sock)
		return;

	sk = sock->sk;
	if (!sk)
		return;

	napi_id = READ_ONCE(sk->sk_napi_id);
	ep = epi->ep;

	/* Non-NAPI IDs can be rejected
	 *	or
	 * Nothing to do if we already have this ID
	 */
	if (napi_id < MIN_NAPI_ID || napi_id == ep->napi_id)
		return;

	/* record NAPI ID for use in next busy poll */
	ep->napi_id = napi_id;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

static int ep_call_nested(struct nested_calls *ncalls, int max_nests,
			  int (*nproc)(void *, void *, int), void *priv,
			  void *cookie, void *ctx)
{
	int error, call_nests = 0;
	unsigned long flags;
	struct list_head *lsthead = &ncalls->tasks_call_list;
	struct nested_call_node *tncur;
	struct nested_call_node tnode;

	spin_lock_irqsave(&ncalls->lock, flags);

	/*
	 * Try to see if the current task is already inside this wakeup call.
	 * We use a list here, since the population inside this set is always
	 * very much limited.
	 */
	list_for_each_entry(tncur, lsthead, llink) {
		if (tncur->ctx == ctx &&
		    (tncur->cookie == cookie || ++call_nests > max_nests)) {
			/*
			 * Ops ... loop detected or maximum nest level reached.
			 * We abort this wake by breaking the cycle itself.
			 */
			error = -1;
			goto out_unlock;
		}
	}

	/* Add the current task and cookie to the list */
	tnode.ctx = ctx;
	tnode.cookie = cookie;
	list_add(&tnode.llink, lsthead);

	spin_unlock_irqrestore(&ncalls->lock, flags);

	/* Call the nested function */
	error = (*nproc)(priv, cookie, call_nests);

	/* Remove the current task from the list */
	spin_lock_irqsave(&ncalls->lock, flags);
	list_del(&tnode.llink);
out_unlock:
	spin_unlock_irqrestore(&ncalls->lock, flags);

	return error;
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#error "klp-ccp: non-taken branch"
#else

static void ep_poll_safewake(wait_queue_head_t *wq)
{
	wake_up_poll(wq, POLLIN);
}

#endif

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

static void klpr_ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi)
{
	struct list_head *lsthead = &epi->pwqlist;
	struct eppoll_entry *pwq;

	while (!list_empty(lsthead)) {
		pwq = list_first_entry(lsthead, struct eppoll_entry, llink);

		list_del(&pwq->llink);
		ep_remove_wait_queue(pwq);
		kmem_cache_free((*klpe_pwq_cache), pwq);
	}
}

static inline struct wakeup_source *ep_wakeup_source(struct epitem *epi)
{
	return rcu_dereference_check(epi->ws, lockdep_is_held(&epi->ep->mtx));
}

static inline void ep_pm_stay_awake(struct epitem *epi)
{
	struct wakeup_source *ws = ep_wakeup_source(epi);

	if (ws)
		__pm_stay_awake(ws);
}

static inline bool ep_has_wakeup_source(struct epitem *epi)
{
	return rcu_access_pointer(epi->ws) ? true : false;
}

static int ep_scan_ready_list(struct eventpoll *ep,
			      int (*sproc)(struct eventpoll *,
					   struct list_head *, void *),
			      void *priv, int depth, bool ep_locked)
{
	int error, pwake = 0;
	unsigned long flags;
	struct epitem *epi, *nepi;
	LIST_HEAD(txlist);

	/*
	 * We need to lock this because we could be hit by
	 * eventpoll_release_file() and epoll_ctl().
	 */

	if (!ep_locked)
		mutex_lock_nested(&ep->mtx, depth);

	/*
	 * Steal the ready list, and re-init the original one to the
	 * empty list. Also, set ep->ovflist to NULL so that events
	 * happening while looping w/out locks, are not lost. We cannot
	 * have the poll callback to queue directly on ep->rdllist,
	 * because we want the "sproc" callback to be able to do it
	 * in a lockless way.
	 */
	spin_lock_irqsave(&ep->lock, flags);
	list_splice_init(&ep->rdllist, &txlist);
	ep->ovflist = NULL;
	spin_unlock_irqrestore(&ep->lock, flags);

	/*
	 * Now call the callback function.
	 */
	error = (*sproc)(ep, &txlist, priv);

	spin_lock_irqsave(&ep->lock, flags);
	/*
	 * During the time we spent inside the "sproc" callback, some
	 * other events might have been queued by the poll callback.
	 * We re-insert them inside the main ready-list here.
	 */
	for (nepi = ep->ovflist; (epi = nepi) != NULL;
	     nepi = epi->next, epi->next = EP_UNACTIVE_PTR) {
		/*
		 * We need to check if the item is already in the list.
		 * During the "sproc" callback execution time, items are
		 * queued into ->ovflist but the "txlist" might already
		 * contain them, and the list_splice() below takes care of them.
		 */
		if (!ep_is_linked(&epi->rdllink)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);
		}
	}
	/*
	 * We need to set back ep->ovflist to EP_UNACTIVE_PTR, so that after
	 * releasing the lock, events will be queued in the normal way inside
	 * ep->rdllist.
	 */
	ep->ovflist = EP_UNACTIVE_PTR;

	/*
	 * Quickly re-inject items left on "txlist".
	 */
	list_splice(&txlist, &ep->rdllist);
	__pm_relax(ep->ws);

	if (!list_empty(&ep->rdllist)) {
		/*
		 * Wake up (if active) both the eventpoll wait list and
		 * the ->poll() wait list (delayed after we release the lock).
		 */
		if (waitqueue_active(&ep->wq))
			wake_up_locked(&ep->wq);
		if (waitqueue_active(&ep->poll_wait))
			pwake++;
	}
	spin_unlock_irqrestore(&ep->lock, flags);

	if (!ep_locked)
		mutex_unlock(&ep->mtx);

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return error;
}

static int (*klpe_ep_remove)(struct eventpoll *ep, struct epitem *epi);

static int (*klpe_ep_read_events_proc)(struct eventpoll *ep, struct list_head *head,
			       void *priv);
static void (*klpe_ep_ptable_queue_proc)(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt);

static unsigned int klpr_ep_item_poll(struct epitem *epi, poll_table *pt, int depth)
{
	struct eventpoll *ep;
	bool locked;

	pt->_key = epi->event.events;
	if (!klpr_is_file_epoll(epi->ffd.file))
		return epi->ffd.file->f_op->poll(epi->ffd.file, pt) &
		       epi->event.events;

	ep = epi->ffd.file->private_data;
	poll_wait(epi->ffd.file, &ep->poll_wait, pt);
	locked = pt && (pt->_qproc == (*klpe_ep_ptable_queue_proc));

	return ep_scan_ready_list(epi->ffd.file->private_data,
				  (*klpe_ep_read_events_proc), &depth, depth,
				  locked) & epi->event.events;
}

static int (*klpe_ep_read_events_proc)(struct eventpoll *ep, struct list_head *head,
			       void *priv);

static const struct file_operations (*klpe_eventpoll_fops);

static struct epitem *ep_find(struct eventpoll *ep, struct file *file, int fd)
{
	int kcmp;
	struct rb_node *rbp;
	struct epitem *epi, *epir = NULL;
	struct epoll_filefd ffd;

	ep_set_ffd(&ffd, file, fd);
	for (rbp = ep->rbr.rb_root.rb_node; rbp; ) {
		epi = rb_entry(rbp, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&ffd, &epi->ffd);
		if (kcmp > 0)
			rbp = rbp->rb_right;
		else if (kcmp < 0)
			rbp = rbp->rb_left;
		else {
			epir = epi;
			break;
		}
	}

	return epir;
}

static void (*klpe_ep_ptable_queue_proc)(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt);

static void ep_rbtree_insert(struct eventpoll *ep, struct epitem *epi)
{
	int kcmp;
	struct rb_node **p = &ep->rbr.rb_root.rb_node, *parent = NULL;
	struct epitem *epic;
	bool leftmost = true;

	while (*p) {
		parent = *p;
		epic = rb_entry(parent, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&epi->ffd, &epic->ffd);
		if (kcmp > 0) {
			p = &parent->rb_right;
			leftmost = false;
		} else
			p = &parent->rb_left;
	}
	rb_link_node(&epi->rbn, parent, p);
	rb_insert_color_cached(&epi->rbn, &ep->rbr, leftmost);
}

#define PATH_ARR_SIZE 5

static int (*klpe_path_count)[PATH_ARR_SIZE];

static void klpr_path_count_init(void)
{
	int i;

	for (i = 0; i < PATH_ARR_SIZE; i++)
		(*klpe_path_count)[i] = 0;
}

static int (*klpe_reverse_path_check_proc)(void *priv, void *cookie, int call_nests);

static int klpr_reverse_path_check(void)
{
	int error = 0;
	struct file *current_file;

	/* let's call this for all tfiles */
	list_for_each_entry(current_file, &(*klpe_tfile_check_list), f_tfile_llink) {
		klpr_path_count_init();
		error = ep_call_nested(&(*klpe_poll_loop_ncalls), EP_MAX_NESTS,
					(*klpe_reverse_path_check_proc), current_file,
					current_file, current);
		if (error)
			break;
	}
	return error;
}

static int (*klpe_ep_create_wakeup_source)(struct epitem *epi);

static void (*klpe_ep_destroy_wakeup_source)(struct epitem *epi);

static int klpr_ep_insert(struct eventpoll *ep, struct epoll_event *event,
		     struct file *tfile, int fd, int full_check)
{
	int error, revents, pwake = 0;
	unsigned long flags;
	long user_watches;
	struct epitem *epi;
	struct ep_pqueue epq;

	user_watches = atomic_long_read(&ep->user->epoll_watches);
	if (unlikely(user_watches >= (*klpe_max_user_watches)))
		return -ENOSPC;
	if (!(epi = kmem_cache_alloc((*klpe_epi_cache), GFP_KERNEL)))
		return -ENOMEM;

	/* Item initialization follow here ... */
	INIT_LIST_HEAD(&epi->rdllink);
	INIT_LIST_HEAD(&epi->fllink);
	INIT_LIST_HEAD(&epi->pwqlist);
	epi->ep = ep;
	ep_set_ffd(&epi->ffd, tfile, fd);
	epi->event = *event;
	epi->nwait = 0;
	epi->next = EP_UNACTIVE_PTR;
	if (epi->event.events & EPOLLWAKEUP) {
		error = (*klpe_ep_create_wakeup_source)(epi);
		if (error)
			goto error_create_wakeup_source;
	} else {
		RCU_INIT_POINTER(epi->ws, NULL);
	}

	/* Initialize the poll table using the queue callback */
	epq.epi = epi;
	init_poll_funcptr(&epq.pt, (*klpe_ep_ptable_queue_proc));

	/*
	 * Attach the item to the poll hooks and get current event bits.
	 * We can safely use the file* here because its usage count has
	 * been increased by the caller of this function. Note that after
	 * this operation completes, the poll callback can start hitting
	 * the new item.
	 */
	revents = klpr_ep_item_poll(epi, &epq.pt, 1);

	/*
	 * We have to check if something went wrong during the poll wait queue
	 * install process. Namely an allocation for a wait queue failed due
	 * high memory pressure.
	 */
	error = -ENOMEM;
	if (epi->nwait < 0)
		goto error_unregister;

	/* Add the current item to the list of active epoll hook for this file */
	spin_lock(&tfile->f_lock);
	list_add_tail_rcu(&epi->fllink, &tfile->f_ep_links);
	spin_unlock(&tfile->f_lock);

	/*
	 * Add the current item to the RB tree. All RB tree operations are
	 * protected by "mtx", and ep_insert() is called with "mtx" held.
	 */
	ep_rbtree_insert(ep, epi);

	/* now check if we've created too many backpaths */
	error = -EINVAL;
	if (full_check && klpr_reverse_path_check())
		goto error_remove_epi;

	/* We have to drop the new item inside our item list to keep track of it */
	spin_lock_irqsave(&ep->lock, flags);

	/* record NAPI ID of new item if present */
	klpr_ep_set_busy_poll_napi_id(epi);

	/* If the file is already "ready" we drop it inside the ready list */
	if ((revents & event->events) && !ep_is_linked(&epi->rdllink)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);
		ep_pm_stay_awake(epi);

		/* Notify waiting tasks that events are available */
		if (waitqueue_active(&ep->wq))
			wake_up_locked(&ep->wq);
		if (waitqueue_active(&ep->poll_wait))
			pwake++;
	}

	spin_unlock_irqrestore(&ep->lock, flags);

	atomic_long_inc(&ep->user->epoll_watches);

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return 0;

error_remove_epi:
	spin_lock(&tfile->f_lock);
	list_del_rcu(&epi->fllink);
	spin_unlock(&tfile->f_lock);

	rb_erase_cached(&epi->rbn, &ep->rbr);

error_unregister:
	klpr_ep_unregister_pollwait(ep, epi);

	/*
	 * We need to do this because an event could have been arrived on some
	 * allocated wait queue. Note that we don't care about the ep->ovflist
	 * list, since that is used/cleaned only inside a section bound by "mtx".
	 * And ep_insert() is called with "mtx" held.
	 */
	spin_lock_irqsave(&ep->lock, flags);
	if (ep_is_linked(&epi->rdllink))
		list_del_init(&epi->rdllink);
	spin_unlock_irqrestore(&ep->lock, flags);

	wakeup_source_unregister(ep_wakeup_source(epi));

error_create_wakeup_source:
	kmem_cache_free((*klpe_epi_cache), epi);

	return error;
}

static int klpr_ep_modify(struct eventpoll *ep, struct epitem *epi, struct epoll_event *event)
{
	int pwake = 0;
	unsigned int revents;
	poll_table pt;

	init_poll_funcptr(&pt, NULL);

	/*
	 * Set the new event interest mask before calling f_op->poll();
	 * otherwise we might miss an event that happens between the
	 * f_op->poll() call and the new event set registering.
	 */
	epi->event.events = event->events; /* need barrier below */
	epi->event.data = event->data; /* protected by mtx */
	if (epi->event.events & EPOLLWAKEUP) {
		if (!ep_has_wakeup_source(epi))
			(*klpe_ep_create_wakeup_source)(epi);
	} else if (ep_has_wakeup_source(epi)) {
		(*klpe_ep_destroy_wakeup_source)(epi);
	}

	/*
	 * The following barrier has two effects:
	 *
	 * 1) Flush epi changes above to other CPUs.  This ensures
	 *    we do not miss events from ep_poll_callback if an
	 *    event occurs immediately after we call f_op->poll().
	 *    We need this because we did not take ep->lock while
	 *    changing epi above (but ep_poll_callback does take
	 *    ep->lock).
	 *
	 * 2) We also need to ensure we do not miss _past_ events
	 *    when calling f_op->poll().  This barrier also
	 *    pairs with the barrier in wq_has_sleeper (see
	 *    comments for wq_has_sleeper).
	 *
	 * This barrier will now guarantee ep_poll_callback or f_op->poll
	 * (or both) will notice the readiness of an item.
	 */
	smp_mb();

	/*
	 * Get current event bits. We can safely use the file* here because
	 * its usage count has been increased by the caller of this function.
	 */
	revents = klpr_ep_item_poll(epi, &pt, 1);

	/*
	 * If the item is "hot" and it is not registered inside the ready
	 * list, push it inside.
	 */
	if (revents & event->events) {
		spin_lock_irq(&ep->lock);
		if (!ep_is_linked(&epi->rdllink)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);

			/* Notify waiting tasks that events are available */
			if (waitqueue_active(&ep->wq))
				wake_up_locked(&ep->wq);
			if (waitqueue_active(&ep->poll_wait))
				pwake++;
		}
		spin_unlock_irq(&ep->lock);
	}

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return 0;
}

static int klpp_ep_loop_check_proc(void *priv, void *cookie, int call_nests)
{
	int error = 0;
	struct file *file = priv;
	struct eventpoll *ep = file->private_data;
	struct eventpoll *ep_tovisit;
	struct rb_node *rbp;
	struct epitem *epi;

	mutex_lock_nested(&ep->mtx, call_nests + 1);
	ep->visited = 1;
	list_add(&ep->visited_list_link, &(*klpe_visited_list));
	for (rbp = rb_first_cached(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		epi = rb_entry(rbp, struct epitem, rbn);
		if (unlikely(klpr_is_file_epoll(epi->ffd.file))) {
			ep_tovisit = epi->ffd.file->private_data;
			if (ep_tovisit->visited)
				continue;
			error = ep_call_nested(&(*klpe_poll_loop_ncalls), EP_MAX_NESTS,
					klpp_ep_loop_check_proc, epi->ffd.file,
					ep_tovisit, current);
			if (error != 0)
				break;
		} else {
			/*
			 * If we've reached a file that is not associated with
			 * an ep, then we need to check if the newly added
			 * links are going to add too many wakeup paths. We do
			 * this by adding it to the tfile_check_list, if it's
			 * not already there, and calling reverse_path_check()
			 * during ep_insert().
			 */
			/*
			 * Fix CVE-2020-0466
			 *  -3 lines, +5 lines
			 */
			if (list_empty(&epi->ffd.file->f_tfile_llink)) {
				if (get_file_rcu(epi->ffd.file))
					list_add(&epi->ffd.file->f_tfile_llink,
						 &(*klpe_tfile_check_list));
			}
		}
	}
	mutex_unlock(&ep->mtx);

	return error;
}

static int klpr_ep_loop_check(struct eventpoll *ep, struct file *file)
{
	int ret;
	struct eventpoll *ep_cur, *ep_next;

	ret = ep_call_nested(&(*klpe_poll_loop_ncalls), EP_MAX_NESTS,
			      klpp_ep_loop_check_proc, file, ep, current);
	/* clear visited list */
	list_for_each_entry_safe(ep_cur, ep_next, &(*klpe_visited_list),
							visited_list_link) {
		ep_cur->visited = 0;
		list_del(&ep_cur->visited_list_link);
	}
	return ret;
}

static void klpp_clear_tfile_check_list(void)
{
	struct file *file;

	/* first clear the tfile_check_list */
	while (!list_empty(&(*klpe_tfile_check_list))) {
		file = list_first_entry(&(*klpe_tfile_check_list), struct file,
					f_tfile_llink);
		list_del_init(&file->f_tfile_llink);
		/*
		 * Fix CVE-2020-0466
		 *  +1 line
		 */
		fput(file);
	}
	INIT_LIST_HEAD(&(*klpe_tfile_check_list));
}

__SYSCALL_DEFINEx(4, _klpp_epoll_ctl, int, epfd, int, op, int, fd,
		  struct epoll_event __user *, event)
{
	int error;
	int full_check = 0;
	struct fd f, tf;
	struct eventpoll *ep;
	struct epitem *epi;
	struct epoll_event epds;
	struct eventpoll *tep = NULL;

	error = -EFAULT;
	if (ep_op_has_event(op) &&
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		goto error_return;

	error = -EBADF;
	f = fdget(epfd);
	if (!f.file)
		goto error_return;

	/* Get the "struct file *" for the target file */
	tf = fdget(fd);
	if (!tf.file)
		goto error_fput;

	/* The target file descriptor must support poll */
	error = -EPERM;
	if (!tf.file->f_op->poll)
		goto error_tgt_fput;

	/* Check if EPOLLWAKEUP is allowed */
	if (ep_op_has_event(op))
		ep_take_care_of_epollwakeup(&epds);

	/*
	 * We have to check that the file structure underneath the file descriptor
	 * the user passed to us _is_ an eventpoll file. And also we do not permit
	 * adding an epoll file descriptor inside itself.
	 */
	error = -EINVAL;
	if (f.file == tf.file || !klpr_is_file_epoll(f.file))
		goto error_tgt_fput;

	/*
	 * epoll adds to the wakeup queue at EPOLL_CTL_ADD time only,
	 * so EPOLLEXCLUSIVE is not allowed for a EPOLL_CTL_MOD operation.
	 * Also, we do not currently supported nested exclusive wakeups.
	 */
	if (ep_op_has_event(op) && (epds.events & EPOLLEXCLUSIVE)) {
		if (op == EPOLL_CTL_MOD)
			goto error_tgt_fput;
		if (op == EPOLL_CTL_ADD && (klpr_is_file_epoll(tf.file) ||
				(epds.events & ~EPOLLEXCLUSIVE_OK_BITS)))
			goto error_tgt_fput;
	}

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = f.file->private_data;

	/*
	 * When we insert an epoll file descriptor, inside another epoll file
	 * descriptor, there is the change of creating closed loops, which are
	 * better be handled here, than in more critical paths. While we are
	 * checking for loops we also determine the list of files reachable
	 * and hang them on the tfile_check_list, so we can check that we
	 * haven't created too many possible wakeup paths.
	 *
	 * We do not need to take the global 'epumutex' on EPOLL_CTL_ADD when
	 * the epoll file descriptor is attaching directly to a wakeup source,
	 * unless the epoll file descriptor is nested. The purpose of taking the
	 * 'epmutex' on add is to prevent complex toplogies such as loops and
	 * deep wakeup paths from forming in parallel through multiple
	 * EPOLL_CTL_ADD operations.
	 */
	mutex_lock_nested(&ep->mtx, 0);
	if (op == EPOLL_CTL_ADD) {
		if (!list_empty(&f.file->f_ep_links) ||
						klpr_is_file_epoll(tf.file)) {
			full_check = 1;
			mutex_unlock(&ep->mtx);
			mutex_lock(&(*klpe_epmutex));
			/*
			 * Fix CVE-2020-0466
			 *  +6 lines
			 *
			 * Livepatch specific paranoia check that
			 * tfile_check_list is indeed empty upon
			 * entry. Note that unlike it is the case with
			 * upstream, this is true for the livepatched
			 * kernels, in particular a backport of
			 * upstream commit 52c479697c9b
			 * ("do_epoll_ctl(): clean the failure exits
			 * up a bit") isn't really needed for
			 * correctness.
			 */
			if (WARN_ON_ONCE(!list_empty(&(*klpe_tfile_check_list)))) {
				mutex_unlock(&(*klpe_epmutex));
				fdput(tf);
				fdput(f);
				return -EINVAL;
			}
			if (klpr_is_file_epoll(tf.file)) {
				error = -ELOOP;
				if (klpr_ep_loop_check(ep, tf.file) != 0) {
					/*
					 * Fix CVE-2020-0466
					 *  -1 line
					 */
					goto error_tgt_fput;
				}
			/*
			 * Fix CVE-2020-0466
			 *  -3 lines, +5 lines
			 */
			} else {
				get_file(tf.file);
				list_add(&tf.file->f_tfile_llink,
							&(*klpe_tfile_check_list));
			}
			mutex_lock_nested(&ep->mtx, 0);
			if (klpr_is_file_epoll(tf.file)) {
				tep = tf.file->private_data;
				mutex_lock_nested(&tep->mtx, 1);
			}
		}
	}

	/*
	 * Try to lookup the file inside our RB tree, Since we grabbed "mtx"
	 * above, we can be sure to be able to use the item looked up by
	 * ep_find() till we release the mutex.
	 */
	epi = ep_find(ep, tf.file, fd);

	error = -EINVAL;
	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds.events |= POLLERR | POLLHUP;
			error = klpr_ep_insert(ep, &epds, tf.file, fd, full_check);
		} else
			error = -EEXIST;
		/*
		 * Fix CVE-2020-0466
		 *  -2 lines
		 */
		break;
	case EPOLL_CTL_DEL:
		if (epi)
			error = (*klpe_ep_remove)(ep, epi);
		else
			error = -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			if (!(epi->event.events & EPOLLEXCLUSIVE)) {
				epds.events |= POLLERR | POLLHUP;
				error = klpr_ep_modify(ep, epi, &epds);
			}
		} else
			error = -ENOENT;
		break;
	}
	if (tep != NULL)
		mutex_unlock(&tep->mtx);
	mutex_unlock(&ep->mtx);

error_tgt_fput:
	/*
	 * Fix CVE-2020-0466
	 *  -2 lines, +4 lines
	 */
	if (full_check) {
		klpp_clear_tfile_check_list();
		mutex_unlock(&(*klpe_epmutex));
	}

	fdput(tf);
error_fput:
	fdput(f);
error_return:

	return error;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1180032.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "epi_cache", (void *)&klpe_epi_cache },
	{ "max_user_watches", (void *)&klpe_max_user_watches },
	{ "visited_list", (void *)&klpe_visited_list },
	{ "poll_loop_ncalls", (void *)&klpe_poll_loop_ncalls },
	{ "sysctl_net_busy_poll", (void *)&klpe_sysctl_net_busy_poll },
	{ "eventpoll_fops", (void *)&klpe_eventpoll_fops },
	{ "tfile_check_list", (void *)&klpe_tfile_check_list },
	{ "pwq_cache", (void *)&klpe_pwq_cache, .sympos = 1 },
	{ "epmutex", (void *)&klpe_epmutex },
	{ "path_count", (void *)&klpe_path_count },
	{ "ep_read_events_proc", (void *)&klpe_ep_read_events_proc },
	{ "ep_remove", (void *)&klpe_ep_remove },
	{ "ep_ptable_queue_proc", (void *)&klpe_ep_ptable_queue_proc },
	{ "ep_create_wakeup_source", (void *)&klpe_ep_create_wakeup_source },
	{ "reverse_path_check_proc", (void *)&klpe_reverse_path_check_proc },
	{ "ep_destroy_wakeup_source", (void *)&klpe_ep_destroy_wakeup_source },
};

int livepatch_bsc1180032_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
