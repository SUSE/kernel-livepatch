/*
 * livepatch_bsc1252048
 *
 * Fix for CVE-2025-39977, bsc#1252048
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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


/* klp-ccp: from kernel/futex/requeue.c */
#include <linux/sched/signal.h>
/* klp-ccp: from kernel/futex/futex.h */
#include <linux/futex.h>
#include <linux/rtmutex.h>
#include <linux/sched/wake_q.h>
#include <linux/uaccess.h>

#ifdef CONFIG_PREEMPT_RT
#include <linux/rcuwait.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

# define FLAGS_SHARED		0x01

#ifdef CONFIG_FAIL_FUTEX
#error "klp-ccp: non-taken branch"
#else
static inline bool should_fail_futex(bool fshared)
{
	return false;
}
#endif

struct futex_hash_bucket {
	atomic_t waiters;
	spinlock_t lock;
	struct plist_head chain;
} ____cacheline_aligned_in_smp;

struct futex_pi_state {
	/*
	 * list of 'owned' pi_state instances - these have to be
	 * cleaned up in do_exit() if the task exits prematurely:
	 */
	struct list_head list;

	/*
	 * The PI object:
	 */
	struct rt_mutex_base pi_mutex;

	struct task_struct *owner;
	refcount_t refcount;

	union futex_key key;
} __randomize_layout;

struct futex_q {
	struct plist_node list;

	struct task_struct *task;
	spinlock_t *lock_ptr;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
	atomic_t requeue_state;
#ifdef CONFIG_PREEMPT_RT
	struct rcuwait requeue_wait;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
} __randomize_layout;

enum futex_access {
	FUTEX_READ,
	FUTEX_WRITE
};

extern int get_futex_key(u32 __user *uaddr, bool fshared, union futex_key *key,
			 enum futex_access rw);

extern struct futex_hash_bucket *futex_hash(union futex_key *key);

static inline int futex_match(union futex_key *key1, union futex_key *key2)
{
	return (key1 && key2
		&& key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}

extern void futex_wake_mark(struct wake_q_head *wake_q, struct futex_q *q);

extern int fault_in_user_writeable(u32 __user *uaddr);
extern struct futex_q *futex_top_waiter(struct futex_hash_bucket *hb, union futex_key *key);

static __always_inline int futex_read_inatomic(u32 *dest, u32 __user *from)
{
	u32 val;

	if (can_do_masked_user_access())
		from = masked_user_access_begin(from);
	else if (!user_read_access_begin(from, sizeof(*from)))
		return -EFAULT;
	unsafe_get_user(val, from, Efault);
	user_read_access_end();
	*dest = val;
	return 0;
Efault:
	user_read_access_end();
	return -EFAULT;
}

static inline int futex_get_value_locked(u32 *dest, u32 __user *from)
{
	int ret;

	pagefault_disable();
	ret = futex_read_inatomic(dest, from);
	pagefault_enable();

	return ret;
}

extern void __futex_unqueue(struct futex_q *q);

extern void wait_for_owner_exiting(int ret, struct task_struct *exiting);

static inline void futex_hb_waiters_inc(struct futex_hash_bucket *hb)
{
#ifdef CONFIG_SMP
	atomic_inc(&hb->waiters);
	/*
	 * Full barrier (A), see the ordering comment above.
	 */
	smp_mb__after_atomic();
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

static inline void futex_hb_waiters_dec(struct futex_hash_bucket *hb)
{
#ifdef CONFIG_SMP
	atomic_dec(&hb->waiters);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

extern int futex_lock_pi_atomic(u32 __user *uaddr, struct futex_hash_bucket *hb,
				union futex_key *key,
				struct futex_pi_state **ps,
				struct task_struct *task,
				struct task_struct **exiting,
				int set_waiters);

extern int refill_pi_state_cache(void);
extern void get_pi_state(struct futex_pi_state *pi_state);
extern void put_pi_state(struct futex_pi_state *pi_state);

static inline void
double_lock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	if (hb1 > hb2)
		swap(hb1, hb2);

	spin_lock(&hb1->lock);
	if (hb1 != hb2)
		spin_lock_nested(&hb2->lock, SINGLE_DEPTH_NESTING);
}

static inline void
double_unlock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	spin_unlock(&hb1->lock);
	if (hb1 != hb2)
		spin_unlock(&hb2->lock);
}

/* klp-ccp: from kernel/locking/rtmutex_common.h */
#include <linux/debug_locks.h>
#include <linux/rtmutex.h>
#include <linux/sched/wake_q.h>

extern int rt_mutex_start_proxy_lock(struct rt_mutex_base *lock,
				     struct rt_mutex_waiter *waiter,
				     struct task_struct *task);

/* klp-ccp: from kernel/futex/requeue.c */
enum {
	Q_REQUEUE_PI_NONE		=  0,
	Q_REQUEUE_PI_IGNORE,
	Q_REQUEUE_PI_IN_PROGRESS,
	Q_REQUEUE_PI_WAIT,
	Q_REQUEUE_PI_DONE,
	Q_REQUEUE_PI_LOCKED,
};

static inline
void requeue_futex(struct futex_q *q, struct futex_hash_bucket *hb1,
		   struct futex_hash_bucket *hb2, union futex_key *key2)
{

	/*
	 * If key1 and key2 hash to the same bucket, no need to
	 * requeue.
	 */
	if (likely(&hb1->chain != &hb2->chain)) {
		plist_del(&q->list, &hb1->chain);
		futex_hb_waiters_dec(hb1);
		futex_hb_waiters_inc(hb2);
		plist_add(&q->list, &hb2->chain);
		q->lock_ptr = &hb2->lock;
	}
	q->key = *key2;
}

static inline bool futex_requeue_pi_prepare(struct futex_q *q,
					    struct futex_pi_state *pi_state)
{
	int old, new;

	/*
	 * Set state to Q_REQUEUE_PI_IN_PROGRESS unless an early wakeup has
	 * already set Q_REQUEUE_PI_IGNORE to signal that requeue should
	 * ignore the waiter.
	 */
	old = atomic_read_acquire(&q->requeue_state);
	do {
		if (old == Q_REQUEUE_PI_IGNORE)
			return false;

		/*
		 * futex_proxy_trylock_atomic() might have set it to
		 * IN_PROGRESS and a interleaved early wake to WAIT.
		 *
		 * It was considered to have an extra state for that
		 * trylock, but that would just add more conditionals
		 * all over the place for a dubious value.
		 */
		if (old != Q_REQUEUE_PI_NONE)
			break;

		new = Q_REQUEUE_PI_IN_PROGRESS;
	} while (!atomic_try_cmpxchg(&q->requeue_state, &old, new));

	q->pi_state = pi_state;
	return true;
}

static inline void futex_requeue_pi_complete(struct futex_q *q, int locked)
{
	int old, new;

	old = atomic_read_acquire(&q->requeue_state);
	do {
		if (old == Q_REQUEUE_PI_IGNORE)
			return;

		if (locked >= 0) {
			/* Requeue succeeded. Set DONE or LOCKED */
			WARN_ON_ONCE(old != Q_REQUEUE_PI_IN_PROGRESS &&
				     old != Q_REQUEUE_PI_WAIT);
			new = Q_REQUEUE_PI_DONE + locked;
		} else if (old == Q_REQUEUE_PI_IN_PROGRESS) {
			/* Deadlock, no early wakeup interleave */
			new = Q_REQUEUE_PI_NONE;
		} else {
			/* Deadlock, early wakeup interleave. */
			WARN_ON_ONCE(old != Q_REQUEUE_PI_WAIT);
			new = Q_REQUEUE_PI_IGNORE;
		}
	} while (!atomic_try_cmpxchg(&q->requeue_state, &old, new));

#ifdef CONFIG_PREEMPT_RT
	if (unlikely(old == Q_REQUEUE_PI_WAIT))
		rcuwait_wake_up(&q->requeue_wait);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

static inline
void klpp_requeue_pi_wake_futex(struct futex_q *q, union futex_key *key,
			   struct futex_hash_bucket *hb)
{
	struct task_struct *task;

	q->key = *key;
	__futex_unqueue(q);

	WARN_ON(!q->rt_waiter);
	q->rt_waiter = NULL;

	q->lock_ptr = &hb->lock;
	task = READ_ONCE(q->task);

	/* Signal locked state to the waiter */
	futex_requeue_pi_complete(q, 1);
	wake_up_state(task, TASK_NORMAL);
}

static int
klpr_futex_proxy_trylock_atomic(u32 __user *pifutex, struct futex_hash_bucket *hb1,
			   struct futex_hash_bucket *hb2, union futex_key *key1,
			   union futex_key *key2, struct futex_pi_state **ps,
			   struct task_struct **exiting, int set_waiters)
{
	struct futex_q *top_waiter;
	u32 curval;
	int ret;

	if (futex_get_value_locked(&curval, pifutex))
		return -EFAULT;

	if (unlikely(should_fail_futex(true)))
		return -EFAULT;

	/*
	 * Find the top_waiter and determine if there are additional waiters.
	 * If the caller intends to requeue more than 1 waiter to pifutex,
	 * force futex_lock_pi_atomic() to set the FUTEX_WAITERS bit now,
	 * as we have means to handle the possible fault.  If not, don't set
	 * the bit unnecessarily as it will force the subsequent unlock to enter
	 * the kernel.
	 */
	top_waiter = futex_top_waiter(hb1, key1);

	/* There are no waiters, nothing for us to do. */
	if (!top_waiter)
		return 0;

	/*
	 * Ensure that this is a waiter sitting in futex_wait_requeue_pi()
	 * and waiting on the 'waitqueue' futex which is always !PI.
	 */
	if (!top_waiter->rt_waiter || top_waiter->pi_state)
		return -EINVAL;

	/* Ensure we requeue to the expected futex. */
	if (!futex_match(top_waiter->requeue_pi_key, key2))
		return -EINVAL;

	/* Ensure that this does not race against an early wakeup */
	if (!futex_requeue_pi_prepare(top_waiter, NULL))
		return -EAGAIN;

	/*
	 * Try to take the lock for top_waiter and set the FUTEX_WAITERS bit
	 * in the contended case or if @set_waiters is true.
	 *
	 * In the contended case PI state is attached to the lock owner. If
	 * the user space lock can be acquired then PI state is attached to
	 * the new owner (@top_waiter->task) when @set_waiters is true.
	 */
	ret = futex_lock_pi_atomic(pifutex, hb2, key2, ps, top_waiter->task,
				   exiting, set_waiters);
	if (ret == 1) {
		/*
		 * Lock was acquired in user space and PI state was
		 * attached to @top_waiter->task. That means state is fully
		 * consistent and the waiter can return to user space
		 * immediately after the wakeup.
		 */
		klpp_requeue_pi_wake_futex(top_waiter, key2, hb2);
	} else if (ret < 0) {
		/* Rewind top_waiter::requeue_state */
		futex_requeue_pi_complete(top_waiter, ret);
	} else {
		/*
		 * futex_lock_pi_atomic() did not acquire the user space
		 * futex, but managed to establish the proxy lock and pi
		 * state. top_waiter::requeue_state cannot be fixed up here
		 * because the waiter is not enqueued on the rtmutex
		 * yet. This is handled at the callsite depending on the
		 * result of rt_mutex_start_proxy_lock() which is
		 * guaranteed to be reached with this function returning 0.
		 */
	}
	return ret;
}

int klpp_futex_requeue(u32 __user *uaddr1, unsigned int flags, u32 __user *uaddr2,
		  int nr_wake, int nr_requeue, u32 *cmpval, int requeue_pi)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	int task_count = 0, ret;
	struct futex_pi_state *pi_state = NULL;
	struct futex_hash_bucket *hb1, *hb2;
	struct futex_q *this, *next;
	DEFINE_WAKE_Q(wake_q);

	if (nr_wake < 0 || nr_requeue < 0)
		return -EINVAL;

	/*
	 * When PI not supported: return -ENOSYS if requeue_pi is true,
	 * consequently the compiler knows requeue_pi is always false past
	 * this point which will optimize away all the conditional code
	 * further down.
	 */
	if (!IS_ENABLED(CONFIG_FUTEX_PI) && requeue_pi)
		return -ENOSYS;

	if (requeue_pi) {
		/*
		 * Requeue PI only works on two distinct uaddrs. This
		 * check is only valid for private futexes. See below.
		 */
		if (uaddr1 == uaddr2)
			return -EINVAL;

		/*
		 * futex_requeue() allows the caller to define the number
		 * of waiters to wake up via the @nr_wake argument. With
		 * REQUEUE_PI, waking up more than one waiter is creating
		 * more problems than it solves. Waking up a waiter makes
		 * only sense if the PI futex @uaddr2 is uncontended as
		 * this allows the requeue code to acquire the futex
		 * @uaddr2 before waking the waiter. The waiter can then
		 * return to user space without further action. A secondary
		 * wakeup would just make the futex_wait_requeue_pi()
		 * handling more complex, because that code would have to
		 * look up pi_state and do more or less all the handling
		 * which the requeue code has to do for the to be requeued
		 * waiters. So restrict the number of waiters to wake to
		 * one, and only wake it up when the PI futex is
		 * uncontended. Otherwise requeue it and let the unlock of
		 * the PI futex handle the wakeup.
		 *
		 * All REQUEUE_PI users, e.g. pthread_cond_signal() and
		 * pthread_cond_broadcast() must use nr_wake=1.
		 */
		if (nr_wake != 1)
			return -EINVAL;

		/*
		 * requeue_pi requires a pi_state, try to allocate it now
		 * without any locks in case it fails.
		 */
		if (refill_pi_state_cache())
			return -ENOMEM;
	}

retry:
	ret = get_futex_key(uaddr1, flags & FLAGS_SHARED, &key1, FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;
	ret = get_futex_key(uaddr2, flags & FLAGS_SHARED, &key2,
			    requeue_pi ? FUTEX_WRITE : FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;

	/*
	 * The check above which compares uaddrs is not sufficient for
	 * shared futexes. We need to compare the keys:
	 */
	if (requeue_pi && futex_match(&key1, &key2))
		return -EINVAL;

	hb1 = futex_hash(&key1);
	hb2 = futex_hash(&key2);

retry_private:
	futex_hb_waiters_inc(hb2);
	double_lock_hb(hb1, hb2);

	if (likely(cmpval != NULL)) {
		u32 curval;

		ret = futex_get_value_locked(&curval, uaddr1);

		if (unlikely(ret)) {
			double_unlock_hb(hb1, hb2);
			futex_hb_waiters_dec(hb2);

			ret = get_user(curval, uaddr1);
			if (ret)
				return ret;

			if (!(flags & FLAGS_SHARED))
				goto retry_private;

			goto retry;
		}
		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	if (requeue_pi) {
		struct task_struct *exiting = NULL;

		/*
		 * Attempt to acquire uaddr2 and wake the top waiter. If we
		 * intend to requeue waiters, force setting the FUTEX_WAITERS
		 * bit.  We force this here where we are able to easily handle
		 * faults rather in the requeue loop below.
		 *
		 * Updates topwaiter::requeue_state if a top waiter exists.
		 */
		ret = klpr_futex_proxy_trylock_atomic(uaddr2, hb1, hb2, &key1,
						 &key2, &pi_state,
						 &exiting, nr_requeue);

		/*
		 * At this point the top_waiter has either taken uaddr2 or
		 * is waiting on it. In both cases pi_state has been
		 * established and an initial refcount on it. In case of an
		 * error there's nothing.
		 *
		 * The top waiter's requeue_state is up to date:
		 *
		 *  - If the lock was acquired atomically (ret == 1), then
		 *    the state is Q_REQUEUE_PI_LOCKED.
		 *
		 *    The top waiter has been dequeued and woken up and can
		 *    return to user space immediately. The kernel/user
		 *    space state is consistent. In case that there must be
		 *    more waiters requeued the WAITERS bit in the user
		 *    space futex is set so the top waiter task has to go
		 *    into the syscall slowpath to unlock the futex. This
		 *    will block until this requeue operation has been
		 *    completed and the hash bucket locks have been
		 *    dropped.
		 *
		 *  - If the trylock failed with an error (ret < 0) then
		 *    the state is either Q_REQUEUE_PI_NONE, i.e. "nothing
		 *    happened", or Q_REQUEUE_PI_IGNORE when there was an
		 *    interleaved early wakeup.
		 *
		 *  - If the trylock did not succeed (ret == 0) then the
		 *    state is either Q_REQUEUE_PI_IN_PROGRESS or
		 *    Q_REQUEUE_PI_WAIT if an early wakeup interleaved.
		 *    This will be cleaned up in the loop below, which
		 *    cannot fail because futex_proxy_trylock_atomic() did
		 *    the same sanity checks for requeue_pi as the loop
		 *    below does.
		 */
		switch (ret) {
		case 0:
			/* We hold a reference on the pi state. */
			break;

		case 1:
			/*
			 * futex_proxy_trylock_atomic() acquired the user space
			 * futex. Adjust task_count.
			 */
			task_count++;
			ret = 0;
			break;

		/*
		 * If the above failed, then pi_state is NULL and
		 * waiter::requeue_state is correct.
		 */
		case -EFAULT:
			double_unlock_hb(hb1, hb2);
			futex_hb_waiters_dec(hb2);
			ret = fault_in_user_writeable(uaddr2);
			if (!ret)
				goto retry;
			return ret;
		case -EBUSY:
		case -EAGAIN:
			/*
			 * Two reasons for this:
			 * - EBUSY: Owner is exiting and we just wait for the
			 *   exit to complete.
			 * - EAGAIN: The user space value changed.
			 */
			double_unlock_hb(hb1, hb2);
			futex_hb_waiters_dec(hb2);
			/*
			 * Handle the case where the owner is in the middle of
			 * exiting. Wait for the exit to complete otherwise
			 * this task might loop forever, aka. live lock.
			 */
			wait_for_owner_exiting(ret, exiting);
			cond_resched();
			goto retry;
		default:
			goto out_unlock;
		}
	}

	plist_for_each_entry_safe(this, next, &hb1->chain, list) {
		if (task_count - nr_wake >= nr_requeue)
			break;

		if (!futex_match(&this->key, &key1))
			continue;

		/*
		 * FUTEX_WAIT_REQUEUE_PI and FUTEX_CMP_REQUEUE_PI should always
		 * be paired with each other and no other futex ops.
		 *
		 * We should never be requeueing a futex_q with a pi_state,
		 * which is awaiting a futex_unlock_pi().
		 */
		if ((requeue_pi && !this->rt_waiter) ||
		    (!requeue_pi && this->rt_waiter) ||
		    this->pi_state) {
			ret = -EINVAL;
			break;
		}

		/* Plain futexes just wake or requeue and are done */
		if (!requeue_pi) {
			if (++task_count <= nr_wake)
				futex_wake_mark(&wake_q, this);
			else
				requeue_futex(this, hb1, hb2, &key2);
			continue;
		}

		/* Ensure we requeue to the expected futex for requeue_pi. */
		if (!futex_match(this->requeue_pi_key, &key2)) {
			ret = -EINVAL;
			break;
		}

		/*
		 * Requeue nr_requeue waiters and possibly one more in the case
		 * of requeue_pi if we couldn't acquire the lock atomically.
		 *
		 * Prepare the waiter to take the rt_mutex. Take a refcount
		 * on the pi_state and store the pointer in the futex_q
		 * object of the waiter.
		 */
		get_pi_state(pi_state);

		/* Don't requeue when the waiter is already on the way out. */
		if (!futex_requeue_pi_prepare(this, pi_state)) {
			/*
			 * Early woken waiter signaled that it is on the
			 * way out. Drop the pi_state reference and try the
			 * next waiter. @this->pi_state is still NULL.
			 */
			put_pi_state(pi_state);
			continue;
		}

		ret = rt_mutex_start_proxy_lock(&pi_state->pi_mutex,
						this->rt_waiter,
						this->task);

		if (ret == 1) {
			/*
			 * We got the lock. We do neither drop the refcount
			 * on pi_state nor clear this->pi_state because the
			 * waiter needs the pi_state for cleaning up the
			 * user space value. It will drop the refcount
			 * after doing so. this::requeue_state is updated
			 * in the wakeup as well.
			 */
			klpp_requeue_pi_wake_futex(this, &key2, hb2);
			task_count++;
		} else if (!ret) {
			/* Waiter is queued, move it to hb2 */
			requeue_futex(this, hb1, hb2, &key2);
			futex_requeue_pi_complete(this, 0);
			task_count++;
		} else {
			/*
			 * rt_mutex_start_proxy_lock() detected a potential
			 * deadlock when we tried to queue that waiter.
			 * Drop the pi_state reference which we took above
			 * and remove the pointer to the state from the
			 * waiters futex_q object.
			 */
			this->pi_state = NULL;
			put_pi_state(pi_state);
			futex_requeue_pi_complete(this, ret);
			/*
			 * We stop queueing more waiters and let user space
			 * deal with the mess.
			 */
			break;
		}
	}

	/*
	 * We took an extra initial reference to the pi_state in
	 * futex_proxy_trylock_atomic(). We need to drop it here again.
	 */
	put_pi_state(pi_state);

out_unlock:
	double_unlock_hb(hb1, hb2);
	wake_up_q(&wake_q);
	futex_hb_waiters_dec(hb2);
	return ret ? ret : task_count;
}


#include "livepatch_bsc1252048.h"

#include <linux/livepatch.h>

extern typeof(__futex_unqueue) __futex_unqueue
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __futex_unqueue);
extern typeof(fault_in_user_writeable) fault_in_user_writeable
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fault_in_user_writeable);
extern typeof(futex_hash) futex_hash
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, futex_hash);
extern typeof(futex_lock_pi_atomic) futex_lock_pi_atomic
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, futex_lock_pi_atomic);
extern typeof(futex_top_waiter) futex_top_waiter
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, futex_top_waiter);
extern typeof(futex_wake_mark) futex_wake_mark
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, futex_wake_mark);
extern typeof(get_futex_key) get_futex_key
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, get_futex_key);
extern typeof(get_pi_state) get_pi_state
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, get_pi_state);
extern typeof(plist_add) plist_add KLP_RELOC_SYMBOL(vmlinux, vmlinux, plist_add);
extern typeof(plist_del) plist_del KLP_RELOC_SYMBOL(vmlinux, vmlinux, plist_del);
extern typeof(put_pi_state) put_pi_state
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, put_pi_state);
extern typeof(refill_pi_state_cache) refill_pi_state_cache
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, refill_pi_state_cache);
extern typeof(rt_mutex_start_proxy_lock) rt_mutex_start_proxy_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, rt_mutex_start_proxy_lock);
extern typeof(wait_for_owner_exiting) wait_for_owner_exiting
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, wait_for_owner_exiting);
extern typeof(wake_up_q) wake_up_q KLP_RELOC_SYMBOL(vmlinux, vmlinux, wake_up_q);
extern typeof(wake_up_state) wake_up_state
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, wake_up_state);
