/*
 * livepatch_bsc1176012
 *
 * Fix for CVE-2020-14381, bsc#1176012 and CVE-2021-3347, bsc#1181553
 *
 *  Upstream commit for CVE-2020-14381:
 *  8019ad13ef7f ("futex: Fix inode life-time issue")
 *
 *  SLE12-SP2 and -SP3 commit for CVE-2020-14381:
 *  804983cf0756bc6715608a9e1adeb18d46f892c4
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit for CVE-2020-14381:
 *  0091d772bf287fec3a2e84ada01e5510e22ce46c
 *  7c2a3c29f3c6779e6b82570110c6f9b45d6010cd
 *
 *  SLE15-SP2 commit for CVE-2020-14381:
 *  aa54a719ea49abb6f11166239cecd36a7ab6a5c1
 *
 *
 *  Upstream commits for CVE-2021-3347:
 *  6b4f4bc9cb22 ("locking/futex: Allow low-level atomic operations to return
 *                 -EAGAIN")
 *  9f5d1c336a10 ("futex: Handle transient "ownerless" rtmutex state correctly")
 *  1e106aa3509b ("futex: Don't enable IRQs unconditionally in put_pi_state()")
 *  12bb3f7f1b03 ("futex: Ensure the correct return value from futex_lock_pi()")
 *  04b79c55201f ("futex: Replace pointless printk in fixup_owner()")
 *  c5cade200ab9 ("futex: Provide and use pi_state_update_owner()")
 *  2156ac193416 ("rtmutex: Remove unused argument
 *                 from rt_mutex_proxy_unlock()")
 *  6ccc84f917d3 ("futex: Use pi_state_update_owner() in put_pi_state()")
 *  f2dac39d9398 ("futex: Simplify fixup_pi_state_owner()")
 *  34b1a1ce1458 ("futex: Handle faults correctly for PI futexes")
 *
 *  SLE12-SP2 and SLE12-SP3 commits for CVE-2021-3347:
 *  73663d8a45b8328532b7901c0cfcfa8ed9ee67d4
 *  e1fc006ef66520c31fab2b9572bb04a979a5844f
 *  6c60412b2792170920b3db5b9879f12c5784ff9b
 *  e2c6d647fe6c7c346c786d8bc37579ed9feee4a6
 *  c87ed53d465c9e4a9dcd636d9c154c8777f8f84f
 *  553c1a3c1fba0de86c8e5c0064aece6966e27fcf
 *  3307ee69c9e29f4c72dba1e6779b45ba0799d472
 *  c188bc685cc781f4ed4431d53e12f23b4419b45e
 *  0f091912e862f7546d0cea60511b148d3dac07d4
 *  eaeb5cd80af07b2d9712e1938d68c5bbc6f4c8ca
 *  51a6ea0a9d6c232ee255c3d98a9007c7b6d4d66a
 *  73b507f89bd348bd41f27851302231340aa52887
 *  446b9bf34bc2f33816f3c71294f2b80b7869262b
 *  d0d92ebb8860e7713969d2ae23c53f68f1bdd344
 *  5c581f525fb2fc6523bfd7a770a9ee62a5ba1b7a
 *  727868366c01c7bce4bf232a09040d9b6e16aee0
 *  51eb6990c7c9403e5c82e0a66144e0ff6e1e952a
 *  e5f413c12d8a83b344d9bc33f34e4dcc8651514c
 *  06c33b17abd7d05ee0635d82c8f80aad8390a646
 *  f588b4ec2e87427c8bd29b80223da02c2e0eff45
 *  c1bd2314b241715d82fd0751dd5670aeab3fec60
 *  437ab1569581cfbb28e3ec0dd6a50a7af77c2eca
 *  ac0d9a151b33ca176e82f6f00bc364cf98ed144c
 *  3ea3e69e54b9a840b5b622db069077638f909343
 *  c41659a772085fb6649530e45049b039bb2d9d99
 *  cce36b88cbc54aba3a02290f679f2a57f61d6c16 (SLE12-SP3 only)
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits for CVE-2021-3347:
 *  60003eaf0885b9ae01d18e45fad2e11934d9d6bf (SLE12-SP5 + SLE15-SP1 only)
 *  96fc4b89769eb37be05dc1d7f07b54c04b3731a1 (SLE12-SP5 + SLE15-SP1 only)
 *  19b7ad52837a6281d19ae1dcc91ecbd22bb03325
 *  47116ff320dc436a77570fad745e0785210fd747
 *  d60800efe414ee57d3305259dbaf3f42131ef550
 *  122df43674e1e0694534cc7116657393846f5de8
 *  2081c4c509b3bbd88d9b1c4598cb22e8a8f6620d
 *  3c34595ba02bbee6c84ea4599bf31d9af344d969
 *  e293043c889a8925020e385c2182c69741748ec5
 *  ccacb1085ee9ff6d34a44e28155d80c2364366fa
 *  058c695a81a3a15d89b90958840af8e50d7e8cbd
 *  0ba69a9af32cc3575877623dbb7592b0b18aedcb
 *  424d8c77978886d7ee7481092ca298f8a49e53f1 (SLE15 only)
 *  901da74cd86e5a11c37b8db6471340a11420e830 (SLE12-SP5 + SLE15-SP1 only)
 *  96704b75162d319ec38238229e19ed2539061656 (SLE12-SP5 + SLE15-SP1 only)
 *
 *  SLE15-SP2 commits for CVE-2021-3347:
 *  1f84aa83d29b61762e93e69ba813d06d69d0129a
 *  15c899ad75e036f3345e0d2ceab13ef0dc4c40e4
 *  3e3a93fcbd64b7a9326cbb15256e6f395cd6110a
 *  5928ceda161395b4ab5d0cc926440891ebc7e294
 *  00c28bf548b6497abb3bd30caedef7c3eb22f3e8
 *  40403938aca364fbe138d252266284bdaeb3db91
 *  df16641065ad91f8ba36f471d823819e7f5a439a
 *  b1c5ed250bd4d8817c4d367492e422a6d76f836b
 *  72f29b4ee6719d2f1dc2fd28ea1c3932d07648b6
 *  ceb865c876c4e6661dc4d65bf43f49971535cc6c
 *  8a00d32516a676e9ee022c8c857f680229017856
 *
 *
 *  Copyright (c) 2020, 2021 SUSE
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/livepatch.h>
#include <linux/file.h>

#include "livepatch_bsc1176012.h"
#include "../kallsyms_relocs.h"
#include "../shadow.h"

#define KLP_BSC1176012_SHARED_STATE_ID KLP_SHADOW_ID(1176012, 0)

/*
 * Maintain a list of compatible patches in a shared shadow variable.
 * Protected by module_mutex.
 */
struct klp_bsc1176012_shared_state
{
	struct spinlock lock;
	struct list_head compatible_patches;
};

static struct klp_bsc1176012_shared_state *klp_bsc1176012_shared_state;

struct klp_bsc1176012_compatible_patch
{
	struct list_head list;
	struct module * const patch_mod;
};

/*
 * New, livepatch specific. Check whether a given klp_patch->mod is on
 * klp_bsc1176012_shared_state's list of registered compatible
 * patches.
 */
static bool klpp_patch_is_compatible(struct module *m)
{
	bool found = false;
	struct klp_bsc1176012_compatible_patch *p;

	spin_lock(&klp_bsc1176012_shared_state->lock);
	list_for_each_entry(p, &klp_bsc1176012_shared_state->compatible_patches,
			    list) {
		if (p->patch_mod == m) {
			found = true;
			break;
		}
	}
	spin_unlock(&klp_bsc1176012_shared_state->lock);

	return found;
}

static struct klp_patch *(*klpe_klp_transition_patch);
static struct list_head (*klpe_klp_patches);

/*
 * New, livepatch specific. Check whether some task queued on some
 * futex is in a compatible livepatching state.
 *
 * Must be called only on current or on tasks on a futex_hash_bucket
 * list with the bucket ->lock being held.
 */
static bool klpp_task_is_compatible(struct task_struct *t)
{
	int cur_patch_state, other_patch_state;
	struct klp_patch *patch;
	struct list_head *prev;
	struct module *patch_mod;

	if (t == current)
		return true;

	/*
	 * Task t has put itself on some futex_hash_bucket for which
	 * it had to acquire + release its ->lock. It might have been
	 * requeued to another bucket in the meanwhile, but each time
	 * the resp. locks had been taken. The current task now owns
	 * the ->lock of the bucket the task t is currently queued on
	 * and thus, this sequence forms a release-acquire chain from
	 * the ->lock release of the initial enqueueing operation up
	 * to the ->lock acquire from the current task. Furthermore,
	 * note that a task on the locked futex_hash_bucket won't exit
	 * the livepatched set (it can't proceed to unqueue itself)
	 * and thus, its livepatch transition, if any, can't have
	 * completed inbetween entering the patched set and now. These
	 * two facts together imply that if task t's prior execution
	 * of klp_ftrace_handler(), if any, observed a value of
	 * KLP_PATCHED or KLP_UNPATCHED for t->patch_state, then we'll
	 * read the very same value below.
	 */

	cur_patch_state = READ_ONCE(current->patch_state);
	/* Sanity check to cover partial writes. Should not happen. */
	if (cur_patch_state != KLP_UNDEFINED &&
	    cur_patch_state != KLP_PATCHED &&
	    cur_patch_state != KLP_UNPATCHED) {
		return false;
	}

	if (likely(cur_patch_state == KLP_UNDEFINED)) {
		/*
		 * A patch transition might currently be about to
		 * start and t->patch_state can be anything. However,
		 * the klp_funcs' ->transition gets set only after all
		 * ->patch_states have been initialized and there's a
		 * smp_wmb() issued inbetween. Thus, as per the memory
		 * ordering imposed by the futex_hash_bucket ->lock,
		 * task t's klp_ftrace_handler() execution, if any,
		 * cannot have observed func->transition ==
		 * true. Thus, t is executing within the very same
		 * livepatch.
		 */
		return true;
	}

	other_patch_state = READ_ONCE(t->patch_state);
	/* Sanity check to cover partial writes. Should not happen. */
	if (other_patch_state != KLP_UNDEFINED &&
	    other_patch_state != KLP_PATCHED &&
	    other_patch_state != KLP_UNPATCHED) {
		return false;
	}

	if (cur_patch_state == KLP_UNPATCHED) {
		/*
		 * A transition to another livepatch is about to get
		 * started or already in progress. The transition
		 * might have been reversed, but this doesn't matter.
		 */
		if (other_patch_state != KLP_PATCHED) {
			/*
			 * Note that if other_patch_state == KLP_UNDEFINED,
			 * then the prior klp_ftrace_handler() executed in
			 * the context of current cannot have observed
			 * func->transition == true. As per the
			 * release-acquire chain on futex_hash_bucket ->lock,
			 * the same holds for the klp_ftrace_handler()
			 * previously executed in the context of task t, if
			 * any. Thus, the KLP_UNDEFINED case is
			 * equivalent to the KLP_UNPATCHED case here.
			 */
			return true;
		}

		/*
		 * Task t has been switched over and that must have
		 * happened before it entered the livepatched set,
		 * i.e. before its execution of
		 * klp_ftrace_handler(). So the latter did observe
		 * func->transition == true. Furthermore, as per the
		 * release-acquire semanics of the futex_hash_bucket
		 * ->lock, we can observe the previously written value
		 * of klp_transition_patch here and it's stable,
		 * because the current task can't get transitioned.
		 */
		patch = READ_ONCE(*klpe_klp_transition_patch);
		if (!patch) {
			/* Should not happen, but better be safe than sorry. */
			return false;
		}
		/*
		 * In principle it should be safe to read from
		 * patch->mod directly. However, be paranoid.
		 */
		if (probe_kernel_read(&patch_mod, &patch->mod,
				      sizeof(patch_mod)) < 0) {
			return false;
		}

		return klpp_patch_is_compatible(patch_mod);
	}

	/*
	 * The remaining case is cur_patch_state == KLP_PATCHED, which
	 * implies that either a pending transition to the livepatch
	 * provided by THIS_MODULE has completed for the current task
	 * or that an unpatch operation is about to get started or
	 * already in progress.
	 */
	if (other_patch_state != KLP_UNPATCHED) {
		/*
		 * For KLP_UNDEFINED, task t cannot have observed
		 * func->transition being set, c.f. the comment above.
		 */
		return true;
	}

	/*
	 * At this point, it is known that the transition is fully in
	 * progress, because current->patch_state == KLP_PATCHED
	 * whereas t->patch_state == KLP_UNPATCHED. So either of the
	 * two tasks must have been switched over already. It again
	 * follows that any prior writes to the klp_transition_patch
	 * resp. the klp_patches list are visible here and stable.
	 */
	patch = READ_ONCE(*klpe_klp_transition_patch);
	if (!patch) {
		/* Should not happen, but better be safe than sorry. */
		return false;
	}
	/*
	 * In principle it should be safe to read from *patch
	 * directly. However, be paranoid.
	 */
	if (probe_kernel_read(&prev, &patch->list.prev, sizeof(prev)) < 0) {
		return false;
	}

	if (prev == &(*klpe_klp_patches)) {
		/*
		 * There's no other livepatch on the list, it's an
		 * unpatch operation.
		 */
		return false;
	}

	patch = container_of(prev, struct klp_patch, list);
	/*
	 * In principle it should be safe to read from
	 * patch->mod directly. However, be paranoid.
	 */
	if (probe_kernel_read(&patch_mod, &patch->mod, sizeof(patch_mod)) < 0) {
		return false;
	}

	return klpp_patch_is_compatible(patch_mod);
}



/* klp-ccp: from kernel/futex.c */
#include <linux/slab.h>
#include <linux/poll.h>

/* klp-ccp: from include/linux/plist.h */
static void (*klpe_plist_add)(struct plist_node *node, struct plist_head *head);
static void (*klpe_plist_del)(struct plist_node *node, struct plist_head *head);

/* klp-ccp: from include/linux/sched.h */
static int (*klpe_wake_up_state)(struct task_struct *tsk, unsigned int state);

/* klp-ccp: from kernel/futex.c */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/futex.h>

/* klp-ccp: from include/linux/futex.h */
#ifdef CONFIG_HAVE_FUTEX_CMPXCHG
#define klpr_futex_cmpxchg_enabled 1
#else
static int (*klpe_futex_cmpxchg_enabled);
#define klpr_futex_cmpxchg_enabled (*klpe_futex_cmpxchg_enabled)
#endif

/* klp-ccp: from kernel/futex.c */
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/export.h>
#include <linux/magic.h>
#include <linux/pid.h>
#include <linux/nsproxy.h>
#include <linux/ptrace.h>
#include <linux/sched/wake_q.h>

/* klp-ccp: from include/linux/sched/wake_q.h */
static void (*klpe_wake_up_q)(struct wake_q_head *head);

/* klp-ccp: from kernel/futex.c */
#include <linux/sched/mm.h>

/* klp-ccp: from include/linux/hugetlb.h */
#ifdef CONFIG_HUGETLB_PAGE

static pgoff_t (*klpe___basepage_index)(struct page *page);

static inline pgoff_t klpr_basepage_index(struct page *page)
{
	if (!PageCompound(page))
		return page->index;

	return (*klpe___basepage_index)(page);
}

#else	/* CONFIG_HUGETLB_PAGE */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_HUGETLB_PAGE */

/* klp-ccp: from kernel/futex.c */
#include <asm/futex.h>
/* klp-ccp: from kernel/locking/rtmutex_common.h */
#include <linux/rtmutex.h>
#include <linux/sched/wake_q.h>

struct rt_mutex_waiter {
	struct rb_node          tree_entry;
	struct rb_node          pi_tree_entry;
	struct task_struct	*task;
	struct rt_mutex		*lock;
#ifdef CONFIG_DEBUG_RT_MUTEXES
#error "klp-ccp: non-taken branch"
#endif
	int prio;
	u64 deadline;
};

#define RT_MUTEX_HAS_WAITERS	1UL

static inline struct task_struct *rt_mutex_owner(struct rt_mutex *lock)
{
	unsigned long owner = (unsigned long) READ_ONCE(lock->owner);

	return (struct task_struct *) (owner & ~RT_MUTEX_HAS_WAITERS);
}

static struct task_struct *(*klpe_rt_mutex_next_owner)(struct rt_mutex *lock);

static void (*klpe_rt_mutex_init_waiter)(struct rt_mutex_waiter *waiter);
static int (*klpe___rt_mutex_start_proxy_lock)(struct rt_mutex *lock,
				     struct rt_mutex_waiter *waiter,
				     struct task_struct *task);
static int (*klpe_rt_mutex_start_proxy_lock)(struct rt_mutex *lock,
				     struct rt_mutex_waiter *waiter,
				     struct task_struct *task);
static int (*klpe_rt_mutex_wait_proxy_lock)(struct rt_mutex *lock,
			       struct hrtimer_sleeper *to,
			       struct rt_mutex_waiter *waiter);
static bool (*klpe_rt_mutex_cleanup_proxy_lock)(struct rt_mutex *lock,
				 struct rt_mutex_waiter *waiter);

static int (*klpe_rt_mutex_futex_trylock)(struct rt_mutex *l);
static int (*klpe___rt_mutex_futex_trylock)(struct rt_mutex *l);

static bool (*klpe___rt_mutex_futex_unlock)(struct rt_mutex *lock,
				 struct wake_q_head *wqh);

static void (*klpe_rt_mutex_postunlock)(struct wake_q_head *wake_q);

/* klp-ccp: from kernel/locking/rtmutex.h */
#define debug_rt_mutex_free_waiter(w)			do { } while (0)

/* klp-ccp: from kernel/futex.c */
# define FLAGS_SHARED		0x01

#define FLAGS_CLOCKRT		0x02
#define FLAGS_HAS_TIMEOUT	0x04

struct futex_pi_state {
	/*
	 * list of 'owned' pi_state instances - these have to be
	 * cleaned up in do_exit() if the task exits prematurely:
	 */
	struct list_head list;

	/*
	 * The PI object:
	 */
	struct rt_mutex pi_mutex;

	struct task_struct *owner;
	atomic_t refcount;

	union futex_key key;
};

struct futex_q {
	struct plist_node list;

	struct task_struct *task;
	spinlock_t *lock_ptr;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
};

/* New. */
struct klpp_futex_key_ext
{
	unsigned long magic;
	struct file *filp;
};

/* New. */
static const struct klpp_futex_key_ext klpp_futex_key_ext_init = {
	.magic = 0xdecafbad,
	.filp = NULL,
};

/* New. */
static inline void klpp_futex_get_file(struct klpp_futex_key_ext *key_ext)
{
	if (key_ext->filp)
		key_ext->filp = get_file(key_ext->filp);
	/* see futex_get_mm() */
	smp_mb__after_atomic();
}

/* New. */
static inline void klpp_futex_key_ext_put(struct klpp_futex_key_ext *key_ext)
{
	if (key_ext->filp) {
		fput(key_ext->filp);
		key_ext->filp = NULL;
	}
}

/* New. */
static inline
void klpp_futex_key_ext_destroy(struct klpp_futex_key_ext *key_ext)
{
	/* Don't leave a magic on the stack. */
	WRITE_ONCE(key_ext->magic, 0xdeaddead);
}

/* New. */
struct klpp_futex_q {
	struct futex_q orig;
	struct klpp_futex_key_ext key_ext;
};

/* New. */
#define KLPP_FUTEX_KEY_EXT_MAGIC 0xdecafbad

/* New. */
static const struct klpp_futex_q klpp_futex_q_init = {
	/* Initialize ->orig with futex_q_init from the original code. */
	.orig = {
		/* list gets initialized in queue_me() */
		.key = FUTEX_KEY_INIT,
		.bitset = FUTEX_BITSET_MATCH_ANY
	},
	.key_ext = {
		.magic = KLPP_FUTEX_KEY_EXT_MAGIC,
		.filp = NULL,
	},
};

/* New. */
static struct klpp_futex_key_ext * klpp_q_get_key_ext(struct futex_q *q)
{
	struct klpp_futex_q *klpp_q;

	/*
	 * ->task is NULL before __queue_me(). We should never end up
	 * examining an unqueued an unqueued q, but better be safe.
	 */
	if (!q->task)
		return NULL;

	if (!klpp_task_is_compatible(q->task))
		return NULL;

	klpp_q = container_of(q, struct klpp_futex_q, orig);
	if (klpp_q->key_ext.magic != KLPP_FUTEX_KEY_EXT_MAGIC)
		return NULL;

	return &klpp_q->key_ext;
}

struct futex_hash_bucket {
	atomic_t waiters;
	spinlock_t lock;
	struct plist_head chain;
} ____cacheline_aligned_in_smp;

#ifdef CONFIG_FAIL_FUTEX
#error "klp-ccp: non-taken branch"
#else
static inline bool should_fail_futex(bool fshared)
{
	return false;
}
#endif /* CONFIG_FAIL_FUTEX */

static inline void futex_get_mm(union futex_key *key)
{
	mmgrab(key->private.mm);
	/*
	 * Ensure futex_get_mm() implies a full barrier such that
	 * get_futex_key() implies a full barrier. This is relied upon
	 * as smp_mb(); (B), see the ordering comment above.
	 */
	smp_mb__after_atomic();
}

static inline void hb_waiters_inc(struct futex_hash_bucket *hb)
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

static inline void hb_waiters_dec(struct futex_hash_bucket *hb)
{
#ifdef CONFIG_SMP
	atomic_dec(&hb->waiters);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

static inline int hb_waiters_pending(struct futex_hash_bucket *hb)
{
#ifdef CONFIG_SMP
	return atomic_read(&hb->waiters);
#else
#error "klp-ccp: non-taken branch"
#endif
}

static struct futex_hash_bucket *(*klpe_hash_futex)(union futex_key *key);

static inline int match_futex(union futex_key *key1, union futex_key *key2)
{
	return (key1 && key2
		&& key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}

static void get_futex_key_refs(union futex_key *key)
{
	if (!key->both.ptr)
		return;

	/*
	 * On MMU less systems futexes are always "private" as there is no per
	 * process address space. We need the smp wmb nevertheless - yes,
	 * arch/blackfin has MMU less SMP ...
	 */
	if (!IS_ENABLED(CONFIG_MMU)) {
		smp_mb(); /* explicit smp_mb(); (B) */
		return;
	}

	switch (key->both.offset & (FUT_OFF_INODE|FUT_OFF_MMSHARED)) {
	case FUT_OFF_INODE:
		ihold(key->shared.inode); /* implies smp_mb(); (B) */
		break;
	case FUT_OFF_MMSHARED:
		futex_get_mm(key); /* implies smp_mb(); (B) */
		break;
	default:
		/*
		 * Private futexes do not hold reference on an inode or
		 * mm, therefore the only purpose of calling get_futex_key_refs
		 * is because we need the barrier for the lockless waiter check.
		 */
		smp_mb(); /* explicit smp_mb(); (B) */
	}
}

static void drop_futex_key_refs(union futex_key *key)
{
	if (!key->both.ptr) {
		/* If we're here then we tried to put a key we failed to get */
		WARN_ON_ONCE(1);
		return;
	}

	if (!IS_ENABLED(CONFIG_MMU))
		return;

	switch (key->both.offset & (FUT_OFF_INODE|FUT_OFF_MMSHARED)) {
	case FUT_OFF_INODE:
		iput(key->shared.inode);
		break;
	case FUT_OFF_MMSHARED:
		mmdrop(key->private.mm);
		break;
	}
}

static int
/*
 * Fix CVE-2020-14381
 *  -1 line, +2 lines
 */
klpp_get_futex_key(u32 __user *uaddr, int fshared, union futex_key *key,
		   struct klpp_futex_key_ext *key_ext, int rw)
{
	unsigned long address = (unsigned long)uaddr;
	struct mm_struct *mm = current->mm;
	struct page *page, *tail;
	struct address_space *mapping;
	int err, ro = 0;

	/*
	 * The futex address must be "naturally" aligned.
	 */
	key->both.offset = address % PAGE_SIZE;
	if (unlikely((address % sizeof(u32)) != 0))
		return -EINVAL;
	address -= key->both.offset;

	if (unlikely(!access_ok(rw, uaddr, sizeof(u32))))
		return -EFAULT;

	if (unlikely(should_fail_futex(fshared)))
		return -EFAULT;

	/*
	 * PROCESS_PRIVATE futexes are fast.
	 * As the mm cannot disappear under us and the 'key' only needs
	 * virtual address, we dont even have to find the underlying vma.
	 * Note : We do have to check 'uaddr' is a valid user address,
	 *        but access_ok() should be faster than find_vma()
	 */
	if (!fshared) {
		key->private.mm = mm;
		key->private.address = address;
		get_futex_key_refs(key);  /* implies smp_mb(); (B) */
		return 0;
	}

again:
	/* Ignore any VERIFY_READ mapping (futex common case) */
	if (unlikely(should_fail_futex(fshared)))
		return -EFAULT;

	err = get_user_pages_fast(address, 1, 1, &page);
	/*
	 * If write access is not required (eg. FUTEX_WAIT), try
	 * and get read-only access.
	 */
	if (err == -EFAULT && rw == VERIFY_READ) {
		err = get_user_pages_fast(address, 1, 0, &page);
		ro = 1;
	}
	if (err < 0)
		return err;
	else
		err = 0;

	/*
	 * The treatment of mapping from this point on is critical. The page
	 * lock protects many things but in this context the page lock
	 * stabilizes mapping, prevents inode freeing in the shared
	 * file-backed region case and guards against movement to swap cache.
	 *
	 * Strictly speaking the page lock is not needed in all cases being
	 * considered here and page lock forces unnecessarily serialization
	 * From this point on, mapping will be re-verified if necessary and
	 * page lock will be acquired only if it is unavoidable
	 *
	 * Mapping checks require the head page for any compound page so the
	 * head page and mapping is looked up now. For anonymous pages, it
	 * does not matter if the page splits in the future as the key is
	 * based on the address. For filesystem-backed pages, the tail is
	 * required as the index of the page determines the key. For
	 * base pages, there is no tail page and tail == page.
	 */
	tail = page;
	page = compound_head(page);
	mapping = READ_ONCE(page->mapping);

	/*
	 * If page->mapping is NULL, then it cannot be a PageAnon
	 * page; but it might be the ZERO_PAGE or in the gate area or
	 * in a special mapping (all cases which we are happy to fail);
	 * or it may have been a good file page when get_user_pages_fast
	 * found it, but truncated or holepunched or subjected to
	 * invalidate_complete_page2 before we got the page lock (also
	 * cases which we are happy to fail).  And we hold a reference,
	 * so refcount care in invalidate_complete_page's remove_mapping
	 * prevents drop_caches from setting mapping to NULL beneath us.
	 *
	 * The case we do have to guard against is when memory pressure made
	 * shmem_writepage move it from filecache to swapcache beneath us:
	 * an unlikely race, but we do need to retry for page->mapping.
	 */
	if (unlikely(!mapping)) {
		int shmem_swizzled;

		/*
		 * Page lock is required to identify which special case above
		 * applies. If this is really a shmem page then the page lock
		 * will prevent unexpected transitions.
		 */
		lock_page(page);
		shmem_swizzled = PageSwapCache(page) || page->mapping;
		unlock_page(page);
		put_page(page);

		if (shmem_swizzled)
			goto again;

		return -EFAULT;
	}

	/*
	 * Private mappings are handled in a simple way.
	 *
	 * If the futex key is stored on an anonymous page, then the associated
	 * object is the mm which is implicitly pinned by the calling process.
	 *
	 * NOTE: When userspace waits on a MAP_SHARED mapping, even if
	 * it's a read-only handle, it's expected that futexes attach to
	 * the object not the particular process.
	 */
	if (PageAnon(page)) {
		/*
		 * A RO anonymous page will never change and thus doesn't make
		 * sense for futex operations.
		 */
		if (unlikely(should_fail_futex(fshared)) || ro) {
			err = -EFAULT;
			goto out;
		}

		key->both.offset |= FUT_OFF_MMSHARED; /* ref taken on mm */
		key->private.mm = mm;
		key->private.address = address;

		get_futex_key_refs(key); /* implies smp_mb(); (B) */

	} else {
		/*
		 * Fix CVE-2020-14381
		 *  -62 lines, +57 lines
		 */
		struct mm_struct *mm = current->mm;
		struct vm_area_struct *vma;

		put_page(page); /* undo previous gup_fast() */

		down_read(&mm->mmap_sem);

		err = get_user_pages(address, 1, FOLL_WRITE, &page, &vma);
		/*
		 * If write access is not required (eg. FUTEX_WAIT), try
		 * and get read-only access.
		 */
		if (err == -EFAULT && rw == VERIFY_READ)
			err = get_user_pages(address, 1, 0, &page, &vma);

		if (err < 0) {
			up_read(&mm->mmap_sem);
			return err;
		}

		/*
		 * Virtual address could have been remapped.
		 */
		if (!vma->vm_file || PageAnon(page)) {
			put_page(page);
			up_read(&mm->mmap_sem);

			goto again;
		}

		key->both.offset |= FUT_OFF_INODE; /* inode-based key */
		key->shared.inode = vma->vm_file->f_path.dentry->d_inode;
		key->shared.pgoff = klpr_basepage_index(page);

		/*
		 * Livepatch specific:
		 *  - ->filp lives in klpp_futex_key_ext
		 *  - A reference to the struct file is taken via
		 *    klpp_futex_get_file() below, get_futex_key_refs()
		 *    won't be patched to do that.
		 *  - A reference to the inode is still taken in
		 *    get_futex_key_refs(). This is needed
		 *    so that the current task is kept compatible
		 *    with requeueing operations from unpatched tasks.
		 */
		key_ext->filp = vma->vm_file;
		klpp_futex_get_file(key_ext);
		get_futex_key_refs(key); /* implies smp_mb(); (B) */

		put_page(page);

		up_read(&mm->mmap_sem);
		return 0;
	}

out:
	put_page(page);
	return err;
}

/*
 * Fix CVE-2020-14381
 *  -1 line, +2 lines
 */
static inline void klpp_put_futex_key(union futex_key *key,
				      struct klpp_futex_key_ext *key_ext)
{
	drop_futex_key_refs(key);
	klpp_futex_key_ext_put(key_ext);
}

static int (*klpe_fault_in_user_writeable)(u32 __user *uaddr);

static struct futex_q *(*klpe_futex_top_waiter)(struct futex_hash_bucket *hb,
					union futex_key *key);

static int (*klpe_cmpxchg_futex_value_locked)(u32 *curval, u32 __user *uaddr,
				      u32 uval, u32 newval);

static int (*klpe_get_futex_value_locked)(u32 *dest, u32 __user *from);

static int refill_pi_state_cache(void)
{
	struct futex_pi_state *pi_state;

	if (likely(current->pi_state_cache))
		return 0;

	pi_state = kzalloc(sizeof(*pi_state), GFP_KERNEL);

	if (!pi_state)
		return -ENOMEM;

	INIT_LIST_HEAD(&pi_state->list);
	/* pi_mutex gets initialized later */
	pi_state->owner = NULL;
	atomic_set(&pi_state->refcount, 1);
	pi_state->key = FUTEX_KEY_INIT;

	current->pi_state_cache = pi_state;

	return 0;
}

/* New. */
static void klpp_pi_state_update_owner(struct futex_pi_state *pi_state,
				       struct task_struct *new_owner)
{
	struct task_struct *old_owner = pi_state->owner;

	lockdep_assert_held(&pi_state->pi_mutex.wait_lock);

	if (old_owner) {
		raw_spin_lock(&old_owner->pi_lock);
		WARN_ON(list_empty(&pi_state->list));
		list_del_init(&pi_state->list);
		raw_spin_unlock(&old_owner->pi_lock);
	}

	if (new_owner) {
		raw_spin_lock(&new_owner->pi_lock);
		WARN_ON(!list_empty(&pi_state->list));
		list_add(&pi_state->list, &new_owner->pi_state_list);
		pi_state->owner = new_owner;
		raw_spin_unlock(&new_owner->pi_lock);
	}
}

static void (*klpe_get_pi_state)(struct futex_pi_state *pi_state);

static void (*klpe_put_pi_state)(struct futex_pi_state *pi_state);

static int (*klpe_attach_to_pi_state)(u32 __user *uaddr, u32 uval,
			      struct futex_pi_state *pi_state,
			      struct futex_pi_state **ps);

static int (*klpe_attach_to_pi_owner)(u32 __user *uaddr, u32 uval, union futex_key *key,
			      struct futex_pi_state **ps);

static int klpr_lookup_pi_state(u32 __user *uaddr, u32 uval,
			   struct futex_hash_bucket *hb,
			   union futex_key *key, struct futex_pi_state **ps)
{
	struct futex_q *top_waiter = (*klpe_futex_top_waiter)(hb, key);

	/*
	 * If there is a waiter on that futex, validate it and
	 * attach to the pi_state when the validation succeeds.
	 */
	if (top_waiter)
		return (*klpe_attach_to_pi_state)(uaddr, uval, top_waiter->pi_state, ps);

	/*
	 * We are the first waiter - try to look up the owner based on
	 * @uval and attach to it.
	 */
	return (*klpe_attach_to_pi_owner)(uaddr, uval, key, ps);
}

static int (*klpe_futex_lock_pi_atomic)(u32 __user *uaddr, struct futex_hash_bucket *hb,
				union futex_key *key,
				struct futex_pi_state **ps,
				struct task_struct *task, int set_waiters);

static void (*klpe___unqueue_futex)(struct futex_q *q);

static void (*klpe_mark_wake_futex)(struct wake_q_head *wake_q, struct futex_q *q);

static int klpp_wake_futex_pi(u32 __user *uaddr, u32 uval, struct futex_pi_state *pi_state)
{
	u32 uninitialized_var(curval), newval;
	struct task_struct *new_owner;
	bool postunlock = false;
	DEFINE_WAKE_Q(wake_q);
	int ret = 0;

	new_owner = (*klpe_rt_mutex_next_owner)(&pi_state->pi_mutex);
	/*
	 * Fix CVE-2021-3347
	 *  -1 line, +1 line
	 * Note: remove the WARN_ON_ONCE() because it's bogus
	 * and gets triggered in our testcase.
	 */
	if (!new_owner) {
		/*
		 * As per the comment in futex_unlock_pi() this should not happen.
		 *
		 * When this happens, give up our locks and try again, giving
		 * the futex_lock_pi() instance time to complete, either by
		 * waiting on the rtmutex or removing itself from the futex
		 * queue.
		 */
		ret = -EAGAIN;
		goto out_unlock;
	}

	/*
	 * We pass it to the next owner. The WAITERS bit is always kept
	 * enabled while there is PI state around. We cleanup the owner
	 * died bit, because we are the owner.
	 */
	newval = FUTEX_WAITERS | task_pid_vnr(new_owner);

	if (unlikely(should_fail_futex(true)))
		ret = -EFAULT;

	if ((*klpe_cmpxchg_futex_value_locked)(&curval, uaddr, uval, newval)) {
		ret = -EFAULT;

	} else if (curval != uval) {
		/*
		 * If a unconditional UNLOCK_PI operation (user space did not
		 * try the TID->0 transition) raced with a waiter setting the
		 * FUTEX_WAITERS flag between get_user() and locking the hash
		 * bucket lock, retry the operation.
		 */
		if ((FUTEX_TID_MASK & curval) == uval)
			ret = -EAGAIN;
		else
			ret = -EINVAL;
	}

	if (ret)
		goto out_unlock;

	/*
	 * This is a point of no return; once we modify the uval there is no
	 * going back and subsequent operations must not fail.
	 */

	raw_spin_lock(&pi_state->owner->pi_lock);
	WARN_ON(list_empty(&pi_state->list));
	list_del_init(&pi_state->list);
	raw_spin_unlock(&pi_state->owner->pi_lock);

	raw_spin_lock(&new_owner->pi_lock);
	WARN_ON(!list_empty(&pi_state->list));
	list_add(&pi_state->list, &new_owner->pi_state_list);
	pi_state->owner = new_owner;
	raw_spin_unlock(&new_owner->pi_lock);

	postunlock = (*klpe___rt_mutex_futex_unlock)(&pi_state->pi_mutex, &wake_q);

out_unlock:
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);

	if (postunlock)
		(*klpe_rt_mutex_postunlock)(&wake_q);

	return ret;
}

static inline void
double_lock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	if (hb1 <= hb2) {
		spin_lock(&hb1->lock);
		if (hb1 < hb2)
			spin_lock_nested(&hb2->lock, SINGLE_DEPTH_NESTING);
	} else { /* hb1 > hb2 */
		spin_lock(&hb2->lock);
		spin_lock_nested(&hb1->lock, SINGLE_DEPTH_NESTING);
	}
}

static inline void
double_unlock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	spin_unlock(&hb1->lock);
	if (hb1 != hb2)
		spin_unlock(&hb2->lock);
}

int
klpp_futex_wake(u32 __user *uaddr, unsigned int flags, int nr_wake, u32 bitset)
{
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	union futex_key key = FUTEX_KEY_INIT;
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	struct klpp_futex_key_ext key_ext = klpp_futex_key_ext_init;
	int ret;
	DEFINE_WAKE_Q(wake_q);

	if (!bitset) {
		/*
		 * Fix CVE-2020-14381
		 *  +1 line
		 */
		klpp_futex_key_ext_destroy(&key_ext);
		return -EINVAL;
	}

	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	ret = klpp_get_futex_key(uaddr, flags & FLAGS_SHARED, &key, &key_ext, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;

	hb = (*klpe_hash_futex)(&key);

	/* Make sure we really have tasks to wakeup */
	if (!hb_waiters_pending(hb))
		goto out_put_key;

	spin_lock(&hb->lock);

	plist_for_each_entry_safe(this, next, &hb->chain, list) {
		if (match_futex (&this->key, &key)) {
			if (this->pi_state || this->rt_waiter) {
				ret = -EINVAL;
				break;
			}

			/* Check if one of the bits is set in both bitsets */
			if (!(this->bitset & bitset))
				continue;

			(*klpe_mark_wake_futex)(&wake_q, this);
			if (++ret >= nr_wake)
				break;
		}
	}

	spin_unlock(&hb->lock);
	(*klpe_wake_up_q)(&wake_q);
out_put_key:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key, &key_ext);
out:
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	klpp_futex_key_ext_destroy(&key_ext);
	return ret;
}

static int futex_atomic_op_inuser(unsigned int encoded_op, u32 __user *uaddr)
{
	unsigned int op =	  (encoded_op & 0x70000000) >> 28;
	unsigned int cmp =	  (encoded_op & 0x0f000000) >> 24;
	int oparg = sign_extend32((encoded_op & 0x00fff000) >> 12, 11);
	int cmparg = sign_extend32(encoded_op & 0x00000fff, 11);
	int oldval, ret;

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28)) {
		if (oparg < 0 || oparg > 31) {
			char comm[sizeof(current->comm)];
			/*
			 * kill this print and return -EINVAL when userspace
			 * is sane again
			 */
			pr_info_ratelimited("futex_wake_op: %s tries to shift op by %d; fix this program\n",
					get_task_comm(comm, current), oparg);
			oparg &= 31;
		}
		oparg = 1 << oparg;
	}

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(u32)))
		return -EFAULT;

	ret = arch_futex_atomic_op_inuser(op, oparg, &oldval, uaddr);
	if (ret)
		return ret;

	switch (cmp) {
	case FUTEX_OP_CMP_EQ:
		return oldval == cmparg;
	case FUTEX_OP_CMP_NE:
		return oldval != cmparg;
	case FUTEX_OP_CMP_LT:
		return oldval < cmparg;
	case FUTEX_OP_CMP_GE:
		return oldval >= cmparg;
	case FUTEX_OP_CMP_LE:
		return oldval <= cmparg;
	case FUTEX_OP_CMP_GT:
		return oldval > cmparg;
	default:
		return -ENOSYS;
	}
}

static int
klpp_futex_wake_op(u32 __user *uaddr1, unsigned int flags, u32 __user *uaddr2,
	      int nr_wake, int nr_wake2, int op)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	/*
	 * Fix CVE-2020-14381
	 *  +2 lines
	 */
	struct klpp_futex_key_ext key1_ext = klpp_futex_key_ext_init;
	struct klpp_futex_key_ext key2_ext = klpp_futex_key_ext_init;
	struct futex_hash_bucket *hb1, *hb2;
	struct futex_q *this, *next;
	int ret, op_ret;
	DEFINE_WAKE_Q(wake_q);

retry:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	ret = klpp_get_futex_key(uaddr1, flags & FLAGS_SHARED, &key1, &key1_ext, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	ret = klpp_get_futex_key(uaddr2, flags & FLAGS_SHARED, &key2, &key2_ext, VERIFY_WRITE);
	if (unlikely(ret != 0))
		goto out_put_key1;

	hb1 = (*klpe_hash_futex)(&key1);
	hb2 = (*klpe_hash_futex)(&key2);

retry_private:
	double_lock_hb(hb1, hb2);
	op_ret = futex_atomic_op_inuser(op, uaddr2);
	if (unlikely(op_ret < 0)) {

		double_unlock_hb(hb1, hb2);

#ifndef CONFIG_MMU
#error "klp-ccp: non-taken branch"
#endif
		if (unlikely(op_ret != -EFAULT)) {
			ret = op_ret;
			goto out_put_keys;
		}

		ret = (*klpe_fault_in_user_writeable)(uaddr2);
		if (ret)
			goto out_put_keys;

		if (!(flags & FLAGS_SHARED))
			goto retry_private;

		/*
		 * Fix CVE-2020-14381
		 *  -2 lines, +2 lines
		 */
		klpp_put_futex_key(&key2, &key2_ext);
		klpp_put_futex_key(&key1, &key1_ext);
		goto retry;
	}

	plist_for_each_entry_safe(this, next, &hb1->chain, list) {
		if (match_futex (&this->key, &key1)) {
			if (this->pi_state || this->rt_waiter) {
				ret = -EINVAL;
				goto out_unlock;
			}
			(*klpe_mark_wake_futex)(&wake_q, this);
			if (++ret >= nr_wake)
				break;
		}
	}

	if (op_ret > 0) {
		op_ret = 0;
		plist_for_each_entry_safe(this, next, &hb2->chain, list) {
			if (match_futex (&this->key, &key2)) {
				if (this->pi_state || this->rt_waiter) {
					ret = -EINVAL;
					goto out_unlock;
				}
				(*klpe_mark_wake_futex)(&wake_q, this);
				if (++op_ret >= nr_wake2)
					break;
			}
		}
		ret += op_ret;
	}

out_unlock:
	double_unlock_hb(hb1, hb2);
	(*klpe_wake_up_q)(&wake_q);
out_put_keys:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key2, &key2_ext);
out_put_key1:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key1, &key1_ext);
out:
	/*
	 * Fix CVE-2020-14381
	 *  +2 lines
	 */
	klpp_futex_key_ext_destroy(&key1_ext);
	klpp_futex_key_ext_destroy(&key2_ext);
	return ret;
}

static inline
void klpp_requeue_futex(struct futex_q *q, struct futex_hash_bucket *hb1,
		   /*
		    * Fix CVE-2020-14381
		    *  -1 line, +2 lines
		    */
		   struct futex_hash_bucket *hb2, union futex_key *key2,
		   struct klpp_futex_key_ext *key2_ext)
{
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	struct klpp_futex_key_ext *q_key_ext;

	/*
	 * If key1 and key2 hash to the same bucket, no need to
	 * requeue.
	 */
	if (likely(&hb1->chain != &hb2->chain)) {
		(*klpe_plist_del)(&q->list, &hb1->chain);
		hb_waiters_dec(hb1);
		hb_waiters_inc(hb2);
		(*klpe_plist_add)(&q->list, &hb2->chain);
		q->lock_ptr = &hb2->lock;
	}
	get_futex_key_refs(key2);
	q->key = *key2;

	/*
	 * Fix CVE-2020-14381
	 *  +6 lines
	 */
	q_key_ext = klpp_q_get_key_ext(q);
	if (q_key_ext) {
		klpp_futex_key_ext_put(q_key_ext);
		klpp_futex_get_file(key2_ext);
		*q_key_ext = *key2_ext;
	}
}

static inline
void klpp_requeue_pi_wake_futex(struct futex_q *q, union futex_key *key,
			   /*
			    * Fix CVE-2020-14381
			    *  +1 line
			    */
			   struct klpp_futex_key_ext *key_ext,
			   struct futex_hash_bucket *hb)
{
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	struct klpp_futex_key_ext *q_key_ext;

	get_futex_key_refs(key);
	q->key = *key;
	/*
	 * Fix CVE-2020-14381
	 *  +6 lines
	 */
	q_key_ext = klpp_q_get_key_ext(q);
	if (q_key_ext) {
		klpp_futex_key_ext_put(q_key_ext);
		klpp_futex_get_file(key_ext);
		*q_key_ext = *key_ext;
	}

	(*klpe___unqueue_futex)(q);

	WARN_ON(!q->rt_waiter);
	q->rt_waiter = NULL;

	q->lock_ptr = &hb->lock;

	(*klpe_wake_up_state)(q->task, TASK_NORMAL);
}

static int klpp_futex_proxy_trylock_atomic(u32 __user *pifutex,
				 struct futex_hash_bucket *hb1,
				 struct futex_hash_bucket *hb2,
				 union futex_key *key1, union futex_key *key2,
				 /*
				  * Fix CVE-2020-14381
				  *  +1 line
				  */
				 struct klpp_futex_key_ext *key2_ext,
				 struct futex_pi_state **ps, int set_waiters)
{
	struct futex_q *top_waiter = NULL;
	u32 curval;
	int ret, vpid;

	if ((*klpe_get_futex_value_locked)(&curval, pifutex))
		return -EFAULT;

	if (unlikely(should_fail_futex(true)))
		return -EFAULT;

	/*
	 * Find the top_waiter and determine if there are additional waiters.
	 * If the caller intends to requeue more than 1 waiter to pifutex,
	 * force futex_lock_pi_atomic() to set the FUTEX_WAITERS bit now,
	 * as we have means to handle the possible fault.  If not, don't set
	 * the bit unecessarily as it will force the subsequent unlock to enter
	 * the kernel.
	 */
	top_waiter = (*klpe_futex_top_waiter)(hb1, key1);

	/* There are no waiters, nothing for us to do. */
	if (!top_waiter)
		return 0;

	/* Ensure we requeue to the expected futex. */
	if (!match_futex(top_waiter->requeue_pi_key, key2))
		return -EINVAL;

	/*
	 * Try to take the lock for top_waiter.  Set the FUTEX_WAITERS bit in
	 * the contended case or if set_waiters is 1.  The pi_state is returned
	 * in ps in contended cases.
	 */
	vpid = task_pid_vnr(top_waiter->task);
	ret = (*klpe_futex_lock_pi_atomic)(pifutex, hb2, key2, ps, top_waiter->task,
				   set_waiters);
	if (ret == 1) {
		/*
		 * Fix CVE-2020-14381
		 *  -1 line, +1 line
		 */
		klpp_requeue_pi_wake_futex(top_waiter, key2, key2_ext, hb2);
		return vpid;
	}
	return ret;
}

static int klpp_futex_requeue(u32 __user *uaddr1, unsigned int flags,
			 u32 __user *uaddr2, int nr_wake, int nr_requeue,
			 u32 *cmpval, int requeue_pi)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	/*
	 * Fix CVE-2020-14381
	 *  +2 lines
	 */
	struct klpp_futex_key_ext key1_ext = klpp_futex_key_ext_init;
	struct klpp_futex_key_ext key2_ext = klpp_futex_key_ext_init;
	int drop_count = 0, task_count = 0, ret;
	struct futex_pi_state *pi_state = NULL;
	struct futex_hash_bucket *hb1, *hb2;
	struct futex_q *this, *next;
	DEFINE_WAKE_Q(wake_q);

	if (nr_wake < 0 || nr_requeue < 0) {
		/*
		 * Fix CVE-2020-14381
		 *  +2 lines
		 */
		klpp_futex_key_ext_destroy(&key1_ext);
		klpp_futex_key_ext_destroy(&key2_ext);
		return -EINVAL;
	}

	if (requeue_pi) {
		/*
		 * Requeue PI only works on two distinct uaddrs. This
		 * check is only valid for private futexes. See below.
		 */
		if (uaddr1 == uaddr2) {
			/*
			 * Fix CVE-2020-14381
			 *  +2 lines
			 */
			klpp_futex_key_ext_destroy(&key1_ext);
			klpp_futex_key_ext_destroy(&key2_ext);
			return -EINVAL;
		}

		/*
		 * requeue_pi requires a pi_state, try to allocate it now
		 * without any locks in case it fails.
		 */
		if (refill_pi_state_cache()) {
			/*
			 * Fix CVE-2020-14381
			 *  +2 lines
			 */
			klpp_futex_key_ext_destroy(&key1_ext);
			klpp_futex_key_ext_destroy(&key2_ext);
			return -ENOMEM;
		}

		/*
		 * requeue_pi must wake as many tasks as it can, up to nr_wake
		 * + nr_requeue, since it acquires the rt_mutex prior to
		 * returning to userspace, so as to not leave the rt_mutex with
		 * waiters and no owner.  However, second and third wake-ups
		 * cannot be predicted as they involve race conditions with the
		 * first wake and a fault while looking up the pi_state.  Both
		 * pthread_cond_signal() and pthread_cond_broadcast() should
		 * use nr_wake=1.
		 */
		if (nr_wake != 1) {
			/*
			 * Fix CVE-2020-14381
			 *  +2 lines
			 */
			klpp_futex_key_ext_destroy(&key1_ext);
			klpp_futex_key_ext_destroy(&key2_ext);
			return -EINVAL;
		}
	}

retry:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	ret = klpp_get_futex_key(uaddr1, flags & FLAGS_SHARED, &key1, &key1_ext, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	ret = klpp_get_futex_key(uaddr2, flags & FLAGS_SHARED, &key2, &key2_ext,
			    requeue_pi ? VERIFY_WRITE : VERIFY_READ);
	if (unlikely(ret != 0))
		goto out_put_key1;

	/*
	 * The check above which compares uaddrs is not sufficient for
	 * shared futexes. We need to compare the keys:
	 */
	if (requeue_pi && match_futex(&key1, &key2)) {
		ret = -EINVAL;
		goto out_put_keys;
	}

	hb1 = (*klpe_hash_futex)(&key1);
	hb2 = (*klpe_hash_futex)(&key2);

retry_private:
	hb_waiters_inc(hb2);
	double_lock_hb(hb1, hb2);

	if (likely(cmpval != NULL)) {
		u32 curval;

		ret = (*klpe_get_futex_value_locked)(&curval, uaddr1);

		if (unlikely(ret)) {
			double_unlock_hb(hb1, hb2);
			hb_waiters_dec(hb2);

			ret = get_user(curval, uaddr1);
			if (ret)
				goto out_put_keys;

			if (!(flags & FLAGS_SHARED))
				goto retry_private;

			/*
			 * Fix CVE-2020-14381
			 *  -1 line, +1 line
			 */
			klpp_put_futex_key(&key2, &key2_ext);
			/*
			 * Fix CVE-2020-14381
			 *  -1 line, +1 line
			 */
			klpp_put_futex_key(&key1, &key1_ext);
			goto retry;
		}
		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	if (requeue_pi && (task_count - nr_wake < nr_requeue)) {
		/*
		 * Attempt to acquire uaddr2 and wake the top waiter. If we
		 * intend to requeue waiters, force setting the FUTEX_WAITERS
		 * bit.  We force this here where we are able to easily handle
		 * faults rather in the requeue loop below.
		 */
		ret = klpp_futex_proxy_trylock_atomic(uaddr2, hb1, hb2, &key1,
						 /*
						  * Fix CVE-2020-14381
						  *  -1 line, +1 line
						  */
						 &key2, &key2_ext, &pi_state, nr_requeue);

		/*
		 * At this point the top_waiter has either taken uaddr2 or is
		 * waiting on it.  If the former, then the pi_state will not
		 * exist yet, look it up one more time to ensure we have a
		 * reference to it. If the lock was taken, ret contains the
		 * vpid of the top waiter task.
		 * If the lock was not taken, we have pi_state and an initial
		 * refcount on it. In case of an error we have nothing.
		 */
		if (ret > 0) {
			WARN_ON(pi_state);
			drop_count++;
			task_count++;
			/*
			 * If we acquired the lock, then the user space value
			 * of uaddr2 should be vpid. It cannot be changed by
			 * the top waiter as it is blocked on hb2 lock if it
			 * tries to do so. If something fiddled with it behind
			 * our back the pi state lookup might unearth it. So
			 * we rather use the known value than rereading and
			 * handing potential crap to lookup_pi_state.
			 *
			 * If that call succeeds then we have pi_state and an
			 * initial refcount on it.
			 */
			ret = klpr_lookup_pi_state(uaddr2, ret, hb2, &key2, &pi_state);
		}

		switch (ret) {
		case 0:
			/* We hold a reference on the pi state. */
			break;

			/* If the above failed, then pi_state is NULL */
		case -EFAULT:
			double_unlock_hb(hb1, hb2);
			hb_waiters_dec(hb2);
			/*
			 * Fix CVE-2020-14381
			 *  -1 line, +1 line
			 */
			klpp_put_futex_key(&key2, &key2_ext);
			/*
			 * Fix CVE-2020-14381
			 *  -1 line, +1 line
			 */
			klpp_put_futex_key(&key1, &key1_ext);
			ret = (*klpe_fault_in_user_writeable)(uaddr2);
			if (!ret)
				goto retry;
			goto out;
		case -EAGAIN:
			/*
			 * Two reasons for this:
			 * - Owner is exiting and we just wait for the
			 *   exit to complete.
			 * - The user space value changed.
			 */
			double_unlock_hb(hb1, hb2);
			hb_waiters_dec(hb2);
			/*
			 * Fix CVE-2020-14381
			 *  -1 line, +1 line
			 */
			klpp_put_futex_key(&key2, &key2_ext);
			/*
			 * Fix CVE-2020-14381
			 *  -1 line, +1 line
			 */
			klpp_put_futex_key(&key1, &key1_ext);
			cond_resched();
			goto retry;
		default:
			goto out_unlock;
		}
	}

	plist_for_each_entry_safe(this, next, &hb1->chain, list) {
		if (task_count - nr_wake >= nr_requeue)
			break;

		if (!match_futex(&this->key, &key1))
			continue;

		/*
		 * FUTEX_WAIT_REQEUE_PI and FUTEX_CMP_REQUEUE_PI should always
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

		/*
		 * Wake nr_wake waiters.  For requeue_pi, if we acquired the
		 * lock, we already woke the top_waiter.  If not, it will be
		 * woken by futex_unlock_pi().
		 */
		if (++task_count <= nr_wake && !requeue_pi) {
			(*klpe_mark_wake_futex)(&wake_q, this);
			continue;
		}

		/* Ensure we requeue to the expected futex for requeue_pi. */
		if (requeue_pi && !match_futex(this->requeue_pi_key, &key2)) {
			ret = -EINVAL;
			break;
		}

		/*
		 * Requeue nr_requeue waiters and possibly one more in the case
		 * of requeue_pi if we couldn't acquire the lock atomically.
		 */
		if (requeue_pi) {
			/*
			 * Prepare the waiter to take the rt_mutex. Take a
			 * refcount on the pi_state and store the pointer in
			 * the futex_q object of the waiter.
			 */
			(*klpe_get_pi_state)(pi_state);
			this->pi_state = pi_state;
			ret = (*klpe_rt_mutex_start_proxy_lock)(&pi_state->pi_mutex,
							this->rt_waiter,
							this->task);
			if (ret == 1) {
				/*
				 * We got the lock. We do neither drop the
				 * refcount on pi_state nor clear
				 * this->pi_state because the waiter needs the
				 * pi_state for cleaning up the user space
				 * value. It will drop the refcount after
				 * doing so.
				 */
				/*
				 * Fix CVE-2020-14381
				 *  -1 line, +1 line
				 */
				klpp_requeue_pi_wake_futex(this, &key2, &key2_ext, hb2);
				drop_count++;
				continue;
			} else if (ret) {
				/*
				 * rt_mutex_start_proxy_lock() detected a
				 * potential deadlock when we tried to queue
				 * that waiter. Drop the pi_state reference
				 * which we took above and remove the pointer
				 * to the state from the waiters futex_q
				 * object.
				 */
				this->pi_state = NULL;
				(*klpe_put_pi_state)(pi_state);
				/*
				 * We stop queueing more waiters and let user
				 * space deal with the mess.
				 */
				break;
			}
		}
		/*
		 * Fix CVE-2020-14381
		 *  -1 line, +1 line
		 */
		klpp_requeue_futex(this, hb1, hb2, &key2, &key2_ext);
		drop_count++;
	}

	/*
	 * We took an extra initial reference to the pi_state either
	 * in futex_proxy_trylock_atomic() or in lookup_pi_state(). We
	 * need to drop it here again.
	 */
	(*klpe_put_pi_state)(pi_state);

out_unlock:
	double_unlock_hb(hb1, hb2);
	(*klpe_wake_up_q)(&wake_q);
	hb_waiters_dec(hb2);

	/*
	 * drop_futex_key_refs() must be called outside the spinlocks. During
	 * the requeue we moved futex_q's from the hash bucket at key1 to the
	 * one at key2 and updated their key pointer.  We no longer need to
	 * hold the references to key1.
	 */
	while (--drop_count >= 0)
		drop_futex_key_refs(&key1);

out_put_keys:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key2, &key2_ext);
out_put_key1:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key1, &key1_ext);
out:
	/*
	 * Fix CVE-2020-14381
	 *  +2 lines
	 */
	klpp_futex_key_ext_destroy(&key1_ext);
	klpp_futex_key_ext_destroy(&key2_ext);
	return ret ? ret : task_count;
}

static inline struct futex_hash_bucket *klpr_queue_lock(struct futex_q *q)
	__acquires(&hb->lock)
{
	struct futex_hash_bucket *hb;

	hb = (*klpe_hash_futex)(&q->key);

	/*
	 * Increment the counter before taking the lock so that
	 * a potential waker won't miss a to-be-slept task that is
	 * waiting for the spinlock. This is safe as all queue_lock()
	 * users end up calling queue_me(). Similarly, for housekeeping,
	 * decrement the counter at queue_unlock() when some error has
	 * occurred and we don't end up adding the task to the list.
	 */
	hb_waiters_inc(hb);

	q->lock_ptr = &hb->lock;

	spin_lock(&hb->lock); /* implies smp_mb(); (A) */
	return hb;
}

static inline void
queue_unlock(struct futex_hash_bucket *hb)
	__releases(&hb->lock)
{
	spin_unlock(&hb->lock);
	hb_waiters_dec(hb);
}

static inline void klpr___queue_me(struct futex_q *q, struct futex_hash_bucket *hb)
{
	int prio;

	/*
	 * The priority used to register this element is
	 * - either the real thread-priority for the real-time threads
	 * (i.e. threads with a priority lower than MAX_RT_PRIO)
	 * - or MAX_RT_PRIO for non-RT threads.
	 * Thus, all RT-threads are woken first in priority order, and
	 * the others are woken last, in FIFO order.
	 */
	prio = min(current->normal_prio, MAX_RT_PRIO);

	plist_node_init(&q->list, prio);
	(*klpe_plist_add)(&q->list, &hb->chain);
	q->task = current;
}

/*
 * Fix CVE-2020-14381
 *  -1 line, +1 line
 */
static int klpp_unqueue_me(struct klpp_futex_q *klpp_q)
{
	spinlock_t *lock_ptr;
	int ret = 0;
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	struct futex_q *q = &klpp_q->orig;

	/* In the common case we don't take the spinlock, which is nice. */
retry:
	/*
	 * q->lock_ptr can change between this read and the following spin_lock.
	 * Use READ_ONCE to forbid the compiler from reloading q->lock_ptr and
	 * optimizing lock_ptr out of the logic below.
	 */
	lock_ptr = READ_ONCE(q->lock_ptr);
	if (lock_ptr != NULL) {
		spin_lock(lock_ptr);
		/*
		 * q->lock_ptr can change between reading it and
		 * spin_lock(), causing us to take the wrong lock.  This
		 * corrects the race condition.
		 *
		 * Reasoning goes like this: if we have the wrong lock,
		 * q->lock_ptr must have changed (maybe several times)
		 * between reading it and the spin_lock().  It can
		 * change again after the spin_lock() but only if it was
		 * already changed before the spin_lock().  It cannot,
		 * however, change back to the original value.  Therefore
		 * we can detect whether we acquired the correct lock.
		 */
		if (unlikely(lock_ptr != q->lock_ptr)) {
			spin_unlock(lock_ptr);
			goto retry;
		}
		(*klpe___unqueue_futex)(q);

		BUG_ON(q->pi_state);

		spin_unlock(lock_ptr);
		ret = 1;
	}

	drop_futex_key_refs(&q->key);
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	klpp_futex_key_ext_put(&klpp_q->key_ext);
	return ret;
}

static void (*klpe_unqueue_me_pi)(struct futex_q *q);

/*
 * Fix CVE-2021-3347
 *  -1 line, +1 line
 */
static int klpp___fixup_pi_state_owner(u32 __user *uaddr, struct futex_q *q,
				struct task_struct *argowner)
{
	/*
	 * Fix CVE-2021-3347
	 *  +1 line
	 */
	u32 uval, uninitialized_var(curval), newval, newtid;
	struct futex_pi_state *pi_state = q->pi_state;
	/*
	 * Fix CVE-2021-3347
	 *  -1 line
	 */
	struct task_struct *oldowner, *newowner;
	/*
	 * Fix CVE-2021-3347
	 *  -2 lines, +1 line
	 */
	int err = 0;

	/*
	 * Fix CVE-2021-3347
	 *  -3 lines
	 */

	oldowner = pi_state->owner;

	/*
	 * We are here because either:
	 *
	 *  - we stole the lock and pi_state->owner needs updating to reflect
	 *    that (@argowner == current),
	 *
	 * or:
	 *
	 *  - someone stole our lock and we need to fix things to point to the
	 *    new owner (@argowner == NULL).
	 *
	 * Either way, we have to replace the TID in the user space variable.
	 * This must be atomic as we have to preserve the owner died bit here.
	 *
	 * Note: We write the user space value _before_ changing the pi_state
	 * because we can fault here. Imagine swapped out pages or a fork
	 * that marked all the anonymous memory readonly for cow.
	 *
	 * Modifying pi_state _before_ the user space value would leave the
	 * pi_state in an inconsistent state when we fault here, because we
	 * need to drop the locks to handle the fault. This might be observed
	 * in the PID check in lookup_pi_state.
	 */
retry:
	if (!argowner) {
		if (oldowner != current) {
			/*
			 * We raced against a concurrent self; things are
			 * already fixed up. Nothing to do.
			 */
			/*
			 * Fix CVE-2021-3347
			 *  -2 lines, +1 line
			 */
			return 0;
		}

		if ((*klpe___rt_mutex_futex_trylock)(&pi_state->pi_mutex)) {
			/*
			 * Fix CVE-2021-3347
			 *  -3 lines, +2 lines
			 */
			/* We got the lock. pi_state is correct. Tell caller. */
			return 1;
		}

		/*
		 * Fix CVE-2021-3347
		 *  -3 lines, +4 lines
		 */
		/*
		 * The trylock just failed, so either there is an owner or
		 * there is a higher priority waiter than this one.
		 */
		newowner = rt_mutex_owner(&pi_state->pi_mutex);
		/*
		 * Fix CVE-2021-3347
		 *  -1 line, +12 lines
		 */
		/*
		 * If the higher priority waiter has not yet taken over the
		 * rtmutex then newowner is NULL. We can't return here with
		 * that state because it's inconsistent vs. the user space
		 * state. So drop the locks and try again. It's a valid
		 * situation and not any different from the other retry
		 * conditions.
		 */
		if (unlikely(!newowner)) {
			err = -EAGAIN;
			goto handle_err;
		}
	} else {
		WARN_ON_ONCE(argowner != current);
		if (oldowner == current) {
			/*
			 * We raced against a concurrent self; things are
			 * already fixed up. Nothing to do.
			 */
			/*
			 * Fix CVE-2021-3347
			 *  -2 lines, +1 line
			 */
			return 1;
		}
		newowner = argowner;
	}

	newtid = task_pid_vnr(newowner) | FUTEX_WAITERS;
	/* Owner died? */
	if (!pi_state->owner)
		newtid |= FUTEX_OWNER_DIED;

	/*
	 * Fix CVE-2021-3347
	 *  -2 lines, +3 lines
	 */
	err = (*klpe_get_futex_value_locked)(&uval, uaddr);
	if (err)
		goto handle_err;

	for (;;) {
		newval = (uval & FUTEX_OWNER_DIED) | newtid;

		/*
		 * Fix CVE-2021-3347
		 *  -2 lines, +3 lines
		 */
		err = (*klpe_cmpxchg_futex_value_locked)(&curval, uaddr, uval, newval);
		if (err)
			goto handle_err;

		if (curval == uval)
			break;
		uval = curval;
	}

	/*
	 * We fixed up user space. Now we need to fix the pi_state
	 * itself.
	 */
	/*
	 * Fix CVE-2021-3347
	 *  -13 lines, +1 line
	 */
	klpp_pi_state_update_owner(pi_state, newowner);
	/*
	 * Fix CVE-2021-3347
	 *  -1 line
	 */

	/*
	 * Fix CVE-2021-3347
	 *  -1 line, +1 line
	 */
	return argowner == current;

	/*
	 * Fix CVE-2021-3347
	 *  -8 lines, +8 lines
	 */
	/*
	 * In order to reschedule or handle a page fault, we need to drop the
	 * locks here. In the case of a fault, this gives the other task
	 * (either the highest priority waiter itself or the task which stole
	 * the rtmutex) the chance to try the fixup of the pi_state. So once we
	 * are back from handling the fault we need to check the pi_state after
	 * reacquiring the locks and before trying to do another fixup. When
	 * the fixup has been done already we simply return.
	 *
	 * Note: we hold both hb->lock and pi_mutex->wait_lock. We can safely
	 * drop hb->lock since the caller owns the hb -> futex_q relation.
	 * Dropping the pi_mutex->wait_lock requires the state revalidate.
	 */
/*
 * Fix CVE-2021-3347
 *  -1 line, +1 line
 */
handle_err:
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
	spin_unlock(q->lock_ptr);

	/*
	 * Fix CVE-2021-3347
	 *  -1 line, +14 lines
	 */
	switch (err) {
	case -EFAULT:
		err = (*klpe_fault_in_user_writeable)(uaddr);
		break;

	case -EAGAIN:
		cond_resched();
		err = 0;
		break;

	default:
		WARN_ON_ONCE(1);
		break;
	}

	spin_lock(q->lock_ptr);
	raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);

	/*
	 * Check if someone else fixed it for us:
	 */
	if (pi_state->owner != oldowner) {
		/*
		 * Fix CVE-2021-3347
		 *  -2 lines, +1 line
		 */
		return argowner == current;
	}

	/*
	 * Fix CVE-2021-3347
	 *  -8 lines, +23 lines
	 */
	/* Retry if err was -EAGAIN or the fault in succeeded */
	if (!err)
		goto retry;

	/*
	 * fault_in_user_writeable() failed so user state is immutable. At
	 * best we can make the kernel state consistent but user state will
	 * be most likely hosed and any subsequent unlock operation will be
	 * rejected due to PI futex rule [10].
	 *
	 * Ensure that the rtmutex owner is also the pi_state owner despite
	 * the user space value claiming something different. There is no
	 * point in unlocking the rtmutex if current is the owner as it
	 * would need to wait until the next waiter has taken the rtmutex
	 * to guarantee consistent state. Keep it simple. Userspace asked
	 * for this wreckaged state.
	 *
	 * The rtmutex has an owner - either current or some other
	 * task. See the EAGAIN loop above.
	 */
	klpp_pi_state_update_owner(pi_state, rt_mutex_owner(&pi_state->pi_mutex));

	return err;
}

/*
 * Fix CVE-2021-3347
 *  +13 lines
 */
static int klpp_fixup_pi_state_owner(u32 __user *uaddr, struct futex_q *q,
				struct task_struct *argowner)
{
	struct futex_pi_state *pi_state = q->pi_state;
	int ret;

	lockdep_assert_held(q->lock_ptr);

	raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);
	ret = klpp___fixup_pi_state_owner(uaddr, q, argowner);
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
	return ret;
}

static long (*klpe_futex_wait_restart)(struct restart_block *restart);

static int klpp_fixup_owner(u32 __user *uaddr, struct futex_q *q, int locked)
{
	/*
	 * Fix CVE-2021-3347
	 *  -1 line
	 */

	if (locked) {
		/*
		 * Got the lock. We might not be the anticipated owner if we
		 * did a lock-steal - fix up the PI-state in that case:
		 *
		 * Speculative pi_state->owner read (we don't hold wait_lock);
		 * since we own the lock pi_state->owner == current is the
		 * stable state, anything else needs more attention.
		 */
		if (q->pi_state->owner != current)
			/*
			 * Fix CVE-2021-3347
			 *  -1 line, +1 line
			 */
			return klpp_fixup_pi_state_owner(uaddr, q, current);
		/*
		 * Fix CVE-2021-3347
		 *  -1 line, +1 line
		 */
		return 1;
	}

	/*
	 * If we didn't get the lock; check if anybody stole it from us. In
	 * that case, we need to fix up the uval to point to them instead of
	 * us, otherwise bad things happen. [10]
	 *
	 * Another speculative read; pi_state->owner == current is unstable
	 * but needs our attention.
	 */
	if (q->pi_state->owner == current) {
		/*
		 * Fix CVE-2021-3347
		 *  -2 lines, +1 line
		 */
		return klpp_fixup_pi_state_owner(uaddr, q, NULL);
	}

	/*
	 * Fix CVE-2021-3347
	 *  -10 lines, +6 lines
	 */
	/*
	 * Paranoia check. If we did not take the lock, then we should not be
	 * the owner of the rt_mutex. Warn and establish consistent state.
	 */
	if (WARN_ON_ONCE(rt_mutex_owner(&q->pi_state->pi_mutex) == current))
		return klpp_fixup_pi_state_owner(uaddr, q, current);

	/*
	 * Fix CVE-2021-3347
	 *  -2 lines, +1 line
	 */
	return 0;
}

static void (*klpe_futex_wait_queue_me)(struct futex_hash_bucket *hb, struct futex_q *q,
				struct hrtimer_sleeper *timeout);

static int klpp_futex_wait_setup(u32 __user *uaddr, u32 val, unsigned int flags,
			   /*
			    * Fix CVE-2020-14381
			    *  -1 line, +1 line
			    */
			   struct klpp_futex_q *klp_q, struct futex_hash_bucket **hb)
{
	u32 uval;
	int ret;
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	struct futex_q *q = &klp_q->orig;

	/*
	 * Access the page AFTER the hash-bucket is locked.
	 * Order is important:
	 *
	 *   Userspace waiter: val = var; if (cond(val)) futex_wait(&var, val);
	 *   Userspace waker:  if (cond(var)) { var = new; futex_wake(&var); }
	 *
	 * The basic logical guarantee of a futex is that it blocks ONLY
	 * if cond(var) is known to be true at the time of blocking, for
	 * any cond.  If we locked the hash-bucket after testing *uaddr, that
	 * would open a race condition where we could block indefinitely with
	 * cond(var) false, which would violate the guarantee.
	 *
	 * On the other hand, we insert q and release the hash-bucket only
	 * after testing *uaddr.  This guarantees that futex_wait() will NOT
	 * absorb a wakeup if *uaddr does not match the desired values
	 * while the syscall executes.
	 */
retry:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +2 lines
	 */
	ret = klpp_get_futex_key(uaddr, flags & FLAGS_SHARED,
				 &q->key, &klp_q->key_ext, VERIFY_READ);
	if (unlikely(ret != 0))
		return ret;

retry_private:
	*hb = klpr_queue_lock(q);

	ret = (*klpe_get_futex_value_locked)(&uval, uaddr);

	if (ret) {
		queue_unlock(*hb);

		ret = get_user(uval, uaddr);
		if (ret)
			goto out;

		if (!(flags & FLAGS_SHARED))
			goto retry_private;

		/*
		 * Fix CVE-2020-14381
		 *  -1 line, +1 line
		 */
		klpp_put_futex_key(&q->key, &klp_q->key_ext);
		goto retry;
	}

	if (uval != val) {
		queue_unlock(*hb);
		ret = -EWOULDBLOCK;
	}

out:
	if (ret)
		/*
		 * Fix CVE-2020-14381
		 *  -1 line, +1 line
		 */
		klpp_put_futex_key(&q->key, &klp_q->key_ext);
	return ret;
}

int klpp_futex_wait(u32 __user *uaddr, unsigned int flags, u32 val,
		      ktime_t *abs_time, u32 bitset)
{
	struct hrtimer_sleeper timeout, *to = NULL;
	struct restart_block *restart;
	struct futex_hash_bucket *hb;
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +2 lines
	 */
	struct klpp_futex_q klp_q = klpp_futex_q_init;
#define q (klp_q.orig)
	int ret;

	if (!bitset) {
		/*
		 * Fix CVE-2020-14381
		 *  +1 line
		 */
		klpp_futex_key_ext_destroy(&klp_q.key_ext);
		return -EINVAL;
	}

	q.bitset = bitset;

	if (abs_time) {
		to = &timeout;

		hrtimer_init_on_stack(&to->timer, (flags & FLAGS_CLOCKRT) ?
				      CLOCK_REALTIME : CLOCK_MONOTONIC,
				      HRTIMER_MODE_ABS);
		hrtimer_init_sleeper(to, current);
		hrtimer_set_expires_range_ns(&to->timer, *abs_time,
					     current->timer_slack_ns);
	}

retry:
	/*
	 * Prepare to wait on uaddr. On success, holds hb lock and increments
	 * q.key refs.
	 */
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	ret = klpp_futex_wait_setup(uaddr, val, flags, &klp_q, &hb);
	if (ret)
		goto out;

	/* queue_me and wait for wakeup, timeout, or a signal. */
	(*klpe_futex_wait_queue_me)(hb, &q, to);

	/* If we were woken (and unqueued), we succeeded, whatever. */
	ret = 0;
	/* unqueue_me() drops q.key ref */
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	if (!klpp_unqueue_me(&klp_q))
		goto out;
	ret = -ETIMEDOUT;
	if (to && !to->task)
		goto out;

	/*
	 * We expect signal_pending(current), but we might be the
	 * victim of a spurious wakeup as well.
	 */
	if (!signal_pending(current))
		goto retry;

	ret = -ERESTARTSYS;
	if (!abs_time)
		goto out;

	restart = &current->restart_block;
	restart->fn = (*klpe_futex_wait_restart);
	restart->futex.uaddr = uaddr;
	restart->futex.val = val;
	restart->futex.time = *abs_time;
	restart->futex.bitset = bitset;
	restart->futex.flags = flags | FLAGS_HAS_TIMEOUT;

	ret = -ERESTART_RESTARTBLOCK;

out:
	if (to) {
		hrtimer_cancel(&to->timer);
		destroy_hrtimer_on_stack(&to->timer);
	}
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	klpp_futex_key_ext_destroy(&klp_q.key_ext);
	return ret;
/*
 * Fix CVE-2020-14381
 *  +1 line
 */
#undef q
}

static long (*klpe_futex_wait_restart)(struct restart_block *restart);

static int klpp_futex_lock_pi(u32 __user *uaddr, unsigned int flags,
			 ktime_t *time, int trylock)
{
	struct hrtimer_sleeper timeout, *to = NULL;
	/*
	 * Fix CVE-2021-3347
	 *  -1 line
	 */
	struct rt_mutex_waiter rt_waiter;
	struct futex_hash_bucket *hb;
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +2 lines
	 */
	struct klpp_futex_q klp_q = klpp_futex_q_init;
#define q (klp_q.orig)
	int res, ret;

	if (refill_pi_state_cache()) {
		/*
		 * Fix CVE-2020-14381
		 *  +1 line
		 */
		klpp_futex_key_ext_destroy(&klp_q.key_ext);
		return -ENOMEM;
	}

	if (time) {
		to = &timeout;
		hrtimer_init_on_stack(&to->timer, CLOCK_REALTIME,
				      HRTIMER_MODE_ABS);
		hrtimer_init_sleeper(to, current);
		hrtimer_set_expires(&to->timer, *time);
	}

retry:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +2 lines
	 */
	ret = klpp_get_futex_key(uaddr, flags & FLAGS_SHARED,
				 &q.key, &klp_q.key_ext, VERIFY_WRITE);
	if (unlikely(ret != 0))
		goto out;

retry_private:
	hb = klpr_queue_lock(&q);

	ret = (*klpe_futex_lock_pi_atomic)(uaddr, hb, &q.key, &q.pi_state, current, 0);
	if (unlikely(ret)) {
		/*
		 * Atomic work succeeded and we got the lock,
		 * or failed. Either way, we do _not_ block.
		 */
		switch (ret) {
		case 1:
			/* We got the lock. */
			ret = 0;
			goto out_unlock_put_key;
		case -EFAULT:
			goto uaddr_faulted;
		case -EAGAIN:
			/*
			 * Two reasons for this:
			 * - Task is exiting and we just wait for the
			 *   exit to complete.
			 * - The user space value changed.
			 */
			queue_unlock(hb);
			/*
			 * Fix CVE-2020-14381
			 *  -1 line, +1 line
			 */
			klpp_put_futex_key(&q.key, &klp_q.key_ext);
			cond_resched();
			goto retry;
		default:
			goto out_unlock_put_key;
		}
	}

	WARN_ON(!q.pi_state);

	/*
	 * Only actually queue now that the atomic ops are done:
	 */
	klpr___queue_me(&q, hb);

	if (trylock) {
		ret = (*klpe_rt_mutex_futex_trylock)(&q.pi_state->pi_mutex);
		/* Fixup the trylock return value: */
		ret = ret ? 0 : -EWOULDBLOCK;
		goto no_block;
	}

	(*klpe_rt_mutex_init_waiter)(&rt_waiter);

	/*
	 * On PREEMPT_RT_FULL, when hb->lock becomes an rt_mutex, we must not
	 * hold it while doing rt_mutex_start_proxy(), because then it will
	 * include hb->lock in the blocking chain, even through we'll not in
	 * fact hold it while blocking. This will lead it to report -EDEADLK
	 * and BUG when futex_unlock_pi() interleaves with this.
	 *
	 * Therefore acquire wait_lock while holding hb->lock, but drop the
	 * latter before calling __rt_mutex_start_proxy_lock(). This
	 * interleaves with futex_unlock_pi() -- which does a similar lock
	 * handoff -- such that the latter can observe the futex_q::pi_state
	 * before __rt_mutex_start_proxy_lock() is done.
	 */
	raw_spin_lock_irq(&q.pi_state->pi_mutex.wait_lock);
	spin_unlock(q.lock_ptr);
	/*
	 * __rt_mutex_start_proxy_lock() unconditionally enqueues the @rt_waiter
	 * such that futex_unlock_pi() is guaranteed to observe the waiter when
	 * it sees the futex_q::pi_state.
	 */
	ret = (*klpe___rt_mutex_start_proxy_lock)(&q.pi_state->pi_mutex, &rt_waiter, current);
	raw_spin_unlock_irq(&q.pi_state->pi_mutex.wait_lock);

	if (ret) {
		if (ret == 1)
			ret = 0;

		goto cleanup;
	}

	if (unlikely(to))
		hrtimer_start_expires(&to->timer, HRTIMER_MODE_ABS);

	ret = (*klpe_rt_mutex_wait_proxy_lock)(&q.pi_state->pi_mutex, to, &rt_waiter);
cleanup:
	spin_lock(q.lock_ptr);
	/*
	 * If we failed to acquire the lock (deadlock/signal/timeout), we must
	 * first acquire the hb->lock before removing the lock from the
	 * rt_mutex waitqueue, such that we can keep the hb and rt_mutex wait
	 * lists consistent.
	 *
	 * In particular; it is important that futex_unlock_pi() can not
	 * observe this inconsistency.
	 */
	if (ret && !(*klpe_rt_mutex_cleanup_proxy_lock)(&q.pi_state->pi_mutex, &rt_waiter))
		ret = 0;

no_block:
	/*
	 * Fixup the pi_state owner and possibly acquire the lock if we
	 * haven't already.
	 */
	res = klpp_fixup_owner(uaddr, &q, !ret);
	/*
	 * If fixup_owner() returned an error, proprogate that.  If it acquired
	 * the lock, clear our -ETIMEDOUT or -EINTR.
	 */
	if (res)
		ret = (res < 0) ? res : 0;

	/*
	 * Fix CVE-2021-3347
	 *  -8 lines
	 */

	/* Unqueue and drop the lock */
	(*klpe_unqueue_me_pi)(&q);

	/*
	 * Fix CVE-2021-3347
	 *  -4 lines
	 */

	goto out_put_key;

out_unlock_put_key:
	queue_unlock(hb);

out_put_key:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&q.key, &klp_q.key_ext);
out:
	if (to) {
		hrtimer_cancel(&to->timer);
		destroy_hrtimer_on_stack(&to->timer);
	}
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	klpp_futex_key_ext_destroy(&klp_q.key_ext);
	return ret != -EINTR ? ret : -ERESTARTNOINTR;

uaddr_faulted:
	queue_unlock(hb);

	ret = (*klpe_fault_in_user_writeable)(uaddr);
	if (ret)
		goto out_put_key;

	if (!(flags & FLAGS_SHARED))
		goto retry_private;

	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&q.key, &klp_q.key_ext);
	goto retry;
/*
 * Fix CVE-2020-14381
 *  +1 line
 */
#undef q
}

static int klpp_futex_unlock_pi(u32 __user *uaddr, unsigned int flags)
{
	u32 uninitialized_var(curval), uval, vpid = task_pid_vnr(current);
	union futex_key key = FUTEX_KEY_INIT;
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	struct klpp_futex_key_ext key_ext = klpp_futex_key_ext_init;
	struct futex_hash_bucket *hb;
	struct futex_q *top_waiter;
	int ret;

retry:
	if (get_user(uval, uaddr)) {
		/*
		 * Fix CVE-2020-14381
		 *  +1 line
		 */
		klpp_futex_key_ext_destroy(&key_ext);
		return -EFAULT;
	}
	/*
	 * We release only a lock we actually own:
	 */
	if ((uval & FUTEX_TID_MASK) != vpid) {
		/*
		 * Fix CVE-2020-14381
		 *  +1 line
		 */
		klpp_futex_key_ext_destroy(&key_ext);
		return -EPERM;
	}

	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +2 lines
	 */
	ret = klpp_get_futex_key(uaddr, flags & FLAGS_SHARED, &key, &key_ext,
				 VERIFY_WRITE);
	if (ret) {
		/*
		 * Fix CVE-2020-14381
		 *  +1 line
		 */
		klpp_futex_key_ext_destroy(&key_ext);
		return ret;
	}

	hb = (*klpe_hash_futex)(&key);
	spin_lock(&hb->lock);

	/*
	 * Check waiters first. We do not trust user space values at
	 * all and we at least want to know if user space fiddled
	 * with the futex value instead of blindly unlocking.
	 */
	top_waiter = (*klpe_futex_top_waiter)(hb, &key);
	if (top_waiter) {
		struct futex_pi_state *pi_state = top_waiter->pi_state;

		ret = -EINVAL;
		if (!pi_state)
			goto out_unlock;

		/*
		 * If current does not own the pi_state then the futex is
		 * inconsistent and user space fiddled with the futex value.
		 */
		if (pi_state->owner != current)
			goto out_unlock;

		(*klpe_get_pi_state)(pi_state);
		/*
		 * By taking wait_lock while still holding hb->lock, we ensure
		 * there is no point where we hold neither; and therefore
		 * wake_futex_pi() must observe a state consistent with what we
		 * observed.
		 *
		 * In particular; this forces __rt_mutex_start_proxy() to
		 * complete such that we're guaranteed to observe the
		 * rt_waiter. Also see the WARN in wake_futex_pi().
		 */
		raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);
		spin_unlock(&hb->lock);

		/* drops pi_state->pi_mutex.wait_lock */
		ret = klpp_wake_futex_pi(uaddr, uval, pi_state);

		(*klpe_put_pi_state)(pi_state);

		/*
		 * Success, we're done! No tricky corner cases.
		 */
		if (!ret)
			goto out_putkey;
		/*
		 * The atomic access to the futex value generated a
		 * pagefault, so retry the user-access and the wakeup:
		 */
		if (ret == -EFAULT)
			goto pi_faulted;
		/*
		 * A unconditional UNLOCK_PI op raced against a waiter
		 * setting the FUTEX_WAITERS bit. Try again.
		 */
		if (ret == -EAGAIN) {
			/*
			 * Fix CVE-2020-14381
			 *  +1 line
			 */
			klpp_put_futex_key(&key, &key_ext);
			goto retry;
		}
		/*
		 * wake_futex_pi has detected invalid state. Tell user
		 * space.
		 */
		goto out_putkey;
	}

	/*
	 * We have no kernel internal state, i.e. no waiters in the
	 * kernel. Waiters which are about to queue themselves are stuck
	 * on hb->lock. So we can safely ignore them. We do neither
	 * preserve the WAITERS bit not the OWNER_DIED one. We are the
	 * owner.
	 */
	if ((*klpe_cmpxchg_futex_value_locked)(&curval, uaddr, uval, 0)) {
		spin_unlock(&hb->lock);
		goto pi_faulted;
	}

	/*
	 * If uval has changed, let user space handle it.
	 */
	ret = (curval == uval) ? 0 : -EAGAIN;

out_unlock:
	spin_unlock(&hb->lock);
out_putkey:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key, &key_ext);
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	klpp_futex_key_ext_destroy(&key_ext);
	return ret;

pi_faulted:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key, &key_ext);

	ret = (*klpe_fault_in_user_writeable)(uaddr);
	if (!ret)
		goto retry;

	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	klpp_futex_key_ext_destroy(&key_ext);
	return ret;
}

static inline
int klpr_handle_early_requeue_pi_wakeup(struct futex_hash_bucket *hb,
				   struct futex_q *q, union futex_key *key2,
				   struct hrtimer_sleeper *timeout)
{
	int ret = 0;

	/*
	 * With the hb lock held, we avoid races while we process the wakeup.
	 * We only need to hold hb (and not hb2) to ensure atomicity as the
	 * wakeup code can't change q.key from uaddr to uaddr2 if we hold hb.
	 * It can't be requeued from uaddr2 to something else since we don't
	 * support a PI aware source futex for requeue.
	 */
	if (!match_futex(&q->key, key2)) {
		WARN_ON(q->lock_ptr && (&hb->lock != q->lock_ptr));
		/*
		 * We were woken prior to requeue by a timeout or a signal.
		 * Unqueue the futex_q and determine which it was.
		 */
		(*klpe_plist_del)(&q->list, &hb->chain);
		hb_waiters_dec(hb);

		/* Handle spurious wakeups gracefully */
		ret = -EWOULDBLOCK;
		if (timeout && !timeout->task)
			ret = -ETIMEDOUT;
		else if (signal_pending(current))
			ret = -ERESTARTNOINTR;
	}
	return ret;
}

static int klpp_futex_wait_requeue_pi(u32 __user *uaddr, unsigned int flags,
				 u32 val, ktime_t *abs_time, u32 bitset,
				 u32 __user *uaddr2)
{
	struct hrtimer_sleeper timeout, *to = NULL;
	/*
	 * Fix CVE-2021-3347
	 *  -1 line
	 */
	struct rt_mutex_waiter rt_waiter;
	struct futex_hash_bucket *hb;
	union futex_key key2 = FUTEX_KEY_INIT;
	/*
	 * Fix CVE-2020-14381
	 *  +1 line
	 */
	struct klpp_futex_key_ext key2_ext = klpp_futex_key_ext_init;
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +2 lines
	 */
	struct klpp_futex_q klp_q = klpp_futex_q_init;
#define q (klp_q.orig)
	int res, ret;

	if (uaddr == uaddr2) {
		/*
		 * Fix CVE-2020-14381
		 *  +2 lines
		 */
		klpp_futex_key_ext_destroy(&key2_ext);
		klpp_futex_key_ext_destroy(&klp_q.key_ext);
		return -EINVAL;
	}

	if (!bitset) {
		/*
		 * Fix CVE-2020-14381
		 *  +2 lines
		 */
		klpp_futex_key_ext_destroy(&key2_ext);
		klpp_futex_key_ext_destroy(&klp_q.key_ext);
		return -EINVAL;
	}

	if (abs_time) {
		to = &timeout;
		hrtimer_init_on_stack(&to->timer, (flags & FLAGS_CLOCKRT) ?
				      CLOCK_REALTIME : CLOCK_MONOTONIC,
				      HRTIMER_MODE_ABS);
		hrtimer_init_sleeper(to, current);
		hrtimer_set_expires_range_ns(&to->timer, *abs_time,
					     current->timer_slack_ns);
	}

	/*
	 * The waiter is allocated on our stack, manipulated by the requeue
	 * code while we sleep on uaddr.
	 */
	(*klpe_rt_mutex_init_waiter)(&rt_waiter);

	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +2 lines
	 */
	ret = klpp_get_futex_key(uaddr2, flags & FLAGS_SHARED, &key2, &key2_ext,
				 VERIFY_WRITE);
	if (unlikely(ret != 0))
		goto out;

	q.bitset = bitset;
	q.rt_waiter = &rt_waiter;
	q.requeue_pi_key = &key2;

	/*
	 * Prepare to wait on uaddr. On success, increments q.key (key1) ref
	 * count.
	 */
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	ret = klpp_futex_wait_setup(uaddr, val, flags, &klp_q, &hb);
	if (ret)
		goto out_key2;

	/*
	 * The check above which compares uaddrs is not sufficient for
	 * shared futexes. We need to compare the keys:
	 */
	if (match_futex(&q.key, &key2)) {
		queue_unlock(hb);
		ret = -EINVAL;
		goto out_put_keys;
	}

	/* Queue the futex_q, drop the hb lock, wait for wakeup. */
	(*klpe_futex_wait_queue_me)(hb, &q, to);

	spin_lock(&hb->lock);
	ret = klpr_handle_early_requeue_pi_wakeup(hb, &q, &key2, to);
	spin_unlock(&hb->lock);
	if (ret)
		goto out_put_keys;

	/*
	 * In order for us to be here, we know our q.key == key2, and since
	 * we took the hb->lock above, we also know that futex_requeue() has
	 * completed and we no longer have to concern ourselves with a wakeup
	 * race with the atomic proxy lock acquisition by the requeue code. The
	 * futex_requeue dropped our key1 reference and incremented our key2
	 * reference count.
	 */

	/* Check if the requeue code acquired the second futex for us. */
	if (!q.rt_waiter) {
		/*
		 * Got the lock. We might not be the anticipated owner if we
		 * did a lock-steal - fix up the PI-state in that case.
		 */
		if (q.pi_state && (q.pi_state->owner != current)) {
			spin_lock(q.lock_ptr);
			ret = klpp_fixup_pi_state_owner(uaddr2, &q, current);
			/*
			 * Fix CVE-2021-3347
			 *  -4 lines
			 */
			/*
			 * Drop the reference to the pi state which
			 * the requeue_pi() code acquired for us.
			 */
			(*klpe_put_pi_state)(q.pi_state);
			spin_unlock(q.lock_ptr);
			/*
			 * Fix CVE-2021-3347
			 *  +5 lines
			 */
			/*
			 * Adjust the return value. It's either -EFAULT or
			 * success (1) but the caller expects 0 for success.
			 */
			ret = ret < 0 ? ret : 0;
		}
	} else {
		struct rt_mutex *pi_mutex;

		/*
		 * We have been woken up by futex_unlock_pi(), a timeout, or a
		 * signal.  futex_unlock_pi() will not destroy the lock_ptr nor
		 * the pi_state.
		 */
		WARN_ON(!q.pi_state);
		pi_mutex = &q.pi_state->pi_mutex;
		ret = (*klpe_rt_mutex_wait_proxy_lock)(pi_mutex, to, &rt_waiter);

		spin_lock(q.lock_ptr);
		if (ret && !(*klpe_rt_mutex_cleanup_proxy_lock)(pi_mutex, &rt_waiter))
			ret = 0;

		debug_rt_mutex_free_waiter(&rt_waiter);
		/*
		 * Fixup the pi_state owner and possibly acquire the lock if we
		 * haven't already.
		 */
		res = klpp_fixup_owner(uaddr2, &q, !ret);
		/*
		 * If fixup_owner() returned an error, proprogate that.  If it
		 * acquired the lock, clear -ETIMEDOUT or -EINTR.
		 */
		if (res)
			ret = (res < 0) ? res : 0;

		/*
		 * Fix CVE-2021-3347
		 *  -9 lines
		 */

		/* Unqueue and drop the lock. */
		(*klpe_unqueue_me_pi)(&q);
	}

	/*
	 * Fix CVE-2021-3347
	 *  -4 lines
	 */

	if (ret == -EINTR) {
		/*
		 * We've already been requeued, but cannot restart by calling
		 * futex_lock_pi() directly. We could restart this syscall, but
		 * it would detect that the user space "val" changed and return
		 * -EWOULDBLOCK.  Save the overhead of the restart and return
		 * -EWOULDBLOCK directly.
		 */
		ret = -EWOULDBLOCK;
	}

out_put_keys:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&q.key, &klp_q.key_ext);
out_key2:
	/*
	 * Fix CVE-2020-14381
	 *  -1 line, +1 line
	 */
	klpp_put_futex_key(&key2, &key2_ext);

out:
	if (to) {
		hrtimer_cancel(&to->timer);
		destroy_hrtimer_on_stack(&to->timer);
	}
	/*
	 * Fix CVE-2020-14381
	 *  +2 lines
	 */
	klpp_futex_key_ext_destroy(&key2_ext);
	klpp_futex_key_ext_destroy(&klp_q.key_ext);
	return ret;
/*
 * Fix CVE-2020-14381
 *  +1 line
 */
#undef q
}

long klpp_do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3)
{
	int cmd = op & FUTEX_CMD_MASK;
	unsigned int flags = 0;

	if (!(op & FUTEX_PRIVATE_FLAG))
		flags |= FLAGS_SHARED;

	if (op & FUTEX_CLOCK_REALTIME) {
		flags |= FLAGS_CLOCKRT;
		if (cmd != FUTEX_WAIT && cmd != FUTEX_WAIT_BITSET && \
		    cmd != FUTEX_WAIT_REQUEUE_PI)
			return -ENOSYS;
	}

	switch (cmd) {
	case FUTEX_LOCK_PI:
	case FUTEX_UNLOCK_PI:
	case FUTEX_TRYLOCK_PI:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_CMP_REQUEUE_PI:
		if (!klpr_futex_cmpxchg_enabled)
			return -ENOSYS;
	}

	switch (cmd) {
	case FUTEX_WAIT:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAIT_BITSET:
		return klpp_futex_wait(uaddr, flags, val, timeout, val3);
	case FUTEX_WAKE:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAKE_BITSET:
		return klpp_futex_wake(uaddr, flags, val, val3);
	case FUTEX_REQUEUE:
		return klpp_futex_requeue(uaddr, flags, uaddr2, val, val2, NULL, 0);
	case FUTEX_CMP_REQUEUE:
		return klpp_futex_requeue(uaddr, flags, uaddr2, val, val2, &val3, 0);
	case FUTEX_WAKE_OP:
		return klpp_futex_wake_op(uaddr, flags, uaddr2, val, val2, val3);
	case FUTEX_LOCK_PI:
		return klpp_futex_lock_pi(uaddr, flags, timeout, 0);
	case FUTEX_UNLOCK_PI:
		return klpp_futex_unlock_pi(uaddr, flags);
	case FUTEX_TRYLOCK_PI:
		return klpp_futex_lock_pi(uaddr, flags, NULL, 1);
	case FUTEX_WAIT_REQUEUE_PI:
		val3 = FUTEX_BITSET_MATCH_ANY;
		return klpp_futex_wait_requeue_pi(uaddr, flags, val, timeout, val3,
					     uaddr2);
	case FUTEX_CMP_REQUEUE_PI:
		return klpp_futex_requeue(uaddr, flags, uaddr2, val, val2, &val3, 1);
	}
	return -ENOSYS;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "klp_transition_patch", (void *)&klpe_klp_transition_patch },
	{ "klp_patches", (void *)&klpe_klp_patches },
#ifndef CONFIG_HAVE_FUTEX_CMPXCHG
	{ "futex_cmpxchg_enabled", (void *)&klpe_futex_cmpxchg_enabled },
#endif
	{ "hash_futex", (void *)&klpe_hash_futex },
	{ "plist_del", (void *)&klpe_plist_del },
	{ "plist_add", (void *)&klpe_plist_add },
	{ "wake_up_state", (void *)&klpe_wake_up_state },
	{ "wake_up_q", (void *)&klpe_wake_up_q },
	{ "__basepage_index", (void *)&klpe___basepage_index },
	{ "rt_mutex_next_owner", (void *)&klpe_rt_mutex_next_owner },
	{ "rt_mutex_init_waiter", (void *)&klpe_rt_mutex_init_waiter },
	{ "__rt_mutex_start_proxy_lock",
	  (void *)&klpe___rt_mutex_start_proxy_lock },
	{ "rt_mutex_start_proxy_lock",
	  (void *)&klpe_rt_mutex_start_proxy_lock },
	{ "rt_mutex_wait_proxy_lock", (void *)&klpe_rt_mutex_wait_proxy_lock },
	{ "rt_mutex_cleanup_proxy_lock",
	  (void *)&klpe_rt_mutex_cleanup_proxy_lock },
	{ "rt_mutex_futex_trylock", (void *)&klpe_rt_mutex_futex_trylock },
	{ "__rt_mutex_futex_trylock", (void *)&klpe___rt_mutex_futex_trylock },
	{ "__rt_mutex_futex_unlock", (void *)&klpe___rt_mutex_futex_unlock },
	{ "rt_mutex_postunlock", (void *)&klpe_rt_mutex_postunlock },
	{ "fault_in_user_writeable", (void *)&klpe_fault_in_user_writeable },
	{ "get_futex_value_locked", (void *)&klpe_get_futex_value_locked },
	{ "futex_top_waiter", (void *)&klpe_futex_top_waiter },
	{ "cmpxchg_futex_value_locked",
	  (void *)&klpe_cmpxchg_futex_value_locked },
	{ "mark_wake_futex", (void *)&klpe_mark_wake_futex },
	{ "get_pi_state", (void *)&klpe_get_pi_state },
	{ "put_pi_state", (void *)&klpe_put_pi_state },
	{ "attach_to_pi_state", (void *)&klpe_attach_to_pi_state },
	{ "attach_to_pi_owner", (void *)&klpe_attach_to_pi_owner },
	{ "futex_lock_pi_atomic", (void *)&klpe_futex_lock_pi_atomic },
	{ "__unqueue_futex", (void *)&klpe___unqueue_futex },
	{ "unqueue_me_pi", (void *)&klpe_unqueue_me_pi },
	{ "futex_wait_restart", (void *)&klpe_futex_wait_restart },
	{ "futex_wait_queue_me", (void *)&klpe_futex_wait_queue_me },
};


static int klp_bsc1176012_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	struct klp_bsc1176012_shared_state *s = shadow_data;

	memset(s, 0, sizeof(*s));

	INIT_LIST_HEAD(&s->compatible_patches);
	spin_lock_init(&s->lock);

	return 0;
}

static struct klp_bsc1176012_compatible_patch klp_bsc1176012_this_patch = {
	.list = LIST_HEAD_INIT(klp_bsc1176012_this_patch.list),
	.patch_mod = THIS_MODULE,
};

/* Must be called with module_mutex held. */
static int __klp_bsc1176012_get_shared_state(void)
{
	klp_bsc1176012_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1176012_SHARED_STATE_ID,
					sizeof(*klp_bsc1176012_shared_state),
					GFP_KERNEL,
					klp_bsc1176012_init_shared_state, NULL);
	if (!klp_bsc1176012_shared_state)
		return -ENOMEM;

	spin_lock(&klp_bsc1176012_shared_state->lock);
	list_add(&klp_bsc1176012_this_patch.list,
		 &klp_bsc1176012_shared_state->compatible_patches);
	spin_unlock(&klp_bsc1176012_shared_state->lock);

	return 0;
}

/* Must be called with module_mutex held. */
static void __klp_bsc1176012_put_shared_state(void)
{
	spin_lock(&klp_bsc1176012_shared_state->lock);
	list_del(&klp_bsc1176012_this_patch.list);
	spin_unlock(&klp_bsc1176012_shared_state->lock);

	if (list_empty(&klp_bsc1176012_shared_state->compatible_patches)) {
		klp_shadow_free(NULL, KLP_BSC1176012_SHARED_STATE_ID, NULL);
	}

	klp_bsc1176012_shared_state = NULL;
}

int livepatch_bsc1176012_init(void)
{
	int r;

	r =  __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	if (r)
		return r;

	mutex_lock(&module_mutex);
	r = __klp_bsc1176012_get_shared_state();
	mutex_unlock(&module_mutex);

	return r;
}

void livepatch_bsc1176012_cleanup(void)
{
	mutex_lock(&module_mutex);
	__klp_bsc1176012_put_shared_state();
	mutex_unlock(&module_mutex);
}
