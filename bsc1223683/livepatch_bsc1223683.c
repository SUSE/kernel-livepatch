/*
 * livepatch_bsc1223683
 *
 * Fix for CVE-2024-26923, bsc#1223683
 *
 *  Upstream commit:
 *  47d8ac011fe1 ("af_unix: Fix garbage collector racing against connect()")
 *
 *  SLE12-SP5 commit:
 *  d9e2f7965009ebebd9bcc9d95590202e6d5f16c8
 *
 *  SLE15-SP2 and -SP3 commit:
 *  9a2eeafd8771477afc6ca99339064ebbb8a29a6a
 *
 *  SLE15-SP4 and -SP5 commit:
 *  94450ecbe527581336bcc2c72f98c8c2a0e0515d
 *
 *  SLE15-SP6 commit:
 *  a683abbc7003c0c84741b6f7cf0fa7efe4731b94
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

/* klp-ccp: from net/unix/garbage.c */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <net/af_unix.h>

/* klp-ccp: from net/unix/garbage.c */
#include <net/scm.h>
#include <net/tcp_states.h>

/* klp-ccp: from net/unix/scm.h */
extern struct list_head gc_inflight_list;
extern spinlock_t unix_gc_lock;

/* klp-ccp: from net/unix/garbage.c */
extern struct list_head gc_candidates;
extern struct wait_queue_head unix_gc_wait;

extern void scan_children(struct sock *x, void (*func)(struct unix_sock *),
			  struct sk_buff_head *hitlist);

extern void dec_inflight(struct unix_sock *usk);

extern void inc_inflight(struct unix_sock *usk);

extern void inc_inflight_move_tail(struct unix_sock *u);

extern bool gc_in_progress;

void klpp_unix_gc(void)
{
	struct sk_buff *next_skb, *skb;
	struct unix_sock *u;
	struct unix_sock *next;
	struct sk_buff_head hitlist;
	struct list_head cursor;
	LIST_HEAD(not_cycle_list);

	spin_lock(&unix_gc_lock);

	/* Avoid a recursive GC. */
	if (gc_in_progress)
		goto out;

	/* Paired with READ_ONCE() in wait_for_unix_gc(). */
	WRITE_ONCE(gc_in_progress, true);

	/* First, select candidates for garbage collection.  Only
	 * in-flight sockets are considered, and from those only ones
	 * which don't have any external reference.
	 *
	 * Holding unix_gc_lock will protect these candidates from
	 * being detached, and hence from gaining an external
	 * reference.  Since there are no possible receivers, all
	 * buffers currently on the candidates' queues stay there
	 * during the garbage collection.
	 *
	 * We also know that no new candidate can be added onto the
	 * receive queues.  Other, non candidate sockets _can_ be
	 * added to queue, so we must make sure only to touch
	 * candidates.
	 *
	 * Embryos, though never candidates themselves, affect which
	 * candidates are reachable by the garbage collector.  Before
	 * being added to a listener's queue, an embryo may already
	 * receive data carrying SCM_RIGHTS, potentially making the
	 * passed socket a candidate that is not yet reachable by the
	 * collector.  It becomes reachable once the embryo is
	 * enqueued.  Therefore, we must ensure that no SCM-laden
	 * embryo appears in a (candidate) listener's queue between
	 * consecutive scan_children() calls.
	 */
	list_for_each_entry_safe(u, next, &gc_inflight_list, link) {
		struct sock *sk = &u->sk;
		long total_refs;
		long inflight_refs;

		total_refs = file_count(sk->sk_socket->file);
		inflight_refs = atomic_long_read(&u->inflight);

		BUG_ON(inflight_refs < 1);
		BUG_ON(total_refs < inflight_refs);
		if (total_refs == inflight_refs) {
			list_move_tail(&u->link, &gc_candidates);
			__set_bit(UNIX_GC_CANDIDATE, &u->gc_flags);
			__set_bit(UNIX_GC_MAYBE_CYCLE, &u->gc_flags);

			if (sk->sk_state == TCP_LISTEN) {
				unix_state_lock(sk);
				unix_state_unlock(sk);
			}
		}
	}

	/* Now remove all internal in-flight reference to children of
	 * the candidates.
	 */
	list_for_each_entry(u, &gc_candidates, link)
		scan_children(&u->sk, dec_inflight, NULL);

	/* Restore the references for children of all candidates,
	 * which have remaining references.  Do this recursively, so
	 * only those remain, which form cyclic references.
	 *
	 * Use a "cursor" link, to make the list traversal safe, even
	 * though elements might be moved about.
	 */
	list_add(&cursor, &gc_candidates);
	while (cursor.next != &gc_candidates) {
		u = list_entry(cursor.next, struct unix_sock, link);

		/* Move cursor to after the current position. */
		list_move(&cursor, &u->link);

		if (atomic_long_read(&u->inflight) > 0) {
			list_move_tail(&u->link, &not_cycle_list);
			__clear_bit(UNIX_GC_MAYBE_CYCLE, &u->gc_flags);
			scan_children(&u->sk, inc_inflight_move_tail, NULL);
		}
	}
	list_del(&cursor);

	/* Now gc_candidates contains only garbage.  Restore original
	 * inflight counters for these as well, and remove the skbuffs
	 * which are creating the cycle(s).
	 */
	skb_queue_head_init(&hitlist);
	list_for_each_entry(u, &gc_candidates, link)
		scan_children(&u->sk, inc_inflight, &hitlist);

	/* not_cycle_list contains those sockets which do not make up a
	 * cycle.  Restore these to the inflight list.
	 */
	while (!list_empty(&not_cycle_list)) {
		u = list_entry(not_cycle_list.next, struct unix_sock, link);
		__clear_bit(UNIX_GC_CANDIDATE, &u->gc_flags);
		list_move_tail(&u->link, &gc_inflight_list);
	}

	spin_unlock(&unix_gc_lock);

	/* We need io_uring to clean its registered files, ignore all io_uring
	 * originated skbs. It's fine as io_uring doesn't keep references to
	 * other io_uring instances and so killing all other files in the cycle
	 * will put all io_uring references forcing it to go through normal
	 * release.path eventually putting registered files.
	 */
	skb_queue_walk_safe(&hitlist, skb, next_skb) {
		if (skb->destructor == io_uring_destruct_scm) {
			__skb_unlink(skb, &hitlist);
			skb_queue_tail(&skb->sk->sk_receive_queue, skb);
		}
	}

	/* Here we are. Hitlist is filled. Die. */
	__skb_queue_purge(&hitlist);

	spin_lock(&unix_gc_lock);

	/* There could be io_uring registered files, just push them back to
	 * the inflight list
	 */
	list_for_each_entry_safe(u, next, &gc_candidates, link)
		list_move_tail(&u->link, &gc_inflight_list);

	/* All candidates should have been detached by now. */
	BUG_ON(!list_empty(&gc_candidates));

	/* Paired with READ_ONCE() in wait_for_unix_gc(). */
	WRITE_ONCE(gc_in_progress, false);

	wake_up(&unix_gc_wait);

 out:
	spin_unlock(&unix_gc_lock);
}


#include "livepatch_bsc1223683.h"

#include <linux/livepatch.h>

extern typeof(dec_inflight) dec_inflight
	 KLP_RELOC_SYMBOL(vmlinux,vmlinux,dec_inflight);
extern typeof(gc_candidates) gc_candidates
	 KLP_RELOC_SYMBOL(vmlinux,vmlinux,gc_candidates);
extern typeof(gc_in_progress) gc_in_progress
	 KLP_RELOC_SYMBOL(vmlinux,vmlinux,gc_in_progress);
extern typeof(inc_inflight) inc_inflight
	 KLP_RELOC_SYMBOL(vmlinux,vmlinux,inc_inflight);
extern typeof(inc_inflight_move_tail) inc_inflight_move_tail
	 KLP_RELOC_SYMBOL(vmlinux,vmlinux,inc_inflight_move_tail);
extern typeof(scan_children) scan_children
	 KLP_RELOC_SYMBOL(vmlinux,vmlinux,scan_children);
extern typeof(unix_gc_wait) unix_gc_wait
	 KLP_RELOC_SYMBOL(vmlinux,vmlinux,unix_gc_wait);
