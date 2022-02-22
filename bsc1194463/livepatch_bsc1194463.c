/*
 * livepatch_bsc1194463
 *
 * Fix for CVE-2021-0920, bsc#1194463
 *
 *  Upstream commit:
 *  cbcf01128d0a ("af_unix: fix garbage collect vs MSG_PEEK")
 *
 *  SLE12-SP3 commit:
 *  665af81366f87b5a542c403a41e572e0c8689ecf
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  167f0fb30909a06acb860c469bc0c579f7071825
 *
 *  SLE15-SP2 and -SP3 commit:
 *  none yet
 *
 *  Copyright (c) 2022 SUSE
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/fcntl.h>
#include <linux/termios.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/af_unix.h>

static spinlock_t *klpe_unix_gc_lock;

static void unix_peek_fds(struct scm_cookie *scm, struct sk_buff *skb)
{
	scm->fp = scm_fp_dup(UNIXCB(skb).fp);

	/*
	 * Garbage collection of unix sockets starts by selecting a set of
	 * candidate sockets which have reference only from being in flight
	 * (total_refs == inflight_refs).  This condition is checked once during
	 * the candidate collection phase, and candidates are marked as such, so
	 * that non-candidates can later be ignored.  While inflight_refs is
	 * protected by unix_gc_lock, total_refs (file count) is not, hence this
	 * is an instantaneous decision.
	 *
	 * Once a candidate, however, the socket must not be reinstalled into a
	 * file descriptor while the garbage collection is in progress.
	 *
	 * If the above conditions are met, then the directed graph of
	 * candidates (*) does not change while unix_gc_lock is held.
	 *
	 * Any operations that changes the file count through file descriptors
	 * (dup, close, sendmsg) does not change the graph since candidates are
	 * not installed in fds.
	 *
	 * Dequeing a candidate via recvmsg would install it into an fd, but
	 * that takes unix_gc_lock to decrement the inflight count, so it's
	 * serialized with garbage collection.
	 *
	 * MSG_PEEK is special in that it does not change the inflight count,
	 * yet does install the socket into an fd.  The following lock/unlock
	 * pair is to ensure serialization with garbage collection.  It must be
	 * done between incrementing the file count and installing the file into
	 * an fd.
	 *
	 * If garbage collection starts after the barrier provided by the
	 * lock/unlock, then it will see the elevated refcount and not mark this
	 * as a candidate.  If a garbage collection is already in progress
	 * before the file count was incremented, then the lock/unlock pair will
	 * ensure that garbage collection is finished before progressing to
	 * installing the fd.
	 *
	 * (*) A -> B where B is on the queue of A or B is on the queue of C
	 * which is on the queue of listening socket A.
	 */
	spin_lock(klpe_unix_gc_lock);
	spin_unlock(klpe_unix_gc_lock);
}

/* klp-ccp: from include/net/af_unix.h */
static void (*klpe_unix_notinflight)(struct user_struct *user, struct file *fp);

/* klp-ccp: from net/unix/af_unix.c */
#include <linux/seq_file.h>
#include <net/scm.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/rtnetlink.h>
#include <net/checksum.h>
#include <linux/security.h>
#include <linux/freezer.h>

#ifdef CONFIG_SECURITY_NETWORK

static inline void unix_set_secdata(struct scm_cookie *scm, struct sk_buff *skb)
{
	scm->secid = UNIXCB(skb).secid;
}

static inline bool unix_secdata_eq(struct scm_cookie *scm, struct sk_buff *skb)
{
	return (scm->secid == UNIXCB(skb).secid);
}
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SECURITY_NETWORK */

int klpp_unix_dgram_recvmsg(struct socket *, struct msghdr *, size_t, int);

static void klpr_unix_detach_fds(struct scm_cookie *scm, struct sk_buff *skb)
{
	int i;

	scm->fp = UNIXCB(skb).fp;
	UNIXCB(skb).fp = NULL;

	for (i = scm->fp->count-1; i >= 0; i--)
		(*klpe_unix_notinflight)(scm->fp->user, scm->fp->fp[i]);
}

static bool unix_skb_scm_eq(struct sk_buff *skb,
			    struct scm_cookie *scm)
{
	const struct unix_skb_parms *u = &UNIXCB(skb);

	return u->pid == scm->pid &&
	       uid_eq(u->uid, scm->creds.uid) &&
	       gid_eq(u->gid, scm->creds.gid) &&
	       unix_secdata_eq(scm, skb);
}

static void unix_copy_addr(struct msghdr *msg, struct sock *sk)
{
	struct unix_address *addr = smp_load_acquire(&unix_sk(sk)->addr);

	if (addr) {
		msg->msg_namelen = addr->len;
		memcpy(msg->msg_name, addr->name, addr->len);
	}
}

int klpp_unix_dgram_recvmsg(struct socket *sock, struct msghdr *msg,
			      size_t size, int flags)
{
	struct scm_cookie scm;
	struct sock *sk = sock->sk;
	struct unix_sock *u = unix_sk(sk);
	struct sk_buff *skb, *last;
	long timeo;
	int err;
	int peeked, skip;

	err = -EOPNOTSUPP;
	if (flags&MSG_OOB)
		goto out;

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	do {
		mutex_lock(&u->iolock);

		skip = sk_peek_offset(sk, flags);
		skb = __skb_try_recv_datagram(sk, flags, NULL, &peeked, &skip,
					      &err, &last);
		if (skb)
			break;

		mutex_unlock(&u->iolock);

		if (err != -EAGAIN)
			break;
	} while (timeo &&
		 !__skb_wait_for_more_packets(sk, &err, &timeo, last));

	if (!skb) { /* implies iolock unlocked */
		unix_state_lock(sk);
		/* Signal EOF on disconnected non-blocking SEQPACKET socket. */
		if (sk->sk_type == SOCK_SEQPACKET && err == -EAGAIN &&
		    (sk->sk_shutdown & RCV_SHUTDOWN))
			err = 0;
		unix_state_unlock(sk);
		goto out;
	}

	if (wq_has_sleeper(&u->peer_wait))
		wake_up_interruptible_sync_poll(&u->peer_wait,
						POLLOUT | POLLWRNORM |
						POLLWRBAND);

	if (msg->msg_name)
		unix_copy_addr(msg, skb->sk);

	if (size > skb->len - skip)
		size = skb->len - skip;
	else if (size < skb->len - skip)
		msg->msg_flags |= MSG_TRUNC;

	err = skb_copy_datagram_msg(skb, skip, msg, size);
	if (err)
		goto out_free;

	if (sock_flag(sk, SOCK_RCVTSTAMP))
		__sock_recv_timestamp(msg, sk, skb);

	memset(&scm, 0, sizeof(scm));

	scm_set_cred(&scm, UNIXCB(skb).pid, UNIXCB(skb).uid, UNIXCB(skb).gid);
	unix_set_secdata(&scm, skb);

	if (!(flags & MSG_PEEK)) {
		if (UNIXCB(skb).fp)
			klpr_unix_detach_fds(&scm, skb);

		sk_peek_offset_bwd(sk, skb->len);
	} else {
		/* It is questionable: on PEEK we could:
		   - do not return fds - good, but too simple 8)
		   - return fds, and do not return them on read (old strategy,
		     apparently wrong)
		   - clone fds (I chose it for now, it is the most universal
		     solution)

		   POSIX 1003.1g does not actually define this clearly
		   at all. POSIX 1003.1g doesn't define a lot of things
		   clearly however!

		*/

		sk_peek_offset_fwd(sk, size);

		if (UNIXCB(skb).fp)
			unix_peek_fds(&scm, skb);
	}
	err = (flags & MSG_TRUNC) ? skb->len - skip : size;

	scm_recv(sock, msg, &scm, flags);

out_free:
	skb_free_datagram(sk, skb);
	mutex_unlock(&u->iolock);
out:
	return err;
}

static long unix_stream_data_wait(struct sock *sk, long timeo,
				  struct sk_buff *last, unsigned int last_len,
				  bool freezable)
{
	struct sk_buff *tail;
	DEFINE_WAIT(wait);

	unix_state_lock(sk);

	for (;;) {
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

		tail = skb_peek_tail(&sk->sk_receive_queue);
		if (tail != last ||
		    (tail && tail->len != last_len) ||
		    sk->sk_err ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current) ||
		    !timeo)
			break;

		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		unix_state_unlock(sk);
		if (freezable)
			timeo = freezable_schedule_timeout(timeo);
		else
			timeo = schedule_timeout(timeo);
		unix_state_lock(sk);

		if (sock_flag(sk, SOCK_DEAD))
			break;

		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	}

	finish_wait(sk_sleep(sk), &wait);
	unix_state_unlock(sk);
	return timeo;
}

static unsigned int unix_skb_len(const struct sk_buff *skb)
{
	return skb->len - UNIXCB(skb).consumed;
}

struct unix_stream_read_state {
	int (*recv_actor)(struct sk_buff *, int, int,
			  struct unix_stream_read_state *);
	struct socket *socket;
	struct msghdr *msg;
	struct pipe_inode_info *pipe;
	size_t size;
	int flags;
	unsigned int splice_flags;
};

int klpp_unix_stream_read_generic(struct unix_stream_read_state *state,
				    bool freezable)
{
	struct scm_cookie scm;
	struct socket *sock = state->socket;
	struct sock *sk = sock->sk;
	struct unix_sock *u = unix_sk(sk);
	int copied = 0;
	int flags = state->flags;
	int noblock = flags & MSG_DONTWAIT;
	bool check_creds = false;
	int target;
	int err = 0;
	long timeo;
	int skip;
	size_t size = state->size;
	unsigned int last_len;

	if (unlikely(sk->sk_state != TCP_ESTABLISHED)) {
		err = -EINVAL;
		goto out;
	}

	if (unlikely(flags & MSG_OOB)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, size);
	timeo = sock_rcvtimeo(sk, noblock);

	memset(&scm, 0, sizeof(scm));

	/* Lock the socket to prevent queue disordering
	 * while sleeps in memcpy_tomsg
	 */
	mutex_lock(&u->iolock);

	if (flags & MSG_PEEK)
		skip = sk_peek_offset(sk, flags);
	else
		skip = 0;

	do {
		int chunk;
		bool drop_skb;
		struct sk_buff *skb, *last;

redo:
		unix_state_lock(sk);
		if (sock_flag(sk, SOCK_DEAD)) {
			err = -ECONNRESET;
			goto unlock;
		}
		last = skb = skb_peek(&sk->sk_receive_queue);
		last_len = last ? last->len : 0;
again:
		if (skb == NULL) {
			unix_sk(sk)->recursion_level = 0;
			if (copied >= target)
				goto unlock;

			/*
			 *	POSIX 1003.1g mandates this order.
			 */

			err = sock_error(sk);
			if (err)
				goto unlock;
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				goto unlock;

			unix_state_unlock(sk);
			if (!timeo) {
				err = -EAGAIN;
				break;
			}

			mutex_unlock(&u->iolock);

			timeo = unix_stream_data_wait(sk, timeo, last,
						      last_len, freezable);

			if (signal_pending(current)) {
				err = sock_intr_errno(timeo);
				scm_destroy(&scm);
				goto out;
			}

			mutex_lock(&u->iolock);
			goto redo;
unlock:
			unix_state_unlock(sk);
			break;
		}

		while (skip >= unix_skb_len(skb)) {
			skip -= unix_skb_len(skb);
			last = skb;
			last_len = skb->len;
			skb = skb_peek_next(skb, &sk->sk_receive_queue);
			if (!skb)
				goto again;
		}

		unix_state_unlock(sk);

		if (check_creds) {
			/* Never glue messages from different writers */
			if (!unix_skb_scm_eq(skb, &scm))
				break;
		} else if (test_bit(SOCK_PASSCRED, &sock->flags)) {
			/* Copy credentials */
			scm_set_cred(&scm, UNIXCB(skb).pid, UNIXCB(skb).uid, UNIXCB(skb).gid);
			unix_set_secdata(&scm, skb);
			check_creds = true;
		}

		/* Copy address just once */
		if (state->msg && state->msg->msg_name) {
			DECLARE_SOCKADDR(struct sockaddr_un *, sunaddr,
					 state->msg->msg_name);
			unix_copy_addr(state->msg, skb->sk);
			sunaddr = NULL;
		}

		chunk = min_t(unsigned int, unix_skb_len(skb) - skip, size);
		skb_get(skb);
		chunk = state->recv_actor(skb, skip, chunk, state);
		drop_skb = !unix_skb_len(skb);
		/* skb is only safe to use if !drop_skb */
		consume_skb(skb);
		if (chunk < 0) {
			if (copied == 0)
				copied = -EFAULT;
			break;
		}
		copied += chunk;
		size -= chunk;

		if (drop_skb) {
			/* the skb was touched by a concurrent reader;
			 * we should not expect anything from this skb
			 * anymore and assume it invalid - we can be
			 * sure it was dropped from the socket queue
			 *
			 * let's report a short read
			 */
			err = 0;
			break;
		}

		/* Mark read part of skb as used */
		if (!(flags & MSG_PEEK)) {
			UNIXCB(skb).consumed += chunk;

			sk_peek_offset_bwd(sk, chunk);

			if (UNIXCB(skb).fp)
				klpr_unix_detach_fds(&scm, skb);

			if (unix_skb_len(skb))
				break;

			skb_unlink(skb, &sk->sk_receive_queue);
			consume_skb(skb);

			if (scm.fp)
				break;
		} else {
			/* It is questionable, see note in unix_dgram_recvmsg.
			 */
			if (UNIXCB(skb).fp)
				unix_peek_fds(&scm, skb);

			sk_peek_offset_fwd(sk, chunk);

			if (UNIXCB(skb).fp)
				break;

			skip = 0;
			last = skb;
			last_len = skb->len;
			unix_state_lock(sk);
			skb = skb_peek_next(skb, &sk->sk_receive_queue);
			if (skb)
				goto again;
			unix_state_unlock(sk);
			break;
		}
	} while (size);

	mutex_unlock(&u->iolock);
	if (state->msg)
		scm_recv(sock, state->msg, &scm, flags);
	else
		scm_destroy(&scm);
out:
	return copied ? : err;
}




#include "livepatch_bsc1194463.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "unix_notinflight", (void *)&klpe_unix_notinflight },
	{ "unix_gc_lock", (void *)&klpe_unix_gc_lock },
};

int livepatch_bsc1194463_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
