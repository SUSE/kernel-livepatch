/*
 * livepatch_bsc1215442
 *
 * Fix for CVE-2023-4622, bsc#1215442
 *
 *  Upstream commit:
 *  Not affected
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  c96e3673d40fbc76b959ac3b17bb3cbc5da9a394
 *
 *  SLE15-SP2 and -SP3 commit:
 *  bd1d94281dd1bc06f3b1e5fd7c6d7c8a7777208a
 *
 *  SLE15-SP4 and -SP5 commit:
 *  a6ce336aff6184bdcf29480849d6b894229c1b1c
 *
 *  Copyright (c) 2023 SUSE
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



/* klp-ccp: from net/unix/af_unix.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include <linux/seq_file.h>
#include <net/scm.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/rtnetlink.h>
#include <net/checksum.h>
#include <linux/security.h>

#ifdef CONFIG_SECURITY_NETWORK

static inline bool unix_secdata_eq(struct scm_cookie *scm, struct sk_buff *skb)
{
	return (scm->secid == UNIXCB(skb).secid);
}
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SECURITY_NETWORK */

#define unix_peer(sk) (unix_sk(sk)->peer)

ssize_t klpp_unix_stream_sendpage(struct socket *, struct page *, int offset,
				    size_t size, int flags);

static int (*klpe_unix_scm_to_skb)(struct scm_cookie *scm, struct sk_buff *skb, bool send_fds);

static int (*klpe_maybe_init_creds)(struct scm_cookie *scm,
			    struct socket *socket,
			    const struct sock *other);

static bool unix_skb_scm_eq(struct sk_buff *skb,
			    struct scm_cookie *scm)
{
	const struct unix_skb_parms *u = &UNIXCB(skb);

	return u->pid == scm->pid &&
	       uid_eq(u->uid, scm->creds.uid) &&
	       gid_eq(u->gid, scm->creds.gid) &&
	       unix_secdata_eq(scm, skb);
}

ssize_t klpp_unix_stream_sendpage(struct socket *socket, struct page *page,
				    int offset, size_t size, int flags)
{
	int err;
	bool send_sigpipe = false;
	bool init_scm = true;
	struct scm_cookie scm;
	struct sock *other, *sk = socket->sk;
	struct sk_buff *skb, *newskb = NULL, *tail = NULL;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	other = unix_peer(sk);
	if (!other || sk->sk_state != TCP_ESTABLISHED)
		return -ENOTCONN;

	if (false) {
alloc_skb:
		spin_unlock(&other->sk_receive_queue.lock);
		unix_state_unlock(other);
		mutex_unlock(&unix_sk(other)->iolock);
		newskb = sock_alloc_send_pskb(sk, 0, 0, flags & MSG_DONTWAIT,
					      &err, 0);
		if (!newskb)
			goto err;
	}

	/* we must acquire iolock as we modify already present
	 * skbs in the sk_receive_queue and mess with skb->len
	 */
	err = mutex_lock_interruptible(&unix_sk(other)->iolock);
	if (err) {
		err = flags & MSG_DONTWAIT ? -EAGAIN : -ERESTARTSYS;
		goto err;
	}

	if (sk->sk_shutdown & SEND_SHUTDOWN) {
		err = -EPIPE;
		send_sigpipe = true;
		goto err_unlock;
	}

	unix_state_lock(other);

	if (sock_flag(other, SOCK_DEAD) ||
	    other->sk_shutdown & RCV_SHUTDOWN) {
		err = -EPIPE;
		send_sigpipe = true;
		goto err_state_unlock;
	}

	if (init_scm) {
		err = (*klpe_maybe_init_creds)(&scm, socket, other);
		if (err)
			goto err_state_unlock;
		init_scm = false;
	}

	spin_lock(&other->sk_receive_queue.lock);
	skb = skb_peek_tail(&other->sk_receive_queue);
	if (tail && tail == skb) {
		skb = newskb;
	} else if (!skb || !unix_skb_scm_eq(skb, &scm)) {
		if (newskb) {
			skb = newskb;
		} else {
			tail = skb;
			goto alloc_skb;
		}
	} else if (newskb) {
		/* this is fast path, we don't necessarily need to
		 * call to kfree_skb even though with newskb == NULL
		 * this - does no harm
		 */
		consume_skb(newskb);
		newskb = NULL;
	}

	if (skb_append_pagefrags(skb, page, offset, size)) {
		tail = skb;
		goto alloc_skb;
	}

	skb->len += size;
	skb->data_len += size;
	skb->truesize += size;
	atomic_add(size, &sk->sk_wmem_alloc);

	if (newskb) {
		(*klpe_unix_scm_to_skb)(&scm, skb, false);
		__skb_queue_tail(&other->sk_receive_queue, newskb);
	}

	spin_unlock(&other->sk_receive_queue.lock);
	unix_state_unlock(other);
	mutex_unlock(&unix_sk(other)->iolock);

	other->sk_data_ready(other);
	scm_destroy(&scm);
	return size;

err_state_unlock:
	unix_state_unlock(other);
err_unlock:
	mutex_unlock(&unix_sk(other)->iolock);
err:
	kfree_skb(newskb);
	if (send_sigpipe && !(flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);
	if (!init_scm)
		scm_destroy(&scm);
	return err;
}


#include "livepatch_bsc1215442.h"
#include <linux/kernel.h>
#include "../kallsyms_relocs.h"


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "maybe_init_creds", (void *)&klpe_maybe_init_creds },
	{ "unix_scm_to_skb", (void *)&klpe_unix_scm_to_skb },
};


int livepatch_bsc1215442_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

