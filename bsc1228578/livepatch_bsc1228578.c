/*
 * livepatch_bsc1228578
 *
 * Fix for CVE-2024-41062, bsc#1228578
 *
 *  Upstream commit:
 *  89e856e124f9 ("bluetooth/l2cap: sync sock recv cb and release")
 *
 *  SLE12-SP5 commit:
 *  729406166eaf4196706aa74f5fba5347cefad907
 *
 *  SLE15-SP3 commit:
 *  7440805c858810982c046f3e34559728ad90801d
 *
 *  SLE15-SP4 and -SP5 commit:
 *  5b1f7430fca17d2b3ed74f288b8058778f1fc7f8
 *
 *  SLE15-SP6 commit:
 *  655352699615abd6822e96cb0ec5e27e1e710ae7
 *
 *  SLE MICRO-6-0 commit:
 *  655352699615abd6822e96cb0ec5e27e1e710ae7
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
#include <linux/module.h>
#include <linux/export.h>
#include <linux/filter.h>
#include <linux/sched/signal.h>

#include <net/bluetooth/bluetooth.h>

#include <net/bluetooth/l2cap.h>

extern struct bt_sock_list l2cap_sk_list;

void klpp_l2cap_sock_cleanup_listen(struct sock *parent);

static void klpp_l2cap_sock_kill(struct sock *sk)
{
	if (!sock_flag(sk, SOCK_ZAPPED) || sk->sk_socket)
		return;

	BT_DBG("sk %p state %s", sk, state_to_string(sk->sk_state));

	/* Sock is dead, so set chan data to NULL, avoid other task use invalid
	 * sock pointer.
	 */
	l2cap_pi(sk)->chan->data = NULL;
	/* Kill poor orphan */

	l2cap_chan_put(l2cap_pi(sk)->chan);
	sock_set_flag(sk, SOCK_DEAD);
	sock_put(sk);
}

extern int l2cap_sock_shutdown(struct socket *sock, int how);

int klpp_l2cap_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	int err;
	struct l2cap_chan *chan;

	BT_DBG("sock %p, sk %p", sock, sk);

	if (!sk)
		return 0;

	klpp_l2cap_sock_cleanup_listen(sk);
	bt_sock_unlink(&l2cap_sk_list, sk);

	err = l2cap_sock_shutdown(sock, SHUT_RDWR);
	chan = l2cap_pi(sk)->chan;

	l2cap_chan_hold(chan);
	l2cap_chan_lock(chan);

	sock_orphan(sk);
	klpp_l2cap_sock_kill(sk);

	l2cap_chan_unlock(chan);
	l2cap_chan_put(chan);

	return err;
}

void klpp_l2cap_sock_cleanup_listen(struct sock *parent)
{
	struct sock *sk;

	BT_DBG("parent %p state %s", parent,
	       state_to_string(parent->sk_state));

	/* Close not yet accepted channels */
	while ((sk = bt_accept_dequeue(parent, NULL))) {
		struct l2cap_chan *chan = l2cap_pi(sk)->chan;

		BT_DBG("child chan %p state %s", chan,
		       state_to_string(chan->state));

		l2cap_chan_hold(chan);
		l2cap_chan_lock(chan);

		__clear_chan_timer(chan);
		l2cap_chan_close(chan, ECONNRESET);
		klpp_l2cap_sock_kill(sk);

		l2cap_chan_unlock(chan);
		l2cap_chan_put(chan);
	}
}

int klpp_l2cap_sock_recv_cb(struct l2cap_chan *chan, struct sk_buff *skb)
{
	struct sock *sk;
	int err;


	/* To avoid race with sock_release, a chan lock needs to be added here
	 * to synchronize the sock.
	 */
	l2cap_chan_hold(chan);
	l2cap_chan_lock(chan);
	sk = chan->data;

	if (!sk) {
		l2cap_chan_unlock(chan);
		l2cap_chan_put(chan);
		return -ENXIO;
	}

	lock_sock(sk);
	if (l2cap_pi(sk)->rx_busy_skb) {
		err = -ENOMEM;
		goto done;
	}

	if (chan->mode != L2CAP_MODE_ERTM &&
	    chan->mode != L2CAP_MODE_STREAMING) {
		/* Even if no filter is attached, we could potentially
		 * get errors from security modules, etc.
		 */
		err = sk_filter(sk, skb);
		if (err)
			goto done;
	}

	err = __sock_queue_rcv_skb(sk, skb);

	/* For ERTM, handle one skb that doesn't fit into the recv
	 * buffer.  This is important to do because the data frames
	 * have already been acked, so the skb cannot be discarded.
	 *
	 * Notify the l2cap core that the buffer is full, so the
	 * LOCAL_BUSY state is entered and no more frames are
	 * acked and reassembled until there is buffer space
	 * available.
	 */
	if (err < 0 && chan->mode == L2CAP_MODE_ERTM) {
		l2cap_pi(sk)->rx_busy_skb = skb;
		l2cap_chan_busy(chan, 1);
		err = 0;
	}

done:
	release_sock(sk);
	l2cap_chan_unlock(chan);
	l2cap_chan_put(chan);

	return err;
}

void klpp_l2cap_sock_close_cb(struct l2cap_chan *chan)
{
	struct sock *sk = chan->data;

	if (!sk)
		return;

	klpp_l2cap_sock_kill(sk);
}


#include "livepatch_bsc1228578.h"

#include <linux/livepatch.h>

extern typeof(bt_accept_dequeue) bt_accept_dequeue
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, bt_accept_dequeue);
extern typeof(bt_sock_unlink) bt_sock_unlink
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, bt_sock_unlink);
extern typeof(l2cap_chan_busy) l2cap_chan_busy
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, l2cap_chan_busy);
extern typeof(l2cap_chan_close) l2cap_chan_close
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, l2cap_chan_close);
extern typeof(l2cap_chan_hold) l2cap_chan_hold
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, l2cap_chan_hold);
extern typeof(l2cap_chan_put) l2cap_chan_put
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, l2cap_chan_put);
extern typeof(l2cap_sk_list) l2cap_sk_list
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, l2cap_sk_list);
extern typeof(l2cap_sock_shutdown) l2cap_sock_shutdown
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, l2cap_sock_shutdown);

#endif /* IS_ENABLED(CONFIG_BT) */
