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
#include <linux/sched/signal.h>

#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static void (*klpe_bt_sock_unlink)(struct bt_sock_list *l, struct sock *s);

static struct sock *(*klpe_bt_accept_dequeue)(struct sock *parent, struct socket *newsock);

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from include/net/bluetooth/l2cap.h */
static void (*klpe_l2cap_chan_hold)(struct l2cap_chan *c);
static void (*klpe_l2cap_chan_put)(struct l2cap_chan *c);

static inline bool klpr_l2cap_clear_timer(struct l2cap_chan *chan,
				     struct delayed_work *work)
{
	bool ret;

	/* put(chan) if delayed work cancelled otherwise it
	   is done in delayed work function */
	ret = cancel_delayed_work(work);
	if (ret)
		(*klpe_l2cap_chan_put)(chan);

	return ret;
}

static void (*klpe_l2cap_chan_close)(struct l2cap_chan *chan, int reason);

static void (*klpe_l2cap_chan_busy)(struct l2cap_chan *chan, int busy);

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
static struct bt_sock_list (*klpe_l2cap_sk_list);

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

	(*klpe_l2cap_chan_put)(l2cap_pi(sk)->chan);
	sock_set_flag(sk, SOCK_DEAD);
	sock_put(sk);
}

static int (*klpe_l2cap_sock_shutdown)(struct socket *sock, int how);

int klpp_l2cap_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	int err;
	struct l2cap_chan *chan;

	BT_DBG("sock %p, sk %p", sock, sk);

	if (!sk)
		return 0;

	klpp_l2cap_sock_cleanup_listen(sk);
	(*klpe_bt_sock_unlink)(&(*klpe_l2cap_sk_list), sk);

	err = (*klpe_l2cap_sock_shutdown)(sock, 2);
	chan = l2cap_pi(sk)->chan;

	(*klpe_l2cap_chan_hold)(chan);
	l2cap_chan_lock(chan);

	sock_orphan(sk);
	klpp_l2cap_sock_kill(sk);

	l2cap_chan_unlock(chan);
	(*klpe_l2cap_chan_put)(chan);

	return err;
}

void klpp_l2cap_sock_cleanup_listen(struct sock *parent)
{
	struct sock *sk;

	BT_DBG("parent %p state %s", parent,
	       state_to_string(parent->sk_state));

	/* Close not yet accepted channels */
	while ((sk = (*klpe_bt_accept_dequeue)(parent, NULL))) {
		struct l2cap_chan *chan = l2cap_pi(sk)->chan;

		BT_DBG("child chan %p state %s", chan,
		       state_to_string(chan->state));

		(*klpe_l2cap_chan_hold)(chan);
		l2cap_chan_lock(chan);

		klpr_l2cap_clear_timer(chan, &chan->chan_timer);
		(*klpe_l2cap_chan_close)(chan, ECONNRESET);
		klpp_l2cap_sock_kill(sk);

		l2cap_chan_unlock(chan);
		(*klpe_l2cap_chan_put)(chan);
	}
}

int klpp_l2cap_sock_recv_cb(struct l2cap_chan *chan, struct sk_buff *skb)
{
	struct sock *sk;
	int err;


	/* To avoid race with sock_release, a chan lock needs to be added here
	 * to synchronize the sock.
	 */
	(*klpe_l2cap_chan_hold)(chan);
	l2cap_chan_lock(chan);
	sk = chan->data;

	if (!sk) {
		l2cap_chan_unlock(chan);
		(*klpe_l2cap_chan_put)(chan);
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
		(*klpe_l2cap_chan_busy)(chan, 1);
		err = 0;
	}

done:
	release_sock(sk);
	l2cap_chan_unlock(chan);
	(*klpe_l2cap_chan_put)(chan);

	return err;
}

void klpp_l2cap_sock_close_cb(struct l2cap_chan *chan)
{
	struct sock *sk = chan->data;

	klpp_l2cap_sock_kill(sk);
}


#include "livepatch_bsc1228578.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "bluetooth"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bt_accept_dequeue", (void *)&klpe_bt_accept_dequeue, "bluetooth" },
	{ "bt_sock_unlink", (void *)&klpe_bt_sock_unlink, "bluetooth" },
	{ "l2cap_chan_busy", (void *)&klpe_l2cap_chan_busy, "bluetooth" },
	{ "l2cap_chan_close", (void *)&klpe_l2cap_chan_close, "bluetooth" },
	{ "l2cap_chan_hold", (void *)&klpe_l2cap_chan_hold, "bluetooth" },
	{ "l2cap_chan_put", (void *)&klpe_l2cap_chan_put, "bluetooth" },
	{ "l2cap_sk_list", (void *)&klpe_l2cap_sk_list, "bluetooth" },
	{ "l2cap_sock_shutdown", (void *)&klpe_l2cap_sock_shutdown,
	  "bluetooth" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1228578_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1228578_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
