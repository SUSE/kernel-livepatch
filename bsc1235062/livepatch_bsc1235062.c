/*
 * livepatch_bsc1235062
 *
 * Fix for CVE-2024-56605, bsc#1235062
 *
 *  Upstream commit:
 *  7c4f78cdb8e7 ("Bluetooth: L2CAP: do not leave dangling sk pointer on error in l2cap_sock_create()")
 *
 *  SLE12-SP5 commit:
 *  6ac1393bc69ad2def6d67511ac2152fe4aa22e58
 *
 *  SLE15-SP3 commit:
 *  20f98a1dccdbe1cbec4572120239070d8d0bcede
 *
 *  SLE15-SP4 and -SP5 commit:
 *  c461209d99bef5301941c51b29154648b21d3447
 *
 *  SLE15-SP6 commit:
 *  d023f1f3e97051defc7bdb07558756ae07c2736f
 *
 *  SLE MICRO-6-0 commit:
 *  d023f1f3e97051defc7bdb07558756ae07c2736f
 *
 *  Copyright (c) 2025 SUSE
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
static void (*klpe_bt_sock_link)(struct bt_sock_list *l, struct sock *s);

static void (*klpe_bt_accept_enqueue)(struct sock *parent, struct sock *sk, bool bh);

static void (*klpe_bt_sock_reclassify_lock)(struct sock *sk, int proto);

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from include/net/bluetooth/l2cap.h */
static void (*klpe_l2cap_chan_hold)(struct l2cap_chan *c);

static struct l2cap_chan *(*klpe_l2cap_chan_create)(void);

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
static struct bt_sock_list (*klpe_l2cap_sk_list);

static const struct proto_ops (*klpe_l2cap_sock_ops);
static void (*klpe_l2cap_sock_init)(struct sock *sk, struct sock *parent);
static struct sock *klpp_l2cap_sock_alloc(struct net *net, struct socket *sock,
				     int proto, gfp_t prio, int kern);

struct l2cap_chan *klpp_l2cap_sock_new_connection_cb(struct l2cap_chan *chan)
{
	struct sock *sk, *parent = chan->data;

	lock_sock(parent);

	/* Check for backlog size */
	if (sk_acceptq_is_full(parent)) {
		BT_DBG("backlog full %d", parent->sk_ack_backlog);
		release_sock(parent);
		return NULL;
	}

	sk = klpp_l2cap_sock_alloc(sock_net(parent), NULL, BTPROTO_L2CAP,
			      GFP_ATOMIC, 0);
	if (!sk) {
		release_sock(parent);
		return NULL;
        }

	(*klpe_bt_sock_reclassify_lock)(sk, BTPROTO_L2CAP);

	(*klpe_l2cap_sock_init)(sk, parent);

	(*klpe_bt_accept_enqueue)(parent, sk, false);

	release_sock(parent);

	return l2cap_pi(sk)->chan;
}

static void (*klpe_l2cap_sock_destruct)(struct sock *sk);

static void (*klpe_l2cap_sock_init)(struct sock *sk, struct sock *parent);

static struct proto (*klpe_l2cap_proto);

static struct sock *klpp_l2cap_sock_alloc(struct net *net, struct socket *sock,
				     int proto, gfp_t prio, int kern)
{
	struct sock *sk;
	struct l2cap_chan *chan;

	sk = sk_alloc(net, PF_BLUETOOTH, prio, &(*klpe_l2cap_proto), kern);
	if (!sk)
		return NULL;

	sock_init_data(sock, sk);
	INIT_LIST_HEAD(&bt_sk(sk)->accept_q);

	sk->sk_destruct = (*klpe_l2cap_sock_destruct);
	sk->sk_sndtimeo = L2CAP_CONN_TIMEOUT;

	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
	sk->sk_state = BT_OPEN;

	chan = (*klpe_l2cap_chan_create)();
	if (!chan) {
		sk_free(sk);
		sock->sk = NULL;
		return NULL;
	}

	(*klpe_l2cap_chan_hold)(chan);

	l2cap_pi(sk)->chan = chan;

	return sk;
}

int klpp_l2cap_sock_create(struct net *net, struct socket *sock, int protocol,
			     int kern)
{
	struct sock *sk;

	BT_DBG("sock %p", sock);

	sock->state = SS_UNCONNECTED;

	if (sock->type != SOCK_SEQPACKET && sock->type != SOCK_STREAM &&
	    sock->type != SOCK_DGRAM && sock->type != SOCK_RAW)
		return -ESOCKTNOSUPPORT;

	if (sock->type == SOCK_RAW && !kern && !capable(CAP_NET_RAW))
		return -EPERM;

	sock->ops = &(*klpe_l2cap_sock_ops);

	sk = klpp_l2cap_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	if (!sk)
		return -ENOMEM;

	(*klpe_l2cap_sock_init)(sk, NULL);
	(*klpe_bt_sock_link)(&(*klpe_l2cap_sk_list), sk);
	return 0;
}

static const struct proto_ops (*klpe_l2cap_sock_ops);


#include "livepatch_bsc1235062.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "bluetooth"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bt_accept_enqueue", (void *)&klpe_bt_accept_enqueue, "bluetooth" },
	{ "bt_sock_link", (void *)&klpe_bt_sock_link, "bluetooth" },
	{ "bt_sock_reclassify_lock", (void *)&klpe_bt_sock_reclassify_lock,
	  "bluetooth" },
	{ "l2cap_chan_create", (void *)&klpe_l2cap_chan_create, "bluetooth" },
	{ "l2cap_chan_hold", (void *)&klpe_l2cap_chan_hold, "bluetooth" },
	{ "l2cap_proto", (void *)&klpe_l2cap_proto, "bluetooth" },
	{ "l2cap_sk_list", (void *)&klpe_l2cap_sk_list, "bluetooth" },
	{ "l2cap_sock_destruct", (void *)&klpe_l2cap_sock_destruct,
	  "bluetooth" },
	{ "l2cap_sock_init", (void *)&klpe_l2cap_sock_init, "bluetooth" },
	{ "l2cap_sock_ops", (void *)&klpe_l2cap_sock_ops, "bluetooth" },
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

int livepatch_bsc1235062_init(void)
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

void livepatch_bsc1235062_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
