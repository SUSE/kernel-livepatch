/*
 * livepatch_bsc1255066
 *
 * Fix for CVE-2025-40309, bsc#1255066
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

#include "livepatch_bsc1255066.h"


/* klp-ccp: from net/bluetooth/sco.c */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>
#include <net/bluetooth/sco.h>

extern struct bt_sock_list sco_sk_list;

struct sco_conn {
	struct hci_conn	*hcon;

	spinlock_t	lock;
	struct sock	*sk;

	struct delayed_work	timeout_work;

	unsigned int    mtu;
};

#define sco_conn_lock(c)	spin_lock(&c->lock)
#define sco_conn_unlock(c)	spin_unlock(&c->lock)

void klpp_sco_sock_kill(struct sock *sk);

#define sco_pi(sk) ((struct sco_pinfo *) sk)

struct sco_pinfo {
	struct bt_sock	bt;
	bdaddr_t	src;
	bdaddr_t	dst;
	__u32		flags;
	__u16		setting;
	struct bt_codec codec;
	struct sco_conn	*conn;
};

void klpp_sco_sock_kill(struct sock *sk)
{
	if (!sock_flag(sk, SOCK_ZAPPED) || sk->sk_socket)
		return;

	BT_DBG("sk %p state %d", sk, sk->sk_state);

	/* Sock is dead, so set conn->sk to NULL to avoid possible UAF */
	if (sco_pi(sk)->conn) {
		sco_conn_lock(sco_pi(sk)->conn);
		sco_pi(sk)->conn->sk = NULL;
		sco_conn_unlock(sco_pi(sk)->conn);
	}

	/* Kill poor orphan */
	bt_sock_unlink(&sco_sk_list, sk);
	sock_set_flag(sk, SOCK_DEAD);
	sock_put(sk);
}


#include <linux/livepatch.h>

extern typeof(bt_sock_unlink) bt_sock_unlink
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, bt_sock_unlink);
extern typeof(sco_sk_list) sco_sk_list
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, sco_sk_list);

#endif /* IS_ENABLED(CONFIG_BT) */
