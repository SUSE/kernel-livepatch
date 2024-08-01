/*
 * livepatch_bsc1225013
 *
 * Fix for CVE-2024-27398, bsc#1225013
 *
 *  Upstream commit:
 *  483bc0818182 ("Bluetooth: Fix use-after-free bugs caused by sco_sock_timeout")
 *
 *  SLE12-SP5 commit:
 *  231873be8e3a4de16bbdab3876407f0352b1d12c
 *
 *  SLE15-SP2 and -SP3 commit:
 *  2d997261c29194fd4ee74392cc8e72b5e736101a
 *
 *  SLE15-SP4 and -SP5 commit:
 *  d55ff833b5e6c344c24e1c442d67f81a806b3086
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from net/bluetooth/sco.c */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <net/bluetooth/bluetooth.h>

/* ---- SCO connections ---- */
struct sco_conn {
	struct hci_conn	*hcon;

	spinlock_t	lock;
	struct sock	*sk;

	struct delayed_work	timeout_work;

	unsigned int    mtu;
};

#define sco_conn_lock(c)	spin_lock(&c->lock)
#define sco_conn_unlock(c)	spin_unlock(&c->lock)

void klpp_sco_sock_timeout(struct work_struct *work)
{
	struct sco_conn *conn = container_of(work, struct sco_conn,
					     timeout_work.work);
	struct sock *sk;

	sco_conn_lock(conn);
	if (!conn->hcon) {
		sco_conn_unlock(conn);
		return;
	}
	sk = conn->sk;
	if (sk)
		sock_hold(sk);
	sco_conn_unlock(conn);

	if (!sk)
		return;

	BT_DBG("sock %p state %d", sk, sk->sk_state);

	lock_sock(sk);
	sk->sk_err = ETIMEDOUT;
	sk->sk_state_change(sk);
	release_sock(sk);
	sock_put(sk);
}

#include "livepatch_bsc1225013.h"

#endif /* IS_ENABLED(CONFIG_BT) */
