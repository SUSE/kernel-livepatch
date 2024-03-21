/*
 * livepatch_bsc1218610
 *
 * Fix for CVE-2023-51779, bsc#1218610
 *
 *  Upstream commit:
 *  2e07e8348ea4 ("Bluetooth: af_bluetooth: Fix Use-After-Free in bt_sock_recvmsg")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  f63e9448b0ffdfc79939c0872bc2da61f34dc8c8
 *
 *  SLE15-SP2 and -SP3 commit:
 *  10b8efcc22849679affc1ed2edc2e15529d8c397
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b8b33097b86b798e46cf030e46dc15313d84644b
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/bluetooth/af_bluetooth.c */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/stringify.h>
#include <linux/sched/signal.h>
#include <asm/ioctls.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from net/bluetooth/af_bluetooth.c */
int klpp_bt_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
		    int flags)
{
	int noblock = flags & MSG_DONTWAIT;
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	size_t copied;
	size_t skblen;
	int err;

	BT_DBG("sock %p sk %p len %zu", sock, sk, len);

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	lock_sock(sk);

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb) {
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			err = 0;

		release_sock(sk);
		return err;
	}

	skblen = skb->len;
	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	skb_reset_transport_header(skb);
	err = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (err == 0) {
		sock_recv_ts_and_drops(msg, sk, skb);

		if (msg->msg_name && bt_sk(sk)->skb_msg_name)
			bt_sk(sk)->skb_msg_name(skb, msg->msg_name,
						&msg->msg_namelen);

		if (bt_sk(sk)->skb_put_cmsg)
			bt_sk(sk)->skb_put_cmsg(skb, msg, sk);
	}

	skb_free_datagram(sk, skb);

	release_sock(sk);

	if (flags & MSG_TRUNC)
		copied = skblen;

	return err ? : copied;
}

#include "livepatch_bsc1218610.h"

#endif /* IS_ENABLED(CONFIG_BT) */
