/*
 * bsc1208911_net_ipv4_inet_connection_sock
 *
 * Fix for CVE-2023-0461, bsc#1208911
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


/* klp-ccp: from net/ipv4/inet_connection_sock.c */
#include <linux/jhash.h>
#include <net/inet_connection_sock.h>

#include <net/tcp.h>

/* klp-ccp: from include/net/request_sock.h */
static void (*klpe_reqsk_queue_alloc)(struct request_sock_queue *queue);

/* klp-ccp: from include/net/inet_sock.h */
static void (*klpe_inet_sk_state_store)(struct sock *sk, int newstate);

/* klp-ccp: from include/net/inet_connection_sock.h */
int klpp_inet_csk_listen_start(struct sock *sk, int backlog);

/* klp-ccp: from net/ipv4/inet_connection_sock.c */
#include <net/inet_timewait_sock.h>
#include <net/route.h>
#include <net/tcp_states.h>

/* klp-ccp: from net/ipv4/inet_connection_sock.c */
#include <net/sock_reuseport.h>

static int inet_ulp_can_listen(const struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ulp_ops && !icsk->icsk_ulp_ops->clone)
		return -EINVAL;

	return 0;
}

int klpp_inet_csk_listen_start(struct sock *sk, int backlog)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	int err;

	err = inet_ulp_can_listen(sk);
	if (unlikely(err))
		return err;
	err = -EADDRINUSE;

	(*klpe_reqsk_queue_alloc)(&icsk->icsk_accept_queue);

	sk->sk_ack_backlog = 0;
	inet_csk_delack_init(sk);

	if (sk->sk_txrehash == SOCK_TXREHASH_DEFAULT)
		sk->sk_txrehash = READ_ONCE(sock_net(sk)->core.sysctl_txrehash);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	(*klpe_inet_sk_state_store)(sk, TCP_LISTEN);
	if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
		inet->inet_sport = htons(inet->inet_num);

		sk_dst_reset(sk);
		err = sk->sk_prot->hash(sk);

		if (likely(!err))
			return 0;
	}

	inet_sk_set_state(sk, TCP_CLOSE);
	return err;
}





#include <linux/kernel.h>
#include "livepatch_bsc1208911.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "inet_sk_state_store", (void *)&klpe_inet_sk_state_store },
	{ "reqsk_queue_alloc", (void *)&klpe_reqsk_queue_alloc },
};

int bsc1208911_net_ipv4_inet_connection_sock_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

