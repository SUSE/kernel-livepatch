/*
 * bsc1285686_net_ipv4_af_inet
 *
 * Fix for CVE-2026-98432, bsc#1285686
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


#include "livepatch_bsc1285686.h"


/* klp-ccp: from net/ipv4/af_inet.c */
#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/slab.h>

#include <linux/uaccess.h>

#include <linux/inet.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <net/ping.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/raw.h>
#include <net/icmp.h>
#include <net/inet_common.h>

/* klp-ccp: from include/net/inet_common.h */
/* klp-ccp: from net/ipv4/af_inet.c */
#include <net/ip_tunnels.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/secure_seq.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <net/l3mdev.h>


#undef kfree_rcu
#define kfree_rcu(ptr, rhf)						\
do {									\
	typeof (ptr) ___p = (ptr);					\
									\
	if (___p)							\
		__kfree_rcu(&((___p)->rhf), offsetof(typeof(*(ptr)), rhf)); \
} while (0)


void klpp_inet_sock_destruct(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	sk_mem_reclaim(sk);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		pr_err("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	}
	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	WARN_ON(sk->sk_wmem_queued);
	WARN_ON(sk->sk_forward_alloc);

	kfree_rcu(rcu_dereference_protected(inet->inet_opt, 1), rcu);
	dst_release(rcu_dereference_check(sk->sk_dst_cache, 1));
	dst_release(rcu_dereference_protected(sk->sk_rx_dst, 1));
	sk_refcnt_debug_dec(sk);
}



