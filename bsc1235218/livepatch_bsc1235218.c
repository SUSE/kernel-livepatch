/*
 * livepatch_bsc1235218
 *
 * Fix for CVE-2024-56600, bsc#1235218
 *
 *  Upstream commit:
 *  9df99c395d0f ("net: inet6: do not leave a dangling sk pointer in inet6_create()")
 *
 *  SLE12-SP5 commit:
 *  a01a9a3cd01733ab79336f62b48bc566a351ff37
 *
 *  SLE15-SP3 commit:
 *  f48987195a2aaeba401bca88caafbe52d37a2391
 *
 *  SLE15-SP4 and -SP5 commit:
 *  4f3d37a173656957032e10ec80a0da6467a273c5
 *
 *  SLE15-SP6 commit:
 *  d23e8d72f20e0e33961a6552534dec8ff76faf26
 *
 *  SLE MICRO-6-0 commit:
 *  d23e8d72f20e0e33961a6552534dec8ff76faf26
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Petr Mladek <pmladek@suse.com>
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

/* klp-ccp: from net/ipv6/af_inet6.c */
#define pr_fmt(fmt) "IPv6: " fmt

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>

#include <linux/stat.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/icmpv6.h>
#include <linux/netfilter_ipv6.h>

#include <net/ip.h>
#include <net/ipv6.h>

#include <net/tcp.h>

#include <net/protocol.h>

#include <net/route.h>

#include <net/addrconf.h>
#include <net/ipv6_stubs.h>
#include <net/ndisc.h>

#include <linux/uaccess.h>

extern struct list_head inetsw6[SOCK_MAX];

static __inline__ struct ipv6_pinfo *inet6_sk_generic(struct sock *sk)
{
	const int offset = sk->sk_prot->obj_size - sizeof(struct ipv6_pinfo);

	return (struct ipv6_pinfo *)(((u8 *)sk) + offset);
}

void inet6_sock_destruct(struct sock *sk);

extern typeof(inet6_sock_destruct) inet6_sock_destruct;

int klpp_inet6_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	struct inet_sock *inet;
	struct ipv6_pinfo *np;
	struct sock *sk;
	struct inet_protosw *answer;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int try_loading_module = 0;
	int err;

	if (protocol < 0 || protocol >= IPPROTO_MAX)
		return -EINVAL;

	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	list_for_each_entry_rcu(answer, &inetsw6[sock->type], list) {

		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	if (err) {
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-10-proto-132-type-1
			 * (net-pf-PF_INET6-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
						PF_INET6, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-10-proto-132
			 * (net-pf-PF_INET6-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
						PF_INET6, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	if (sock->type == SOCK_RAW && !kern &&
	    !ns_capable(net->user_ns, CAP_NET_RAW))
		goto out_rcu_unlock;

	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(!answer_prot->slab);

	err = -ENOBUFS;
	sk = sk_alloc(net, PF_INET6, GFP_KERNEL, answer_prot, kern);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);

	err = 0;
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = SK_CAN_REUSE;

	inet = inet_sk(sk);
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

	if (SOCK_RAW == sock->type) {
		inet->inet_num = protocol;
		if (IPPROTO_RAW == protocol)
			inet->hdrincl = 1;
	}

	sk->sk_destruct		= inet6_sock_destruct;
	sk->sk_family		= PF_INET6;
	sk->sk_protocol		= protocol;

	sk->sk_backlog_rcv	= answer->prot->backlog_rcv;

	inet_sk(sk)->pinet6 = np = inet6_sk_generic(sk);
	np->hop_limit	= -1;
	np->mcast_hops	= IPV6_DEFAULT_MCASTHOPS;
	np->mc_loop	= 1;
	np->mc_all	= 1;
	np->pmtudisc	= IPV6_PMTUDISC_WANT;
	np->repflow	= net->ipv6.sysctl.flowlabel_reflect & FLOWLABEL_REFLECT_ESTABLISHED;
	sk->sk_ipv6only	= net->ipv6.sysctl.bindv6only;
	sk->sk_txrehash = READ_ONCE(net->core.sysctl_txrehash);

	/* Init the ipv4 part of the socket since we can have sockets
	 * using v6 API for ipv4.
	 */
	inet->uc_ttl	= -1;

	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_index	= 0;
	RCU_INIT_POINTER(inet->mc_list, NULL);
	inet->rcv_tos	= 0;

	if (READ_ONCE(net->ipv4.sysctl_ip_no_pmtu_disc))
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	if (inet->inet_num) {
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically shares.
		 */
		inet->inet_sport = htons(inet->inet_num);
		err = sk->sk_prot->hash(sk);
		if (err)
			goto out_sk_release;
	}
	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err)
			goto out_sk_release;
	}

	if (!kern) {
		err = BPF_CGROUP_RUN_PROG_INET_SOCK(sk);
		if (err)
			goto out_sk_release;
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
out_sk_release:
	sk_common_release(sk);
	sock->sk = NULL;
	goto out;
}


#include "livepatch_bsc1235218.h"

#include <linux/livepatch.h>

extern typeof(inetsw6) inetsw6 KLP_RELOC_SYMBOL(vmlinux, vmlinux, inetsw6);
