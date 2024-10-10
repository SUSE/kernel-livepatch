/*
 * livepatch_bsc1228786
 *
 * Fix for CVE-2024-40954, bsc#1228786
 *
 *  Upstream commit:
 *  6cd4a78d962b ("net: do not leave a dangling sk pointer, when socket creation fails")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  8f44f810e2d8ae285da899161ca12080b27bfc59
 *
 *  SLE15-SP6 commit:
 *  5ea4aa980449d74b4222b6736f2ca11018d0294e
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

/* klp-ccp: from net/core/sock.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/unaligned.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/errqueue.h>

/* klp-ccp: from net/core/sock.c */
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/user_namespace.h>
#include <linux/static_key.h>
#include <linux/memcontrol.h>
#include <linux/prefetch.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/request_sock.h>
#include <net/sock.h>
#include <linux/net_tstamp.h>
#include <net/xfrm.h>
#include <linux/ipsec.h>
#include <net/netprio_cgroup.h>
/* klp-ccp: from net/core/dev.h */
#include <linux/types.h>

void klpp_sk_common_release(struct sock *sk)
{
	if (sk->sk_prot->destroy)
		sk->sk_prot->destroy(sk);

	/*
	 * Observation: when sk_common_release is called, processes have
	 * no access to socket. But net still has.
	 * Step one, detach it from networking:
	 *
	 * A. Remove from hash tables.
	 */

	sk->sk_prot->unhash(sk);

	if (sk->sk_socket)
		sk->sk_socket->sk = NULL;

	/*
	 * In this point socket cannot receive new packets, but it is possible
	 * that some packets are in flight because some CPU runs receiver and
	 * did hash table lookup before we unhashed socket. They will achieve
	 * receive queue and will be purged by socket destructor.
	 *
	 * Also we still have packets pending on receive queue and probably,
	 * our own packets waiting in device queues. sock_destroy will drain
	 * receive queue, but transmitted packets will delay socket destruction
	 * until the last reference will be released.
	 */

	sock_orphan(sk);

	xfrm_sk_free_policy(sk);

	sock_put(sk);
}

#include "livepatch_bsc1228786.h"
