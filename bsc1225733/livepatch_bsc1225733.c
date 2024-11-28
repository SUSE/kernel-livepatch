/*
 * livepatch_bsc1225733
 *
 * Fix for CVE-2024-36904, bsc#1225733
 *
 *  Upstream commit:
 *  f2db7230f73a ("tcp: Use refcount_inc_not_zero() in tcp_twsk_unique().")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  80f0f471a138056a4622c45f7683e68f8fbebcc5
 *
 *  SLE15-SP4 and -SP5 commit:
 *  975b193b41af852baeff63238c7e18954883701e
 *
 *  SLE15-SP6 commit:
 *  d578dcc7c35643084583d73e6f4760898731ba21
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

/* klp-ccp: from net/ipv4/tcp_ipv4.c */
#define pr_fmt(fmt) "TCP: " fmt

#include <linux/bottom_half.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/init.h>

#include <linux/slab.h>
#include <linux/sched.h>

#include <net/net_namespace.h>
#include <net/icmp.h>

/* klp-ccp: from include/linux/btf_ids.h */
#define _LINUX_BTF_IDS_H

/* klp-ccp: from net/ipv4/tcp_ipv4.c */
#include <net/ipv6.h>

#include <net/timewait_sock.h>

#include <linux/ipv6.h>
#include <linux/stddef.h>

#include <linux/seq_file.h>

#include <linux/btf_ids.h>

#include <linux/scatterlist.h>

int klpp_tcp_twsk_unique(struct sock *sk, struct sock *sktw, void *twp)
{
	int reuse = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_tw_reuse);
	const struct inet_timewait_sock *tw = inet_twsk(sktw);
	const struct tcp_timewait_sock *tcptw = tcp_twsk(sktw);
	struct tcp_sock *tp = tcp_sk(sk);

	if (reuse == 2) {
		/* Still does not detect *everything* that goes through
		 * lo, since we require a loopback src or dst address
		 * or direct binding to 'lo' interface.
		 */
		bool loopback = false;
		if (tw->tw_bound_dev_if == LOOPBACK_IFINDEX)
			loopback = true;
#if IS_ENABLED(CONFIG_IPV6)
		if (tw->tw_family == AF_INET6) {
			if (ipv6_addr_loopback(&tw->tw_v6_daddr) ||
			    ipv6_addr_v4mapped_loopback(&tw->tw_v6_daddr) ||
			    ipv6_addr_loopback(&tw->tw_v6_rcv_saddr) ||
			    ipv6_addr_v4mapped_loopback(&tw->tw_v6_rcv_saddr))
				loopback = true;
		} else
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		{
			if (ipv4_is_loopback(tw->tw_daddr) ||
			    ipv4_is_loopback(tw->tw_rcv_saddr))
				loopback = true;
		}
		if (!loopback)
			reuse = 0;
	}

	/* With PAWS, it is safe from the viewpoint
	   of data integrity. Even without PAWS it is safe provided sequence
	   spaces do not overlap i.e. at data rates <= 80Mbit/sec.

	   Actually, the idea is close to VJ's one, only timestamp cache is
	   held not per host, but per port pair and TW bucket is used as state
	   holder.

	   If TW bucket has been already destroyed we fall back to VJ's scheme
	   and use initial timestamp retrieved from peer table.
	 */
	if (tcptw->tw_ts_recent_stamp &&
	    (!twp || (reuse && time_after32(ktime_get_seconds(),
					    tcptw->tw_ts_recent_stamp)))) {
		/* inet_twsk_hashdance() sets sk_refcnt after putting twsk
		 * and releasing the bucket lock.
		 */
		if (unlikely(!refcount_inc_not_zero(&sktw->sk_refcnt)))
			return 0;

		/* In case of repair and re-using TIME-WAIT sockets we still
		 * want to be sure that it is safe as above but honor the
		 * sequence numbers and time stamps set as part of the repair
		 * process.
		 *
		 * Without this check re-using a TIME-WAIT socket with TCP
		 * repair would accumulate a -1 on the repair assigned
		 * sequence number. The first time it is reused the sequence
		 * is -1, the second time -2, etc. This fixes that issue
		 * without appearing to create any others.
		 */
		if (likely(!tp->repair)) {
			u32 seq = tcptw->tw_snd_nxt + 65535 + 2;

			if (!seq)
				seq = 1;
			WRITE_ONCE(tp->write_seq, seq);
			tp->rx_opt.ts_recent	   = tcptw->tw_ts_recent;
			tp->rx_opt.ts_recent_stamp = tcptw->tw_ts_recent_stamp;
		}

		return 1;
	}

	return 0;
}

#include "livepatch_bsc1225733.h"
