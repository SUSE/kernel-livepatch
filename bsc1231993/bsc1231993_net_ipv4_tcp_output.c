/*
 * bsc1231993_net_ipv4_tcp_output
 *
 * Fix for CVE-2024-47684, bsc#1231993
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/ipv4/tcp_output.c */
#define pr_fmt(fmt) "TCP: " fmt

#include <net/tcp.h>

/* klp-ccp: from include/net/tcp.h */
static int (*klpe_sysctl_tcp_early_retrans);

/* klp-ccp: from net/ipv4/tcp_output.c */
#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/static_key.h>

#include "livepatch_bsc1231993.h"

bool klpp_tcp_schedule_loss_probe(struct sock *sk, bool advancing_rto)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 rtt = usecs_to_jiffies(tp->srtt_us >> 3);
	u32 timeout, rto_delta_us;

	/* Don't do any loss probe on a Fast Open connection before 3WHS
	 * finishes.
	 */
	if (tp->fastopen_rsk)
		return false;

	/* Schedule a loss probe in 2*RTT for SACK capable connections
	 * in Open state, that are either limited by cwnd or application.
	 */
	if (((*klpe_sysctl_tcp_early_retrans) != 3 && (*klpe_sysctl_tcp_early_retrans) != 4) ||
	    !tp->packets_out || !tcp_is_sack(tp) ||
	    icsk->icsk_ca_state != TCP_CA_Open)
		return false;

	if ((tp->snd_cwnd > tcp_packets_in_flight(tp)) &&
	     tcp_send_head(sk))
		return false;

	/* Probe timeout is at least 1.5*rtt + TCP_DELACK_MAX to account
	 * for delayed ack when there's one outstanding packet. If no RTT
	 * sample is available then probe after TCP_TIMEOUT_INIT.
	 */
	timeout = rtt << 1 ? : TCP_TIMEOUT_INIT;
	if (tp->packets_out == 1)
		timeout = max_t(u32, timeout,
				(rtt + (rtt >> 1) + TCP_DELACK_MAX));
	timeout = max_t(u32, timeout, msecs_to_jiffies(10));

	/* If the RTO formula yields an earlier time, then use that time. */
	rto_delta_us = advancing_rto ?
			jiffies_to_usecs(inet_csk(sk)->icsk_rto) :
			klpp_tcp_rto_delta_us(sk);  /* How far in future is RTO? */
	if (rto_delta_us > 0)
		timeout = min_t(u32, timeout, usecs_to_jiffies(rto_delta_us));

	inet_csk_reset_xmit_timer(sk, ICSK_TIME_LOSS_PROBE, timeout,
				  TCP_RTO_MAX);
	return true;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sysctl_tcp_early_retrans", (void *)&klpe_sysctl_tcp_early_retrans },
};

int bsc1231993_net_ipv4_tcp_output_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
