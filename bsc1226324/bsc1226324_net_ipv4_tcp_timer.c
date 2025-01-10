/*
 * bsc1226324_net_ipv4_tcp_timer
 *
 * Fix for CVE-2024-36971, bsc#1226324
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/ipv4/tcp_timer.c */
#include <linux/module.h>
#include <linux/gfp.h>
#include <net/tcp.h>

#include "bsc1226324_net_sock.h"

/* klp-ccp: from net/ipv4/tcp_timer.c */
static u32 tcp_clamp_rto_to_user_timeout(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 elapsed, start_ts;
	s32 remaining;

	start_ts = tcp_sk(sk)->retrans_stamp;
	if (!icsk->icsk_user_timeout)
		return icsk->icsk_rto;
	elapsed = tcp_time_stamp(tcp_sk(sk)) - start_ts;
	remaining = icsk->icsk_user_timeout - elapsed;
	if (remaining <= 0)
		return 1; /* user timeout has passed; fire ASAP */

	return min_t(u32, icsk->icsk_rto, msecs_to_jiffies(remaining));
}

extern void tcp_write_err(struct sock *sk);

extern int tcp_out_of_resources(struct sock *sk, bool do_reset);

static int tcp_orphan_retries(struct sock *sk, bool alive)
{
	int retries = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_orphan_retries); /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (READ_ONCE(sk->sk_err_soft) && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	const struct net *net = sock_net(sk);
	int mss;

	/* Black hole detection */
	if (!READ_ONCE(net->ipv4.sysctl_tcp_mtu_probing))
		return;

	if (!icsk->icsk_mtup.enabled) {
		icsk->icsk_mtup.enabled = 1;
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
	} else {
		mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1;
		mss = min(READ_ONCE(net->ipv4.sysctl_tcp_base_mss), mss);
		mss = max(mss, READ_ONCE(net->ipv4.sysctl_tcp_mtu_probe_floor));
		mss = max(mss, READ_ONCE(net->ipv4.sysctl_tcp_min_snd_mss));
		icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
	}
	tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
}

static unsigned int tcp_model_timeout(struct sock *sk,
				      unsigned int boundary,
				      unsigned int rto_base)
{
	unsigned int linear_backoff_thresh, timeout;

	linear_backoff_thresh = ilog2(TCP_RTO_MAX / rto_base);
	if (boundary <= linear_backoff_thresh)
		timeout = ((2 << boundary) - 1) * rto_base;
	else
		timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
			(boundary - linear_backoff_thresh) * TCP_RTO_MAX;
	return jiffies_to_msecs(timeout);
}

static bool retransmits_timed_out(struct sock *sk,
				  unsigned int boundary,
				  unsigned int timeout)
{
	unsigned int start_ts;

	if (!inet_csk(sk)->icsk_retransmits)
		return false;

	start_ts = tcp_sk(sk)->retrans_stamp;
	if (likely(timeout == 0)) {
		unsigned int rto_base = TCP_RTO_MIN;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			rto_base = tcp_timeout_init(sk);
		timeout = tcp_model_timeout(sk, boundary, rto_base);
	}

	return (s32)(tcp_time_stamp(tcp_sk(sk)) - start_ts - timeout) >= 0;
}

static int klpp_tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	bool expired = false, do_reset;
	int retry_until, max_retransmits;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		if (icsk->icsk_retransmits)
			klpp___dst_negative_advice(sk);
		retry_until = icsk->icsk_syn_retries ? :
			READ_ONCE(net->ipv4.sysctl_tcp_syn_retries);

		max_retransmits = retry_until;
		if (sk->sk_state == TCP_SYN_SENT)
			max_retransmits += READ_ONCE(net->ipv4.sysctl_tcp_syn_linear_timeouts);

		expired = icsk->icsk_retransmits >= max_retransmits;
	} else {
		if (retransmits_timed_out(sk, READ_ONCE(net->ipv4.sysctl_tcp_retries1), 0)) {
			/* Black hole detection */
			tcp_mtu_probing(icsk, sk);

			klpp___dst_negative_advice(sk);
		}

		retry_until = READ_ONCE(net->ipv4.sysctl_tcp_retries2);
		if (sock_flag(sk, SOCK_DEAD)) {
			const bool alive = icsk->icsk_rto < TCP_RTO_MAX;

			retry_until = tcp_orphan_retries(sk, alive);
			do_reset = alive ||
				!retransmits_timed_out(sk, retry_until, 0);

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}
	if (!expired)
		expired = retransmits_timed_out(sk, retry_until,
						icsk->icsk_user_timeout);
	tcp_fastopen_active_detect_blackhole(sk, expired);

	if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RTO_CB_FLAG))
		tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RTO_CB,
				  icsk->icsk_retransmits,
				  icsk->icsk_rto, (int)expired);

	if (expired) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}

	if (sk_rethink_txhash(sk)) {
		tp->timeout_rehash++;
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEOUTREHASH);
	}

	return 0;
}

static void tcp_update_rto_stats(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (!icsk->icsk_retransmits) {
		tp->total_rto_recoveries++;
		tp->rto_stamp = tcp_time_stamp(tp);
	}
	icsk->icsk_retransmits++;
	tp->total_rto++;
}

static void tcp_fastopen_synack_timer(struct sock *sk, struct request_sock *req)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_retries;

	req->rsk_ops->syn_ack_timeout(req);

	/* add one more retry for fastopen */
	max_retries = icsk->icsk_syn_retries ? :
		READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_synack_retries) + 1;

	if (req->num_timeout >= max_retries) {
		tcp_write_err(sk);
		return;
	}
	/* Lower cwnd after certain SYNACK timeout like tcp_init_transfer() */
	if (icsk->icsk_retransmits == 1)
		tcp_enter_loss(sk);
	/* XXX (TFO) - Unlike regular SYN-ACK retransmit, we ignore error
	 * returned from rtx_syn_ack() to make it more persistent like
	 * regular retransmit because if the child socket has been accepted
	 * it's not good to give up too easily.
	 */
	inet_rtx_syn_ack(sk, req);
	req->num_timeout++;
	tcp_update_rto_stats(sk);
	if (!tp->retrans_stamp)
		tp->retrans_stamp = tcp_time_stamp(tp);
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
			  req->timeout << req->num_timeout, TCP_RTO_MAX);
}

static bool tcp_rtx_probe0_timed_out(const struct sock *sk,
				     const struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const int timeout = TCP_RTO_MAX * 2;
	u32 rcv_delta, rtx_delta;

	rcv_delta = inet_csk(sk)->icsk_timeout - tp->rcv_tstamp;
	if (rcv_delta <= timeout)
		return false;

	rtx_delta = (u32)msecs_to_jiffies(tcp_time_stamp(tp) -
			(tp->retrans_stamp ?: tcp_skb_timestamp(skb)));

	return rtx_delta > timeout;
}

void klpp_tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock *req;
	struct sk_buff *skb;

	req = rcu_dereference_protected(tp->fastopen_rsk,
					lockdep_sock_is_held(sk));
	if (req) {
		WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV &&
			     sk->sk_state != TCP_FIN_WAIT1);
		tcp_fastopen_synack_timer(sk, req);
		/* Before we receive ACK to our SYN-ACK don't retransmit
		 * anything else (e.g., data or FIN segments).
		 */
		return;
	}

	if (!tp->packets_out)
		return;

	skb = tcp_rtx_queue_head(sk);
	if (WARN_ON_ONCE(!skb))
		return;

	tp->tlp_high_seq = 0;

	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
		struct inet_sock *inet = inet_sk(sk);
		if (sk->sk_family == AF_INET) {
			net_dbg_ratelimited("Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
					    &inet->inet_daddr,
					    ntohs(inet->inet_dport),
					    inet->inet_num,
					    tp->snd_una, tp->snd_nxt);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (sk->sk_family == AF_INET6) {
			net_dbg_ratelimited("Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
					    &sk->sk_v6_daddr,
					    ntohs(inet->inet_dport),
					    inet->inet_num,
					    tp->snd_una, tp->snd_nxt);
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		if (tcp_rtx_probe0_timed_out(sk, skb)) {
			tcp_write_err(sk);
			goto out;
		}
		tcp_enter_loss(sk);
		tcp_retransmit_skb(sk, skb, 1);
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

	__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEOUTS);
	if (klpp_tcp_write_timeout(sk))
		goto out;

	if (icsk->icsk_retransmits == 0) {
		int mib_idx = 0;

		if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else if ((icsk->icsk_ca_state == TCP_CA_Disorder) ||
			   tp->sacked_out) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		}
		if (mib_idx)
			__NET_INC_STATS(sock_net(sk), mib_idx);
	}

	tcp_enter_loss(sk);

	tcp_update_rto_stats(sk);
	if (tcp_retransmit_skb(sk, tcp_rtx_queue_head(sk), 1) > 0) {
		/* Retransmission failed because of local congestion,
		 * Let senders fight for local resources conservatively.
		 */
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  TCP_RESOURCE_PROBE_INTERVAL,
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || READ_ONCE(net->ipv4.sysctl_tcp_thin_linear_timeouts)) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = clamp(__tcp_set_rto(tp),
				       tcp_rto_min(sk),
				       TCP_RTO_MAX);
	} else if (sk->sk_state != TCP_SYN_SENT ||
		   tp->total_rto >
		   READ_ONCE(net->ipv4.sysctl_tcp_syn_linear_timeouts)) {
		/* Use normal (exponential) backoff unless linear timeouts are
		 * activated.
		 */
		icsk->icsk_backoff++;
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  tcp_clamp_rto_to_user_timeout(sk), TCP_RTO_MAX);
	if (retransmits_timed_out(sk, READ_ONCE(net->ipv4.sysctl_tcp_retries1) + 1, 0))
		__sk_dst_reset(sk);

out:;
}

#include <linux/livepatch.h>

#include "livepatch_bsc1226324.h"

extern typeof(tcp_enter_loss) tcp_enter_loss
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcp_enter_loss);
extern typeof(tcp_fastopen_active_detect_blackhole)
	 tcp_fastopen_active_detect_blackhole
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcp_fastopen_active_detect_blackhole);
extern typeof(tcp_out_of_resources) tcp_out_of_resources
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcp_out_of_resources);
extern typeof(tcp_retransmit_skb) tcp_retransmit_skb
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcp_retransmit_skb);
extern typeof(tcp_write_err) tcp_write_err
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcp_write_err);
