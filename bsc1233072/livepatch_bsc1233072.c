/*
 * livepatch_bsc1233072
 *
 * Fix for CVE-2024-50154, bsc#1233072
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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
#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>

/* klp-ccp: from net/ipv4/inet_connection_sock.c */
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>

#include <net/route.h>
#include <net/tcp_states.h>

/* klp-ccp: from include/net/tcp.h */
#define TCP_RTO_MAX	((unsigned)(120*HZ))

#define TCP_TIMEOUT_INIT ((unsigned)(1*HZ))	/* RFC6298 2.1 initial RTO value	*/

/* klp-ccp: from net/ipv4/inet_connection_sock.c */
static inline void syn_ack_recalc(struct request_sock *req, const int thresh,
				  const int max_retries,
				  const u8 rskq_defer_accept,
				  int *expire, int *resend)
{
	if (!rskq_defer_accept) {
		*expire = req->num_timeout >= thresh;
		*resend = 1;
		return;
	}
	*expire = req->num_timeout >= thresh &&
		  (!inet_rsk(req)->acked || req->num_timeout >= max_retries);
	/*
	 * Do not resend while waiting for data after ACK,
	 * start to resend on end of deferring period to give
	 * last chance for data or ACK to create established socket.
	 */
	*resend = !inet_rsk(req)->acked ||
		  req->num_timeout >= rskq_defer_accept - 1;
}

int inet_rtx_syn_ack(const struct sock *parent, struct request_sock *req);

extern typeof(inet_rtx_syn_ack) inet_rtx_syn_ack;

static bool reqsk_queue_unlink(struct request_sock_queue *queue,
			       struct request_sock *req)
{
	struct inet_hashinfo *hashinfo = req_to_sk(req)->sk_prot->h.hashinfo;
	bool found = false;

	if (sk_hashed(req_to_sk(req))) {
		spinlock_t *lock = inet_ehash_lockp(hashinfo, req->rsk_hash);

		spin_lock(lock);
		found = __sk_nulls_del_node_init_rcu(req_to_sk(req));
		spin_unlock(lock);
	}

	return found;
}

static void __inet_csk_reqsk_queue_drop(struct sock *sk, struct request_sock *req, bool from_timer)
{
	if (!from_timer && timer_delete_sync(&req->rsk_timer))
		reqsk_put(req);

	if (reqsk_queue_unlink(&inet_csk(sk)->icsk_accept_queue, req)) {
		reqsk_queue_removed(&inet_csk(sk)->icsk_accept_queue, req);
		reqsk_put(req);
	}
}

void klpp_inet_csk_reqsk_queue_drop(struct sock *sk, struct request_sock *req)
{
	__inet_csk_reqsk_queue_drop(sk, req, false);
}

typeof(klpp_inet_csk_reqsk_queue_drop) klpp_inet_csk_reqsk_queue_drop;

void klpp_reqsk_timer_handler(unsigned long data)
{
	struct request_sock *req = (struct request_sock *)data;
	struct sock *sk_listener = req->rsk_listener;
	struct net *net = sock_net(sk_listener);
	struct inet_connection_sock *icsk = inet_csk(sk_listener);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	int qlen, expire = 0, resend = 0;
	int max_retries, thresh;
	u8 defer_accept;

	if (sk_state_load(sk_listener) != TCP_LISTEN)
		goto drop;

	max_retries = icsk->icsk_syn_retries ? : net->ipv4.sysctl_tcp_synack_retries;
	thresh = max_retries;
	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 1 second, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	qlen = reqsk_queue_len(queue);
	if ((qlen << 1) > max(8U, sk_listener->sk_max_ack_backlog)) {
		int young = reqsk_queue_len_young(queue) << 1;

		while (thresh > 2) {
			if (qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}
	defer_accept = READ_ONCE(queue->rskq_defer_accept);
	if (defer_accept)
		max_retries = defer_accept;
	syn_ack_recalc(req, thresh, max_retries, defer_accept,
		       &expire, &resend);
	req->rsk_ops->syn_ack_timeout(req);
	if (!expire &&
	    (!resend ||
	     !inet_rtx_syn_ack(sk_listener, req) ||
	     inet_rsk(req)->acked)) {
		unsigned long timeo;

		if (req->num_timeout++ == 0)
			atomic_dec(&queue->young);
		timeo = min(TCP_TIMEOUT_INIT << req->num_timeout, TCP_RTO_MAX);
		mod_timer(&req->rsk_timer, jiffies + timeo);
		return;
	}
drop:
	__inet_csk_reqsk_queue_drop(sk_listener, req, true);
	reqsk_put(req);
}


#include "livepatch_bsc1233072.h"

