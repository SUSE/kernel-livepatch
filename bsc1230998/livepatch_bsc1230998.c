/*
 * livepatch_bsc1230998
 *
 * Fix for CVE-2024-45016, bsc#1230998
 *
 *  Upstream commit:
 *  177b8007463c ("net: netem: fix backlog accounting for corrupted GSO frames")
 *  3e14c383de34 ("net: netem: fix use after free and double free with packet corruption")
 *  a7fa12d15855 ("net: netem: fix error path for corrupted GSO frames")
 *  e0ad032e1447 ("net: netem: correct the parent's backlog when corrupted packet was dropped")
 *  c07ff8592d57 ("netem: fix return value if duplicate enqueue fails")
 *
 *  SLE12-SP5 commit:
 *  1f86a606378086ed1cd98e6f3a85dfb233c4ed64
 *  9dbd87c4a8a229c61cff294bb9bba0adb45ee22d
 *  1e84704b3efc7fc77e40d96cdadb6376af256bf8
 *  3de8102e312e5323b41cb3ae0821f94e3594ed19
 *  8535e0cbaa05525f3e7557226026af02d08be15c
 *
 *  SLE15-SP2 and -SP3 commit:
 *  c2e23cabf5aa420ff9be68052c21251726c1607e
 *
 *  SLE15-SP4 and -SP5 commit:
 *  2e9108ac7a7fe6785e690c95c3485d47c43d3eea
 *
 *  SLE15-SP6 commit:
 *  8c9c269c62d7153572b79e3ac338df4c4b2f4a52
 *
 *  SLE MICRO-6-0 commit:
 *  8c9c269c62d7153572b79e3ac338df4c4b2f4a52
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

/* klp-ccp: from net/sched/sch_netem.c */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/rtnetlink.h>
#include <linux/reciprocal_div.h>
#include <linux/rbtree.h>

#include <net/gso.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

struct disttable {
	u32  size;
	s16 table[];
};

struct netem_sched_data {
	/* internal t(ime)fifo qdisc uses t_root and sch->limit */
	struct rb_root t_root;

	/* a linear queue; reduces rbtree rebalancing when jitter is low */
	struct sk_buff	*t_head;
	struct sk_buff	*t_tail;

	/* optional qdisc for classful handling (NULL at netem init) */
	struct Qdisc	*qdisc;

	struct qdisc_watchdog watchdog;

	s64 latency;
	s64 jitter;

	u32 loss;
	u32 ecn;
	u32 limit;
	u32 counter;
	u32 gap;
	u32 duplicate;
	u32 reorder;
	u32 corrupt;
	u64 rate;
	s32 packet_overhead;
	u32 cell_size;
	struct reciprocal_value cell_size_reciprocal;
	s32 cell_overhead;

	struct crndstate {
		u32 last;
		u32 rho;
	} delay_cor, loss_cor, dup_cor, reorder_cor, corrupt_cor;

	struct disttable *delay_dist;

	enum  {
		CLG_RANDOM,
		CLG_4_STATES,
		CLG_GILB_ELL,
	} loss_model;

	enum {
		TX_IN_GAP_PERIOD = 1,
		TX_IN_BURST_PERIOD,
		LOST_IN_GAP_PERIOD,
		LOST_IN_BURST_PERIOD,
	} _4_state_model;

	enum {
		GOOD_STATE = 1,
		BAD_STATE,
	} GE_state_model;

	/* Correlated Loss Generation models */
	struct clgstate {
		/* state of the Markov chain */
		u8 state;

		/* 4-states and Gilbert-Elliot models */
		u32 a1;	/* p13 for 4-states or p for GE */
		u32 a2;	/* p31 for 4-states or r for GE */
		u32 a3;	/* p32 for 4-states or h for GE */
		u32 a4;	/* p14 for 4-states or 1-k for GE */
		u32 a5; /* p23 used only in 4-states */
	} clg;

	struct tc_netem_slot slot_config;
	struct slotstate {
		u64 slot_next;
		s32 packets_left;
		s32 bytes_left;
	} slot;

	struct disttable *slot_dist;
};

struct netem_skb_cb {
	u64	        time_to_send;
};

static inline struct netem_skb_cb *netem_skb_cb(struct sk_buff *skb)
{
	/* we assume we can use skb next/prev/tstamp as storage for rb_node */
	qdisc_cb_private_validate(skb, sizeof(struct netem_skb_cb));
	return (struct netem_skb_cb *)qdisc_skb_cb(skb)->data;
}

static u32 get_crandom(struct crndstate *state)
{
	u64 value, rho;
	unsigned long answer;

	if (!state || state->rho == 0)	/* no correlation */
		return get_random_u32();

	value = get_random_u32();
	rho = (u64)state->rho + 1;
	answer = (value * ((1ull<<32) - rho) + state->last * rho) >> 32;
	state->last = answer;
	return answer;
}

static bool loss_4state(struct netem_sched_data *q)
{
	struct clgstate *clg = &q->clg;
	u32 rnd = get_random_u32();

	/*
	 * Makes a comparison between rnd and the transition
	 * probabilities outgoing from the current state, then decides the
	 * next state and if the next packet has to be transmitted or lost.
	 * The four states correspond to:
	 *   TX_IN_GAP_PERIOD => successfully transmitted packets within a gap period
	 *   LOST_IN_GAP_PERIOD => isolated losses within a gap period
	 *   LOST_IN_BURST_PERIOD => lost packets within a burst period
	 *   TX_IN_BURST_PERIOD => successfully transmitted packets within a burst period
	 */
	switch (clg->state) {
	case TX_IN_GAP_PERIOD:
		if (rnd < clg->a4) {
			clg->state = LOST_IN_GAP_PERIOD;
			return true;
		} else if (clg->a4 < rnd && rnd < clg->a1 + clg->a4) {
			clg->state = LOST_IN_BURST_PERIOD;
			return true;
		} else if (clg->a1 + clg->a4 < rnd) {
			clg->state = TX_IN_GAP_PERIOD;
		}

		break;
	case TX_IN_BURST_PERIOD:
		if (rnd < clg->a5) {
			clg->state = LOST_IN_BURST_PERIOD;
			return true;
		} else {
			clg->state = TX_IN_BURST_PERIOD;
		}

		break;
	case LOST_IN_BURST_PERIOD:
		if (rnd < clg->a3)
			clg->state = TX_IN_BURST_PERIOD;
		else if (clg->a3 < rnd && rnd < clg->a2 + clg->a3) {
			clg->state = TX_IN_GAP_PERIOD;
		} else if (clg->a2 + clg->a3 < rnd) {
			clg->state = LOST_IN_BURST_PERIOD;
			return true;
		}
		break;
	case LOST_IN_GAP_PERIOD:
		clg->state = TX_IN_GAP_PERIOD;
		break;
	}

	return false;
}

static bool loss_gilb_ell(struct netem_sched_data *q)
{
	struct clgstate *clg = &q->clg;

	switch (clg->state) {
	case GOOD_STATE:
		if (get_random_u32() < clg->a1)
			clg->state = BAD_STATE;
		if (get_random_u32() < clg->a4)
			return true;
		break;
	case BAD_STATE:
		if (get_random_u32() < clg->a2)
			clg->state = GOOD_STATE;
		if (get_random_u32() > clg->a3)
			return true;
	}

	return false;
}

static bool loss_event(struct netem_sched_data *q)
{
	switch (q->loss_model) {
	case CLG_RANDOM:
		/* Random packet drop 0 => none, ~0 => all */
		return q->loss && q->loss >= get_crandom(&q->loss_cor);

	case CLG_4_STATES:
		/* 4state loss model algorithm (used also for GI model)
		* Extracts a value from the markov 4 state loss generator,
		* if it is 1 drops a packet and if needed writes the event in
		* the kernel logs
		*/
		return loss_4state(q);

	case CLG_GILB_ELL:
		/* Gilbert-Elliot loss model algorithm
		* Extracts a value from the Gilbert-Elliot loss generator,
		* if it is 1 drops a packet and if needed writes the event in
		* the kernel logs
		*/
		return loss_gilb_ell(q);
	}

	return false;	/* not reached */
}

static s64 tabledist(s64 mu, s32 sigma,
		     struct crndstate *state,
		     const struct disttable *dist)
{
	s64 x;
	long t;
	u32 rnd;

	if (sigma == 0)
		return mu;

	rnd = get_crandom(state);

	/* default uniform distribution */
	if (dist == NULL)
		return ((rnd % (2 * (u32)sigma)) + mu) - sigma;

	t = dist->table[rnd % dist->size];
	x = (sigma % NETEM_DIST_SCALE) * t;
	if (x >= 0)
		x += NETEM_DIST_SCALE/2;
	else
		x -= NETEM_DIST_SCALE/2;

	return  x / NETEM_DIST_SCALE + (sigma / NETEM_DIST_SCALE) * t + mu;
}

static u64 packet_time_ns(u64 len, const struct netem_sched_data *q)
{
	len += q->packet_overhead;

	if (q->cell_size) {
		u32 cells = reciprocal_divide(len, q->cell_size_reciprocal);

		if (len > cells * q->cell_size)	/* extra cell needed for remainder */
			cells++;
		len = cells * (q->cell_size + q->cell_overhead);
	}

	return div64_u64(len * NSEC_PER_SEC, q->rate);
}

static void tfifo_enqueue(struct sk_buff *nskb, struct Qdisc *sch)
{
	struct netem_sched_data *q = qdisc_priv(sch);
	u64 tnext = netem_skb_cb(nskb)->time_to_send;

	if (!q->t_tail || tnext >= netem_skb_cb(q->t_tail)->time_to_send) {
		if (q->t_tail)
			q->t_tail->next = nskb;
		else
			q->t_head = nskb;
		q->t_tail = nskb;
	} else {
		struct rb_node **p = &q->t_root.rb_node, *parent = NULL;

		while (*p) {
			struct sk_buff *skb;

			parent = *p;
			skb = rb_to_skb(parent);
			if (tnext >= netem_skb_cb(skb)->time_to_send)
				p = &parent->rb_right;
			else
				p = &parent->rb_left;
		}
		rb_link_node(&nskb->rbnode, parent, p);
		rb_insert_color(&nskb->rbnode, &q->t_root);
	}
	sch->q.qlen++;
}

static struct sk_buff *netem_segment(struct sk_buff *skb, struct Qdisc *sch,
				     struct sk_buff **to_free)
{
	struct sk_buff *segs;
	netdev_features_t features = netif_skb_features(skb);

	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

	if (IS_ERR_OR_NULL(segs)) {
		qdisc_drop(skb, sch, to_free);
		return NULL;
	}
	consume_skb(skb);
	return segs;
}

int klpp_netem_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	struct netem_sched_data *q = qdisc_priv(sch);
	/* We don't fill cb now as skb_unshare() may invalidate it */
	struct netem_skb_cb *cb;
	struct sk_buff *skb2 = NULL;
	struct sk_buff *segs = NULL;
	unsigned int prev_len = qdisc_pkt_len(skb);
	int count = 1;

	/* Do not fool qdisc_drop_all() */
	skb->prev = NULL;

	/* Random duplication */
	if (q->duplicate && q->duplicate >= get_crandom(&q->dup_cor))
		++count;

	/* Drop packet? */
	if (loss_event(q)) {
		if (q->ecn && INET_ECN_set_ce(skb))
			qdisc_qstats_drop(sch); /* mark packet */
		else
			--count;
	}
	if (count == 0) {
		qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	}

	/* If a delay is expected, orphan the skb. (orphaning usually takes
	 * place at TX completion time, so _before_ the link transit delay)
	 */
	if (q->latency || q->jitter || q->rate)
		skb_orphan_partial(skb);

	/*
	 * If we need to duplicate packet, then clone it before
	 * original is modified.
	 */
	if (count > 1)
		skb2 = skb_clone(skb, GFP_ATOMIC);
	
	/*
	 * Randomized packet corruption.
	 * Make copy if needed since we are modifying
	 * If packet is going to be hardware checksummed, then
	 * do it now in software before we mangle it.
	 */
	if (q->corrupt && q->corrupt >= get_crandom(&q->corrupt_cor)) {
		if (skb_is_gso(skb)) {
			skb = netem_segment(skb, sch, to_free);
			if (!skb)
				goto finish_segs;

			segs = skb->next;
			skb_mark_not_on_list(skb);
			qdisc_skb_cb(skb)->pkt_len = skb->len;
		}

		skb = skb_unshare(skb, GFP_ATOMIC);
		if (unlikely(!skb)) {
			qdisc_qstats_drop(sch);
			goto finish_segs;
		}
		if (skb->ip_summed == CHECKSUM_PARTIAL &&
		    skb_checksum_help(skb)) {
			qdisc_drop(skb, sch, to_free);
			skb = NULL;
			goto finish_segs;
		}

		skb->data[get_random_u32_below(skb_headlen(skb))] ^=
			1<<get_random_u32_below(8);
	}

	if (unlikely(sch->q.qlen >= sch->limit)) {
		/* re-link segs, so that qdisc_drop_all() frees them all */
		skb->next = segs;
		qdisc_drop_all(skb, sch, to_free);
		if (skb2)
			__qdisc_drop(skb2, to_free);
		return NET_XMIT_DROP;
	}

	/*
	 * If doing duplication then re-insert at top of the
	 * qdisc tree, since parent queuer expects that only one
	 * skb will be queued.
	 */
	if (skb2) {
		struct Qdisc *rootq = qdisc_root_bh(sch);
		u32 dupsave = q->duplicate; /* prevent duplicating a dup... */

		q->duplicate = 0;
		rootq->enqueue(skb2, rootq, to_free);
		q->duplicate = dupsave;
		skb2 = NULL;
	}

	qdisc_qstats_backlog_inc(sch, skb);

	cb = netem_skb_cb(skb);
	if (q->gap == 0 ||		/* not doing reordering */
	    q->counter < q->gap - 1 ||	/* inside last reordering gap */
	    q->reorder < get_crandom(&q->reorder_cor)) {
		u64 now;
		s64 delay;

		delay = tabledist(q->latency, q->jitter,
				  &q->delay_cor, q->delay_dist);

		now = ktime_get_ns();

		if (q->rate) {
			struct netem_skb_cb *last = NULL;

			if (sch->q.tail)
				last = netem_skb_cb(sch->q.tail);
			if (q->t_root.rb_node) {
				struct sk_buff *t_skb;
				struct netem_skb_cb *t_last;

				t_skb = skb_rb_last(&q->t_root);
				t_last = netem_skb_cb(t_skb);
				if (!last ||
				    t_last->time_to_send > last->time_to_send)
					last = t_last;
			}
			if (q->t_tail) {
				struct netem_skb_cb *t_last =
					netem_skb_cb(q->t_tail);

				if (!last ||
				    t_last->time_to_send > last->time_to_send)
					last = t_last;
			}

			if (last) {
				/*
				 * Last packet in queue is reference point (now),
				 * calculate this time bonus and subtract
				 * from delay.
				 */
				delay -= last->time_to_send - now;
				delay = max_t(s64, 0, delay);
				now = last->time_to_send;
			}

			delay += packet_time_ns(qdisc_pkt_len(skb), q);
		}

		cb->time_to_send = now + delay;
		++q->counter;
		tfifo_enqueue(skb, sch);
	} else {
		/*
		 * Do re-ordering by putting one out of N packets at the front
		 * of the queue.
		 */
		cb->time_to_send = ktime_get_ns();
		q->counter = 0;

		__qdisc_enqueue_head(skb, &sch->q);
		sch->qstats.requeues++;
	}

finish_segs:
	if (skb2)
		__qdisc_drop(skb2, to_free);

	if (segs) {
		unsigned int len, last_len;
		int rc, nb;

		len = skb ? skb->len : 0;
		nb = skb ? 1 : 0;

		while (segs) {
			skb2 = segs->next;
			skb_mark_not_on_list(segs);
			qdisc_skb_cb(segs)->pkt_len = segs->len;
			last_len = segs->len;
			rc = qdisc_enqueue(segs, sch, to_free);
			if (rc != NET_XMIT_SUCCESS) {
				if (net_xmit_drop_count(rc))
					qdisc_qstats_drop(sch);
			} else {
				nb++;
				len += last_len;
			}
			segs = skb2;
		}
		/* Parent qdiscs accounted for 1 skb of size @prev_len */
		qdisc_tree_reduce_backlog(sch, -(nb - 1), -(len - prev_len));
	} else if (!skb) {
		return NET_XMIT_DROP;
	}
	return NET_XMIT_SUCCESS;
}

#include "livepatch_bsc1230998.h"
