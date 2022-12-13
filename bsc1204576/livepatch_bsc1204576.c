/*
 * livepatch_bsc1204576
 *
 * Fix for CVE-2022-3586, bsc#1204576
 *
 *  Upstream commits:
 *  9efd23297cca ("sch_sfb: Don't assume the skb is still around after
 *                 enqueueing to child")
 *  2f09707d0c97 ("sch_sfb: Also store skb len before calling child enqueue")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  3fbdbcf1c5a5b234b6a5fc8e6af489fa941ea780
 *  baac8bc80b8419b8c06a4d69e31ce23522123a61
 *
 *  SLE15-SP2 and -SP3 commits:
 *  45ee5c5950e56480f045dc8db208468960d9faf1
 *  bbd433f2c103dc53306c9a74ee2ee6d664404478
 *
 *  SLE15-SP4 commits:
 *  940aac0ed08861498660e2748741973893900590
 *  678894398a036c671fffac1c838788ab20da1d50
 *
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_NET_SCH_SFB)
#error "Live patch supports only CONFIG_NET_SCH_SFB=m"
#endif

/* klp-ccp: from net/sched/sch_sfb.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <net/ip.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

#define SFB_BUCKET_SHIFT 4
#define SFB_NUMBUCKETS	(1 << SFB_BUCKET_SHIFT) /* N bins per Level */
#define SFB_BUCKET_MASK (SFB_NUMBUCKETS - 1)
#define SFB_LEVELS	(32 / SFB_BUCKET_SHIFT) /* L */

struct sfb_bucket {
	u16		qlen; /* length of virtual queue */
	u16		p_mark; /* marking probability */
};

struct sfb_bins {
	u32		  perturbation; /* jhash perturbation */
	struct sfb_bucket bins[SFB_LEVELS][SFB_NUMBUCKETS];
};

struct sfb_sched_data {
	struct Qdisc	*qdisc;
	struct tcf_proto __rcu *filter_list;
	struct tcf_block *block;
	unsigned long	rehash_interval;
	unsigned long	warmup_time;	/* double buffering warmup time in jiffies */
	u32		max;
	u32		bin_size;	/* maximum queue length per bin */
	u32		increment;	/* d1 */
	u32		decrement;	/* d2 */
	u32		limit;		/* HARD maximal queue length */
	u32		penalty_rate;
	u32		penalty_burst;
	u32		tokens_avail;
	unsigned long	rehash_time;
	unsigned long	token_time;

	u8		slot;		/* current active bins (0 or 1) */
	bool		double_buffering;
	struct sfb_bins bins[2];

	struct {
		u32	earlydrop;
		u32	penaltydrop;
		u32	bucketdrop;
		u32	queuedrop;
		u32	childdrop;	/* drops in child qdisc */
		u32	marked;		/* ECN mark */
	} stats;
};

struct sfb_skb_cb {
	u32 hashes[2];
};

static inline struct sfb_skb_cb *sfb_skb_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct sfb_skb_cb));
	return (struct sfb_skb_cb *)qdisc_skb_cb(skb)->data;
}

static u32 prob_plus(u32 p1, u32 p2)
{
	u32 res = p1 + p2;

	return min_t(u32, res, SFB_MAX_PROB);
}

static u32 prob_minus(u32 p1, u32 p2)
{
	return p1 > p2 ? p1 - p2 : 0;
}

static void increment_one_qlen(u32 sfbhash, u32 slot, struct sfb_sched_data *q)
{
	int i;
	struct sfb_bucket *b = &q->bins[slot].bins[0][0];

	for (i = 0; i < SFB_LEVELS; i++) {
		u32 hash = sfbhash & SFB_BUCKET_MASK;

		sfbhash >>= SFB_BUCKET_SHIFT;
		if (b[hash].qlen < 0xFFFF)
			b[hash].qlen++;
		b += SFB_NUMBUCKETS; /* next level */
	}
}

/*
 * Fix CVE-2022-3586
 *  -1 line, +1 line
 */
static void klpp_increment_qlen(const struct sfb_skb_cb *cb, struct sfb_sched_data *q)
{
	u32 sfbhash;

	/*
	 * Fix CVE-2022-3586
	 *  -1 line, +1 line
	 */
	sfbhash = cb->hashes[0];
	if (sfbhash)
		increment_one_qlen(sfbhash, 0, q);

	/*
	 * Fix CVE-2022-3586
	 *  -1 line, +1 line
	 */
	sfbhash = cb->hashes[1];;
	if (sfbhash)
		increment_one_qlen(sfbhash, 1, q);
}

static void decrement_prob(struct sfb_bucket *b, struct sfb_sched_data *q)
{
	b->p_mark = prob_minus(b->p_mark, q->decrement);
}

static void increment_prob(struct sfb_bucket *b, struct sfb_sched_data *q)
{
	b->p_mark = prob_plus(b->p_mark, q->increment);
}

static void sfb_init_perturbation(u32 slot, struct sfb_sched_data *q)
{
	q->bins[slot].perturbation = prandom_u32();
}

static void sfb_swap_slot(struct sfb_sched_data *q)
{
	sfb_init_perturbation(q->slot, q);
	q->slot ^= 1;
	q->double_buffering = false;
}

static bool sfb_rate_limit(struct sk_buff *skb, struct sfb_sched_data *q)
{
	if (q->penalty_rate == 0 || q->penalty_burst == 0)
		return true;

	if (q->tokens_avail < 1) {
		unsigned long age = min(10UL * HZ, jiffies - q->token_time);

		q->tokens_avail = (age * q->penalty_rate) / HZ;
		if (q->tokens_avail > q->penalty_burst)
			q->tokens_avail = q->penalty_burst;
		q->token_time = jiffies;
		if (q->tokens_avail < 1)
			return true;
	}

	q->tokens_avail--;
	return false;
}

static bool sfb_classify(struct sk_buff *skb, struct tcf_proto *fl,
			 int *qerr, u32 *salt)
{
	struct tcf_result res;
	int result;

	result = tcf_classify(skb, fl, &res, false);
	if (result >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			/* fall through */
		case TC_ACT_SHOT:
			return false;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		*salt = TC_H_MIN(res.classid);
		return true;
	}
	return false;
}

int klpp_sfb_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{

	struct sfb_sched_data *q = qdisc_priv(sch);
	/*
	 * Fix CVE-2022-3586
	 *  +1 line
	 */
	unsigned int len = qdisc_pkt_len(skb);
	struct Qdisc *child = q->qdisc;
	struct tcf_proto *fl;
	/*
	 * Fix CVE-2022-3586
	 *  +1 line
	 */
	struct sfb_skb_cb cb;
	int i;
	u32 p_min = ~0;
	u32 minqlen = ~0;
	u32 r, sfbhash;
	u32 slot = q->slot;
	int ret = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;

	if (unlikely(sch->q.qlen >= q->limit)) {
		qdisc_qstats_overlimit(sch);
		q->stats.queuedrop++;
		goto drop;
	}

	if (q->rehash_interval > 0) {
		unsigned long limit = q->rehash_time + q->rehash_interval;

		if (unlikely(time_after(jiffies, limit))) {
			sfb_swap_slot(q);
			q->rehash_time = jiffies;
		} else if (unlikely(!q->double_buffering && q->warmup_time > 0 &&
				    time_after(jiffies, limit - q->warmup_time))) {
			q->double_buffering = true;
		}
	}

	fl = rcu_dereference_bh(q->filter_list);
	if (fl) {
		u32 salt;

		/* If using external classifiers, get result and record it. */
		if (!sfb_classify(skb, fl, &ret, &salt))
			goto other_drop;
		sfbhash = jhash_1word(salt, q->bins[slot].perturbation);
	} else {
		sfbhash = skb_get_hash_perturb(skb, q->bins[slot].perturbation);
	}


	if (!sfbhash)
		sfbhash = 1;
	sfb_skb_cb(skb)->hashes[slot] = sfbhash;

	for (i = 0; i < SFB_LEVELS; i++) {
		u32 hash = sfbhash & SFB_BUCKET_MASK;
		struct sfb_bucket *b = &q->bins[slot].bins[i][hash];

		sfbhash >>= SFB_BUCKET_SHIFT;
		if (b->qlen == 0)
			decrement_prob(b, q);
		else if (b->qlen >= q->bin_size)
			increment_prob(b, q);
		if (minqlen > b->qlen)
			minqlen = b->qlen;
		if (p_min > b->p_mark)
			p_min = b->p_mark;
	}

	slot ^= 1;
	sfb_skb_cb(skb)->hashes[slot] = 0;

	if (unlikely(minqlen >= q->max)) {
		qdisc_qstats_overlimit(sch);
		q->stats.bucketdrop++;
		goto drop;
	}

	if (unlikely(p_min >= SFB_MAX_PROB)) {
		/* Inelastic flow */
		if (q->double_buffering) {
			sfbhash = skb_get_hash_perturb(skb,
			    q->bins[slot].perturbation);
			if (!sfbhash)
				sfbhash = 1;
			sfb_skb_cb(skb)->hashes[slot] = sfbhash;

			for (i = 0; i < SFB_LEVELS; i++) {
				u32 hash = sfbhash & SFB_BUCKET_MASK;
				struct sfb_bucket *b = &q->bins[slot].bins[i][hash];

				sfbhash >>= SFB_BUCKET_SHIFT;
				if (b->qlen == 0)
					decrement_prob(b, q);
				else if (b->qlen >= q->bin_size)
					increment_prob(b, q);
			}
		}
		if (sfb_rate_limit(skb, q)) {
			qdisc_qstats_overlimit(sch);
			q->stats.penaltydrop++;
			goto drop;
		}
		goto enqueue;
	}

	r = prandom_u32() & SFB_MAX_PROB;

	if (unlikely(r < p_min)) {
		if (unlikely(p_min > SFB_MAX_PROB / 2)) {
			/* If we're marking that many packets, then either
			 * this flow is unresponsive, or we're badly congested.
			 * In either case, we want to start dropping packets.
			 */
			if (r < (p_min - SFB_MAX_PROB / 2) * 2) {
				q->stats.earlydrop++;
				goto drop;
			}
		}
		if (INET_ECN_set_ce(skb)) {
			q->stats.marked++;
		} else {
			q->stats.earlydrop++;
			goto drop;
		}
	}

enqueue:
	/*
	 * Fix CVE-2022-3586
	 *  +1 line
	 */
	memcpy(&cb, sfb_skb_cb(skb), sizeof(cb));
	ret = qdisc_enqueue(skb, child, to_free);
	if (likely(ret == NET_XMIT_SUCCESS)) {
		/*
		 * Fix CVE-2022-3586
		 *  -1 line, +1 line
		 */
		sch->qstats.backlog += len;
		sch->q.qlen++;
		/*
		 * Fix CVE-2022-3586
		 *  -1 line, +1 line
		 */
		klpp_increment_qlen(&cb, q);
	} else if (net_xmit_drop_count(ret)) {
		q->stats.childdrop++;
		qdisc_qstats_drop(sch);
	}
	return ret;

drop:
	qdisc_drop(skb, sch, to_free);
	return NET_XMIT_CN;
other_drop:
	if (ret & __NET_XMIT_BYPASS)
		qdisc_qstats_drop(sch);
	kfree_skb(skb);
	return ret;
}



#include "livepatch_bsc1204576.h"
