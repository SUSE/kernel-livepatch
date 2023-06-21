/*
 * livepatch_bsc1210779
 *
 * Fix for CVE-2023-1390, bsc#1210779
 *
 *  Upstream commit:
 *  b77413446408 ("tipc: fix NULL deref in tipc_link_xmit()")
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
 *  91c876a1863bef595f78e5059a4fe218d44c2700
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b2c153384ebb7ee37a59ece9de1aca6b089c6fe0
 *
 *  SLE15-SP4 commit:
 *  Not affected
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

#if !IS_MODULE(CONFIG_TIPC)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/tipc/core.h */
#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/atomic.h>
#include <asm/hardirq.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/netns/generic.h>
#include <linux/rhashtable.h>

#define NODE_HTABLE_SIZE       512
#define MAX_BEARERS	         3

static unsigned int (*klpe_tipc_net_id) __read_mostly;

struct tipc_net {
	u32 own_addr;
	int net_id;
	int random;

	/* Node table and node list */
	spinlock_t node_list_lock;
	struct hlist_head node_htable[NODE_HTABLE_SIZE];
	struct list_head node_list;
	u32 num_nodes;
	u32 num_links;

	/* Neighbor monitoring list */
	struct tipc_monitor *monitors[MAX_BEARERS];
	int mon_threshold;

	/* Bearer list */
	struct tipc_bearer __rcu *bearer_list[MAX_BEARERS + 1];

	/* Broadcast link */
	spinlock_t bclock;
	struct tipc_bc_base *bcbase;
	struct tipc_link *bcl;

	/* Socket hash table */
	struct rhashtable sk_rht;

	/* Name table */
	spinlock_t nametbl_lock;
	struct name_table *nametbl;

	/* Name dist queue */
	struct list_head dist_queue;

	/* Topology subscription server */
	struct tipc_server *topsrv;
	atomic_t subscription_count;
};

/* klp-ccp: from net/tipc/server.h */
#include <linux/idr.h>
#include <linux/tipc.h>
#include <net/net_namespace.h>

/* klp-ccp: from net/tipc/msg.h */
#include <linux/tipc.h>

#define TIPC_SYSTEM_IMPORTANCE	4

#define  MSG_BUNDLER          6

#define  MSG_FRAGMENTER       12

#define  SOCK_WAKEUP          14       /* pseudo user */

#define INT_H_SIZE                40	/* Internal messages */

struct tipc_skb_cb {
	u32 bytes_read;
	struct sk_buff *tail;
	bool validated;
	u16 chain_imp;
	u16 ackers;
};

#define TIPC_SKB_CB(__skb) ((struct tipc_skb_cb *)&((__skb)->cb[0]))

struct tipc_msg {
	__be32 hdr[15];
};

static inline struct tipc_msg *buf_msg(struct sk_buff *skb)
{
	return (struct tipc_msg *)skb->data;
}

static inline u32 msg_word(struct tipc_msg *m, u32 pos)
{
	return ntohl(m->hdr[pos]);
}

static inline u32 msg_bits(struct tipc_msg *m, u32 w, u32 pos, u32 mask)
{
	return (msg_word(m, w) >> pos) & mask;
}

static inline void msg_set_bits(struct tipc_msg *m, u32 w,
				u32 pos, u32 mask, u32 val)
{
	val = (val & mask) << pos;
	mask = mask << pos;
	m->hdr[w] &= ~htonl(mask);
	m->hdr[w] |= htonl(val);
}

static inline u32 msg_user(struct tipc_msg *m)
{
	return msg_bits(m, 0, 25, 0xf);
}

static inline u32 msg_hdr_sz(struct tipc_msg *m)
{
	return msg_bits(m, 0, 21, 0xf) << 2;
}

static inline u32 msg_size(struct tipc_msg *m)
{
	return msg_bits(m, 0, 0, 0x1ffff);
}

static inline void msg_set_dest_droppable(struct tipc_msg *m, u32 d)
{
	msg_set_bits(m, 0, 19, 1, d);
}

static inline unchar *msg_data(struct tipc_msg *m)
{
	return ((unchar *)m) + msg_hdr_sz(m);
}

static inline struct tipc_msg *msg_get_wrapped(struct tipc_msg *m)
{
	return (struct tipc_msg *)msg_data(m);
}

static inline u32 msg_errcode(struct tipc_msg *m)
{
	return msg_bits(m, 1, 25, 0xf);
}

static inline void msg_set_bcast_ack(struct tipc_msg *m, u16 n)
{
	msg_set_bits(m, 1, 0, 0xffff, n);
}

static inline void msg_set_ack(struct tipc_msg *m, u16 n)
{
	msg_set_bits(m, 2, 16, 0xffff, n);
}

static inline void msg_set_seqno(struct tipc_msg *m, u16 n)
{
	msg_set_bits(m, 2, 0, 0xffff, n);
}

static inline u32 msg_importance(struct tipc_msg *m)
{
	int usr = msg_user(m);

	if (likely((usr <= TIPC_CRITICAL_IMPORTANCE) && !msg_errcode(m)))
		return usr;
	if ((usr == MSG_FRAGMENTER) || (usr == MSG_BUNDLER))
		return msg_bits(m, 9, 0, 0x7);
	return TIPC_SYSTEM_IMPORTANCE;
}

static inline u32 msg_origport(struct tipc_msg *m)
{
	if (msg_user(m) == MSG_FRAGMENTER)
		m = msg_get_wrapped(m);
	return msg_word(m, 4);
}

static struct sk_buff *(*klpe_tipc_msg_create)(uint user, uint type, uint hdr_sz,
				uint data_sz, u32 dnode, u32 onode,
				u32 dport, u32 oport, int errcode);

static bool (*klpe_tipc_msg_bundle)(struct sk_buff *skb, struct tipc_msg *msg, u32 mtu);
static bool (*klpe_tipc_msg_make_bundle)(struct sk_buff **skb, struct tipc_msg *msg,
			  u32 mtu, u32 dnode);

/* klp-ccp: from net/tipc/addr.h */
#include <linux/types.h>
#include <linux/tipc.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

static inline u32 klpr_tipc_own_addr(struct net *net)
{
	struct tipc_net *tn = net_generic(net, (*klpe_tipc_net_id));

	return tn->own_addr;
}

u32 klpr_tipc_own_addr(struct net *net);

/* klp-ccp: from net/tipc/net.h */
#include <net/genetlink.h>
/* klp-ccp: from net/tipc/netlink.h */
#include <net/netlink.h>

/* klp-ccp: from net/tipc/link.h */
#define ELINKCONG EAGAIN	/* link congestion <=> resource unavailable */

int klpp_tipc_link_xmit(struct tipc_link *link, struct sk_buff_head *list,
		   struct sk_buff_head *xmitq);

/* klp-ccp: from net/tipc/monitor.h */
struct tipc_mon_state {
	u16 list_gen;
	u16 peer_gen;
	u16 acked_gen;
	bool monitoring :1;
	bool probing    :1;
	bool reset      :1;
	bool synched    :1;
};

/* klp-ccp: from net/tipc/link.c */
#include <linux/pkt_sched.h>

struct tipc_stats {
	u32 sent_pkts;
	u32 recv_pkts;
	u32 sent_states;
	u32 recv_states;
	u32 sent_probes;
	u32 recv_probes;
	u32 sent_nacks;
	u32 recv_nacks;
	u32 sent_acks;
	u32 sent_bundled;
	u32 sent_bundles;
	u32 recv_bundled;
	u32 recv_bundles;
	u32 retransmitted;
	u32 sent_fragmented;
	u32 sent_fragments;
	u32 recv_fragmented;
	u32 recv_fragments;
	u32 link_congs;		/* # port sends blocked by congestion */
	u32 deferred_recv;
	u32 duplicates;
	u32 max_queue_sz;	/* send queue size high water mark */
	u32 accu_queue_sz;	/* used for send queue size profiling */
	u32 queue_sz_counts;	/* used for send queue size profiling */
	u32 msg_length_counts;	/* used for message length profiling */
	u32 msg_lengths_total;	/* used for message length profiling */
	u32 msg_length_profile[7]; /* used for msg. length profiling */
};

struct tipc_link {
	u32 addr;
	char name[TIPC_MAX_LINK_NAME];
	struct net *net;

	/* Management and link supervision data */
	u32 peer_session;
	u32 session;
	u32 peer_bearer_id;
	u32 bearer_id;
	u32 tolerance;
	u32 abort_limit;
	u32 state;
	u16 peer_caps;
	bool active;
	u32 silent_intv_cnt;
	char if_name[TIPC_MAX_IF_NAME];
	u32 priority;
	char net_plane;
	struct tipc_mon_state mon_state;
	u16 rst_cnt;

	/* Failover/synch */
	u16 drop_point;
	struct sk_buff *failover_reasm_skb;

	/* Max packet negotiation */
	u16 mtu;
	u16 advertised_mtu;

	/* Sending */
	struct sk_buff_head transmq;
	struct sk_buff_head backlogq;
	struct {
		u16 len;
		u16 limit;
		struct sk_buff *target_bskb;
	} backlog[5];
	u16 snd_nxt;
	u16 last_retransm;
	u16 window;
	u32 stale_count;

	/* Reception */
	u16 rcv_nxt;
	u32 rcv_unacked;
	struct sk_buff_head deferdq;
	struct sk_buff_head *inputq;
	struct sk_buff_head *namedq;

	/* Congestion handling */
	struct sk_buff_head wakeupq;

	/* Fragmentation/reassembly */
	struct sk_buff *reasm_buf;

	/* Broadcast */
	u16 ackers;
	u16 acked;
	struct tipc_link *bc_rcvlink;
	struct tipc_link *bc_sndlink;
	unsigned long prev_retr;
	u16 prev_from;
	u16 prev_to;
	u8 nack_state;
	bool bc_peer_is_up;

	/* Statistics */
	struct tipc_stats stats;
};

static const char *link_rst_msg = "Resetting link ";

static int klpr_link_schedule_user(struct tipc_link *l, struct tipc_msg *hdr)
{
	u32 dnode = klpr_tipc_own_addr(l->net);
	u32 dport = msg_origport(hdr);
	struct sk_buff *skb;

	/* Create and schedule wakeup pseudo message */
	skb = (*klpe_tipc_msg_create)(SOCK_WAKEUP, 0, INT_H_SIZE, 0,
			      dnode, l->addr, dport, 0, 0);
	if (!skb)
		return -ENOBUFS;
	msg_set_dest_droppable(buf_msg(skb), true);
	TIPC_SKB_CB(skb)->chain_imp = msg_importance(hdr);
	skb_queue_tail(&l->wakeupq, skb);
	l->stats.link_congs++;
	return -ELINKCONG;
}

int klpp_tipc_link_xmit(struct tipc_link *l, struct sk_buff_head *list,
		   struct sk_buff_head *xmitq)
{
	struct tipc_msg *hdr;
	unsigned int maxwin = l->window;
	int imp;
	unsigned int mtu = l->mtu;
	u16 ack = l->rcv_nxt - 1;
	u16 seqno = l->snd_nxt;
	u16 bc_ack = l->bc_rcvlink->rcv_nxt - 1;
	struct sk_buff_head *transmq = &l->transmq;
	struct sk_buff_head *backlogq = &l->backlogq;
	struct sk_buff *skb, *_skb, **tskb;
	int pkt_cnt = skb_queue_len(list);
	int rc = 0;

	if (pkt_cnt <= 0)
		return 0;

	hdr = buf_msg(skb_peek(list));

	if (unlikely(msg_size(hdr) > mtu)) {
		skb_queue_purge(list);
		return -EMSGSIZE;
	}

	imp = msg_importance(hdr);
	/* Allow oversubscription of one data msg per source at congestion */
	if (unlikely(l->backlog[imp].len >= l->backlog[imp].limit)) {
		if (imp == TIPC_SYSTEM_IMPORTANCE) {
			pr_warn("%s<%s>, link overflow", link_rst_msg, l->name);
			return -ENOBUFS;
		}
		rc = klpr_link_schedule_user(l, hdr);
	}

	if (pkt_cnt > 1) {
		l->stats.sent_fragmented++;
		l->stats.sent_fragments += pkt_cnt;
	}

	/* Prepare each packet for sending, and add to relevant queue: */
	while (skb_queue_len(list)) {
		skb = skb_peek(list);
		hdr = buf_msg(skb);
		msg_set_seqno(hdr, seqno);
		msg_set_ack(hdr, ack);
		msg_set_bcast_ack(hdr, bc_ack);

		if (likely(skb_queue_len(transmq) < maxwin)) {
			_skb = skb_clone(skb, GFP_ATOMIC);
			if (!_skb) {
				skb_queue_purge(list);
				return -ENOBUFS;
			}
			__skb_dequeue(list);
			__skb_queue_tail(transmq, skb);
			__skb_queue_tail(xmitq, _skb);
			TIPC_SKB_CB(skb)->ackers = l->ackers;
			l->rcv_unacked = 0;
			l->stats.sent_pkts++;
			seqno++;
			continue;
		}
		tskb = &l->backlog[imp].target_bskb;
		if ((*klpe_tipc_msg_bundle)(*tskb, hdr, mtu)) {
			kfree_skb(__skb_dequeue(list));
			l->stats.sent_bundled++;
			continue;
		}
		if ((*klpe_tipc_msg_make_bundle)(tskb, hdr, mtu, l->addr)) {
			kfree_skb(__skb_dequeue(list));
			__skb_queue_tail(backlogq, *tskb);
			l->backlog[imp].len++;
			l->stats.sent_bundled++;
			l->stats.sent_bundles++;
			continue;
		}
		l->backlog[imp].target_bskb = NULL;
		l->backlog[imp].len += skb_queue_len(list);
		skb_queue_splice_tail_init(list, backlogq);
	}
	l->snd_nxt = seqno;
	return rc;
}



#define LP_MODULE "tipc"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1210779.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tipc_msg_bundle", (void *)&klpe_tipc_msg_bundle, "tipc" },
	{ "tipc_msg_create", (void *)&klpe_tipc_msg_create, "tipc" },
	{ "tipc_msg_make_bundle", (void *)&klpe_tipc_msg_make_bundle, "tipc" },
	{ "tipc_net_id", (void *)&klpe_tipc_net_id, "tipc" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1210779_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1210779_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
