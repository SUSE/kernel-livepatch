/*
 * livepatch_bsc1195308
 *
 * Fix for CVE-2022-0435, bsc#1195308
 *
 *  Upstream commit:
 *  None yet
 *
 *  SLE12-SP3 commit:
 *  Not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  eff4836bb29f91c4769857e032cbf019162cfdec
 *
 *  SLE15-SP2 and -SP3 commit:
 *  5e4e31ed176ccf5463049d4f4fa9eac9412667d7
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

#if !IS_MODULE(CONFIG_TIPC)
#error "Live patch supports only CONFIG_TIPC=m"
#endif

/* klp-ccp: from net/tipc/monitor.c */
#include <net/genetlink.h>

/* klp-ccp: from net/tipc/core.h */
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

static inline struct tipc_net *klpr_tipc_net(struct net *net)
{
	return net_generic(net, (*klpe_tipc_net_id));
}

static inline unsigned int tipc_hashfn(u32 addr)
{
	return addr & (NODE_HTABLE_SIZE - 1);
}

static inline u16 mod(u16 x)
{
	return x & 0xffffu;
}

static inline int less_eq(u16 left, u16 right)
{
	return mod(right - left) < 32768u;
}

static inline int more(u16 left, u16 right)
{
	return !less_eq(left, right);
}

/* klp-ccp: from net/tipc/addr.h */
#include <linux/types.h>
#include <linux/tipc.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
/* klp-ccp: from net/tipc/netlink.h */
#include <net/netlink.h>

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

void klpp_tipc_mon_rcv(struct net *net, void *data, u16 dlen, u32 addr,
		  struct tipc_mon_state *state, int bearer_id);

/* klp-ccp: from net/tipc/msg.h */
#include <linux/tipc.h>
/* klp-ccp: from net/tipc/bearer.h */
#include <net/genetlink.h>

/* klp-ccp: from net/tipc/monitor.c */
#define MAX_MON_DOMAIN       64

struct tipc_mon_domain {
	u16 len;
	u16 gen;
	u16 ack_gen;
	u16 member_cnt;
	u64 up_map;
	u32 members[MAX_MON_DOMAIN];
};

struct tipc_peer {
	u32 addr;
	struct tipc_mon_domain *domain;
	struct hlist_node hash;
	struct list_head list;
	u8 applied;
	u8 down_cnt;
	bool is_up;
	bool is_head;
	bool is_local;
};

struct tipc_monitor {
	struct hlist_head peers[NODE_HTABLE_SIZE];
	int peer_cnt;
	struct tipc_peer *self;
	rwlock_t lock;
	struct tipc_mon_domain cache;
	u16 list_gen;
	u16 dom_gen;
	struct net *net;
	struct timer_list timer;
	unsigned long timer_intv;
};

static struct tipc_monitor *klpr_tipc_monitor(struct net *net, int bearer_id)
{
	return klpr_tipc_net(net)->monitors[bearer_id];
}

static int dom_rec_len(struct tipc_mon_domain *dom, u16 mcnt)
{
	return ((void *)&dom->members - (void *)dom) + (mcnt * sizeof(u32));
}

static int map_get(u64 up_map, int i)
{
	return (up_map & (1 << i)) >> i;
}

static struct tipc_peer *peer_prev(struct tipc_peer *peer)
{
	return list_last_entry(&peer->list, struct tipc_peer, list);
}

static struct tipc_peer *peer_nxt(struct tipc_peer *peer)
{
	return list_first_entry(&peer->list, struct tipc_peer, list);
}

static struct tipc_peer *peer_head(struct tipc_peer *peer)
{
	while (!peer->is_head)
		peer = peer_prev(peer);
	return peer;
}

static struct tipc_peer *get_peer(struct tipc_monitor *mon, u32 addr)
{
	struct tipc_peer *peer;
	unsigned int thash = tipc_hashfn(addr);

	hlist_for_each_entry(peer, &mon->peers[thash], hash) {
		if (peer->addr == addr)
			return peer;
	}
	return NULL;
}

static void mon_identify_lost_members(struct tipc_peer *peer,
				      struct tipc_mon_domain *dom_bef,
				      int applied_bef)
{
	struct tipc_peer *member = peer;
	struct tipc_mon_domain *dom_aft = peer->domain;
	int applied_aft = peer->applied;
	int i;

	for (i = 0; i < applied_bef; i++) {
		member = peer_nxt(member);

		/* Do nothing if self or peer already see member as down */
		if (!member->is_up || !map_get(dom_bef->up_map, i))
			continue;

		/* Loss of local node must be detected by active probing */
		if (member->is_local)
			continue;

		/* Start probing if member was removed from applied domain */
		if (!applied_aft || (applied_aft < i)) {
			member->down_cnt = 1;
			continue;
		}

		/* Member loss is confirmed if it is still in applied domain */
		if (!map_get(dom_aft->up_map, i))
			member->down_cnt++;
	}
}

static void mon_apply_domain(struct tipc_monitor *mon,
			     struct tipc_peer *peer)
{
	struct tipc_mon_domain *dom = peer->domain;
	struct tipc_peer *member;
	u32 addr;
	int i;

	if (!dom || !peer->is_up)
		return;

	/* Scan across domain members and match against monitor list */
	peer->applied = 0;
	member = peer_nxt(peer);
	for (i = 0; i < dom->member_cnt; i++) {
		addr = dom->members[i];
		if (addr != member->addr)
			return;
		peer->applied++;
		member = peer_nxt(member);
	}
}

static void mon_assign_roles(struct tipc_monitor *mon, struct tipc_peer *head)
{
	struct tipc_peer *peer = peer_nxt(head);
	struct tipc_peer *self = mon->self;
	int i = 0;

	for (; peer != self; peer = peer_nxt(peer)) {
		peer->is_local = false;

		/* Update domain member */
		if (i++ < head->applied) {
			peer->is_head = false;
			if (head == self)
				peer->is_local = true;
			continue;
		}
		/* Assign next domain head */
		if (!peer->is_up)
			continue;
		if (peer->is_head)
			break;
		head = peer;
		head->is_head = true;
		i = 0;
	}
	mon->list_gen++;
}

void klpp_tipc_mon_rcv(struct net *net, void *data, u16 dlen, u32 addr,
		  struct tipc_mon_state *state, int bearer_id)
{
	struct tipc_monitor *mon = klpr_tipc_monitor(net, bearer_id);
	struct tipc_mon_domain *arrv_dom = data;
	struct tipc_mon_domain dom_bef;
	struct tipc_mon_domain *dom;
	struct tipc_peer *peer;
	u16 new_member_cnt = ntohs(arrv_dom->member_cnt);
	int new_dlen = dom_rec_len(arrv_dom, new_member_cnt);
	u16 new_gen = ntohs(arrv_dom->gen);
	u16 acked_gen = ntohs(arrv_dom->ack_gen);
	bool probing = state->probing;
	int i, applied_bef;

	state->probing = false;

	/* Sanity check received domain record */
	if (dlen < dom_rec_len(arrv_dom, 0))
		return;
	if (dlen != dom_rec_len(arrv_dom, new_member_cnt))
		return;
	if ((dlen < new_dlen) || ntohs(arrv_dom->len) != new_dlen)
		return;
	/*
	 * Fix CVE-2022-0435
	 *  +2 lines
	 */
	if (new_member_cnt > MAX_MON_DOMAIN)
		return;

	/* Synch generation numbers with peer if link just came up */
	if (!state->synched) {
		state->peer_gen = new_gen - 1;
		state->acked_gen = acked_gen;
		state->synched = true;
	}

	if (more(acked_gen, state->acked_gen))
		state->acked_gen = acked_gen;

	/* Drop duplicate unless we are waiting for a probe response */
	if (!more(new_gen, state->peer_gen) && !probing)
		return;

	write_lock_bh(&mon->lock);
	peer = get_peer(mon, addr);
	if (!peer || !peer->is_up)
		goto exit;

	/* Peer is confirmed, stop any ongoing probing */
	peer->down_cnt = 0;

	/* Task is done for duplicate record */
	if (!more(new_gen, state->peer_gen))
		goto exit;

	state->peer_gen = new_gen;

	/* Cache current domain record for later use */
	dom_bef.member_cnt = 0;
	dom = peer->domain;
	if (dom)
		memcpy(&dom_bef, dom, dom->len);

	/* Transform and store received domain record */
	if (!dom || (dom->len < new_dlen)) {
		kfree(dom);
		dom = kmalloc(new_dlen, GFP_ATOMIC);
		peer->domain = dom;
		if (!dom)
			goto exit;
	}
	dom->len = new_dlen;
	dom->gen = new_gen;
	dom->member_cnt = new_member_cnt;
	dom->up_map = be64_to_cpu(arrv_dom->up_map);
	for (i = 0; i < new_member_cnt; i++)
		dom->members[i] = ntohl(arrv_dom->members[i]);

	/* Update peers affected by this domain record */
	applied_bef = peer->applied;
	mon_apply_domain(mon, peer);
	mon_identify_lost_members(peer, &dom_bef, applied_bef);
	mon_assign_roles(mon, peer_head(peer));
exit:
	write_unlock_bh(&mon->lock);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1195308.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "tipc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tipc_net_id", (void *)&klpe_tipc_net_id, "tipc" },
};

static int livepatch_bsc1195308_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1195308_module_nb = {
	.notifier_call = livepatch_bsc1195308_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1195308_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1195308_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1195308_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1195308_module_nb);
}
