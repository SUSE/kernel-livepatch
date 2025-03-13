/*
 * bsc1229640_net_netfilter_nfnetlink_queue
 *
 * Fix for CVE-2022-48911, bsc#1229640
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

/* klp-ccp: from net/netfilter/nfnetlink_queue.c */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>

/* klp-ccp: from include/linux/netfilter/nfnetlink.h */
#define _NFNETLINK_H

/* klp-ccp: from net/netfilter/nfnetlink_queue.c */
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/netfilter/nf_queue.h>
#include <net/netns/generic.h>
#include <linux/atomic.h>

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)

/* klp-ccp: from net/bridge/br_private.h */
#include <linux/u64_stats_sync.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from net/netfilter/nfnetlink_queue.c */
#endif

#include "livepatch_bsc1229640.h"

struct nfqnl_instance {
	struct hlist_node hlist;		/* global list of queues */
	struct rcu_head rcu;

	u32 peer_portid;
	unsigned int queue_maxlen;
	unsigned int copy_range;
	unsigned int queue_dropped;
	unsigned int queue_user_dropped;


	u_int16_t queue_num;			/* number of this queue */
	u_int8_t copy_mode;
	u_int32_t flags;			/* Set using NFQA_CFG_FLAGS */
/*
 * Following fields are dirtied for each queued packet,
 * keep them in same cache line if possible.
 */
	spinlock_t	lock	____cacheline_aligned_in_smp;
	unsigned int	queue_total;
	unsigned int	id_sequence;		/* 'sequence' of pkt ids */
	struct list_head queue_list;		/* packets in queue */
};

static unsigned int (*klpe_nfnl_queue_net_id) __read_mostly;

#define INSTANCE_BUCKETS	16
struct nfnl_queue_net {
	spinlock_t instances_lock;
	struct hlist_head instance_table[INSTANCE_BUCKETS];
};

static struct nfnl_queue_net *klpr_nfnl_queue_pernet(struct net *net)
{
	return net_generic(net, (*klpe_nfnl_queue_net_id));
}

static inline u_int8_t instance_hashfn(u_int16_t queue_num)
{
	return ((queue_num >> 8) ^ queue_num) % INSTANCE_BUCKETS;
}

static struct nfqnl_instance *
instance_lookup(struct nfnl_queue_net *q, u_int16_t queue_num)
{
	struct hlist_head *head;
	struct nfqnl_instance *inst;

	head = &q->instance_table[instance_hashfn(queue_num)];
	hlist_for_each_entry_rcu(inst, head, hlist) {
		if (inst->queue_num == queue_num)
			return inst;
	}
	return NULL;
}

static int
(*klpe___nfqnl_enqueue_packet)(struct net *net, struct nfqnl_instance *queue,
			struct nf_queue_entry *entry);

static struct nf_queue_entry *
klpp_nf_queue_entry_dup(struct nf_queue_entry *e)
{
	struct nf_queue_entry *entry = kmemdup(e, e->size, GFP_ATOMIC);

	if (!entry)
		return NULL;

	if (klpp_nf_queue_entry_get_refs(entry))
		return entry;

	kfree(entry);
	return NULL;
}

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)

static void nf_bridge_adjust_skb_data(struct sk_buff *skb)
{
	if (skb->nf_bridge)
		__skb_push(skb, skb->network_header - skb->mac_header);
}

static void (*klpe_nf_bridge_adjust_segmented_data)(struct sk_buff *skb);

#else
#error "klp-ccp: non-taken branch"
#endif

static void free_entry(struct nf_queue_entry *entry)
{
	nf_queue_entry_release_refs(entry);
	kfree(entry);
}

static int
klpp___nfqnl_enqueue_packet_gso(struct net *net, struct nfqnl_instance *queue,
			   struct sk_buff *skb, struct nf_queue_entry *entry)
{
	int ret = -ENOMEM;
	struct nf_queue_entry *entry_seg;

	(*klpe_nf_bridge_adjust_segmented_data)(skb);

	if (skb->next == NULL) { /* last packet, no need to copy entry */
		struct sk_buff *gso_skb = entry->skb;
		entry->skb = skb;
		ret = (*klpe___nfqnl_enqueue_packet)(net, queue, entry);
		if (ret)
			entry->skb = gso_skb;
		return ret;
	}

	skb_mark_not_on_list(skb);

	entry_seg = klpp_nf_queue_entry_dup(entry);
	if (entry_seg) {
		entry_seg->skb = skb;
		ret = (*klpe___nfqnl_enqueue_packet)(net, queue, entry_seg);
		if (ret)
			free_entry(entry_seg);
	}
	return ret;
}

int
klpp_nfqnl_enqueue_packet(struct nf_queue_entry *entry, unsigned int queuenum)
{
	unsigned int queued;
	struct nfqnl_instance *queue;
	struct sk_buff *skb, *segs;
	int err = -ENOBUFS;
	struct net *net = entry->state.net;
	struct nfnl_queue_net *q = klpr_nfnl_queue_pernet(net);

	/* rcu_read_lock()ed by nf_hook_thresh */
	queue = instance_lookup(q, queuenum);
	if (!queue)
		return -ESRCH;

	if (queue->copy_mode == NFQNL_COPY_NONE)
		return -EINVAL;

	skb = entry->skb;

	switch (entry->state.pf) {
	case NFPROTO_IPV4:
		skb->protocol = htons(ETH_P_IP);
		break;
	case NFPROTO_IPV6:
		skb->protocol = htons(ETH_P_IPV6);
		break;
	}

	if ((queue->flags & NFQA_CFG_F_GSO) || !skb_is_gso(skb))
		return (*klpe___nfqnl_enqueue_packet)(net, queue, entry);

	nf_bridge_adjust_skb_data(skb);
	segs = skb_gso_segment(skb, 0);
	/* Does not use PTR_ERR to limit the number of error codes that can be
	 * returned by nf_queue.  For instance, callers rely on -ESRCH to
	 * mean 'ignore this hook'.
	 */
	if (IS_ERR_OR_NULL(segs))
		goto out_err;
	queued = 0;
	err = 0;
	do {
		struct sk_buff *nskb = segs->next;
		if (err == 0)
			err = klpp___nfqnl_enqueue_packet_gso(net, queue,
							segs, entry);
		if (err == 0)
			queued++;
		else
			kfree_skb(segs);
		segs = nskb;
	} while (segs);

	if (queued) {
		if (err) /* some segments are already queued */
			free_entry(entry);
		kfree_skb(skb);
		return 0;
	}
 out_err:
	(*klpe_nf_bridge_adjust_segmented_data)(skb);
	return err;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nfnetlink_queue"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__nfqnl_enqueue_packet", (void *)&klpe___nfqnl_enqueue_packet,
	  "nfnetlink_queue" },
	{ "nf_bridge_adjust_segmented_data",
	  (void *)&klpe_nf_bridge_adjust_segmented_data, "nfnetlink_queue" },
	{ "nfnl_queue_net_id", (void *)&klpe_nfnl_queue_net_id,
	  "nfnetlink_queue" },
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

int bsc1229640_net_netfilter_nfnetlink_queue_init(void)
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

void bsc1229640_net_netfilter_nfnetlink_queue_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
