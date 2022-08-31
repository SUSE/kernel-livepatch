/*
 * livepatch_bsc1201941
 *
 * Fix for CVE-2022-36946, bsc#1201941
 *
 *  Upstream commit:
 *  99a63d36cb3e ("netfilter: nf_queue: do not allow packet truncation below
 *                 transport header offset")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  06aa7006aef207b75b7b637f4b5cf40f95a5856f
 *
 *  SLE15-SP2 and -SP3 commit:
 *  f4f33cdae4b2741d6b5e10c391f9105523122dda
 *
 *  SLE15-SP4 commit:
 *  none yet
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

#if !IS_MODULE(CONFIG_NETFILTER_NETLINK_QUEUE)
#error "Live patch supports only CONFIG_NETFILTER_NETLINK_QUEUE=m"
#endif

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
#include <linux/netfilter/nfnetlink.h>
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
#include <linux/netdevice.h>
#include <linux/u64_stats_sync.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from net/netfilter/nfnetlink_queue.c */
#endif

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

static unsigned int (*klpe_nfnl_queue_net_id);

static struct nfnl_queue_net *klpr_nfnl_queue_pernet(struct net *net)
{
	return net_generic(net, (*klpe_nfnl_queue_net_id));
}

static void
__dequeue_entry(struct nfqnl_instance *queue, struct nf_queue_entry *entry)
{
	list_del(&entry->list);
	queue->queue_total--;
}

static struct nf_queue_entry *
find_dequeue_entry(struct nfqnl_instance *queue, unsigned int id)
{
	struct nf_queue_entry *entry = NULL, *i;

	spin_lock_bh(&queue->lock);

	list_for_each_entry(i, &queue->queue_list, list) {
		if (i->id == id) {
			entry = i;
			break;
		}
	}

	if (entry)
		__dequeue_entry(queue, entry);

	spin_unlock_bh(&queue->lock);

	return entry;
}

static int
/*
 * Fix CVE-2022-36946
 *  -1 line, +1 line
 */
klpp_nfqnl_mangle(void *data, unsigned int data_len, struct nf_queue_entry *e, int diff)
{
	struct sk_buff *nskb;

	if (diff < 0) {
		/*
		 * Fix CVE-2022-36946
		 *  +5 lines
		 */
		unsigned int min_len = skb_transport_offset(e->skb);

		if (data_len < min_len)
			return -EINVAL;

		if (pskb_trim(e->skb, data_len))
			return -ENOMEM;
	} else if (diff > 0) {
		if (data_len > 0xFFFF)
			return -EINVAL;
		if (diff > skb_tailroom(e->skb)) {
			nskb = skb_copy_expand(e->skb, skb_headroom(e->skb),
					       diff, GFP_ATOMIC);
			if (!nskb) {
				printk(KERN_WARNING "nf_queue: OOM "
				      "in mangle, dropping packet\n");
				return -ENOMEM;
			}
			kfree_skb(e->skb);
			e->skb = nskb;
		}
		skb_put(e->skb, diff);
	}
	if (!skb_make_writable(e->skb, data_len))
		return -ENOMEM;
	skb_copy_to_linear_data(e->skb, data, data_len);
	e->skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static const struct nla_policy (*klpe_nfqa_vlan_policy)[NFQA_VLAN_MAX + 1];

static struct nfqnl_instance *
(*klpe_verdict_instance_lookup)(struct nfnl_queue_net *q, u16 queue_num, u32 nlportid);

static struct nfqnl_msg_verdict_hdr*
verdicthdr_get(const struct nlattr * const nfqa[])
{
	struct nfqnl_msg_verdict_hdr *vhdr;
	unsigned int verdict;

	if (!nfqa[NFQA_VERDICT_HDR])
		return NULL;

	vhdr = nla_data(nfqa[NFQA_VERDICT_HDR]);
	verdict = ntohl(vhdr->verdict) & NF_VERDICT_MASK;
	if (verdict > NF_MAX_VERDICT || verdict == NF_STOLEN)
		return NULL;
	return vhdr;
}

static struct nf_conn *nfqnl_ct_parse(struct nfnl_ct_hook *nfnl_ct,
				      const struct nlmsghdr *nlh,
				      const struct nlattr * const nfqa[],
				      struct nf_queue_entry *entry,
				      enum ip_conntrack_info *ctinfo)
{
	struct nf_conn *ct;

	ct = nfnl_ct->get_ct(entry->skb, ctinfo);
	if (ct == NULL)
		return NULL;

	if (nfnl_ct->parse(nfqa[NFQA_CT], ct) < 0)
		return NULL;

	if (nfqa[NFQA_EXP])
		nfnl_ct->attach_expect(nfqa[NFQA_EXP], ct,
				      NETLINK_CB(entry->skb).portid,
				      nlmsg_report(nlh));
	return ct;
}

static int klpr_nfqa_parse_bridge(struct nf_queue_entry *entry,
			     const struct nlattr * const nfqa[])
{
	if (nfqa[NFQA_VLAN]) {
		struct nlattr *tb[NFQA_VLAN_MAX + 1];
		int err;

		err = nla_parse_nested(tb, NFQA_VLAN_MAX, nfqa[NFQA_VLAN],
				       (*klpe_nfqa_vlan_policy), NULL);
		if (err < 0)
			return err;

		if (!tb[NFQA_VLAN_TCI] || !tb[NFQA_VLAN_PROTO])
			return -EINVAL;

		entry->skb->vlan_tci = ntohs(nla_get_be16(tb[NFQA_VLAN_TCI]));
		entry->skb->vlan_proto = nla_get_be16(tb[NFQA_VLAN_PROTO]);
	}

	if (nfqa[NFQA_L2HDR]) {
		int mac_header_len = entry->skb->network_header -
			entry->skb->mac_header;

		if (mac_header_len != nla_len(nfqa[NFQA_L2HDR]))
			return -EINVAL;
		else if (mac_header_len > 0)
			memcpy(skb_mac_header(entry->skb),
			       nla_data(nfqa[NFQA_L2HDR]),
			       mac_header_len);
	}

	return 0;
}

int klpp_nfqnl_recv_verdict(struct net *net, struct sock *ctnl,
			      struct sk_buff *skb,
			      const struct nlmsghdr *nlh,
			      const struct nlattr * const nfqa[])
{
	struct nfgenmsg *nfmsg = nlmsg_data(nlh);
	u_int16_t queue_num = ntohs(nfmsg->res_id);
	struct nfqnl_msg_verdict_hdr *vhdr;
	struct nfqnl_instance *queue;
	unsigned int verdict;
	struct nf_queue_entry *entry;
	enum ip_conntrack_info uninitialized_var(ctinfo);
	struct nfnl_ct_hook *nfnl_ct;
	struct nf_conn *ct = NULL;
	struct nfnl_queue_net *q = klpr_nfnl_queue_pernet(net);
	int err;

	queue = (*klpe_verdict_instance_lookup)(q, queue_num,
					NETLINK_CB(skb).portid);
	if (IS_ERR(queue))
		return PTR_ERR(queue);

	vhdr = verdicthdr_get(nfqa);
	if (!vhdr)
		return -EINVAL;

	verdict = ntohl(vhdr->verdict);

	entry = find_dequeue_entry(queue, ntohl(vhdr->id));
	if (entry == NULL)
		return -ENOENT;

	/* rcu lock already held from nfnl->call_rcu. */
	nfnl_ct = rcu_dereference(nfnl_ct_hook);

	if (nfqa[NFQA_CT]) {
		if (nfnl_ct != NULL)
			ct = nfqnl_ct_parse(nfnl_ct, nlh, nfqa, entry, &ctinfo);
	}

	if (entry->state.pf == PF_BRIDGE) {
		err = klpr_nfqa_parse_bridge(entry, nfqa);
		if (err < 0)
			return err;
	}

	if (nfqa[NFQA_PAYLOAD]) {
		u16 payload_len = nla_len(nfqa[NFQA_PAYLOAD]);
		int diff = payload_len - entry->skb->len;

		if (klpp_nfqnl_mangle(nla_data(nfqa[NFQA_PAYLOAD]),
				 payload_len, entry, diff) < 0)
			verdict = NF_DROP;

		if (ct && diff)
			nfnl_ct->seq_adjust(entry->skb, ct, ctinfo, diff);
	}

	if (nfqa[NFQA_MARK])
		entry->skb->mark = ntohl(nla_get_be32(nfqa[NFQA_MARK]));

	nf_reinject(entry, verdict);
	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1201941.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfnetlink_queue"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfnl_queue_net_id", (void *)&klpe_nfnl_queue_net_id,
	  "nfnetlink_queue" },
	{ "nfqa_vlan_policy", (void *)&klpe_nfqa_vlan_policy,
	  "nfnetlink_queue" },
	{ "verdict_instance_lookup", (void *)&klpe_verdict_instance_lookup,
	  "nfnetlink_queue" },
};

static int livepatch_bsc1201941_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1201941_module_nb = {
	.notifier_call = livepatch_bsc1201941_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1201941_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1201941_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1201941_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1201941_module_nb);
}
