/*
 * bsc1285687_net_netfilter_nfnetlink_queue
 *
 * Fix for CVE-2026-99999, bsc#1285687
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


#include "livepatch_bsc1285687.h"

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/list.h>
#include <linux/cgroup-defs.h>
#include <net/gso.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/netfilter/nf_queue.h>
#include <net/netns/generic.h>
#include <linux/atomic.h>

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)

/* klp-ccp: from net/bridge/br_private.h */
#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/netpoll.h>
#include <linux/u64_stats_sync.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <net/pkt_cls.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from net/netfilter/nfnetlink_queue.c */
#endif

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
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

static inline void
__enqueue_entry(struct nfqnl_instance *queue, struct nf_queue_entry *entry)
{
       list_add_tail(&entry->list, &queue->queue_list);
       queue->queue_total++;
}

extern void nfqnl_reinject(struct nf_queue_entry *entry, unsigned int verdict);

static int
nfqnl_put_packet_info(struct sk_buff *nlskb, struct sk_buff *packet,
		      bool csum_verify)
{
	__u32 flags = 0;

	if (packet->ip_summed == CHECKSUM_PARTIAL)
		flags = NFQA_SKB_CSUMNOTREADY;
	else if (csum_verify)
		flags = NFQA_SKB_CSUM_NOTVERIFIED;

	if (skb_is_gso(packet))
		flags |= NFQA_SKB_GSO;

	return flags ? nla_put_be32(nlskb, NFQA_SKB_INFO, htonl(flags)) : 0;
}

static int nfqnl_put_sk_uidgid(struct sk_buff *skb, struct sock *sk)
{
	const struct cred *cred;

	if (!sk_fullsock(sk))
		return 0;

	read_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_socket && sk->sk_socket->file) {
		cred = sk->sk_socket->file->f_cred;
		if (nla_put_be32(skb, NFQA_UID,
		    htonl(from_kuid_munged(&init_user_ns, cred->fsuid))))
			goto nla_put_failure;
		if (nla_put_be32(skb, NFQA_GID,
		    htonl(from_kgid_munged(&init_user_ns, cred->fsgid))))
			goto nla_put_failure;
	}
	read_unlock_bh(&sk->sk_callback_lock);
	return 0;

nla_put_failure:
	read_unlock_bh(&sk->sk_callback_lock);
	return -1;
}

static int nfqnl_put_sk_classid(struct sk_buff *skb, struct sock *sk)
{
#if IS_ENABLED(CONFIG_CGROUP_NET_CLASSID)
	if (sk && sk_fullsock(sk)) {
		u32 classid = sock_cgroup_classid(&sk->sk_cgrp_data);

		if (classid && nla_put_be32(skb, NFQA_CGROUP_CLASSID, htonl(classid)))
			return -1;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return 0;
}

static u32 nfqnl_get_sk_secctx(struct sk_buff *skb, char **secdata)
{
	u32 seclen = 0;
#if IS_ENABLED(CONFIG_NETWORK_SECMARK)
	if (!skb || !sk_fullsock(skb->sk))
		return 0;

	read_lock_bh(&skb->sk->sk_callback_lock);

	if (skb->secmark)
		security_secid_to_secctx(skb->secmark, secdata, &seclen);

	read_unlock_bh(&skb->sk->sk_callback_lock);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return seclen;
}

static u32 nfqnl_get_bridge_size(struct nf_queue_entry *entry)
{
	struct sk_buff *entskb = entry->skb;
	u32 nlalen = 0;

	if (entry->state.pf != PF_BRIDGE || !skb_mac_header_was_set(entskb))
		return 0;

	if (skb_vlan_tag_present(entskb))
		nlalen += nla_total_size(nla_total_size(sizeof(__be16)) +
					 nla_total_size(sizeof(__be16)));

	if (entskb->network_header > entskb->mac_header)
		nlalen += nla_total_size((entskb->network_header -
					  entskb->mac_header));

	return nlalen;
}

static int nfqnl_put_bridge(struct nf_queue_entry *entry, struct sk_buff *skb)
{
	struct sk_buff *entskb = entry->skb;

	if (entry->state.pf != PF_BRIDGE || !skb_mac_header_was_set(entskb))
		return 0;

	if (skb_vlan_tag_present(entskb)) {
		struct nlattr *nest;

		nest = nla_nest_start(skb, NFQA_VLAN);
		if (!nest)
			goto nla_put_failure;

		if (nla_put_be16(skb, NFQA_VLAN_TCI, htons(entskb->vlan_tci)) ||
		    nla_put_be16(skb, NFQA_VLAN_PROTO, entskb->vlan_proto))
			goto nla_put_failure;

		nla_nest_end(skb, nest);
	}

	if (entskb->mac_header < entskb->network_header) {
		int len = (int)(entskb->network_header - entskb->mac_header);

		if (nla_put(skb, NFQA_L2HDR, len, skb_mac_header(entskb)))
			goto nla_put_failure;
	}

	return 0;

nla_put_failure:
	return -1;
}

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
static int nfqnl_put_master_ifindex(struct sk_buff *nlskb, int attr,
				    const struct net_device *dev)
{
	const struct net_device *upper;

	if (dev && !netif_is_bridge_port(dev))
		return 0;

	upper = netdev_master_upper_dev_get_rcu((struct net_device *)dev);
	if (upper && nla_put_be32(nlskb, attr, htonl(upper->ifindex)))
		return -EMSGSIZE;

	return 0;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static struct sk_buff *
nfqnl_build_packet_message(struct net *net, struct nfqnl_instance *queue,
			   struct nf_queue_entry *entry,
			   __be32 **packet_id_ptr)
{
	size_t size;
	size_t data_len = 0, cap_len = 0;
	unsigned int hlen = 0;
	struct sk_buff *skb;
	struct nlattr *nla;
	struct nfqnl_msg_packet_hdr *pmsg;
	struct nlmsghdr *nlh;
	struct sk_buff *entskb = entry->skb;
	struct net_device *indev;
	struct net_device *outdev;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo = 0;
	const struct nfnl_ct_hook *nfnl_ct;
	bool csum_verify;
	char *secdata = NULL;
	u32 seclen = 0;
	ktime_t tstamp;

	size = nlmsg_total_size(sizeof(struct nfgenmsg))
		+ nla_total_size(sizeof(struct nfqnl_msg_packet_hdr))
		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
		+ nla_total_size(sizeof(u_int32_t))	/* ifindex */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		+ nla_total_size(sizeof(u_int32_t))	/* mark */
		+ nla_total_size(sizeof(u_int32_t))	/* priority */
		+ nla_total_size(sizeof(struct nfqnl_msg_packet_hw))
		+ nla_total_size(sizeof(u_int32_t))	/* skbinfo */
#if IS_ENABLED(CONFIG_CGROUP_NET_CLASSID)
		+ nla_total_size(sizeof(u_int32_t))	/* classid */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		+ nla_total_size(sizeof(u_int32_t));	/* cap_len */

	tstamp = skb_tstamp_cond(entskb, false);
	if (tstamp)
		size += nla_total_size(sizeof(struct nfqnl_msg_packet_timestamp));

	size += nfqnl_get_bridge_size(entry);

	if (entry->state.hook <= NF_INET_FORWARD ||
	   (entry->state.hook == NF_INET_POST_ROUTING && entskb->sk == NULL))
		csum_verify = !skb_csum_unnecessary(entskb);
	else
		csum_verify = false;

	outdev = entry->state.out;

	switch ((enum nfqnl_config_mode)READ_ONCE(queue->copy_mode)) {
	case NFQNL_COPY_META:
	case NFQNL_COPY_NONE:
		break;

	case NFQNL_COPY_PACKET:
		if (!(queue->flags & NFQA_CFG_F_GSO) &&
		    entskb->ip_summed == CHECKSUM_PARTIAL) {
			if (entskb->protocol == htons(ETH_P_IP) &&
			    (!pskb_network_may_pull(entskb, sizeof(struct iphdr)) ||
				ip_check_csum_start(entskb)))
				return NULL;
			if (skb_checksum_help(entskb))
				return NULL;
		}

		data_len = READ_ONCE(queue->copy_range);
		if (data_len > entskb->len)
			data_len = entskb->len;

		hlen = skb_zerocopy_headlen(entskb);
		hlen = min_t(unsigned int, hlen, data_len);
		size += sizeof(struct nlattr) + hlen;
		cap_len = entskb->len;
		break;
	}

	nfnl_ct = rcu_dereference(nfnl_ct_hook);

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	if (queue->flags & NFQA_CFG_F_CONNTRACK) {
		if (nfnl_ct != NULL) {
			ct = nf_ct_get(entskb, &ctinfo);
			if (ct != NULL)
				size += nfnl_ct->build_size(ct);
		}
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

	if (queue->flags & NFQA_CFG_F_UID_GID) {
		size += (nla_total_size(sizeof(u_int32_t))	/* uid */
			+ nla_total_size(sizeof(u_int32_t)));	/* gid */
	}

	if ((queue->flags & NFQA_CFG_F_SECCTX) && entskb->sk) {
		seclen = nfqnl_get_sk_secctx(entskb, &secdata);
		if (seclen)
			size += nla_total_size(seclen);
	}

	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb) {
		skb_tx_error(entskb);
		goto nlmsg_failure;
	}

	nlh = nfnl_msg_put(skb, 0, 0,
			   nfnl_msg_type(NFNL_SUBSYS_QUEUE, NFQNL_MSG_PACKET),
			   0, entry->state.pf, NFNETLINK_V0,
			   htons(queue->queue_num));
	if (!nlh) {
		skb_tx_error(entskb);
		kfree_skb(skb);
		goto nlmsg_failure;
	}

	nla = __nla_reserve(skb, NFQA_PACKET_HDR, sizeof(*pmsg));
	pmsg = nla_data(nla);
	pmsg->hw_protocol	= entskb->protocol;
	pmsg->hook		= entry->state.hook;
	*packet_id_ptr		= &pmsg->packet_id;

	indev = entry->state.in;
	if (indev) {
#if !IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#error "klp-ccp: non-taken branch"
#else
		if (entry->state.pf == PF_BRIDGE) {
			/* Case 1: indev is physical input device, we need to
			 * look for bridge group (when called from
			 * netfilter_bridge) */
			if (nla_put_be32(skb, NFQA_IFINDEX_PHYSINDEV,
					 htonl(indev->ifindex)) ||
			    nfqnl_put_master_ifindex(skb, NFQA_IFINDEX_INDEV, indev))
				goto nla_put_failure;
		} else {
			int physinif;

			/* Case 2: indev is bridge group, we need to look for
			 * physical device (when called from ipv4) */
			if (nla_put_be32(skb, NFQA_IFINDEX_INDEV,
					 htonl(indev->ifindex)))
				goto nla_put_failure;

			physinif = nf_bridge_get_physinif(entskb);
			if (physinif &&
			    nla_put_be32(skb, NFQA_IFINDEX_PHYSINDEV,
					 htonl(physinif)))
				goto nla_put_failure;
		}
#endif
	}

	if (outdev) {
#if !IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#error "klp-ccp: non-taken branch"
#else
		if (entry->state.pf == PF_BRIDGE) {
			/* Case 1: outdev is physical output device, we need to
			 * look for bridge group (when called from
			 * netfilter_bridge) */
			if (nla_put_be32(skb, NFQA_IFINDEX_PHYSOUTDEV,
					 htonl(outdev->ifindex)) ||
			    nfqnl_put_master_ifindex(skb, NFQA_IFINDEX_OUTDEV, outdev))
				goto nla_put_failure;
		} else {
			int physoutif;

			/* Case 2: outdev is bridge group, we need to look for
			 * physical output device (when called from ipv4) */
			if (nla_put_be32(skb, NFQA_IFINDEX_OUTDEV,
					 htonl(outdev->ifindex)))
				goto nla_put_failure;

			physoutif = nf_bridge_get_physoutif(entskb);
			if (physoutif &&
			    nla_put_be32(skb, NFQA_IFINDEX_PHYSOUTDEV,
					 htonl(physoutif)))
				goto nla_put_failure;
		}
#endif
	}

	if (entskb->mark &&
	    nla_put_be32(skb, NFQA_MARK, htonl(entskb->mark)))
		goto nla_put_failure;

	if (entskb->priority &&
	    nla_put_be32(skb, NFQA_PRIORITY, htonl(entskb->priority)))
		goto nla_put_failure;

	if (indev && entskb->dev &&
	    skb_mac_header_was_set(entskb) &&
	    skb_mac_header_len(entskb) != 0) {
		struct nfqnl_msg_packet_hw phw;
		int len;

		memset(&phw, 0, sizeof(phw));
		len = dev_parse_header(entskb, phw.hw_addr);
		if (len) {
			phw.hw_addrlen = htons(len);
			if (nla_put(skb, NFQA_HWADDR, sizeof(phw), &phw))
				goto nla_put_failure;
		}
	}

	if (nfqnl_put_bridge(entry, skb) < 0)
		goto nla_put_failure;

	if (entry->state.hook <= NF_INET_FORWARD && tstamp) {
		struct nfqnl_msg_packet_timestamp ts;
		struct timespec64 kts = ktime_to_timespec64(tstamp);

		ts.sec = cpu_to_be64(kts.tv_sec);
		ts.usec = cpu_to_be64(kts.tv_nsec / NSEC_PER_USEC);

		if (nla_put(skb, NFQA_TIMESTAMP, sizeof(ts), &ts))
			goto nla_put_failure;
	}

	if ((queue->flags & NFQA_CFG_F_UID_GID) && entskb->sk &&
	    nfqnl_put_sk_uidgid(skb, entskb->sk) < 0)
		goto nla_put_failure;

	if (nfqnl_put_sk_classid(skb, entskb->sk) < 0)
		goto nla_put_failure;

	if (seclen && nla_put(skb, NFQA_SECCTX, seclen, secdata))
		goto nla_put_failure;

	if (ct && nfnl_ct->build(skb, ct, ctinfo, NFQA_CT, NFQA_CT_INFO) < 0)
		goto nla_put_failure;

	if (cap_len > data_len &&
	    nla_put_be32(skb, NFQA_CAP_LEN, htonl(cap_len)))
		goto nla_put_failure;

	if (nfqnl_put_packet_info(skb, entskb, csum_verify))
		goto nla_put_failure;

	if (data_len) {
		struct nlattr *nla;

		if (skb_tailroom(skb) < sizeof(*nla) + hlen)
			goto nla_put_failure;

		nla = skb_put(skb, sizeof(*nla));
		nla->nla_type = NFQA_PAYLOAD;
		nla->nla_len = nla_attr_size(data_len);

		if (skb_zerocopy(skb, entskb, data_len, hlen))
			goto nla_put_failure;
	}

	nlh->nlmsg_len = skb->len;
	if (seclen)
		security_release_secctx(secdata, seclen);
	return skb;

nla_put_failure:
	skb_tx_error(entskb);
	kfree_skb(skb);
	net_err_ratelimited("nf_queue: error creating packet message\n");
nlmsg_failure:
	if (seclen)
		security_release_secctx(secdata, seclen);
	return NULL;
}

static bool nf_ct_drop_unconfirmed(const struct nf_queue_entry *entry)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	static const unsigned long flags = IPS_CONFIRMED | IPS_DYING;
	const struct nf_conn *ct = (void *)skb_nfct(entry->skb);

	if (ct && ((ct->status & flags) == IPS_DYING))
		return true;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return false;
}

extern int
klpp___nfqnl_enqueue_packet(struct net *net, struct nfqnl_instance *queue,
			struct nf_queue_entry *entry)
{
	struct sk_buff *nskb;
	int err = -ENOBUFS;
	__be32 *packet_id_ptr;
	int failopen = 0;

	nskb = nfqnl_build_packet_message(net, queue, entry, &packet_id_ptr);
	if (nskb == NULL) {
		err = -ENOMEM;
		goto err_out;
	}
	spin_lock_bh(&queue->lock);

	if (nf_ct_drop_unconfirmed(entry))
		goto err_out_free_nskb;

	if (queue->queue_total >= queue->queue_maxlen) {
		if (queue->flags & NFQA_CFG_F_FAIL_OPEN) {
			failopen = 1;
			err = 0;
		} else {
			queue->queue_dropped++;
			net_warn_ratelimited("nf_queue: full at %d entries, dropping packets(s)\n",
					     queue->queue_total);
		}
		goto err_out_free_nskb;
	}
	entry->id = ++queue->id_sequence;
	*packet_id_ptr = htonl(entry->id);

	/* nfnetlink_unicast will either free the nskb or add it to a socket */
	err = nfnetlink_unicast(nskb, net, queue->peer_portid);
	if (err < 0) {
		if (queue->flags & NFQA_CFG_F_FAIL_OPEN) {
			failopen = 1;
			err = 0;
		} else {
			queue->queue_user_dropped++;
		}
		goto err_out_unlock;
	}

	__enqueue_entry(queue, entry);

	spin_unlock_bh(&queue->lock);
	return 0;

err_out_free_nskb:
	kfree_skb(nskb);
err_out_unlock:
	spin_unlock_bh(&queue->lock);
	if (failopen)
		nfqnl_reinject(entry, NF_ACCEPT);
err_out:
	return err;
}


#include <linux/livepatch.h>

extern typeof(nfnetlink_unicast) nfnetlink_unicast
	 KLP_RELOC_SYMBOL(nfnetlink_queue, nfnetlink, nfnetlink_unicast);
extern typeof(nfqnl_reinject) nfqnl_reinject
	 KLP_RELOC_SYMBOL(nfnetlink_queue, nfnetlink_queue, nfqnl_reinject);
