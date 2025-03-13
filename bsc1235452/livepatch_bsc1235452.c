/*
 * livepatch_bsc1235452
 *
 * Fix for CVE-2024-56648, bsc#1235452
 *
 *  Upstream commit:
 *  b9653d19e556 ("net: hsr: avoid potential out-of-bound access in fill_frame_info()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  0a88cb04926b38ae64ede55697d0a1e0363acccf
 *
 *  SLE15-SP6 commit:
 *  79ce319c7bdfcd556009968e2946f9088669fd83
 *
 *  SLE MICRO-6-0 commit:
 *  79ce319c7bdfcd556009968e2946f9088669fd83
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

/* klp-ccp: from net/hsr/hsr_forward.h */
#include <linux/netdevice.h>
/* klp-ccp: from net/hsr/hsr_main.h */
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/if_vlan.h>
#include <linux/if_hsr.h>

#define HSR_TLV_EOT				   0  /* End of TLVs */
#define HSR_TLV_ANNOUNCE		   22
#define HSR_TLV_LIFE_CHECK		   23

#define PRP_TLV_LIFE_CHECK_DD		   20

#define PRP_TLV_LIFE_CHECK_DA		   21

#define PRP_TLV_REDBOX_MAC		   30

struct hsr_vlan_ethhdr {
	struct vlan_ethhdr vlanhdr;
	struct hsr_tag	hsr_tag;
} __packed;

struct hsr_sup_tlv {
	u8		HSR_TLV_type;
	u8		HSR_TLV_length;
} __packed;

struct hsr_sup_tag {
	__be16				path_and_HSR_ver;
	__be16				sequence_nr;
	struct hsr_sup_tlv  tlv;
} __packed;

struct hsr_sup_payload {
	unsigned char	macaddress_A[ETH_ALEN];
} __packed;

struct hsrv0_ethhdr_sp {
	struct ethhdr		ethhdr;
	struct hsr_sup_tag	hsr_sup;
} __packed;

struct hsrv1_ethhdr_sp {
	struct ethhdr		ethhdr;
	struct hsr_tag		hsr;
	struct hsr_sup_tag	hsr_sup;
} __packed;

enum hsr_port_type {
	HSR_PT_NONE = 0,	/* Must be 0, used by framereg */
	HSR_PT_SLAVE_A,
	HSR_PT_SLAVE_B,
	HSR_PT_INTERLINK,
	HSR_PT_MASTER,
	HSR_PT_PORTS,	/* This must be the last item in the enum */
};

struct hsr_port {
	struct list_head	port_list;
	struct net_device	*dev;
	struct hsr_priv		*hsr;
	enum hsr_port_type	type;
};

struct hsr_frame_info;
struct hsr_node;

struct hsr_proto_ops {
	/* format and send supervision frame */
	void (*send_sv_frame)(struct hsr_port *port, unsigned long *interval);
	void (*handle_san_frame)(bool san, enum hsr_port_type port,
				 struct hsr_node *node);
	bool (*drop_frame)(struct hsr_frame_info *frame, struct hsr_port *port);
	struct sk_buff * (*get_untagged_frame)(struct hsr_frame_info *frame,
					       struct hsr_port *port);
	struct sk_buff * (*create_tagged_frame)(struct hsr_frame_info *frame,
						struct hsr_port *port);
	int (*fill_frame_info)(__be16 proto, struct sk_buff *skb,
			       struct hsr_frame_info *frame);
	bool (*invalid_dan_ingress_frame)(__be16 protocol);
	void (*update_san_info)(struct hsr_node *node, bool is_sup);
};

struct hsr_priv {
	struct rcu_head		rcu_head;
	struct list_head	ports;
	struct list_head	node_db;	/* Known HSR nodes */
	struct hsr_self_node	__rcu *self_node;	/* MACs of slaves */
	struct timer_list	announce_timer;	/* Supervision frame dispatch */
	struct timer_list	prune_timer;
	int announce_count;
	u16 sequence_nr;
	u16 sup_sequence_nr;	/* For HSRv1 separate seq_nr for supervision */
	enum hsr_version prot_version;	/* Indicate if HSRv0, HSRv1 or PRPv1 */
	spinlock_t seqnr_lock;	/* locking for sequence_nr */
	spinlock_t list_lock;	/* locking for node list */
	struct hsr_proto_ops	*proto_ops;
	u8 net_id;		/* for PRP, it occupies most significant 3 bits
				 * of lan_id
				 */
	unsigned char		sup_multicast_addr[ETH_ALEN] __aligned(sizeof(u16));

#ifdef	CONFIG_DEBUG_FS
	struct dentry *node_tbl_root;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

#define hsr_for_each_port(hsr, port) \
	list_for_each_entry_rcu((port), &(hsr)->ports, port_list)

/* klp-ccp: from net/hsr/hsr_forward.c */
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>

/* klp-ccp: from net/hsr/hsr_framereg.h */
struct hsr_frame_info {
	struct sk_buff *skb_std;
	struct sk_buff *skb_hsr;
	struct sk_buff *skb_prp;
	struct hsr_port *port_rcv;
	struct hsr_node *node_src;
	u16 sequence_nr;
	bool is_supervision;
	bool is_vlan;
	bool is_local_dest;
	bool is_local_exclusive;
	bool is_from_san;
};

struct hsr_node *hsr_get_node(struct hsr_port *port, struct list_head *node_db,
			      struct sk_buff *skb, bool is_sup,
			      enum hsr_port_type rx_port);
void hsr_handle_sup_frame(struct hsr_frame_info *frame);
bool hsr_addr_is_self(struct hsr_priv *hsr, unsigned char *addr);

void hsr_addr_subst_source(struct hsr_node *node, struct sk_buff *skb);
void hsr_addr_subst_dest(struct hsr_node *node_src, struct sk_buff *skb,
			 struct hsr_port *port);

void hsr_register_frame_in(struct hsr_node *node, struct hsr_port *port,
			   u16 sequence_nr);
int hsr_register_frame_out(struct hsr_port *port, struct hsr_node *node,
			   u16 sequence_nr);

/* klp-ccp: from net/hsr/hsr_forward.c */
static bool is_supervision_frame(struct hsr_priv *hsr, struct sk_buff *skb)
{
	struct ethhdr *eth_hdr;
	struct hsr_sup_tag *hsr_sup_tag;
	struct hsrv1_ethhdr_sp *hsr_V1_hdr;
	struct hsr_sup_tlv *hsr_sup_tlv;
	u16 total_length = 0;

	WARN_ON_ONCE(!skb_mac_header_was_set(skb));
	eth_hdr = (struct ethhdr *)skb_mac_header(skb);

	/* Correct addr? */
	if (!ether_addr_equal(eth_hdr->h_dest,
			      hsr->sup_multicast_addr))
		return false;

	/* Correct ether type?. */
	if (!(eth_hdr->h_proto == htons(ETH_P_PRP) ||
	      eth_hdr->h_proto == htons(ETH_P_HSR)))
		return false;

	/* Get the supervision header from correct location. */
	if (eth_hdr->h_proto == htons(ETH_P_HSR)) { /* Okay HSRv1. */
		total_length = sizeof(struct hsrv1_ethhdr_sp);
		if (!pskb_may_pull(skb, total_length))
			return false;

		hsr_V1_hdr = (struct hsrv1_ethhdr_sp *)skb_mac_header(skb);
		if (hsr_V1_hdr->hsr.encap_proto != htons(ETH_P_PRP))
			return false;

		hsr_sup_tag = &hsr_V1_hdr->hsr_sup;
	} else {
		total_length = sizeof(struct hsrv0_ethhdr_sp);
		if (!pskb_may_pull(skb, total_length))
			return false;

		hsr_sup_tag =
		     &((struct hsrv0_ethhdr_sp *)skb_mac_header(skb))->hsr_sup;
	}

	if (hsr_sup_tag->tlv.HSR_TLV_type != HSR_TLV_ANNOUNCE &&
	    hsr_sup_tag->tlv.HSR_TLV_type != HSR_TLV_LIFE_CHECK &&
	    hsr_sup_tag->tlv.HSR_TLV_type != PRP_TLV_LIFE_CHECK_DD &&
	    hsr_sup_tag->tlv.HSR_TLV_type != PRP_TLV_LIFE_CHECK_DA)
		return false;
	if (hsr_sup_tag->tlv.HSR_TLV_length != 12 &&
	    hsr_sup_tag->tlv.HSR_TLV_length != sizeof(struct hsr_sup_payload))
		return false;

	/* Get next tlv */
	total_length += sizeof(struct hsr_sup_tlv) + hsr_sup_tag->tlv.HSR_TLV_length;
	if (!pskb_may_pull(skb, total_length))
		return false;
	skb_pull(skb, total_length);
	hsr_sup_tlv = (struct hsr_sup_tlv *)skb->data;
	skb_push(skb, total_length);

	/* if this is a redbox supervision frame we need to verify
	 * that more data is available
	 */
	if (hsr_sup_tlv->HSR_TLV_type == PRP_TLV_REDBOX_MAC) {
		/* tlv length must be a length of a mac address */
		if (hsr_sup_tlv->HSR_TLV_length != sizeof(struct hsr_sup_payload))
			return false;

		/* make sure another tlv follows */
		total_length += sizeof(struct hsr_sup_tlv) + hsr_sup_tlv->HSR_TLV_length;
		if (!pskb_may_pull(skb, total_length))
			return false;

		/* get next tlv */
		skb_pull(skb, total_length);
		hsr_sup_tlv = (struct hsr_sup_tlv *)skb->data;
		skb_push(skb, total_length);
	}

	/* end of tlvs must follow at the end */
	if (hsr_sup_tlv->HSR_TLV_type == HSR_TLV_EOT &&
	    hsr_sup_tlv->HSR_TLV_length != 0)
		return false;

	return true;
}

static void hsr_deliver_master(struct sk_buff *skb, struct net_device *dev,
			       struct hsr_node *node_src)
{
	bool was_multicast_frame;
	int res, recv_len;

	was_multicast_frame = (skb->pkt_type == PACKET_MULTICAST);
	hsr_addr_subst_source(node_src, skb);
	skb_pull(skb, ETH_HLEN);
	recv_len = skb->len;
	res = netif_rx(skb);
	if (res == NET_RX_DROP) {
		dev->stats.rx_dropped++;
	} else {
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += recv_len;
		if (was_multicast_frame)
			dev->stats.multicast++;
	}
}

static int hsr_xmit(struct sk_buff *skb, struct hsr_port *port,
		    struct hsr_frame_info *frame)
{
	if (frame->port_rcv->type == HSR_PT_MASTER) {
		hsr_addr_subst_dest(frame->node_src, skb, port);

		/* Address substitution (IEC62439-3 pp 26, 50): replace mac
		 * address of outgoing frame with that of the outgoing slave's.
		 */
		ether_addr_copy(eth_hdr(skb)->h_source, port->dev->dev_addr);
	}
	return dev_queue_xmit(skb);
}

static void hsr_forward_do(struct hsr_frame_info *frame)
{
	struct hsr_port *port;
	struct sk_buff *skb;
	bool sent = false;

	hsr_for_each_port(frame->port_rcv->hsr, port) {
		struct hsr_priv *hsr = port->hsr;
		/* Don't send frame back the way it came */
		if (port == frame->port_rcv)
			continue;

		/* Don't deliver locally unless we should */
		if (port->type == HSR_PT_MASTER && !frame->is_local_dest)
			continue;

		/* Deliver frames directly addressed to us to master only */
		if (port->type != HSR_PT_MASTER && frame->is_local_exclusive)
			continue;

		/* If hardware duplicate generation is enabled, only send out
		 * one port.
		 */
		if ((port->dev->features & NETIF_F_HW_HSR_DUP) && sent)
			continue;

		/* Don't send frame over port where it has been sent before.
		 * Also fro SAN, this shouldn't be done.
		 */
		if (!frame->is_from_san &&
		    hsr_register_frame_out(port, frame->node_src,
					   frame->sequence_nr))
			continue;

		if (frame->is_supervision && port->type == HSR_PT_MASTER) {
			hsr_handle_sup_frame(frame);
			continue;
		}

		/* Check if frame is to be dropped. Eg. for PRP no forward
		 * between ports.
		 */
		if (hsr->proto_ops->drop_frame &&
		    hsr->proto_ops->drop_frame(frame, port))
			continue;

		if (port->type != HSR_PT_MASTER)
			skb = hsr->proto_ops->create_tagged_frame(frame, port);
		else
			skb = hsr->proto_ops->get_untagged_frame(frame, port);

		if (!skb) {
			frame->port_rcv->dev->stats.rx_dropped++;
			continue;
		}

		skb->dev = port->dev;
		if (port->type == HSR_PT_MASTER) {
			hsr_deliver_master(skb, port->dev, frame->node_src);
		} else {
			if (!hsr_xmit(skb, port, frame))
				sent = true;
		}
	}
}

static void check_local_dest(struct hsr_priv *hsr, struct sk_buff *skb,
			     struct hsr_frame_info *frame)
{
	if (hsr_addr_is_self(hsr, eth_hdr(skb)->h_dest)) {
		frame->is_local_exclusive = true;
		skb->pkt_type = PACKET_HOST;
	} else {
		frame->is_local_exclusive = false;
	}

	if (skb->pkt_type == PACKET_HOST ||
	    skb->pkt_type == PACKET_MULTICAST ||
	    skb->pkt_type == PACKET_BROADCAST) {
		frame->is_local_dest = true;
	} else {
		frame->is_local_dest = false;
	}
}

static int fill_frame_info(struct hsr_frame_info *frame,
			   struct sk_buff *skb, struct hsr_port *port)
{
	struct hsr_priv *hsr = port->hsr;
	struct hsr_vlan_ethhdr *vlan_hdr;
	struct ethhdr *ethhdr;
	__be16 proto;
	int ret;

	/* Check if skb contains ethhdr */
	if (skb->mac_len < sizeof(struct ethhdr))
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));
	frame->is_supervision = is_supervision_frame(port->hsr, skb);
	frame->node_src = hsr_get_node(port, &hsr->node_db, skb,
				       frame->is_supervision,
				       port->type);
	if (!frame->node_src)
		return -1; /* Unknown node and !is_supervision, or no mem */

	ethhdr = (struct ethhdr *)skb_mac_header(skb);
	frame->is_vlan = false;
	proto = ethhdr->h_proto;

	if (proto == htons(ETH_P_8021Q))
		frame->is_vlan = true;

	if (frame->is_vlan) {
		if (skb->mac_len < offsetofend(struct hsr_vlan_ethhdr, vlanhdr))
			return -EINVAL;
		vlan_hdr = (struct hsr_vlan_ethhdr *)ethhdr;
		proto = vlan_hdr->vlanhdr.h_vlan_encapsulated_proto;
		/* FIXME: */
		netdev_warn_once(skb->dev, "VLAN not yet supported");
		return -EINVAL;
	}

	frame->is_from_san = false;
	frame->port_rcv = port;
	ret = hsr->proto_ops->fill_frame_info(proto, skb, frame);
	if (ret)
		return ret;

	check_local_dest(port->hsr, skb, frame);

	return 0;
}

void klpp_hsr_forward_skb(struct sk_buff *skb, struct hsr_port *port)
{
	struct hsr_frame_info frame;

	rcu_read_lock();
	if (fill_frame_info(&frame, skb, port) < 0)
		goto out_drop;

	hsr_register_frame_in(frame.node_src, port, frame.sequence_nr);
	hsr_forward_do(&frame);
	rcu_read_unlock();
	/* Gets called for ingress frames as well as egress from master port.
	 * So check and increment stats for master port only here.
	 */
	if (port->type == HSR_PT_MASTER) {
		port->dev->stats.tx_packets++;
		port->dev->stats.tx_bytes += skb->len;
	}

	kfree_skb(frame.skb_hsr);
	kfree_skb(frame.skb_prp);
	kfree_skb(frame.skb_std);
	return;

out_drop:
	rcu_read_unlock();
	port->dev->stats.tx_dropped++;
	kfree_skb(skb);
}


#include "livepatch_bsc1235452.h"

#include <linux/livepatch.h>

extern typeof(hsr_addr_is_self) hsr_addr_is_self
	 KLP_RELOC_SYMBOL(hsr, hsr, hsr_addr_is_self);
extern typeof(hsr_addr_subst_dest) hsr_addr_subst_dest
	 KLP_RELOC_SYMBOL(hsr, hsr, hsr_addr_subst_dest);
extern typeof(hsr_addr_subst_source) hsr_addr_subst_source
	 KLP_RELOC_SYMBOL(hsr, hsr, hsr_addr_subst_source);
extern typeof(hsr_get_node) hsr_get_node
	 KLP_RELOC_SYMBOL(hsr, hsr, hsr_get_node);
extern typeof(hsr_handle_sup_frame) hsr_handle_sup_frame
	 KLP_RELOC_SYMBOL(hsr, hsr, hsr_handle_sup_frame);
extern typeof(hsr_register_frame_in) hsr_register_frame_in
	 KLP_RELOC_SYMBOL(hsr, hsr, hsr_register_frame_in);
extern typeof(hsr_register_frame_out) hsr_register_frame_out
	 KLP_RELOC_SYMBOL(hsr, hsr, hsr_register_frame_out);
