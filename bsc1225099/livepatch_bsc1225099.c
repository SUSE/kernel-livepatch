/*
 * livepatch_bsc1225099
 *
 * Fix for CVE-2023-52846, bsc#1225099
 *
 *  Upstream commit:
 *  876f8ab52363 ("hsr: Prevent use after free in prp_create_tagged_frame()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  74c7662a961ccba6dac0505059ed7f0dc25e453a
 *
 *  SLE15-SP6 commit:
 *  cf63988c516f2ec586a9997415dd21876467150b
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from net/hsr/hsr_forward.h */
#include <linux/netdevice.h>
/* klp-ccp: from net/hsr/hsr_main.h */
#include <linux/netdevice.h>
#include <linux/list.h>

/* klp-ccp: from include/linux/if_vlan.h */
#define _LINUX_IF_VLAN_H_

/* klp-ccp: from include/linux/etherdevice.h */
#define _LINUX_ETHERDEVICE_H

/* klp-ccp: from include/linux/if_vlan.h */
#define VLAN_ETH_ZLEN	64		/* Min. octets in frame sans FCS */

/* klp-ccp: from net/hsr/hsr_main.h */
#include <linux/if_hsr.h>

enum hsr_port_type {
	HSR_PT_NONE = 0,	/* Must be 0, used by framereg */
	HSR_PT_SLAVE_A,
	HSR_PT_SLAVE_B,
	HSR_PT_INTERLINK,
	HSR_PT_MASTER,
	HSR_PT_PORTS,	/* This must be the last item in the enum */
};

struct prp_rct {
	__be16          sequence_nr;
	__be16          lan_id_and_LSDU_size;
	__be16          PRP_suffix;
} __packed;

static inline void set_prp_lan_id(struct prp_rct *rct, u16 lan_id)
{
	rct->lan_id_and_LSDU_size = htons((ntohs(rct->lan_id_and_LSDU_size) &
					  0x0FFF) | (lan_id << 12));
}
static inline void set_prp_LSDU_size(struct prp_rct *rct, u16 LSDU_size)
{
	rct->lan_id_and_LSDU_size = htons((ntohs(rct->lan_id_and_LSDU_size) &
					  0xF000) | (LSDU_size & 0x0FFF));
}

struct hsr_port {
	struct list_head	port_list;
	struct net_device	*dev;
	struct hsr_priv		*hsr;
	enum hsr_port_type	type;
};

struct hsr_frame_info;

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

static inline struct prp_rct *skb_get_PRP_rct(struct sk_buff *skb)
{
	unsigned char *tail = skb_tail_pointer(skb) - HSR_HLEN;

	struct prp_rct *rct = (struct prp_rct *)tail;

	if (rct->PRP_suffix == htons(ETH_P_PRP))
		return rct;

	return NULL;
}

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

/* klp-ccp: from net/hsr/hsr_forward.c */
static void prp_set_lan_id(struct prp_rct *trailer,
			   struct hsr_port *port)
{
	int lane_id;

	if (port->type == HSR_PT_SLAVE_A)
		lane_id = 0;
	else
		lane_id = 1;

	/* Add net_id in the upper 3 bits of lane_id */
	lane_id |= port->hsr->net_id;
	set_prp_lan_id(trailer, lane_id);
}

static struct sk_buff *prp_fill_rct(struct sk_buff *skb,
				    struct hsr_frame_info *frame,
				    struct hsr_port *port)
{
	struct prp_rct *trailer;
	int min_size = ETH_ZLEN;
	int lsdu_size;

	if (!skb)
		return skb;

	if (frame->is_vlan)
		min_size = VLAN_ETH_ZLEN;

	if (skb_put_padto(skb, min_size))
		return NULL;

	trailer = (struct prp_rct *)skb_put(skb, HSR_HLEN);
	lsdu_size = skb->len - 14;
	if (frame->is_vlan)
		lsdu_size -= 4;
	prp_set_lan_id(trailer, port);
	set_prp_LSDU_size(trailer, lsdu_size);
	trailer->sequence_nr = htons(frame->sequence_nr);
	trailer->PRP_suffix = htons(ETH_P_PRP);
	skb->protocol = eth_hdr(skb)->h_proto;

	return skb;
}

struct sk_buff *klpp_prp_create_tagged_frame(struct hsr_frame_info *frame,
					     struct hsr_port *port)
{
	struct sk_buff *skb;

	if (frame->skb_prp) {
		struct prp_rct *trailer = skb_get_PRP_rct(frame->skb_prp);

		if (trailer) {
			prp_set_lan_id(trailer, port);
		} else {
			WARN_ONCE(!trailer, "errored PRP skb");
			return NULL;
		}
		return skb_clone(frame->skb_prp, GFP_ATOMIC);
	} else if (port->dev->features & NETIF_F_HW_HSR_TAG_INS) {
		return skb_clone(frame->skb_std, GFP_ATOMIC);
	}

	skb = skb_copy_expand(frame->skb_std, 0,
			      skb_tailroom(frame->skb_std) + HSR_HLEN,
			      GFP_ATOMIC);
	return prp_fill_rct(skb, frame, port);
}

#include "livepatch_bsc1225099.h"
