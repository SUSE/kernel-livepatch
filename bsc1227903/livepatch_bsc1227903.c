/*
 * livepatch_bsc1227903
 *
 * Fix for CVE-2024-40937, bsc#1227903
 *
 *  Upstream commit:
 *  6f4d93b78ade ("gve: Clear napi->skb before dev_kfree_skb_any()")
 *
 *  SLE12-SP5 commit:
 *  753a87a0191ad6a20b35d4da39974ef3f1b8748a
 *
 *  SLE15-SP3 commit:
 *  2df93fe62309d02c6daeafc12097f67ed12ef91e
 *
 *  SLE15-SP4 and -SP5 commit:
 *  610d4692cedf01de0de5e1a9d0a2c07045956e8b
 *
 *  SLE15-SP6 commit:
 *  8d4dcfb7d31502d023080d8af2bd025a373a4418
 *
 *  SLE MICRO-6-0 commit:
 *  8d4dcfb7d31502d023080d8af2bd025a373a4418
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.com>
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

#if IS_ENABLED(CONFIG_GVE)

#if !IS_MODULE(CONFIG_GVE)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/ethernet/google/gve/gve.h */
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/u64_stats_sync.h>

/* klp-ccp: from drivers/net/ethernet/google/gve/gve_desc.h */
#include <linux/build_bug.h>

/* klp-ccp: from drivers/net/ethernet/google/gve/gve_desc_dqo.h */
#include <linux/build_bug.h>

struct gve_rx_compl_desc_dqo {
	/* Must be 1 */
	u8 rxdid: 4;
	u8 reserved0: 4;

	/* Packet originated from this system rather than the network. */
	u8 loopback: 1;
	/* Set when IPv6 packet contains a destination options header or routing
	 * header.
	 */
	u8 ipv6_ex_add: 1;
	/* Invalid packet was received. */
	u8 rx_error: 1;
	u8 reserved1: 5;

	u16 packet_type: 10;
	u16 ip_hdr_err: 1;
	u16 udp_len_err: 1;
	u16 raw_cs_invalid: 1;
	u16 reserved2: 3;

	u16 packet_len: 14;
	/* Flipped by HW to notify the descriptor is populated. */
	u16 generation: 1;
	/* Should be zero. */
	u16 buffer_queue_id: 1;

	u16 header_len: 10;
	u16 rsc: 1;
	u16 split_header: 1;
	u16 reserved3: 4;

	u8 descriptor_done: 1;
	u8 end_of_packet: 1;
	u8 header_buffer_overflow: 1;
	u8 l3_l4_processed: 1;
	u8 csum_ip_err: 1;
	u8 csum_l4_err: 1;
	u8 csum_external_ip_err: 1;
	u8 csum_external_udp_err: 1;

	u8 status_error1;

	__le16 reserved5;
	__le16 buf_id; /* Buffer ID which was sent on the buffer queue. */

	union {
		/* Packet checksum. */
		__le16 raw_cs;
		/* Segment length for RSC packets. */
		__le16 rsc_seg_len;
	};
	__le32 hash;
	__le32 reserved6;
	__le64 reserved7;
} __packed;

/* klp-ccp: from drivers/net/ethernet/google/gve/gve.h */
#define GVE_NUM_PTYPES	1024

#define GVE_XDP_ACTIONS 5

#define GVE_DQO_QPL_ONDEMAND_ALLOC_THRESHOLD 96

struct gve_rx_desc_queue {
	struct gve_rx_desc *desc_ring; /* the descriptor ring */
	dma_addr_t bus; /* the bus for the desc_ring */
	u8 seqno; /* the next expected seqno for this desc*/
};

struct gve_rx_slot_page_info {
	struct page *page;
	void *page_address;
	u32 page_offset; /* offset to write to in page */
	int pagecnt_bias; /* expected pagecnt if only the driver has a ref */
	u16 pad; /* adjustment for rx padding */
	u8 can_flip; /* tracks if the networking stack is using the page */
};

struct gve_rx_data_queue {
	union gve_rx_data_slot *data_ring; /* read by NIC */
	dma_addr_t data_bus; /* dma mapping of the slots */
	struct gve_rx_slot_page_info *page_info; /* page info of the buffers */
	struct gve_queue_page_list *qpl; /* qpl assigned to this queue */
	u8 raw_addressing; /* use raw_addressing? */
};

struct gve_rx_buf_queue_dqo {
	struct gve_rx_desc_dqo *desc_ring;
	dma_addr_t bus;
	u32 head; /* Pointer to start cleaning buffers at. */
	u32 tail; /* Last posted buffer index + 1 */
	u32 mask; /* Mask for indices to the size of the ring */
};

struct gve_rx_compl_queue_dqo {
	struct gve_rx_compl_desc_dqo *desc_ring;
	dma_addr_t bus;

	/* Number of slots which did not have a buffer posted yet. We should not
	 * post more buffers than the queue size to avoid HW overrunning the
	 * queue.
	 */
	int num_free_slots;

	/* HW uses a "generation bit" to notify SW of new descriptors. When a
	 * descriptor's generation bit is different from the current generation,
	 * that descriptor is ready to be consumed by SW.
	 */
	u8 cur_gen_bit;

	/* Pointer into desc_ring where the next completion descriptor will be
	 * received.
	 */
	u32 head;
	u32 mask; /* Mask for indices to the size of the ring */
};

struct gve_rx_buf_state_dqo {
	/* The page posted to HW. */
	struct gve_rx_slot_page_info page_info;

	/* The DMA address corresponding to `page_info`. */
	dma_addr_t addr;

	/* Last offset into the page when it only had a single reference, at
	 * which point every other offset is free to be reused.
	 */
	u32 last_single_ref_offset;

	/* Linked list index to next element in the list, or -1 if none */
	s16 next;
};

struct gve_index_list {
	s16 head;
	s16 tail;
};

struct gve_rx_ctx {
	/* head and tail of skb chain for the current packet or NULL if none */
	struct sk_buff *skb_head;
	struct sk_buff *skb_tail;
	u32 total_size;
	u8 frag_cnt;
	bool drop_pkt;
};

struct gve_rx_ring {
	struct gve_priv *gve;
	union {
		/* GQI fields */
		struct {
			struct gve_rx_desc_queue desc;
			struct gve_rx_data_queue data;

			/* threshold for posting new buffs and descs */
			u32 db_threshold;
			u16 packet_buffer_size;

			u32 qpl_copy_pool_mask;
			u32 qpl_copy_pool_head;
			struct gve_rx_slot_page_info *qpl_copy_pool;
		};

		/* DQO fields. */
		struct {
			struct gve_rx_buf_queue_dqo bufq;
			struct gve_rx_compl_queue_dqo complq;

			struct gve_rx_buf_state_dqo *buf_states;
			u16 num_buf_states;

			/* Linked list of gve_rx_buf_state_dqo. Index into
			 * buf_states, or -1 if empty.
			 */
			s16 free_buf_states;

			/* Linked list of gve_rx_buf_state_dqo. Indexes into
			 * buf_states, or -1 if empty.
			 *
			 * This list contains buf_states which are pointing to
			 * valid buffers.
			 *
			 * We use a FIFO here in order to increase the
			 * probability that buffers can be reused by increasing
			 * the time between usages.
			 */
			struct gve_index_list recycled_buf_states;

			/* Linked list of gve_rx_buf_state_dqo. Indexes into
			 * buf_states, or -1 if empty.
			 *
			 * This list contains buf_states which have buffers
			 * which cannot be reused yet.
			 */
			struct gve_index_list used_buf_states;

			/* qpl assigned to this queue */
			struct gve_queue_page_list *qpl;

			/* index into queue page list */
			u32 next_qpl_page_idx;

			/* track number of used buffers */
			u16 used_buf_states_cnt;
		} dqo;
	};

	u64 rbytes; /* free-running bytes received */
	u64 rpackets; /* free-running packets received */
	u32 cnt; /* free-running total number of completed packets */
	u32 fill_cnt; /* free-running total number of descs and buffs posted */
	u32 mask; /* masks the cnt and fill_cnt to the size of the ring */
	u64 rx_copybreak_pkt; /* free-running count of copybreak packets */
	u64 rx_copied_pkt; /* free-running total number of copied packets */
	u64 rx_skb_alloc_fail; /* free-running count of skb alloc fails */
	u64 rx_buf_alloc_fail; /* free-running count of buffer alloc fails */
	u64 rx_desc_err_dropped_pkt; /* free-running count of packets dropped by descriptor error */
	u64 rx_cont_packet_cnt; /* free-running multi-fragment packets received */
	u64 rx_frag_flip_cnt; /* free-running count of rx segments where page_flip was used */
	u64 rx_frag_copy_cnt; /* free-running count of rx segments copied */
	u64 rx_frag_alloc_cnt; /* free-running count of rx page allocations */
	u64 xdp_tx_errors;
	u64 xdp_redirect_errors;
	u64 xdp_alloc_fails;
	u64 xdp_actions[GVE_XDP_ACTIONS];
	u32 q_num; /* queue index */
	u32 ntfy_id; /* notification block index */
	struct gve_queue_resources *q_resources; /* head and tail pointer idx */
	dma_addr_t q_resources_bus; /* dma address for the queue resources */
	struct u64_stats_sync statss; /* sync stats for 32bit archs */

	struct gve_rx_ctx ctx; /* Info for packet currently being processed in this ring. */

	/* XDP stuff */
	struct xdp_rxq_info xdp_rxq;
	struct page_frag_cache page_cache; /* Page cache to allocate XDP frames */
};

struct gve_notify_block {
	__be32 *irq_db_index; /* pointer to idx into Bar2 */
	char name[IFNAMSIZ + 16]; /* name registered with the kernel */
	struct napi_struct napi; /* kernel napi struct for this block */
	struct gve_priv *priv;
	struct gve_tx_ring *tx; /* tx rings on this block */
	struct gve_rx_ring *rx; /* rx rings on this block */
};

struct gve_queue_config {
	u16 max_queues;
	u16 num_queues; /* current */
};

struct gve_qpl_config {
	u32 qpl_map_size; /* map memory size */
	unsigned long *qpl_id_map; /* bitmap of used qpl ids */
};

struct gve_options_dqo_rda {
	u16 tx_comp_ring_entries; /* number of tx_comp descriptors */
	u16 rx_buff_ring_entries; /* number of rx_buff descriptors */
};

struct gve_ptype {
	u8 l3_type;  /* `gve_l3_type` in gve_adminq.h */
	u8 l4_type;  /* `gve_l4_type` in gve_adminq.h */
};

struct gve_ptype_lut {
	struct gve_ptype ptypes[GVE_NUM_PTYPES];
};

enum gve_queue_format {
	GVE_QUEUE_FORMAT_UNSPECIFIED	= 0x0,
	GVE_GQI_RDA_FORMAT		= 0x1,
	GVE_GQI_QPL_FORMAT		= 0x2,
	GVE_DQO_RDA_FORMAT		= 0x3,
	GVE_DQO_QPL_FORMAT		= 0x4,
};

struct gve_priv {
	struct net_device *dev;
	struct gve_tx_ring *tx; /* array of tx_cfg.num_queues */
	struct gve_rx_ring *rx; /* array of rx_cfg.num_queues */
	struct gve_queue_page_list *qpls; /* array of num qpls */
	struct gve_notify_block *ntfy_blocks; /* array of num_ntfy_blks */
	struct gve_irq_db *irq_db_indices; /* array of num_ntfy_blks */
	dma_addr_t irq_db_indices_bus;
	struct msix_entry *msix_vectors; /* array of num_ntfy_blks + 1 */
	char mgmt_msix_name[IFNAMSIZ + 16];
	u32 mgmt_msix_idx;
	__be32 *counter_array; /* array of num_event_counters */
	dma_addr_t counter_array_bus;

	u16 num_event_counters;
	u16 tx_desc_cnt; /* num desc per ring */
	u16 rx_desc_cnt; /* num desc per ring */
	u16 tx_pages_per_qpl; /* Suggested number of pages per qpl for TX queues by NIC */
	u16 rx_pages_per_qpl; /* Suggested number of pages per qpl for RX queues by NIC */
	u16 rx_data_slot_cnt; /* rx buffer length */
	u64 max_registered_pages;
	u64 num_registered_pages; /* num pages registered with NIC */
	struct bpf_prog *xdp_prog; /* XDP BPF program */
	u32 rx_copybreak; /* copy packets smaller than this */
	u16 default_num_queues; /* default num queues to set up */

	u16 num_xdp_queues;
	struct gve_queue_config tx_cfg;
	struct gve_queue_config rx_cfg;
	struct gve_qpl_config qpl_cfg; /* map used QPL ids */
	u32 num_ntfy_blks; /* spilt between TX and RX so must be even */

	struct gve_registers __iomem *reg_bar0; /* see gve_register.h */
	__be32 __iomem *db_bar2; /* "array" of doorbells */
	u32 msg_enable;	/* level for netif* netdev print macros	*/
	struct pci_dev *pdev;

	/* metrics */
	u32 tx_timeo_cnt;

	/* Admin queue - see gve_adminq.h*/
	union gve_adminq_command *adminq;
	dma_addr_t adminq_bus_addr;
	u32 adminq_mask; /* masks prod_cnt to adminq size */
	u32 adminq_prod_cnt; /* free-running count of AQ cmds executed */
	u32 adminq_cmd_fail; /* free-running count of AQ cmds failed */
	u32 adminq_timeouts; /* free-running count of AQ cmds timeouts */
	/* free-running count of per AQ cmd executed */
	u32 adminq_describe_device_cnt;
	u32 adminq_cfg_device_resources_cnt;
	u32 adminq_register_page_list_cnt;
	u32 adminq_unregister_page_list_cnt;
	u32 adminq_create_tx_queue_cnt;
	u32 adminq_create_rx_queue_cnt;
	u32 adminq_destroy_tx_queue_cnt;
	u32 adminq_destroy_rx_queue_cnt;
	u32 adminq_dcfg_device_resources_cnt;
	u32 adminq_set_driver_parameter_cnt;
	u32 adminq_report_stats_cnt;
	u32 adminq_report_link_speed_cnt;
	u32 adminq_get_ptype_map_cnt;
	u32 adminq_verify_driver_compatibility_cnt;

	/* Global stats */
	u32 interface_up_cnt; /* count of times interface turned up since last reset */
	u32 interface_down_cnt; /* count of times interface turned down since last reset */
	u32 reset_cnt; /* count of reset */
	u32 page_alloc_fail; /* count of page alloc fails */
	u32 dma_mapping_error; /* count of dma mapping errors */
	u32 stats_report_trigger_cnt; /* count of device-requested stats-reports since last reset */
	u32 suspend_cnt; /* count of times suspended */
	u32 resume_cnt; /* count of times resumed */
	struct workqueue_struct *gve_wq;
	struct work_struct service_task;
	struct work_struct stats_report_task;
	unsigned long service_task_flags;
	unsigned long state_flags;

	struct gve_stats_report *stats_report;
	u64 stats_report_len;
	dma_addr_t stats_report_bus; /* dma address for the stats report */
	unsigned long ethtool_flags;

	unsigned long stats_report_timer_period;
	struct timer_list stats_report_timer;

	/* Gvnic device link speed from hypervisor. */
	u64 link_speed;
	bool up_before_suspend; /* True if dev was up before suspend */

	struct gve_options_dqo_rda options_dqo_rda;
	struct gve_ptype_lut *ptype_lut_dqo;

	/* Must be a power of two. */
	int data_buffer_size_dqo;

	enum gve_queue_format queue_format;
};

/* klp-ccp: from drivers/net/ethernet/google/gve/gve_adminq.h */
#include <linux/build_bug.h>

enum gve_l3_type {
	/* Must be zero so zero initialized LUT is unknown. */
	GVE_L3_TYPE_UNKNOWN = 0,
	GVE_L3_TYPE_OTHER,
	GVE_L3_TYPE_IPV4,
	GVE_L3_TYPE_IPV6,
};

enum gve_l4_type {
	/* Must be zero so zero initialized LUT is unknown. */
	GVE_L4_TYPE_UNKNOWN = 0,
	GVE_L4_TYPE_OTHER,
	GVE_L4_TYPE_TCP,
	GVE_L4_TYPE_UDP,
	GVE_L4_TYPE_ICMP,
	GVE_L4_TYPE_SCTP,
};

static void (*klpe_gve_rx_post_buffers_dqo)(struct gve_rx_ring *rx);

/* klp-ccp: from drivers/net/ethernet/google/gve/gve_utils.h */
static struct sk_buff *(*klpe_gve_rx_copy)(struct net_device *dev, struct napi_struct *napi,
			    struct gve_rx_slot_page_info *page_info, u16 len);

static void (*klpe_gve_dec_pagecnt_bias)(struct gve_rx_slot_page_info *page_info);

/* klp-ccp: from drivers/net/ethernet/google/gve/gve_rx_dqo.c */
#include <linux/skbuff.h>
#include <linux/slab.h>

/* klp-ccp: from include/net/ipv6.h */
#define _NET_IPV6_H

/* klp-ccp: from drivers/net/ethernet/google/gve/gve_rx_dqo.c */
#include <net/ipv6.h>

static int gve_buf_ref_cnt(struct gve_rx_buf_state_dqo *bs)
{
	return page_count(bs->page_info.page) - bs->page_info.pagecnt_bias;
}

static bool gve_buf_state_is_allocated(struct gve_rx_ring *rx,
				       struct gve_rx_buf_state_dqo *buf_state)
{
	s16 buffer_id = buf_state - rx->dqo.buf_states;

	return buf_state->next == buffer_id;
}

static void gve_enqueue_buf_state(struct gve_rx_ring *rx,
				  struct gve_index_list *list,
				  struct gve_rx_buf_state_dqo *buf_state)
{
	s16 buffer_id = buf_state - rx->dqo.buf_states;

	buf_state->next = -1;

	if (list->head == -1) {
		list->head = buffer_id;
		list->tail = buffer_id;
	} else {
		int tail = list->tail;

		rx->dqo.buf_states[tail].next = buffer_id;
		list->tail = buffer_id;
	}
}

static void gve_try_recycle_buf(struct gve_priv *priv, struct gve_rx_ring *rx,
				struct gve_rx_buf_state_dqo *buf_state)
{
	const int data_buffer_size = priv->data_buffer_size_dqo;
	int pagecount;

	/* Can't reuse if we only fit one buffer per page */
	if (data_buffer_size * 2 > PAGE_SIZE)
		goto mark_used;

	pagecount = gve_buf_ref_cnt(buf_state);

	/* Record the offset when we have a single remaining reference.
	 *
	 * When this happens, we know all of the other offsets of the page are
	 * usable.
	 */
	if (pagecount == 1) {
		buf_state->last_single_ref_offset =
			buf_state->page_info.page_offset;
	}

	/* Use the next buffer sized chunk in the page. */
	buf_state->page_info.page_offset += data_buffer_size;
	buf_state->page_info.page_offset &= (PAGE_SIZE - 1);

	/* If we wrap around to the same offset without ever dropping to 1
	 * reference, then we don't know if this offset was ever freed.
	 */
	if (buf_state->page_info.page_offset ==
	    buf_state->last_single_ref_offset) {
		goto mark_used;
	}

	gve_enqueue_buf_state(rx, &rx->dqo.recycled_buf_states, buf_state);
	return;

mark_used:
	gve_enqueue_buf_state(rx, &rx->dqo.used_buf_states, buf_state);
	rx->dqo.used_buf_states_cnt++;
}

static void gve_rx_skb_csum(struct sk_buff *skb,
			    const struct gve_rx_compl_desc_dqo *desc,
			    struct gve_ptype ptype)
{
	skb->ip_summed = CHECKSUM_NONE;

	/* HW did not identify and process L3 and L4 headers. */
	if (unlikely(!desc->l3_l4_processed))
		return;

	if (ptype.l3_type == GVE_L3_TYPE_IPV4) {
		if (unlikely(desc->csum_ip_err || desc->csum_external_ip_err))
			return;
	} else if (ptype.l3_type == GVE_L3_TYPE_IPV6) {
		/* Checksum should be skipped if this flag is set. */
		if (unlikely(desc->ipv6_ex_add))
			return;
	}

	if (unlikely(desc->csum_l4_err))
		return;

	switch (ptype.l4_type) {
	case GVE_L4_TYPE_TCP:
	case GVE_L4_TYPE_UDP:
	case GVE_L4_TYPE_ICMP:
	case GVE_L4_TYPE_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		break;
	}
}

static void gve_rx_skb_hash(struct sk_buff *skb,
			    const struct gve_rx_compl_desc_dqo *compl_desc,
			    struct gve_ptype ptype)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_L2;

	if (ptype.l4_type != GVE_L4_TYPE_UNKNOWN)
		hash_type = PKT_HASH_TYPE_L4;
	else if (ptype.l3_type != GVE_L3_TYPE_UNKNOWN)
		hash_type = PKT_HASH_TYPE_L3;

	skb_set_hash(skb, le32_to_cpu(compl_desc->hash), hash_type);
}

static void klpp_gve_rx_free_skb(struct napi_struct *napi, struct gve_rx_ring *rx)
{
	if (!rx->ctx.skb_head)
		return;

	if (rx->ctx.skb_head == napi->skb)
		napi->skb = NULL;
	dev_kfree_skb_any(rx->ctx.skb_head);
	rx->ctx.skb_head = NULL;
	rx->ctx.skb_tail = NULL;
}

static bool gve_rx_should_trigger_copy_ondemand(struct gve_rx_ring *rx)
{
	if (!rx->dqo.qpl)
		return false;
	if (rx->dqo.used_buf_states_cnt <
		     (rx->dqo.num_buf_states -
		     GVE_DQO_QPL_ONDEMAND_ALLOC_THRESHOLD))
		return false;
	return true;
}

static int (*klpe_gve_rx_copy_ondemand)(struct gve_rx_ring *rx,
				struct gve_rx_buf_state_dqo *buf_state,
				u16 buf_len);

static int klpr_gve_rx_append_frags(struct napi_struct *napi,
			       struct gve_rx_buf_state_dqo *buf_state,
			       u16 buf_len, struct gve_rx_ring *rx,
			       struct gve_priv *priv)
{
	int num_frags = skb_shinfo(rx->ctx.skb_tail)->nr_frags;

	if (unlikely(num_frags == MAX_SKB_FRAGS)) {
		struct sk_buff *skb;

		skb = napi_alloc_skb(napi, 0);
		if (!skb)
			return -1;

		if (rx->ctx.skb_tail == rx->ctx.skb_head)
			skb_shinfo(rx->ctx.skb_head)->frag_list = skb;
		else
			rx->ctx.skb_tail->next = skb;
		rx->ctx.skb_tail = skb;
		num_frags = 0;
	}
	if (rx->ctx.skb_tail != rx->ctx.skb_head) {
		rx->ctx.skb_head->len += buf_len;
		rx->ctx.skb_head->data_len += buf_len;
		rx->ctx.skb_head->truesize += priv->data_buffer_size_dqo;
	}

	/* Trigger ondemand page allocation if we are running low on buffers */
	if (gve_rx_should_trigger_copy_ondemand(rx))
		return (*klpe_gve_rx_copy_ondemand)(rx, buf_state, buf_len);

	skb_add_rx_frag(rx->ctx.skb_tail, num_frags,
			buf_state->page_info.page,
			buf_state->page_info.page_offset,
			buf_len, priv->data_buffer_size_dqo);
	(*klpe_gve_dec_pagecnt_bias)(&buf_state->page_info);

	/* Advances buffer page-offset if page is partially used.
	 * Marks buffer as used if page is full.
	 */
	gve_try_recycle_buf(priv, rx, buf_state);
	return 0;
}

static int klpr_gve_rx_dqo(struct napi_struct *napi, struct gve_rx_ring *rx,
		      const struct gve_rx_compl_desc_dqo *compl_desc,
		      int queue_idx)
{
	const u16 buffer_id = le16_to_cpu(compl_desc->buf_id);
	const bool eop = compl_desc->end_of_packet != 0;
	struct gve_rx_buf_state_dqo *buf_state;
	struct gve_priv *priv = rx->gve;
	u16 buf_len;

	if (unlikely(buffer_id >= rx->dqo.num_buf_states)) {
		net_err_ratelimited("%s: Invalid RX buffer_id=%u\n",
				    priv->dev->name, buffer_id);
		return -EINVAL;
	}
	buf_state = &rx->dqo.buf_states[buffer_id];
	if (unlikely(!gve_buf_state_is_allocated(rx, buf_state))) {
		net_err_ratelimited("%s: RX buffer_id is not allocated: %u\n",
				    priv->dev->name, buffer_id);
		return -EINVAL;
	}

	if (unlikely(compl_desc->rx_error)) {
		gve_enqueue_buf_state(rx, &rx->dqo.recycled_buf_states,
				      buf_state);
		return -EINVAL;
	}

	buf_len = compl_desc->packet_len;

	/* Page might have not been used for awhile and was likely last written
	 * by a different thread.
	 */
	prefetch(buf_state->page_info.page);

	/* Sync the portion of dma buffer for CPU to read. */
	dma_sync_single_range_for_cpu(&priv->pdev->dev, buf_state->addr,
				      buf_state->page_info.page_offset,
				      buf_len, DMA_FROM_DEVICE);

	/* Append to current skb if one exists. */
	if (rx->ctx.skb_head) {
		if (unlikely(klpr_gve_rx_append_frags(napi, buf_state, buf_len, rx,
						 priv)) != 0) {
			goto error;
		}
		return 0;
	}

	if (eop && buf_len <= priv->rx_copybreak) {
		rx->ctx.skb_head = (*klpe_gve_rx_copy)(priv->dev, napi,
					       &buf_state->page_info, buf_len);
		if (unlikely(!rx->ctx.skb_head))
			goto error;
		rx->ctx.skb_tail = rx->ctx.skb_head;

		u64_stats_update_begin(&rx->statss);
		rx->rx_copied_pkt++;
		rx->rx_copybreak_pkt++;
		u64_stats_update_end(&rx->statss);

		gve_enqueue_buf_state(rx, &rx->dqo.recycled_buf_states,
				      buf_state);
		return 0;
	}

	rx->ctx.skb_head = napi_get_frags(napi);
	if (unlikely(!rx->ctx.skb_head))
		goto error;
	rx->ctx.skb_tail = rx->ctx.skb_head;

	if (gve_rx_should_trigger_copy_ondemand(rx)) {
		if ((*klpe_gve_rx_copy_ondemand)(rx, buf_state, buf_len) < 0)
			goto error;
		return 0;
	}

	skb_add_rx_frag(rx->ctx.skb_head, 0, buf_state->page_info.page,
			buf_state->page_info.page_offset, buf_len,
			priv->data_buffer_size_dqo);
	(*klpe_gve_dec_pagecnt_bias)(&buf_state->page_info);

	gve_try_recycle_buf(priv, rx, buf_state);
	return 0;

error:
	gve_enqueue_buf_state(rx, &rx->dqo.recycled_buf_states, buf_state);
	return -ENOMEM;
}

static int gve_rx_complete_rsc(struct sk_buff *skb,
			       const struct gve_rx_compl_desc_dqo *desc,
			       struct gve_ptype ptype)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);

	/* Only TCP is supported right now. */
	if (ptype.l4_type != GVE_L4_TYPE_TCP)
		return -EINVAL;

	switch (ptype.l3_type) {
	case GVE_L3_TYPE_IPV4:
		shinfo->gso_type = SKB_GSO_TCPV4;
		break;
	case GVE_L3_TYPE_IPV6:
		shinfo->gso_type = SKB_GSO_TCPV6;
		break;
	default:
		return -EINVAL;
	}

	shinfo->gso_size = le16_to_cpu(desc->rsc_seg_len);
	return 0;
}

static int gve_rx_complete_skb(struct gve_rx_ring *rx, struct napi_struct *napi,
			       const struct gve_rx_compl_desc_dqo *desc,
			       netdev_features_t feat)
{
	struct gve_ptype ptype =
		rx->gve->ptype_lut_dqo->ptypes[desc->packet_type];
	int err;

	skb_record_rx_queue(rx->ctx.skb_head, rx->q_num);

	if (feat & NETIF_F_RXHASH)
		gve_rx_skb_hash(rx->ctx.skb_head, desc, ptype);

	if (feat & NETIF_F_RXCSUM)
		gve_rx_skb_csum(rx->ctx.skb_head, desc, ptype);

	/* RSC packets must set gso_size otherwise the TCP stack will complain
	 * that packets are larger than MTU.
	 */
	if (desc->rsc) {
		err = gve_rx_complete_rsc(rx->ctx.skb_head, desc, ptype);
		if (err < 0)
			return err;
	}

	if (skb_headlen(rx->ctx.skb_head) == 0)
		napi_gro_frags(napi);
	else
		napi_gro_receive(napi, rx->ctx.skb_head);

	return 0;
}

int klpp_gve_rx_poll_dqo(struct gve_notify_block *block, int budget)
{
	struct napi_struct *napi = &block->napi;
	netdev_features_t feat = napi->dev->features;

	struct gve_rx_ring *rx = block->rx;
	struct gve_rx_compl_queue_dqo *complq = &rx->dqo.complq;

	u32 work_done = 0;
	u64 bytes = 0;
	int err;

	while (work_done < budget) {
		struct gve_rx_compl_desc_dqo *compl_desc =
			&complq->desc_ring[complq->head];
		u32 pkt_bytes;

		/* No more new packets */
		if (compl_desc->generation == complq->cur_gen_bit)
			break;

		/* Prefetch the next two descriptors. */
		prefetch(&complq->desc_ring[(complq->head + 1) & complq->mask]);
		prefetch(&complq->desc_ring[(complq->head + 2) & complq->mask]);

		/* Do not read data until we own the descriptor */
		dma_rmb();

		err = klpr_gve_rx_dqo(napi, rx, compl_desc, rx->q_num);
		if (err < 0) {
			klpp_gve_rx_free_skb(napi, rx);
			u64_stats_update_begin(&rx->statss);
			if (err == -ENOMEM)
				rx->rx_skb_alloc_fail++;
			else if (err == -EINVAL)
				rx->rx_desc_err_dropped_pkt++;
			u64_stats_update_end(&rx->statss);
		}

		complq->head = (complq->head + 1) & complq->mask;
		complq->num_free_slots++;

		/* When the ring wraps, the generation bit is flipped. */
		complq->cur_gen_bit ^= (complq->head == 0);

		/* Receiving a completion means we have space to post another
		 * buffer on the buffer queue.
		 */
		{
			struct gve_rx_buf_queue_dqo *bufq = &rx->dqo.bufq;

			bufq->head = (bufq->head + 1) & bufq->mask;
		}

		/* Free running counter of completed descriptors */
		rx->cnt++;

		if (!rx->ctx.skb_head)
			continue;

		if (!compl_desc->end_of_packet)
			continue;

		work_done++;
		pkt_bytes = rx->ctx.skb_head->len;
		/* The ethernet header (first ETH_HLEN bytes) is snipped off
		 * by eth_type_trans.
		 */
		if (skb_headlen(rx->ctx.skb_head))
			pkt_bytes += ETH_HLEN;

		/* gve_rx_complete_skb() will consume skb if successful */
		if (gve_rx_complete_skb(rx, napi, compl_desc, feat) != 0) {
			klpp_gve_rx_free_skb(napi, rx);
			u64_stats_update_begin(&rx->statss);
			rx->rx_desc_err_dropped_pkt++;
			u64_stats_update_end(&rx->statss);
			continue;
		}

		bytes += pkt_bytes;
		rx->ctx.skb_head = NULL;
		rx->ctx.skb_tail = NULL;
	}

	(*klpe_gve_rx_post_buffers_dqo)(rx);

	u64_stats_update_begin(&rx->statss);
	rx->rpackets += work_done;
	rx->rbytes += bytes;
	u64_stats_update_end(&rx->statss);

	return work_done;
}


#include "livepatch_bsc1227903.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "gve"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "gve_dec_pagecnt_bias", (void *)&klpe_gve_dec_pagecnt_bias, "gve" },
	{ "gve_rx_copy", (void *)&klpe_gve_rx_copy, "gve" },
	{ "gve_rx_copy_ondemand", (void *)&klpe_gve_rx_copy_ondemand, "gve" },
	{ "gve_rx_post_buffers_dqo", (void *)&klpe_gve_rx_post_buffers_dqo,
	  "gve" },
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

int livepatch_bsc1227903_init(void)
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

void livepatch_bsc1227903_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_GVE) */
