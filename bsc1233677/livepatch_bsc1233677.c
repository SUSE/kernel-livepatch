/*
 * livepatch_bsc1233677
 *
 * Fix for CVE-2024-53082, bsc#1233677
 *
 *  Upstream commit:
 *  3f7d9c1964fc ("virtio_net: Add hash_key_length check")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  1273e471f19ce71332f60a12819a6fd954d8cb85
 *
 *  SLE MICRO-6-0 commit:
 *  1273e471f19ce71332f60a12819a6fd954d8cb85
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from drivers/net/virtio_net.c */
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/average.h>
#include <linux/filter.h>
#include <linux/kernel.h>

#include <net/xdp.h>
#include <net/net_failover.h>

extern int napi_weight;

extern bool csum;
extern bool gso;
extern bool napi_tx;

#define GOOD_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)

/* klp-ccp: not from file */
#undef inline

DECLARE_EWMA(pkt_len, 0, 64)

extern const unsigned long guest_offloads[8];

struct virtnet_sq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 xdp_tx;
	u64 xdp_tx_drops;
	u64 kicks;
	u64 tx_timeouts;
};

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 xdp_packets;
	u64 xdp_tx;
	u64 xdp_redirects;
	u64 xdp_drops;
	u64 kicks;
};

struct send_queue {
	/* Virtqueue associated with this send _queue */
	struct virtqueue *vq;

	/* TX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Name of the send queue: output.$index */
	char name[16];

	struct virtnet_sq_stats stats;

	struct napi_struct napi;

	/* Record whether sq is in reset state. */
	bool reset;
};

struct receive_queue {
	/* Virtqueue associated with this receive_queue */
	struct virtqueue *vq;

	struct napi_struct napi;

	struct bpf_prog __rcu *xdp_prog;

	struct virtnet_rq_stats stats;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Min single buffer size for mergeable buffers case. */
	unsigned int min_buf_len;

	/* Name of this receive queue: input.$index */
	char name[16];

	struct xdp_rxq_info xdp_rxq;
};

#define VIRTIO_NET_RSS_MAX_KEY_SIZE     40
#define VIRTIO_NET_RSS_MAX_TABLE_LEN    128
struct virtio_net_ctrl_rss {
	u32 hash_types;
	u16 indirection_table_mask;
	u16 unclassified_queue;
	u16 indirection_table[VIRTIO_NET_RSS_MAX_TABLE_LEN];
	u16 max_tx_vq;
	u8 hash_key_length;
	u8 key[VIRTIO_NET_RSS_MAX_KEY_SIZE];
};

struct control_buf {
	struct virtio_net_ctrl_hdr hdr;
	virtio_net_ctrl_ack status;
	struct virtio_net_ctrl_mq mq;
	u8 promisc;
	u8 allmulti;
	__virtio16 vid;
	__virtio64 offloads;
	struct virtio_net_ctrl_rss rss;
	struct virtio_net_ctrl_coal_tx coal_tx;
	struct virtio_net_ctrl_coal_rx coal_rx;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;

	/* Max # of queue pairs supported by the device */
	u16 max_queue_pairs;

	/* # of queue pairs currently used by the driver */
	u16 curr_queue_pairs;

	/* # of XDP queue pairs currently used by the driver */
	u16 xdp_queue_pairs;

	/* xdp_queue_pairs may be 0, when xdp is already loaded. So add this. */
	bool xdp_enabled;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* number of sg entries allocated for big packets */
	unsigned int big_packets_num_skbfrags;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Host supports rss and/or hash report */
	bool has_rss;
	bool has_rss_hash_report;
	u8 rss_key_size;
	u16 rss_indir_table_size;
	u32 rss_hash_types_supported;
	u32 rss_hash_types_saved;

	/* Has control virtqueue */
	bool has_cvq;

	/* Host can handle any s/g split between our header and packet data */
	bool any_header_sg;

	/* Packet virtio header size */
	u8 hdr_len;

	/* Work struct for delayed refilling if we run low on memory. */
	struct delayed_work refill;

	/* Is delayed refill enabled? */
	bool refill_enabled;

	/* The lock to synchronize the access to refill_enabled */
	spinlock_t refill_lock;

	/* Work struct for config space updates */
	struct work_struct config_work;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;

	/* CPU hotplug instances for online & dead */
	struct hlist_node node;
	struct hlist_node node_dead;

	struct control_buf *ctrl;

	/* Ethtool settings */
	u8 duplex;
	u32 speed;

	/* Interrupt coalescing settings */
	u32 tx_usecs;
	u32 rx_usecs;
	u32 tx_max_packets;
	u32 rx_max_packets;

	unsigned long guest_offloads;
	unsigned long guest_offloads_capable;

	/* failover when STANDBY feature enabled */
	struct failover *failover;
};

static int txq2vq(int txq)
{
	return txq * 2 + 1;
}

static int rxq2vq(int rxq)
{
	return rxq * 2;
}

extern void skb_xmit_done(struct virtqueue *vq);

extern void skb_recv_done(struct virtqueue *rvq);

extern void refill_work(struct work_struct *work);

extern int virtnet_poll(struct napi_struct *napi, int budget);

extern int virtnet_poll_tx(struct napi_struct *napi, int budget);

extern bool virtnet_send_command(struct virtnet_info *vi, u8 class, u8 cmd,
				 struct scatterlist *out);

extern int _virtnet_set_queues(struct virtnet_info *vi, u16 queue_pairs);

extern void virtnet_set_affinity(struct virtnet_info *vi);

extern enum cpuhp_state virtionet_online;

static int virtnet_cpu_notif_add(struct virtnet_info *vi)
{
	int ret;

	ret = cpuhp_state_add_instance_nocalls(virtionet_online, &vi->node);
	if (ret)
		return ret;
	ret = cpuhp_state_add_instance_nocalls(CPUHP_VIRT_NET_DEAD,
					       &vi->node_dead);
	if (!ret)
		return ret;
	cpuhp_state_remove_instance_nocalls(virtionet_online, &vi->node);
	return ret;
}

static void virtnet_init_default_rss(struct virtnet_info *vi)
{
	u32 indir_val = 0;
	int i = 0;

	vi->ctrl->rss.hash_types = vi->rss_hash_types_supported;
	vi->rss_hash_types_saved = vi->rss_hash_types_supported;
	vi->ctrl->rss.indirection_table_mask = vi->rss_indir_table_size
						? vi->rss_indir_table_size - 1 : 0;
	vi->ctrl->rss.unclassified_queue = 0;

	for (; i < vi->rss_indir_table_size; ++i) {
		indir_val = ethtool_rxfh_indir_default(i, vi->curr_queue_pairs);
		vi->ctrl->rss.indirection_table[i] = indir_val;
	}

	vi->ctrl->rss.max_tx_vq = vi->has_rss ? vi->curr_queue_pairs : 0;
	vi->ctrl->rss.hash_key_length = vi->rss_key_size;

	netdev_rss_key_fill(vi->ctrl->rss.key, vi->rss_key_size);
}

static void virtnet_init_settings(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);

	vi->speed = SPEED_UNKNOWN;
	vi->duplex = DUPLEX_UNKNOWN;
}

extern void virtnet_update_settings(struct virtnet_info *vi);

extern const struct ethtool_ops virtnet_ethtool_ops;

static int init_vqs(struct virtnet_info *vi);

extern const struct net_device_ops virtnet_netdev;

extern void virtnet_config_changed_work(struct work_struct *work);

extern void virtnet_free_queues(struct virtnet_info *vi);

static void free_receive_page_frags(struct virtnet_info *vi)
{
	int i;
	for (i = 0; i < vi->max_queue_pairs; i++)
		if (vi->rq[i].alloc_frag.page)
			put_page(vi->rq[i].alloc_frag.page);
}

extern void virtnet_del_vqs(struct virtnet_info *vi);

static unsigned int mergeable_min_buf_len(struct virtnet_info *vi, struct virtqueue *vq)
{
	const unsigned int hdr_len = vi->hdr_len;
	unsigned int rq_size = virtqueue_get_vring_size(vq);
	unsigned int packet_len = vi->big_packets ? IP_MAX_MTU : vi->dev->max_mtu;
	unsigned int buf_len = hdr_len + ETH_HLEN + VLAN_HLEN + packet_len;
	unsigned int min_buf_len = DIV_ROUND_UP(buf_len, rq_size);

	return max(max(min_buf_len, hdr_len) - hdr_len,
		   (unsigned int)GOOD_PACKET_LEN);
}

static int virtnet_find_vqs(struct virtnet_info *vi)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	const char **names;
	int ret = -ENOMEM;
	int total_vqs;
	bool *ctx;
	u16 i;

	/* We expect 1 RX virtqueue followed by 1 TX virtqueue, followed by
	 * possible N-1 RX/TX queue pairs used in multiqueue mode, followed by
	 * possible control vq.
	 */
	total_vqs = vi->max_queue_pairs * 2 +
		    virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VQ);

	/* Allocate space for find_vqs parameters */
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	callbacks = kmalloc_array(total_vqs, sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;
	names = kmalloc_array(total_vqs, sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;
	if (!vi->big_packets || vi->mergeable_rx_bufs) {
		ctx = kcalloc(total_vqs, sizeof(*ctx), GFP_KERNEL);
		if (!ctx)
			goto err_ctx;
	} else {
		ctx = NULL;
	}

	/* Parameters for control virtqueue, if any */
	if (vi->has_cvq) {
		callbacks[total_vqs - 1] = NULL;
		names[total_vqs - 1] = "control";
	}

	/* Allocate/initialize parameters for send/receive virtqueues */
	for (i = 0; i < vi->max_queue_pairs; i++) {
		callbacks[rxq2vq(i)] = skb_recv_done;
		callbacks[txq2vq(i)] = skb_xmit_done;
		sprintf(vi->rq[i].name, "input.%u", i);
		sprintf(vi->sq[i].name, "output.%u", i);
		names[rxq2vq(i)] = vi->rq[i].name;
		names[txq2vq(i)] = vi->sq[i].name;
		if (ctx)
			ctx[rxq2vq(i)] = true;
	}

	ret = virtio_find_vqs_ctx(vi->vdev, total_vqs, vqs, callbacks,
				  names, ctx, NULL);
	if (ret)
		goto err_find;

	if (vi->has_cvq) {
		vi->cvq = vqs[total_vqs - 1];
		if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VLAN))
			vi->dev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	}

	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].vq = vqs[rxq2vq(i)];
		vi->rq[i].min_buf_len = mergeable_min_buf_len(vi, vi->rq[i].vq);
		vi->sq[i].vq = vqs[txq2vq(i)];
	}

	/* run here: ret == 0. */


err_find:
	kfree(ctx);
err_ctx:
	kfree(names);
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	return ret;
}

static int virtnet_alloc_queues(struct virtnet_info *vi)
{
	int i;

	if (vi->has_cvq) {
		vi->ctrl = kzalloc(sizeof(*vi->ctrl), GFP_KERNEL);
		if (!vi->ctrl)
			goto err_ctrl;
	} else {
		vi->ctrl = NULL;
	}
	vi->sq = kcalloc(vi->max_queue_pairs, sizeof(*vi->sq), GFP_KERNEL);
	if (!vi->sq)
		goto err_sq;
	vi->rq = kcalloc(vi->max_queue_pairs, sizeof(*vi->rq), GFP_KERNEL);
	if (!vi->rq)
		goto err_rq;

	INIT_DELAYED_WORK(&vi->refill, refill_work);
	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].pages = NULL;
		netif_napi_add_weight(vi->dev, &vi->rq[i].napi, virtnet_poll,
				      napi_weight);
		netif_napi_add_tx_weight(vi->dev, &vi->sq[i].napi,
					 virtnet_poll_tx,
					 napi_tx ? napi_weight : 0);

		sg_init_table(vi->rq[i].sg, ARRAY_SIZE(vi->rq[i].sg));
		ewma_pkt_len_init(&vi->rq[i].mrg_avg_pkt_len);
		sg_init_table(vi->sq[i].sg, ARRAY_SIZE(vi->sq[i].sg));

		u64_stats_init(&vi->rq[i].stats.syncp);
		u64_stats_init(&vi->sq[i].stats.syncp);
	}

	return 0;

err_rq:
	kfree(vi->sq);
err_sq:
	kfree(vi->ctrl);
err_ctrl:
	return -ENOMEM;
}

static int init_vqs(struct virtnet_info *vi)
{
	int ret;

	/* Allocate send & receive queues */
	ret = virtnet_alloc_queues(vi);
	if (ret)
		goto err;

	ret = virtnet_find_vqs(vi);
	if (ret)
		goto err_free;

	cpus_read_lock();
	virtnet_set_affinity(vi);
	cpus_read_unlock();

	return 0;

err_free:
	virtnet_free_queues(vi);
err:
	return ret;
}

#ifdef CONFIG_SYSFS

extern const struct attribute_group virtio_net_mrg_rx_group;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define MIN_MTU ETH_MIN_MTU
#define MAX_MTU ETH_MAX_MTU

static bool virtnet_check_guest_gso(const struct virtnet_info *vi)
{
	return virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_TSO4) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_TSO6) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_ECN) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_UFO) ||
		(virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_USO4) &&
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_USO6));
}

static void virtnet_set_big_packets(struct virtnet_info *vi, const int mtu)
{
	bool guest_gso = virtnet_check_guest_gso(vi);

	/* If device can receive ANY guest GSO packets, regardless of mtu,
	 * allocate packets of maximum size, otherwise limit it to only
	 * mtu size worth only.
	 */
	if (mtu > ETH_DATA_LEN || guest_gso) {
		vi->big_packets = true;
		vi->big_packets_num_skbfrags = guest_gso ? MAX_SKB_FRAGS : DIV_ROUND_UP(mtu, PAGE_SIZE);
	}
}

int klpp_virtnet_probe(struct virtio_device *vdev)
{
	int i, err = -ENOMEM;
	struct net_device *dev;
	struct virtnet_info *vi;
	u16 max_queue_pairs;
	int mtu = 0;

	/* Find if host supports multiqueue/rss virtio_net device */
	max_queue_pairs = 1;
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MQ) || virtio_has_feature(vdev, VIRTIO_NET_F_RSS))
		max_queue_pairs =
		     virtio_cread16(vdev, offsetof(struct virtio_net_config, max_virtqueue_pairs));

	/* We need at least 2 queue's */
	if (max_queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
	    max_queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
	    !virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		max_queue_pairs = 1;

	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev_mq(sizeof(struct virtnet_info), max_queue_pairs);
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE |
			   IFF_TX_SKB_NO_LINEAR;
	dev->netdev_ops = &virtnet_netdev;
	dev->features = NETIF_F_HIGHDMA;

	dev->ethtool_ops = &virtnet_ethtool_ops;
	SET_NETDEV_DEV(dev, &vdev->dev);

	/* Do we support "hardware" checksums? */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
		/* This opens up the world of extra features. */
		dev->hw_features |= NETIF_F_HW_CSUM | NETIF_F_SG;
		if (csum)
			dev->features |= NETIF_F_HW_CSUM | NETIF_F_SG;

		if (virtio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
			dev->hw_features |= NETIF_F_TSO
				| NETIF_F_TSO_ECN | NETIF_F_TSO6;
		}
		/* Individual feature bits: what can host handle? */
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4))
			dev->hw_features |= NETIF_F_TSO;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6))
			dev->hw_features |= NETIF_F_TSO6;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN))
			dev->hw_features |= NETIF_F_TSO_ECN;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_USO))
			dev->hw_features |= NETIF_F_GSO_UDP_L4;

		dev->features |= NETIF_F_GSO_ROBUST;

		if (gso)
			dev->features |= dev->hw_features & NETIF_F_ALL_TSO;
		/* (!csum && gso) case will be fixed by register_netdev() */
	}

	/* 1. With VIRTIO_NET_F_GUEST_CSUM negotiation, the driver doesn't
	 * need to calculate checksums for partially checksummed packets,
	 * as they're considered valid by the upper layer.
	 * 2. Without VIRTIO_NET_F_GUEST_CSUM negotiation, the driver only
	 * receives fully checksummed packets. The device may assist in
	 * validating these packets' checksums, so the driver won't have to.
	 */
	dev->features |= NETIF_F_RXCSUM;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6))
		dev->features |= NETIF_F_GRO_HW;
	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS))
		dev->hw_features |= NETIF_F_GRO_HW;

	dev->vlan_features = dev->features;
	dev->xdp_features = NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_REDIRECT;

	/* MTU range: 68 - 65535 */
	dev->min_mtu = MIN_MTU;
	dev->max_mtu = MAX_MTU;

	/* Configuration may specify what MAC to use.  Otherwise random. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC)) {
		u8 addr[ETH_ALEN];

		virtio_cread_bytes(vdev,
				   offsetof(struct virtio_net_config, mac),
				   addr, ETH_ALEN);
		eth_hw_addr_set(dev, addr);
	} else {
		eth_hw_addr_random(dev);
		dev_info(&vdev->dev, "Assigned random MAC address %pM\n",
			 dev->dev_addr);
	}

	/* Set up our device-specific information */
	vi = netdev_priv(dev);
	vi->dev = dev;
	vi->vdev = vdev;
	vdev->priv = vi;

	INIT_WORK(&vi->config_work, virtnet_config_changed_work);
	spin_lock_init(&vi->refill_lock);

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF)) {
		vi->mergeable_rx_bufs = true;
		dev->xdp_features |= NETDEV_XDP_ACT_RX_SG;
	}

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_NOTF_COAL)) {
		vi->rx_usecs = 0;
		vi->tx_usecs = 0;
		vi->tx_max_packets = 0;
		vi->rx_max_packets = 0;
	}

	if (virtio_has_feature(vdev, VIRTIO_NET_F_HASH_REPORT))
		vi->has_rss_hash_report = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_RSS)) {
		vi->has_rss = true;

		vi->rss_indir_table_size =
			virtio_cread16(vdev, offsetof(struct virtio_net_config,
				rss_max_indirection_table_length));
	}

	if (vi->has_rss || vi->has_rss_hash_report) {
		vi->rss_key_size =
			virtio_cread8(vdev, offsetof(struct virtio_net_config, rss_max_key_size));
		if (vi->rss_key_size > VIRTIO_NET_RSS_MAX_KEY_SIZE) {
			dev_err(&vdev->dev, "rss_max_key_size=%u exceeds the limit %u.\n",
				vi->rss_key_size, VIRTIO_NET_RSS_MAX_KEY_SIZE);
			err = -EINVAL;
			goto free;
		}

		vi->rss_hash_types_supported =
		    virtio_cread32(vdev, offsetof(struct virtio_net_config, supported_hash_types));
		vi->rss_hash_types_supported &=
				~(VIRTIO_NET_RSS_HASH_TYPE_IP_EX |
				  VIRTIO_NET_RSS_HASH_TYPE_TCP_EX |
				  VIRTIO_NET_RSS_HASH_TYPE_UDP_EX);

		dev->hw_features |= NETIF_F_RXHASH;
	}

	if (vi->has_rss_hash_report)
		vi->hdr_len = sizeof(struct virtio_net_hdr_v1_hash);
	else if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF) ||
		 virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		vi->hdr_len = sizeof(struct virtio_net_hdr);

	if (virtio_has_feature(vdev, VIRTIO_F_ANY_LAYOUT) ||
	    virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->any_header_sg = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		vi->has_cvq = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
		mtu = virtio_cread16(vdev,
				     offsetof(struct virtio_net_config,
					      mtu));
		if (mtu < dev->min_mtu) {
			/* Should never trigger: MTU was previously validated
			 * in virtnet_validate.
			 */
			dev_err(&vdev->dev,
				"device MTU appears to have changed it is now %d < %d",
				mtu, dev->min_mtu);
			err = -EINVAL;
			goto free;
		}

		dev->mtu = mtu;
		dev->max_mtu = mtu;
	}

	virtnet_set_big_packets(vi, mtu);

	if (vi->any_header_sg)
		dev->needed_headroom = vi->hdr_len;

	/* Enable multiqueue by default */
	if (num_online_cpus() >= max_queue_pairs)
		vi->curr_queue_pairs = max_queue_pairs;
	else
		vi->curr_queue_pairs = num_online_cpus();
	vi->max_queue_pairs = max_queue_pairs;

	/* Allocate/initialize the rx/tx queues, and invoke find_vqs */
	err = init_vqs(vi);
	if (err)
		goto free;

#ifdef CONFIG_SYSFS
	if (vi->mergeable_rx_bufs)
		dev->sysfs_rx_queue_group = &virtio_net_mrg_rx_group;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	netif_set_real_num_tx_queues(dev, vi->curr_queue_pairs);
	netif_set_real_num_rx_queues(dev, vi->curr_queue_pairs);

	virtnet_init_settings(dev);

	if (virtio_has_feature(vdev, VIRTIO_NET_F_STANDBY)) {
		vi->failover = net_failover_create(vi->dev);
		if (IS_ERR(vi->failover)) {
			err = PTR_ERR(vi->failover);
			goto free_vqs;
		}
	}

	if (vi->has_rss || vi->has_rss_hash_report)
		virtnet_init_default_rss(vi);

	/* serialize netdev register + virtio_device_ready() with ndo_open() */
	rtnl_lock();

	err = register_netdevice(dev);
	if (err) {
		pr_debug("virtio_net: registering device failed\n");
		rtnl_unlock();
		goto free_failover;
	}

	virtio_device_ready(vdev);

	_virtnet_set_queues(vi, vi->curr_queue_pairs);

	/* a random MAC address has been assigned, notify the device.
	 * We don't fail probe if VIRTIO_NET_F_CTRL_MAC_ADDR is not there
	 * because many devices work fine without getting MAC explicitly
	 */
	if (!virtio_has_feature(vdev, VIRTIO_NET_F_MAC) &&
	    virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_MAC_ADDR)) {
		struct scatterlist sg;

		sg_init_one(&sg, dev->dev_addr, dev->addr_len);
		if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MAC,
					  VIRTIO_NET_CTRL_MAC_ADDR_SET, &sg)) {
			pr_debug("virtio_net: setting MAC address failed\n");
			rtnl_unlock();
			err = -EINVAL;
			goto free_unregister_netdev;
		}
	}

	rtnl_unlock();

	err = virtnet_cpu_notif_add(vi);
	if (err) {
		pr_debug("virtio_net: registering cpu notifier failed\n");
		goto free_unregister_netdev;
	}

	/* Assume link up if device can't report link status,
	   otherwise get link status from config. */
	netif_carrier_off(dev);
	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS)) {
		schedule_work(&vi->config_work);
	} else {
		vi->status = VIRTIO_NET_S_LINK_UP;
		virtnet_update_settings(vi);
		netif_carrier_on(dev);
	}

	for (i = 0; i < ARRAY_SIZE(guest_offloads); i++)
		if (virtio_has_feature(vi->vdev, guest_offloads[i]))
			set_bit(guest_offloads[i], &vi->guest_offloads);
	vi->guest_offloads_capable = vi->guest_offloads;

	pr_debug("virtnet: registered device %s with %d RX and TX vq's\n",
		 dev->name, max_queue_pairs);

	return 0;

free_unregister_netdev:
	unregister_netdev(dev);
free_failover:
	net_failover_destroy(vi->failover);
free_vqs:
	virtio_reset_device(vdev);
	cancel_delayed_work_sync(&vi->refill);
	free_receive_page_frags(vi);
	virtnet_del_vqs(vi);
free:
	free_netdev(dev);
	return err;
}


#include "livepatch_bsc1233677.h"

#include <linux/livepatch.h>

extern typeof(_virtnet_set_queues) _virtnet_set_queues
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, _virtnet_set_queues);
extern typeof(csum) csum KLP_RELOC_SYMBOL(virtio_net, virtio_net, csum);
extern typeof(gso) gso KLP_RELOC_SYMBOL(virtio_net, virtio_net, gso);
extern typeof(guest_offloads) guest_offloads
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, guest_offloads);
extern typeof(napi_tx) napi_tx KLP_RELOC_SYMBOL(virtio_net, virtio_net, napi_tx);
extern typeof(napi_weight) napi_weight
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, napi_weight);
extern typeof(refill_work) refill_work
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, refill_work);
extern typeof(skb_recv_done) skb_recv_done
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, skb_recv_done);
extern typeof(skb_xmit_done) skb_xmit_done
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, skb_xmit_done);
extern typeof(virtio_net_mrg_rx_group) virtio_net_mrg_rx_group
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtio_net_mrg_rx_group);
extern typeof(virtionet_online) virtionet_online
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtionet_online);
extern typeof(virtnet_config_changed_work) virtnet_config_changed_work
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_config_changed_work);
extern typeof(virtnet_del_vqs) virtnet_del_vqs
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_del_vqs);
extern typeof(virtnet_ethtool_ops) virtnet_ethtool_ops
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_ethtool_ops);
extern typeof(virtnet_free_queues) virtnet_free_queues
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_free_queues);
extern typeof(virtnet_netdev) virtnet_netdev
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_netdev);
extern typeof(virtnet_poll) virtnet_poll
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_poll);
extern typeof(virtnet_poll_tx) virtnet_poll_tx
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_poll_tx);
extern typeof(virtnet_send_command) virtnet_send_command
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_send_command);
extern typeof(virtnet_set_affinity) virtnet_set_affinity
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_set_affinity);
extern typeof(virtnet_update_settings) virtnet_update_settings
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_update_settings);
extern typeof(net_failover_create) net_failover_create
	 KLP_RELOC_SYMBOL(virtio_net, net_failover, net_failover_create);
extern typeof(net_failover_destroy) net_failover_destroy
	 KLP_RELOC_SYMBOL(virtio_net, net_failover, net_failover_destroy);
