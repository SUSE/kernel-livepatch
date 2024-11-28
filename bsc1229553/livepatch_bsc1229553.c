/*
 * livepatch_bsc1229553
 *
 * Fix for CVE-2024-43861, bsc#1229553
 *
 *  Upstream commit:
 *  7ab107544b77 ("net: usb: qmi_wwan: fix memory leak for not ip packets")
 *
 *  SLE12-SP5 commit:
 *  706ebe0a74ce1e4b7379e054dd0e424aea125046
 *
 *  SLE15-SP2 and -SP3 commit:
 *  5720eddd168f779d3f4fecd2dba28feb208f040a
 *
 *  SLE15-SP4 and -SP5 commit:
 *  3e796c33083281556914c9b64738f6de4a3ac33f
 *
 *  SLE15-SP6 commit:
 *  90880a5034cbb27ba579079894974a35654f1701
 *
 *  Copyright (c) 2024 SUSE
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

#if IS_ENABLED(CONFIG_USB_NET_QMI_WWAN)

#if !IS_MODULE(CONFIG_USB_NET_QMI_WWAN)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/usb/qmi_wwan.c */
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>

#include <linux/kstrtox.h>
#include <linux/mii.h>

#include <linux/usb.h>

#include <linux/usb/usbnet.h>

#include <linux/u64_stats_sync.h>

struct qmi_wwan_state {
	struct usb_driver *subdriver;
	atomic_t pmcount;
	unsigned long flags;
	struct usb_interface *control;
	struct usb_interface *data;
};

enum qmi_wwan_flags {
	QMI_WWAN_FLAG_RAWIP = 1 << 0,
	QMI_WWAN_FLAG_MUX = 1 << 1,
	QMI_WWAN_FLAG_PASS_THROUGH = 1 << 2,
};

struct qmimux_hdr {
	u8 pad;
	u8 mux_id;
	__be16 pkt_len;
};

struct qmimux_priv {
	struct net_device *real_dev;
	u8 mux_id;
};

static struct net_device *qmimux_find_dev(struct usbnet *dev, u8 mux_id)
{
	struct qmimux_priv *priv;
	struct list_head *iter;
	struct net_device *ldev;

	rcu_read_lock();
	netdev_for_each_upper_dev_rcu(dev->net, ldev, iter) {
		priv = netdev_priv(ldev);
		if (priv->mux_id == mux_id) {
			rcu_read_unlock();
			return ldev;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static int qmimux_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	unsigned int len, offset = 0, pad_len, pkt_len;
	struct qmimux_hdr *hdr;
	struct net_device *net;
	struct sk_buff *skbn;
	u8 qmimux_hdr_sz = sizeof(*hdr);

	while (offset + qmimux_hdr_sz < skb->len) {
		hdr = (struct qmimux_hdr *)(skb->data + offset);
		len = be16_to_cpu(hdr->pkt_len);

		/* drop the packet, bogus length */
		if (offset + len + qmimux_hdr_sz > skb->len)
			return 0;

		/* control packet, we do not know what to do */
		if (hdr->pad & 0x80)
			goto skip;

		/* extract padding length and check for valid length info */
		pad_len = hdr->pad & 0x3f;
		if (len == 0 || pad_len >= len)
			goto skip;
		pkt_len = len - pad_len;

		net = qmimux_find_dev(dev, hdr->mux_id);
		if (!net)
			goto skip;
		skbn = netdev_alloc_skb(net, pkt_len + LL_MAX_HEADER);
		if (!skbn)
			return 0;

		switch (skb->data[offset + qmimux_hdr_sz] & 0xf0) {
		case 0x40:
			skbn->protocol = htons(ETH_P_IP);
			break;
		case 0x60:
			skbn->protocol = htons(ETH_P_IPV6);
			break;
		default:
			/* not ip - do not know what to do */
			kfree_skb(skbn);
			goto skip;
		}

		skb_reserve(skbn, LL_MAX_HEADER);
		skb_put_data(skbn, skb->data + offset + qmimux_hdr_sz, pkt_len);
		if (netif_rx(skbn) != NET_RX_SUCCESS) {
			net->stats.rx_errors++;
			return 0;
		} else {
			dev_sw_netstats_rx_add(net, pkt_len);
		}

skip:
		offset += len + qmimux_hdr_sz;
	}
	return 1;
}

int klpp_qmi_wwan_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	struct qmi_wwan_state *info = (void *)&dev->data;
	bool rawip = info->flags & QMI_WWAN_FLAG_RAWIP;
	__be16 proto;

	/* This check is no longer done by usbnet */
	if (skb->len < dev->net->hard_header_len)
		return 0;

	if (info->flags & QMI_WWAN_FLAG_MUX)
		return qmimux_rx_fixup(dev, skb);

	if (info->flags & QMI_WWAN_FLAG_PASS_THROUGH) {
		skb->protocol = htons(ETH_P_MAP);
		return 1;
	}

	switch (skb->data[0] & 0xf0) {
	case 0x40:
		proto = htons(ETH_P_IP);
		break;
	case 0x60:
		proto = htons(ETH_P_IPV6);
		break;
	case 0x00:
		if (rawip)
			return 0;
		if (is_multicast_ether_addr(skb->data))
			return 1;
		/* possibly bogus destination - rewrite just in case */
		skb_reset_mac_header(skb);
		goto fix_dest;
	default:
		if (rawip)
			return 0;
		/* pass along other packets without modifications */
		return 1;
	}
	if (rawip) {
		skb_reset_mac_header(skb);
		skb->dev = dev->net; /* normally set by eth_type_trans */
		skb->protocol = proto;
		return 1;
	}

	if (skb_headroom(skb) < ETH_HLEN)
		return 0;
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	eth_hdr(skb)->h_proto = proto;
	eth_zero_addr(eth_hdr(skb)->h_source);
fix_dest:
	memcpy(eth_hdr(skb)->h_dest, dev->net->dev_addr, ETH_ALEN);
	return 1;
}

#include "livepatch_bsc1229553.h"

#endif /* IS_ENABLED(CONFIG_USB_NET_QMI_WWAN) */
