/*
 * livepatch_bsc1248400
 *
 * Fix for CVE-2025-38572, bsc#1248400
 *
 *  Copyright (c) 2026 SUSE
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

#include "livepatch_bsc1248400.h"

/* klp-ccp: from net/ipv6/ip6_offload.c */
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/printk.h>

#include <net/protocol.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/gro.h>
#include <net/gso.h>

/**
 * skb_reset_transport_header_careful - conditionally reset transport header
 * @skb: buffer to alter
 *
 * Hardened version of skb_reset_transport_header().
 *
 * Returns: true if the operation was a success.
 */
static inline bool __must_check
skb_reset_transport_header_careful(struct sk_buff *skb)
{
	long offset = skb->data - skb->head;

	if (unlikely(offset != (typeof(skb->transport_header))offset))
		return false;

	if (unlikely(offset == (typeof(skb->transport_header))~0U))
		return false;

	skb->transport_header = offset;
	return true;
}

extern int ipv6_gso_pull_exthdrs(struct sk_buff *skb, int proto);

struct sk_buff *klpp_ipv6_gso_segment(struct sk_buff *skb,
	netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct ipv6hdr *ipv6h;
	const struct net_offload *ops;
	int proto, err;
	struct frag_hdr *fptr;
	unsigned int payload_len;
	u8 *prevhdr;
	int offset = 0;
	bool encap, udpfrag;
	int nhoff;
	bool gso_partial;

	skb_reset_network_header(skb);
	err = ipv6_hopopt_jumbo_remove(skb);
	if (err)
		return ERR_PTR(err);
	nhoff = skb_network_header(skb) - skb_mac_header(skb);
	if (unlikely(!pskb_may_pull(skb, sizeof(*ipv6h))))
		goto out;

	encap = SKB_GSO_CB(skb)->encap_level > 0;
	if (encap)
		features &= skb->dev->hw_enc_features;
	SKB_GSO_CB(skb)->encap_level += sizeof(*ipv6h);

	ipv6h = ipv6_hdr(skb);
	__skb_pull(skb, sizeof(*ipv6h));
	segs = ERR_PTR(-EPROTONOSUPPORT);

	proto = ipv6_gso_pull_exthdrs(skb, ipv6h->nexthdr);

	if (skb->encapsulation &&
	    skb_shinfo(skb)->gso_type & (SKB_GSO_IPXIP4 | SKB_GSO_IPXIP6))
		udpfrag = proto == IPPROTO_UDP && encap &&
			  (skb_shinfo(skb)->gso_type & SKB_GSO_UDP);
	else
		udpfrag = proto == IPPROTO_UDP && !skb->encapsulation &&
			  (skb_shinfo(skb)->gso_type & SKB_GSO_UDP);

	ops = rcu_dereference(inet6_offloads[proto]);
	if (likely(ops && ops->callbacks.gso_segment)) {
		if (!skb_reset_transport_header_careful(skb))
			goto out;

		segs = ops->callbacks.gso_segment(skb, features);
		if (!segs)
			skb->network_header = skb_mac_header(skb) + nhoff - skb->head;
	}

	if (IS_ERR_OR_NULL(segs))
		goto out;

	gso_partial = !!(skb_shinfo(segs)->gso_type & SKB_GSO_PARTIAL);

	for (skb = segs; skb; skb = skb->next) {
		ipv6h = (struct ipv6hdr *)(skb_mac_header(skb) + nhoff);
		if (gso_partial && skb_is_gso(skb))
			payload_len = skb_shinfo(skb)->gso_size +
				      SKB_GSO_CB(skb)->data_offset +
				      skb->head - (unsigned char *)(ipv6h + 1);
		else
			payload_len = skb->len - nhoff - sizeof(*ipv6h);
		ipv6h->payload_len = htons(payload_len);
		skb->network_header = (u8 *)ipv6h - skb->head;
		skb_reset_mac_len(skb);

		if (udpfrag) {
			int err = ip6_find_1stfragopt(skb, &prevhdr);
			if (err < 0) {
				kfree_skb_list(segs);
				return ERR_PTR(err);
			}
			fptr = (struct frag_hdr *)((u8 *)ipv6h + err);
			fptr->frag_off = htons(offset);
			if (skb->next)
				fptr->frag_off |= htons(IP6_MF);
			offset += (ntohs(ipv6h->payload_len) -
				   sizeof(struct frag_hdr));
		}
		if (encap)
			skb_reset_inner_headers(skb);
	}

out:
	return segs;
}


#include <linux/livepatch.h>

extern typeof(ipv6_gso_pull_exthdrs) ipv6_gso_pull_exthdrs
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipv6_gso_pull_exthdrs);
