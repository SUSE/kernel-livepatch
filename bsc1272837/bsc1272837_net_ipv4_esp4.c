/*
 * bsc1272837_net_ipv4_esp4
 *
 * Fix for CVE-2026-63912, bsc#1272837
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1272837.h"


/* klp-ccp: from net/ipv4/esp4.c */
#define pr_fmt(fmt) "IPsec: " fmt

#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>

/* klp-ccp: from include/net/esp.h */
int klpp_esp_output_head(struct xfrm_state *x, struct sk_buff *skb, struct esp_info *esp);

/* klp-ccp: from net/ipv4/esp4.c */
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/in6.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/espintcp.h>
#include <linux/skbuff_ref.h>
#include <linux/highmem.h>

#ifdef CONFIG_INET_ESPINTCP
extern struct sock *esp_find_tcp_sk(struct xfrm_state *x);

#else
#error "klp-ccp: non-taken branch"
#endif

static struct ip_esp_hdr *esp_output_udp_encap(struct sk_buff *skb,
					       int encap_type,
					       struct esp_info *esp,
					       __be16 sport,
					       __be16 dport)
{
	struct udphdr *uh;
	__be32 *udpdata32;
	unsigned int len;

	len = skb->len + esp->tailen - skb_transport_offset(skb);
	if (len + sizeof(struct iphdr) > IP_MAX_MTU)
		return ERR_PTR(-EMSGSIZE);

	uh = (struct udphdr *)esp->esph;
	uh->source = sport;
	uh->dest = dport;
	uh->len = htons(len);
	uh->check = 0;

	*skb_mac_header(skb) = IPPROTO_UDP;

	if (encap_type == UDP_ENCAP_ESPINUDP_NON_IKE) {
		udpdata32 = (__be32 *)(uh + 1);
		udpdata32[0] = udpdata32[1] = 0;
		return (struct ip_esp_hdr *)(udpdata32 + 2);
	}

	return (struct ip_esp_hdr *)(uh + 1);
}

#ifdef CONFIG_INET_ESPINTCP
static struct ip_esp_hdr *esp_output_tcp_encap(struct xfrm_state *x,
						    struct sk_buff *skb,
						    struct esp_info *esp)
{
	__be16 *lenp = (void *)esp->esph;
	struct ip_esp_hdr *esph;
	unsigned int len;
	struct sock *sk;

	len = skb->len + esp->tailen - skb_transport_offset(skb);
	if (len > IP_MAX_MTU)
		return ERR_PTR(-EMSGSIZE);

	rcu_read_lock();
	sk = esp_find_tcp_sk(x);
	rcu_read_unlock();

	if (IS_ERR(sk))
		return ERR_CAST(sk);

	sock_put(sk);

	*lenp = htons(len);
	esph = (struct ip_esp_hdr *)(lenp + 1);

	return esph;
}
#else
#error "klp-ccp: non-taken branch"
#endif

static int esp_output_encap(struct xfrm_state *x, struct sk_buff *skb,
			    struct esp_info *esp)
{
	struct xfrm_encap_tmpl *encap = x->encap;
	struct ip_esp_hdr *esph;
	__be16 sport, dport;
	int encap_type;

	spin_lock_bh(&x->lock);
	sport = encap->encap_sport;
	dport = encap->encap_dport;
	encap_type = encap->encap_type;
	spin_unlock_bh(&x->lock);

	switch (encap_type) {
	default:
	case UDP_ENCAP_ESPINUDP:
	case UDP_ENCAP_ESPINUDP_NON_IKE:
		esph = esp_output_udp_encap(skb, encap_type, esp, sport, dport);
		break;
	case TCP_ENCAP_ESPINTCP:
		esph = esp_output_tcp_encap(x, skb, esp);
		break;
	}

	if (IS_ERR(esph))
		return PTR_ERR(esph);

	esp->esph = esph;

	return 0;
}

int klpp_esp_output_head(struct xfrm_state *x, struct sk_buff *skb, struct esp_info *esp)
{
	u8 *tail;
	int nfrags;
	int esph_offset;
	struct page *page;
	struct sk_buff *trailer;
	int tailen = esp->tailen;

	/* this is non-NULL only with TCP/UDP Encapsulation */
	if (x->encap) {
		int err = esp_output_encap(x, skb, esp);

		if (err < 0)
			return err;
	}

	if (ALIGN(skb->data_len + tailen, L1_CACHE_BYTES) >
	    PAGE_SIZE)
		goto cow;

	if (!skb_cloned(skb)) {
		if (tailen <= skb_tailroom(skb)) {
			nfrags = 1;
			trailer = skb;
			tail = skb_tail_pointer(trailer);

			goto skip_cow;
		} else if ((skb_shinfo(skb)->nr_frags < MAX_SKB_FRAGS)
			   && !skb_has_frag_list(skb)) {
			int allocsize;
			struct sock *sk = skb->sk;
			struct page_frag *pfrag = &x->xfrag;

			esp->inplace = false;

			allocsize = ALIGN(tailen, L1_CACHE_BYTES);

			spin_lock_bh(&x->lock);

			if (unlikely(!skb_page_frag_refill(allocsize, pfrag, GFP_ATOMIC))) {
				spin_unlock_bh(&x->lock);
				goto cow;
			}

			page = pfrag->page;
			get_page(page);

			tail = page_address(page) + pfrag->offset;

			esp_output_fill_trailer(tail, esp->tfclen, esp->plen, esp->proto);

			nfrags = skb_shinfo(skb)->nr_frags;

			__skb_fill_page_desc(skb, nfrags, page, pfrag->offset,
					     tailen);
			skb_shinfo(skb)->nr_frags = ++nfrags;

			pfrag->offset = pfrag->offset + allocsize;

			spin_unlock_bh(&x->lock);

			nfrags++;

			skb_len_add(skb, tailen);
			if (sk && sk_fullsock(sk))
				refcount_add(tailen, &sk->sk_wmem_alloc);

			goto out;
		}
	}

cow:
	esph_offset = (unsigned char *)esp->esph - skb_transport_header(skb);

	nfrags = skb_cow_data(skb, tailen, &trailer);
	if (nfrags < 0)
		goto out;
	tail = skb_tail_pointer(trailer);
	esp->esph = (struct ip_esp_hdr *)(skb_transport_header(skb) + esph_offset);

skip_cow:
	esp_output_fill_trailer(tail, esp->tfclen, esp->plen, esp->proto);
	pskb_put(skb, trailer, tailen);

out:
	return nfrags;
}

typeof(klpp_esp_output_head) klpp_esp_output_head;


#include <linux/livepatch.h>

extern typeof(esp_find_tcp_sk) esp_find_tcp_sk
	 KLP_RELOC_SYMBOL(esp4, esp4, esp_find_tcp_sk);
