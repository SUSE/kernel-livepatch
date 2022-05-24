/*
 * bsc1197133_esp4
 *
 * Fix for CVE-2022-0886, bsc#1197133
 *
 *  Copyright (c) 2022 SUSE
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


#include "livepatch_bsc1197133.h"




/* klp-ccp: from net/ipv4/esp4.c */
#define pr_fmt(fmt) "IPsec: " fmt

#include <crypto/aead.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>

/* klp-ccp: from net/ipv4/esp4.c */
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/in6.h>
#include <linux/highmem.h>

static void (*klpe_esp_output_fill_trailer)(u8 *tail, int tfclen, int plen, __u8 proto);

static void esp_output_udp_encap(struct xfrm_state *x, struct sk_buff *skb, struct esp_info *esp)
{
	int encap_type;
	struct udphdr *uh;
	__be32 *udpdata32;
	__be16 sport, dport;
	struct xfrm_encap_tmpl *encap = x->encap;
	struct ip_esp_hdr *esph = esp->esph;

	spin_lock_bh(&x->lock);
	sport = encap->encap_sport;
	dport = encap->encap_dport;
	encap_type = encap->encap_type;
	spin_unlock_bh(&x->lock);

	uh = (struct udphdr *)esph;
	uh->source = sport;
	uh->dest = dport;
	uh->len = htons(skb->len + esp->tailen
		  - skb_transport_offset(skb));
	uh->check = 0;

	switch (encap_type) {
	default:
	case UDP_ENCAP_ESPINUDP:
		esph = (struct ip_esp_hdr *)(uh + 1);
		break;
	case UDP_ENCAP_ESPINUDP_NON_IKE:
		udpdata32 = (__be32 *)(uh + 1);
		udpdata32[0] = udpdata32[1] = 0;
		esph = (struct ip_esp_hdr *)(udpdata32 + 2);
		break;
	}

	*skb_mac_header(skb) = IPPROTO_UDP;
	esp->esph = esph;
}

#define ESP_SKB_FRAG_MAXSIZE (PAGE_SIZE << get_order(32768))

int klpp_esp_output_head(struct xfrm_state *x, struct sk_buff *skb, struct esp_info *esp)
{
	u8 *tail;
	u8 *vaddr;
	int nfrags;
	int esph_offset;
	struct page *page;
	struct sk_buff *trailer;
	int tailen = esp->tailen;
	unsigned int allocsz;

	/* this is non-NULL only with UDP Encapsulation */
	if (x->encap)
		esp_output_udp_encap(x, skb, esp);

	allocsz = ALIGN(skb->data_len + tailen, L1_CACHE_BYTES);
	if (allocsz > ESP_SKB_FRAG_MAXSIZE)
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

			vaddr = kmap_atomic(page);

			tail = vaddr + pfrag->offset;

			(*klpe_esp_output_fill_trailer)(tail, esp->tfclen, esp->plen, esp->proto);

			kunmap_atomic(vaddr);

			nfrags = skb_shinfo(skb)->nr_frags;

			__skb_fill_page_desc(skb, nfrags, page, pfrag->offset,
					     tailen);
			skb_shinfo(skb)->nr_frags = ++nfrags;

			pfrag->offset = pfrag->offset + allocsize;

			spin_unlock_bh(&x->lock);

			nfrags++;

			skb->len += tailen;
			skb->data_len += tailen;
			skb->truesize += tailen;
			if (sk)
				atomic_add(tailen, &sk->sk_wmem_alloc);

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
	(*klpe_esp_output_fill_trailer)(tail, esp->tfclen, esp->plen, esp->proto);
	pskb_put(skb, trailer, tailen);

out:
	return nfrags;
}




#define LP_MODULE "esp4"
#include <linux/module.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "esp_output_fill_trailer", (void *)&klpe_esp_output_fill_trailer,
	  "esp4" },
};

static int bsc1197133_esp4_module_notify(struct notifier_block *nb,
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

static struct notifier_block bsc1197133_esp4_module_nb = {
	.notifier_call = bsc1197133_esp4_module_notify,
	.priority = INT_MIN+1,
};

int bsc1197133_esp4_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&bsc1197133_esp4_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1197133_esp4_cleanup(void)
{
	unregister_module_notifier(&bsc1197133_esp4_module_nb);
}
