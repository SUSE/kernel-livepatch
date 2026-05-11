/*
 * bsc1264459_net_ipv4_esp4
 *
 * Fix for CVE-2026-43284, bsc#1264459
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


#include "livepatch_bsc1264459.h"


/* klp-ccp: from net/ipv4/esp4.c */
#define pr_fmt(fmt) "IPsec: " fmt

#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>
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

struct esp_skb_cb {
	struct xfrm_skb_cb xfrm;
	void *tmp;
};

struct esp_output_extra {
	__be32 seqhi;
	u32 esphoff;
};

#define ESP_SKB_CB(__skb) ((struct esp_skb_cb *)&((__skb)->cb[0]))

extern void *esp_alloc_tmp(struct crypto_aead *aead, int nfrags, int extralen);

static inline void *esp_tmp_extra(void *tmp)
{
	return PTR_ALIGN(tmp, __alignof__(struct esp_output_extra));
}

static inline u8 *esp_tmp_iv(struct crypto_aead *aead, void *tmp, int extralen)
{
	return crypto_aead_ivsize(aead) ?
	       PTR_ALIGN((u8 *)tmp + extralen,
			 crypto_aead_alignmask(aead) + 1) : tmp + extralen;
}

static inline struct aead_request *esp_tmp_req(struct crypto_aead *aead, u8 *iv)
{
	struct aead_request *req;

	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
				crypto_tfm_ctx_alignment());
	aead_request_set_tfm(req, aead);
	return req;
}

static inline struct scatterlist *esp_req_sg(struct crypto_aead *aead,
					     struct aead_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_aead_reqsize(aead),
			     __alignof__(struct scatterlist));
}

static void esp_restore_header(struct sk_buff *skb, unsigned int offset)
{
	struct ip_esp_hdr *esph = (void *)(skb->data + offset);
	void *tmp = ESP_SKB_CB(skb)->tmp;
	__be32 *seqhi = esp_tmp_extra(tmp);

	esph->seq_no = esph->spi;
	esph->spi = *seqhi;
}

int esp_input_done2(struct sk_buff *skb, int err);

extern typeof(esp_input_done2) esp_input_done2;

extern void esp_input_done(void *data, int err);

static void esp_input_restore_header(struct sk_buff *skb)
{
	esp_restore_header(skb, 0);
	__skb_pull(skb, 4);
}

static void esp_input_set_header(struct sk_buff *skb, __be32 *seqhi)
{
	struct xfrm_state *x = xfrm_input_state(skb);
	struct ip_esp_hdr *esph;

	/* For ESN we move the header forward by 4 bytes to
	 * accommodate the high bits.  We will move it back after
	 * decryption.
	 */
	if ((x->props.flags & XFRM_STATE_ESN)) {
		esph = skb_push(skb, 4);
		*seqhi = esph->spi;
		esph->spi = esph->seq_no;
		esph->seq_no = XFRM_SKB_CB(skb)->seq.input.hi;
	}
}

extern void esp_input_done_esn(void *data, int err);

int klpp_esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
	struct crypto_aead *aead = x->data;
	struct aead_request *req;
	struct sk_buff *trailer;
	int ivlen = crypto_aead_ivsize(aead);
	int elen = skb->len - sizeof(struct ip_esp_hdr) - ivlen;
	int nfrags;
	int assoclen;
	int seqhilen;
	__be32 *seqhi;
	void *tmp;
	u8 *iv;
	struct scatterlist *sg;
	int err = -EINVAL;

	if (!pskb_may_pull(skb, sizeof(struct ip_esp_hdr) + ivlen))
		goto out;

	if (elen <= 0)
		goto out;

	assoclen = sizeof(struct ip_esp_hdr);
	seqhilen = 0;

	if (x->props.flags & XFRM_STATE_ESN) {
		seqhilen += sizeof(__be32);
		assoclen += seqhilen;
	}

	if (!skb_cloned(skb)) {
		if (!skb_is_nonlinear(skb)) {
			nfrags = 1;

			goto skip_cow;
		} else if (!skb_has_frag_list(skb) &&
			   !skb_has_shared_frag(skb)) {
			nfrags = skb_shinfo(skb)->nr_frags;
			nfrags++;

			goto skip_cow;
		}
	}

	err = skb_cow_data(skb, 0, &trailer);
	if (err < 0)
		goto out;

	nfrags = err;

skip_cow:
	err = -ENOMEM;
	tmp = esp_alloc_tmp(aead, nfrags, seqhilen);
	if (!tmp)
		goto out;

	ESP_SKB_CB(skb)->tmp = tmp;
	seqhi = esp_tmp_extra(tmp);
	iv = esp_tmp_iv(aead, tmp, seqhilen);
	req = esp_tmp_req(aead, iv);
	sg = esp_req_sg(aead, req);

	esp_input_set_header(skb, seqhi);

	sg_init_table(sg, nfrags);
	err = skb_to_sgvec(skb, sg, 0, skb->len);
	if (unlikely(err < 0)) {
		kfree(tmp);
		goto out;
	}

	skb->ip_summed = CHECKSUM_NONE;

	if ((x->props.flags & XFRM_STATE_ESN))
		aead_request_set_callback(req, 0, esp_input_done_esn, skb);
	else
		aead_request_set_callback(req, 0, esp_input_done, skb);

	aead_request_set_crypt(req, sg, sg, elen + ivlen, iv);
	aead_request_set_ad(req, assoclen);

	err = crypto_aead_decrypt(req);
	if (err == -EINPROGRESS)
		goto out;

	if ((x->props.flags & XFRM_STATE_ESN))
		esp_input_restore_header(skb);

	err = esp_input_done2(skb, err);

out:
	return err;
}


#include <linux/livepatch.h>

extern typeof(esp_alloc_tmp) esp_alloc_tmp
	 KLP_RELOC_SYMBOL(esp4, esp4, esp_alloc_tmp);
extern typeof(esp_input_done) esp_input_done
	 KLP_RELOC_SYMBOL(esp4, esp4, esp_input_done);
extern typeof(esp_input_done2) esp_input_done2
	 KLP_RELOC_SYMBOL(esp4, esp4, esp_input_done2);
extern typeof(esp_input_done_esn) esp_input_done_esn
	 KLP_RELOC_SYMBOL(esp4, esp4, esp_input_done_esn);
