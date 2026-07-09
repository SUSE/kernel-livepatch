/*
 * livepatch_bsc1262759
 *
 * Fix for CVE-2026-31533, bsc#1262759
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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


/* klp-ccp: from net/tls/tls_sw.c */
#include <linux/bug.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/splice.h>
#include <crypto/aead.h>

#include <net/strparser.h>
#include <net/tls.h>
#include <trace/events/sock.h>

/* klp-ccp: from net/tls/tls.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/skmsg.h>
#include <net/tls.h>
#include <net/tls_prot.h>

struct tls_rec {
	struct list_head list;
	int tx_ready;
	int tx_flags;

	struct sk_msg msg_plaintext;
	struct sk_msg msg_encrypted;

	/* AAD | msg_plaintext.sg.data | sg_tag */
	struct scatterlist sg_aead_in[2];
	/* AAD | msg_encrypted.sg.data (data contains overhead for hdr & iv & tag) */
	struct scatterlist sg_aead_out[2];

	char content_type;
	struct scatterlist sg_content_type;

	struct sock *sk;

	char aad_space[TLS_AAD_SPACE_SIZE];
	u8 iv_data[TLS_MAX_IV_SIZE];
	struct aead_request aead_req;
	u8 aead_req_ctx[];
};

void tls_err_abort(struct sock *sk, int err);

int tls_tx_records(struct sock *sk, int flags);

static inline bool tls_bigint_increment(unsigned char *seq, int len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}

	return (i == -1);
}

static inline void
tls_advance_record_sn(struct sock *sk, struct tls_prot_info *prot,
		      struct cipher_context *ctx)
{
	if (tls_bigint_increment(ctx->rec_seq, prot->rec_seq_size))
		tls_err_abort(sk, -EBADMSG);

	if (prot->version != TLS_1_3_VERSION &&
	    prot->cipher_type != TLS_CIPHER_CHACHA20_POLY1305)
		tls_bigint_increment(ctx->iv + prot->salt_size,
				     prot->iv_size);
}

static inline void
tls_xor_iv_with_seq(struct tls_prot_info *prot, char *iv, char *seq)
{
	int i;

	if (prot->version == TLS_1_3_VERSION ||
	    prot->cipher_type == TLS_CIPHER_CHACHA20_POLY1305) {
		for (i = 0; i < 8; i++)
			iv[i + 4] ^= seq[i];
	}
}

static inline void
tls_fill_prepend(struct tls_context *ctx, char *buf, size_t plaintext_len,
		 unsigned char record_type)
{
	struct tls_prot_info *prot = &ctx->prot_info;
	size_t pkt_len, iv_size = prot->iv_size;

	pkt_len = plaintext_len + prot->tag_size;
	if (prot->version != TLS_1_3_VERSION &&
	    prot->cipher_type != TLS_CIPHER_CHACHA20_POLY1305) {
		pkt_len += iv_size;

		memcpy(buf + TLS_NONCE_OFFSET,
		       ctx->tx.iv + prot->salt_size, iv_size);
	}

	/* we cover nonce explicit here as well, so buf should be of
	 * size KTLS_DTLS_HEADER_SIZE + KTLS_DTLS_NONCE_EXPLICIT_SIZE
	 */
	buf[0] = prot->version == TLS_1_3_VERSION ?
		   TLS_RECORD_TYPE_DATA : record_type;
	/* Note that VERSION must be TLS_1_2 for both TLS1.2 and TLS1.3 */
	buf[1] = TLS_1_2_VERSION_MINOR;
	buf[2] = TLS_1_2_VERSION_MAJOR;
	/* we can use IV for nonce explicit according to spec */
	buf[3] = pkt_len >> 8;
	buf[4] = pkt_len & 0xFF;
}

static inline
void tls_make_aad(char *buf, size_t size, char *record_sequence,
		  unsigned char record_type, struct tls_prot_info *prot)
{
	if (prot->version != TLS_1_3_VERSION) {
		memcpy(buf, record_sequence, prot->rec_seq_size);
		buf += 8;
	} else {
		size += prot->tag_size;
	}

	buf[0] = prot->version == TLS_1_3_VERSION ?
		  TLS_RECORD_TYPE_DATA : record_type;
	buf[1] = TLS_1_2_VERSION_MAJOR;
	buf[2] = TLS_1_2_VERSION_MINOR;
	buf[3] = size >> 8;
	buf[4] = size & 0xFF;
}

/* klp-ccp: from net/tls/tls_sw.c */
noinline void tls_err_abort(struct sock *sk, int err);

extern struct tls_rec *tls_get_rec(struct sock *sk);

extern void tls_free_rec(struct sock *sk, struct tls_rec *rec);

int tls_tx_records(struct sock *sk, int flags);

extern void tls_encrypt_done(void *data, int err);

extern int tls_encrypt_async_wait(struct tls_sw_context_tx *ctx);

static int klpp_tls_do_encryption(struct sock *sk,
			     struct tls_context *tls_ctx,
			     struct tls_sw_context_tx *ctx,
			     struct aead_request *aead_req,
			     size_t data_len, u32 start)
{
	struct tls_prot_info *prot = &tls_ctx->prot_info;
	struct tls_rec *rec = ctx->open_rec;
	struct sk_msg *msg_en = &rec->msg_encrypted;
	struct scatterlist *sge = sk_msg_elem(msg_en, start);
	int rc, iv_offset = 0;

	/* For CCM based ciphers, first byte of IV is a constant */
	switch (prot->cipher_type) {
	case TLS_CIPHER_AES_CCM_128:
		rec->iv_data[0] = TLS_AES_CCM_IV_B0_BYTE;
		iv_offset = 1;
		break;
	case TLS_CIPHER_SM4_CCM:
		rec->iv_data[0] = TLS_SM4_CCM_IV_B0_BYTE;
		iv_offset = 1;
		break;
	}

	memcpy(&rec->iv_data[iv_offset], tls_ctx->tx.iv,
	       prot->iv_size + prot->salt_size);

	tls_xor_iv_with_seq(prot, rec->iv_data + iv_offset,
			    tls_ctx->tx.rec_seq);

	sge->offset += prot->prepend_size;
	sge->length -= prot->prepend_size;

	msg_en->sg.curr = start;

	aead_request_set_tfm(aead_req, ctx->aead_send);
	aead_request_set_ad(aead_req, prot->aad_size);
	aead_request_set_crypt(aead_req, rec->sg_aead_in,
			       rec->sg_aead_out,
			       data_len, rec->iv_data);

	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  tls_encrypt_done, rec);

	/* Add the record in tx_list */
	list_add_tail((struct list_head *)&rec->list, &ctx->tx_list);
	DEBUG_NET_WARN_ON_ONCE(atomic_read(&ctx->encrypt_pending) < 1);
	atomic_inc(&ctx->encrypt_pending);

	rc = crypto_aead_encrypt(aead_req);
	if (rc == -EBUSY) {
		rc = tls_encrypt_async_wait(ctx);
		rc = rc ?: -EINPROGRESS;
		/*
		 * The async callback tls_encrypt_done() has already
		 * decremented encrypt_pending and restored the sge on
		 * both success and error. Skip the synchronous cleanup
		 * below on error, just remove the record and return.
		 */
		if (rc != -EINPROGRESS) {
			list_del(&rec->list);
			return rc;
		}
	}
	if (!rc || rc != -EINPROGRESS) {
		atomic_dec(&ctx->encrypt_pending);
		sge->offset -= prot->prepend_size;
		sge->length += prot->prepend_size;
	}

	if (!rc) {
		WRITE_ONCE(rec->tx_ready, true);
	} else if (rc != -EINPROGRESS) {
		list_del(&rec->list);
		return rc;
	}

	/* Unhook the record from context if encryption is not failure */
	ctx->open_rec = NULL;
	tls_advance_record_sn(sk, prot, &tls_ctx->tx);
	return rc;
}

static int tls_split_open_record(struct sock *sk, struct tls_rec *from,
				 struct tls_rec **to, struct sk_msg *msg_opl,
				 struct sk_msg *msg_oen, u32 split_point,
				 u32 tx_overhead_size, u32 *orig_end)
{
	u32 i, j, bytes = 0, apply = msg_opl->apply_bytes;
	struct scatterlist *sge, *osge, *nsge;
	u32 orig_size = msg_opl->sg.size;
	struct scatterlist tmp = { };
	struct sk_msg *msg_npl;
	struct tls_rec *new;
	int ret;

	new = tls_get_rec(sk);
	if (!new)
		return -ENOMEM;
	ret = sk_msg_alloc(sk, &new->msg_encrypted, msg_opl->sg.size +
			   tx_overhead_size, 0);
	if (ret < 0) {
		tls_free_rec(sk, new);
		return ret;
	}

	*orig_end = msg_opl->sg.end;
	i = msg_opl->sg.start;
	sge = sk_msg_elem(msg_opl, i);
	while (apply && sge->length) {
		if (sge->length > apply) {
			u32 len = sge->length - apply;

			get_page(sg_page(sge));
			sg_set_page(&tmp, sg_page(sge), len,
				    sge->offset + apply);
			sge->length = apply;
			bytes += apply;
			apply = 0;
		} else {
			apply -= sge->length;
			bytes += sge->length;
		}

		sk_msg_iter_var_next(i);
		if (i == msg_opl->sg.end)
			break;
		sge = sk_msg_elem(msg_opl, i);
	}

	msg_opl->sg.end = i;
	msg_opl->sg.curr = i;
	msg_opl->sg.copybreak = 0;
	msg_opl->apply_bytes = 0;
	msg_opl->sg.size = bytes;

	msg_npl = &new->msg_plaintext;
	msg_npl->apply_bytes = apply;
	msg_npl->sg.size = orig_size - bytes;

	j = msg_npl->sg.start;
	nsge = sk_msg_elem(msg_npl, j);
	if (tmp.length) {
		memcpy(nsge, &tmp, sizeof(*nsge));
		sk_msg_iter_var_next(j);
		nsge = sk_msg_elem(msg_npl, j);
	}

	osge = sk_msg_elem(msg_opl, i);
	while (osge->length) {
		memcpy(nsge, osge, sizeof(*nsge));
		sg_unmark_end(nsge);
		sk_msg_iter_var_next(i);
		sk_msg_iter_var_next(j);
		if (i == *orig_end)
			break;
		osge = sk_msg_elem(msg_opl, i);
		nsge = sk_msg_elem(msg_npl, j);
	}

	msg_npl->sg.end = j;
	msg_npl->sg.curr = j;
	msg_npl->sg.copybreak = 0;

	*to = new;
	return 0;
}

extern void tls_merge_open_record(struct sock *sk, struct tls_rec *to,
				  struct tls_rec *from, u32 orig_end);

int klpp_tls_push_record(struct sock *sk, int flags,
			   unsigned char record_type)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_prot_info *prot = &tls_ctx->prot_info;
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct tls_rec *rec = ctx->open_rec, *tmp = NULL;
	u32 i, split_point, orig_end;
	struct sk_msg *msg_pl, *msg_en;
	struct aead_request *req;
	bool split;
	int rc;

	if (!rec)
		return 0;

	msg_pl = &rec->msg_plaintext;
	msg_en = &rec->msg_encrypted;

	split_point = msg_pl->apply_bytes;
	split = split_point && split_point < msg_pl->sg.size;
	if (unlikely((!split &&
		      msg_pl->sg.size +
		      prot->overhead_size > msg_en->sg.size) ||
		     (split &&
		      split_point +
		      prot->overhead_size > msg_en->sg.size))) {
		split = true;
		split_point = msg_en->sg.size;
	}
	if (split) {
		rc = tls_split_open_record(sk, rec, &tmp, msg_pl, msg_en,
					   split_point, prot->overhead_size,
					   &orig_end);
		if (rc < 0)
			return rc;
		/* This can happen if above tls_split_open_record allocates
		 * a single large encryption buffer instead of two smaller
		 * ones. In this case adjust pointers and continue without
		 * split.
		 */
		if (!msg_pl->sg.size) {
			tls_merge_open_record(sk, rec, tmp, orig_end);
			msg_pl = &rec->msg_plaintext;
			msg_en = &rec->msg_encrypted;
			split = false;
		}
		sk_msg_trim(sk, msg_en, msg_pl->sg.size +
			    prot->overhead_size);
	}

	rec->tx_flags = flags;
	req = &rec->aead_req;

	i = msg_pl->sg.end;
	sk_msg_iter_var_prev(i);

	rec->content_type = record_type;
	if (prot->version == TLS_1_3_VERSION) {
		/* Add content type to end of message.  No padding added */
		sg_set_buf(&rec->sg_content_type, &rec->content_type, 1);
		sg_mark_end(&rec->sg_content_type);
		sg_chain(msg_pl->sg.data, msg_pl->sg.end + 1,
			 &rec->sg_content_type);
	} else {
		sg_mark_end(sk_msg_elem(msg_pl, i));
	}

	if (msg_pl->sg.end < msg_pl->sg.start) {
		sg_chain(&msg_pl->sg.data[msg_pl->sg.start],
			 MAX_SKB_FRAGS - msg_pl->sg.start + 1,
			 msg_pl->sg.data);
	}

	i = msg_pl->sg.start;
	sg_chain(rec->sg_aead_in, 2, &msg_pl->sg.data[i]);

	i = msg_en->sg.end;
	sk_msg_iter_var_prev(i);
	sg_mark_end(sk_msg_elem(msg_en, i));

	i = msg_en->sg.start;
	sg_chain(rec->sg_aead_out, 2, &msg_en->sg.data[i]);

	tls_make_aad(rec->aad_space, msg_pl->sg.size + prot->tail_size,
		     tls_ctx->tx.rec_seq, record_type, prot);

	tls_fill_prepend(tls_ctx,
			 page_address(sg_page(&msg_en->sg.data[i])) +
			 msg_en->sg.data[i].offset,
			 msg_pl->sg.size + prot->tail_size,
			 record_type);

	tls_ctx->pending_open_record_frags = false;

	rc = klpp_tls_do_encryption(sk, tls_ctx, ctx, req,
			       msg_pl->sg.size + prot->tail_size, i);
	if (rc < 0) {
		if (rc != -EINPROGRESS) {
			tls_err_abort(sk, -EBADMSG);
			if (split) {
				tls_ctx->pending_open_record_frags = true;
				tls_merge_open_record(sk, rec, tmp, orig_end);
			}
		}
		ctx->async_capable = 1;
		return rc;
	} else if (split) {
		msg_pl = &tmp->msg_plaintext;
		msg_en = &tmp->msg_encrypted;
		sk_msg_trim(sk, msg_en, msg_pl->sg.size + prot->overhead_size);
		tls_ctx->pending_open_record_frags = true;
		ctx->open_rec = tmp;
	}

	return tls_tx_records(sk, flags);
}


#include "livepatch_bsc1262759.h"

#include <linux/livepatch.h>

extern typeof(tls_encrypt_async_wait) tls_encrypt_async_wait
	 KLP_RELOC_SYMBOL(tls, tls, tls_encrypt_async_wait);
extern typeof(tls_encrypt_done) tls_encrypt_done
	 KLP_RELOC_SYMBOL(tls, tls, tls_encrypt_done);
extern typeof(tls_err_abort) tls_err_abort
	 KLP_RELOC_SYMBOL(tls, tls, tls_err_abort);
extern typeof(tls_free_rec) tls_free_rec
	 KLP_RELOC_SYMBOL(tls, tls, tls_free_rec);
extern typeof(tls_get_rec) tls_get_rec KLP_RELOC_SYMBOL(tls, tls, tls_get_rec);
extern typeof(tls_merge_open_record) tls_merge_open_record
	 KLP_RELOC_SYMBOL(tls, tls, tls_merge_open_record);
extern typeof(tls_tx_records) tls_tx_records
	 KLP_RELOC_SYMBOL(tls, tls, tls_tx_records);
