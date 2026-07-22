/*
 * livepatch_bsc1262404
 *
 * Fix for CVE-2026-23240, bsc#1262404
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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


#include "livepatch_bsc1262404.h"


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

#define BIT_DISABLED_CVE_2026_23240 8

struct tls_cipher_desc {
	unsigned int nonce;
	unsigned int iv;
	unsigned int key;
	unsigned int salt;
	unsigned int tag;
	unsigned int rec_seq;
	unsigned int iv_offset;
	unsigned int key_offset;
	unsigned int salt_offset;
	unsigned int rec_seq_offset;
	char *cipher_name;
	bool offloadable;
	size_t crypto_info;
};

#define TLS_CIPHER_MIN TLS_CIPHER_AES_GCM_128
#define TLS_CIPHER_MAX TLS_CIPHER_ARIA_GCM_256
extern const struct tls_cipher_desc tls_cipher_desc[TLS_CIPHER_MAX + 1 - TLS_CIPHER_MIN];

static inline const struct tls_cipher_desc *get_cipher_desc(u16 cipher_type)
{
	if (cipher_type < TLS_CIPHER_MIN || cipher_type > TLS_CIPHER_MAX)
		return NULL;

	return &tls_cipher_desc[cipher_type - TLS_CIPHER_MIN];
}

static inline char *crypto_info_iv(struct tls_crypto_info *crypto_info,
				   const struct tls_cipher_desc *cipher_desc)
{
	return (char *)crypto_info + cipher_desc->iv_offset;
}

static inline char *crypto_info_key(struct tls_crypto_info *crypto_info,
				    const struct tls_cipher_desc *cipher_desc)
{
	return (char *)crypto_info + cipher_desc->key_offset;
}

static inline char *crypto_info_salt(struct tls_crypto_info *crypto_info,
				     const struct tls_cipher_desc *cipher_desc)
{
	return (char *)crypto_info + cipher_desc->salt_offset;
}

static inline char *crypto_info_rec_seq(struct tls_crypto_info *crypto_info,
					const struct tls_cipher_desc *cipher_desc)
{
	return (char *)crypto_info + cipher_desc->rec_seq_offset;
}

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

int init_prot_info(struct tls_prot_info *prot,
		   const struct tls_crypto_info *crypto_info,
		   const struct tls_cipher_desc *cipher_desc);
int klpp_tls_set_sw_offload(struct sock *sk, int tx);
void tls_update_rx_zc_capable(struct tls_context *tls_ctx);

void klpp_tls_sw_cancel_work_tx(struct tls_context *tls_ctx);

int tls_tx_records(struct sock *sk, int flags);

int tls_strp_init(struct tls_strparser *strp, struct sock *sk);

/* klp-ccp: from net/tls/tls_sw.c */
noinline void tls_err_abort(struct sock *sk, int err);

int tls_tx_records(struct sock *sk, int flags);

void klpp_tls_encrypt_done(void *data, int err)
{
	struct tls_sw_context_tx *ctx;
	struct tls_context *tls_ctx;
	struct tls_prot_info *prot;
	struct tls_rec *rec = data;
	struct scatterlist *sge;
	struct sk_msg *msg_en;
	struct sock *sk;

	if (err == -EINPROGRESS) /* see the comment in tls_decrypt_done() */
		return;

	msg_en = &rec->msg_encrypted;

	sk = rec->sk;
	tls_ctx = tls_get_ctx(sk);
	prot = &tls_ctx->prot_info;
	ctx = tls_sw_ctx_tx(tls_ctx);

	sge = sk_msg_elem(msg_en, msg_en->sg.curr);
	sge->offset -= prot->prepend_size;
	sge->length += prot->prepend_size;

	/* Check if error is previously set on socket */
	if (err || sk->sk_err) {
		rec = NULL;

		/* If err is already set on socket, return the same code */
		if (sk->sk_err) {
			ctx->async_wait.err = -sk->sk_err;
		} else {
			ctx->async_wait.err = err;
			tls_err_abort(sk, err);
		}
	}

	if (rec) {
		struct tls_rec *first_rec;

		/* Mark the record as ready for transmission */
		smp_store_mb(rec->tx_ready, true);

		/* If received record is at head of tx_list, schedule tx */
		first_rec = list_first_entry(&ctx->tx_list,
					     struct tls_rec, list);
		if (rec == first_rec) {
			/* Schedule the transmission */
			if (!test_and_set_bit(BIT_TX_SCHEDULED,
					      &ctx->tx_bitmask) &&
			    !test_bit(BIT_DISABLED_CVE_2026_23240, &ctx->tx_bitmask))
			/*    !ctx->tx_work.disabled)*/
				schedule_delayed_work(&ctx->tx_work.work, 1);
		}
	}

	if (atomic_dec_and_test(&ctx->encrypt_pending))
		complete(&ctx->async_wait.completion);
}

extern int tls_sw_push_pending_record(struct sock *sk, int flags);

void klpp_tls_sw_cancel_work_tx(struct tls_context *tls_ctx)
{
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);

	set_bit(BIT_TX_CLOSING, &ctx->tx_bitmask);
	set_bit(BIT_TX_SCHEDULED, &ctx->tx_bitmask);
	/* disable queueing, workaround for missing disable_ */
	set_bit(BIT_DISABLED_CVE_2026_23240, &ctx->tx_bitmask);
	/*ctx->tx_work.disabled = true;*/
	cancel_delayed_work_sync(&ctx->tx_work.work);
}

extern void tx_work_handler(struct work_struct *work);

void klpp_tx_work_handler(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct tx_work *tx_work = container_of(delayed_work,
					       struct tx_work, work);
	struct sock *sk = tx_work->sk;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx;

	if (unlikely(!tls_ctx))
		return;

	ctx = tls_sw_ctx_tx(tls_ctx);
	if (test_bit(BIT_TX_CLOSING, &ctx->tx_bitmask))
		return;

	if (!test_and_clear_bit(BIT_TX_SCHEDULED, &ctx->tx_bitmask))
		return;

	if (mutex_trylock(&tls_ctx->tx_lock)) {
		lock_sock(sk);
		tls_tx_records(sk, -1);
		release_sock(sk);
		mutex_unlock(&tls_ctx->tx_lock);
	} else if (!test_and_set_bit(BIT_TX_SCHEDULED, &ctx->tx_bitmask) &&
		   !test_bit(BIT_DISABLED_CVE_2026_23240, &ctx->tx_bitmask)) {
		   /*!ctx->tx_work.disabled) { */
		/* Someone is holding the tx_lock, they will likely run Tx
		 * and cancel the work on their way out of the lock section.
		 * Schedule a long delay just in case.
		 */
		schedule_delayed_work(&ctx->tx_work.work, msecs_to_jiffies(10));
	}
}

void tls_update_rx_zc_capable(struct tls_context *tls_ctx);

static struct tls_sw_context_tx *klpp_init_ctx_tx(struct tls_context *ctx, struct sock *sk)
{
	struct tls_sw_context_tx *sw_ctx_tx;

	if (!ctx->priv_ctx_tx) {
		sw_ctx_tx = kzalloc(sizeof(*sw_ctx_tx), GFP_KERNEL);
		if (!sw_ctx_tx)
			return NULL;
	} else {
		sw_ctx_tx = ctx->priv_ctx_tx;
	}

	crypto_init_wait(&sw_ctx_tx->async_wait);
	atomic_set(&sw_ctx_tx->encrypt_pending, 1);
	INIT_LIST_HEAD(&sw_ctx_tx->tx_list);
	clear_bit(BIT_DISABLED_CVE_2026_23240, &sw_ctx_tx->tx_bitmask);
	/* sw_ctx_tx->tx_work.disabled = false;*/
	INIT_DELAYED_WORK(&sw_ctx_tx->tx_work.work, tx_work_handler);
	sw_ctx_tx->tx_work.sk = sk;

	return sw_ctx_tx;
}

static struct tls_sw_context_rx *init_ctx_rx(struct tls_context *ctx)
{
	struct tls_sw_context_rx *sw_ctx_rx;

	if (!ctx->priv_ctx_rx) {
		sw_ctx_rx = kzalloc(sizeof(*sw_ctx_rx), GFP_KERNEL);
		if (!sw_ctx_rx)
			return NULL;
	} else {
		sw_ctx_rx = ctx->priv_ctx_rx;
	}

	crypto_init_wait(&sw_ctx_rx->async_wait);
	atomic_set(&sw_ctx_rx->decrypt_pending, 1);
	init_waitqueue_head(&sw_ctx_rx->wq);
	skb_queue_head_init(&sw_ctx_rx->rx_list);
	skb_queue_head_init(&sw_ctx_rx->async_hold);

	return sw_ctx_rx;
}

int init_prot_info(struct tls_prot_info *prot,
		   const struct tls_crypto_info *crypto_info,
		   const struct tls_cipher_desc *cipher_desc);

int klpp_tls_set_sw_offload(struct sock *sk, int tx)
{
	struct tls_sw_context_tx *sw_ctx_tx = NULL;
	struct tls_sw_context_rx *sw_ctx_rx = NULL;
	const struct tls_cipher_desc *cipher_desc;
	struct tls_crypto_info *crypto_info;
	char *iv, *rec_seq, *key, *salt;
	struct cipher_context *cctx;
	struct tls_prot_info *prot;
	struct crypto_aead **aead;
	struct tls_context *ctx;
	struct crypto_tfm *tfm;
	int rc = 0;

	ctx = tls_get_ctx(sk);
	prot = &ctx->prot_info;

	if (tx) {
		ctx->priv_ctx_tx = klpp_init_ctx_tx(ctx, sk);
		if (!ctx->priv_ctx_tx)
			return -ENOMEM;

		sw_ctx_tx = ctx->priv_ctx_tx;
		crypto_info = &ctx->crypto_send.info;
		cctx = &ctx->tx;
		aead = &sw_ctx_tx->aead_send;
	} else {
		ctx->priv_ctx_rx = init_ctx_rx(ctx);
		if (!ctx->priv_ctx_rx)
			return -ENOMEM;

		sw_ctx_rx = ctx->priv_ctx_rx;
		crypto_info = &ctx->crypto_recv.info;
		cctx = &ctx->rx;
		aead = &sw_ctx_rx->aead_recv;
	}

	cipher_desc = get_cipher_desc(crypto_info->cipher_type);
	if (!cipher_desc) {
		rc = -EINVAL;
		goto free_priv;
	}

	rc = init_prot_info(prot, crypto_info, cipher_desc);
	if (rc)
		goto free_priv;

	iv = crypto_info_iv(crypto_info, cipher_desc);
	key = crypto_info_key(crypto_info, cipher_desc);
	salt = crypto_info_salt(crypto_info, cipher_desc);
	rec_seq = crypto_info_rec_seq(crypto_info, cipher_desc);

	memcpy(cctx->iv, salt, cipher_desc->salt);
	memcpy(cctx->iv + cipher_desc->salt, iv, cipher_desc->iv);
	memcpy(cctx->rec_seq, rec_seq, cipher_desc->rec_seq);

	if (!*aead) {
		*aead = crypto_alloc_aead(cipher_desc->cipher_name, 0, 0);
		if (IS_ERR(*aead)) {
			rc = PTR_ERR(*aead);
			*aead = NULL;
			goto free_priv;
		}
	}

	ctx->push_pending_record = tls_sw_push_pending_record;

	rc = crypto_aead_setkey(*aead, key, cipher_desc->key);
	if (rc)
		goto free_aead;

	rc = crypto_aead_setauthsize(*aead, prot->tag_size);
	if (rc)
		goto free_aead;

	if (sw_ctx_rx) {
		tfm = crypto_aead_tfm(sw_ctx_rx->aead_recv);

		tls_update_rx_zc_capable(ctx);
		sw_ctx_rx->async_capable =
			crypto_info->version != TLS_1_3_VERSION &&
			!!(tfm->__crt_alg->cra_flags & CRYPTO_ALG_ASYNC);

		rc = tls_strp_init(&sw_ctx_rx->strp, sk);
		if (rc)
			goto free_aead;
	}

	goto out;

free_aead:
	crypto_free_aead(*aead);
	*aead = NULL;
free_priv:
	if (tx) {
		kfree(ctx->priv_ctx_tx);
		ctx->priv_ctx_tx = NULL;
	} else {
		kfree(ctx->priv_ctx_rx);
		ctx->priv_ctx_rx = NULL;
	}
out:
	return rc;
}


#include <linux/livepatch.h>

extern typeof(init_prot_info) init_prot_info
	 KLP_RELOC_SYMBOL(tls, tls, init_prot_info);
extern typeof(tls_cipher_desc) tls_cipher_desc
	 KLP_RELOC_SYMBOL(tls, tls, tls_cipher_desc);
extern typeof(tls_err_abort) tls_err_abort
	 KLP_RELOC_SYMBOL(tls, tls, tls_err_abort);
extern typeof(tls_strp_init) tls_strp_init
	 KLP_RELOC_SYMBOL(tls, tls, tls_strp_init);
extern typeof(tls_sw_push_pending_record) tls_sw_push_pending_record
	 KLP_RELOC_SYMBOL(tls, tls, tls_sw_push_pending_record);
extern typeof(tls_tx_records) tls_tx_records
	 KLP_RELOC_SYMBOL(tls, tls, tls_tx_records);
extern typeof(tls_update_rx_zc_capable) tls_update_rx_zc_capable
	 KLP_RELOC_SYMBOL(tls, tls, tls_update_rx_zc_capable);
extern typeof(tx_work_handler) tx_work_handler
	 KLP_RELOC_SYMBOL(tls, tls, tx_work_handler);
