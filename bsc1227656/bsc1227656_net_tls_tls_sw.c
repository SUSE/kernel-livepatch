/*
 * bsc1227656_net_tls_tls_sw
 *
 * Fix for CVE-2021-47496, bsc#1227656
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

/* klp-ccp: from include/linux/splice.h */
#define SPLICE_H

#define SPLICE_F_NONBLOCK (0x02) /* don't block on the pipe splicing (but */

/* klp-ccp: from net/tls/tls_sw.c */
#include <crypto/aead.h>

#include <net/strparser.h>

/* klp-ccp: from net/tls/tls_sw.c */
#include <net/tls.h>

/* klp-ccp: from include/net/tls.h */
int klpp_tls_sw_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		   int nonblock, int flags, int *addr_len);

ssize_t klpp_tls_sw_splice_read(struct socket *sock, loff_t *ppos,
			   struct pipe_inode_info *pipe,
			   size_t len, unsigned int flags);

int klpp_tls_tx_records(struct sock *sk, int flags);

static int (*klpe_tls_push_sg)(struct sock *sk, struct tls_context *ctx,
		struct scatterlist *sg, u16 first_offset,
		int flags);
static int (*klpe_tls_push_partial_record)(struct sock *sk, struct tls_context *ctx,
			    int flags);

static int (*klpe_tls_device_decrypted)(struct sock *sk, struct sk_buff *skb);

static void (*klpe_handle_device_resync)(struct sock *sk, u32 seq, u64 rcd_sn);

/* klp-ccp: from net/tls/tls_sw.c */
#define MAX_IV_SIZE	TLS_CIPHER_AES_GCM_128_IV_SIZE

static noinline void klpp_tls_err_abort(struct sock *sk, int err)
{
	WARN_ON_ONCE(err >= 0);
	/* sk->sk_err should contain a positive error code. */
	sk->sk_err = -err;
	sk->sk_error_report(sk);
}

/* manually copied from include/net/tls.h */
static inline void klpp_tls_advance_record_sn(struct sock *sk,
					 struct cipher_context *ctx)
{
	if (tls_bigint_increment(ctx->rec_seq, ctx->rec_seq_size))
		klpp_tls_err_abort(sk, -EBADMSG);
	tls_bigint_increment(ctx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			     ctx->iv_size);
}

void klpp_tls_decrypt_done(struct crypto_async_request *req, int err)
{
	struct aead_request *aead_req = (struct aead_request *)req;
	struct scatterlist *sgout = aead_req->dst;
	struct tls_sw_context_rx *ctx;
	struct tls_context *tls_ctx;
	struct scatterlist *sg;
	struct sk_buff *skb;
	unsigned int pages;
	int pending;

	skb = (struct sk_buff *)req->data;
	tls_ctx = tls_get_ctx(skb->sk);
	ctx = tls_sw_ctx_rx(tls_ctx);
	pending = atomic_dec_return(&ctx->decrypt_pending);

	/* Propagate if there was an err */
	if (err) {
		ctx->async_wait.err = err;
		klpp_tls_err_abort(skb->sk, err);
	}

	/* After using skb->sk to propagate sk through crypto async callback
	 * we need to NULL it again.
	 */
	skb->sk = NULL;

	/* Release the skb, pages and memory allocated for crypto req */
	kfree_skb(skb);

	/* Skip the first S/G entry as it points to AAD */
	for_each_sg(sg_next(sgout), sg, UINT_MAX, pages) {
		if (!sg)
			break;
		put_page(sg_page(sg));
	}

	kfree(aead_req);

	if (!pending && READ_ONCE(ctx->async_notify))
		complete(&ctx->async_wait.completion);
}

static struct tls_rec *(*klpe_tls_get_rec)(struct sock *sk);

static void tls_free_rec(struct sock *sk, struct tls_rec *rec)
{
	sk_msg_free(sk, &rec->msg_encrypted);
	sk_msg_free(sk, &rec->msg_plaintext);
	kfree(rec);
}

int klpp_tls_tx_records(struct sock *sk, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct tls_rec *rec, *tmp;
	struct sk_msg *msg_en;
	int tx_flags, rc = 0;

	if (tls_is_partially_sent_record(tls_ctx)) {
		rec = list_first_entry(&ctx->tx_list,
				       struct tls_rec, list);

		if (flags == -1)
			tx_flags = rec->tx_flags;
		else
			tx_flags = flags;

		rc = (*klpe_tls_push_partial_record)(sk, tls_ctx, tx_flags);
		if (rc)
			goto tx_err;

		/* Full record has been transmitted.
		 * Remove the head of tx_list
		 */
		list_del(&rec->list);
		sk_msg_free(sk, &rec->msg_plaintext);
		kfree(rec);
	}

	/* Tx all ready records */
	list_for_each_entry_safe(rec, tmp, &ctx->tx_list, list) {
		if (READ_ONCE(rec->tx_ready)) {
			if (flags == -1)
				tx_flags = rec->tx_flags;
			else
				tx_flags = flags;

			msg_en = &rec->msg_encrypted;
			rc = (*klpe_tls_push_sg)(sk, tls_ctx,
					 &msg_en->sg.data[msg_en->sg.curr],
					 0, tx_flags);
			if (rc)
				goto tx_err;

			list_del(&rec->list);
			sk_msg_free(sk, &rec->msg_plaintext);
			kfree(rec);
		} else {
			break;
		}
	}

tx_err:
	if (rc < 0 && rc != -EAGAIN)
		klpp_tls_err_abort(sk, -EBADMSG);

	return rc;
}

void klpp_tls_encrypt_done(struct crypto_async_request *req, int err)
{
	struct aead_request *aead_req = (struct aead_request *)req;
	struct sock *sk = req->data;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct scatterlist *sge;
	struct sk_msg *msg_en;
	struct tls_rec *rec;
	int pending;

	rec = container_of(aead_req, struct tls_rec, aead_req);
	msg_en = &rec->msg_encrypted;

	sge = sk_msg_elem(msg_en, msg_en->sg.curr);
	sge->offset -= tls_ctx->tx.prepend_size;
	sge->length += tls_ctx->tx.prepend_size;

	/* Check if error is previously set on socket */
	if (err || sk->sk_err) {
		rec = NULL;

		/* If err is already set on socket, return the same code */
		if (sk->sk_err) {
			ctx->async_wait.err = sk->sk_err;
		} else {
			ctx->async_wait.err = err;
			klpp_tls_err_abort(sk, err);
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
					      &ctx->tx_bitmask))
				schedule_delayed_work(&ctx->tx_work.work, 1);
		}
	}

	pending = atomic_dec_return(&ctx->encrypt_pending);

	if (!pending && READ_ONCE(ctx->async_notify))
		complete(&ctx->async_wait.completion);
}

static int klpr_tls_do_encryption(struct sock *sk,
			     struct tls_context *tls_ctx,
			     struct tls_sw_context_tx *ctx,
			     struct aead_request *aead_req,
			     size_t data_len, u32 start)
{
	struct tls_rec *rec = ctx->open_rec;
	struct sk_msg *msg_en = &rec->msg_encrypted;
	struct scatterlist *sge = sk_msg_elem(msg_en, start);
	int rc;

	memcpy(rec->iv_data, tls_ctx->tx.iv, sizeof(rec->iv_data));

	sge->offset += tls_ctx->tx.prepend_size;
	sge->length -= tls_ctx->tx.prepend_size;

	msg_en->sg.curr = start;

	aead_request_set_tfm(aead_req, ctx->aead_send);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(aead_req, rec->sg_aead_in,
			       rec->sg_aead_out,
			       data_len, rec->iv_data);

	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  klpp_tls_encrypt_done, sk);

	/* Add the record in tx_list */
	list_add_tail((struct list_head *)&rec->list, &ctx->tx_list);
	atomic_inc(&ctx->encrypt_pending);

	rc = crypto_aead_encrypt(aead_req);
	if (!rc || rc != -EINPROGRESS) {
		atomic_dec(&ctx->encrypt_pending);
		sge->offset -= tls_ctx->tx.prepend_size;
		sge->length += tls_ctx->tx.prepend_size;
	}

	if (!rc) {
		WRITE_ONCE(rec->tx_ready, true);
	} else if (rc != -EINPROGRESS) {
		list_del(&rec->list);
		return rc;
	}

	/* Unhook the record from context if encryption is not failure */
	ctx->open_rec = NULL;
	klpp_tls_advance_record_sn(sk, &tls_ctx->tx);
	return rc;
}

static int klpr_tls_split_open_record(struct sock *sk, struct tls_rec *from,
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

	new = (*klpe_tls_get_rec)(sk);
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

static void tls_merge_open_record(struct sock *sk, struct tls_rec *to,
				  struct tls_rec *from, u32 orig_end)
{
	struct sk_msg *msg_npl = &from->msg_plaintext;
	struct sk_msg *msg_opl = &to->msg_plaintext;
	struct scatterlist *osge, *nsge;
	u32 i, j;

	i = msg_opl->sg.end;
	sk_msg_iter_var_prev(i);
	j = msg_npl->sg.start;

	osge = sk_msg_elem(msg_opl, i);
	nsge = sk_msg_elem(msg_npl, j);

	if (sg_page(osge) == sg_page(nsge) &&
	    osge->offset + osge->length == nsge->offset) {
		osge->length += nsge->length;
		put_page(sg_page(nsge));
	}

	msg_opl->sg.end = orig_end;
	msg_opl->sg.curr = orig_end;
	msg_opl->sg.copybreak = 0;
	msg_opl->apply_bytes = msg_opl->sg.size + msg_npl->sg.size;
	msg_opl->sg.size += msg_npl->sg.size;

	sk_msg_free(sk, &to->msg_encrypted);
	sk_msg_xfer_full(&to->msg_encrypted, &from->msg_encrypted);

	kfree(from);
}

int klpp_tls_push_record(struct sock *sk, int flags,
			   unsigned char record_type)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct tls_rec *rec = ctx->open_rec, *tmp = NULL;
	u32 i, split_point, uninitialized_var(orig_end);
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
	if (split) {
		rc = klpr_tls_split_open_record(sk, rec, &tmp, msg_pl, msg_en,
					   split_point, tls_ctx->tx.overhead_size,
					   &orig_end);
		if (rc < 0)
			return rc;
		sk_msg_trim(sk, msg_en, msg_pl->sg.size +
			    tls_ctx->tx.overhead_size);
	}

	rec->tx_flags = flags;
	req = &rec->aead_req;

	i = msg_pl->sg.end;
	sk_msg_iter_var_prev(i);
	sg_mark_end(sk_msg_elem(msg_pl, i));

	i = msg_pl->sg.start;
	sg_chain(rec->sg_aead_in, 2, rec->inplace_crypto ?
		 &msg_en->sg.data[i] : &msg_pl->sg.data[i]);

	i = msg_en->sg.end;
	sk_msg_iter_var_prev(i);
	sg_mark_end(sk_msg_elem(msg_en, i));

	i = msg_en->sg.start;
	sg_chain(rec->sg_aead_out, 2, &msg_en->sg.data[i]);

	tls_make_aad(rec->aad_space, msg_pl->sg.size,
		     tls_ctx->tx.rec_seq, tls_ctx->tx.rec_seq_size,
		     record_type);

	tls_fill_prepend(tls_ctx,
			 page_address(sg_page(&msg_en->sg.data[i])) +
			 msg_en->sg.data[i].offset, msg_pl->sg.size,
			 record_type);

	tls_ctx->pending_open_record_frags = false;

	rc = klpr_tls_do_encryption(sk, tls_ctx, ctx, req, msg_pl->sg.size, i);
	if (rc < 0) {
		if (rc != -EINPROGRESS) {
			klpp_tls_err_abort(sk, -EBADMSG);
			if (split) {
				tls_ctx->pending_open_record_frags = true;
				tls_merge_open_record(sk, rec, tmp, orig_end);
			}
		}
		return rc;
	} else if (split) {
		msg_pl = &tmp->msg_plaintext;
		msg_en = &tmp->msg_encrypted;
		sk_msg_trim(sk, msg_en, msg_pl->sg.size +
			    tls_ctx->tx.overhead_size);
		tls_ctx->pending_open_record_frags = true;
		ctx->open_rec = tmp;
	}

	return klpp_tls_tx_records(sk, flags);
}

static struct sk_buff *(*klpe_tls_wait_data)(struct sock *sk, struct sk_psock *psock,
				     bool nonblock, long timeo, int *err);

static int (*klpe_decrypt_internal)(struct sock *sk, struct sk_buff *skb,
			    struct iov_iter *out_iov,
			    struct scatterlist *out_sg,
			    int *chunk, bool *zc);

int klpp_decrypt_skb_update(struct sock *sk, struct sk_buff *skb,
			      struct iov_iter *dest, int *chunk, bool *zc)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct strp_msg *rxm = strp_msg(skb);
	int err = 0;

#ifdef CONFIG_TLS_DEVICE
	err = (*klpe_tls_device_decrypted)(sk, skb);
	if (err < 0)
		return err;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (!ctx->decrypted) {
		err = (*klpe_decrypt_internal)(sk, skb, dest, NULL, chunk, zc);
		if (err < 0) {
			if (err == -EINPROGRESS)
				klpp_tls_advance_record_sn(sk, &tls_ctx->rx);

			return err;
		}
	} else {
		*zc = false;
	}

	rxm->offset += tls_ctx->rx.prepend_size;
	rxm->full_len -= tls_ctx->rx.overhead_size;
	klpp_tls_advance_record_sn(sk, &tls_ctx->rx);
	ctx->decrypted = true;
	ctx->saved_data_ready(sk);

	return err;
}

static bool (*klpe_tls_sw_advance_skb)(struct sock *sk, struct sk_buff *skb,
			       unsigned int len);

int klpp_tls_sw_recvmsg(struct sock *sk,
		   struct msghdr *msg,
		   size_t len,
		   int nonblock,
		   int flags,
		   int *addr_len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct sk_psock *psock;
	unsigned char control;
	struct strp_msg *rxm;
	struct sk_buff *skb;
	ssize_t copied = 0;
	bool cmsg = false;
	int target, err = 0;
	long timeo;
	bool is_kvec = msg->msg_iter.type & ITER_KVEC;
	int num_async = 0;

	flags |= nonblock;

	if (unlikely(flags & MSG_ERRQUEUE))
		return sock_recv_errqueue(sk, msg, len, SOL_IP, IP_RECVERR);

	psock = sk_psock_get(sk);
	lock_sock(sk);

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	do {
		bool zc = false;
		bool async = false;
		int chunk = 0;

		skb = (*klpe_tls_wait_data)(sk, psock, flags & MSG_DONTWAIT, timeo, &err);
		if (!skb) {
			if (psock) {
				int ret = __tcp_bpf_recvmsg(sk, psock,
							    msg, len, flags);

				if (ret > 0) {
					copied += ret;
					len -= ret;
					continue;
				}
			}
			goto recv_end;
		}

		rxm = strp_msg(skb);

		if (!cmsg) {
			int cerr;

			cerr = put_cmsg(msg, SOL_TLS, TLS_GET_RECORD_TYPE,
					sizeof(ctx->control), &ctx->control);
			cmsg = true;
			control = ctx->control;
			if (ctx->control != TLS_RECORD_TYPE_DATA) {
				if (cerr || msg->msg_flags & MSG_CTRUNC) {
					err = -EIO;
					goto recv_end;
				}
			}
		} else if (control != ctx->control) {
			goto recv_end;
		}

		if (!ctx->decrypted) {
			int to_copy = rxm->full_len - tls_ctx->rx.overhead_size;

			if (!is_kvec && to_copy <= len &&
			    likely(!(flags & MSG_PEEK)))
				zc = true;

			err = klpp_decrypt_skb_update(sk, skb, &msg->msg_iter,
						 &chunk, &zc);
			if (err < 0 && err != -EINPROGRESS) {
				klpp_tls_err_abort(sk, -EBADMSG);
				goto recv_end;
			}

			if (err == -EINPROGRESS) {
				async = true;
				num_async++;
				goto pick_next_record;
			}

			ctx->decrypted = true;
		}

		if (!zc) {
			chunk = min_t(unsigned int, rxm->full_len, len);

			err = skb_copy_datagram_msg(skb, rxm->offset, msg,
						    chunk);
			if (err < 0)
				goto recv_end;
		}

pick_next_record:
		copied += chunk;
		len -= chunk;
		if (likely(!(flags & MSG_PEEK))) {
			u8 control = ctx->control;

			/* For async, drop current skb reference */
			if (async)
				skb = NULL;

			if ((*klpe_tls_sw_advance_skb)(sk, skb, chunk)) {
				/* Return full control message to
				 * userspace before trying to parse
				 * another message type
				 */
				msg->msg_flags |= MSG_EOR;
				if (control != TLS_RECORD_TYPE_DATA)
					goto recv_end;
			} else {
				break;
			}
		} else {
			/* MSG_PEEK right now cannot look beyond current skb
			 * from strparser, meaning we cannot advance skb here
			 * and thus unpause strparser since we'd loose original
			 * one.
			 */
			break;
		}

		/* If we have a new message from strparser, continue now. */
		if (copied >= target && !ctx->recv_pkt)
			break;
	} while (len);

recv_end:
	if (num_async) {
		/* Wait for all previously submitted records to be decrypted */
		smp_store_mb(ctx->async_notify, true);
		if (atomic_read(&ctx->decrypt_pending)) {
			err = crypto_wait_req(-EINPROGRESS, &ctx->async_wait);
			if (err) {
				/* one of async decrypt failed */
				klpp_tls_err_abort(sk, err);
				copied = 0;
			}
		} else {
			reinit_completion(&ctx->async_wait.completion);
		}
		WRITE_ONCE(ctx->async_notify, false);
	}

	release_sock(sk);
	if (psock)
		sk_psock_put(sk, psock);
	return copied ? : err;
}

ssize_t klpp_tls_sw_splice_read(struct socket *sock,  loff_t *ppos,
			   struct pipe_inode_info *pipe,
			   size_t len, unsigned int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sock->sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct strp_msg *rxm = NULL;
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	ssize_t copied = 0;
	int err = 0;
	long timeo;
	int chunk;
	bool zc = false;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & SPLICE_F_NONBLOCK);

	skb = (*klpe_tls_wait_data)(sk, NULL, flags & SPLICE_F_NONBLOCK, timeo, &err);
	if (!skb)
		goto splice_read_end;

	/* splice does not support reading control messages */
	if (ctx->control != TLS_RECORD_TYPE_DATA) {
		err = -ENOTSUPP;
		goto splice_read_end;
	}

	if (!ctx->decrypted) {
		err = klpp_decrypt_skb_update(sk, skb, NULL, &chunk, &zc);

		if (err < 0) {
			klpp_tls_err_abort(sk, -EBADMSG);
			goto splice_read_end;
		}
		ctx->decrypted = true;
	}
	rxm = strp_msg(skb);

	chunk = min_t(unsigned int, rxm->full_len, len);
	copied = skb_splice_bits(skb, sk, rxm->offset, pipe, chunk, flags);
	if (copied < 0)
		goto splice_read_end;

	if (likely(!(flags & MSG_PEEK)))
		(*klpe_tls_sw_advance_skb)(sk, skb, copied);

splice_read_end:
	release_sock(sk);
	return copied ? : err;
}

int klpp_tls_read_size(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_context *tls_ctx = tls_get_ctx(strp->sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	char header[TLS_HEADER_SIZE + MAX_IV_SIZE];
	struct strp_msg *rxm = strp_msg(skb);
	size_t cipher_overhead;
	size_t data_len = 0;
	int ret;

	/* Verify that we have a full TLS header, or wait for more data */
	if (rxm->offset + tls_ctx->rx.prepend_size > skb->len)
		return 0;

	/* Sanity-check size of on-stack buffer. */
	if (WARN_ON(tls_ctx->rx.prepend_size > sizeof(header))) {
		ret = -EINVAL;
		goto read_failure;
	}

	/* Linearize header to local buffer */
	ret = skb_copy_bits(skb, rxm->offset, header, tls_ctx->rx.prepend_size);

	if (ret < 0)
		goto read_failure;

	ctx->control = header[0];

	data_len = ((header[4] & 0xFF) | (header[3] << 8));

	cipher_overhead = tls_ctx->rx.tag_size + tls_ctx->rx.iv_size;

	if (data_len > TLS_MAX_PAYLOAD_SIZE + cipher_overhead) {
		ret = -EMSGSIZE;
		goto read_failure;
	}
	if (data_len < cipher_overhead) {
		ret = -EBADMSG;
		goto read_failure;
	}

	if (header[1] != TLS_VERSION_MINOR(tls_ctx->crypto_recv.info.version) ||
	    header[2] != TLS_VERSION_MAJOR(tls_ctx->crypto_recv.info.version)) {
		ret = -EINVAL;
		goto read_failure;
	}

#ifdef CONFIG_TLS_DEVICE
	(*klpe_handle_device_resync)(strp->sk, TCP_SKB_CB(skb)->seq + rxm->offset,
			     *(u64*)tls_ctx->rx.rec_seq);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return data_len + TLS_HEADER_SIZE;

read_failure:
	klpp_tls_err_abort(strp->sk, ret);

	return ret;
}


#include "livepatch_bsc1227656.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "tls"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "decrypt_internal", (void *)&klpe_decrypt_internal, "tls" },
	{ "handle_device_resync", (void *)&klpe_handle_device_resync, "tls" },
	{ "tls_device_decrypted", (void *)&klpe_tls_device_decrypted, "tls" },
	{ "tls_get_rec", (void *)&klpe_tls_get_rec, "tls" },
	{ "tls_push_partial_record", (void *)&klpe_tls_push_partial_record,
	  "tls" },
	{ "tls_push_sg", (void *)&klpe_tls_push_sg, "tls" },
	{ "tls_sw_advance_skb", (void *)&klpe_tls_sw_advance_skb, "tls" },
	{ "tls_wait_data", (void *)&klpe_tls_wait_data, "tls" },
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

int bsc1227656_net_tls_tls_sw_init(void)
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

void bsc1227656_net_tls_tls_sw_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
