/*
 * livepatch_bsc1250192
 *
 * Fix for CVE-2025-39682, bsc#1250192
 *
 *  Copyright (c) 2025 SUSE
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

#include <crypto/aead.h>

#include <net/strparser.h>
#include <net/tls.h>

/* klp-ccp: from net/tls/tls.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/skmsg.h>
#include <net/tls.h>
#include <net/tls_prot.h>

void tls_strp_msg_done(struct tls_strparser *strp);

static inline struct tls_msg *tls_msg(struct sk_buff *skb)
{
	struct sk_skb_cb *scb = (struct sk_skb_cb *)skb->cb;

	return &scb->tls;
}

static inline struct sk_buff *tls_strp_msg(struct tls_sw_context_rx *ctx)
{
	DEBUG_NET_WARN_ON_ONCE(!ctx->strp.msg_ready || !ctx->strp.anchor->len);
	return ctx->strp.anchor;
}

static inline bool tls_strp_msg_ready(struct tls_sw_context_rx *ctx)
{
	return ctx->strp.msg_ready;
}

/* klp-ccp: from net/tls/tls_sw.c */
struct tls_decrypt_arg {
	struct_group(inargs,
	bool zc;
	bool async;
	bool async_done;
	u8 tail;
	);

	struct sk_buff *skb;
};

noinline void tls_err_abort(struct sock *sk, int err);

static int tls_decrypt_async_wait(struct tls_sw_context_rx *ctx)
{
	if (!atomic_dec_and_test(&ctx->decrypt_pending))
		crypto_wait_req(-EINPROGRESS, &ctx->async_wait);
	atomic_inc(&ctx->decrypt_pending);

	return ctx->async_wait.err;
}

extern int
tls_rx_rec_wait(struct sock *sk, struct sk_psock *psock, bool nonblock,
		bool released);

extern int tls_rx_one_record(struct sock *sk, struct msghdr *msg,
			     struct tls_decrypt_arg *darg);

extern int tls_record_content_type(struct msghdr *msg, struct tls_msg *tlm,
				   u8 *control);

static void tls_rx_rec_done(struct tls_sw_context_rx *ctx)
{
	tls_strp_msg_done(&ctx->strp);
}

extern int process_rx_list(struct tls_sw_context_rx *ctx,
			   struct msghdr *msg,
			   u8 *control,
			   size_t skip,
			   size_t len,
			   bool is_peek,
			   bool *more);

static bool
tls_read_flush_backlog(struct sock *sk, struct tls_prot_info *prot,
		       size_t len_left, size_t decrypted, ssize_t done,
		       size_t *flushed_at)
{
	size_t max_rec;

	if (len_left <= decrypted)
		return false;

	max_rec = prot->overhead_size - prot->tail_size + TLS_MAX_PAYLOAD_SIZE;
	if (done - *flushed_at < SZ_128K && tcp_inq(sk) > max_rec)
		return false;

	*flushed_at = done;
	return sk_flush_backlog(sk);
}

extern int tls_rx_reader_acquire(struct sock *sk, struct tls_sw_context_rx *ctx,
				 bool nonblock);

static int tls_rx_reader_lock(struct sock *sk, struct tls_sw_context_rx *ctx,
			      bool nonblock)
{
	int err;

	lock_sock(sk);
	err = tls_rx_reader_acquire(sk, ctx, nonblock);
	if (err)
		release_sock(sk);
	return err;
}

static void tls_rx_reader_release(struct sock *sk, struct tls_sw_context_rx *ctx)
{
	if (unlikely(ctx->reader_contended)) {
		if (wq_has_sleeper(&ctx->wq))
			wake_up(&ctx->wq);
		else
			ctx->reader_contended = 0;

		WARN_ON_ONCE(!ctx->reader_present);
	}

	WRITE_ONCE(ctx->reader_present, 0);
}

static void tls_rx_reader_unlock(struct sock *sk, struct tls_sw_context_rx *ctx)
{
	tls_rx_reader_release(sk, ctx);
	release_sock(sk);
}

int klpp_tls_sw_recvmsg(struct sock *sk,
		   struct msghdr *msg,
		   size_t len,
		   int flags,
		   int *addr_len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	struct tls_prot_info *prot = &tls_ctx->prot_info;
	ssize_t decrypted = 0, async_copy_bytes = 0;
	struct sk_psock *psock;
	unsigned char control = 0;
	size_t flushed_at = 0;
	struct strp_msg *rxm;
	struct tls_msg *tlm;
	ssize_t copied = 0;
	ssize_t peeked = 0;
	bool async = false;
	int target, err;
	bool is_kvec = iov_iter_is_kvec(&msg->msg_iter);
	bool is_peek = flags & MSG_PEEK;
	bool rx_more = false;
	bool released = true;
	bool bpf_strp_enabled;
	bool zc_capable;

	if (unlikely(flags & MSG_ERRQUEUE))
		return sock_recv_errqueue(sk, msg, len, SOL_IP, IP_RECVERR);

	err = tls_rx_reader_lock(sk, ctx, flags & MSG_DONTWAIT);
	if (err < 0)
		return err;
	psock = sk_psock_get(sk);
	bpf_strp_enabled = sk_psock_strp_enabled(psock);

	/* If crypto failed the connection is broken */
	err = ctx->async_wait.err;
	if (err)
		goto end;

	/* Process pending decrypted records. It must be non-zero-copy */
	err = process_rx_list(ctx, msg, &control, 0, len, is_peek, &rx_more);
	if (err < 0)
		goto end;

	/* process_rx_list() will set @control if it processed any records */
	copied = err;
	if (len <= copied || rx_more ||
	    (control && control != TLS_RECORD_TYPE_DATA))
		goto end;

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	len = len - copied;

	zc_capable = !bpf_strp_enabled && !is_kvec && !is_peek &&
		ctx->zc_capable;
	decrypted = 0;
	while (len && (decrypted + copied < target || tls_strp_msg_ready(ctx))) {
		struct tls_decrypt_arg darg;
		int to_decrypt, chunk;

		err = tls_rx_rec_wait(sk, psock, flags & MSG_DONTWAIT,
				      released);
		if (err <= 0) {
			if (psock) {
				chunk = sk_msg_recvmsg(sk, psock, msg, len,
						       flags);
				if (chunk > 0) {
					decrypted += chunk;
					len -= chunk;
					continue;
				}
			}
			goto recv_end;
		}

		memset(&darg.inargs, 0, sizeof(darg.inargs));

		rxm = strp_msg(tls_strp_msg(ctx));
		tlm = tls_msg(tls_strp_msg(ctx));

		to_decrypt = rxm->full_len - prot->overhead_size;

		if (zc_capable && to_decrypt <= len &&
		    tlm->control == TLS_RECORD_TYPE_DATA)
			darg.zc = true;

		/* Do not use async mode if record is non-data */
		if (tlm->control == TLS_RECORD_TYPE_DATA && !bpf_strp_enabled)
			darg.async = ctx->async_capable;
		else
			darg.async = false;

		err = tls_rx_one_record(sk, msg, &darg);
		if (err < 0) {
			tls_err_abort(sk, -EBADMSG);
			goto recv_end;
		}

		async |= darg.async;

		/* If the type of records being processed is not known yet,
		 * set it to record type just dequeued. If it is already known,
		 * but does not match the record type just dequeued, go to end.
		 * We always get record type here since for tls1.2, record type
		 * is known just after record is dequeued from stream parser.
		 * For tls1.3, we disable async.
		 */
		err = tls_record_content_type(msg, tls_msg(darg.skb), &control);
		if (err <= 0) {
			DEBUG_NET_WARN_ON_ONCE(darg.zc);
			tls_rx_rec_done(ctx);
put_on_rx_list_err:
			__skb_queue_tail(&ctx->rx_list, darg.skb);
			goto recv_end;
		}

		/* periodically flush backlog, and feed strparser */
		released = tls_read_flush_backlog(sk, prot, len, to_decrypt,
						  decrypted + copied,
						  &flushed_at);

		/* TLS 1.3 may have updated the length by more than overhead */
		rxm = strp_msg(darg.skb);
		chunk = rxm->full_len;
		tls_rx_rec_done(ctx);

		if (!darg.zc) {
			bool partially_consumed = chunk > len;
			struct sk_buff *skb = darg.skb;

			DEBUG_NET_WARN_ON_ONCE(darg.skb == ctx->strp.anchor);

			if (async) {
				/* TLS 1.2-only, to_decrypt must be text len */
				chunk = min_t(int, to_decrypt, len);
				async_copy_bytes += chunk;
put_on_rx_list:
				decrypted += chunk;
				len -= chunk;
				__skb_queue_tail(&ctx->rx_list, skb);
				if (unlikely(control != TLS_RECORD_TYPE_DATA))
					break;
				continue;
			}

			if (bpf_strp_enabled) {
				released = true;
				err = sk_psock_tls_strp_read(psock, skb);
				if (err != __SK_PASS) {
					rxm->offset = rxm->offset + rxm->full_len;
					rxm->full_len = 0;
					if (err == __SK_DROP)
						consume_skb(skb);
					continue;
				}
			}

			if (partially_consumed)
				chunk = len;

			err = skb_copy_datagram_msg(skb, rxm->offset,
						    msg, chunk);
			if (err < 0)
				goto put_on_rx_list_err;

			if (is_peek) {
				peeked += chunk;
				goto put_on_rx_list;
			}

			if (partially_consumed) {
				rxm->offset += chunk;
				rxm->full_len -= chunk;
				goto put_on_rx_list;
			}

			consume_skb(skb);
		}

		decrypted += chunk;
		len -= chunk;

		/* Return full control message to userspace before trying
		 * to parse another message type
		 */
		msg->msg_flags |= MSG_EOR;
		if (control != TLS_RECORD_TYPE_DATA)
			break;
	}

recv_end:
	if (async) {
		int ret;

		/* Wait for all previously submitted records to be decrypted */
		ret = tls_decrypt_async_wait(ctx);
		__skb_queue_purge(&ctx->async_hold);

		if (ret) {
			if (err >= 0 || err == -EINPROGRESS)
				err = ret;
			decrypted = 0;
			goto end;
		}

		/* Drain records from the rx_list & copy if required */
		if (is_peek || is_kvec)
			err = process_rx_list(ctx, msg, &control, copied + peeked,
					      decrypted - peeked, is_peek, NULL);
		else
			err = process_rx_list(ctx, msg, &control, 0,
					      async_copy_bytes, is_peek, NULL);
	}

	copied += decrypted;

end:
	tls_rx_reader_unlock(sk, ctx);
	if (psock)
		sk_psock_put(sk, psock);
	return copied ? : err;
}


#include "livepatch_bsc1250192.h"

#include <linux/livepatch.h>

extern typeof(process_rx_list) process_rx_list
	 KLP_RELOC_SYMBOL(tls, tls, process_rx_list);
extern typeof(tls_err_abort) tls_err_abort
	 KLP_RELOC_SYMBOL(tls, tls, tls_err_abort);
extern typeof(tls_record_content_type) tls_record_content_type
	 KLP_RELOC_SYMBOL(tls, tls, tls_record_content_type);
extern typeof(tls_rx_one_record) tls_rx_one_record
	 KLP_RELOC_SYMBOL(tls, tls, tls_rx_one_record);
extern typeof(tls_rx_reader_acquire) tls_rx_reader_acquire
	 KLP_RELOC_SYMBOL(tls, tls, tls_rx_reader_acquire);
extern typeof(tls_rx_rec_wait) tls_rx_rec_wait
	 KLP_RELOC_SYMBOL(tls, tls, tls_rx_rec_wait);
extern typeof(tls_strp_msg_done) tls_strp_msg_done
	 KLP_RELOC_SYMBOL(tls, tls, tls_strp_msg_done);
