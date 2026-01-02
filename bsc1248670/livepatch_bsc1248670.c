/*
 * livepatch_bsc1248670
 *
 * Fix for CVE-2025-38608, bsc#1248670
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

/* klp-ccp: from net/tls/tls_sw.c */
extern void tls_free_rec(struct sock *sk, struct tls_rec *rec);

static void tls_free_open_rec(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct tls_rec *rec = ctx->open_rec;

	if (rec) {
		tls_free_rec(sk, rec);
		ctx->open_rec = NULL;
	}
}

extern int tls_push_record(struct sock *sk, int flags,
			   unsigned char record_type);

int klpp_bpf_exec_tx_verdict(struct sk_msg *msg, struct sock *sk,
			       bool full_record, u8 record_type,
			       ssize_t *copied, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct sk_msg msg_redir = { };
	struct sk_psock *psock;
	struct sock *sk_redir;
	struct tls_rec *rec;
	bool enospc, policy, redir_ingress;
	int err = 0, send;
	u32 delta = 0;

	policy = !(flags & MSG_SENDPAGE_NOPOLICY);
	psock = sk_psock_get(sk);
	if (!psock || !policy) {
		err = tls_push_record(sk, flags, record_type);
		if (err && err != -EINPROGRESS && sk->sk_err == EBADMSG) {
			*copied -= sk_msg_free(sk, msg);
			tls_free_open_rec(sk);
			err = -sk->sk_err;
		}
		if (psock)
			sk_psock_put(sk, psock);
		return err;
	}
more_data:
	enospc = sk_msg_full(msg);
	if (psock->eval == __SK_NONE) {
		delta = msg->sg.size;
		psock->eval = sk_psock_msg_verdict(sk, psock, msg);
		delta -= msg->sg.size;

		if ((s32)delta > 0) {
			/* It indicates that we executed bpf_msg_pop_data(),
			 * causing the plaintext data size to decrease.
			 * Therefore the encrypted data size also needs to
			 * correspondingly decrease. We only need to subtract
			 * delta to calculate the new ciphertext length since
			 * ktls does not support block encryption.
			 */
			struct sk_msg *enc = &ctx->open_rec->msg_encrypted;

			sk_msg_trim(sk, enc, enc->sg.size - delta);
		}
	}
	if (msg->cork_bytes && msg->cork_bytes > msg->sg.size &&
	    !enospc && !full_record) {
		err = -ENOSPC;
		goto out_err;
	}
	msg->cork_bytes = 0;
	send = msg->sg.size;
	if (msg->apply_bytes && msg->apply_bytes < send)
		send = msg->apply_bytes;

	switch (psock->eval) {
	case __SK_PASS:
		err = tls_push_record(sk, flags, record_type);
		if (err && err != -EINPROGRESS && sk->sk_err == EBADMSG) {
			*copied -= sk_msg_free(sk, msg);
			tls_free_open_rec(sk);
			err = -sk->sk_err;
			goto out_err;
		}
		break;
	case __SK_REDIRECT:
		redir_ingress = psock->redir_ingress;
		sk_redir = psock->sk_redir;
		memcpy(&msg_redir, msg, sizeof(*msg));
		if (msg->apply_bytes < send)
			msg->apply_bytes = 0;
		else
			msg->apply_bytes -= send;
		sk_msg_return_zero(sk, msg, send);
		msg->sg.size -= send;
		release_sock(sk);
		err = tcp_bpf_sendmsg_redir(sk_redir, redir_ingress,
					    &msg_redir, send, flags);
		lock_sock(sk);
		if (err < 0) {
			*copied -= sk_msg_free_nocharge(sk, &msg_redir);
			msg->sg.size = 0;
		}
		if (msg->sg.size == 0)
			tls_free_open_rec(sk);
		break;
	case __SK_DROP:
	default:
		sk_msg_free_partial(sk, msg, send);
		if (msg->apply_bytes < send)
			msg->apply_bytes = 0;
		else
			msg->apply_bytes -= send;
		if (msg->sg.size == 0)
			tls_free_open_rec(sk);
		*copied -= (send + delta);
		err = -EACCES;
	}

	if (likely(!err)) {
		bool reset_eval = !ctx->open_rec;

		rec = ctx->open_rec;
		if (rec) {
			msg = &rec->msg_plaintext;
			if (!msg->apply_bytes)
				reset_eval = true;
		}
		if (reset_eval) {
			psock->eval = __SK_NONE;
			if (psock->sk_redir) {
				sock_put(psock->sk_redir);
				psock->sk_redir = NULL;
			}
		}
		if (rec)
			goto more_data;
	}
 out_err:
	sk_psock_put(sk, psock);
	return err;
}


#include "livepatch_bsc1248670.h"

#include <linux/livepatch.h>

extern typeof(tls_free_rec) tls_free_rec
	 KLP_RELOC_SYMBOL(tls, tls, tls_free_rec);
extern typeof(tls_push_record) tls_push_record
	 KLP_RELOC_SYMBOL(tls, tls, tls_push_record);
