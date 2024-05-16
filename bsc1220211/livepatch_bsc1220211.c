/*
 * livepatch_bsc1220211
 *
 * Fix for CVE-2024-26585, bsc#1220211
 *
 *  Upstream commit:
 *  e01e3934a1b2 ("tls: fix race between tx work scheduling and socket close")
 *
 *  SLE12-SP5 commit:
 *  2d824bed7271bf41ee941c9ede6542cefc98dc0d
 *
 *  SLE15-SP2 and -SP3 commit:
 *  72079991ab5c6cc60f4a63257d2dcdf3deaffcb2
 *
 *  SLE15-SP4 and -SP5 commit:
 *  1306bffd3f2f37da9ab6ec741acaa5b9dcd63529
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <crypto/aead.h>
#include <net/strparser.h>
#include <net/tls.h>

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
					      &ctx->tx_bitmask))
				schedule_delayed_work(&ctx->tx_work.work, 1);
		}
	}

	pending = atomic_dec_return(&ctx->encrypt_pending);

	if (!pending && READ_ONCE(ctx->async_notify))
		complete(&ctx->async_wait.completion);
}


#include "livepatch_bsc1220211.h"

