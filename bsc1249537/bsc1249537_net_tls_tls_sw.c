/*
 * bsc1249537_net_tls_tls_sw
 *
 * Fix for CVE-2025-38616, bsc#1249537
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

#include "livepatch_bsc1249537.h"

void tls_strp_check_rcv(struct tls_strparser *strp);

static inline bool tls_strp_msg_ready(struct tls_sw_context_rx *ctx)
{
	return ctx->strp.msg_ready;
}

/* klp-ccp: from net/tls/tls_sw.c */
int
klpp_tls_rx_rec_wait(struct sock *sk, struct sk_psock *psock, bool nonblock,
		bool released)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *ctx = tls_sw_ctx_rx(tls_ctx);
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int ret = 0;
	long timeo;

	timeo = sock_rcvtimeo(sk, nonblock);

	while (!tls_strp_msg_ready(ctx)) {
		if (!sk_psock_queue_empty(psock))
			return 0;

		if (sk->sk_err)
			return sock_error(sk);

		if (ret < 0)
			return ret;

		if (!skb_queue_empty(&sk->sk_receive_queue)) {
			tls_strp_check_rcv(&ctx->strp);
			if (tls_strp_msg_ready(ctx))
				break;
		}

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return 0;

		if (sock_flag(sk, SOCK_DONE))
			return 0;

		if (!timeo)
			return -EAGAIN;

		released = true;
		add_wait_queue(sk_sleep(sk), &wait);
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		ret = sk_wait_event(sk, &timeo,
				    tls_strp_msg_ready(ctx) ||
				    !sk_psock_queue_empty(psock),
				    &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		remove_wait_queue(sk_sleep(sk), &wait);

		/* Handle signals */
		if (signal_pending(current))
			return sock_intr_errno(timeo);
	}

	if (unlikely(!klpp_tls_strp_msg_load(&ctx->strp, released)))
		return klpp_tls_rx_rec_wait(sk, psock, nonblock, false);

	return 1;
}


#include <linux/livepatch.h>

extern typeof(tls_strp_check_rcv) tls_strp_check_rcv
	 KLP_RELOC_SYMBOL(tls, tls, tls_strp_check_rcv);
