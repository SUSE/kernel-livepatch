/*
 * livepatch_bsc1277768
 *
 * Fix for CVE-2026-74588, bsc#1277768
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


#include "livepatch_bsc1277768.h"


/* klp-ccp: from net/sctp/outqueue.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/list.h>   /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/slab.h>
#include <net/sock.h>	  /* For skb_set_owner_w */

#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/stream_sched.h>
#include <trace/events/sctp.h>
static inline void sctp_outq_head_data(struct sctp_outq *q,
				       struct sctp_chunk *ch)
{
	struct sctp_stream_out_ext *oute;
	__u16 stream;

	list_add(&ch->list, &q->out_chunk_list);
	q->out_qlen += ch->skb->len;

	stream = sctp_chunk_stream_no(ch);
	oute = SCTP_SO(&q->asoc->stream, stream)->ext;
	list_add(&ch->stream_list, &oute->outq);
}

static inline struct sctp_chunk *sctp_outq_dequeue_data(struct sctp_outq *q)
{
	return q->sched->dequeue(q);
}

extern void sctp_insert_list(struct list_head *head, struct list_head *new);

static int klpp___sctp_outq_flush_rtx(struct sctp_outq *q, struct sctp_packet *pkt,
				 int rtx_timeout, int *start_timer, gfp_t gfp)
{
	struct sctp_transport *transport = pkt->transport;
	struct sctp_chunk *chunk, *chunk1;
	struct list_head *lqueue;
	enum sctp_xmit status;
	int error = 0;
	int timer = 0;
	int done = 0;
	int fast_rtx;

	lqueue = &q->retransmit;
	fast_rtx = q->fast_rtx;

	/* This loop handles time-out retransmissions, fast retransmissions,
	 * and retransmissions due to opening of whindow.
	 *
	 * RFC 2960 6.3.3 Handle T3-rtx Expiration
	 *
	 * E3) Determine how many of the earliest (i.e., lowest TSN)
	 * outstanding DATA chunks for the address for which the
	 * T3-rtx has expired will fit into a single packet, subject
	 * to the MTU constraint for the path corresponding to the
	 * destination transport address to which the retransmission
	 * is being sent (this may be different from the address for
	 * which the timer expires [see Section 6.4]). Call this value
	 * K. Bundle and retransmit those K DATA chunks in a single
	 * packet to the destination endpoint.
	 *
	 * [Just to be painfully clear, if we are retransmitting
	 * because a timeout just happened, we should send only ONE
	 * packet of retransmitted data.]
	 *
	 * For fast retransmissions we also send only ONE packet.  However,
	 * if we are just flushing the queue due to open window, we'll
	 * try to send as much as possible.
	 */
	list_for_each_entry_safe(chunk, chunk1, lqueue, transmitted_list) {
		/* If the chunk is abandoned, move it to abandoned list. */
		if (sctp_chunk_abandoned(chunk)) {
			list_del_init(&chunk->transmitted_list);
			sctp_insert_list(&q->abandoned,
					 &chunk->transmitted_list);
			continue;
		}

		/* Make sure that Gap Acked TSNs are not retransmitted.  A
		 * simple approach is just to move such TSNs out of the
		 * way and into a 'transmitted' queue and skip to the
		 * next chunk.
		 */
		if (chunk->tsn_gap_acked) {
			list_move_tail(&chunk->transmitted_list,
				       &transport->transmitted);
			chunk->transport = transport;
			continue;
		}

		/* If we are doing fast retransmit, ignore non-fast_rtransmit
		 * chunks
		 */
		if (fast_rtx && !chunk->fast_retransmit)
			continue;

redo:
		/* Attempt to append this chunk to the packet. */
		status = sctp_packet_append_chunk(pkt, chunk);

		switch (status) {
		case SCTP_XMIT_PMTU_FULL:
			if (!pkt->has_data && !pkt->has_cookie_echo) {
				/* If this packet did not contain DATA then
				 * retransmission did not happen, so do it
				 * again.  We'll ignore the error here since
				 * control chunks are already freed so there
				 * is nothing we can do.
				 */
				sctp_packet_transmit(pkt, gfp);
				goto redo;
			}

			/* Send this packet.  */
			error = sctp_packet_transmit(pkt, gfp);

			/* If we are retransmitting, we should only
			 * send a single packet.
			 * Otherwise, try appending this chunk again.
			 */
			if (rtx_timeout || fast_rtx)
				done = 1;
			else
				goto redo;

			/* Bundle next chunk in the next round.  */
			break;

		case SCTP_XMIT_RWND_FULL:
			/* Send this packet. */
			error = sctp_packet_transmit(pkt, gfp);

			/* Stop sending DATA as there is no more room
			 * at the receiver.
			 */
			done = 1;
			break;

		case SCTP_XMIT_DELAY:
			/* Send this packet. */
			error = sctp_packet_transmit(pkt, gfp);

			/* Stop sending DATA because of nagle delay. */
			done = 1;
			break;

		default:
			/* The append was successful, so add this chunk to
			 * the transmitted list.
			 */
			list_move_tail(&chunk->transmitted_list,
				       &transport->transmitted);

			/* Mark the chunk as ineligible for fast retransmit
			 * after it is retransmitted.
			 */
			if (chunk->fast_retransmit == SCTP_NEED_FRTX)
				chunk->fast_retransmit = SCTP_DONT_FRTX;

			q->asoc->stats.rtxchunks++;
			break;
		}

		/* Set the timer if there were no errors */
		if (!error && !timer)
			timer = 1;

		if (done)
			break;
	}

	/* If we are here due to a retransmit timeout or a fast
	 * retransmit and if there are any chunks left in the retransmit
	 * queue that could not fit in the PMTU sized packet, they need
	 * to be marked as ineligible for a subsequent fast retransmit.
	 */
	if (rtx_timeout || fast_rtx) {
		list_for_each_entry(chunk1, lqueue, transmitted_list) {
			if (chunk1->fast_retransmit == SCTP_NEED_FRTX)
				chunk1->fast_retransmit = SCTP_DONT_FRTX;
		}
	}

	*start_timer = timer;

	/* Clear fast retransmit hint */
	if (fast_rtx)
		q->fast_rtx = 0;

	return error;
}

extern int sctp_packet_singleton(struct sctp_transport *transport,
				 struct sctp_chunk *chunk, gfp_t gfp);

struct sctp_flush_ctx {
	struct sctp_outq *q;
	/* Current transport being used. It's NOT the same as curr active one */
	struct sctp_transport *transport;
	/* These transports have chunks to send. */
	struct list_head transport_list;
	struct sctp_association *asoc;
	/* Packet on the current transport above */
	struct sctp_packet *packet;
	gfp_t gfp;
};

extern void sctp_outq_select_transport(struct sctp_flush_ctx *ctx,
				       struct sctp_chunk *chunk);

static void sctp_outq_flush_ctrl(struct sctp_flush_ctx *ctx)
{
	struct sctp_chunk *chunk, *tmp;
	enum sctp_xmit status;
	int one_packet, error;

	list_for_each_entry_safe(chunk, tmp, &ctx->q->control_chunk_list, list) {
		one_packet = 0;

		/* RFC 5061, 5.3
		 * F1) This means that until such time as the ASCONF
		 * containing the add is acknowledged, the sender MUST
		 * NOT use the new IP address as a source for ANY SCTP
		 * packet except on carrying an ASCONF Chunk.
		 */
		if (ctx->asoc->src_out_of_asoc_ok &&
		    chunk->chunk_hdr->type != SCTP_CID_ASCONF)
			continue;

		list_del_init(&chunk->list);

		/* Pick the right transport to use. Should always be true for
		 * the first chunk as we don't have a transport by then.
		 */
		sctp_outq_select_transport(ctx, chunk);

		switch (chunk->chunk_hdr->type) {
		/* 6.10 Bundling
		 *   ...
		 *   An endpoint MUST NOT bundle INIT, INIT ACK or SHUTDOWN
		 *   COMPLETE with any other chunks.  [Send them immediately.]
		 */
		case SCTP_CID_INIT:
		case SCTP_CID_INIT_ACK:
		case SCTP_CID_SHUTDOWN_COMPLETE:
			error = sctp_packet_singleton(ctx->transport, chunk,
						      ctx->gfp);
			if (error < 0) {
				ctx->asoc->base.sk->sk_err = -error;
				return;
			}
			ctx->asoc->stats.octrlchunks++;
			break;

		case SCTP_CID_ABORT:
			if (sctp_test_T_bit(chunk))
				ctx->packet->vtag = ctx->asoc->c.my_vtag;
			fallthrough;

		/* The following chunks are "response" chunks, i.e.
		 * they are generated in response to something we
		 * received.  If we are sending these, then we can
		 * send only 1 packet containing these chunks.
		 */
		case SCTP_CID_HEARTBEAT_ACK:
		case SCTP_CID_SHUTDOWN_ACK:
		case SCTP_CID_COOKIE_ACK:
		case SCTP_CID_COOKIE_ECHO:
		case SCTP_CID_ERROR:
		case SCTP_CID_ECN_CWR:
		case SCTP_CID_ASCONF_ACK:
			one_packet = 1;
			fallthrough;

		case SCTP_CID_HEARTBEAT:
			if (chunk->pmtu_probe) {
				error = sctp_packet_singleton(ctx->transport,
							      chunk, ctx->gfp);
				if (!error)
					ctx->asoc->stats.octrlchunks++;
				break;
			}
			fallthrough;
		case SCTP_CID_SACK:
		case SCTP_CID_SHUTDOWN:
		case SCTP_CID_ECN_ECNE:
		case SCTP_CID_ASCONF:
		case SCTP_CID_FWD_TSN:
		case SCTP_CID_I_FWD_TSN:
		case SCTP_CID_RECONF:
			status = sctp_packet_transmit_chunk(ctx->packet, chunk,
							    one_packet, ctx->gfp);
			if (status != SCTP_XMIT_OK) {
				/* put the chunk back */
				list_add(&chunk->list, &ctx->q->control_chunk_list);
				break;
			}

			ctx->asoc->stats.octrlchunks++;
			/* PR-SCTP C5) If a FORWARD TSN is sent, the
			 * sender MUST assure that at least one T3-rtx
			 * timer is running.
			 */
			if (chunk->chunk_hdr->type == SCTP_CID_FWD_TSN ||
			    chunk->chunk_hdr->type == SCTP_CID_I_FWD_TSN) {
				sctp_transport_reset_t3_rtx(ctx->transport);
				ctx->transport->last_time_sent = jiffies;
			}

			if (chunk == ctx->asoc->strreset_chunk)
				sctp_transport_reset_reconf_timer(ctx->transport);

			break;

		default:
			/* We built a chunk with an illegal type! */
			BUG();
		}
	}
}

static bool klpp_sctp_outq_flush_rtx(struct sctp_flush_ctx *ctx,
				int rtx_timeout)
{
	int error, start_timer = 0;

	if (ctx->asoc->peer.retran_path->state == SCTP_UNCONFIRMED)
		return false;

	if (ctx->transport != ctx->asoc->peer.retran_path) {
		/* Switch transports & prepare the packet.  */
		ctx->transport = ctx->asoc->peer.retran_path;
		ctx->packet = &ctx->transport->packet;

		if (list_empty(&ctx->transport->send_ready))
			list_add_tail(&ctx->transport->send_ready,
				      &ctx->transport_list);

		sctp_packet_config(ctx->packet, ctx->asoc->peer.i.init_tag,
				   ctx->asoc->peer.ecn_capable);
	}

	error = klpp___sctp_outq_flush_rtx(ctx->q, ctx->packet, rtx_timeout,
				      &start_timer, ctx->gfp);
	if (error < 0)
		ctx->asoc->base.sk->sk_err = -error;

	if (start_timer) {
		sctp_transport_reset_t3_rtx(ctx->transport);
		ctx->transport->last_time_sent = jiffies;
	}

	/* This can happen on COOKIE-ECHO resend.  Only
	 * one chunk can get bundled with a COOKIE-ECHO.
	 */
	if (ctx->packet->has_cookie_echo)
		return false;

	/* Don't send new data if there is still data
	 * waiting to retransmit.
	 */
	if (!list_empty(&ctx->q->retransmit))
		return false;

	return true;
}

static void klpr_sctp_outq_flush_data(struct sctp_flush_ctx *ctx,
				 int rtx_timeout)
{
	struct sctp_chunk *chunk;
	enum sctp_xmit status;

	/* Is it OK to send data chunks?  */
	switch (ctx->asoc->state) {
	case SCTP_STATE_COOKIE_ECHOED:
		/* Only allow bundling when this packet has a COOKIE-ECHO
		 * chunk.
		 */
		if (!ctx->packet || !ctx->packet->has_cookie_echo)
			return;

		fallthrough;
	case SCTP_STATE_ESTABLISHED:
	case SCTP_STATE_SHUTDOWN_PENDING:
	case SCTP_STATE_SHUTDOWN_RECEIVED:
		break;

	default:
		/* Do nothing. */
		return;
	}

	/* RFC 2960 6.1  Transmission of DATA Chunks
	 *
	 * C) When the time comes for the sender to transmit,
	 * before sending new DATA chunks, the sender MUST
	 * first transmit any outstanding DATA chunks which
	 * are marked for retransmission (limited by the
	 * current cwnd).
	 */
	if (!list_empty(&ctx->q->retransmit) &&
	    !klpp_sctp_outq_flush_rtx(ctx, rtx_timeout))
		return;

	/* Apply Max.Burst limitation to the current transport in
	 * case it will be used for new data.  We are going to
	 * rest it before we return, but we want to apply the limit
	 * to the currently queued data.
	 */
	if (ctx->transport)
		sctp_transport_burst_limited(ctx->transport);

	/* Finally, transmit new packets.  */
	while ((chunk = sctp_outq_dequeue_data(ctx->q)) != NULL) {
		__u32 sid = ntohs(chunk->subh.data_hdr->stream);
		__u8 stream_state = SCTP_SO(&ctx->asoc->stream, sid)->state;

		/* Has this chunk expired? */
		if (sctp_chunk_abandoned(chunk)) {
			sctp_sched_dequeue_done(ctx->q, chunk);
			sctp_chunk_fail(chunk, 0);
			sctp_chunk_free(chunk);
			continue;
		}

		if (stream_state == SCTP_STREAM_CLOSED) {
			sctp_outq_head_data(ctx->q, chunk);
			break;
		}

		sctp_outq_select_transport(ctx, chunk);

		pr_debug("%s: outq:%p, chunk:%p[%s], tx-tsn:0x%x skb->head:%p skb->users:%d\n",
			 __func__, ctx->q, chunk, chunk && chunk->chunk_hdr ?
			 sctp_cname(SCTP_ST_CHUNK(chunk->chunk_hdr->type)) :
			 "illegal chunk", ntohl(chunk->subh.data_hdr->tsn),
			 chunk->skb ? chunk->skb->head : NULL, chunk->skb ?
			 refcount_read(&chunk->skb->users) : -1);

		/* Add the chunk to the packet.  */
		status = sctp_packet_transmit_chunk(ctx->packet, chunk, 0,
						    ctx->gfp);
		if (status != SCTP_XMIT_OK) {
			/* We could not append this chunk, so put
			 * the chunk back on the output queue.
			 */
			pr_debug("%s: could not transmit tsn:0x%x, status:%d\n",
				 __func__, ntohl(chunk->subh.data_hdr->tsn),
				 status);

			sctp_outq_head_data(ctx->q, chunk);
			break;
		}

		/* The sender is in the SHUTDOWN-PENDING state,
		 * The sender MAY set the I-bit in the DATA
		 * chunk header.
		 */
		if (ctx->asoc->state == SCTP_STATE_SHUTDOWN_PENDING)
			chunk->chunk_hdr->flags |= SCTP_DATA_SACK_IMM;
		if (chunk->chunk_hdr->flags & SCTP_DATA_UNORDERED)
			ctx->asoc->stats.ouodchunks++;
		else
			ctx->asoc->stats.oodchunks++;

		/* Only now it's safe to consider this
		 * chunk as sent, sched-wise.
		 */
		sctp_sched_dequeue_done(ctx->q, chunk);

		list_add_tail(&chunk->transmitted_list,
			      &ctx->transport->transmitted);

		sctp_transport_reset_t3_rtx(ctx->transport);
		ctx->transport->last_time_sent = jiffies;

		/* Only let one DATA chunk get bundled with a
		 * COOKIE-ECHO chunk.
		 */
		if (ctx->packet->has_cookie_echo)
			break;
	}
}

static void sctp_outq_flush_transports(struct sctp_flush_ctx *ctx)
{
	struct sock *sk = ctx->asoc->base.sk;
	struct list_head *ltransport;
	struct sctp_packet *packet;
	struct sctp_transport *t;
	int error = 0;

	while ((ltransport = sctp_list_dequeue(&ctx->transport_list)) != NULL) {
		t = list_entry(ltransport, struct sctp_transport, send_ready);
		packet = &t->packet;
		if (!sctp_packet_empty(packet)) {
			rcu_read_lock();
			if (t->dst && __sk_dst_get(sk) != t->dst) {
				dst_hold(t->dst);
				sk_setup_caps(sk, t->dst);
			}
			rcu_read_unlock();
			error = sctp_packet_transmit(packet, ctx->gfp);
			if (error < 0)
				ctx->q->asoc->base.sk->sk_err = -error;
		}

		/* Clear the burst limited state, if any */
		sctp_transport_burst_reset(t);
	}
}

void klpp_sctp_outq_flush(struct sctp_outq *q, int rtx_timeout, gfp_t gfp)
{
	struct sctp_flush_ctx ctx = {
		.q = q,
		.transport = NULL,
		.transport_list = LIST_HEAD_INIT(ctx.transport_list),
		.asoc = q->asoc,
		.packet = NULL,
		.gfp = gfp,
	};

	/* 6.10 Bundling
	 *   ...
	 *   When bundling control chunks with DATA chunks, an
	 *   endpoint MUST place control chunks first in the outbound
	 *   SCTP packet.  The transmitter MUST transmit DATA chunks
	 *   within a SCTP packet in increasing order of TSN.
	 *   ...
	 */

	sctp_outq_flush_ctrl(&ctx);

	if (q->asoc->src_out_of_asoc_ok)
		goto sctp_flush_out;

	klpr_sctp_outq_flush_data(&ctx, rtx_timeout);

sctp_flush_out:

	sctp_outq_flush_transports(&ctx);
}


#include <linux/livepatch.h>

extern typeof(sctp_chunk_abandoned) sctp_chunk_abandoned
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_chunk_abandoned);
extern typeof(sctp_chunk_fail) sctp_chunk_fail
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_chunk_fail);
extern typeof(sctp_chunk_free) sctp_chunk_free
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_chunk_free);
extern typeof(sctp_cname) sctp_cname KLP_RELOC_SYMBOL(sctp, sctp, sctp_cname);
extern typeof(sctp_insert_list) sctp_insert_list
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_insert_list);
extern typeof(sctp_outq_select_transport) sctp_outq_select_transport
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_outq_select_transport);
extern typeof(sctp_packet_append_chunk) sctp_packet_append_chunk
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_packet_append_chunk);
extern typeof(sctp_packet_config) sctp_packet_config
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_packet_config);
extern typeof(sctp_packet_singleton) sctp_packet_singleton
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_packet_singleton);
extern typeof(sctp_packet_transmit) sctp_packet_transmit
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_packet_transmit);
extern typeof(sctp_packet_transmit_chunk) sctp_packet_transmit_chunk
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_packet_transmit_chunk);
extern typeof(sctp_sched_dequeue_done) sctp_sched_dequeue_done
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_sched_dequeue_done);
extern typeof(sctp_transport_burst_limited) sctp_transport_burst_limited
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_burst_limited);
extern typeof(sctp_transport_burst_reset) sctp_transport_burst_reset
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_burst_reset);
extern typeof(sctp_transport_reset_reconf_timer)
	 sctp_transport_reset_reconf_timer
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_reset_reconf_timer);
extern typeof(sctp_transport_reset_t3_rtx) sctp_transport_reset_t3_rtx
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_reset_t3_rtx);
