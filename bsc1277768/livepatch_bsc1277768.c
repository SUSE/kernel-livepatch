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

/* klp-ccp: from include/net/sctp/constants.h */
static const char *(*klpe_sctp_cname)(const sctp_subtype_t);

/* klp-ccp: from include/net/sctp/structs.h */
static void (*klpe_sctp_chunk_fail)(struct sctp_chunk *, int error);
static int (*klpe_sctp_chunk_abandoned)(struct sctp_chunk *);

static void (*klpe_sctp_chunk_free)(struct sctp_chunk *);

static void (*klpe_sctp_packet_init)(struct sctp_packet *, struct sctp_transport *,
		      __u16 sport, __u16 dport);
static void (*klpe_sctp_packet_config)(struct sctp_packet *, __u32 vtag, int);
static sctp_xmit_t (*klpe_sctp_packet_transmit_chunk)(struct sctp_packet *,
				       struct sctp_chunk *, int, gfp_t);
static sctp_xmit_t (*klpe_sctp_packet_append_chunk)(struct sctp_packet *,
                                     struct sctp_chunk *);
static int (*klpe_sctp_packet_transmit)(struct sctp_packet *, gfp_t);

static void (*klpe_sctp_transport_reset_t3_rtx)(struct sctp_transport *);

static void (*klpe_sctp_transport_reset_reconf_timer)(struct sctp_transport *transport);

static void (*klpe_sctp_transport_burst_limited)(struct sctp_transport *);
static void (*klpe_sctp_transport_burst_reset)(struct sctp_transport *);

static struct sctp_transport *(*klpe_sctp_assoc_lookup_paddr)(const struct sctp_association *,
					  const union sctp_addr *);

static int (*klpe_sctp_cmp_addr_exact)(const union sctp_addr *ss1,
			const union sctp_addr *ss2);

/* klp-ccp: from net/sctp/outqueue.c */
#include <net/sctp/sm.h>
static inline void sctp_outq_head_data(struct sctp_outq *q,
					struct sctp_chunk *ch)
{
	list_add(&ch->list, &q->out_chunk_list);
	q->out_qlen += ch->skb->len;
}

static inline struct sctp_chunk *sctp_outq_dequeue_data(struct sctp_outq *q)
{
	struct sctp_chunk *ch = NULL;

	if (!list_empty(&q->out_chunk_list)) {
		struct list_head *entry = q->out_chunk_list.next;

		ch = list_entry(entry, struct sctp_chunk, list);
		list_del_init(entry);
		q->out_qlen -= ch->skb->len;
	}
	return ch;
}

static void (*klpe_sctp_insert_list)(struct list_head *head, struct list_head *new);

static int klpp_sctp_outq_flush_rtx(struct sctp_outq *q, struct sctp_packet *pkt,
			       int rtx_timeout, int *start_timer)
{
	struct list_head *lqueue;
	struct sctp_transport *transport = pkt->transport;
	sctp_xmit_t status;
	struct sctp_chunk *chunk, *chunk1;
	int fast_rtx;
	int error = 0;
	int timer = 0;
	int done = 0;

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
		if ((*klpe_sctp_chunk_abandoned)(chunk)) {
			list_del_init(&chunk->transmitted_list);
			(*klpe_sctp_insert_list)(&q->abandoned,
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
		status = (*klpe_sctp_packet_append_chunk)(pkt, chunk);

		switch (status) {
		case SCTP_XMIT_PMTU_FULL:
			if (!pkt->has_data && !pkt->has_cookie_echo) {
				/* If this packet did not contain DATA then
				 * retransmission did not happen, so do it
				 * again.  We'll ignore the error here since
				 * control chunks are already freed so there
				 * is nothing we can do.
				 */
				(*klpe_sctp_packet_transmit)(pkt, GFP_ATOMIC);
				goto redo;
			}

			/* Send this packet.  */
			error = (*klpe_sctp_packet_transmit)(pkt, GFP_ATOMIC);

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
			error = (*klpe_sctp_packet_transmit)(pkt, GFP_ATOMIC);

			/* Stop sending DATA as there is no more room
			 * at the receiver.
			 */
			done = 1;
			break;

		case SCTP_XMIT_DELAY:
			/* Send this packet. */
			error = (*klpe_sctp_packet_transmit)(pkt, GFP_ATOMIC);

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

void klpp_sctp_outq_flush(struct sctp_outq *q, int rtx_timeout, gfp_t gfp)
{
	struct sctp_packet *packet;
	struct sctp_packet singleton;
	struct sctp_association *asoc = q->asoc;
	__u16 sport = asoc->base.bind_addr.port;
	__u16 dport = asoc->peer.port;
	__u32 vtag = asoc->peer.i.init_tag;
	struct sctp_transport *transport = NULL;
	struct sctp_transport *new_transport;
	struct sctp_chunk *chunk, *tmp;
	sctp_xmit_t status;
	int error = 0;
	int start_timer = 0;
	int one_packet = 0;

	/* These transports have chunks to send. */
	struct list_head transport_list;
	struct list_head *ltransport;

	INIT_LIST_HEAD(&transport_list);
	packet = NULL;

	/*
	 * 6.10 Bundling
	 *   ...
	 *   When bundling control chunks with DATA chunks, an
	 *   endpoint MUST place control chunks first in the outbound
	 *   SCTP packet.  The transmitter MUST transmit DATA chunks
	 *   within a SCTP packet in increasing order of TSN.
	 *   ...
	 */

	list_for_each_entry_safe(chunk, tmp, &q->control_chunk_list, list) {
		/* RFC 5061, 5.3
		 * F1) This means that until such time as the ASCONF
		 * containing the add is acknowledged, the sender MUST
		 * NOT use the new IP address as a source for ANY SCTP
		 * packet except on carrying an ASCONF Chunk.
		 */
		if (asoc->src_out_of_asoc_ok &&
		    chunk->chunk_hdr->type != SCTP_CID_ASCONF)
			continue;

		list_del_init(&chunk->list);

		/* Pick the right transport to use. */
		new_transport = chunk->transport;

		if (!new_transport) {
			/*
			 * If we have a prior transport pointer, see if
			 * the destination address of the chunk
			 * matches the destination address of the
			 * current transport.  If not a match, then
			 * try to look up the transport with a given
			 * destination address.  We do this because
			 * after processing ASCONFs, we may have new
			 * transports created.
			 */
			if (transport &&
			    (*klpe_sctp_cmp_addr_exact)(&chunk->dest,
						&transport->ipaddr))
					new_transport = transport;
			else
				new_transport = (*klpe_sctp_assoc_lookup_paddr)(asoc,
								&chunk->dest);

			/* if we still don't have a new transport, then
			 * use the current active path.
			 */
			if (!new_transport)
				new_transport = asoc->peer.active_path;
		} else if ((new_transport->state == SCTP_INACTIVE) ||
			   (new_transport->state == SCTP_UNCONFIRMED) ||
			   (new_transport->state == SCTP_PF)) {
			/* If the chunk is Heartbeat or Heartbeat Ack,
			 * send it to chunk->transport, even if it's
			 * inactive.
			 *
			 * 3.3.6 Heartbeat Acknowledgement:
			 * ...
			 * A HEARTBEAT ACK is always sent to the source IP
			 * address of the IP datagram containing the
			 * HEARTBEAT chunk to which this ack is responding.
			 * ...
			 *
			 * ASCONF_ACKs also must be sent to the source.
			 */
			if (chunk->chunk_hdr->type != SCTP_CID_HEARTBEAT &&
			    chunk->chunk_hdr->type != SCTP_CID_HEARTBEAT_ACK &&
			    chunk->chunk_hdr->type != SCTP_CID_ASCONF_ACK)
				new_transport = asoc->peer.active_path;
		}

		/* Are we switching transports?
		 * Take care of transport locks.
		 */
		if (new_transport != transport) {
			transport = new_transport;
			if (list_empty(&transport->send_ready)) {
				list_add_tail(&transport->send_ready,
					      &transport_list);
			}
			packet = &transport->packet;
			(*klpe_sctp_packet_config)(packet, vtag,
					   asoc->peer.ecn_capable);
		}

		switch (chunk->chunk_hdr->type) {
		/*
		 * 6.10 Bundling
		 *   ...
		 *   An endpoint MUST NOT bundle INIT, INIT ACK or SHUTDOWN
		 *   COMPLETE with any other chunks.  [Send them immediately.]
		 */
		case SCTP_CID_INIT:
		case SCTP_CID_INIT_ACK:
		case SCTP_CID_SHUTDOWN_COMPLETE:
			(*klpe_sctp_packet_init)(&singleton, transport, sport, dport);
			(*klpe_sctp_packet_config)(&singleton, vtag, 0);
			(*klpe_sctp_packet_append_chunk)(&singleton, chunk);
			error = (*klpe_sctp_packet_transmit)(&singleton, gfp);
			if (error < 0) {
				asoc->base.sk->sk_err = -error;
				return;
			}
			break;

		case SCTP_CID_ABORT:
			if (sctp_test_T_bit(chunk)) {
				packet->vtag = asoc->c.my_vtag;
			}
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
			/* Fall through */

		case SCTP_CID_SACK:
		case SCTP_CID_HEARTBEAT:
		case SCTP_CID_SHUTDOWN:
		case SCTP_CID_ECN_ECNE:
		case SCTP_CID_ASCONF:
		case SCTP_CID_FWD_TSN:
		case SCTP_CID_RECONF:
			status = (*klpe_sctp_packet_transmit_chunk)(packet, chunk,
							    one_packet, gfp);
			if (status  != SCTP_XMIT_OK) {
				/* put the chunk back */
				list_add(&chunk->list, &q->control_chunk_list);
				break;
			}

			asoc->stats.octrlchunks++;
			/* PR-SCTP C5) If a FORWARD TSN is sent, the
			 * sender MUST assure that at least one T3-rtx
			 * timer is running.
			 */
			if (chunk->chunk_hdr->type == SCTP_CID_FWD_TSN) {
				(*klpe_sctp_transport_reset_t3_rtx)(transport);
				transport->last_time_sent = jiffies;
			}

			if (chunk == asoc->strreset_chunk)
				(*klpe_sctp_transport_reset_reconf_timer)(transport);

			break;

		default:
			/* We built a chunk with an illegal type! */
			BUG();
		}
	}

	if (q->asoc->src_out_of_asoc_ok)
		goto sctp_flush_out;

	/* Is it OK to send data chunks?  */
	switch (asoc->state) {
	case SCTP_STATE_COOKIE_ECHOED:
		/* Only allow bundling when this packet has a COOKIE-ECHO
		 * chunk.
		 */
		if (!packet || !packet->has_cookie_echo)
			break;

		/* fallthru */
	case SCTP_STATE_ESTABLISHED:
	case SCTP_STATE_SHUTDOWN_PENDING:
	case SCTP_STATE_SHUTDOWN_RECEIVED:
		/*
		 * RFC 2960 6.1  Transmission of DATA Chunks
		 *
		 * C) When the time comes for the sender to transmit,
		 * before sending new DATA chunks, the sender MUST
		 * first transmit any outstanding DATA chunks which
		 * are marked for retransmission (limited by the
		 * current cwnd).
		 */
		if (!list_empty(&q->retransmit)) {
			if (asoc->peer.retran_path->state == SCTP_UNCONFIRMED)
				goto sctp_flush_out;
			if (transport == asoc->peer.retran_path)
				goto retran;

			/* Switch transports & prepare the packet.  */

			transport = asoc->peer.retran_path;

			if (list_empty(&transport->send_ready)) {
				list_add_tail(&transport->send_ready,
					      &transport_list);
			}

			packet = &transport->packet;
			(*klpe_sctp_packet_config)(packet, vtag,
					   asoc->peer.ecn_capable);
		retran:
			error = klpp_sctp_outq_flush_rtx(q, packet,
						    rtx_timeout, &start_timer);
			if (error < 0)
				asoc->base.sk->sk_err = -error;

			if (start_timer) {
				(*klpe_sctp_transport_reset_t3_rtx)(transport);
				transport->last_time_sent = jiffies;
			}

			/* This can happen on COOKIE-ECHO resend.  Only
			 * one chunk can get bundled with a COOKIE-ECHO.
			 */
			if (packet->has_cookie_echo)
				goto sctp_flush_out;

			/* Don't send new data if there is still data
			 * waiting to retransmit.
			 */
			if (!list_empty(&q->retransmit))
				goto sctp_flush_out;
		}

		/* Apply Max.Burst limitation to the current transport in
		 * case it will be used for new data.  We are going to
		 * rest it before we return, but we want to apply the limit
		 * to the currently queued data.
		 */
		if (transport)
			(*klpe_sctp_transport_burst_limited)(transport);

		/* Finally, transmit new packets.  */
		while ((chunk = sctp_outq_dequeue_data(q)) != NULL) {
			__u32 sid = ntohs(chunk->subh.data_hdr->stream);

			/* RFC 2960 6.5 Every DATA chunk MUST carry a valid
			 * stream identifier.
			 */
			if (chunk->sinfo.sinfo_stream >= asoc->stream->outcnt) {

				/* Mark as failed send. */
				(*klpe_sctp_chunk_fail)(chunk, SCTP_ERROR_INV_STRM);
				if (asoc->peer.prsctp_capable &&
				    SCTP_PR_PRIO_ENABLED(chunk->sinfo.sinfo_flags))
					asoc->sent_cnt_removable--;
				(*klpe_sctp_chunk_free)(chunk);
				continue;
			}

			/* Has this chunk expired? */
			if ((*klpe_sctp_chunk_abandoned)(chunk)) {
				(*klpe_sctp_chunk_fail)(chunk, 0);
				(*klpe_sctp_chunk_free)(chunk);
				continue;
			}

			if (asoc->stream->out[sid].state == SCTP_STREAM_CLOSED) {
				sctp_outq_head_data(q, chunk);
				goto sctp_flush_out;
			}

			/* If there is a specified transport, use it.
			 * Otherwise, we want to use the active path.
			 */
			new_transport = chunk->transport;
			if (!new_transport ||
			    ((new_transport->state == SCTP_INACTIVE) ||
			     (new_transport->state == SCTP_UNCONFIRMED) ||
			     (new_transport->state == SCTP_PF)))
				new_transport = asoc->peer.active_path;
			if (new_transport->state == SCTP_UNCONFIRMED) {
				WARN_ONCE(1, "Attempt to send packet on unconfirmed path.");
				(*klpe_sctp_chunk_fail)(chunk, 0);
				(*klpe_sctp_chunk_free)(chunk);
				continue;
			}

			/* Change packets if necessary.  */
			if (new_transport != transport) {
				transport = new_transport;

				/* Schedule to have this transport's
				 * packet flushed.
				 */
				if (list_empty(&transport->send_ready)) {
					list_add_tail(&transport->send_ready,
						      &transport_list);
				}

				packet = &transport->packet;
				(*klpe_sctp_packet_config)(packet, vtag,
						   asoc->peer.ecn_capable);
				/* We've switched transports, so apply the
				 * Burst limit to the new transport.
				 */
				(*klpe_sctp_transport_burst_limited)(transport);
			}

			pr_debug("%s: outq:%p, chunk:%p[%s], tx-tsn:0x%x skb->head:%p "
				 "skb->users:%d\n",
				 __func__, q, chunk, chunk && chunk->chunk_hdr ?
				 (*klpe_sctp_cname)(SCTP_ST_CHUNK(chunk->chunk_hdr->type)) :
				 "illegal chunk", ntohl(chunk->subh.data_hdr->tsn),
				 chunk->skb ? chunk->skb->head : NULL, chunk->skb ?
				 refcount_read(&chunk->skb->users) : -1);

			/* Add the chunk to the packet.  */
			status = (*klpe_sctp_packet_transmit_chunk)(packet, chunk, 0, gfp);

			switch (status) {
			case SCTP_XMIT_PMTU_FULL:
			case SCTP_XMIT_RWND_FULL:
			case SCTP_XMIT_DELAY:
				/* We could not append this chunk, so put
				 * the chunk back on the output queue.
				 */
				pr_debug("%s: could not transmit tsn:0x%x, status:%d\n",
					 __func__, ntohl(chunk->subh.data_hdr->tsn),
					 status);

				sctp_outq_head_data(q, chunk);
				goto sctp_flush_out;

			case SCTP_XMIT_OK:
				/* The sender is in the SHUTDOWN-PENDING state,
				 * The sender MAY set the I-bit in the DATA
				 * chunk header.
				 */
				if (asoc->state == SCTP_STATE_SHUTDOWN_PENDING)
					chunk->chunk_hdr->flags |= SCTP_DATA_SACK_IMM;
				if (chunk->chunk_hdr->flags & SCTP_DATA_UNORDERED)
					asoc->stats.ouodchunks++;
				else
					asoc->stats.oodchunks++;

				break;

			default:
				BUG();
			}

			/* BUG: We assume that the sctp_packet_transmit()
			 * call below will succeed all the time and add the
			 * chunk to the transmitted list and restart the
			 * timers.
			 * It is possible that the call can fail under OOM
			 * conditions.
			 *
			 * Is this really a problem?  Won't this behave
			 * like a lost TSN?
			 */
			list_add_tail(&chunk->transmitted_list,
				      &transport->transmitted);

			(*klpe_sctp_transport_reset_t3_rtx)(transport);
			transport->last_time_sent = jiffies;

			/* Only let one DATA chunk get bundled with a
			 * COOKIE-ECHO chunk.
			 */
			if (packet->has_cookie_echo)
				goto sctp_flush_out;
		}
		break;

	default:
		/* Do nothing.  */
		break;
	}

sctp_flush_out:

	/* Before returning, examine all the transports touched in
	 * this call.  Right now, we bluntly force clear all the
	 * transports.  Things might change after we implement Nagle.
	 * But such an examination is still required.
	 *
	 * --xguo
	 */
	while ((ltransport = sctp_list_dequeue(&transport_list)) != NULL) {
		struct sctp_transport *t = list_entry(ltransport,
						      struct sctp_transport,
						      send_ready);
		packet = &t->packet;
		if (!sctp_packet_empty(packet)) {
			error = (*klpe_sctp_packet_transmit)(packet, gfp);
			if (error < 0)
				asoc->base.sk->sk_err = -error;
		}

		/* Clear the burst limited state, if any */
		(*klpe_sctp_transport_burst_reset)(t);
	}
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_assoc_lookup_paddr", (void *)&klpe_sctp_assoc_lookup_paddr,
	  "sctp" },
	{ "sctp_chunk_abandoned", (void *)&klpe_sctp_chunk_abandoned, "sctp" },
	{ "sctp_chunk_fail", (void *)&klpe_sctp_chunk_fail, "sctp" },
	{ "sctp_chunk_free", (void *)&klpe_sctp_chunk_free, "sctp" },
	{ "sctp_cmp_addr_exact", (void *)&klpe_sctp_cmp_addr_exact, "sctp" },
	{ "sctp_cname", (void *)&klpe_sctp_cname, "sctp" },
	{ "sctp_insert_list", (void *)&klpe_sctp_insert_list, "sctp" },
	{ "sctp_packet_append_chunk", (void *)&klpe_sctp_packet_append_chunk,
	  "sctp" },
	{ "sctp_packet_config", (void *)&klpe_sctp_packet_config, "sctp" },
	{ "sctp_packet_init", (void *)&klpe_sctp_packet_init, "sctp" },
	{ "sctp_packet_transmit", (void *)&klpe_sctp_packet_transmit, "sctp" },
	{ "sctp_packet_transmit_chunk",
	  (void *)&klpe_sctp_packet_transmit_chunk, "sctp" },
	{ "sctp_transport_burst_limited",
	  (void *)&klpe_sctp_transport_burst_limited, "sctp" },
	{ "sctp_transport_burst_reset",
	  (void *)&klpe_sctp_transport_burst_reset, "sctp" },
	{ "sctp_transport_reset_reconf_timer",
	  (void *)&klpe_sctp_transport_reset_reconf_timer, "sctp" },
	{ "sctp_transport_reset_t3_rtx",
	  (void *)&klpe_sctp_transport_reset_t3_rtx, "sctp" },
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

int livepatch_bsc1277768_init(void)
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

void livepatch_bsc1277768_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
