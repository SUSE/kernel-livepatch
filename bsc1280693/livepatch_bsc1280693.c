/*
 * livepatch_bsc1280693
 *
 * Fix for CVE-2026-74469, bsc#1280693
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


#include "livepatch_bsc1280693.h"

#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>

#include <linux/slab.h>
#include <linux/in.h>
#include <net/ipv6.h>
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/sctp/structs.h */
/* klp-ccp: from net/sctp/associola.c */
#include <net/sctp/sm.h>

void sctp_assoc_set_primary(struct sctp_association *asoc,
			    struct sctp_transport *transport);

struct sctp_transport *klpp_sctp_assoc_add_peer(struct sctp_association *asoc,
					   const union sctp_addr *addr,
					   const gfp_t gfp,
					   const int peer_state)
{
	struct sctp_transport *peer;
	struct sctp_sock *sp;
	unsigned short port;

	sp = sctp_sk(asoc->base.sk);

	/* AF_INET and AF_INET6 share common port field. */
	port = ntohs(addr->v4.sin_port);

	pr_debug("%s: association:%p addr:%pISpc state:%d\n", __func__,
		 asoc, &addr->sa, peer_state);

	/* Set the port if it has not been set yet.  */
	if (0 == asoc->peer.port)
		asoc->peer.port = port;

	/* Check to see if this is a duplicate. */
	peer = sctp_assoc_lookup_paddr(asoc, addr);
	if (peer) {
		/* An UNKNOWN state is only set on transports added by
		 * user in sctp_connectx() call.  Such transports should be
		 * considered CONFIRMED per RFC 4960, Section 5.4.
		 */
		if (peer->state == SCTP_UNKNOWN) {
			peer->state = SCTP_ACTIVE;
		}
		return peer;
	}

	if (asoc->peer.transport_count == U16_MAX)
		return NULL;

	peer = sctp_transport_new(asoc->base.net, addr, gfp);
	if (!peer)
		return NULL;

	sctp_transport_set_owner(peer, asoc);

	/* Initialize the peer's heartbeat interval based on the
	 * association configured value.
	 */
	peer->hbinterval = asoc->hbinterval;
	peer->probe_interval = asoc->probe_interval;

	peer->encap_port = asoc->encap_port;

	/* Set the path max_retrans.  */
	peer->pathmaxrxt = asoc->pathmaxrxt;

	/* And the partial failure retrans threshold */
	peer->pf_retrans = asoc->pf_retrans;
	/* And the primary path switchover retrans threshold */
	peer->ps_retrans = asoc->ps_retrans;

	/* Initialize the peer's SACK delay timeout based on the
	 * association configured value.
	 */
	peer->sackdelay = asoc->sackdelay;
	peer->sackfreq = asoc->sackfreq;

	if (addr->sa.sa_family == AF_INET6) {
		__be32 info = addr->v6.sin6_flowinfo;

		if (info) {
			peer->flowlabel = ntohl(info & IPV6_FLOWLABEL_MASK);
			peer->flowlabel |= SCTP_FLOWLABEL_SET_MASK;
		} else {
			peer->flowlabel = asoc->flowlabel;
		}
	}
	peer->dscp = asoc->dscp;

	/* Enable/disable heartbeat, SACK delay, and path MTU discovery
	 * based on association setting.
	 */
	peer->param_flags = asoc->param_flags;

	/* Initialize the pmtu of the transport. */
	sctp_transport_route(peer, NULL, sp);

	/* If this is the first transport addr on this association,
	 * initialize the association PMTU to the peer's PMTU.
	 * If not and the current association PMTU is higher than the new
	 * peer's PMTU, reset the association PMTU to the new peer's PMTU.
	 */
	sctp_assoc_set_pmtu(asoc, asoc->pathmtu ?
				  min_t(int, peer->pathmtu, asoc->pathmtu) :
				  peer->pathmtu);

	peer->pmtu_pending = 0;

	/* The asoc->peer.port might not be meaningful yet, but
	 * initialize the packet structure anyway.
	 */
	sctp_packet_init(&peer->packet, peer, asoc->base.bind_addr.port,
			 asoc->peer.port);

	/* 7.2.1 Slow-Start
	 *
	 * o The initial cwnd before DATA transmission or after a sufficiently
	 *   long idle period MUST be set to
	 *      min(4*MTU, max(2*MTU, 4380 bytes))
	 *
	 * o The initial value of ssthresh MAY be arbitrarily high
	 *   (for example, implementations MAY use the size of the
	 *   receiver advertised window).
	 */
	peer->cwnd = min(4*asoc->pathmtu, max_t(__u32, 2*asoc->pathmtu, 4380));

	/* At this point, we may not have the receiver's advertised window,
	 * so initialize ssthresh to the default value and it will be set
	 * later when we process the INIT.
	 */
	peer->ssthresh = SCTP_DEFAULT_MAXWINDOW;

	peer->partial_bytes_acked = 0;
	peer->flight_size = 0;
	peer->burst_limited = 0;

	/* Set the transport's RTO.initial value */
	peer->rto = asoc->rto_initial;
	sctp_max_rto(asoc, peer);

	/* Set the peer's active state. */
	peer->state = peer_state;

	/* Add this peer into the transport hashtable */
	if (sctp_hash_transport(peer)) {
		sctp_transport_free(peer);
		return NULL;
	}

	sctp_transport_pl_reset(peer);

	/* Attach the remote transport to our asoc.  */
	list_add_tail_rcu(&peer->transports, &asoc->peer.transport_addr_list);
	asoc->peer.transport_count++;

	sctp_ulpevent_notify_peer_addr_change(peer, SCTP_ADDR_ADDED, 0);

	/* If we do not yet have a primary path, set one.  */
	if (!asoc->peer.primary_path) {
		sctp_assoc_set_primary(asoc, peer);
		asoc->peer.retran_path = peer;
	}

	if (asoc->peer.active_path == asoc->peer.retran_path &&
	    peer->state != SCTP_UNCONFIRMED) {
		asoc->peer.retran_path = peer;
	}

	return peer;
}

struct sctp_transport *sctp_assoc_lookup_paddr(
					const struct sctp_association *asoc,
					const union sctp_addr *address);

void sctp_assoc_set_pmtu(struct sctp_association *asoc, __u32 pmtu);


#include <linux/livepatch.h>

extern typeof(sctp_assoc_lookup_paddr) sctp_assoc_lookup_paddr
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_lookup_paddr);
extern typeof(sctp_assoc_set_pmtu) sctp_assoc_set_pmtu
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_set_pmtu);
extern typeof(sctp_assoc_set_primary) sctp_assoc_set_primary
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_set_primary);
extern typeof(sctp_hash_transport) sctp_hash_transport
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_hash_transport);
extern typeof(sctp_packet_init) sctp_packet_init
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_packet_init);
extern typeof(sctp_transport_free) sctp_transport_free
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_free);
extern typeof(sctp_transport_new) sctp_transport_new
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_new);
extern typeof(sctp_transport_put) sctp_transport_put
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_put);
extern typeof(sctp_transport_reset_probe_timer) sctp_transport_reset_probe_timer
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_reset_probe_timer);
extern typeof(sctp_transport_route) sctp_transport_route
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_route);
extern typeof(sctp_transport_set_owner) sctp_transport_set_owner
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_set_owner);
extern typeof(sctp_ulpevent_notify_peer_addr_change)
	 sctp_ulpevent_notify_peer_addr_change
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_ulpevent_notify_peer_addr_change);
