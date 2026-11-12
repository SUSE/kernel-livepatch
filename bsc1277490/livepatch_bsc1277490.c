/*
 * livepatch_bsc1277490
 *
 * Fix for CVE-2026-74688, bsc#1277490
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


#include "livepatch_bsc1277490.h"


/* klp-ccp: from net/sctp/associola.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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

void klpp_sctp_assoc_rm_peer(struct sctp_association *asoc,
			struct sctp_transport *peer)
{
	struct sctp_transport *transport;
	struct list_head *pos;
	struct sctp_chunk *ch;

	pr_debug("%s: association:%p addr:%pISpc\n",
		 __func__, asoc, &peer->ipaddr.sa);

	/* If we are to remove the current retran_path, update it
	 * to the next peer before removing this peer from the list.
	 */
	if (asoc->peer.retran_path == peer)
		sctp_assoc_update_retran_path(asoc);

	/* Remove this peer from the list. */
	list_del_rcu(&peer->transports);
	/* Remove this peer from the transport hashtable */
	sctp_unhash_transport(peer);

	/* Get the first transport of asoc. */
	pos = asoc->peer.transport_addr_list.next;
	transport = list_entry(pos, struct sctp_transport, transports);

	/* Update any entries that match the peer to be deleted. */
	if (asoc->peer.primary_path == peer)
		sctp_assoc_set_primary(asoc, transport);
	if (asoc->peer.active_path == peer)
		asoc->peer.active_path = transport;
	if (asoc->peer.retran_path == peer)
		asoc->peer.retran_path = transport;
	if (asoc->peer.last_data_from == peer)
		asoc->peer.last_data_from = transport;

	if (asoc->strreset_chunk &&
	    asoc->strreset_chunk->transport == peer) {
		asoc->strreset_chunk->transport = transport;
		sctp_transport_reset_reconf_timer(transport);
	}

	/* If we remove the transport an INIT was last sent to, set it to
	 * NULL. Combined with the update of the retran path above, this
	 * will cause the next INIT to be sent to the next available
	 * transport, maintaining the cycle.
	 */
	if (asoc->init_last_sent_to == peer)
		asoc->init_last_sent_to = NULL;

	/* If we remove the transport an SHUTDOWN was last sent to, set it
	 * to NULL. Combined with the update of the retran path above, this
	 * will cause the next SHUTDOWN to be sent to the next available
	 * transport, maintaining the cycle.
	 */
	if (asoc->shutdown_last_sent_to == peer)
		asoc->shutdown_last_sent_to = NULL;

	/* If we remove the transport an ASCONF was last sent to, set it to
	 * NULL.
	 */
	if (asoc->addip_last_asconf &&
	    asoc->addip_last_asconf->transport == peer)
		asoc->addip_last_asconf->transport = NULL;

	/* If we have something on the transmitted list, we have to
	 * save it off.  The best place is the active path.
	 */
	if (!list_empty(&peer->transmitted)) {
		struct sctp_transport *active = asoc->peer.active_path;

		/* Reset the transport of each chunk on this list */
		list_for_each_entry(ch, &peer->transmitted,
					transmitted_list) {
			ch->transport = NULL;
			ch->rtt_in_progress = 0;
		}

		list_splice_tail_init(&peer->transmitted,
					&active->transmitted);

		/* Start a T3 timer here in case it wasn't running so
		 * that these migrated packets have a chance to get
		 * retransmitted.
		 */
		if (!timer_pending(&active->T3_rtx_timer))
			if (!mod_timer(&active->T3_rtx_timer,
					jiffies + active->rto))
				sctp_transport_hold(active);
	}

	list_for_each_entry(ch, &asoc->outqueue.out_chunk_list, list)
		if (ch->transport == peer)
			ch->transport = NULL;

	list_for_each_entry(ch, &asoc->outqueue.control_chunk_list, list)
		if (ch->transport == peer)
			ch->transport = NULL;

	asoc->peer.transport_count--;

	sctp_ulpevent_notify_peer_addr_change(peer, SCTP_ADDR_REMOVED, 0);
	sctp_transport_free(peer);
}

void sctp_assoc_update_retran_path(struct sctp_association *asoc);


#include <linux/livepatch.h>

extern typeof(sctp_assoc_set_primary) sctp_assoc_set_primary
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_set_primary);
extern typeof(sctp_assoc_update_retran_path) sctp_assoc_update_retran_path
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_update_retran_path);
extern typeof(sctp_transport_free) sctp_transport_free
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_free);
extern typeof(sctp_transport_hold) sctp_transport_hold
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_hold);
extern typeof(sctp_transport_reset_reconf_timer)
	 sctp_transport_reset_reconf_timer
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_reset_reconf_timer);
extern typeof(sctp_ulpevent_notify_peer_addr_change)
	 sctp_ulpevent_notify_peer_addr_change
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_ulpevent_notify_peer_addr_change);
extern typeof(sctp_unhash_transport) sctp_unhash_transport
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_unhash_transport);
