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
static void (*klpe_sctp_packet_init)(struct sctp_packet *, struct sctp_transport *,
		      __u16 sport, __u16 dport);

static struct sctp_transport *(*klpe_sctp_transport_new)(struct net *, const union sctp_addr *,
					  gfp_t);
static void (*klpe_sctp_transport_set_owner)(struct sctp_transport *,
			      struct sctp_association *);
static void (*klpe_sctp_transport_route)(struct sctp_transport *, union sctp_addr *,
			  struct sctp_sock *);

static void (*klpe_sctp_transport_free)(struct sctp_transport *);

static struct sctp_transport *(*klpe_sctp_assoc_lookup_paddr)(const struct sctp_association *,
					  const union sctp_addr *);
static void (*klpe_sctp_assoc_set_primary)(struct sctp_association *,
			    struct sctp_transport *);

/* klp-ccp: from include/net/sctp/sctp.h */
static int (*klpe_sctp_hash_transport)(struct sctp_transport *t);

/* klp-ccp: from net/sctp/associola.c */
#include <net/sctp/sm.h>
struct sctp_transport *klpp_sctp_assoc_add_peer(struct sctp_association *asoc,
					   const union sctp_addr *addr,
					   const gfp_t gfp,
					   const int peer_state)
{
	struct net *net = sock_net(asoc->base.sk);
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
	peer = (*klpe_sctp_assoc_lookup_paddr)(asoc, addr);
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

	peer = (*klpe_sctp_transport_new)(net, addr, gfp);
	if (!peer)
		return NULL;

	(*klpe_sctp_transport_set_owner)(peer, asoc);

	/* Initialize the peer's heartbeat interval based on the
	 * association configured value.
	 */
	peer->hbinterval = asoc->hbinterval;

	/* Set the path max_retrans.  */
	peer->pathmaxrxt = asoc->pathmaxrxt;

	/* And the partial failure retrans threshold */
	peer->pf_retrans = asoc->pf_retrans;

	/* Initialize the peer's SACK delay timeout based on the
	 * association configured value.
	 */
	peer->sackdelay = asoc->sackdelay;
	peer->sackfreq = asoc->sackfreq;

	/* Enable/disable heartbeat, SACK delay, and path MTU discovery
	 * based on association setting.
	 */
	peer->param_flags = asoc->param_flags;

	(*klpe_sctp_transport_route)(peer, NULL, sp);

	/* Initialize the pmtu of the transport. */
	if (peer->param_flags & SPP_PMTUD_DISABLE) {
		if (asoc->pathmtu)
			peer->pathmtu = asoc->pathmtu;
		else
			peer->pathmtu = SCTP_DEFAULT_MAXSEGMENT;
	}

	/* If this is the first transport addr on this association,
	 * initialize the association PMTU to the peer's PMTU.
	 * If not and the current association PMTU is higher than the new
	 * peer's PMTU, reset the association PMTU to the new peer's PMTU.
	 */
	if (asoc->pathmtu)
		asoc->pathmtu = min_t(int, peer->pathmtu, asoc->pathmtu);
	else
		asoc->pathmtu = peer->pathmtu;

	pr_debug("%s: association:%p PMTU set to %d\n", __func__, asoc,
		 asoc->pathmtu);

	peer->pmtu_pending = 0;

	asoc->frag_point = sctp_frag_point(asoc, asoc->pathmtu);

	/* The asoc->peer.port might not be meaningful yet, but
	 * initialize the packet structure anyway.
	 */
	(*klpe_sctp_packet_init)(&peer->packet, peer, asoc->base.bind_addr.port,
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
	if ((*klpe_sctp_hash_transport)(peer)) {
		(*klpe_sctp_transport_free)(peer);
		return NULL;
	}

	/* Attach the remote transport to our asoc.  */
	list_add_tail_rcu(&peer->transports, &asoc->peer.transport_addr_list);
	asoc->peer.transport_count++;

	/* If we do not yet have a primary path, set one.  */
	if (!asoc->peer.primary_path) {
		(*klpe_sctp_assoc_set_primary)(asoc, peer);
		asoc->peer.retran_path = peer;
	}

	if (asoc->peer.active_path == asoc->peer.retran_path &&
	    peer->state != SCTP_UNCONFIRMED) {
		asoc->peer.retran_path = peer;
	}

	return peer;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_assoc_lookup_paddr", (void *)&klpe_sctp_assoc_lookup_paddr,
	  "sctp" },
	{ "sctp_assoc_set_primary", (void *)&klpe_sctp_assoc_set_primary,
	  "sctp" },
	{ "sctp_hash_transport", (void *)&klpe_sctp_hash_transport, "sctp" },
	{ "sctp_packet_init", (void *)&klpe_sctp_packet_init, "sctp" },
	{ "sctp_transport_free", (void *)&klpe_sctp_transport_free, "sctp" },
	{ "sctp_transport_new", (void *)&klpe_sctp_transport_new, "sctp" },
	{ "sctp_transport_route", (void *)&klpe_sctp_transport_route, "sctp" },
	{ "sctp_transport_set_owner", (void *)&klpe_sctp_transport_set_owner,
	  "sctp" },
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

int livepatch_bsc1280693_init(void)
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

void livepatch_bsc1280693_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
