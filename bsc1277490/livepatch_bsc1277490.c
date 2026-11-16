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
static void (*klpe_sctp_transport_free)(struct sctp_transport *);

static void (*klpe_sctp_transport_reset_reconf_timer)(struct sctp_transport *transport);
static int (*klpe_sctp_transport_hold)(struct sctp_transport *);

static void (*klpe_sctp_assoc_update_retran_path)(struct sctp_association *);
static void (*klpe_sctp_assoc_set_primary)(struct sctp_association *,
			    struct sctp_transport *);

/* klp-ccp: from include/net/sctp/sctp.h */
static void (*klpe_sctp_unhash_transport)(struct sctp_transport *t);

/* klp-ccp: from net/sctp/associola.c */
#include <net/sctp/sm.h>
void klpp_sctp_assoc_rm_peer(struct sctp_association *asoc,
			struct sctp_transport *peer)
{
	struct list_head	*pos;
	struct sctp_transport	*transport;
	struct sctp_chunk *ch;

	pr_debug("%s: association:%p addr:%pISpc\n",
		 __func__, asoc, &peer->ipaddr.sa);

	/* If we are to remove the current retran_path, update it
	 * to the next peer before removing this peer from the list.
	 */
	if (asoc->peer.retran_path == peer)
		(*klpe_sctp_assoc_update_retran_path)(asoc);

	/* Remove this peer from the list. */
	list_del_rcu(&peer->transports);
	/* Remove this peer from the transport hashtable */
	(*klpe_sctp_unhash_transport)(peer);

	/* Get the first transport of asoc. */
	pos = asoc->peer.transport_addr_list.next;
	transport = list_entry(pos, struct sctp_transport, transports);

	/* Update any entries that match the peer to be deleted. */
	if (asoc->peer.primary_path == peer)
		(*klpe_sctp_assoc_set_primary)(asoc, transport);
	if (asoc->peer.active_path == peer)
		asoc->peer.active_path = transport;
	if (asoc->peer.retran_path == peer)
		asoc->peer.retran_path = transport;
	if (asoc->peer.last_data_from == peer)
		asoc->peer.last_data_from = transport;

	if (asoc->strreset_chunk &&
	    asoc->strreset_chunk->transport == peer) {
		asoc->strreset_chunk->transport = transport;
		(*klpe_sctp_transport_reset_reconf_timer)(transport);
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
				(*klpe_sctp_transport_hold)(active);
	}

	list_for_each_entry(ch, &asoc->outqueue.control_chunk_list, list)
		if (ch->transport == peer)
			ch->transport = NULL;

	asoc->peer.transport_count--;

	(*klpe_sctp_transport_free)(peer);
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_assoc_set_primary", (void *)&klpe_sctp_assoc_set_primary,
	  "sctp" },
	{ "sctp_assoc_update_retran_path",
	  (void *)&klpe_sctp_assoc_update_retran_path, "sctp" },
	{ "sctp_transport_free", (void *)&klpe_sctp_transport_free, "sctp" },
	{ "sctp_transport_hold", (void *)&klpe_sctp_transport_hold, "sctp" },
	{ "sctp_transport_reset_reconf_timer",
	  (void *)&klpe_sctp_transport_reset_reconf_timer, "sctp" },
	{ "sctp_unhash_transport", (void *)&klpe_sctp_unhash_transport,
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

int livepatch_bsc1277490_init(void)
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

void livepatch_bsc1277490_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
