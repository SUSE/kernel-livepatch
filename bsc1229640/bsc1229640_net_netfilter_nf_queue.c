/*
 * bsc1229640_net_netfilter_nf_queue
 *
 * Fix for CVE-2022-48911, bsc#1229640
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from net/netfilter/nf_queue.c */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <net/protocol.h>

/* klp-ccp: from net/netfilter/nf_queue.c */
#include <net/netfilter/nf_queue.h>

/* klp-ccp: from net/netfilter/nf_queue.c */
#include <net/dst.h>
/* klp-ccp: from net/netfilter/nf_internals.h */
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

/* klp-ccp: from net/netfilter/nf_queue.c */
void nf_queue_entry_release_refs(struct nf_queue_entry *entry);

extern typeof(nf_queue_entry_release_refs) nf_queue_entry_release_refs;

bool klpp_nf_queue_entry_get_refs(struct nf_queue_entry *entry)
{
	struct nf_hook_state *state = &entry->state;

	if (state->sk && !atomic_inc_not_zero(&state->sk->sk_refcnt))
		return false;

	if (state->in)
		dev_hold(state->in);
	if (state->out)
		dev_hold(state->out);
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	if (entry->skb->nf_bridge) {
		struct net_device *physdev;

		physdev = nf_bridge_get_physindev(entry->skb);
		if (physdev)
			dev_hold(physdev);
		physdev = nf_bridge_get_physoutdev(entry->skb);
		if (physdev)
			dev_hold(physdev);
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return true;
}

static int __nf_queue(struct sk_buff *skb, const struct nf_hook_state *state,
		      struct nf_hook_entry *hook_entry, unsigned int queuenum)
{
	int status = -ENOENT;
	struct nf_queue_entry *entry = NULL;
	const struct nf_afinfo *afinfo;
	const struct nf_queue_handler *qh;
	struct net *net = state->net;

	/* QUEUE == DROP if no one is waiting, to be safe. */
	qh = rcu_dereference(net->nf.queue_handler);
	if (!qh) {
		status = -ESRCH;
		goto err;
	}

	afinfo = nf_get_afinfo(state->pf);
	if (!afinfo)
		goto err;

	entry = kmalloc(sizeof(*entry) + afinfo->route_key_size, GFP_ATOMIC);
	if (!entry) {
		status = -ENOMEM;
		goto err;
	}

	if (skb_dst(skb) && !skb_dst_force(skb)) {
		status = -ENETDOWN;
		goto err;
	}

	*entry = (struct nf_queue_entry) {
		.skb	= skb,
		.state	= *state,
		.hook	= hook_entry,
		.size	= sizeof(*entry) + afinfo->route_key_size,
	};

	if (!klpp_nf_queue_entry_get_refs(entry)) {
		status = -ENOTCONN;
		goto err;
	}
	afinfo->saveroute(skb, entry);
	status = qh->outfn(entry, queuenum);

	if (status < 0) {
		nf_queue_entry_release_refs(entry);
		goto err;
	}

	return 0;

err:
	kfree(entry);
	return status;
}

int klpp_nf_queue(struct sk_buff *skb, struct nf_hook_state *state,
	     struct nf_hook_entry **entryp, unsigned int verdict)
{
	struct nf_hook_entry *entry = *entryp;
	int ret;

	ret = __nf_queue(skb, state, entry, verdict >> NF_VERDICT_QBITS);
	if (ret < 0) {
		if (ret == -ESRCH &&
		    (verdict & NF_VERDICT_FLAG_QUEUE_BYPASS)) {
			*entryp = rcu_dereference(entry->next);
			return 1;
		}
		kfree_skb(skb);
	}

	return 0;
}


#include "livepatch_bsc1229640.h"

