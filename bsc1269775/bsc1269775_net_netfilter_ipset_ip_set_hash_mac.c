/*
 * bsc1269775_net_netfilter_ipset_ip_set_hash_mac
 *
 * Fix for CVE-2026-53131, bsc#1269775
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1269775.h"


/* klp-ccp: from net/netfilter/ipset/ip_set_hash_mac.c */
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <net/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_hash.h>

struct hash_mac4_elem {
	/* Zero valued IP addresses cannot be stored */
	union {
		unsigned char ether[ETH_ALEN];
		__be32 foo[2];
	};
};

/* klp-ccp: from net/netfilter/ipset/ip_set_hash_gen.h */
#ifndef _IP_SET_HASH_GEN_H

#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <linux/types.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _IP_SET_HASH_GEN_H */
/* klp-ccp: from net/netfilter/ipset/ip_set_hash_mac.c */
int klpp_hash_mac4_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_mac4_elem e = { { .foo[0] = 0, .foo[1] = 0 } };
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);

	if (!skb->dev || skb->dev->type != ARPHRD_ETHER ||
	    !skb_mac_header_was_set(skb) || skb_mac_header_len(skb) < ETH_HLEN)
		return -EINVAL;

	if (opt->flags & IPSET_DIM_ONE_SRC)
		ether_addr_copy(e.ether, eth_hdr(skb)->h_source);
	else
		ether_addr_copy(e.ether, eth_hdr(skb)->h_dest);

	if (is_zero_ether_addr(e.ether))
		return -EINVAL;
	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
}


