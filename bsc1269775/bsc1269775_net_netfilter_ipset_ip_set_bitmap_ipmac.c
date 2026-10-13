/*
 * bsc1269775_net_netfilter_ipset_ip_set_bitmap_ipmac
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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/netfilter/ipset/ip_set_bitmap_ipmac.c */
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <net/netlink.h>
#include <linux/netfilter/ipset/pfxlen.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_bitmap.h>

struct bitmap_ipmac {
	void *members;		/* the set members */
	u32 first_ip;		/* host byte order, included in range */
	u32 last_ip;		/* host byte order, included in range */
	u32 elements;		/* number of max elements in the set */
	size_t memsize;		/* members size */
	struct timer_list gc;	/* garbage collector */
	unsigned char extensions[0]	/* MAC + data extensions */
		__aligned(__alignof__(u64));
};

struct bitmap_ipmac_adt_elem {
	unsigned char ether[ETH_ALEN] __aligned(2);
	u16 id;
	u16 add_mac;
};

static inline u32
ip_to_id(const struct bitmap_ipmac *m, u32 ip)
{
	return ip - m->first_ip;
}

int klpp_bitmap_ipmac_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	struct bitmap_ipmac *map = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct bitmap_ipmac_adt_elem e = { .id = 0, .add_mac = 1 };
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
	u32 ip;

	/* MAC can be src only */
	if (!(opt->flags & IPSET_DIM_TWO_SRC))
		return 0;

	ip = ntohl(ip4addr(skb, opt->flags & IPSET_DIM_ONE_SRC));
	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	/* Backward compatibility: we don't check the second flag */
	if (!skb->dev || skb->dev->type != ARPHRD_ETHER ||
	    !skb_mac_header_was_set(skb) || skb_mac_header_len(skb) < ETH_HLEN)
		return -EINVAL;

	e.id = ip_to_id(map, ip);
	memcpy(e.ether, eth_hdr(skb)->h_source, ETH_ALEN);

	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
}


