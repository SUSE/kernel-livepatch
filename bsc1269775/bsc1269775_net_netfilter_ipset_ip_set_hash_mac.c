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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
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
#include <linux/netfilter/ipset/ip_set_timeout.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _IP_SET_HASH_GEN_H */
/* klp-ccp: from net/netfilter/ipset/ip_set_hash_mac.c */
static const unsigned char (*klpe_invalid_ether)[ETH_ALEN];

int klpp_hash_mac4_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_mac4_elem e = { { .foo[0] = 0, .foo[1] = 0 } };
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);

	 /* MAC can be src only */
	if (!(opt->flags & IPSET_DIM_ONE_SRC))
		return 0;

	if (!skb->dev || skb->dev->type != ARPHRD_ETHER ||
	    !skb_mac_header_was_set(skb) || skb_mac_header_len(skb) < ETH_HLEN)
		return -EINVAL;

	ether_addr_copy(e.ether, eth_hdr(skb)->h_source);
	if (memcmp(e.ether, (*klpe_invalid_ether), ETH_ALEN) == 0)
		return -EINVAL;
	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ip_set_hash_mac"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "invalid_ether", (void *)&klpe_invalid_ether, "ip_set_hash_mac" },
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

int bsc1269775_net_netfilter_ipset_ip_set_hash_mac_init(void)
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

void bsc1269775_net_netfilter_ipset_ip_set_hash_mac_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
