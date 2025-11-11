/*
 * livepatch_bsc1245778
 *
 * Fix for CVE-2024-53141, bsc#1245778
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from net/netfilter/ipset/ip_set_bitmap_ip.c */
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <net/netlink.h>
#include <net/tcp.h>

#include <linux/netfilter/ipset/pfxlen.h>

/* klp-ccp: from include/linux/netfilter/ipset/pfxlen.h */
static const union nf_inet_addr (*klpe_ip_set_hostmask_map)[];

static inline u32
klpr_ip_set_hostmask(u8 pfxlen)
{
	return (__force u32) (*klpe_ip_set_hostmask_map)[pfxlen].ip;
}

/* klp-ccp: from net/netfilter/ipset/ip_set_bitmap_ip.c */
#include <linux/netfilter/ipset/ip_set.h>

/* klp-ccp: from include/linux/netfilter/ipset/ip_set.h */
static int (*klpe_ip_set_get_ipaddr4)(struct nlattr *nla,  __be32 *ipaddr);

static int (*klpe_ip_set_get_extensions)(struct ip_set *set, struct nlattr *tb[],
				 struct ip_set_ext *ext);

static inline int
klpr_ip_set_get_hostipaddr4(struct nlattr *nla, u32 *ipaddr)
{
	__be32 ip;
	int ret = (*klpe_ip_set_get_ipaddr4)(nla, &ip);

	if (ret)
		return ret;
	*ipaddr = ntohl(ip);
	return 0;
}

/* klp-ccp: from net/netfilter/ipset/ip_set_bitmap_ip.c */
#include <linux/netfilter/ipset/ip_set_bitmap.h>

#define HOST_MASK	32

struct bitmap_ip {
	void *members;		/* the set members */
	u32 first_ip;		/* host byte order, included in range */
	u32 last_ip;		/* host byte order, included in range */
	u32 elements;		/* number of max elements in the set */
	u32 hosts;		/* number of hosts in a subnet */
	size_t memsize;		/* members size */
	u8 netmask;		/* subnet netmask */
	struct timer_list gc;	/* garbage collection */
	unsigned char extensions[0]	/* data extensions */
		__aligned(__alignof__(u64));
};

struct bitmap_ip_adt_elem {
	u16 id;
};

static inline u32
klpr_ip_to_id(const struct bitmap_ip *m, u32 ip)
{
	return ((ip & klpr_ip_set_hostmask(m->netmask)) - m->first_ip) / m->hosts;
}

int
klpp_bitmap_ip_uadt(struct ip_set *set, struct nlattr *tb[],
	       enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	struct bitmap_ip *map = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	u32 ip = 0, ip_to = 0;
	struct bitmap_ip_adt_elem e = { .id = 0 };
	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
	int ret = 0;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	if (unlikely(!tb[IPSET_ATTR_IP]))
		return -IPSET_ERR_PROTOCOL;

	ret = klpr_ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &ip);
	if (ret)
		return ret;

	ret = (*klpe_ip_set_get_extensions)(set, tb, &ext);
	if (ret)
		return ret;

	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	if (adt == IPSET_TEST) {
		e.id = klpr_ip_to_id(map, ip);
		return adtfn(set, &e, &ext, &ext, flags);
	}

	if (tb[IPSET_ATTR_IP_TO]) {
		ret = klpr_ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &ip_to);
		if (ret)
			return ret;
		if (ip > ip_to)
			swap(ip, ip_to);
	} else if (tb[IPSET_ATTR_CIDR]) {
		u8 cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);

		if (!cidr || cidr > HOST_MASK)
			return -IPSET_ERR_INVALID_CIDR;
		do { ip &= klpr_ip_set_hostmask(cidr); ip_to = ip | ~klpr_ip_set_hostmask(cidr); } while (0);
	} else {
		ip_to = ip;
	}

	if (ip < map->first_ip || ip_to > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	for (; !before(ip_to, ip); ip += map->hosts) {
		e.id = klpr_ip_to_id(map, ip);
		ret = adtfn(set, &e, &ext, &ext, flags);

		if (ret && !ip_set_eexist(ret, flags))
			return ret;

		ret = 0;
	}
	return ret;
}


#include "livepatch_bsc1245778.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ip_set_bitmap_ip"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ip_set_get_extensions", (void *)&klpe_ip_set_get_extensions,
	  "ip_set" },
	{ "ip_set_get_ipaddr4", (void *)&klpe_ip_set_get_ipaddr4, "ip_set" },
	{ "ip_set_hostmask_map", (void *)&klpe_ip_set_hostmask_map, "ip_set" },
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

int livepatch_bsc1245778_init(void)
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

void livepatch_bsc1245778_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
