/*
 * livepatch_bsc1275458
 *
 * Fix for CVE-2026-64423, bsc#1275458
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


#include "livepatch_bsc1275458.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/ipv4/igmp.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>

/* klp-ccp: from include/linux/igmp.h */
static void (*klpe_ip_mc_down)(struct in_device *);

/* klp-ccp: from net/ipv4/igmp.c */
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/times.h>
#include <linux/pkt_sched.h>
#include <linux/byteorder/generic.h>
#include <net/net_namespace.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <net/inet_common.h>
#include <linux/netfilter_ipv4.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_IP_MULTICAST

static void (*klpe_igmpv3_clear_delrec)(struct in_device *in_dev);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
static void (*klpe_ip_mc_clear_src)(struct ip_mc_list *pmc);

static void ip_ma_put(struct ip_mc_list *im)
{
	if (atomic_dec_and_test(&im->refcnt)) {
		in_dev_put(im->interface);
		kfree_rcu(im, rcu);
	}
}

#ifdef CONFIG_IP_MULTICAST

static void (*klpe_igmpv3_clear_delrec)(struct in_device *in_dev);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static u32 ip_mc_hash(const struct ip_mc_list *im)
{
	return hash_32((__force u32)im->multiaddr, MC_HASH_SZ_LOG);
}

static void ip_mc_hash_remove(struct in_device *in_dev,
			      struct ip_mc_list *im)
{
	struct ip_mc_list __rcu **mc_hash = rtnl_dereference(in_dev->mc_hash);
	struct ip_mc_list *aux;

	if (!mc_hash)
		return;
	mc_hash += ip_mc_hash(im);
	while ((aux = rtnl_dereference(*mc_hash)) != im)
		mc_hash = &aux->next_hash;
	*mc_hash = im->next_hash;
}
void klpp_ip_mc_destroy_dev(struct in_device *in_dev)
{
	struct ip_mc_list *i;

	ASSERT_RTNL();

	/* Deactivate timers */
	(*klpe_ip_mc_down)(in_dev);
#ifdef CONFIG_IP_MULTICAST
	(*klpe_igmpv3_clear_delrec)(in_dev);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	while ((i = rtnl_dereference(in_dev->mc_list)) != NULL) {
		ip_mc_hash_remove(in_dev, i);
		in_dev->mc_list = i->next_rcu;
		in_dev->mc_count--;
		(*klpe_ip_mc_clear_src)(i);
		ip_ma_put(i);
	}
}

static void (*klpe_ip_mc_clear_src)(struct ip_mc_list *pmc);


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "igmpv3_clear_delrec", (void *)&klpe_igmpv3_clear_delrec },
	{ "ip_mc_clear_src", (void *)&klpe_ip_mc_clear_src },
	{ "ip_mc_down", (void *)&klpe_ip_mc_down },
};

int livepatch_bsc1275458_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

