/*
 * livepatch_bsc1269284
 *
 * Fix for CVE-2023-53995, bsc#1269284
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


#include "livepatch_bsc1269284.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/ipv4/devinet.c */
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/slab.h>
#include <linux/hash.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <linux/kmod.h>
#include <linux/netconf.h>

#include <net/arp.h>
#include <net/ip.h>

/* klp-ccp: from include/net/route.h */
static void (*klpe_fib_add_ifaddr)(struct in_ifaddr *);
static void (*klpe_fib_del_ifaddr)(struct in_ifaddr *, struct in_ifaddr *);

/* klp-ccp: from net/ipv4/devinet.c */
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/rtnetlink.h>
#include <net/net_namespace.h>
#include <net/addrconf.h>

static void (*klpe_inet_hash_remove)(struct in_ifaddr *ifa);

static void (*klpe_rtmsg_ifa)(int event, struct in_ifaddr *, struct nlmsghdr *, u32);

static struct blocking_notifier_head (*klpe_inetaddr_chain);

static void (*klpe_inet_rcu_free_ifa)(struct rcu_head *head);

static void klpr_inet_free_ifa(struct in_ifaddr *ifa)
{
	call_rcu(&ifa->rcu_head, (*klpe_inet_rcu_free_ifa));
}

void klpp___inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap,
			 int destroy, struct nlmsghdr *nlh, u32 portid)
{
	struct in_ifaddr *promote = NULL;
	struct in_ifaddr *ifa, *ifa1 = *ifap;
	struct in_ifaddr **last_prim = ifap;
	struct in_ifaddr *prev_prom = NULL;
	int do_promote = IN_DEV_PROMOTE_SECONDARIES(in_dev);

	ASSERT_RTNL();

	if (in_dev->dead)
		goto no_promotions;

	/* 1. Deleting primary ifaddr forces deletion all secondaries
	 * unless alias promotion is set
	 **/

	if (!(ifa1->ifa_flags & IFA_F_SECONDARY)) {
		struct in_ifaddr **ifap1 = &ifa1->ifa_next;

		while ((ifa = *ifap1) != NULL) {
			if (!(ifa->ifa_flags & IFA_F_SECONDARY) &&
			    ifa1->ifa_scope <= ifa->ifa_scope)
				last_prim = &ifa->ifa_next;

			if (!(ifa->ifa_flags & IFA_F_SECONDARY) ||
			    ifa1->ifa_mask != ifa->ifa_mask ||
			    !inet_ifa_match(ifa1->ifa_address, ifa)) {
				ifap1 = &ifa->ifa_next;
				prev_prom = ifa;
				continue;
			}

			if (!do_promote) {
				(*klpe_inet_hash_remove)(ifa);
				*ifap1 = ifa->ifa_next;

				(*klpe_rtmsg_ifa)(RTM_DELADDR, ifa, nlh, portid);
				blocking_notifier_call_chain(&(*klpe_inetaddr_chain),
						NETDEV_DOWN, ifa);
				klpr_inet_free_ifa(ifa);
			} else {
				promote = ifa;
				break;
			}
		}
	}

	/* On promotion all secondaries from subnet are changing
	 * the primary IP, we must remove all their routes silently
	 * and later to add them back with new prefsrc. Do this
	 * while all addresses are on the device list.
	 */
	for (ifa = promote; ifa; ifa = ifa->ifa_next) {
		if (ifa1->ifa_mask == ifa->ifa_mask &&
		    inet_ifa_match(ifa1->ifa_address, ifa))
			(*klpe_fib_del_ifaddr)(ifa, ifa1);
	}

no_promotions:
	/* 2. Unlink it */

	*ifap = ifa1->ifa_next;
	(*klpe_inet_hash_remove)(ifa1);

	/* 3. Announce address deletion */

	/* Send message first, then call notifier.
	   At first sight, FIB update triggered by notifier
	   will refer to already deleted ifaddr, that could confuse
	   netlink listeners. It is not true: look, gated sees
	   that route deleted and if it still thinks that ifaddr
	   is valid, it will try to restore deleted routes... Grr.
	   So that, this order is correct.
	 */
	(*klpe_rtmsg_ifa)(RTM_DELADDR, ifa1, nlh, portid);
	blocking_notifier_call_chain(&(*klpe_inetaddr_chain), NETDEV_DOWN, ifa1);

	if (promote) {
		struct in_ifaddr *next_sec = promote->ifa_next;

		if (prev_prom) {
			prev_prom->ifa_next = promote->ifa_next;
			promote->ifa_next = *last_prim;
			*last_prim = promote;
		}

		promote->ifa_flags &= ~IFA_F_SECONDARY;
		(*klpe_rtmsg_ifa)(RTM_NEWADDR, promote, nlh, portid);
		blocking_notifier_call_chain(&(*klpe_inetaddr_chain),
				NETDEV_UP, promote);
		for (ifa = next_sec; ifa; ifa = ifa->ifa_next) {
			if (ifa1->ifa_mask != ifa->ifa_mask ||
			    !inet_ifa_match(ifa1->ifa_address, ifa))
					continue;
			(*klpe_fib_add_ifaddr)(ifa);
		}

	}
	if (destroy)
		klpr_inet_free_ifa(ifa1);
}

static void (*klpe_rtmsg_ifa)(int event, struct in_ifaddr *ifa, struct nlmsghdr *nlh,
		      u32 portid);


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fib_add_ifaddr", (void *)&klpe_fib_add_ifaddr },
	{ "fib_del_ifaddr", (void *)&klpe_fib_del_ifaddr },
	{ "inet_hash_remove", (void *)&klpe_inet_hash_remove },
	{ "inet_rcu_free_ifa", (void *)&klpe_inet_rcu_free_ifa },
	{ "inetaddr_chain", (void *)&klpe_inetaddr_chain },
	{ "rtmsg_ifa", (void *)&klpe_rtmsg_ifa },
};

int livepatch_bsc1269284_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

