/*
 * livepatch_bsc1267206
 *
 * Fix for CVE-2026-45970, bsc#1267206
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


#include "livepatch_bsc1267206.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/net/bonding/bond_main.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/socket.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/bitops.h>
#include <linux/io.h>
#include <asm/dma.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/smp.h>
#include <linux/if_ether.h>
#include <net/arp.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/if_bonding.h>
#include <linux/jiffies.h>
#include <linux/preempt.h>
#include <net/route.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/pkt_sched.h>
#include <linux/rculist.h>
#include <net/flow_dissector.h>
#include <net/switchdev.h>
#include <net/bonding.h>

/* klp-ccp: from include/net/bond_alb.h */
static void (*klpe_bond_alb_deinitialize)(struct bonding *bond);

/* klp-ccp: from drivers/net/bonding/bond_main.c */
#include <net/bond_3ad.h>
#include <net/bond_alb.h>

static void bond_work_cancel_all(struct bonding *bond)
{
	cancel_delayed_work_sync(&bond->mii_work);
	cancel_delayed_work_sync(&bond->arp_work);
	cancel_delayed_work_sync(&bond->alb_work);
	cancel_delayed_work_sync(&bond->ad_work);
	cancel_delayed_work_sync(&bond->mcast_work);
	cancel_delayed_work_sync(&bond->slave_arr_work);
}

int klpp_bond_close(struct net_device *bond_dev)
{
	struct bonding *bond = netdev_priv(bond_dev);

	bond_work_cancel_all(bond);
	bond->send_peer_notif = 0;
	WRITE_ONCE(bond->recv_probe, NULL);

	/* Wait for any in-flight RX handlers */
	synchronize_net();

	if (bond_is_lb(bond))
		(*klpe_bond_alb_deinitialize)(bond);

	return 0;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "bonding"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bond_alb_deinitialize", (void *)&klpe_bond_alb_deinitialize,
	  "bonding" },
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

int livepatch_bsc1267206_init(void)
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

void livepatch_bsc1267206_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
