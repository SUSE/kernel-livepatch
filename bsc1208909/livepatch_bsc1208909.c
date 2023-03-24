/*
 * livepatch_bsc1208909
 *
 * Fix for CVE-2023-26545, bsc#1208909
 *
 *  Upstream commit:
 *  fda6c89fe3d9 ("net: mpls: fix stale pointer if allocation fails during device rename")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d61392c056dd433f1c5e684a75aeb4abe2c6c444
 *
 *  SLE15-SP2 and -SP3 commit:
 *  18d9ec70d6c4f460d21caf76dc393229f772cd5b
 *
 *  SLE15-SP4 commit:
 *  7ee1e3a3ca97800dcccd0d7376cfdd0af7768181
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_MPLS_ROUTING)

#if !IS_MODULE(CONFIG_MPLS_ROUTING)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/mpls/af_mpls.c */
#include <linux/types.h>

#include <linux/skbuff.h>

#include <linux/time.h>

#include <uapi/linux/if_packet.h>

/* klp-ccp: from net/mpls/af_mpls.c */
#include <linux/socket.h>
#include <linux/sysctl.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>

#include <uapi/linux/netconf.h>

/* klp-ccp: from net/mpls/af_mpls.c */
#include <linux/vmalloc.h>
#include <linux/percpu.h>

#include <net/ipv6.h>
#include <net/ip_fib.h>
#include <net/arp.h>

/* klp-ccp: from net/mpls/af_mpls.c */
#include <net/dst.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ip_fib.h>

/* klp-ccp: from net/mpls/af_mpls.c */
#include <net/netns/generic.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from net/mpls/internal.h */
struct mpls_dev {
	int				input_enabled;
	struct net_device		*dev;
	struct mpls_pcpu_stats __percpu	*stats;

	struct ctl_table_header		*sysctl;
	struct rcu_head			rcu;
};

/* klp-ccp: from net/mpls/af_mpls.c */
static void (*klpe_mpls_netconf_notify_devconf)(struct net *net, int event,
					int type, struct mpls_dev *mdev);

static const struct ctl_table (*klpe_mpls_dev_table)[2];

int klpp_mpls_dev_sysctl_register(struct net_device *dev,
				    struct mpls_dev *mdev)
{
	char path[sizeof("net/mpls/conf/") + IFNAMSIZ];
	struct net *net = dev_net(dev);
	struct ctl_table *table;
	int i;

	table = kmemdup(&(*klpe_mpls_dev_table), sizeof((*klpe_mpls_dev_table)), GFP_KERNEL);
	if (!table)
		goto out;

	/* Table data contains only offsets relative to the base of
	 * the mdev at this point, so make them absolute.
	 */
	for (i = 0; i < ARRAY_SIZE((*klpe_mpls_dev_table)); i++) {
		table[i].data = (char *)mdev + (uintptr_t)table[i].data;
		table[i].extra1 = mdev;
		table[i].extra2 = net;
	}

	snprintf(path, sizeof(path), "net/mpls/conf/%s", dev->name);

	mdev->sysctl = register_net_sysctl(net, path, table);
	if (!mdev->sysctl)
		goto free;

	(*klpe_mpls_netconf_notify_devconf)(net, RTM_NEWNETCONF, NETCONFA_ALL, mdev);
	return 0;

free:
	kfree(table);
out:
	mdev->sysctl = NULL;
	return -ENOBUFS;
}

void klpp_mpls_dev_sysctl_unregister(struct net_device *dev,
				       struct mpls_dev *mdev)
{
	struct net *net = dev_net(dev);
	struct ctl_table *table;

	if (!mdev->sysctl)
		return;

	table = mdev->sysctl->ctl_table_arg;
	unregister_net_sysctl_table(mdev->sysctl);
	kfree(table);

	(*klpe_mpls_netconf_notify_devconf)(net, RTM_DELNETCONF, 0, mdev);
}



#define LP_MODULE "mpls_router"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1208909.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mpls_dev_table", (void *)&klpe_mpls_dev_table, "mpls_router" },
	{ "mpls_netconf_notify_devconf",
	  (void *)&klpe_mpls_netconf_notify_devconf, "mpls_router" },
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

int livepatch_bsc1208909_init(void)
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

void livepatch_bsc1208909_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_MPLS_ROUTING) */
