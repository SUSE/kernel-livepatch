/*
 * livepatch_bsc1252689
 *
 * Fix for CVE-2025-40018, bsc#1252689
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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>

#include <linux/gfp.h>

#include <asm/unaligned.h>

#include <net/ip_vs.h>

/* klp-ccp: from include/net/ip_vs.h */
static void (*klpe_unregister_ip_vs_app)(struct netns_ipvs *ipvs, struct ip_vs_app *app);

static struct ip_vs_app (*klpe_ip_vs_ftp);
static struct module (*klpe_ip_vs_ftp_mod);

void klpp___ip_vs_ftp_exit(struct net *net)
{
	struct netns_ipvs *ipvs = net_ipvs(net);

	if (!ipvs || module_is_live(&(*klpe_ip_vs_ftp_mod)))
		return;

	(*klpe_unregister_ip_vs_app)(ipvs, &(*klpe_ip_vs_ftp));
}

#include "livepatch_bsc1252689.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ip_vs_ftp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ip_vs_ftp", (void *)&klpe_ip_vs_ftp, "ip_vs_ftp" },
	{ "__this_module", (void *)&klpe_ip_vs_ftp_mod, "ip_vs_ftp" },
	{ "unregister_ip_vs_app", (void *)&klpe_unregister_ip_vs_app,
	  "ip_vs" },
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

int livepatch_bsc1252689_init(void)
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

void livepatch_bsc1252689_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
