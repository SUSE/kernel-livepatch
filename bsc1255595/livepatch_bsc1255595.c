/*
 * livepatch_bsc1255595
 *
 * Fix for CVE-2022-50697, bsc#1255595
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

/* klp-ccp: from net/802/mrp.c */
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

/* klp-ccp: from net/802/mrp.c */
#include <linux/rtnetlink.h>
#include <linux/slab.h>

#include <net/mrp.h>

/* klp-ccp: from net/802/mrp.c */
#include <asm/unaligned.h>

static void (*klpe_mrp_pdu_queue)(struct mrp_applicant *app);

static void mrp_queue_xmit(struct mrp_applicant *app)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&app->queue)))
		dev_queue_xmit(skb);
}

static void (*klpe_mrp_mad_event)(struct mrp_applicant *app, enum mrp_event event);

static void (*klpe_mrp_release_port)(struct net_device *dev);

void klpp_mrp_uninit_applicant(struct net_device *dev, struct mrp_application *appl)
{
	struct mrp_port *port = rtnl_dereference(dev->mrp_port);
	struct mrp_applicant *app = rtnl_dereference(
		port->applicants[appl->type]);

	ASSERT_RTNL();

	RCU_INIT_POINTER(port->applicants[appl->type], NULL);

	/* Delete timer and generate a final TX event to flush out
	 * all pending messages before the applicant is gone.
	 */
	timer_shutdown_sync(&app->join_timer);
	timer_shutdown_sync(&app->periodic_timer);

	spin_lock_bh(&app->lock);
	(*klpe_mrp_mad_event)(app, MRP_EVENT_TX);
	(*klpe_mrp_pdu_queue)(app);
	spin_unlock_bh(&app->lock);

	mrp_queue_xmit(app);

	dev_mc_del(dev, appl->group_address);
	kfree_rcu(app, rcu);
	(*klpe_mrp_release_port)(dev);
}

typeof(klpp_mrp_uninit_applicant) klpp_mrp_uninit_applicant;


#include "livepatch_bsc1255595.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "mrp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mrp_mad_event", (void *)&klpe_mrp_mad_event, "mrp" },
	{ "mrp_pdu_queue", (void *)&klpe_mrp_pdu_queue, "mrp" },
	{ "mrp_release_port", (void *)&klpe_mrp_release_port, "mrp" },
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

int livepatch_bsc1255595_init(void)
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

void livepatch_bsc1255595_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
