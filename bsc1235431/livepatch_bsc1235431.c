/*
 * livepatch_bsc1235431
 *
 * Fix for CVE-2024-56650, bsc#1235431
 *
 *  Upstream commit:
 *  04317f4eb2aa ("netfilter: x_tables: fix LED ID check in led_tg_check()")
 *
 *  SLE12-SP5 commit:
 *  8b9e3119a3d04886fad4f6ed1240161cc227a49e
 *
 *  SLE15-SP3 commit:
 *  910398d2094df352ae9ad72abee941108e7f7500
 *
 *  SLE15-SP4 and -SP5 commit:
 *  a130a9cc3e6b9ec5a5693a3c0088d0572ee9b841
 *
 *  SLE15-SP6 commit:
 *  e2ba4f98453052e2b4739a0d08e6678292f96ed0
 *
 *  SLE MICRO-6-0 commit:
 *  e2ba4f98453052e2b4739a0d08e6678292f96ed0
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_LED)

#if !IS_MODULE(CONFIG_NETFILTER_XT_TARGET_LED)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/netfilter/xt_LED.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/slab.h>
#include <linux/leds.h>
#include <linux/mutex.h>

#include <linux/netfilter/xt_LED.h>

static struct list_head (*klpe_xt_led_triggers);
static struct mutex (*klpe_xt_led_mutex);

struct xt_led_info_internal {
	struct list_head list;
	int refcnt;
	char *trigger_id;
	struct led_trigger netfilter_led_trigger;
	struct timer_list timer;
};

static void (*klpe_led_timeout_callback)(unsigned long data);

static struct xt_led_info_internal *klpr_led_trigger_lookup(const char *name)
{
	struct xt_led_info_internal *ledinternal;

	list_for_each_entry(ledinternal, &(*klpe_xt_led_triggers), list) {
		if (!strcmp(name, ledinternal->netfilter_led_trigger.name)) {
			return ledinternal;
		}
	}
	return NULL;
}

int klpp_led_tg_check(const struct xt_tgchk_param *par)
{
	struct xt_led_info *ledinfo = par->targinfo;
	struct xt_led_info_internal *ledinternal;
	int err;

	/* Bail out if empty string or not a string at all. */
	if (ledinfo->id[0] == '\0' ||
	    !memchr(ledinfo->id, '\0', sizeof(ledinfo->id))) {
		pr_info("No 'id' parameter given.\n");
		return -EINVAL;
	}

	mutex_lock(&(*klpe_xt_led_mutex));

	ledinternal = klpr_led_trigger_lookup(ledinfo->id);
	if (ledinternal) {
		ledinternal->refcnt++;
		goto out;
	}

	err = -ENOMEM;
	ledinternal = kzalloc(sizeof(struct xt_led_info_internal), GFP_KERNEL);
	if (!ledinternal)
		goto exit_mutex_only;

	ledinternal->trigger_id = kstrdup(ledinfo->id, GFP_KERNEL);
	if (!ledinternal->trigger_id)
		goto exit_internal_alloc;

	ledinternal->refcnt = 1;
	ledinternal->netfilter_led_trigger.name = ledinternal->trigger_id;

	err = led_trigger_register(&ledinternal->netfilter_led_trigger);
	if (err) {
		pr_err("Trigger name is already in use.\n");
		goto exit_alloc;
	}

	/* Since the letinternal timer can be shared between multiple targets,
	 * always set it up, even if the current target does not need it
	 */
	setup_timer(&ledinternal->timer, (*klpe_led_timeout_callback),
		    (unsigned long)ledinternal);

	list_add_tail(&ledinternal->list, &(*klpe_xt_led_triggers));

out:
	mutex_unlock(&(*klpe_xt_led_mutex));

	ledinfo->internal_data = ledinternal;

	return 0;

exit_alloc:
	kfree(ledinternal->trigger_id);

exit_internal_alloc:
	kfree(ledinternal);

exit_mutex_only:
	mutex_unlock(&(*klpe_xt_led_mutex));

	return err;
}


#include "livepatch_bsc1235431.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "xt_LED"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "led_timeout_callback", (void *)&klpe_led_timeout_callback,
	  "xt_LED" },
	{ "xt_led_mutex", (void *)&klpe_xt_led_mutex, "xt_LED" },
	{ "xt_led_triggers", (void *)&klpe_xt_led_triggers, "xt_LED" },
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

int livepatch_bsc1235431_init(void)
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

void livepatch_bsc1235431_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_LED) */
