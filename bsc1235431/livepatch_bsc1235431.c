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

extern struct list_head xt_led_triggers;
extern struct mutex xt_led_mutex;

struct xt_led_info_internal {
	struct list_head list;
	int refcnt;
	char *trigger_id;
	struct led_trigger netfilter_led_trigger;
	struct timer_list timer;
};

extern void led_timeout_callback(struct timer_list *t);

static struct xt_led_info_internal *led_trigger_lookup(const char *name)
{
	struct xt_led_info_internal *ledinternal;

	list_for_each_entry(ledinternal, &xt_led_triggers, list) {
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
	    !memchr(ledinfo->id, '\0', sizeof(ledinfo->id)))
		return -EINVAL;

	mutex_lock(&xt_led_mutex);

	ledinternal = led_trigger_lookup(ledinfo->id);
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
		pr_info_ratelimited("Trigger name is already in use.\n");
		goto exit_alloc;
	}

	/* Since the letinternal timer can be shared between multiple targets,
	 * always set it up, even if the current target does not need it
	 */
	timer_setup(&ledinternal->timer, led_timeout_callback, 0);

	list_add_tail(&ledinternal->list, &xt_led_triggers);

out:
	mutex_unlock(&xt_led_mutex);

	ledinfo->internal_data = ledinternal;

	return 0;

exit_alloc:
	kfree(ledinternal->trigger_id);

exit_internal_alloc:
	kfree(ledinternal);

exit_mutex_only:
	mutex_unlock(&xt_led_mutex);

	return err;
}


#include "livepatch_bsc1235431.h"

#include <linux/livepatch.h>

extern typeof(led_timeout_callback) led_timeout_callback
	 KLP_RELOC_SYMBOL(xt_LED, xt_LED, led_timeout_callback);
extern typeof(xt_led_mutex) xt_led_mutex
	 KLP_RELOC_SYMBOL(xt_LED, xt_LED, xt_led_mutex);
extern typeof(xt_led_triggers) xt_led_triggers
	 KLP_RELOC_SYMBOL(xt_LED, xt_LED, xt_led_triggers);

#endif /* IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_LED) */
