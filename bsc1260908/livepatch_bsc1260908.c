/*
 * livepatch_bsc1260908
 *
 * Fix for CVE-2026-23274, bsc#1260908
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
#include <linux/timer.h>
#include <linux/alarmtimer.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_IDLETIMER.h>
#include <linux/kdev_t.h>
#include <linux/kobject.h>
#include <linux/workqueue.h>
#include <linux/sysfs.h>

struct idletimer_tg {
	struct list_head entry;
	struct alarm alarm;
	struct timer_list timer;
	struct work_struct work;

	struct kobject *kobj;
	struct device_attribute attr;

	unsigned int refcnt;
	u8 timer_type;
};

extern struct list_head idletimer_tg_list;
extern struct mutex list_mutex;

extern struct kobject *idletimer_tg_kobj;

static
struct idletimer_tg *__idletimer_tg_find_by_label(const char *label)
{
	struct idletimer_tg *entry;

	list_for_each_entry(entry, &idletimer_tg_list, entry) {
		if (!strcmp(label, entry->attr.attr.name))
			return entry;
	}

	return NULL;
}

int klpp_idletimer_tg_checkentry(const struct xt_tgchk_param *par);

extern ssize_t idletimer_tg_show(struct device *dev,
				 struct device_attribute *attr, char *buf);

extern void idletimer_tg_work(struct work_struct *work);

extern void idletimer_tg_expired(struct timer_list *t);

static int idletimer_check_sysfs_name(const char *name, unsigned int size)
{
	int ret;

	ret = xt_check_proc_name(name, size);
	if (ret < 0)
		return ret;

	if (!strcmp(name, "power") ||
	    !strcmp(name, "subsystem") ||
	    !strcmp(name, "uevent"))
		return -EINVAL;

	return 0;
}

static int idletimer_tg_create(struct idletimer_tg_info *info)
{
	int ret;

	info->timer = kzalloc(sizeof(*info->timer), GFP_KERNEL);
	if (!info->timer) {
		ret = -ENOMEM;
		goto out;
	}

	ret = idletimer_check_sysfs_name(info->label, sizeof(info->label));
	if (ret < 0)
		goto out_free_timer;

	sysfs_attr_init(&info->timer->attr.attr);
	info->timer->attr.attr.name = kstrdup(info->label, GFP_KERNEL);
	if (!info->timer->attr.attr.name) {
		ret = -ENOMEM;
		goto out_free_timer;
	}
	info->timer->attr.attr.mode = 0444;
	info->timer->attr.show = idletimer_tg_show;

	ret = sysfs_create_file(idletimer_tg_kobj, &info->timer->attr.attr);
	if (ret < 0) {
		pr_debug("couldn't add file to sysfs");
		goto out_free_attr;
	}

	list_add(&info->timer->entry, &idletimer_tg_list);

	timer_setup(&info->timer->timer, idletimer_tg_expired, 0);
	info->timer->refcnt = 1;

	INIT_WORK(&info->timer->work, idletimer_tg_work);

	mod_timer(&info->timer->timer,
		  msecs_to_jiffies(info->timeout * 1000) + jiffies);

	return 0;

out_free_attr:
	kfree(info->timer->attr.attr.name);
out_free_timer:
	kfree(info->timer);
out:
	return ret;
}

extern int idletimer_tg_helper(struct idletimer_tg_info *info);

int klpp_idletimer_tg_checkentry(const struct xt_tgchk_param *par)
{
	struct idletimer_tg_info *info = par->targinfo;
	int ret;

	pr_debug("checkentry targinfo%s\n", info->label);

	ret = idletimer_tg_helper(info);
	if(ret < 0)
	{
		pr_debug("checkentry helper return invalid\n");
		return -EINVAL;
	}
	mutex_lock(&list_mutex);

	info->timer = __idletimer_tg_find_by_label(info->label);
	if (info->timer) {
		if (info->timer->timer_type & XT_IDLETIMER_ALARM) {
			pr_debug("Adding/Replacing rule with same label and different timer type is not allowed\n");
			mutex_unlock(&list_mutex);
			return -EINVAL;
		}

		info->timer->refcnt++;
		mod_timer(&info->timer->timer,
			  msecs_to_jiffies(info->timeout * 1000) + jiffies);

		pr_debug("increased refcnt of timer %s to %u\n",
			 info->label, info->timer->refcnt);
	} else {
		ret = idletimer_tg_create(info);
		if (ret < 0) {
			pr_debug("failed to create timer\n");
			mutex_unlock(&list_mutex);
			return ret;
		}
	}

	mutex_unlock(&list_mutex);
	return 0;
}


#include "livepatch_bsc1260908.h"

#include <linux/livepatch.h>

extern typeof(idletimer_tg_expired) idletimer_tg_expired
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, xt_IDLETIMER, idletimer_tg_expired);
extern typeof(idletimer_tg_helper) idletimer_tg_helper
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, xt_IDLETIMER, idletimer_tg_helper);
extern typeof(idletimer_tg_kobj) idletimer_tg_kobj
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, xt_IDLETIMER, idletimer_tg_kobj);
extern typeof(idletimer_tg_list) idletimer_tg_list
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, xt_IDLETIMER, idletimer_tg_list);
extern typeof(idletimer_tg_show) idletimer_tg_show
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, xt_IDLETIMER, idletimer_tg_show);
extern typeof(idletimer_tg_work) idletimer_tg_work
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, xt_IDLETIMER, idletimer_tg_work);
extern typeof(list_mutex) list_mutex
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, xt_IDLETIMER, list_mutex);
extern typeof(xt_check_proc_name) xt_check_proc_name
	 KLP_RELOC_SYMBOL(xt_IDLETIMER, x_tables, xt_check_proc_name);
