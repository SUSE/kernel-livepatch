/*
 * livepatch_bsc1194533
 *
 * bsc1194533_nfc_core
 *
 * Fix for CVE-2021-4202, bsc#1194533 (net/nfc/core.c part)
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if IS_ENABLED(CONFIG_NFC)

#if !IS_MODULE(CONFIG_NFC)
#error "Live patch supports only CONFIG_NFC=m"
#endif

/* klp-ccp: from net/nfc/core.c */
#define pr_fmt(fmt) "nfc" ": %s: " fmt, __func__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/overflow.h>

/* klp-ccp: from net/nfc/core.c */
#include <linux/rfkill.h>

/* klp-ccp: from include/linux/rfkill.h */
#if defined(CONFIG_RFKILL) || defined(CONFIG_RFKILL_MODULE)

static struct rfkill * __must_check (*klpe_rfkill_alloc)(const char *name,
					  struct device *parent,
					  const enum rfkill_type type,
					  const struct rfkill_ops *ops,
					  void *ops_data);

static int __must_check (*klpe_rfkill_register)(struct rfkill *rfkill);

static void (*klpe_rfkill_unregister)(struct rfkill *rfkill);

static void (*klpe_rfkill_destroy)(struct rfkill *rfkill);

static bool (*klpe_rfkill_blocked)(struct rfkill *rfkill);

#else /* !RFKILL */
#error "klp-ccp: non-taken branch"
#endif /* RFKILL || RFKILL_MODULE */

/* klp-ccp: from net/nfc/core.c */
#include <linux/nfc.h>

/* klp-ccp: from net/nfc/nfc.h */
#include <net/nfc/nfc.h>

/* klp-ccp: from include/net/nfc/nfc.h */
int klpp_nfc_register_device(struct nfc_dev *dev);

void klpp_nfc_unregister_device(struct nfc_dev *dev);

/* klp-ccp: from net/nfc/nfc.h */
static int (*klpe_nfc_llcp_register_device)(struct nfc_dev *dev);
static void (*klpe_nfc_llcp_unregister_device)(struct nfc_dev *dev);

static int (*klpe_nfc_devlist_generation);
static struct mutex (*klpe_nfc_devlist_mutex);

static int (*klpe_nfc_genl_device_added)(struct nfc_dev *dev);
static int (*klpe_nfc_genl_device_removed)(struct nfc_dev *dev);

int klpp_nfc_dev_up(struct nfc_dev *dev);

/* klp-ccp: from net/nfc/core.c */
int klpp_nfc_dev_up(struct nfc_dev *dev)
{
	int rc = 0;

	pr_debug("dev_name=%s\n", dev_name(&dev->dev));

	device_lock(&dev->dev);

	/*
	 * Fix CVE-2021-4202
	 *  +4 lines
	 */
	if (!device_is_registered(&dev->dev)) {
		rc = -ENODEV;
		goto error;
	}

	if (dev->rfkill && (*klpe_rfkill_blocked)(dev->rfkill)) {
		rc = -ERFKILL;
		goto error;
	}

	/*
	 * Fix CVE-2021-4202
	 *  -4 lines
	 */

	if (dev->fw_download_in_progress) {
		rc = -EBUSY;
		goto error;
	}

	if (dev->dev_up) {
		rc = -EALREADY;
		goto error;
	}

	if (dev->ops->dev_up)
		rc = dev->ops->dev_up(dev);

	if (!rc)
		dev->dev_up = true;

	/* We have to enable the device before discovering SEs */
	if (dev->ops->discover_se && dev->ops->discover_se(dev))
		pr_err("SE discovery failed\n");

error:
	device_unlock(&dev->dev);
	return rc;
}

static const struct rfkill_ops (*klpe_nfc_rfkill_ops);

int klpp_nfc_register_device(struct nfc_dev *dev)
{
	int rc;

	pr_debug("dev_name=%s\n", dev_name(&dev->dev));

	mutex_lock(&(*klpe_nfc_devlist_mutex));
	(*klpe_nfc_devlist_generation)++;
	rc = device_add(&dev->dev);
	mutex_unlock(&(*klpe_nfc_devlist_mutex));

	if (rc < 0)
		return rc;

	rc = (*klpe_nfc_llcp_register_device)(dev);
	if (rc)
		pr_err("Could not register llcp device\n");

	/*
	 * Fix CVE-2021-4202
	 *  -4 lines
	 */

	/*
	 * Fix CVE-2021-4202
	 *  +1 line
	 */
	device_lock(&dev->dev);
	dev->rfkill = (*klpe_rfkill_alloc)(dev_name(&dev->dev), &dev->dev,
				   RFKILL_TYPE_NFC, &(*klpe_nfc_rfkill_ops), dev);
	if (dev->rfkill) {
		if ((*klpe_rfkill_register)(dev->rfkill) < 0) {
			(*klpe_rfkill_destroy)(dev->rfkill);
			dev->rfkill = NULL;
		}
	}
	/*
	 * Fix CVE-2021-4202
	 *  +1 line
	 */
	device_unlock(&dev->dev);

	/*
	 * Fix CVE-2021-4202
	 *  +4 lines
	 */
	rc = (*klpe_nfc_genl_device_added)(dev);
	if (rc)
		pr_debug("The userspace won't be notified that the device %s was added\n",
			 dev_name(&dev->dev));

	return 0;
}

void klpp_nfc_unregister_device(struct nfc_dev *dev)
{
	int rc;

	pr_debug("dev_name=%s\n", dev_name(&dev->dev));

	/*
	 * Fix CVE-2021-4202
	 *  +4 lines
	 */
	rc = (*klpe_nfc_genl_device_removed)(dev);
	if (rc)
		pr_debug("The userspace won't be notified that the device %s "
			 "was removed\n", dev_name(&dev->dev));

	/*
	 * Fix CVE-2021-4202
	 *  +1 line
	 */
	device_lock(&dev->dev);
	if (dev->rfkill) {
		(*klpe_rfkill_unregister)(dev->rfkill);
		(*klpe_rfkill_destroy)(dev->rfkill);
	}
	/*
	 * Fix CVE-2021-4202
	 *  +1 line
	 */
	device_unlock(&dev->dev);

	if (dev->ops->check_presence) {
		device_lock(&dev->dev);
		dev->shutting_down = true;
		device_unlock(&dev->dev);
		del_timer_sync(&dev->check_pres_timer);
		cancel_work_sync(&dev->check_pres_work);
	}

	/*
	 * Fix CVE-2021-4202
	 *  -4 lines
	 */

	(*klpe_nfc_llcp_unregister_device)(dev);

	mutex_lock(&(*klpe_nfc_devlist_mutex));
	(*klpe_nfc_devlist_generation)++;
	device_del(&dev->dev);
	mutex_unlock(&(*klpe_nfc_devlist_mutex));
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1194533.h"
#include "bsc1194533_common.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfc_devlist_generation", (void *)&klpe_nfc_devlist_generation,
	  "nfc" },
	{ "nfc_devlist_mutex", (void *)&klpe_nfc_devlist_mutex, "nfc" },
	{ "nfc_genl_device_added", (void *)&klpe_nfc_genl_device_added, "nfc" },
	{ "nfc_genl_device_removed", (void *)&klpe_nfc_genl_device_removed,
	  "nfc" },
	{ "nfc_llcp_register_device", (void *)&klpe_nfc_llcp_register_device,
	  "nfc" },
	{ "nfc_llcp_unregister_device",
	  (void *)&klpe_nfc_llcp_unregister_device, "nfc" },
	{ "nfc_rfkill_ops", (void *)&klpe_nfc_rfkill_ops, "nfc" },
	{ "rfkill_alloc", (void *)&klpe_rfkill_alloc, "rfkill" },
	{ "rfkill_blocked", (void *)&klpe_rfkill_blocked, "rfkill" },
	{ "rfkill_destroy", (void *)&klpe_rfkill_destroy, "rfkill" },
	{ "rfkill_register", (void *)&klpe_rfkill_register, "rfkill" },
	{ "rfkill_unregister", (void *)&klpe_rfkill_unregister, "rfkill" },
};

static int livepatch_bsc1194533_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1194533_module_nb = {
	.notifier_call = livepatch_bsc1194533_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1194533_nfc_core_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1194533_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1194533_nfc_core_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1194533_module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC) */
