/*
 * livepatch_bsc1210500
 *
 * Fix for CVE-2023-1989, bsc#1210500
 *
 *  Upstream commit:
 *  1e9ac114c442 ("Bluetooth: btsdio: fix use after free bug in btsdio_remove due to")
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
 *  636a7deabf46fc52a7910e41c09b6cc8bcc3caff
 *
 *  SLE15-SP2 and -SP3 commit:
 *  e27c00d089fc49f4191a0fdcc01087175162740e
 *
 *  SLE15-SP4 commit:
 *  cf5fb98c85c6f4da54046fcb148096c2c7c14a90
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#if IS_ENABLED(CONFIG_BT_HCIBTSDIO)

#if !IS_MODULE(CONFIG_BT_HCIBTSDIO)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/bluetooth/btsdio.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sdio_func.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
#define BT_DBG(fmt, ...)	pr_debug(fmt "\n", ##__VA_ARGS__)

struct hci_dev;

/* klp-ccp: from include/net/bluetooth/hci_core.h */
static void (*klpe_hci_free_dev)(struct hci_dev *hdev);

static void (*klpe_hci_unregister_dev)(struct hci_dev *hdev);

/* klp-ccp: from drivers/bluetooth/btsdio.c */
struct btsdio_data {
	struct hci_dev   *hdev;
	struct sdio_func *func;

	struct work_struct work;

	struct sk_buff_head txq;
};

void klpp_btsdio_remove(struct sdio_func *func)
{
	struct btsdio_data *data = sdio_get_drvdata(func);
	struct hci_dev *hdev;

	BT_DBG("func %p", func);

	if (!data)
		return;

	cancel_work_sync(&data->work);
	hdev = data->hdev;

	sdio_set_drvdata(func, NULL);

	(*klpe_hci_unregister_dev)(hdev);

	(*klpe_hci_free_dev)(hdev);
}



#define LP_MODULE "btsdio"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1210500.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "hci_free_dev", (void *)&klpe_hci_free_dev, "bluetooth" },
	{ "hci_unregister_dev", (void *)&klpe_hci_unregister_dev,
	  "bluetooth" },
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

int livepatch_bsc1210500_init(void)
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

void livepatch_bsc1210500_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT_HCIBTSDIO) */
