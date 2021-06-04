/*
 * livepatch_bsc1185899
 *
 * Fix for CVE-2021-32399, bsc#1185899
 *
 *  Upstream commit:
 *  e2cb6b891ad2 ("bluetooth: eliminate the potential race condition when
 *                 removing the HCI controller")
 *
 *  SLE12-SP3 commit:
 *  12d067d47245adf44b7ed85f4d752157fe0818af
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  4b51cab85bfc062d1abace713e95252760b8ca29
 *
 *  SLE12-SP5 commit:
 *  089b28d63c3c114bef838b99d201590eeaab5b73
 *
 *  SLE15-SP2 commit:
 *  3c88de9e7a9b84d6124e3b97abd13d6ee54bbdf3
 *
 *
 *  Copyright (c) 2021 SUSE
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG_BT=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1185899.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "bluetooth"

/* klp-ccp: from net/bluetooth/hci_request.c */
#include <linux/sched/signal.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>
/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>

#define hci_req_sync_lock(hdev)   mutex_lock(&hdev->req_lock)
#define hci_req_sync_unlock(hdev) mutex_unlock(&hdev->req_lock)

struct hci_request;

int klpp_hci_req_sync(struct hci_dev *hdev, int (*req)(struct hci_request *req,
						  unsigned long opt),
		 unsigned long opt, u32 timeout, u8 *hci_status);
static int (*klpe___hci_req_sync)(struct hci_dev *hdev, int (*func)(struct hci_request *req,
						     unsigned long opt),
		   unsigned long opt, u32 timeout, u8 *hci_status);

/* klp-ccp: from net/bluetooth/hci_request.c */
int klpp_hci_req_sync(struct hci_dev *hdev, int (*req)(struct hci_request *req,
						  unsigned long opt),
		 unsigned long opt, u32 timeout, u8 *hci_status)
{
	int ret;

	/*
	 * Fix CVE-2021-32399
	 *  -2 lines
	 */

	/* Serialize all requests */
	hci_req_sync_lock(hdev);
	/*
	 * Fix CVE-2021-32399
	 *  -1 line, +8 lines
	 */
	/* check the state after obtaing the lock to protect the HCI_UP
	 * against any races from hci_dev_do_close when the controller
	 * gets removed.
	 */
	if (test_bit(HCI_UP, &hdev->flags))
		ret = (*klpe___hci_req_sync)(hdev, req, opt, timeout, hci_status);
	else
		ret = -ENETDOWN;
	hci_req_sync_unlock(hdev);

	return ret;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__hci_req_sync", (void *)&klpe___hci_req_sync, "bluetooth" },
};

static int livepatch_bsc1185899_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1185899_module_nb = {
	.notifier_call = livepatch_bsc1185899_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1185899_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1185899_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1185899_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1185899_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
