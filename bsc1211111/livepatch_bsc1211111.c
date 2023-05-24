/*
 * livepatch_bsc1211111
 *
 * Fix for CVE-2023-28464, bsc#1211111
 *
 *  Upstream commit:
 *  None yet
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
 *  ee49c52bb2b677f5a405c401bdb203f263ed963c
 *
 *  SLE15-SP2 and -SP3 commit:
 *  677d92076b8c80c468d059c9ea2055ac7429cc50
 *
 *  SLE15-SP4 commit:
 *  8b250160f7a4fae56192775cf0d13208cf5c1b76
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/bluetooth/hci_conn.c */
#include <linux/export.h>
#include <linux/debugfs.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
static void (*klpe_hci_chan_list_flush)(struct hci_conn *conn);

static void (*klpe_hci_conn_params_del)(struct hci_dev *hdev, bdaddr_t *addr, u8 addr_type);

static void (*klpe_hci_conn_del_sysfs)(struct hci_conn *conn);

/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>
/* klp-ccp: from net/bluetooth/a2mp.h */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from net/bluetooth/hci_conn.c */
void klpp_hci_conn_cleanup(struct hci_conn *conn)
{
	struct hci_dev *hdev = conn->hdev;

	if (test_bit(HCI_CONN_PARAM_REMOVAL_PEND, &conn->flags))
		(*klpe_hci_conn_params_del)(conn->hdev, &conn->dst, conn->dst_type);

	(*klpe_hci_chan_list_flush)(conn);

	hci_conn_hash_del(hdev, conn);

	if (hdev->notify)
		hdev->notify(hdev, HCI_NOTIFY_CONN_DEL);

	(*klpe_hci_conn_del_sysfs)(conn);

	debugfs_remove_recursive(conn->debugfs);
}



#define LP_MODULE "bluetooth"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1211111.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "hci_chan_list_flush", (void *)&klpe_hci_chan_list_flush,
	  "bluetooth" },
	{ "hci_conn_del_sysfs", (void *)&klpe_hci_conn_del_sysfs,
	  "bluetooth" },
	{ "hci_conn_params_del", (void *)&klpe_hci_conn_params_del,
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

int livepatch_bsc1211111_init(void)
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

void livepatch_bsc1211111_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
