/*
 * livepatch_bsc1235008
 *
 * Fix for CVE-2024-53237, bsc#1235008
 *
 *  Upstream commit:
 *  27aabf27fd01 ("Bluetooth: fix use-after-free in device_for_each_child()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  af2de6e4bf8f1e84144f918f3df42a831ad177e3
 *
 *  SLE MICRO-6-0 commit:
 *  af2de6e4bf8f1e84144f918f3df42a831ad177e3
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

/* klp-ccp: from net/bluetooth/hci_sysfs.c */
#include <linux/module.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>


/* klp-ccp: from net/bluetooth/hci_sysfs.c */
void klpp_hci_conn_del_sysfs(struct hci_conn *conn)
{
	struct hci_dev *hdev = conn->hdev;

	if (!device_is_registered(&conn->dev))
		return;

	/* If there are devices using the connection as parent reset it to NULL
	 * before unregistering the device.
	 */
	while (1) {
		struct device *dev;

		dev = device_find_any_child(&conn->dev);
		if (!dev)
			break;
		device_move(dev, NULL, DPM_ORDER_DEV_LAST);
		put_device(dev);
	}

	device_del(&conn->dev);

	hci_dev_put(hdev);
}


#include "livepatch_bsc1235008.h"


#endif /* IS_ENABLED(CONFIG_BT) */
