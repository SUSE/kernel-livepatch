/*
 * livepatch_bsc1245805
 *
 * Fix for CVE-2025-21701, bsc#1245805
 *
 *  Upstream commit:
 *  12e070eb6964 ("net: avoid race between device unregistration and ethnl ops")
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
 *  adae27d71d229d635d79bcea0e3bba49efe3022f
 *
 *  SLE MICRO-6-0 commit:
 *  adae27d71d229d635d79bcea0e3bba49efe3022f
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from net/ethtool/netlink.c */
#include <net/sock.h>
#include <linux/ethtool_netlink.h>
#include <linux/pm_runtime.h>

/* klp-ccp: from net/ethtool/netlink.h */
#include <linux/ethtool_netlink.h>
#include <linux/netdevice.h>
#include <net/sock.h>

/* klp-ccp: from net/ethtool/module_fw.h */
#include <uapi/linux/ethtool.h>

/* klp-ccp: from net/ethtool/netlink.c */
int klpp_ethnl_ops_begin(struct net_device *dev)
{
	int ret;

	if (!dev)
		return -ENODEV;

	if (dev->dev.parent)
		pm_runtime_get_sync(dev->dev.parent);

	if (!netif_device_present(dev) ||
	    dev->reg_state >= NETREG_UNREGISTERING) {
		ret = -ENODEV;
		goto err;
	}

	if (dev->ethtool_ops->begin) {
		ret = dev->ethtool_ops->begin(dev);
		if (ret)
			goto err;
	}

	return 0;
err:
	if (dev->dev.parent)
		pm_runtime_put(dev->dev.parent);

	return ret;
}


#include "livepatch_bsc1245805.h"

