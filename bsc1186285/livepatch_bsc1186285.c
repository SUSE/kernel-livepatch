/*
 * livepatch_bsc1186285
 *
 * Fix for CVE-2021-33034, bsc#1186285
 *
 *  Upstream commit:
 *  5c4c8c954409 ("Bluetooth: verify AMP hci_chan before amp_destroy")
 *
 *  SLE12-SP3 commit:
 *  e24f222c5b9f1320eb2555c774f26618d9bb8c08
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  daddd4ee5fcbbbee79ee00fcd240e90edc6cb1de
 *
 *  SLE15-SP2 commit:
 *  f6d837e2e05e4be7d72988f1bd327ffc927ae2c3
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
#include "bsc1186285_common.h"
#include "livepatch_bsc1186285.h"

int livepatch_bsc1186285_init(void)
{
	int ret;

	ret = livepatch_bsc1186285_hci_conn_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1186285_hci_event_init();
	if (ret) {
		livepatch_bsc1186285_hci_conn_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1186285_cleanup(void)
{
	livepatch_bsc1186285_hci_event_cleanup();
	livepatch_bsc1186285_hci_conn_cleanup();
}

#endif /* IS_ENABLED(CONFIG_BT) */
