/*
 * livepatch_bsc1194533
 *
 * Fix for CVE-2021-4202, bsc#1194533
 *
 *  Upstream commits:
 *  86cdf8e38792 ("NFC: reorganize the functions in nci_request")
 *  48b71a9e66c2 ("NFC: add NCI_UNREG flag to eliminate the race")
 *  3e3b5dfcd16a ("NFC: reorder the logic in nfc_{un,}register_device")
 *
 *  SLE12-SP3 commits:
 *  97458ad25426d512beaf53c5be788a3edf1b4ab7
 *  ce6989436807f5690d3e65c116abef4ce1f46793
 *  2717b4da4a7fe5d68fda242deae8c8b9094e6162
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  c9d1e9415b2c22e2f1765142f638fa4dfaef0bea
 *  68b4b42294fa47dc318253fbf0b38e3924b6bddd
 *  2cda40e08ff3c1998255ea2fe0211e7a60ac21b6
 *
 *  SLE15-SP2 and -SP3 commits:
 *  e14a6b56cbba37e8cc74588baee03b323c62344e
 *  92c4972a217af5e253e8774f9792cf31920da466
 *  176d8d4f49e6d173c40a8db5b849acf302534986
 *
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

#if IS_ENABLED(CONFIG_NFC_NCI)

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1194533.h"
#include "bsc1194533_common.h"

int livepatch_bsc1194533_init(void)
{
	int ret;

	ret = livepatch_bsc1194533_nfc_core_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1194533_nci_core_init();
	if (ret) {
		livepatch_bsc1194533_nfc_core_cleanup();
		return ret;
	}

	ret = livepatch_bsc1194533_nci_hci_init();
	if (ret) {
		livepatch_bsc1194533_nci_core_cleanup();
		livepatch_bsc1194533_nfc_core_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1194533_cleanup(void)
{
	livepatch_bsc1194533_nci_hci_cleanup();
	livepatch_bsc1194533_nci_core_cleanup();
	livepatch_bsc1194533_nfc_core_cleanup();
}

#endif /* IS_ENABLED(CONFIG_NFC_NCI) */
