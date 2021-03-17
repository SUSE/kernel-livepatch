/*
 * livepatch_bsc1183491
 *
 * Fix for CVE-2021-27363, bsc#1183491 and CVE-2021-27365, bsc#1183491
 *
 *  Upstream commits:
 *  688e8128b7a9 ("scsi: iscsi: Restrict sessions and handles to admin
 *                 capabilities")
 *  ec98ea7070e9 ("scsi: iscsi: Ensure sysfs attributes are limited to
 *                 PAGE_SIZE")
 *  f9dbdf97a5bd ("scsi: iscsi: Verify lengths on passthrough PDUs")
 *
 *  SLE12-SP2 and -SP3 commits:
 *  670f56951e6b77bd42bba74a9459bd07307c56ba
 *  fdc973111aef18e0443e10cf6905e9c192f5573e
 *  903ccb311de04d188af5278423e71ad12878e76d
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  f14c2105dc0b71323c4410fe64c15475d3bb12c5
 *  c735b963be02511be79e624207842e75f0b636f5
 *  ee332c851e6d760d7e682a3a25f21a8466e6464f
 *
 *  SLE15-SP2 commits:
 *  826d5cf3adffd826b98978db640a16045e668914
 *  acb20306c6d406627221e342152959b85c01d928
 *  e5416af443758ea72e3411c5c43a02b2ae3838dd
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

#include "livepatch_bsc1183491.h"

int livepatch_bsc1183491_init(void)
{
	int r;

	r = livepatch_bsc1183491_scsi_transport_iscsi_init();
	if (r)
		return r;

	r = livepatch_bsc1183491_libiscsi_init();
	if (r) {
		livepatch_bsc1183491_scsi_transport_iscsi_cleanup();
		return r;
	}

	return 0;
}

void livepatch_bsc1183491_cleanup(void)
{
	livepatch_bsc1183491_libiscsi_cleanup();
	livepatch_bsc1183491_scsi_transport_iscsi_cleanup();
}
