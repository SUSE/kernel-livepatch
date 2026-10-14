/*
 * livepatch_bsc1272386
 *
 * Fix for CVE-2026-63887, bsc#1272386
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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

#include "livepatch_bsc1272386.h"

int livepatch_bsc1272386_init(void)
{

	int ret;

	ret = bsc1272386_drivers_target_iscsi_iscsi_target_nego_init();
	if (ret)
		return ret;

	ret = bsc1272386_drivers_target_iscsi_iscsi_target_parameters_init();
	if (ret)
		return ret;

	return 0;
}

void livepatch_bsc1272386_cleanup(void)
{
	bsc1272386_drivers_target_iscsi_iscsi_target_nego_cleanup();

	bsc1272386_drivers_target_iscsi_iscsi_target_parameters_cleanup();

}

