/*
 * livepatch_bsc1227656
 *
 * Fix for CVE-2021-47496, bsc#1227656
 *
 *  Upstream commit:
 *  da353fac65fe ("net/tls: Fix flipped sign in tls_err_abort() calls")
 *
 *  SLE12-SP5 commit:
 *  af28ae747904d569b2af0a2b1a8fb6b91c53e5a5
 *
 *  SLE15-SP3 commit:
 *  c2b236a45ce753ed11c84ae3dac376ec152aafe1
 *
 *  SLE15-SP4 and -SP5 commit:
 *  8f2311390c1704a8b8d1da1e6babd703f4ae9fee
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

#include "livepatch_bsc1227656.h"

int bsc1227656_net_tls_tls_device_init(void);
int bsc1227656_net_tls_tls_sw_init(void);
void bsc1227656_net_tls_tls_sw_cleanup(void);
void bsc1227656_net_tls_tls_device_cleanup(void);

int livepatch_bsc1227656_init(void)
{
	int ret;

	ret = bsc1227656_net_tls_tls_device_init();
	if (ret)
		return ret;

	ret = bsc1227656_net_tls_tls_sw_init();
	if (ret)
		bsc1227656_net_tls_tls_device_cleanup();

	return ret;
}

void livepatch_bsc1227656_cleanup(void)
{
	bsc1227656_net_tls_tls_sw_cleanup();
	bsc1227656_net_tls_tls_device_cleanup();
}

