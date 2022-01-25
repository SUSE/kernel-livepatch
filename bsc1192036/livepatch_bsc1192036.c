/*
 * livepatch_bsc1192036
 *
 * Fix for CVE-2021-42739, bsc#1192036
 *
 *  Upstream commit:
 *  35d2969ea3c7 ("media: firewire: firedtv-avc: fix a buffer overflow in
 *		   avc_ca_pmt())
 *
 *  SLE12-SP2 and -SP3 commit:
 *  629d851571080512be9fbbe522cffbb225bd60a6
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d196d584449d83e3e9edbb63fe4cf963d5eaaabc
 *
 *  SLE15-SP2 and SLE15-SP3 commit:
 *  fab3d4fb108688a34c0d45791dbddfd858c10123
 *
 *
 *  Copyright (c) 2021 SUSE
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

#if IS_ENABLED(CONFIG_DVB_FIREDTV)

#if !IS_MODULE(CONFIG_DVB_FIREDTV)
#error "Live patch supports only CONFIG_DVB_FIREDTV=m"
#endif

#include "bsc1192036_common.h"
#include "livepatch_bsc1192036.h"

int livepatch_bsc1192036_init(void)
{
	int ret;

	ret = livepatch_bsc1192036_firewire_firedtv_avc_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1192036_firewire_firedtv_ci_init();
	if (ret)
		livepatch_bsc1192036_firewire_firedtv_avc_cleanup();

	return ret;
}

void livepatch_bsc1192036_cleanup(void)
{
	livepatch_bsc1192036_firewire_firedtv_ci_cleanup();
	livepatch_bsc1192036_firewire_firedtv_avc_cleanup();
}

#endif /* IS_ENABLED(CONFIG_DVB_FIREDTV) */
