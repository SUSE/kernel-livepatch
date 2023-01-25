/*
 * livepatch_bsc1204167
 *
 * Fix for CVE-2022-3424, bsc#1204167
 *
 *  Upstream commit:
 *  643a16a0eb1d ("misc: sgi-gru: fix use-after-free error in gru_set_context_option,")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  729cf0b97120b4a820a08503de301b6d37da5ed6
 *
 *  SLE15-SP2 and -SP3 commit:
 *  721c5807c8ed4a7d6f2583aab42de3ab3e6c6dc4
 *
 *  SLE15-SP4 commit:
 *  bbc730fb53b443fa1b917cd4a7f26b567dbf586b
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

#if IS_ENABLED(CONFIG_SGI_GRU)

#if !IS_MODULE(CONFIG_SGI_GRU)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1204167.h"

int livepatch_bsc1204167_init(void)
{
	int ret;

	ret = bsc1204167_drivers_misc_sgi_gru_grufault_init();
	if (ret)
		return ret;

	ret = bsc1204167_drivers_misc_sgi_gru_grumain_init();
	if (ret)
		bsc1204167_drivers_misc_sgi_gru_grufault_cleanup();

	return ret;
}

void livepatch_bsc1204167_cleanup(void)
{
	bsc1204167_drivers_misc_sgi_gru_grumain_cleanup();
	bsc1204167_drivers_misc_sgi_gru_grufault_cleanup();
}

#endif /* IS_ENABLED(CONFIG_SGI_GRU) */
