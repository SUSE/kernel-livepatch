/*
 * livepatch_bsc1191529
 *
 *  Upstream commits:
 *  56c5485c9e44 ("ath: Use safer key clearing with key cache entries")
 *  73488cb2fa3b ("ath9k: Clear key cache explicitly on disabling hardware")
 *  d2d3e36498dd ("ath: Export ath_hw_keysetmac()")
 *  144cd24dbc36 ("ath: Modify ath_key_delete() to not need full key entry")
 *  ca2848022c12 ("ath9k: Postpone key cache entry deletion for TXQ frames
 *                 reference it")
 *
 *  SLE12-SP3 commits:
 *  8c0142ca0026982b3ff17feb862f2f78848357ef
 *  ce443683246d040ea559e8ff37b190b1eea3b96a
 *  c7cfb634342ba3d8d549c535e53751b3a0236deb
 *  de78b6b8e8c478d3697fc0b78057d676d78683b5
 *  f4306c22e25fb34c82a1d3a078850aa1d0063fcb
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  2d0097069ce307e8c24e32792b7490ac1c242fcc
 *  04f5a966cc8959a3ba52622d43f7b4ca29b10a80
 *  e6ac1c61d587219e600d64f105b176c4cba420e9
 *  7adabdc8cd1cc1bed52477ac65d8fad581f4ce8f
 *  9bf1f4570c6545805c7fa16529cf620af102d577
 *
 *  SLE15-SP2 and -SP3 commits:
 *  b69767caf7aec09a820ce07e596e4372a75d6006
 *  0519ef581f16d169be8d5481eb2734f9fd0d1914
 *  5a642313b4c3c26d383b9f93fcc95de22255b839
 *  14aef619cd393e5d1223812387962ad68b95c850
 *  5fe383f4313ced240d492d2f618ccd31816e3694
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

#if IS_ENABLED(CONFIG_ATH9K)

#if !IS_MODULE(CONFIG_ATH9K)
#error "Live patch supports only CONFIG_ATH9K=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1191529.h"
#include "bsc1191529_common.h"

int livepatch_bsc1191529_init(void)
{
	int ret;

	ret = livepatch_bsc1191529_ath_key_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1191529_ath9k_main_init();
	if (ret) {
		livepatch_bsc1191529_ath_key_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1191529_cleanup(void)
{
	livepatch_bsc1191529_ath9k_main_cleanup();
	livepatch_bsc1191529_ath_key_cleanup();
}

#endif /* IS_ENABLED(CONFIG_ATH9K) */
