/*
 * livepatch_bsc1207190
 *
 * Fix for CVE-2023-0266, bsc#1207190
 *
 *  Upstream commit:
 *  56b88b50565c ("ALSA: pcm: Move rwsem lock inside snd_ctl_elem_read to
 *                 prevent UAF")
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  not affected
 *
 *  SLE12-SP5 commit:
 *  55a788e57b910c3ff8ae11d08cbabe1dd6dbf563
 *
 *  SLE15-SP2 and -SP3 commit:
 *  90144934172236694323615b0e358e91c38b8c78
 *
 *  SLE15-SP4 commit:
 *  ffbf830983189702e7070a85fc735a6ee83a9e2a
 *
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_SND)

#if !IS_MODULE(CONFIG_SND)
#error "Live patch supports only CONFIG_SND=m"
#endif

#if !IS_ENABLED(CONFIG_COMPAT)
#error "Live patch supports only CONFIG_COMPAT=y"
#endif

#include "livepatch_bsc1207190.h"
#include "bsc1207190_common.h"

int livepatch_bsc1207190_init(void)
{
	int ret;

	ret = livepatch_bsc1207190_fs_compat_ioctl_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1207190_snd_control_compat_init();
	if (ret) {
		livepatch_bsc1207190_fs_compat_ioctl_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1207190_cleanup(void)
{
	livepatch_bsc1207190_snd_control_compat_cleanup();
	livepatch_bsc1207190_fs_compat_ioctl_cleanup();
}

#endif /* IS_ENABLED(CONFIG_SND) */
