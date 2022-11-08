/*
 * livepatch_bsc1202087
 *
 * Fix for CVE-2021-33655, bsc#1202087
 *
 *  Upstream commit:
 *  65a01e601dbb ("fbcon: Disallow setting font bigger than screen size")
 *  6c11df58fd1a ("fbmem: Check virtual screen sizes in fb_set_var()")
 *  e64242caef18 ("fbcon: Prevent that screen size is smaller than font size")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  9d99deb7058f3887c873b4b712dc781102d93b87
 *  c1a0922a4d72cf461b2369c22c847475b5199449
 *  1f7d549878e23f415da92d69ae8d55b789815bce
 *
 *  SLE15-SP2 and -SP3 commit:
 *  e399a7c03cd20ddd1b4e28453f4d9c0d1d286eb6
 *  a7693d8163e28652a0d49412524b9a71ec164815
 *  c8a71ff94ed39ecfcbd9f4a6809075bae6d3b874
 *
 *  SLE15-SP4 commit:
 *  f3fdd5b9acea26ff40331cd694b6c602a58a86f6
 *  5e4dc351518bc1b8d0854bc1418ba9c7d1ad79ff
 *  62aba3590837ae2f5f6e44483aa12b8ad3d16112
 *
 *  Copyright (c) 2022 SUSE
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

#if IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE)

#include <linux/kernel.h>
#include "livepatch_bsc1202087.h"
#include "../kallsyms_relocs.h"

int livepatch_bsc1202087_init(void)
{
	int ret;

	ret = bsc1202087_fbcon_init();
	if (ret)
		return ret;

	ret = bsc1202087_fbmem_init();
	if (ret)
		bsc1202087_fbcon_cleanup();

	return ret;
}

void livepatch_bsc1202087_cleanup(void)
{
	bsc1202087_fbmem_cleanup();
	bsc1202087_fbcon_cleanup();
}

#endif /* IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE) */
