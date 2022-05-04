/*
 * livepatch_bsc1195950
 *
 * Fix for CVE-2022-0330, bsc#1195950
 *
 *  Upstream commit:
 *  7938d61591d3 ("drm/i915: Flush TLBs before releasing backing store")
 *
 *  SLE12-SP3 commit:
 *  68b92fb8d3149f05649003fdbf99168e53ea3198
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  bd1197687ae6a09d70ace8029168a1a04d1f5a97
 *
 *  SLE12-SP5 commit:
 *  20f1914787a7c5a9cf8b2c0b5063f680a2139661
 *
 *  SLE15-SP2 and -SP3 commit:
 *  34a8919224693e65319ed46298c4f64727c7a95f
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

#if IS_ENABLED(CONFIG_DRM_I915)

#if !IS_MODULE(CONFIG_DRM_I915)
#error "Live patch supports only CONFIG_DRM_I915=m"
#endif

#include "bsc1195950_common.h"
#include "livepatch_bsc1195950.h"
#include "../kallsyms_relocs.h"

int livepatch_bsc1195950_init(void)
{
	int ret;

	ret = livepatch_bsc1195950_i915_vma_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1195950_i915_gem_init();
	if (ret) {
		livepatch_bsc1195950_i915_vma_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1195950_cleanup(void)
{
	livepatch_bsc1195950_i915_gem_cleanup();
	livepatch_bsc1195950_i915_vma_cleanup();
}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
