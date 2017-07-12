/*
 * livepatch_main.c - kernel live patch main infrastructure
 *
 * Copyright (c) 2014 SUSE
 *  Author: Miroslav Benes <mbenes@suse.cz>
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

#include <linux/kgraft.h>
#include <linux/module.h>
#include <linux/types.h>

#include "uname_patch/livepatch_uname.h"

@@KLP_PATCHES_INCLUDES@@

static struct kgr_patch patch = {
	.name = "kgraft-patch-@@RPMRELEASE@@",
	.owner = THIS_MODULE,
	.replace_all = true,
	.patches = {
		KGR_PATCH(SyS_newuname, klp_sys_newuname),
		@@KLP_PATCHES_FUNCS@@,
		KGR_PATCH_END
	}
};

static int __init klp_patch_init(void)
{
	int retval;

	pr_info("livepatch: initializing\n");

	retval = klp_patch_uname_init();
	if (retval)
		return retval;

	@@KLP_PATCHES_INIT_CALLS@@;

	retval = kgr_patch_kernel(&patch);
	if (!retval)
		return retval;

	/* jumped to from expanded KLP_PATCHES_INIT_CALLS on failure */
@@KLP_PATCHES_INIT_ERR_HANDLERS@@:
}

static void __exit klp_patch_cleanup(void)
{
	pr_info("livepatch: removed\n");

	@@KLP_PATCHES_CLEANUP_CALLS@@;

	kgr_patch_remove(&patch);
}

module_init(klp_patch_init);
module_exit(klp_patch_cleanup);

MODULE_LICENSE("GPL");
