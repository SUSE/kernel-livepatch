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

#include <linux/livepatch.h>
#include <linux/module.h>
#include <linux/types.h>

#include "uname_patch/livepatch_uname.h"

@@KLP_PATCHES_INCLUDES@@

static struct klp_object objs[] = {
	@@KLP_PATCHES_OBJS@@
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
	.replace = true,
};

static int __init klp_patch_init(void)
{
	int retval;

	pr_info("livepatch: initializing\n");

	retval = klp_patch_uname_init();
	if (retval)
		return retval;

	@@KLP_PATCHES_INIT_CALLS@@;

#ifndef KLP_NOREG_API
	retval = klp_register_patch(&patch);
	if (retval)
		goto err_patches_cleanup;
#endif
	retval = klp_enable_patch(&patch);
	if (!retval)
		return retval;

#ifndef KLP_NOREG_API
	WARN_ON(klp_unregister_patch(&patch));
#endif

err_patches_cleanup:
	@@KLP_PATCHES_INIT_ERR_HANDLERS@@;
	return retval;
}

static void __exit klp_patch_cleanup(void)
{
	pr_info("livepatch: removed\n");

	@@KLP_PATCHES_CLEANUP_CALLS@@;

#ifndef KLP_NOREG_API
	WARN_ON(klp_unregister_patch(&patch));
#endif
}

module_init(klp_patch_init);
module_exit(klp_patch_cleanup);

MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
