#include <linux/kgraft.h>
#include <linux/module.h>
#include <linux/types.h>

#include "uname_patch/kgr_patch_uname.h"

static struct kgr_patch patch = {
	.name = "kgraft-patch-@@RELEASE@@",
	.owner = THIS_MODULE,
	.patches = {
		KGR_PATCH(SyS_newuname, kgr_sys_newuname, true),
		KGR_PATCH_END
	}
};

static int __init kgr_patch_init(void)
{
	int retval;

	pr_info("kgraft-patch: initializing\n");

	retval = kgr_patch_uname_init();
	if (retval)
		return retval;

	return kgr_patch_kernel(&patch);
}

static void __exit kgr_patch_cleanup(void)
{
	pr_info("kgraft-patch: removed\n");

	kgr_patch_remove(&patch);
}

module_init(kgr_patch_init);
module_exit(kgr_patch_cleanup);

MODULE_LICENSE("GPL");
