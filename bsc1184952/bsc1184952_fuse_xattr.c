/*
 * bsc1184952_fuse_xattr
 *
 * Fix for CVE-2020-36322, bsc#1184952 (fs/fuse/xattr.c part)
 *
 *  Copyright (c) 2021 SUSE
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

#include "bsc1184952_common.h"

/* klp-ccp: from fs/fuse/fuse_i.h */
static ssize_t (*klpe_fuse_simple_request)(struct fuse_conn *fc, struct fuse_args *args);

static int (*klpe_fuse_allow_current_process)(struct fuse_conn *fc);

static int (*klpe_fuse_setxattr)(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags);
static ssize_t (*klpe_fuse_getxattr)(struct inode *inode, const char *name, void *value,
		      size_t size);
ssize_t klpp_fuse_listxattr(struct dentry *entry, char *list, size_t size);
static int (*klpe_fuse_removexattr)(struct inode *inode, const char *name);

/* klp-ccp: from fs/fuse/xattr.c */
#include <linux/xattr.h>

static int fuse_verify_xattr_list(char *list, size_t size)
{
	size_t origsize = size;

	while (size) {
		size_t thislen = strnlen(list, size);

		if (!thislen || thislen == size)
			return -EIO;

		size -= thislen + 1;
		list += thislen + 1;
	}

	return origsize;
}

ssize_t klpp_fuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (!(*klpe_fuse_allow_current_process)(fc))
		return -EACCES;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = FUSE_LISTXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	/* This is really two different operations rolled into one */
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = list;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = (*klpe_fuse_simple_request)(fc, &args);
	if (!ret && !size)
		ret = min_t(ssize_t, outarg.size, XATTR_LIST_MAX);
	if (ret > 0 && size)
		ret = fuse_verify_xattr_list(list, ret);
	if (ret == -ENOSYS) {
		fc->no_listxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

int klpp_fuse_xattr_get(const struct xattr_handler *handler,
			 struct dentry *dentry, struct inode *inode,
			 const char *name, void *value, size_t size)
{
	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	return (*klpe_fuse_getxattr)(inode, name, value, size);
}

int klpp_fuse_xattr_set(const struct xattr_handler *handler,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (!value)
		return (*klpe_fuse_removexattr)(inode, name);

	return (*klpe_fuse_setxattr)(inode, name, value, size, flags);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1184952.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "fuse"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_simple_request", (void *)&klpe_fuse_simple_request, "fuse" },
	{ "fuse_allow_current_process",
	  (void *)&klpe_fuse_allow_current_process, "fuse" },
	{ "fuse_setxattr", (void *)&klpe_fuse_setxattr, "fuse" },
	{ "fuse_getxattr", (void *)&klpe_fuse_getxattr, "fuse" },
	{ "fuse_removexattr", (void *)&klpe_fuse_removexattr, "fuse" },
};

static int livepatch_bsc1184952_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1184952_module_nb = {
	.notifier_call = livepatch_bsc1184952_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1184952_fuse_xattr_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1184952_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1184952_fuse_xattr_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1184952_module_nb);
}
