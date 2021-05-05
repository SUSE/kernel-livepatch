/*
 * bsc1184952_fuse_acl
 *
 * Fix for CVE-2020-36322, bsc#1184952 (fs/fuse/acl.c part)
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
static void (*klpe_fuse_invalidate_attr)(struct inode *inode);

static int (*klpe_fuse_setxattr)(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags);
static ssize_t (*klpe_fuse_getxattr)(struct inode *inode, const char *name, void *value,
		      size_t size);

static int (*klpe_fuse_removexattr)(struct inode *inode, const char *name);

struct posix_acl *klpp_fuse_get_acl(struct inode *inode, int type);
int klpp_fuse_set_acl(struct inode *inode, struct posix_acl *acl, int type);

/* klp-ccp: from fs/fuse/acl.c */
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

struct posix_acl *klpp_fuse_get_acl(struct inode *inode, int type)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	int size;
	const char *name;
	void *value = NULL;
	struct posix_acl *acl;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return ERR_PTR(-EIO);

	if (!fc->posix_acl || fc->no_getxattr)
		return NULL;

	if (type == ACL_TYPE_ACCESS)
		name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return ERR_PTR(-EOPNOTSUPP);

	value = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!value)
		return ERR_PTR(-ENOMEM);
	size = (*klpe_fuse_getxattr)(inode, name, value, PAGE_SIZE);
	if (size > 0)
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
	else if ((size == 0) || (size == -ENODATA) ||
		 (size == -EOPNOTSUPP && fc->no_getxattr))
		acl = NULL;
	else if (size == -ERANGE)
		acl = ERR_PTR(-E2BIG);
	else
		acl = ERR_PTR(size);

	kfree(value);
	return acl;
}

int klpp_fuse_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	const char *name;
	int ret;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (!fc->posix_acl || fc->no_setxattr)
		return -EOPNOTSUPP;

	if (type == ACL_TYPE_ACCESS)
		name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return -EINVAL;

	if (acl) {
		/*
		 * Fuse userspace is responsible for updating access
		 * permissions in the inode, if needed. fuse_setxattr
		 * invalidates the inode attributes, which will force
		 * them to be refreshed the next time they are used,
		 * and it also updates i_ctime.
		 */
		size_t size = posix_acl_xattr_size(acl->a_count);
		void *value;

		if (size > PAGE_SIZE)
			return -E2BIG;

		value = kmalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;

		ret = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (ret < 0) {
			kfree(value);
			return ret;
		}

		ret = (*klpe_fuse_setxattr)(inode, name, value, size, 0);
		kfree(value);
	} else {
		ret = (*klpe_fuse_removexattr)(inode, name);
	}
	forget_all_cached_acls(inode);
	(*klpe_fuse_invalidate_attr)(inode);

	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1184952.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "fuse"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_invalidate_attr", (void *)&klpe_fuse_invalidate_attr, "fuse" },
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

int livepatch_bsc1184952_fuse_acl_init(void)
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

void livepatch_bsc1184952_fuse_acl_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1184952_module_nb);
}
