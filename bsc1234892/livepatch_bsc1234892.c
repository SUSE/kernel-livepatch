/*
 * livepatch_bsc1234892
 *
 * Fix for CVE-2024-53173, bsc#1234892
 *
 *  Upstream commit:
 *  2fdb05dc0931 ("NFSv4.0: Fix a use-after-free problem in the asynchronous open()")
 *
 *  SLE12-SP5 commit:
 *  a7e3c22f0677df583d33bdd5c9344a08250837df
 *
 *  SLE15-SP3 commit:
 *  a94e553d68dc263090e96d42b9012db1826d767c
 *
 *  SLE15-SP4 and -SP5 commit:
 *  f801b5bdd060f9e5f2f1f51c05fa5a4fea53b773
 *
 *  SLE15-SP6 commit:
 *  9d06142475ccaf4094ca8fb270be42048efec952
 *
 *  SLE MICRO-6-0 commit:
 *  9d06142475ccaf4094ca8fb270be42048efec952
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Marco Crivellari <marco.crivellari@suse.com>
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

#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/ratelimit.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sunrpc/clnt.h>
#include <linux/nfs.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>

/* klp-ccp: from include/linux/nfs_page.h */
#define _LINUX_NFS_PAGE_H

/* klp-ccp: from include/uapi/linux/nfs_mount.h */
#define _LINUX_NFS_MOUNT_H

/* klp-ccp: from include/linux/mount.h */
#define _LINUX_MOUNT_H

/* klp-ccp: from fs/nfs/nfs4proc.c */
#include <linux/module.h>

#include <linux/utsname.h>

/* klp-ccp: from fs/nfs/nfs4_fs.h */
#if IS_ENABLED(CONFIG_NFS_V4)

#include <linux/seqlock.h>

static void (*klpe_nfs4_close_state)(struct nfs4_state *, fmode_t);

static void (*klpe_nfs_release_seqid)(struct nfs_seqid *seqid);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_NFS_V4 */

/* klp-ccp: from fs/nfs/internal.h */
#include <linux/mount.h>
#include <linux/security.h>

#include <linux/nfs_page.h>
#include <linux/wait_bit.h>

/* klp-ccp: from fs/nfs/iostat.h */
#include <linux/percpu.h>
#include <linux/cache.h>

/* klp-ccp: from fs/nfs/pnfs.h */
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/workqueue.h>

/* klp-ccp: from fs/nfs/netns.h */
#include <linux/nfs4.h>
#include <net/net_namespace.h>

/* klp-ccp: from fs/nfs/nfs4idmap.h */
#include <linux/uidgid.h>

/* klp-ccp: from fs/nfs/fscache.h */
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>

/* klp-ccp: from fs/nfs/nfs4trace.h */
#include <trace/define_trace.h>

/* klp-ccp: from fs/nfs/nfs4proc.c */
struct nfs4_opendata {
	struct kref kref;
	struct nfs_openargs o_arg;
	struct nfs_openres o_res;
	struct nfs_open_confirmargs c_arg;
	struct nfs_open_confirmres c_res;
	struct nfs4_string owner_name;
	struct nfs4_string group_name;
	struct nfs4_label *a_label;
	struct nfs_fattr f_attr;
	struct nfs4_label *f_label;
	struct dentry *dir;
	struct dentry *dentry;
	struct nfs4_state_owner *owner;
	struct nfs4_state *state;
	struct iattr attrs;
	unsigned long timestamp;
	unsigned int rpc_done : 1;
	unsigned int file_created : 1;
	unsigned int is_recover : 1;
	int rpc_status;
	int cancelled;
};

static void (*klpe_nfs4_opendata_put)(struct nfs4_opendata *p);

static struct nfs4_state *
(*klpe_nfs4_opendata_to_nfs4_state)(struct nfs4_opendata *data);

void klpp_nfs4_open_release(void *calldata)
{
	struct nfs4_opendata *data = calldata;
	struct nfs4_state *state = NULL;

	/* In case of error, no cleanup! */
	if (data->rpc_status != 0 || !data->rpc_done) {
		(*klpe_nfs_release_seqid)(data->o_arg.seqid);
		goto out_free;
	}
	/* If this request hasn't been cancelled, do nothing */
	if (data->cancelled == 0)
		goto out_free;
	/* In case we need an open_confirm, no cleanup! */
	if (data->o_res.rflags & NFS4_OPEN_RESULT_CONFIRM)
		goto out_free;
	state = (*klpe_nfs4_opendata_to_nfs4_state)(data);
	if (!IS_ERR(state))
		(*klpe_nfs4_close_state)(state, data->o_arg.fmode);
out_free:
	(*klpe_nfs4_opendata_put)(data);
}


#include "livepatch_bsc1234892.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nfsv4"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfs4_close_state", (void *)&klpe_nfs4_close_state, "nfsv4" },
	{ "nfs4_opendata_put", (void *)&klpe_nfs4_opendata_put, "nfsv4" },
	{ "nfs4_opendata_to_nfs4_state",
	  (void *)&klpe_nfs4_opendata_to_nfs4_state, "nfsv4" },
	{ "nfs_release_seqid", (void *)&klpe_nfs_release_seqid, "nfsv4" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1234892_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1234892_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
