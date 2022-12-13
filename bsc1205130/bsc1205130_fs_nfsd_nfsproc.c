/*
 * bsc1205130_fs_nfsd_nfsproc
 *
 * Fix for CVE-2022-43945, bsc#1205130
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

/* klp-ccp: from fs/nfsd/nfsproc.c */
#include <linux/namei.h>
/* klp-ccp: from fs/nfsd/cache.h */
#include <linux/sunrpc/svc.h>

/* klp-ccp: from include/linux/sunrpc/debug.h */
static unsigned int		(*klpe_nfsd_debug);

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>
#include <linux/nfs.h>

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/msg_prot.h>
#include <uapi/linux/nfsd/debug.h>
/* klp-ccp: from fs/nfsd/stats.h */
#include <uapi/linux/nfsd/stats.h>
/* klp-ccp: from fs/nfsd/export.h */
#include <linux/sunrpc/cache.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>

/* klp-ccp: from fs/nfsd/nfsd.h */
struct readdir_cd {
	__be32			err;	/* 0, nfserr, or nfserr_eof */
};

#define	nfs_ok			cpu_to_be32(NFS_OK)

/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/sunrpc/svc.h>
#include <uapi/linux/nfsd/nfsfh.h>

struct svc_fh {
	struct knfsd_fh		fh_handle;	/* FH data */
	int			fh_maxsize;	/* max size for fh_handle */
	struct dentry *		fh_dentry;	/* validated dentry */
	struct svc_export *	fh_export;	/* export pointer */

	bool			fh_locked;	/* inode locked by us */
	bool			fh_want_write;	/* remount protection taken */

#ifdef CONFIG_NFSD_V3
	bool			fh_post_saved;	/* post-op attrs saved */
	bool			fh_pre_saved;	/* pre-op attrs saved */

	/* Pre-op attributes saved during fh_lock */
	__u64			fh_pre_size;	/* size before operation */
	struct timespec		fh_pre_mtime;	/* mtime before oper */
	struct timespec		fh_pre_ctime;	/* ctime before oper */
	/*
	 * pre-op nfsv4 change attr: note must check IS_I_VERSION(inode)
	 *  to find out if it is valid.
	 */
	u64			fh_pre_change;

	/* Post-op attributes saved in fh_unlock */
	struct kstat		fh_post_attr;	/* full attrs after operation */
	u64			fh_post_change; /* nfsv4 change; see above */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_V3 */
};

static char * (*klpe_SVCFH_fmt)(struct svc_fh *fhp);

static void	(*klpe_fh_put)(struct svc_fh *);

/* klp-ccp: from fs/nfsd/xdr.h */
struct nfsd_readdirargs {
	struct svc_fh		fh;
	__u32			cookie;
	__u32			count;
	__be32 *		buffer;
};

struct nfsd_readdirres {
	int			count;

	struct readdir_cd	common;
	__be32 *		buffer;
	int			buflen;
	__be32 *		offset;
};

static int (*klpe_nfssvc_encode_entry)(void *, const char *name,
			int namlen, loff_t offset, u64 ino, unsigned int);

/* klp-ccp: from fs/nfsd/vfs.h */
typedef int (*nfsd_filldir_t)(void *, const char *, int, loff_t, u64, unsigned);

static __be32		(*klpe_nfsd_readdir)(struct svc_rqst *, struct svc_fh *,
			     loff_t *, struct readdir_cd *, nfsd_filldir_t);

#include "common.h"

/* klp-ccp: from fs/nfsd/nfsproc.c */
__be32
klpp_nfsd_proc_readdir(struct svc_rqst *rqstp, struct nfsd_readdirargs *argp,
					  struct nfsd_readdirres  *resp)
{
	int		count;
	__be32		nfserr;
	loff_t		offset;

	klpr_dprintk("nfsd: READDIR  %s %d bytes at %d\n",
			(*klpe_SVCFH_fmt)(&argp->fh),
			argp->count, argp->cookie);

	count = argp->count;
	if (count > PAGE_SIZE)
		count = PAGE_SIZE;
	/* Shrink to the client read size */
	count = (count >> 2) - 2;

	/* Make sure we've room for the NULL ptr & eof flag */
	count -= 2;
	if (count < 0)
		count = 0;

	resp->buffer = argp->buffer;
	resp->offset = NULL;
	resp->buflen = count;
	resp->common.err = nfs_ok;
	/* Read directory and encode entries on the fly */
	offset = argp->cookie;
	nfserr = (*klpe_nfsd_readdir)(rqstp, &argp->fh, &offset, 
			      &resp->common, (*klpe_nfssvc_encode_entry));

	resp->count = resp->buffer - argp->buffer;
	if (resp->offset)
		*resp->offset = htonl(offset);

	(*klpe_fh_put)(&argp->fh);
	return nfserr;
}



#define LP_MODULE "nfsd"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1205130.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "SVCFH_fmt", (void *)&klpe_SVCFH_fmt, "nfsd" },
	{ "fh_put", (void *)&klpe_fh_put, "nfsd" },
	{ "nfsd_debug", (void *)&klpe_nfsd_debug, "sunrpc" },
	{ "nfsd_readdir", (void *)&klpe_nfsd_readdir, "nfsd" },
	{ "nfssvc_encode_entry", (void *)&klpe_nfssvc_encode_entry, "nfsd" },
};

static int bsc1205130_fs_nfsd_nfsproc_module_notify(struct notifier_block *nb,
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
	.notifier_call = bsc1205130_fs_nfsd_nfsproc_module_notify,
	.priority = INT_MIN+1,
};

int bsc1205130_fs_nfsd_nfsproc_init(void)
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

void bsc1205130_fs_nfsd_nfsproc_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
