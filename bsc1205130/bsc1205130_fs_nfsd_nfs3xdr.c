/*
 * bsc1205130_fs_nfsd_nfs3xdr
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

/* klp-ccp: from fs/nfsd/nfs3xdr.c */
#include <linux/namei.h>
#include <linux/sunrpc/svc_xprt.h>

/* klp-ccp: from include/linux/sunrpc/svc.h */
static u32 (*klpe_svc_max_payload)(const struct svc_rqst *rqstp);

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>

/* klp-ccp: from include/uapi/linux/nfs4.h */
#define NFS4_FHSIZE		128

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
/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/sunrpc/svc.h>
#include <uapi/linux/nfsd/nfsfh.h>
#include <linux/iversion.h>

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

static __inline__ struct svc_fh *
fh_init(struct svc_fh *fhp, int maxsize)
{
	memset(fhp, 0, sizeof(*fhp));
	fhp->fh_maxsize = maxsize;
	return fhp;
}

/* klp-ccp: from fs/nfsd/xdr3.h */
struct nfsd3_readargs {
	struct svc_fh		fh;
	__u64			offset;
	__u32			count;
	int			vlen;
};

/* klp-ccp: from fs/nfsd/netns.h */
#include <net/net_namespace.h>

/* klp-ccp: from fs/nfsd/nfs3xdr.c */
static __be32 *
decode_fh(__be32 *p, struct svc_fh *fhp)
{
	unsigned int size;
	fh_init(fhp, NFS3_FHSIZE);
	size = ntohl(*p++);
	if (size > NFS3_FHSIZE)
		return NULL;

	memcpy(&fhp->fh_handle.fh_base, p, size);
	fhp->fh_handle.fh_size = size;
	return p + XDR_QUADLEN(size);
}

int
klpp_nfs3svc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readargs *args)
{
	unsigned int len;
	int v;
	u32 max_blocksize = (*klpe_svc_max_payload)(rqstp);

	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;
	p = xdr_decode_hyper(p, &args->offset);

	args->count = ntohl(*p++);
	len = min(args->count, max_blocksize);
	len = min(len, rqstp->rq_res.buflen);

	/* set up the kvec */
	v=0;
	while (len > 0) {
		struct page *p = *(rqstp->rq_next_page++);

		rqstp->rq_vec[v].iov_base = page_address(p);
		rqstp->rq_vec[v].iov_len = min_t(unsigned int, len, PAGE_SIZE);
		len -= rqstp->rq_vec[v].iov_len;
		v++;
	}
	args->vlen = v;
	return xdr_argsize_check(rqstp, p);
}



#define LP_MODULE "nfsd"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1205130.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "svc_max_payload", (void *)&klpe_svc_max_payload, "sunrpc" },
};

static int bsc1205130_fs_nfsd_nfs3xdr_module_notify(struct notifier_block *nb,
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
	.notifier_call = bsc1205130_fs_nfsd_nfs3xdr_module_notify,
	.priority = INT_MIN+1,
};

int bsc1205130_fs_nfsd_nfs3xdr_init(void)
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

void bsc1205130_fs_nfsd_nfs3xdr_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
