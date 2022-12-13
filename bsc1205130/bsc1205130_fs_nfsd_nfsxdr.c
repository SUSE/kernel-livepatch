/*
 * bsc1205130_fs_nfsd_nfsxdr
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

/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/crc32.h>
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

static __inline__ struct svc_fh *
fh_init(struct svc_fh *fhp, int maxsize)
{
	memset(fhp, 0, sizeof(*fhp));
	fhp->fh_maxsize = maxsize;
	return fhp;
}

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>
#include <linux/nfs.h>
#include <linux/nfs2.h>
#include <linux/nfs3.h>
#include <linux/nfs4.h>
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
#define NFSSVC_MAXBLKSIZE_V2    (8*1024)

/* klp-ccp: from fs/nfsd/xdr.h */
struct nfsd_readargs {
	struct svc_fh		fh;
	__u32			offset;
	__u32			count;
	int			vlen;
};

/* klp-ccp: from fs/nfsd/nfsxdr.c */
static __be32 *
decode_fh(__be32 *p, struct svc_fh *fhp)
{
	fh_init(fhp, NFS_FHSIZE);
	memcpy(&fhp->fh_handle.fh_base, p, NFS_FHSIZE);
	fhp->fh_handle.fh_size = NFS_FHSIZE;

	/* FIXME: Look up export pointer here and verify
	 * Sun Secure RPC if requested */
	return p + (NFS_FHSIZE >> 2);
}


int
klpp_nfssvc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readargs *args)
{
	unsigned int len;
	int v;
	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;

	args->offset    = ntohl(*p++);
	len = args->count     = ntohl(*p++);
	p++; /* totalcount - unused */

	len = min_t(unsigned int, len, NFSSVC_MAXBLKSIZE_V2);
	len = min_t(unsigned int, len, rqstp->rq_res.buflen);

	/* set up somewhere to store response.
	 * We take pages, put them on reslist and include in iovec
	 */
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



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1205130.h"

int bsc1205130_fs_nfsd_nfsxdr_init(void)
{
	return 0;
}

void bsc1205130_fs_nfsd_nfsxdr_cleanup(void)
{
	return;
}
