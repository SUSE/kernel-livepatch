/*
 * bsc1205130_fs_nfsd_nfs3proc
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

/* klp-ccp: from fs/nfsd/nfs3proc.c */
#include <linux/fs.h>

/* klp-ccp: from fs/nfsd/nfs3proc.c */
#include <linux/magic.h>
/* klp-ccp: from fs/nfsd/cache.h */
#include <linux/sunrpc/svc.h>

/* klp-ccp: from include/linux/sunrpc/debug.h */
static unsigned int (*klpe_nfsd_debug);

/* klp-ccp: from include/linux/sunrpc/svc.h */
static u32 (*klpe_svc_max_payload)(const struct svc_rqst *rqstp);

static void (*klpe_svc_reserve)(struct svc_rqst *rqstp, int space);

static inline void klpr_svc_reserve_auth(struct svc_rqst *rqstp, int space)
{
	(*klpe_svc_reserve)(rqstp, space + rqstp->rq_auth_slack);
}

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>
#include <linux/nfs.h>
#include <linux/nfs3.h>

#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/msg_prot.h>
#include <uapi/linux/nfsd/debug.h>
/* klp-ccp: from fs/nfsd/stats.h */
#include <uapi/linux/nfsd/stats.h>
/* klp-ccp: from fs/nfsd/export.h */
#include <linux/sunrpc/cache.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>

struct nfsd4_fs_locations {
	uint32_t locations_count;
	struct nfsd4_fs_location *locations;
/* If we're not actually serving this data ourselves (only providing a
 * list of replicas that do serve it) then we set "migrated": */
	int migrated;
};

#define MAX_SECINFO_LIST	8

struct exp_flavor_info {
	u32	pseudoflavor;
	u32	flags;
};

struct svc_export {
	struct cache_head	h;
	struct auth_domain *	ex_client;
	int			ex_flags;
	struct path		ex_path;
	kuid_t			ex_anon_uid;
	kgid_t			ex_anon_gid;
	int			ex_fsid;
	unsigned char *		ex_uuid; /* 16 byte fsid */
	struct nfsd4_fs_locations ex_fslocs;
	uint32_t		ex_nflavors;
	struct exp_flavor_info	ex_flavors[MAX_SECINFO_LIST];
	u32			ex_layout_types;
	struct nfsd4_deviceid_map *ex_devid_map;
	struct cache_detail	*cd;
};

/* klp-ccp: from fs/nfsd/nfsd.h */
struct readdir_cd {
	__be32			err;	/* 0, nfserr, or nfserr_eof */
};

#define	nfs_ok			cpu_to_be32(NFS_OK)

#define	nfserr_notsupp		cpu_to_be32(NFSERR_NOTSUPP)

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

static __be32	(*klpe_fh_verify)(struct svc_rqst *, struct svc_fh *, umode_t, int);

static __inline__ struct svc_fh *
fh_copy(struct svc_fh *dst, struct svc_fh *src)
{
	WARN_ON(src->fh_dentry || src->fh_locked);
			
	*dst = *src;
	return dst;
}

/* klp-ccp: from fs/nfsd/xdr3.h */
struct nfsd3_readargs {
	struct svc_fh		fh;
	__u64			offset;
	__u32			count;
	int			vlen;
};

struct nfsd3_readdirargs {
	struct svc_fh		fh;
	__u64			cookie;
	__u32			dircount;
	__u32			count;
	__be32 *		verf;
	__be32 *		buffer;
};

struct nfsd3_readres {
	__be32			status;
	struct svc_fh		fh;
	unsigned long		count;
	int			eof;
};

struct nfsd3_readdirres {
	__be32			status;
	struct svc_fh		fh;
	/* Just to save kmalloc on every readdirplus entry (svc_fh is a
	 * little large for the stack): */
	struct svc_fh		scratch;
	int			count;
	__be32			verf[2];

	struct readdir_cd	common;
	__be32 *		buffer;
	int			buflen;
	__be32 *		offset;
	__be32 *		offset1;
	struct svc_rqst *	rqstp;

};

static int (*klpe_nfs3svc_encode_entry)(void *, const char *name,
				int namlen, loff_t offset, u64 ino,
				unsigned int);
static int (*klpe_nfs3svc_encode_entry_plus)(void *, const char *name,
				int namlen, loff_t offset, u64 ino,
				unsigned int);

/* klp-ccp: from fs/nfsd/vfs.h */
#define NFSD_MAY_NOP			0

typedef int (*nfsd_filldir_t)(void *, const char *, int, loff_t, u64, unsigned);

static __be32 		(*klpe_nfsd_read)(struct svc_rqst *, struct svc_fh *,
				loff_t, struct kvec *, int, unsigned long *);

static __be32		(*klpe_nfsd_readdir)(struct svc_rqst *, struct svc_fh *,
			     loff_t *, struct readdir_cd *, nfsd_filldir_t);

static inline bool nfsd_eof_on_read(long requested, long read,
				loff_t offset, loff_t size)
{
	/* We assume a short read means eof: */
	if (requested > read)
		return true;
	/*
	 * A non-short read might also reach end of file.  The spec
	 * still requires us to set eof in that case.
	 *
	 * Further operations may have modified the file size since
	 * the read, so the following check is not atomic with the read.
	 * We've only seen that cause a problem for a client in the case
	 * where the read returned a count of 0 without setting eof.
	 * That case was fixed by the addition of the above check.
	 */
	return (offset + read >= size);
}

#include "common.h"

/* klp-ccp: from fs/nfsd/nfs3proc.c */
#define RETURN_STATUS(st)	{ resp->status = (st); return (st); }

__be32
klpp_nfsd3_proc_read(struct svc_rqst *rqstp, struct nfsd3_readargs *argp,
				        struct nfsd3_readres  *resp)
{
	__be32	nfserr;
	u32	max_blocksize = (*klpe_svc_max_payload)(rqstp);
	unsigned long cnt = min(argp->count, max_blocksize);

	cnt = min_t(unsigned long, cnt, rqstp->rq_res.buflen);

	klpr_dprintk("nfsd: READ(3) %s %lu bytes at %Lu\n",
			(*klpe_SVCFH_fmt)(&argp->fh),
			(unsigned long) argp->count,
			(unsigned long long) argp->offset);

	/* Obtain buffer pointer for payload.
	 * 1 (status) + 22 (post_op_attr) + 1 (count) + 1 (eof)
	 * + 1 (xdr opaque byte count) = 26
	 */
	resp->count = cnt;
	if (argp->offset > (u64)OFFSET_MAX)
		argp->offset = (u64)OFFSET_MAX;
	klpr_svc_reserve_auth(rqstp, ((1 + NFS3_POST_OP_ATTR_WORDS + 3)<<2) + resp->count +4);

	fh_copy(&resp->fh, &argp->fh);
	nfserr = (*klpe_nfsd_read)(rqstp, &resp->fh,
				  argp->offset,
			   	  rqstp->rq_vec, argp->vlen,
				  &resp->count);
	if (nfserr == 0) {
		struct inode	*inode = d_inode(resp->fh.fh_dentry);
		resp->eof = nfsd_eof_on_read(cnt, resp->count, argp->offset,
							inode->i_size);
	}

	RETURN_STATUS(nfserr);
}

__be32
klpp_nfsd3_proc_readdir(struct svc_rqst *rqstp, struct nfsd3_readdirargs *argp,
					   struct nfsd3_readdirres  *resp)
{
	__be32		nfserr;
	int		count;

	klpr_dprintk("nfsd: READDIR(3)  %s %d bytes at %d\n",
			(*klpe_SVCFH_fmt)(&argp->fh),
			argp->count,
			(u32) argp->cookie);

	count = argp->count;
	if (count > rqstp->rq_res.buflen)
		count = rqstp->rq_res.buflen;
	if (count > (*klpe_svc_max_payload)(rqstp))
		count = (*klpe_svc_max_payload)(rqstp);
	/* Make sure we've room for the NULL ptr & eof flag, and shrink to
	 * client read size */
	count = count >> 2;
	if (count < 2)
		count = 2;
	count -= 2;

	/* Read directory and encode entries on the fly */
	fh_copy(&resp->fh, &argp->fh);

	resp->buflen = count;
	resp->common.err = nfs_ok;
	resp->buffer = argp->buffer;
	resp->rqstp = rqstp;
	nfserr = (*klpe_nfsd_readdir)(rqstp, &resp->fh, (loff_t*) &argp->cookie, 
					&resp->common, (*klpe_nfs3svc_encode_entry));
	memcpy(resp->verf, argp->verf, 8);
	resp->count = resp->buffer - argp->buffer;
	if (resp->offset) {
		loff_t offset = argp->cookie;

		if (unlikely(resp->offset1)) {
			/* we ended up with offset on a page boundary */
			*resp->offset = htonl(offset >> 32);
			*resp->offset1 = htonl(offset & 0xffffffff);
			resp->offset1 = NULL;
		} else {
			xdr_encode_hyper(resp->offset, offset);
		}
		resp->offset = NULL;
	}

	RETURN_STATUS(nfserr);
}

__be32
klpp_nfsd3_proc_readdirplus(struct svc_rqst *rqstp, struct nfsd3_readdirargs *argp,
					       struct nfsd3_readdirres  *resp)
{
	__be32	nfserr;
	int	count;
	loff_t	offset;
	struct page **p;
	caddr_t	page_addr = NULL;

	klpr_dprintk("nfsd: READDIR+(3) %s %d bytes at %d\n",
			(*klpe_SVCFH_fmt)(&argp->fh),
			argp->count,
			(u32) argp->cookie);
	count = argp->count;
	if (count > rqstp->rq_res.buflen)
		count = rqstp->rq_res.buflen;
	if (count > (*klpe_svc_max_payload)(rqstp))
		count = (*klpe_svc_max_payload)(rqstp);
	/* Convert byte count to number of words (i.e. >> 2),
	 * and reserve room for the NULL ptr & eof flag (-2 words) */
	count = argp->count >> 2;
	if (count < 2)
		count = 2;
	resp->count = count - 2;

	/* Read directory and encode entries on the fly */
	fh_copy(&resp->fh, &argp->fh);

	resp->common.err = nfs_ok;
	resp->buffer = argp->buffer;
	resp->buflen = resp->count;
	resp->rqstp = rqstp;
	offset = argp->cookie;

	nfserr = (*klpe_fh_verify)(rqstp, &resp->fh, S_IFDIR, NFSD_MAY_NOP);
	if (nfserr)
		RETURN_STATUS(nfserr);

	if (resp->fh.fh_export->ex_flags & NFSEXP_NOREADDIRPLUS)
		RETURN_STATUS(nfserr_notsupp);

	nfserr = (*klpe_nfsd_readdir)(rqstp, &resp->fh,
				     &offset,
				     &resp->common,
				     (*klpe_nfs3svc_encode_entry_plus));
	memcpy(resp->verf, argp->verf, 8);
	count = 0;
	for (p = rqstp->rq_respages + 1; p < rqstp->rq_next_page; p++) {
		page_addr = page_address(*p);

		if (((caddr_t)resp->buffer >= page_addr) &&
		    ((caddr_t)resp->buffer < page_addr + PAGE_SIZE)) {
			count += (caddr_t)resp->buffer - page_addr;
			break;
		}
		count += PAGE_SIZE;
	}
	resp->count = count >> 2;
	if (resp->offset) {
		if (unlikely(resp->offset1)) {
			/* we ended up with offset on a page boundary */
			*resp->offset = htonl(offset >> 32);
			*resp->offset1 = htonl(offset & 0xffffffff);
			resp->offset1 = NULL;
		} else {
			xdr_encode_hyper(resp->offset, offset);
		}
		resp->offset = NULL;
	}

	RETURN_STATUS(nfserr);
}



#define LP_MODULE "nfsd"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1205130.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "SVCFH_fmt", (void *)&klpe_SVCFH_fmt, "nfsd" },
	{ "fh_verify", (void *)&klpe_fh_verify, "nfsd" },
	{ "nfs3svc_encode_entry", (void *)&klpe_nfs3svc_encode_entry, "nfsd" },
	{ "nfs3svc_encode_entry_plus", (void *)&klpe_nfs3svc_encode_entry_plus,
	  "nfsd" },
	{ "nfsd_debug", (void *)&klpe_nfsd_debug, "sunrpc" },
	{ "nfsd_read", (void *)&klpe_nfsd_read, "nfsd" },
	{ "nfsd_readdir", (void *)&klpe_nfsd_readdir, "nfsd" },
	{ "svc_max_payload", (void *)&klpe_svc_max_payload, "sunrpc" },
	{ "svc_reserve", (void *)&klpe_svc_reserve, "sunrpc" },
};

static int bsc1205130_fs_nfsd_nfs3proc_module_notify(struct notifier_block *nb,
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
	.notifier_call = bsc1205130_fs_nfsd_nfs3proc_module_notify,
	.priority = INT_MIN+1,
};

int bsc1205130_fs_nfsd_nfs3proc_init(void)
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

void bsc1205130_fs_nfsd_nfs3proc_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
