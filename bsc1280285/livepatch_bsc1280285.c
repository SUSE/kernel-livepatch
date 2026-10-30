/*
 * livepatch_bsc1280285
 *
 * Fix for CVE-2026-89674, bsc#1280285
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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


#include "livepatch_bsc1280285.h"


/* klp-ccp: from fs/nfsd/flexfilelayoutxdr.c */
#include <linux/sunrpc/svc.h>
#include <linux/nfs4.h>

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>
#include <linux/mount.h>

#include <linux/nfs.h>
#include <linux/nfs2.h>
#include <linux/nfs3.h>
#include <linux/nfs4.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/sunrpc/msg_prot.h>
#include <linux/sunrpc/addr.h>

#include <uapi/linux/nfsd/debug.h>

/* klp-ccp: from fs/nfsd/netns.h */
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/filelock.h>
#include <linux/percpu_counter.h>
#include <linux/siphash.h>
/* klp-ccp: from fs/nfsd/export.h */
#include <linux/sunrpc/cache.h>
#include <linux/percpu_counter.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>
/* klp-ccp: from fs/nfsd/stats.h */
#include <uapi/linux/nfsd/stats.h>
#include <linux/percpu_counter.h>

/* klp-ccp: from fs/nfsd/nfsd.h */
#define	nfserr_toosmall		cpu_to_be32(NFSERR_TOOSMALL)

/* klp-ccp: from fs/nfsd/flexfilelayoutxdr.h */
#include <linux/inet.h>

/* klp-ccp: from fs/nfsd/state.h */
#include <linux/idr.h>
#include <linux/refcount.h>
#include <linux/sunrpc/svc_xprt.h>
/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/crc32.h>
#include <linux/sunrpc/svc.h>
#include <linux/iversion.h>
#include <linux/exportfs.h>
#include <linux/nfs4.h>

/* klp-ccp: from fs/nfsd/state.h */
typedef struct {
	u32             cl_boot;
	u32             cl_id;
} clientid_t;

typedef struct {
	clientid_t	so_clid;
	u32		so_id;
} stateid_opaque_t;

typedef struct {
	u32                     si_generation;
	stateid_opaque_t        si_opaque;
} stateid_t;

/* klp-ccp: from fs/nfsd/xdr4.h */
struct nfsd4_deviceid {
	u64			fsid_idx;
	u32			generation;
	u32			pad;
};

struct nfsd4_layout_seg {
	u32			iomode;
	u64			offset;
	u64			length;
};

struct nfsd4_layoutget {
	u64			lg_minlength;	/* request */
	u32			lg_signal;	/* request */
	u32			lg_layout_type;	/* request */
	u32			lg_maxcount;	/* request */
	stateid_t		lg_sid;		/* request/response */
	struct nfsd4_layout_seg	lg_seg;		/* request/response */
	void			*lg_content;	/* response */
};

/* klp-ccp: from fs/nfsd/flexfilelayoutxdr.h */
struct pnfs_ff_layout {
	u32				flags;
	u32				stats_collect_hint;
	kuid_t				uid;
	kgid_t				gid;
	struct nfsd4_deviceid		deviceid;
	stateid_t			stateid;
	struct nfs_fh			fh;
};
/* klp-ccp: from fs/nfsd/flexfilelayoutxdr.c */
struct ff_idmap {
	char buf[11];
	int len;
};

__be32
klpp_nfsd4_ff_encode_layoutget(struct xdr_stream *xdr,
		struct nfsd4_layoutget *lgp)
{
	struct pnfs_ff_layout *fl = lgp->lg_content;
	int len, mirror_len, ds_len, fh_len;
	__be32 *p;

	/*
	 * Unlike nfsd4_encode_user, we know these will
	 * always be stringified.
	 */
	struct ff_idmap uid;
	struct ff_idmap gid;

	fh_len = 4 + xdr_align_size(fl->fh.size);

	uid.len = sprintf(uid.buf, "%u", from_kuid(&init_user_ns, fl->uid));
	gid.len = sprintf(gid.buf, "%u", from_kgid(&init_user_ns, fl->gid));

	/* data server entry: deviceid + efficiency + stateid + fh list +
	 * user + group + flags + stats_collect_hint
	 */
	ds_len = 16 + 4 + 4 + sizeof(stateid_opaque_t) + 4 + fh_len +
		 4 + xdr_align_size(uid.len) +
		 4 + xdr_align_size(gid.len) +
		 4 + 4;

	/* mirror: ds_count + ds */
	mirror_len = 4 + ds_len;

	/* stripe_unit + mirror_count + mirror */
	len = 12 + mirror_len;

	p = xdr_reserve_space(xdr, sizeof(__be32) + len);
	if (!p)
		return nfserr_toosmall;

	*p++ = cpu_to_be32(len);
	p = xdr_encode_hyper(p, 0);		/* stripe unit of 1 */

	*p++ = cpu_to_be32(1);			/* single mirror */
	*p++ = cpu_to_be32(1);			/* single data server */

	p = xdr_encode_opaque_fixed(p, &fl->deviceid,
			sizeof(struct nfsd4_deviceid));

	*p++ = cpu_to_be32(1);			/* efficiency */

	*p++ = cpu_to_be32(fl->stateid.si_generation);
	p = xdr_encode_opaque_fixed(p, &fl->stateid.si_opaque,
				    sizeof(stateid_opaque_t));

	*p++ = cpu_to_be32(1);			/* single file handle */
	p = xdr_encode_opaque(p, fl->fh.data, fl->fh.size);

	p = xdr_encode_opaque(p, uid.buf, uid.len);
	p = xdr_encode_opaque(p, gid.buf, gid.len);

	*p++ = cpu_to_be32(fl->flags);
	*p++ = cpu_to_be32(0);			/* No stats collect hint */

	return 0;
}


#include <linux/livepatch.h>

extern typeof(xdr_encode_opaque) xdr_encode_opaque
	 KLP_RELOC_SYMBOL(nfsd, sunrpc, xdr_encode_opaque);
extern typeof(xdr_encode_opaque_fixed) xdr_encode_opaque_fixed
	 KLP_RELOC_SYMBOL(nfsd, sunrpc, xdr_encode_opaque_fixed);
extern typeof(xdr_reserve_space) xdr_reserve_space
	 KLP_RELOC_SYMBOL(nfsd, sunrpc, xdr_reserve_space);
