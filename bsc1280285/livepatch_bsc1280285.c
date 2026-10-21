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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from fs/nfsd/flexfilelayoutxdr.c */
#include <linux/sunrpc/svc.h>

/* klp-ccp: from include/linux/sunrpc/xdr.h */
#ifdef __KERNEL__

static __be32 *(*klpe_xdr_encode_opaque_fixed)(__be32 *p, const void *ptr, unsigned int len);
static __be32 *(*klpe_xdr_encode_opaque)(__be32 *p, const void *ptr, unsigned int len);

static __be32 *(*klpe_xdr_reserve_space)(struct xdr_stream *xdr, size_t nbytes);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __KERNEL__ */

/* klp-ccp: from fs/nfsd/flexfilelayoutxdr.c */
#include <linux/nfs4.h>

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>
#include <linux/mount.h>

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
#define	nfserr_toosmall		cpu_to_be32(NFSERR_TOOSMALL)

/* klp-ccp: from fs/nfsd/flexfilelayoutxdr.h */
#include <linux/inet.h>

/* klp-ccp: from fs/nfsd/state.h */
#include <linux/idr.h>
#include <linux/sunrpc/svc_xprt.h>

/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/crc32.h>
#include <linux/sunrpc/svc.h>
#include <uapi/linux/nfsd/nfsfh.h>
#include <linux/iversion.h>

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

	p = (*klpe_xdr_reserve_space)(xdr, sizeof(__be32) + len);
	if (!p)
		return nfserr_toosmall;

	*p++ = cpu_to_be32(len);
	p = xdr_encode_hyper(p, 0);		/* stripe unit of 1 */

	*p++ = cpu_to_be32(1);			/* single mirror */
	*p++ = cpu_to_be32(1);			/* single data server */

	p = (*klpe_xdr_encode_opaque_fixed)(p, &fl->deviceid,
			sizeof(struct nfsd4_deviceid));

	*p++ = cpu_to_be32(1);			/* efficiency */

	*p++ = cpu_to_be32(fl->stateid.si_generation);
	p = (*klpe_xdr_encode_opaque_fixed)(p, &fl->stateid.si_opaque,
				    sizeof(stateid_opaque_t));

	*p++ = cpu_to_be32(1);			/* single file handle */
	p = (*klpe_xdr_encode_opaque)(p, fl->fh.data, fl->fh.size);

	p = (*klpe_xdr_encode_opaque)(p, uid.buf, uid.len);
	p = (*klpe_xdr_encode_opaque)(p, gid.buf, gid.len);

	*p++ = cpu_to_be32(fl->flags);
	*p++ = cpu_to_be32(0);			/* No stats collect hint */

	return 0;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nfsd"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xdr_encode_opaque", (void *)&klpe_xdr_encode_opaque, "sunrpc" },
	{ "xdr_encode_opaque_fixed", (void *)&klpe_xdr_encode_opaque_fixed,
	  "sunrpc" },
	{ "xdr_reserve_space", (void *)&klpe_xdr_reserve_space, "sunrpc" },
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

int livepatch_bsc1280285_init(void)
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

void livepatch_bsc1280285_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
