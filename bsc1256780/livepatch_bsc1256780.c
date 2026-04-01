/*
 * livepatch_bsc1256780
 *
 * Fix for CVE-2025-71120, bsc#1256780
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

/* klp-ccp: from net/sunrpc/auth_gss/svcauth_gss.c */
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/user_namespace.h>

#include <linux/sunrpc/auth_gss.h>
#include <linux/sunrpc/gss_err.h>
#include <linux/sunrpc/svcauth.h>
#include <linux/sunrpc/svcauth_gss.h>
#include <linux/sunrpc/cache.h>

/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_upcall.h */
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/auth_gss.h>

/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_xdr.h */
#include <linux/sunrpc/xdr.h>

struct gssp_in_token {
	struct page **pages;	/* Array of contiguous pages */
	unsigned int page_base;	/* Start of page data */
	unsigned int page_len;	/* Length of page data */
};

/* klp-ccp: from net/sunrpc/netns.h */
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "livepatch_bsc1256780.h"

struct sunrpc_net {
	struct proc_dir_entry *proc_net_rpc;
	struct cache_detail *ip_map_cache;
	struct cache_detail *unix_gid_cache;
	struct cache_detail *rsc_cache;
	struct cache_detail *rsi_cache;

	struct super_block *pipefs_sb;
	struct rpc_pipe *gssd_dummy;
	struct mutex pipefs_sb_lock;

	struct list_head all_clients;
	spinlock_t rpc_client_lock;

	struct rpc_clnt *rpcb_local_clnt;
	struct rpc_clnt *rpcb_local_clnt4;
	spinlock_t rpcb_clnt_lock;
	unsigned int rpcb_users;
	unsigned int rpcb_is_af_local : 1;

	struct mutex gssp_lock;
	struct rpc_clnt *gssp_clnt;
	int use_gss_proxy;
	int pipe_version;
	atomic_t pipe_users;
	struct proc_dir_entry *use_gssp_proc;
	struct proc_dir_entry *gss_krb5_enctypes;
};

extern unsigned int sunrpc_net_id;

/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_upcall.h */
struct gssp_upcall_data {
	struct xdr_netobj in_handle;
	struct gssp_in_token in_token;
	struct xdr_netobj out_handle;
	struct xdr_netobj out_token;
	struct rpcsec_gss_oid mech_oid;
	struct svc_cred creds;
	int found_creds;
	int major_status;
	int minor_status;
};

int gssp_accept_sec_context_upcall(struct net *net,
				struct gssp_upcall_data *data);
void gssp_free_upcall_data(struct gssp_upcall_data *data);

/* klp-ccp: from net/sunrpc/auth_gss/svcauth_gss.c */
extern int dup_to_netobj(struct xdr_netobj *dst, char *src, int len);

static inline int dup_netobj(struct xdr_netobj *dst, struct xdr_netobj *src)
{
	return dup_to_netobj(dst, src->data, src->len);
}

#define GSS_SEQ_WIN	128

struct gss_svc_seq_data {
	/* highest seq number seen so far: */
	u32			sd_max;
	/* for i such that sd_max-GSS_SEQ_WIN < i <= sd_max, the i-th bit of
	 * sd_win is nonzero iff sequence number i has been seen already: */
	unsigned long		sd_win[GSS_SEQ_WIN/BITS_PER_LONG];
	spinlock_t		sd_lock;
};

struct rsc {
	struct cache_head	h;
	struct xdr_netobj	handle;
	struct svc_cred		cred;
	struct gss_svc_seq_data	seqdata;
	struct gss_ctx		*mechctx;
	struct rcu_head		rcu_head;
};

extern struct rsc *
gss_svc_searchbyctx(struct cache_detail *cd, struct xdr_netobj *handle);

extern bool
svcauth_gss_encode_verf(struct svc_rqst *rqstp, struct gss_ctx *ctx_id, u32 seq);

static bool
svcauth_gss_proc_init_verf(struct cache_detail *cd, struct svc_rqst *rqstp,
			   struct xdr_netobj *out_handle, int *major_status,
			   u32 seq_num)
{
	struct xdr_stream *xdr = &rqstp->rq_res_stream;
	struct rsc *rsci;
	bool rc;

	if (*major_status != GSS_S_COMPLETE)
		goto null_verifier;
	rsci = gss_svc_searchbyctx(cd, out_handle);
	if (rsci == NULL) {
		*major_status = GSS_S_NO_CONTEXT;
		goto null_verifier;
	}

	rc = svcauth_gss_encode_verf(rqstp, rsci->mechctx, seq_num);
	cache_put(&rsci->h, cd);
	return rc;

null_verifier:
	return xdr_stream_encode_opaque_auth(xdr, RPC_AUTH_NULL, NULL, 0) > 0;
}

static void gss_free_in_token_pages(struct gssp_in_token *in_token)
{
	int i;

	i = 0;
	while (in_token->pages[i])
		put_page(in_token->pages[i++]);
	kfree(in_token->pages);
	in_token->pages = NULL;
}

static int gss_read_proxy_verf(struct svc_rqst *rqstp,
			       struct rpc_gss_wire_cred *gc,
			       struct xdr_netobj *in_handle,
			       struct gssp_in_token *in_token)
{
	struct xdr_stream *xdr = &rqstp->rq_arg_stream;
	unsigned int length, pgto_offs, pgfrom_offs;
	int pages, i, pgto, pgfrom;
	size_t to_offs, from_offs;
	u32 inlen;

	if (dup_netobj(in_handle, &gc->gc_ctx))
		return SVC_CLOSE;

	/*
	 *  RFC 2203 Section 5.2.2
	 *
	 *	struct rpc_gss_init_arg {
	 *		opaque gss_token<>;
	 *	};
	 */
	if (xdr_stream_decode_u32(xdr, &inlen) < 0)
		goto out_denied_free;
	if (inlen > xdr_stream_remaining(xdr))
		goto out_denied_free;

	pages = DIV_ROUND_UP(inlen, PAGE_SIZE);
	in_token->pages = kcalloc(pages + 1, sizeof(struct page *), GFP_KERNEL);
	if (!in_token->pages)
		goto out_denied_free;
	in_token->page_base = 0;
	in_token->page_len = inlen;
	for (i = 0; i < pages; i++) {
		in_token->pages[i] = alloc_page(GFP_KERNEL);
		if (!in_token->pages[i]) {
			gss_free_in_token_pages(in_token);
			goto out_denied_free;
		}
	}

	length = min_t(unsigned int, inlen, (char *)xdr->end - (char *)xdr->p);
	if (length)
		memcpy(page_address(in_token->pages[0]), xdr->p, length);
	inlen -= length;

	to_offs = length;
	from_offs = rqstp->rq_arg.page_base;
	while (inlen) {
		pgto = to_offs >> PAGE_SHIFT;
		pgfrom = from_offs >> PAGE_SHIFT;
		pgto_offs = to_offs & ~PAGE_MASK;
		pgfrom_offs = from_offs & ~PAGE_MASK;

		length = min_t(unsigned int, inlen,
			 min_t(unsigned int, PAGE_SIZE - pgto_offs,
			       PAGE_SIZE - pgfrom_offs));
		memcpy(page_address(in_token->pages[pgto]) + pgto_offs,
		       page_address(rqstp->rq_arg.pages[pgfrom]) + pgfrom_offs,
		       length);

		to_offs += length;
		from_offs += length;
		inlen -= length;
	}
	return 0;

out_denied_free:
	kfree(in_handle->data);
	return SVC_DENIED;
}

static bool
svcxdr_encode_gss_init_res(struct xdr_stream *xdr,
			   struct xdr_netobj *handle,
			   struct xdr_netobj *gss_token,
			   unsigned int major_status,
			   unsigned int minor_status, u32 seq_num)
{
	if (xdr_stream_encode_opaque(xdr, handle->data, handle->len) < 0)
		return false;
	if (xdr_stream_encode_u32(xdr, major_status) < 0)
		return false;
	if (xdr_stream_encode_u32(xdr, minor_status) < 0)
		return false;
	if (xdr_stream_encode_u32(xdr, seq_num) < 0)
		return false;
	if (xdr_stream_encode_opaque(xdr, gss_token->data, gss_token->len) < 0)
		return false;
	return true;
}

extern int gss_proxy_save_rsc(struct cache_detail *cd,
				struct gssp_upcall_data *ud,
				uint64_t *handle);
#include "klp_trace.h"

KLPR_TRACE_EVENT(auth_rpcgss, rpcgss_svc_accept_upcall,
		TP_PROTO(
			const struct svc_rqst *rqstp,
			u32 major_status,
			u32 minor_status
			),
		TP_ARGS(rqstp, major_status, minor_status)
);

int klpp_svcauth_gss_proxy_init(struct svc_rqst *rqstp,
				struct rpc_gss_wire_cred *gc)
{
	struct xdr_netobj cli_handle;
	struct gssp_upcall_data ud;
	uint64_t handle;
	int status;
	int ret;
	struct net *net = SVC_NET(rqstp);
	struct sunrpc_net *sn = net_generic(net, sunrpc_net_id);

	memset(&ud, 0, sizeof(ud));
	ret = gss_read_proxy_verf(rqstp, gc, &ud.in_handle, &ud.in_token);
	if (ret)
		return ret;

	ret = SVC_CLOSE;

	/* Perform synchronous upcall to gss-proxy */
	status = gssp_accept_sec_context_upcall(net, &ud);
	if (status)
		goto out;

	klpr_trace_rpcgss_svc_accept_upcall(rqstp, ud.major_status, ud.minor_status);

	switch (ud.major_status) {
	case GSS_S_CONTINUE_NEEDED:
		cli_handle = ud.out_handle;
		break;
	case GSS_S_COMPLETE:
		status = gss_proxy_save_rsc(sn->rsc_cache, &ud, &handle);
		if (status)
			goto out;
		cli_handle.data = (u8 *)&handle;
		cli_handle.len = sizeof(handle);
		break;
	default:
		goto out;
	}

	if (!svcauth_gss_proc_init_verf(sn->rsc_cache, rqstp, &cli_handle,
					&ud.major_status, GSS_SEQ_WIN))
		goto out;
	if (!svcxdr_set_accept_stat(rqstp))
		goto out;
	if (!svcxdr_encode_gss_init_res(&rqstp->rq_res_stream, &cli_handle,
					&ud.out_token, ud.major_status,
					ud.minor_status, GSS_SEQ_WIN))
		goto out;

	ret = SVC_COMPLETE;
out:
	gss_free_in_token_pages(&ud.in_token);
	gssp_free_upcall_data(&ud);
	return ret;
}

#include <linux/livepatch.h>

extern typeof(dup_to_netobj) dup_to_netobj
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, dup_to_netobj);
extern typeof(gss_proxy_save_rsc) gss_proxy_save_rsc
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, gss_proxy_save_rsc);
extern typeof(gss_svc_searchbyctx) gss_svc_searchbyctx
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, gss_svc_searchbyctx);
extern typeof(gssp_accept_sec_context_upcall) gssp_accept_sec_context_upcall
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, gssp_accept_sec_context_upcall);
extern typeof(gssp_free_upcall_data) gssp_free_upcall_data
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, gssp_free_upcall_data);
extern typeof(svcauth_gss_encode_verf) svcauth_gss_encode_verf
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, svcauth_gss_encode_verf);
extern typeof(sunrpc_net_id) sunrpc_net_id
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, sunrpc_net_id);
extern typeof(xdr_encode_opaque) xdr_encode_opaque
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_encode_opaque);
extern typeof(xdr_inline_decode) xdr_inline_decode
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_inline_decode);
extern typeof(xdr_reserve_space) xdr_reserve_space
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_reserve_space);
extern typeof(xdr_stream_encode_opaque_auth) xdr_stream_encode_opaque_auth
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_stream_encode_opaque_auth);
