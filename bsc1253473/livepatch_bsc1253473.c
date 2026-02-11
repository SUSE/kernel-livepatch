/*
 * livepatch_bsc1253473
 *
 * Fix for CVE-2025-40129, bsc#1253473
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

/* klp-ccp: from include/linux/sunrpc/gss_err.h */
#define GSS_S_COMPLETE 0

/* klp-ccp: from net/sunrpc/auth_gss/svcauth_gss.c */
#include <linux/sunrpc/svcauth.h>
#include <linux/sunrpc/svcauth_gss.h>
#include <linux/sunrpc/cache.h>

/* klp-ccp: from include/linux/sunrpc/gss_krb5.h */
#define GSS_KRB5_MAX_CKSUM_LEN  (24)

#define GSS_KRB5_TOK_HDR_LEN	(16)

/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_upcall.h */
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/auth_gss.h>

/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_xdr.h */
#include <linux/sunrpc/xdr.h>

/* klp-ccp: from net/sunrpc/netns.h */
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "klp_trace.h"
KLPR_TRACE_EVENT(auth_rpcgss, rpcgss_svc_seqno_low,
  TP_PROTO(const struct svc_rqst *rqstp,
           u32 seqno,
           u32 min,
           u32 max),
  TP_ARGS(rqstp, seqno, min, max)
)

KLPR_TRACE_EVENT(auth_rpcgss, rpcgss_svc_seqno_seen,
  TP_PROTO(const struct svc_rqst *rqstp,
           u32 seqno),
  TP_ARGS(rqstp, seqno)
)

KLPR_TRACE_EVENT(auth_rpcgss, rpcgss_svc_mic,
  TP_PROTO(const struct svc_rqst *rqstp,
           u32 maj_stat),
  TP_ARGS(rqstp, maj_stat)
)

KLPR_TRACE_EVENT(auth_rpcgss, rpcgss_svc_seqno_large,
  TP_PROTO(const struct svc_rqst *rqstp,
           u32 gc_seq),
  TP_ARGS(rqstp, gc_seq)
)

KLPR_TRACE_EVENT(auth_rpcgss, rpcgss_svc_authenticate,
  TP_PROTO(const struct svc_rqst *rqstp,
           struct rpc_gss_wire_cred *gc),
  TP_ARGS(rqstp, gc)
)

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

/* klp-ccp: from net/sunrpc/auth_gss/svcauth_gss.c */
#define GSS_MAX_CKSUMSIZE (GSS_KRB5_TOK_HDR_LEN + GSS_KRB5_MAX_CKSUM_LEN)

#define GSS_SCRATCH_SIZE GSS_MAX_CKSUMSIZE

struct gss_svc_data {
	/* decoded gss client cred: */
	struct rpc_gss_wire_cred	clcred;
	u32				gsd_databody_offset;
	struct rsc			*rsci;

	/* for temporary results */
	__be32				gsd_seq_num;
	u8				gsd_scratch[GSS_SCRATCH_SIZE];
};

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

static bool gss_check_seq_num(const struct svc_rqst *rqstp, struct rsc *rsci,
			      u32 seq_num)
{
	struct gss_svc_seq_data *sd = &rsci->seqdata;
	bool result = false;

	spin_lock(&sd->sd_lock);
	if (seq_num > sd->sd_max) {
		if (seq_num >= sd->sd_max + GSS_SEQ_WIN) {
			memset(sd->sd_win, 0, sizeof(sd->sd_win));
			sd->sd_max = seq_num;
		} else while (sd->sd_max < seq_num) {
			sd->sd_max++;
			__clear_bit(sd->sd_max % GSS_SEQ_WIN, sd->sd_win);
		}
		__set_bit(seq_num % GSS_SEQ_WIN, sd->sd_win);
		goto ok;
	} else if (seq_num + GSS_SEQ_WIN <= sd->sd_max) {
		goto toolow;
	}
	if (__test_and_set_bit(seq_num % GSS_SEQ_WIN, sd->sd_win))
		goto alreadyseen;

ok:
	result = true;
out:
	spin_unlock(&sd->sd_lock);
	return result;

toolow:
	klpr_trace_rpcgss_svc_seqno_low(rqstp, seq_num,
				   sd->sd_max - GSS_SEQ_WIN,
				   sd->sd_max);
	goto out;
alreadyseen:
	klpr_trace_rpcgss_svc_seqno_seen(rqstp, seq_num);
	goto out;
}

static int
svcauth_gss_verify_header(struct svc_rqst *rqstp, struct rsc *rsci,
			  __be32 *rpcstart, struct rpc_gss_wire_cred *gc)
{
	struct xdr_stream	*xdr = &rqstp->rq_arg_stream;
	struct gss_ctx		*ctx_id = rsci->mechctx;
	u32			flavor, maj_stat;
	struct xdr_buf		rpchdr;
	struct xdr_netobj	checksum;
	struct kvec		iov;

	/*
	 * Compute the checksum of the incoming Call from the
	 * XID field to credential field:
	 */
	iov.iov_base = rpcstart;
	iov.iov_len = (u8 *)xdr->p - (u8 *)rpcstart;
	xdr_buf_from_iov(&iov, &rpchdr);

	/* Call's verf field: */
	if (xdr_stream_decode_opaque_auth(xdr, &flavor,
					  (void **)&checksum.data,
					  &checksum.len) < 0) {
		rqstp->rq_auth_stat = rpc_autherr_badverf;
		return SVC_DENIED;
	}
	if (flavor != RPC_AUTH_GSS || checksum.len < XDR_UNIT) {
		rqstp->rq_auth_stat = rpc_autherr_badverf;
		return SVC_DENIED;
	}

	if (rqstp->rq_deferred)
		return SVC_OK;
	maj_stat = gss_verify_mic(ctx_id, &rpchdr, &checksum);
	if (maj_stat != GSS_S_COMPLETE) {
		klpr_trace_rpcgss_svc_mic(rqstp, maj_stat);
		rqstp->rq_auth_stat = rpcsec_gsserr_credproblem;
		return SVC_DENIED;
	}

	if (gc->gc_seq > MAXSEQ) {
		klpr_trace_rpcgss_svc_seqno_large(rqstp, gc->gc_seq);
		rqstp->rq_auth_stat = rpcsec_gsserr_ctxproblem;
		return SVC_DENIED;
	}
	if (!gss_check_seq_num(rqstp, rsci, gc->gc_seq))
		return SVC_DROP;
	return SVC_OK;
}

extern bool
svcauth_gss_encode_verf(struct svc_rqst *rqstp, struct gss_ctx *ctx_id, u32 seq);

extern noinline_for_stack int
svcauth_gss_unwrap_integ(struct svc_rqst *rqstp, u32 seq, struct gss_ctx *ctx);

extern noinline_for_stack int
svcauth_gss_unwrap_priv(struct svc_rqst *rqstp, u32 seq, struct gss_ctx *ctx);

extern noinline_for_stack int
svcauth_gss_proc_init(struct svc_rqst *rqstp, struct rpc_gss_wire_cred *gc);

static bool
svcauth_gss_decode_credbody(struct xdr_stream *xdr,
			    struct rpc_gss_wire_cred *gc,
			    __be32 **rpcstart)
{
	ssize_t handle_len;
	u32 body_len;
	__be32 *p;

	p = xdr_inline_decode(xdr, XDR_UNIT);
	if (!p)
		return false;
	/*
	 * start of rpc packet is 7 u32's back from here:
	 * xid direction rpcversion prog vers proc flavour
	 */
	*rpcstart = p - 7;
	body_len = be32_to_cpup(p);
	if (body_len > RPC_MAX_AUTH_SIZE)
		return false;

	/* struct rpc_gss_cred_t */
	if (xdr_stream_decode_u32(xdr, &gc->gc_v) < 0)
		return false;
	if (xdr_stream_decode_u32(xdr, &gc->gc_proc) < 0)
		return false;
	if (xdr_stream_decode_u32(xdr, &gc->gc_seq) < 0)
		return false;
	if (xdr_stream_decode_u32(xdr, &gc->gc_svc) < 0)
		return false;
	handle_len = xdr_stream_decode_opaque_inline(xdr,
						     (void **)&gc->gc_ctx.data,
						     body_len);
	if (handle_len < 0)
		return false;
	if (body_len != XDR_UNIT * 5 + xdr_align_size(handle_len))
		return false;

	gc->gc_ctx.len = handle_len;
	return true;
}

int klpp_svcauth_gss_accept(struct svc_rqst *rqstp)
{
	struct gss_svc_data *svcdata = rqstp->rq_auth_data;
	__be32		*rpcstart;
	struct rpc_gss_wire_cred *gc;
	struct rsc	*rsci = NULL;
	int		ret;
	struct sunrpc_net *sn = net_generic(SVC_NET(rqstp), sunrpc_net_id);

	rqstp->rq_auth_stat = rpc_autherr_badcred;
	if (!svcdata)
		svcdata = kmalloc(sizeof(*svcdata), GFP_KERNEL);
	if (!svcdata)
		goto auth_err;
	rqstp->rq_auth_data = svcdata;
	svcdata->gsd_databody_offset = 0;
	svcdata->rsci = NULL;
	gc = &svcdata->clcred;

	if (!svcauth_gss_decode_credbody(&rqstp->rq_arg_stream, gc, &rpcstart))
		goto auth_err;
	if (gc->gc_v != RPC_GSS_VERSION)
		goto auth_err;

	switch (gc->gc_proc) {
	case RPC_GSS_PROC_INIT:
	case RPC_GSS_PROC_CONTINUE_INIT:
		if (rqstp->rq_proc != 0)
			goto auth_err;
		return svcauth_gss_proc_init(rqstp, gc);
	case RPC_GSS_PROC_DESTROY:
		if (rqstp->rq_proc != 0)
			goto auth_err;
		fallthrough;
	case RPC_GSS_PROC_DATA:
		rqstp->rq_auth_stat = rpcsec_gsserr_credproblem;
		rsci = gss_svc_searchbyctx(sn->rsc_cache, &gc->gc_ctx);
		if (!rsci)
			goto auth_err;
		switch (svcauth_gss_verify_header(rqstp, rsci, rpcstart, gc)) {
		case SVC_OK:
			break;
		case SVC_DENIED:
			goto auth_err;
		case SVC_DROP:
			goto drop;
		}
		break;
	default:
		if (rqstp->rq_proc != 0)
			goto auth_err;
		rqstp->rq_auth_stat = rpc_autherr_rejectedcred;
		goto auth_err;
	}

	/* now act upon the command: */
	switch (gc->gc_proc) {
	case RPC_GSS_PROC_DESTROY:
		if (!svcauth_gss_encode_verf(rqstp, rsci->mechctx, gc->gc_seq))
			goto auth_err;
		if (!svcxdr_set_accept_stat(rqstp))
			goto auth_err;
		/* Delete the entry from the cache_list and call cache_put */
		sunrpc_cache_unhash(sn->rsc_cache, &rsci->h);
		goto complete;
	case RPC_GSS_PROC_DATA:
		rqstp->rq_auth_stat = rpcsec_gsserr_ctxproblem;
		if (!svcauth_gss_encode_verf(rqstp, rsci->mechctx, gc->gc_seq))
			goto auth_err;
		if (!svcxdr_set_accept_stat(rqstp))
			goto auth_err;
		svcdata->gsd_databody_offset = xdr_stream_pos(&rqstp->rq_res_stream);
		rqstp->rq_cred = rsci->cred;
		get_group_info(rsci->cred.cr_group_info);
		rqstp->rq_auth_stat = rpc_autherr_badcred;
		switch (gc->gc_svc) {
		case RPC_GSS_SVC_NONE:
			break;
		case RPC_GSS_SVC_INTEGRITY:
			/* placeholders for body length and seq. number: */
			xdr_reserve_space(&rqstp->rq_res_stream, XDR_UNIT * 2);
			if (svcauth_gss_unwrap_integ(rqstp, gc->gc_seq,
						     rsci->mechctx))
				goto garbage_args;
			svcxdr_set_auth_slack(rqstp, RPC_MAX_AUTH_SIZE);
			break;
		case RPC_GSS_SVC_PRIVACY:
			/* placeholders for body length and seq. number: */
			xdr_reserve_space(&rqstp->rq_res_stream, XDR_UNIT * 2);
			if (svcauth_gss_unwrap_priv(rqstp, gc->gc_seq,
						    rsci->mechctx))
				goto garbage_args;
			svcxdr_set_auth_slack(rqstp, RPC_MAX_AUTH_SIZE * 2);
			break;
		default:
			goto auth_err;
		}
		svcdata->rsci = rsci;
		cache_get(&rsci->h);
		rqstp->rq_cred.cr_flavor = gss_svc_to_pseudoflavor(
					rsci->mechctx->mech_type,
					GSS_C_QOP_DEFAULT,
					gc->gc_svc);
		ret = SVC_OK;
		klpr_trace_rpcgss_svc_authenticate(rqstp, gc);
		goto out;
	}
garbage_args:
	ret = SVC_GARBAGE;
	goto out;
auth_err:
	xdr_truncate_encode(&rqstp->rq_res_stream, XDR_UNIT * 2);
	ret = SVC_DENIED;
	goto out;
complete:
	ret = SVC_COMPLETE;
	goto out;
drop:
	ret = SVC_CLOSE;
out:
	if (rsci)
		cache_put(&rsci->h, sn->rsc_cache);
	return ret;
}


#include "livepatch_bsc1253473.h"

#include <linux/livepatch.h>

extern typeof(gss_svc_searchbyctx) gss_svc_searchbyctx
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, gss_svc_searchbyctx);
extern typeof(gss_svc_to_pseudoflavor) gss_svc_to_pseudoflavor
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, gss_svc_to_pseudoflavor);
extern typeof(gss_verify_mic) gss_verify_mic
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, gss_verify_mic);
extern typeof(svcauth_gss_encode_verf) svcauth_gss_encode_verf
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, svcauth_gss_encode_verf);
extern typeof(svcauth_gss_proc_init) svcauth_gss_proc_init
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, svcauth_gss_proc_init);
extern typeof(svcauth_gss_unwrap_integ) svcauth_gss_unwrap_integ
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, svcauth_gss_unwrap_integ);
extern typeof(svcauth_gss_unwrap_priv) svcauth_gss_unwrap_priv
	 KLP_RELOC_SYMBOL(auth_rpcgss, auth_rpcgss, svcauth_gss_unwrap_priv);
extern typeof(sunrpc_cache_unhash) sunrpc_cache_unhash
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, sunrpc_cache_unhash);
extern typeof(sunrpc_net_id) sunrpc_net_id
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, sunrpc_net_id);
extern typeof(xdr_buf_from_iov) xdr_buf_from_iov
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_buf_from_iov);
extern typeof(xdr_inline_decode) xdr_inline_decode
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_inline_decode);
extern typeof(xdr_reserve_space) xdr_reserve_space
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_reserve_space);
extern typeof(xdr_stream_decode_opaque_auth) xdr_stream_decode_opaque_auth
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_stream_decode_opaque_auth);
extern typeof(xdr_stream_pos) xdr_stream_pos
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_stream_pos);
extern typeof(xdr_truncate_encode) xdr_truncate_encode
	 KLP_RELOC_SYMBOL(auth_rpcgss, sunrpc, xdr_truncate_encode);
