/*
 * livepatch_bsc1245509
 *
 * Fix for CVE-2025-38089, bsc#1245509
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


/* klp-ccp: from net/sunrpc/svc.c */
#include <linux/linkage.h>
#include <linux/sched/signal.h>
#include <linux/errno.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/module.h>

/* klp-ccp: from include/linux/kthread.h */
#define _LINUX_KTHREAD_H

/* klp-ccp: from net/sunrpc/svc.c */
#include <linux/slab.h>

#include <linux/sunrpc/types.h>
#include <linux/sunrpc/xdr.h>
#include <linux/sunrpc/stats.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/clnt.h>

#include <trace/events/sunrpc.h>

#include "../klp_trace.h"

KLPR_TRACE_EVENT(
	sunrpc,
	svc_process,
	TP_PROTO(const struct svc_rqst *rqst, const char *name),
	TP_ARGS(rqst, name)
);


KLPR_TRACE_EVENT_CONDITION(
	sunrpc,
	svc_authenticate,
	TP_PROTO(const struct svc_rqst *rqst, int auth_res),
	TP_ARGS(rqst, auth_res),
	TP_CONDITION(auth_res != SVC_OK && auth_res != SVC_COMPLETE)
);

#define RPCDBG_FACILITY	RPCDBG_SVCDSP

#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)
extern __printf(2, 3)
void svc_printk(struct svc_rqst *rqstp, const char *fmt, ...);

#else
#error "klp-ccp: non-taken branch"
#endif

int
klpp_svc_process_common(struct svc_rqst *rqstp)
{
	struct xdr_stream	*xdr = &rqstp->rq_res_stream;
	struct svc_program	*progp;
	const struct svc_procedure *procp = NULL;
	struct svc_serv		*serv = rqstp->rq_server;
	struct svc_process_info process;
	int			auth_res, rc;
	unsigned int		aoffset;
	__be32			*p;

	/* Will be turned off by GSS integrity and privacy services */
	set_bit(RQ_SPLICE_OK, &rqstp->rq_flags);
	/* Will be turned off only when NFSv4 Sessions are used */
	set_bit(RQ_USEDEFERRAL, &rqstp->rq_flags);
	clear_bit(RQ_DROPME, &rqstp->rq_flags);

	/* Construct the first words of the reply: */
	svcxdr_init_encode(rqstp);
	xdr_stream_encode_be32(xdr, rqstp->rq_xid);
	xdr_stream_encode_be32(xdr, rpc_reply);

	p = xdr_inline_decode(&rqstp->rq_arg_stream, XDR_UNIT * 4);
	if (unlikely(!p))
		goto err_short_len;
	if (*p++ != cpu_to_be32(RPC_VERSION))
		goto err_bad_rpc;

	xdr_stream_encode_be32(xdr, rpc_msg_accepted);

	rqstp->rq_prog = be32_to_cpup(p++);
	rqstp->rq_vers = be32_to_cpup(p++);
	rqstp->rq_proc = be32_to_cpup(p);

	for (progp = serv->sv_program; progp; progp = progp->pg_next)
		if (rqstp->rq_prog == progp->pg_prog)
			break;

	/*
	 * Decode auth data, and add verifier to reply buffer.
	 * We do this before anything else in order to get a decent
	 * auth verifier.
	 */
	auth_res = svc_authenticate(rqstp);
	/* Also give the program a chance to reject this call: */
	if (auth_res == SVC_OK && progp)
		auth_res = progp->pg_authenticate(rqstp);
	klpr_trace_svc_authenticate(rqstp, auth_res);
	switch (auth_res) {
	case SVC_OK:
		break;
	case SVC_GARBAGE:
		rqstp->rq_auth_stat = rpc_autherr_badcred;
		goto err_bad_auth;
	case SVC_SYSERR:
		goto err_system_err;
	case SVC_DENIED:
		goto err_bad_auth;
	case SVC_CLOSE:
		goto close;
	case SVC_DROP:
		goto dropit;
	case SVC_COMPLETE:
		goto sendit;
	}

	if (progp == NULL)
		goto err_bad_prog;

	switch (progp->pg_init_request(rqstp, progp, &process)) {
	case rpc_success:
		break;
	case rpc_prog_unavail:
		goto err_bad_prog;
	case rpc_prog_mismatch:
		goto err_bad_vers;
	case rpc_proc_unavail:
		goto err_bad_proc;
	}

	procp = rqstp->rq_procinfo;
	/* Should this check go into the dispatcher? */
	if (!procp || !procp->pc_func)
		goto err_bad_proc;

	/* Syntactic check complete */
	serv->sv_stats->rpccnt++;
	klpr_trace_svc_process(rqstp, progp->pg_name);

	aoffset = xdr_stream_pos(xdr);

	/* un-reserve some of the out-queue now that we have a
	 * better idea of reply size
	 */
	if (procp->pc_xdrressize)
		svc_reserve_auth(rqstp, procp->pc_xdrressize<<2);

	/* Call the function that processes the request. */
	rc = process.dispatch(rqstp);
	if (procp->pc_release)
		procp->pc_release(rqstp);
	if (!rc)
		goto dropit;
	if (rqstp->rq_auth_stat != rpc_auth_ok)
		goto err_bad_auth;

	if (*rqstp->rq_accept_statp != rpc_success)
		xdr_truncate_encode(xdr, aoffset);

	if (procp->pc_encode == NULL)
		goto dropit;

 sendit:
	if (svc_authorise(rqstp))
		goto close_xprt;
	return 1;		/* Caller can now send it */

 dropit:
	svc_authorise(rqstp);	/* doesn't hurt to call this twice */
	dprintk("svc: svc_process dropit\n");
	return 0;

 close:
	svc_authorise(rqstp);
close_xprt:
	if (rqstp->rq_xprt && test_bit(XPT_TEMP, &rqstp->rq_xprt->xpt_flags))
		svc_xprt_close(rqstp->rq_xprt);
	dprintk("svc: svc_process close\n");
	return 0;

err_short_len:
	svc_printk(rqstp, "short len %u, dropping request\n",
		   rqstp->rq_arg.len);
	goto close_xprt;

err_bad_rpc:
	serv->sv_stats->rpcbadfmt++;
	xdr_stream_encode_u32(xdr, RPC_MSG_DENIED);
	xdr_stream_encode_u32(xdr, RPC_MISMATCH);
	/* Only RPCv2 supported */
	xdr_stream_encode_u32(xdr, RPC_VERSION);
	xdr_stream_encode_u32(xdr, RPC_VERSION);
	return 1;	/* don't wrap */

err_bad_auth:
	dprintk("svc: authentication failed (%d)\n",
		be32_to_cpu(rqstp->rq_auth_stat));
	serv->sv_stats->rpcbadauth++;
	/* Restore write pointer to location of reply status: */
	xdr_truncate_encode(xdr, XDR_UNIT * 2);
	xdr_stream_encode_u32(xdr, RPC_MSG_DENIED);
	xdr_stream_encode_u32(xdr, RPC_AUTH_ERROR);
	xdr_stream_encode_be32(xdr, rqstp->rq_auth_stat);
	goto sendit;

err_bad_prog:
	dprintk("svc: unknown program %d\n", rqstp->rq_prog);
	serv->sv_stats->rpcbadfmt++;
	*rqstp->rq_accept_statp = rpc_prog_unavail;
	goto sendit;

err_bad_vers:
	svc_printk(rqstp, "unknown version (%d for prog %d, %s)\n",
		       rqstp->rq_vers, rqstp->rq_prog, progp->pg_name);

	serv->sv_stats->rpcbadfmt++;
	*rqstp->rq_accept_statp = rpc_prog_mismatch;

	/*
	 * svc_authenticate() has already added the verifier and
	 * advanced the stream just past rq_accept_statp.
	 */
	xdr_stream_encode_u32(xdr, process.mismatch.lovers);
	xdr_stream_encode_u32(xdr, process.mismatch.hivers);
	goto sendit;

err_bad_proc:
	svc_printk(rqstp, "unknown procedure (%d)\n", rqstp->rq_proc);

	serv->sv_stats->rpcbadfmt++;
	*rqstp->rq_accept_statp = rpc_proc_unavail;
	goto sendit;

err_system_err:
	serv->sv_stats->rpcbadfmt++;
	*rqstp->rq_accept_statp = rpc_system_err;
	goto sendit;
}


#include "livepatch_bsc1245509.h"

#include <linux/livepatch.h>

extern typeof(rpc_debug) rpc_debug KLP_RELOC_SYMBOL(sunrpc, sunrpc, rpc_debug);
extern typeof(svc_authenticate) svc_authenticate
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_authenticate);
extern typeof(svc_authorise) svc_authorise
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_authorise);
extern typeof(svc_printk) svc_printk
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_printk);
extern typeof(svc_reserve) svc_reserve
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_reserve);
extern typeof(svc_xprt_close) svc_xprt_close
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_xprt_close);
extern typeof(xdr_inline_decode) xdr_inline_decode
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, xdr_inline_decode);
extern typeof(xdr_reserve_space) xdr_reserve_space
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, xdr_reserve_space);
extern typeof(xdr_stream_pos) xdr_stream_pos
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, xdr_stream_pos);
extern typeof(xdr_truncate_encode) xdr_truncate_encode
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, xdr_truncate_encode);
