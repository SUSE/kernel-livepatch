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

/* klp-ccp: from include/linux/sunrpc/auth_gss.h */
#ifdef __KERNEL__

/* klp-ccp: from include/linux/sunrpc/auth.h */
#ifdef __KERNEL__

/* klp-ccp: from include/linux/sunrpc/debug.h */
#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)
static unsigned int		(*klpe_rpc_debug);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from include/linux/sunrpc/auth.h */
#endif /* __KERNEL__ */

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from include/linux/sunrpc/auth_gss.h */
#endif /* __KERNEL__ */

/* klp-ccp: from net/sunrpc/auth_gss/svcauth_gss.c */
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
};

static unsigned int (*klpe_sunrpc_net_id);

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

static int (*klpe_gssp_accept_sec_context_upcall)(struct net *net,
				struct gssp_upcall_data *data);
static void (*klpe_gssp_free_upcall_data)(struct gssp_upcall_data *data);

/* klp-ccp: from net/sunrpc/auth_gss/svcauth_gss.c */
static int (*klpe_dup_to_netobj)(struct xdr_netobj *dst, char *src, int len);

static inline int klpr_dup_netobj(struct xdr_netobj *dst, struct xdr_netobj *src)
{
	return (*klpe_dup_to_netobj)(dst, src->data, src->len);
}

#define GSS_SEQ_WIN	128

struct gss_svc_seq_data {
	/* highest seq number seen so far: */
	int			sd_max;
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
};

static struct rsc *
(*klpe_gss_svc_searchbyctx)(struct cache_detail *cd, struct xdr_netobj *handle);

static inline u32 round_up_to_quad(u32 i)
{
	return (i + 3 ) & ~3;
}

static inline int
svc_safe_putnetobj(struct kvec *resv, struct xdr_netobj *o)
{
	u8 *p;

	if (resv->iov_len + 4 > PAGE_SIZE)
		return -1;
	svc_putnl(resv, o->len);
	p = resv->iov_base + resv->iov_len;
	resv->iov_len += round_up_to_quad(o->len);
	if (resv->iov_len > PAGE_SIZE)
		return -1;
	memcpy(p, o->data, o->len);
	memset(p + o->len, 0, round_up_to_quad(o->len) - o->len);
	return 0;
}

static int
gss_write_null_verf(struct svc_rqst *rqstp)
{
	__be32     *p;

	svc_putnl(rqstp->rq_res.head, RPC_AUTH_NULL);
	p = rqstp->rq_res.head->iov_base + rqstp->rq_res.head->iov_len;
	/* don't really need to check if head->iov_len > PAGE_SIZE ... */
	*p++ = 0;
	if (!xdr_ressize_check(rqstp, p))
		return -1;
	return 0;
}

static int
(*klpe_gss_write_verf)(struct svc_rqst *rqstp, struct gss_ctx *ctx_id, u32 seq);

static inline int
klpr_gss_write_init_verf(struct cache_detail *cd, struct svc_rqst *rqstp,
		struct xdr_netobj *out_handle, int *major_status)
{
	struct rsc *rsci;
	int        rc;

	if (*major_status != GSS_S_COMPLETE)
		return gss_write_null_verf(rqstp);
	rsci = (*klpe_gss_svc_searchbyctx)(cd, out_handle);
	if (rsci == NULL) {
		*major_status = GSS_S_NO_CONTEXT;
		return gss_write_null_verf(rqstp);
	}
	rc = (*klpe_gss_write_verf)(rqstp, rsci->mechctx, GSS_SEQ_WIN);
	cache_put(&rsci->h, cd);
	return rc;
}

static inline int
klpr_gss_read_common_verf(struct rpc_gss_wire_cred *gc,
		     struct kvec *argv, __be32 *authp,
		     struct xdr_netobj *in_handle)
{
	/* Read the verifier; should be NULL: */
	*authp = rpc_autherr_badverf;
	if (argv->iov_len < 2 * 4)
		return SVC_DENIED;
	if (svc_getnl(argv) != RPC_AUTH_NULL)
		return SVC_DENIED;
	if (svc_getnl(argv) != 0)
		return SVC_DENIED;
	/* Martial context handle and token for upcall: */
	*authp = rpc_autherr_badcred;
	if (gc->gc_proc == RPC_GSS_PROC_INIT && gc->gc_ctx.len != 0)
		return SVC_DENIED;
	if (klpr_dup_netobj(in_handle, &gc->gc_ctx))
		return SVC_CLOSE;
	*authp = rpc_autherr_badverf;

	return 0;
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

static int klpr_gss_read_proxy_verf(struct svc_rqst *rqstp,
			       struct rpc_gss_wire_cred *gc, __be32 *authp,
			       struct xdr_netobj *in_handle,
			       struct gssp_in_token *in_token)
{
	struct kvec *argv = &rqstp->rq_arg.head[0];
	unsigned int length, pgto_offs, pgfrom_offs;
	int pages, i, res, pgto, pgfrom;
	size_t inlen, to_offs, from_offs;

	res = klpr_gss_read_common_verf(gc, argv, authp, in_handle);
	if (res)
		return res;

	inlen = svc_getnl(argv);
	if (inlen > (argv->iov_len + rqstp->rq_arg.page_len)) {
		kfree(in_handle->data);
		return SVC_DENIED;
	}

	pages = DIV_ROUND_UP(inlen, PAGE_SIZE);
	in_token->pages = kcalloc(pages + 1, sizeof(struct page *), GFP_KERNEL);
	if (!in_token->pages) {
		kfree(in_handle->data);
		return SVC_DENIED;
	}
	in_token->page_base = 0;
	in_token->page_len = inlen;
	for (i = 0; i < pages; i++) {
		in_token->pages[i] = alloc_page(GFP_KERNEL);
		if (!in_token->pages[i]) {
			kfree(in_handle->data);
			gss_free_in_token_pages(in_token);
			return SVC_DENIED;
		}
	}

	length = min_t(unsigned int, inlen, argv->iov_len);
	if (length)
		memcpy(page_address(in_token->pages[0]), argv->iov_base, length);
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
}

static inline int
gss_write_resv(struct kvec *resv, size_t size_limit,
	       struct xdr_netobj *out_handle, struct xdr_netobj *out_token,
	       int major_status, int minor_status)
{
	if (resv->iov_len + 4 > size_limit)
		return -1;
	svc_putnl(resv, RPC_SUCCESS);
	if (svc_safe_putnetobj(resv, out_handle))
		return -1;
	if (resv->iov_len + 3 * 4 > size_limit)
		return -1;
	svc_putnl(resv, major_status);
	svc_putnl(resv, minor_status);
	svc_putnl(resv, GSS_SEQ_WIN);
	if (svc_safe_putnetobj(resv, out_token))
		return -1;
	return 0;
}

static int (*klpe_gss_proxy_save_rsc)(struct cache_detail *cd,
				struct gssp_upcall_data *ud,
				uint64_t *handle);

int klpp_svcauth_gss_proxy_init(struct svc_rqst *rqstp,
			struct rpc_gss_wire_cred *gc, __be32 *authp)
{
	struct kvec *resv = &rqstp->rq_res.head[0];
	struct xdr_netobj cli_handle;
	struct gssp_upcall_data ud;
	uint64_t handle;
	int status;
	int ret;
	struct net *net = SVC_NET(rqstp);
	struct sunrpc_net *sn = net_generic(net, (*klpe_sunrpc_net_id));

	memset(&ud, 0, sizeof(ud));
	ret = klpr_gss_read_proxy_verf(rqstp, gc, authp,
				  &ud.in_handle, &ud.in_token);
	if (ret)
		return ret;

	ret = SVC_CLOSE;

	/* Perform synchronous upcall to gss-proxy */
	status = (*klpe_gssp_accept_sec_context_upcall)(net, &ud);
	if (status)
		goto out;

	do { if (__builtin_expect(!!((*klpe_rpc_debug) & 0x0010), 0)) printk("\001" "d" "RPC:       svcauth_gss: gss major status = %d " "minor status = %d\n",ud.major_status, ud.minor_status); } while (0);

	switch (ud.major_status) {
	case GSS_S_CONTINUE_NEEDED:
		cli_handle = ud.out_handle;
		break;
	case GSS_S_COMPLETE:
		status = (*klpe_gss_proxy_save_rsc)(sn->rsc_cache, &ud, &handle);
		if (status) {
			pr_info("%s: gss_proxy_save_rsc failed (%d)\n",
				__func__, status);
			goto out;
		}
		cli_handle.data = (u8 *)&handle;
		cli_handle.len = sizeof(handle);
		break;
	default:
		ret = SVC_CLOSE;
		goto out;
	}

	/* Got an answer to the upcall; use it: */
	if (klpr_gss_write_init_verf(sn->rsc_cache, rqstp,
				&cli_handle, &ud.major_status)) {
		pr_info("%s: gss_write_init_verf failed\n", __func__);
		goto out;
	}
	if (gss_write_resv(resv, PAGE_SIZE,
			   &cli_handle, &ud.out_token,
			   ud.major_status, ud.minor_status)) {
		pr_info("%s: gss_write_resv failed\n", __func__);
		goto out;
	}

	ret = SVC_COMPLETE;
out:
	gss_free_in_token_pages(&ud.in_token);
	(*klpe_gssp_free_upcall_data)(&ud);
	return ret;
}


#include "livepatch_bsc1256780.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "auth_rpcgss"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "dup_to_netobj", (void *)&klpe_dup_to_netobj, "auth_rpcgss" },
	{ "gss_proxy_save_rsc", (void *)&klpe_gss_proxy_save_rsc,
	  "auth_rpcgss" },
	{ "gss_svc_searchbyctx", (void *)&klpe_gss_svc_searchbyctx,
	  "auth_rpcgss" },
	{ "gss_write_verf", (void *)&klpe_gss_write_verf, "auth_rpcgss" },
	{ "gssp_accept_sec_context_upcall",
	  (void *)&klpe_gssp_accept_sec_context_upcall, "auth_rpcgss" },
	{ "gssp_free_upcall_data", (void *)&klpe_gssp_free_upcall_data,
	  "auth_rpcgss" },
	{ "rpc_debug", (void *)&klpe_rpc_debug, "sunrpc" },
	{ "sunrpc_net_id", (void *)&klpe_sunrpc_net_id, "sunrpc" },
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

int livepatch_bsc1256780_init(void)
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

void livepatch_bsc1256780_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
