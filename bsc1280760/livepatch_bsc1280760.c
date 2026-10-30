/*
 * livepatch_bsc1280760
 *
 * Fix for CVE-2026-89544, bsc#1280760
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


#include "livepatch_bsc1280760.h"

/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_xdr.c */
#include <linux/sunrpc/svcauth.h>

static void (*klpe_xdr_set_scratch_buffer)(struct xdr_stream *xdr, void *buf, size_t buflen);
static __be32 *(*klpe_xdr_inline_decode)(struct xdr_stream *xdr, size_t nbytes);

/* klp-ccp: from include/linux/sunrpc/gss_api.h */
static void (*klpe_gss_mech_put)(struct gss_api_mech *);

/* klp-ccp: from include/linux/sunrpc/svcauth.h */
static inline void klpr_free_svc_cred(struct svc_cred *cred)
{
	if (cred->cr_group_info)
		put_group_info(cred->cr_group_info);
	kfree(cred->cr_raw_principal);
	kfree(cred->cr_principal);
	(*klpe_gss_mech_put)(cred->cr_gss_mech);
	init_svc_cred(cred);
}

/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_xdr.h */
#include <linux/sunrpc/xdr.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/xprtsock.h>

#define CREDS_VALUE  "linux_creds_v1"

typedef struct xdr_netobj gssx_buffer;
typedef struct xdr_netobj utf8string;
typedef struct xdr_netobj gssx_OID;

struct gssx_option {
	gssx_buffer option;
	gssx_buffer value;
};

struct gssx_option_array {
	u32 count;
	struct gssx_option *data;
};

struct gssx_status {
	u64 major_status;
	gssx_OID mech;
	u64 minor_status;
	utf8string major_status_string;
	utf8string minor_status_string;
	gssx_buffer server_ctx;
	struct gssx_option_array options;
};

struct gssx_name {
	gssx_buffer display_name;
};
typedef struct gssx_name gssx_name;

struct gssx_ctx {
	gssx_buffer exported_context_token;
	gssx_buffer state;
	u32 need_release;
	gssx_OID mech;
	gssx_name src_name;
	gssx_name targ_name;
	u64 lifetime;
	u64 ctx_flags;
	u32 locally_initiated;
	u32 open;
	struct gssx_option_array options;
};

struct gssx_res_accept_sec_context {
	struct gssx_status status;
	struct gssx_ctx *context_handle;
	gssx_buffer *output_token;
	/* struct gssx_cred *delegated_cred_handle; not used in kernel */
	struct gssx_option_array options;
};
/* klp-ccp: from net/sunrpc/auth_gss/gss_rpc_xdr.c */
static int klpr_gssx_dec_bool(struct xdr_stream *xdr, u32 *v)
{
	__be32 *p;

	p = (*klpe_xdr_inline_decode)(xdr, 4);
	if (unlikely(p == NULL))
		return -ENOSPC;
	*v = be32_to_cpu(*p);
	return 0;
}

static int (*klpe_gssx_dec_buffer)(struct xdr_stream *xdr,
			   gssx_buffer *buf);

static int (*klpe_dummy_dec_opt_array)(struct xdr_stream *xdr,
				struct gssx_option_array *oa);

static int (*klpe_get_host_u32)(struct xdr_stream *xdr, u32 *res);

static int klpp_gssx_dec_linux_creds(struct xdr_stream *xdr,
				struct svc_cred *creds)
{
	u32 length;
	__be32 *p;
	u32 tmp;
	u32 N;
	int i, err;

	p = (*klpe_xdr_inline_decode)(xdr, 4);
	if (unlikely(p == NULL))
		return -ENOSPC;

	length = be32_to_cpup(p);

	if (length > (3 + NGROUPS_MAX) * sizeof(u32))
		return -ENOSPC;

	/* uid */
	err = (*klpe_get_host_u32)(xdr, &tmp);
	if (err)
		return err;
	creds->cr_uid = make_kuid(&init_user_ns, tmp);

	/* gid */
	err = (*klpe_get_host_u32)(xdr, &tmp);
	if (err)
		return err;
	creds->cr_gid = make_kgid(&init_user_ns, tmp);

	/* number of additional gid's */
	err = (*klpe_get_host_u32)(xdr, &tmp);
	if (err)
		return err;
	N = tmp;
	if ((3 + N) * sizeof(u32) != length)
		return -EINVAL;
	creds->cr_group_info = groups_alloc(N);
	if (creds->cr_group_info == NULL)
		return -ENOMEM;

	/* gid's */
	for (i = 0; i < N; i++) {
		kgid_t kgid;
		err = (*klpe_get_host_u32)(xdr, &tmp);
		if (err)
			goto out_free_groups;
		err = -EINVAL;
		kgid = make_kgid(&init_user_ns, tmp);
		if (!gid_valid(kgid))
			goto out_free_groups;
		creds->cr_group_info->gid[i] = kgid;
	}
	groups_sort(creds->cr_group_info);

	return 0;
out_free_groups:
	put_group_info(creds->cr_group_info);
	creds->cr_group_info = NULL;
	return err;
}

static int klpp_gssx_dec_option_array(struct xdr_stream *xdr,
				 struct gssx_option_array *oa)
{
	struct svc_cred *creds;
	u32 count, i;
	__be32 *p;
	int err;

	p = (*klpe_xdr_inline_decode)(xdr, 4);
	if (unlikely(p == NULL))
		return -ENOSPC;
	count = be32_to_cpup(p++);
	if (!count)
		return 0;

	/* we recognize only 1 currently: CREDS_VALUE */
	oa->data = kmalloc(sizeof(struct gssx_option), GFP_KERNEL);
	if (!oa->data)
		return -ENOMEM;

	oa->count = 1;

	creds = kzalloc(sizeof(struct svc_cred), GFP_KERNEL);
	if (!creds) {
		err = -ENOMEM;
		goto free_oa;
	}

	oa->data[0].option.data = CREDS_VALUE;
	oa->data[0].option.len = sizeof(CREDS_VALUE);
	oa->data[0].value.data = (void *)creds;
	oa->data[0].value.len = 0;

	for (i = 0; i < count; i++) {
		gssx_buffer dummy = { 0, NULL };
		u32 length;

		/* option buffer */
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(p == NULL)) {
			err = -ENOSPC;
			goto free_creds;
		}

		length = be32_to_cpup(p);
		p = (*klpe_xdr_inline_decode)(xdr, length);
		if (unlikely(p == NULL)) {
			err = -ENOSPC;
			goto free_creds;
		}

		if (length == sizeof(CREDS_VALUE) &&
		    memcmp(p, CREDS_VALUE, sizeof(CREDS_VALUE)) == 0) {
			/* We have creds here. parse them */
			err = klpp_gssx_dec_linux_creds(xdr, creds);
			if (err)
				goto free_creds;
			oa->data[0].value.len = 1; /* presence */
		} else {
			/* consume uninteresting buffer */
			err = (*klpe_gssx_dec_buffer)(xdr, &dummy);
			if (err)
				goto free_creds;
		}
	}
	return 0;

free_creds:
	klpr_free_svc_cred(creds);
	kfree(creds);
free_oa:
	oa->count = 0;
	kfree(oa->data);
	oa->data = NULL;
	return err;
}

static int klpr_gssx_dec_status(struct xdr_stream *xdr,
			   struct gssx_status *status)
{
	__be32 *p;
	int err;

	/* status->major_status */
	p = (*klpe_xdr_inline_decode)(xdr, 8);
	if (unlikely(p == NULL))
		return -ENOSPC;
	p = xdr_decode_hyper(p, &status->major_status);

	/* status->mech */
	err = (*klpe_gssx_dec_buffer)(xdr, &status->mech);
	if (err)
		return err;

	/* status->minor_status */
	p = (*klpe_xdr_inline_decode)(xdr, 8);
	if (unlikely(p == NULL))
		return -ENOSPC;
	p = xdr_decode_hyper(p, &status->minor_status);

	/* status->major_status_string */
	err = (*klpe_gssx_dec_buffer)(xdr, &status->major_status_string);
	if (err)
		return err;

	/* status->minor_status_string */
	err = (*klpe_gssx_dec_buffer)(xdr, &status->minor_status_string);
	if (err)
		return err;

	/* status->server_ctx */
	err = (*klpe_gssx_dec_buffer)(xdr, &status->server_ctx);
	if (err)
		return err;

	/* we assume we have no options for now, so simply consume them */
	/* status->options */
	err = (*klpe_dummy_dec_opt_array)(xdr, &status->options);

	return err;
}

static int (*klpe_gssx_dec_name)(struct xdr_stream *xdr,
			 struct gssx_name *name);

static int klpr_gssx_dec_ctx(struct xdr_stream *xdr,
			struct gssx_ctx *ctx)
{
	__be32 *p;
	int err;

	/* ctx->exported_context_token */
	err = (*klpe_gssx_dec_buffer)(xdr, &ctx->exported_context_token);
	if (err)
		return err;

	/* ctx->state */
	err = (*klpe_gssx_dec_buffer)(xdr, &ctx->state);
	if (err)
		return err;

	/* ctx->need_release */
	err = klpr_gssx_dec_bool(xdr, &ctx->need_release);
	if (err)
		return err;

	/* ctx->mech */
	err = (*klpe_gssx_dec_buffer)(xdr, &ctx->mech);
	if (err)
		return err;

	/* ctx->src_name */
	err = (*klpe_gssx_dec_name)(xdr, &ctx->src_name);
	if (err)
		return err;

	/* ctx->targ_name */
	err = (*klpe_gssx_dec_name)(xdr, &ctx->targ_name);
	if (err)
		return err;

	/* ctx->lifetime */
	p = (*klpe_xdr_inline_decode)(xdr, 8+8);
	if (unlikely(p == NULL))
		return -ENOSPC;
	p = xdr_decode_hyper(p, &ctx->lifetime);

	/* ctx->ctx_flags */
	p = xdr_decode_hyper(p, &ctx->ctx_flags);

	/* ctx->locally_initiated */
	err = klpr_gssx_dec_bool(xdr, &ctx->locally_initiated);
	if (err)
		return err;

	/* ctx->open */
	err = klpr_gssx_dec_bool(xdr, &ctx->open);
	if (err)
		return err;

	/* we assume we have no options for now, so simply consume them */
	/* ctx->options */
	err = (*klpe_dummy_dec_opt_array)(xdr, &ctx->options);

	return err;
}

int klpp_gssx_dec_accept_sec_context(struct rpc_rqst *rqstp,
				struct xdr_stream *xdr,
				struct gssx_res_accept_sec_context *res)
{
	u32 value_follows;
	int err;
	struct page *scratch;

	scratch = alloc_page(GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	(*klpe_xdr_set_scratch_buffer)(xdr, page_address(scratch), PAGE_SIZE);

	/* res->status */
	err = klpr_gssx_dec_status(xdr, &res->status);
	if (err)
		goto out_free;

	/* res->context_handle */
	err = klpr_gssx_dec_bool(xdr, &value_follows);
	if (err)
		goto out_free;
	if (value_follows) {
		err = klpr_gssx_dec_ctx(xdr, res->context_handle);
		if (err)
			goto out_free;
	} else {
		res->context_handle = NULL;
	}

	/* res->output_token */
	err = klpr_gssx_dec_bool(xdr, &value_follows);
	if (err)
		goto out_free;
	if (value_follows) {
		err = (*klpe_gssx_dec_buffer)(xdr, res->output_token);
		if (err)
			goto out_free;
	} else {
		res->output_token = NULL;
	}

	/* res->delegated_cred_handle */
	err = klpr_gssx_dec_bool(xdr, &value_follows);
	if (err)
		goto out_free;
	if (value_follows) {
		/* we do not support upcall servers sending this data. */
		err = -EINVAL;
		goto out_free;
	}

	/* res->options */
	err = klpp_gssx_dec_option_array(xdr, &res->options);

out_free:
	__free_page(scratch);
	return err;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "auth_rpcgss"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "dummy_dec_opt_array", (void *)&klpe_dummy_dec_opt_array,
	  "auth_rpcgss" },
	{ "get_host_u32", (void *)&klpe_get_host_u32, "auth_rpcgss" },
	{ "gss_mech_put", (void *)&klpe_gss_mech_put, "auth_rpcgss" },
	{ "gssx_dec_buffer", (void *)&klpe_gssx_dec_buffer, "auth_rpcgss" },
	{ "gssx_dec_name", (void *)&klpe_gssx_dec_name, "auth_rpcgss" },
	{ "xdr_inline_decode", (void *)&klpe_xdr_inline_decode, "sunrpc" },
	{ "xdr_set_scratch_buffer", (void *)&klpe_xdr_set_scratch_buffer,
	  "sunrpc" },
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

int livepatch_bsc1280760_init(void)
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

void livepatch_bsc1280760_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
