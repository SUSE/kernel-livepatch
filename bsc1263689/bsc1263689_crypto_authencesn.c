/*
 * bsc1263689_crypto_authencesn
 *
 * Fix for CVE-2026-31431, bsc#1263689
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


#include "livepatch_bsc1263689.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from crypto/authencesn.c */
#include <crypto/internal/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/authenc.h>
#include <crypto/scatterwalk.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

struct crypto_authenc_esn_ctx {
	unsigned int reqoff;
	struct crypto_ahash *auth;
	struct crypto_skcipher *enc;
	struct crypto_skcipher *null;
};

struct authenc_esn_request_ctx {
	struct scatterlist src[2];
	struct scatterlist dst[2];
	char tail[];
};

void memcpy_sglist(struct scatterlist *dst, struct scatterlist *src,
		   unsigned int nbytes);

int klpp_crypto_authenc_esn_decrypt_tail(struct aead_request *req,
					   unsigned int flags)
{
	struct crypto_aead *authenc_esn = crypto_aead_reqtfm(req);
	unsigned int authsize = crypto_aead_authsize(authenc_esn);
	struct authenc_esn_request_ctx *areq_ctx = aead_request_ctx(req);
	struct crypto_authenc_esn_ctx *ctx = crypto_aead_ctx(authenc_esn);
	struct skcipher_request *skreq = (void *)(areq_ctx->tail +
						  ctx->reqoff);
	struct crypto_ahash *auth = ctx->auth;
	u8 *ohash = PTR_ALIGN((u8 *)areq_ctx->tail,
			      crypto_ahash_alignmask(auth) + 1);
	unsigned int cryptlen = req->cryptlen - authsize;
	unsigned int assoclen = req->assoclen;
	struct scatterlist *src = req->src;
	struct scatterlist *dst = req->dst;
	u8 *ihash = ohash + crypto_ahash_digestsize(auth);
	u32 tmp[2];

	if (!authsize)
		goto decrypt;

	if (src == dst) {
		/* Move high-order bits of sequence number back. */
		scatterwalk_map_and_copy(tmp, dst, 4, 4, 0);
		scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 0);
		scatterwalk_map_and_copy(tmp, dst, 0, 8, 1);
	} else
		memcpy_sglist(dst, src, assoclen);

	if (crypto_memneq(ihash, ohash, authsize))
		return -EBADMSG;

decrypt:

	dst = scatterwalk_ffwd(areq_ctx->dst, dst, assoclen);
	if (req->src == req->dst)
		src = dst;
	else
		src = scatterwalk_ffwd(areq_ctx->src, src, assoclen);

	skcipher_request_set_tfm(skreq, ctx->enc);
	skcipher_request_set_callback(skreq, flags,
				      req->base.complete, req->base.data);
	skcipher_request_set_crypt(skreq, src, dst, cryptlen, req->iv);

	return crypto_skcipher_decrypt(skreq);
}

static void (*klpe_authenc_esn_verify_ahash_done)(struct crypto_async_request *areq,
					  int err);

int klpp_crypto_authenc_esn_decrypt(struct aead_request *req)
{
	struct crypto_aead *authenc_esn = crypto_aead_reqtfm(req);
	struct authenc_esn_request_ctx *areq_ctx = aead_request_ctx(req);
	struct crypto_authenc_esn_ctx *ctx = crypto_aead_ctx(authenc_esn);
	struct ahash_request *ahreq = (void *)(areq_ctx->tail + ctx->reqoff);
	unsigned int authsize = crypto_aead_authsize(authenc_esn);
	struct crypto_ahash *auth = ctx->auth;
	u8 *ohash = PTR_ALIGN((u8 *)areq_ctx->tail,
			      crypto_ahash_alignmask(auth) + 1);
	unsigned int assoclen = req->assoclen;
	unsigned int cryptlen = req->cryptlen;
	u8 *ihash = ohash + crypto_ahash_digestsize(auth);
	struct scatterlist *src = req->src;
	struct scatterlist *dst = req->dst;
	u32 tmp[2];
	int err;

	if (assoclen < 8)
		return -EINVAL;

	if (!authsize)
		goto tail;

	cryptlen -= authsize;
	scatterwalk_map_and_copy(ihash, req->src, assoclen + cryptlen,
				 authsize, 0);

	/* Move high-order bits of sequence number to the end. */
	scatterwalk_map_and_copy(tmp, src, 0, 8, 0);
	if (src == dst) {
		scatterwalk_map_and_copy(tmp, dst, 4, 4, 1);
		scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);
		dst = scatterwalk_ffwd(areq_ctx->dst, dst, 4);
	} else {
		scatterwalk_map_and_copy(tmp, dst, 0, 4, 1);
		scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen - 4, 4, 1);

		src = scatterwalk_ffwd(areq_ctx->src, src, 8);
		dst = scatterwalk_ffwd(areq_ctx->dst, dst, 4);
		memcpy_sglist(dst, src, assoclen + cryptlen - 8);
		dst = req->dst;
	}

	ahash_request_set_tfm(ahreq, auth);
	ahash_request_set_crypt(ahreq, dst, ohash, assoclen + cryptlen);
	ahash_request_set_callback(ahreq, aead_request_flags(req),
				   (*klpe_authenc_esn_verify_ahash_done), req);

	err = crypto_ahash_digest(ahreq);
	if (err)
		return err;

tail:
	return klpp_crypto_authenc_esn_decrypt_tail(req, aead_request_flags(req));
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "authencesn"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "authenc_esn_verify_ahash_done",
	  (void *)&klpe_authenc_esn_verify_ahash_done, "authencesn" },
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

int bsc1263689_crypto_authencesn_init(void)
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

void bsc1263689_crypto_authencesn_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
