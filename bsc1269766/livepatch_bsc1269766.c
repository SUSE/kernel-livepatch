/*
 * livepatch_bsc1269766
 *
 * Fix for CVE-2026-53016, bsc#1269766
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

#if IS_ENABLED(CONFIG_CRYPTO_DEV_CCP_CRYPTO)

#if !IS_MODULE(CONFIG_CRYPTO_DEV_CCP_CRYPTO)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1269766.h"


/* klp-ccp: from drivers/crypto/ccp/ccp-crypto-aes.c */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/ctr.h>
#include <crypto/scatterwalk.h>

/* klp-ccp: from drivers/crypto/ccp/ccp-crypto.h */
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/ccp.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/internal/aead.h>
#include <crypto/aead.h>
#include <crypto/ctr.h>
#include <crypto/hash.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/akcipher.h>
#include <crypto/skcipher.h>
#include <crypto/internal/rsa.h>

struct ccp_aes_ctx {
	/* Fallback cipher for XTS with unsupported unit sizes */
	struct crypto_skcipher *tfm_skcipher;

	enum ccp_engine engine;
	enum ccp_aes_type type;
	enum ccp_aes_mode mode;

	struct scatterlist key_sg;
	unsigned int key_len;
	u8 key[AES_MAX_KEY_SIZE * 2];

	u8 nonce[CTR_RFC3686_NONCE_SIZE];

	/* CMAC key structures */
	struct scatterlist k1_sg;
	struct scatterlist k2_sg;
	unsigned int kn_len;
	u8 k1[AES_BLOCK_SIZE];
	u8 k2[AES_BLOCK_SIZE];
};

struct ccp_aes_req_ctx {
	struct scatterlist iv_sg;
	u8 iv[AES_BLOCK_SIZE];

	struct scatterlist tag_sg;
	u8 tag[AES_BLOCK_SIZE];

	/* Fields used for RFC3686 requests */
	u8 *rfc3686_info;
	u8 rfc3686_iv[AES_BLOCK_SIZE];

	struct ccp_cmd cmd;

	struct skcipher_request fallback_req;	// keep at the end
};

struct ccp_des3_ctx {
	enum ccp_engine engine;
	enum ccp_des3_type type;
	enum ccp_des3_mode mode;

	struct scatterlist key_sg;
	unsigned int key_len;
	u8 key[AES_MAX_KEY_SIZE];
};

#define MAX_SHA_BLOCK_SIZE	SHA512_BLOCK_SIZE

struct ccp_sha_ctx {
	struct scatterlist opad_sg;
	unsigned int opad_count;

	unsigned int key_len;
	u8 key[MAX_SHA_BLOCK_SIZE];
	u8 ipad[MAX_SHA_BLOCK_SIZE];
	u8 opad[MAX_SHA_BLOCK_SIZE];
	struct crypto_shash *hmac_tfm;
};

struct ccp_rsa_ctx {
	unsigned int key_len; /* in bits */
	struct scatterlist e_sg;
	u8 *e_buf;
	unsigned int e_len;
	struct scatterlist n_sg;
	u8 *n_buf;
	unsigned int n_len;
	struct scatterlist d_sg;
	u8 *d_buf;
	unsigned int d_len;
};

struct ccp_ctx {
	int (*complete)(struct crypto_async_request *req, int ret);

	union {
		struct ccp_aes_ctx aes;
		struct ccp_rsa_ctx rsa;
		struct ccp_sha_ctx sha;
		struct ccp_des3_ctx des3;
	} u;
};

/* klp-ccp: from drivers/crypto/ccp/ccp-crypto-aes.c */
int klpp_ccp_aes_complete(struct crypto_async_request *async_req, int ret)
{
	struct skcipher_request *req = skcipher_request_cast(async_req);
	struct ccp_ctx *ctx = crypto_skcipher_ctx_dma(
		crypto_skcipher_reqtfm(req));
	struct ccp_aes_req_ctx *rctx = skcipher_request_ctx_dma(req);

	if (ret)
		return ret;

	if (ctx->u.aes.mode != CCP_AES_MODE_ECB) {
		size_t ivsize = crypto_skcipher_ivsize(crypto_skcipher_reqtfm(req));

		memcpy(req->iv, rctx->iv, ivsize);
	}

	return 0;
}

int klpp_ccp_aes_rfc3686_complete(struct crypto_async_request *async_req,
				    int ret)
{
	struct skcipher_request *req = skcipher_request_cast(async_req);
	struct ccp_aes_req_ctx *rctx = skcipher_request_ctx_dma(req);

	/* Restore the original pointer */
	req->iv = rctx->rfc3686_info;

	return klpp_ccp_aes_complete(async_req, ret);
}

#endif /* IS_ENABLED(CONFIG_CRYPTO_DEV_CCP_CRYPTO) */
