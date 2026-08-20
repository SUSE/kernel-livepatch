/*
 * livepatch_bsc1265306
 *
 * Fix for CVE-2026-43077, bsc#1265306
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


#include "livepatch_bsc1265306.h"


/* klp-ccp: from crypto/algif_aead.c */
#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
#include <crypto/if_alg.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>

static inline bool aead_sufficient_data(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct sock *psk = ask->parent;
	struct alg_sock *pask = alg_sk(psk);
	struct af_alg_ctx *ctx = ask->private;
	struct crypto_aead *tfm = pask->private;
	unsigned int as = crypto_aead_authsize(tfm);

	/*
	 * The minimum amount of memory needed for an AEAD cipher is
	 * the AAD and in case of decryption the tag.
	 */
	return ctx->used >= ctx->aead_assoclen + (ctx->enc ? 0 : as);
}

static int klpp__aead_recvmsg(struct socket *sock, struct msghdr *msg,
			 size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct sock *psk = ask->parent;
	struct alg_sock *pask = alg_sk(psk);
	struct af_alg_ctx *ctx = ask->private;
	struct crypto_aead *tfm = pask->private;
	unsigned int as = crypto_aead_authsize(tfm);
	struct af_alg_async_req *areq;
	struct scatterlist *rsgl_src, *tsgl_src = NULL;
	int err = 0;
	size_t used = 0;		/* [in]  TX bufs to be en/decrypted */
	size_t outlen = 0;		/* [out] RX bufs produced by kernel */
	size_t usedpages = 0;		/* [in]  RX bufs to be used from user */
	size_t processed = 0;		/* [in]  TX bufs to be consumed */

	if (!ctx->init || ctx->more) {
		err = af_alg_wait_for_data(sk, flags, 0);
		if (err)
			return err;
	}

	/*
	 * Data length provided by caller via sendmsg that has not yet been
	 * processed.
	 */
	used = ctx->used;

	/*
	 * Make sure sufficient data is present -- note, the same check is also
	 * present in sendmsg. The checks in sendmsg shall provide an
	 * information to the data sender that something is wrong, but they are
	 * irrelevant to maintain the kernel integrity.  We need this check
	 * here too in case user space decides to not honor the error message
	 * in sendmsg and still call recvmsg. This check here protects the
	 * kernel integrity.
	 */
	if (!aead_sufficient_data(sk))
		return -EINVAL;

	/*
	 * Calculate the minimum output buffer size holding the result of the
	 * cipher operation. When encrypting data, the receiving buffer is
	 * larger by the tag length compared to the input buffer as the
	 * encryption operation generates the tag. For decryption, the input
	 * buffer provides the tag which is consumed resulting in only the
	 * plaintext without a buffer for the tag returned to the caller.
	 */
	if (ctx->enc)
		outlen = used + as;
	else
		outlen = used - as;

	/*
	 * The cipher operation input data is reduced by the associated data
	 * length as this data is processed separately later on.
	 */
	used -= ctx->aead_assoclen;

	/* Allocate cipher request for current operation. */
	areq = af_alg_alloc_areq(sk, sizeof(struct af_alg_async_req) +
				     crypto_aead_reqsize(tfm));
	if (IS_ERR(areq))
		return PTR_ERR(areq);

	/* convert iovecs of output buffers into RX SGL */
	err = af_alg_get_rsgl(sk, msg, flags, areq, outlen, &usedpages);
	if (err)
		goto free;

	/*
	 * Ensure output buffer is sufficiently large. If the caller provides
	 * less buffer space, only use the relative required input size. This
	 * allows AIO operation where the caller sent all data to be processed
	 * and the AIO operation performs the operation on the different chunks
	 * of the input data.
	 */
	if (usedpages < outlen) {
		size_t less = outlen - usedpages;

		if (used < less + (ctx->enc ? 0 : as)) {
			err = -EINVAL;
			goto free;
		}
		used -= less;
		outlen -= less;
	}

	/*
	 * Create a per request TX SGL for this request which tracks the
	 * SG entries from the global TX SGL.
	 */
	processed = used + ctx->aead_assoclen;
	areq->tsgl_entries = af_alg_count_tsgl(sk, processed, 0);
	if (!areq->tsgl_entries)
		areq->tsgl_entries = 1;
	areq->tsgl = sock_kmalloc(sk, array_size(sizeof(*areq->tsgl),
					         areq->tsgl_entries),
				  GFP_KERNEL);
	if (!areq->tsgl) {
		err = -ENOMEM;
		goto free;
	}
	sg_init_table(areq->tsgl, areq->tsgl_entries);
	af_alg_pull_tsgl(sk, processed, areq->tsgl, 0);
	tsgl_src = areq->tsgl;

	/*
	 * Copy of AAD from source to destination
	 *
	 * The AAD is copied to the destination buffer without change. Even
	 * when user space uses an in-place cipher operation, the kernel
	 * will copy the data as it does not see whether such in-place operation
	 * is initiated.
	 */

	/* Use the RX SGL as source (and destination) for crypto op. */
	rsgl_src = areq->first_rsgl.sgl.sgt.sgl;

	memcpy_sglist(rsgl_src, tsgl_src, ctx->aead_assoclen);

	/* Initialize the crypto operation */
	aead_request_set_crypt(&areq->cra_u.aead_req, tsgl_src,
			       areq->first_rsgl.sgl.sgt.sgl, used, ctx->iv);
	aead_request_set_ad(&areq->cra_u.aead_req, ctx->aead_assoclen);
	aead_request_set_tfm(&areq->cra_u.aead_req, tfm);

	if (msg->msg_iocb && !is_sync_kiocb(msg->msg_iocb)) {
		/* AIO operation */
		sock_hold(sk);
		areq->iocb = msg->msg_iocb;

		/* Remember output size that will be generated. */
		areq->outlen = outlen;

		aead_request_set_callback(&areq->cra_u.aead_req,
					  CRYPTO_TFM_REQ_MAY_SLEEP,
					  af_alg_async_cb, areq);
		err = ctx->enc ? crypto_aead_encrypt(&areq->cra_u.aead_req) :
				 crypto_aead_decrypt(&areq->cra_u.aead_req);

		/* AIO operation in progress */
		if (err == -EINPROGRESS)
			return -EIOCBQUEUED;

		sock_put(sk);
	} else {
		/* Synchronous operation */
		aead_request_set_callback(&areq->cra_u.aead_req,
					  CRYPTO_TFM_REQ_MAY_SLEEP |
					  CRYPTO_TFM_REQ_MAY_BACKLOG,
					  crypto_req_done, &ctx->wait);
		err = crypto_wait_req(ctx->enc ?
				crypto_aead_encrypt(&areq->cra_u.aead_req) :
				crypto_aead_decrypt(&areq->cra_u.aead_req),
				&ctx->wait);
	}
free:
	af_alg_free_resources(areq);

	return err ? err : outlen;
}

int klpp_aead_recvmsg(struct socket *sock, struct msghdr *msg,
			size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	int ret = 0;

	lock_sock(sk);
	while (msg_data_left(msg)) {
		int err = klpp__aead_recvmsg(sock, msg, ignored, flags);

		/*
		 * This error covers -EIOCBQUEUED which implies that we can
		 * only handle one AIO request. If the caller wants to have
		 * multiple AIO requests in parallel, he must make multiple
		 * separate AIO calls.
		 *
		 * Also return the error if no data has been processed so far.
		 */
		if (err <= 0) {
			if (err == -EIOCBQUEUED || err == -EBADMSG || !ret)
				ret = err;
			goto out;
		}

		ret += err;
	}

out:
	af_alg_wmem_wakeup(sk);
	release_sock(sk);
	return ret;
}


#include <linux/livepatch.h>

extern typeof(af_alg_alloc_areq) af_alg_alloc_areq
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_alloc_areq);
extern typeof(af_alg_async_cb) af_alg_async_cb
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_async_cb);
extern typeof(af_alg_count_tsgl) af_alg_count_tsgl
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_count_tsgl);
extern typeof(af_alg_free_resources) af_alg_free_resources
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_free_resources);
extern typeof(af_alg_get_rsgl) af_alg_get_rsgl
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_get_rsgl);
extern typeof(af_alg_pull_tsgl) af_alg_pull_tsgl
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_pull_tsgl);
extern typeof(af_alg_wait_for_data) af_alg_wait_for_data
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_wait_for_data);
extern typeof(af_alg_wmem_wakeup) af_alg_wmem_wakeup
	 KLP_RELOC_SYMBOL(algif_aead, af_alg, af_alg_wmem_wakeup);
