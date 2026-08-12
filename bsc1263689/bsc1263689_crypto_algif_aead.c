/*
 * livepatch_bsc1263689
 *
 * Fix for CVE-2026-31431, bsc#1263689
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


#include "livepatch_bsc1263689.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from crypto/algif_aead.c */
#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
#include <crypto/if_alg.h>

/* klp-ccp: from include/crypto/if_alg.h */
static int (*klpe_af_alg_wait_for_completion)(int err, struct af_alg_completion *completion);
static void (*klpe_af_alg_complete)(struct crypto_async_request *req, int err);

static unsigned int (*klpe_af_alg_count_tsgl)(struct sock *sk, size_t bytes, size_t offset);
static void (*klpe_af_alg_pull_tsgl)(struct sock *sk, size_t used, struct scatterlist *dst,
		      size_t dst_offset);

static void (*klpe_af_alg_wmem_wakeup)(struct sock *sk);
static int (*klpe_af_alg_wait_for_data)(struct sock *sk, unsigned flags);

static void (*klpe_af_alg_free_resources)(struct af_alg_async_req *areq);
static void (*klpe_af_alg_async_cb)(struct crypto_async_request *_req, int err);

static struct af_alg_async_req *(*klpe_af_alg_alloc_areq)(struct sock *sk,
					   unsigned int areqlen);
static int (*klpe_af_alg_get_rsgl)(struct sock *sk, struct msghdr *msg, int flags,
		    struct af_alg_async_req *areq, size_t maxsize,
		    size_t *outlen);

/* klp-ccp: from crypto/algif_aead.c */
#include <crypto/skcipher.h>
#include <crypto/null.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>

struct aead_tfm {
	struct crypto_aead *aead;
	bool has_key;
	struct crypto_skcipher *null_tfm;
};

void memcpy_sglist(struct scatterlist *dst, struct scatterlist *src,
		   unsigned int nbytes);


static inline bool aead_sufficient_data(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct sock *psk = ask->parent;
	struct alg_sock *pask = alg_sk(psk);
	struct af_alg_ctx *ctx = ask->private;
	struct aead_tfm *aeadc = pask->private;
	struct crypto_aead *tfm = aeadc->aead;
	unsigned int as = crypto_aead_authsize(tfm);

	/*
	 * The minimum amount of memory needed for an AEAD cipher is
	 * the AAD and in case of decryption the tag.
	 */
	return ctx->used >= ctx->aead_assoclen + (ctx->enc ? 0 : as);
}

/*
 * Flush the dcache of any pages that overlap the region
 * [offset, offset + nbytes) relative to base_page.
 *
 * This should be called only when ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE, to ensure
 * that all relevant code (including the call to sg_page() in the caller, if
 * applicable) gets fully optimized out when !ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE.
 */
static inline void __scatterwalk_flush_dcache_pages(struct page *base_page,
						    unsigned int offset,
						    unsigned int nbytes)
{
	unsigned int num_pages;
	unsigned int i;

	base_page += offset / PAGE_SIZE;
	offset %= PAGE_SIZE;

	/*
	 * This is an overflow-safe version of
	 * num_pages = DIV_ROUND_UP(offset + nbytes, PAGE_SIZE).
	 */
	num_pages = nbytes / PAGE_SIZE;
	num_pages += DIV_ROUND_UP(offset + (nbytes % PAGE_SIZE), PAGE_SIZE);

	for (i = 0; i < num_pages; i++)
		flush_dcache_page(base_page + i);
}

/**
 * memcpy_sglist() - Copy data from one scatterlist to another
 * @dst: The destination scatterlist.  Can be NULL if @nbytes == 0.
 * @src: The source scatterlist.  Can be NULL if @nbytes == 0.
 * @nbytes: Number of bytes to copy
 *
 * The scatterlists can describe exactly the same memory, in which case this
 * function is a no-op.  No other overlaps are supported.
 *
 * Context: Any context
 */
void memcpy_sglist(struct scatterlist *dst, struct scatterlist *src,
		   unsigned int nbytes)
{
	unsigned int src_offset, dst_offset;

	if (unlikely(nbytes == 0)) /* in case src and/or dst is NULL */
		return;

	src_offset = src->offset;
	dst_offset = dst->offset;
	for (;;) {
		/* Compute the length to copy this step. */
		unsigned int len = min3(src->offset + src->length - src_offset,
					dst->offset + dst->length - dst_offset,
					nbytes);
		struct page *src_page = sg_page(src);
		struct page *dst_page = sg_page(dst);
		const void *src_virt;
		void *dst_virt;

#ifdef CONFIG_HIGHMEM
#error "klp-ccp: non-taken branch"
#endif
		/*
		 * !HIGHMEM: no mapping needed.  Just work in the linear
		 * buffer of each sg entry.  Note that we can cross page
		 * boundaries, as they are not significant in this case.
		 */
		src_virt = page_address(src_page) + src_offset;
		dst_virt = page_address(dst_page) + dst_offset;
		if (src_virt != dst_virt) {
			memcpy(dst_virt, src_virt, len);
			if (ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE)
				__scatterwalk_flush_dcache_pages(
					dst_page, dst_offset, len);
		} /* Else, it's the same memory.  No action needed. */

		nbytes -= len;
		if (nbytes == 0) /* No more to copy? */
			break;

		/*
		 * There's more to copy.  Advance the offsets by the length
		 * copied this step, and advance the sg entries as needed.
		 */
		src_offset += len;
		if (src_offset >= src->offset + src->length) {
			src = sg_next(src);
			src_offset = src->offset;
		}
		dst_offset += len;
		if (dst_offset >= dst->offset + dst->length) {
			dst = sg_next(dst);
			dst_offset = dst->offset;
		}
	}
}

static int klpp__aead_recvmsg(struct socket *sock, struct msghdr *msg,
			 size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct sock *psk = ask->parent;
	struct alg_sock *pask = alg_sk(psk);
	struct af_alg_ctx *ctx = ask->private;
	struct aead_tfm *aeadc = pask->private;
	struct crypto_aead *tfm = aeadc->aead;
	unsigned int as = crypto_aead_authsize(tfm);
	struct af_alg_async_req *areq;
	struct scatterlist *rsgl_src, *tsgl_src = NULL;
	int err = 0;
	size_t used = 0;		/* [in]  TX bufs to be en/decrypted */
	size_t outlen = 0;		/* [out] RX bufs produced by kernel */
	size_t usedpages = 0;		/* [in]  RX bufs to be used from user */
	size_t processed = 0;		/* [in]  TX bufs to be consumed */

	if (!ctx->used) {
		err = (*klpe_af_alg_wait_for_data)(sk, flags);
		if (err)
			return err;
	}

	/*
	 * Data length provided by caller via sendmsg/sendpage that has not
	 * yet been processed.
	 */
	used = ctx->used;

	/*
	 * Make sure sufficient data is present -- note, the same check is
	 * is also present in sendmsg/sendpage. The checks in sendpage/sendmsg
	 * shall provide an information to the data sender that something is
	 * wrong, but they are irrelevant to maintain the kernel integrity.
	 * We need this check here too in case user space decides to not honor
	 * the error message in sendmsg/sendpage and still call recvmsg. This
	 * check here protects the kernel integrity.
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
	areq = (*klpe_af_alg_alloc_areq)(sk, sizeof(struct af_alg_async_req) +
				     crypto_aead_reqsize(tfm));
	if (IS_ERR(areq))
		return PTR_ERR(areq);

	/* convert iovecs of output buffers into RX SGL */
	err = (*klpe_af_alg_get_rsgl)(sk, msg, flags, areq, outlen, &usedpages);
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
	areq->tsgl_entries = (*klpe_af_alg_count_tsgl)(sk, processed, 0);
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
	(*klpe_af_alg_pull_tsgl)(sk, processed, areq->tsgl, 0);
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
	rsgl_src = areq->first_rsgl.sgl.sg;

	memcpy_sglist(rsgl_src, tsgl_src, ctx->aead_assoclen);

	/* Initialize the crypto operation */
	aead_request_set_crypt(&areq->cra_u.aead_req, tsgl_src,
			       areq->first_rsgl.sgl.sg, used, ctx->iv);
	aead_request_set_ad(&areq->cra_u.aead_req, ctx->aead_assoclen);
	aead_request_set_tfm(&areq->cra_u.aead_req, tfm);

	if (msg->msg_iocb && !is_sync_kiocb(msg->msg_iocb)) {
		/* AIO operation */
		sock_hold(sk);
		areq->iocb = msg->msg_iocb;

		/* Remember output size that will be generated. */
		areq->outlen = outlen;

		aead_request_set_callback(&areq->cra_u.aead_req,
					  CRYPTO_TFM_REQ_MAY_BACKLOG,
					  (*klpe_af_alg_async_cb), areq);
		err = ctx->enc ? crypto_aead_encrypt(&areq->cra_u.aead_req) :
				 crypto_aead_decrypt(&areq->cra_u.aead_req);

		/* AIO operation in progress */
		if (err == -EINPROGRESS || err == -EBUSY)
			return -EIOCBQUEUED;

		sock_put(sk);
	} else {
		/* Synchronous operation */
		aead_request_set_callback(&areq->cra_u.aead_req,
					  CRYPTO_TFM_REQ_MAY_BACKLOG,
					  (*klpe_af_alg_complete), &ctx->completion);
		err = (*klpe_af_alg_wait_for_completion)(ctx->enc ?
				crypto_aead_encrypt(&areq->cra_u.aead_req) :
				crypto_aead_decrypt(&areq->cra_u.aead_req),
						 &ctx->completion);
	}
free:
	(*klpe_af_alg_free_resources)(areq);

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
	(*klpe_af_alg_wmem_wakeup)(sk);
	release_sock(sk);
	return ret;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "algif_aead"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "af_alg_alloc_areq", (void *)&klpe_af_alg_alloc_areq, "af_alg" },
	{ "af_alg_async_cb", (void *)&klpe_af_alg_async_cb, "af_alg" },
	{ "af_alg_complete", (void *)&klpe_af_alg_complete, "af_alg" },
	{ "af_alg_count_tsgl", (void *)&klpe_af_alg_count_tsgl, "af_alg" },
	{ "af_alg_free_resources", (void *)&klpe_af_alg_free_resources,
	  "af_alg" },
	{ "af_alg_get_rsgl", (void *)&klpe_af_alg_get_rsgl, "af_alg" },
	{ "af_alg_pull_tsgl", (void *)&klpe_af_alg_pull_tsgl, "af_alg" },
	{ "af_alg_wait_for_completion",
	  (void *)&klpe_af_alg_wait_for_completion, "af_alg" },
	{ "af_alg_wait_for_data", (void *)&klpe_af_alg_wait_for_data,
	  "af_alg" },
	{ "af_alg_wmem_wakeup", (void *)&klpe_af_alg_wmem_wakeup, "af_alg" },
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

int bsc1263689_crypto_algif_aead_init(void)
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

void bsc1263689_crypto_algif_aead_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
