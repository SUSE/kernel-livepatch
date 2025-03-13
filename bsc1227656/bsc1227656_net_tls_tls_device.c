/*
 * bsc1227656_net_tls_tls_device
 *
 * Fix for CVE-2021-47496, bsc#1227656
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

/* klp-ccp: from net/tls/tls_device.c */
#include <crypto/aead.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/dst.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/tls.h>


/* manually copied from include/net/tls.h */
static noinline void klpp_tls_err_abort(struct sock *sk, int err)
{
	WARN_ON_ONCE(err >= 0);
	/* sk->sk_err should contain a positive error code. */
	sk->sk_err = -err;
	sk->sk_error_report(sk);
}

/* manually copied from include/net/tls.h */
static inline void klpp_tls_advance_record_sn(struct sock *sk,
					 struct cipher_context *ctx)
{
	if (tls_bigint_increment(ctx->rec_seq, ctx->rec_seq_size))
		klpp_tls_err_abort(sk, -EBADMSG);
	tls_bigint_increment(ctx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			     ctx->iv_size);
}

/* klp-ccp: from include/net/tls.h */
static int (*klpe_tls_push_sg)(struct sock *sk, struct tls_context *ctx,
		struct scatterlist *sg, u16 first_offset,
		int flags);
static int (*klpe_tls_push_partial_record)(struct sock *sk, struct tls_context *ctx,
			    int flags);

/* klp-ccp: from net/tls/tls_device.c */
static void (*klpe_destroy_record)(struct tls_record_info *record);

static void (*klpe_tls_append_frag)(struct tls_record_info *record,
			    struct page_frag *pfrag,
			    int size);

static int klpr_tls_push_record(struct sock *sk,
			   struct tls_context *ctx,
			   struct tls_offload_context_tx *offload_ctx,
			   struct tls_record_info *record,
			   struct page_frag *pfrag,
			   int flags,
			   unsigned char record_type)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct page_frag dummy_tag_frag;
	skb_frag_t *frag;
	int i;

	/* fill prepend */
	frag = &record->frags[0];
	tls_fill_prepend(ctx,
			 skb_frag_address(frag),
			 record->len - ctx->tx.prepend_size,
			 record_type);

	/* HW doesn't care about the data in the tag, because it fills it. */
	dummy_tag_frag.page = skb_frag_page(frag);
	dummy_tag_frag.offset = 0;

	(*klpe_tls_append_frag)(record, &dummy_tag_frag, ctx->tx.tag_size);
	record->end_seq = tp->write_seq + record->len;
	spin_lock_irq(&offload_ctx->lock);
	list_add_tail(&record->list, &offload_ctx->records_list);
	spin_unlock_irq(&offload_ctx->lock);
	offload_ctx->open_record = NULL;
	klpp_tls_advance_record_sn(sk, &ctx->tx);

	for (i = 0; i < record->num_frags; i++) {
		frag = &record->frags[i];
		sg_unmark_end(&offload_ctx->sg_tx_data[i]);
		sg_set_page(&offload_ctx->sg_tx_data[i], skb_frag_page(frag),
			    frag->size, frag->page_offset);
		sk_mem_charge(sk, frag->size);
		get_page(skb_frag_page(frag));
	}
	sg_mark_end(&offload_ctx->sg_tx_data[record->num_frags - 1]);

	/* all ready, send */
	return (*klpe_tls_push_sg)(sk, ctx, offload_ctx->sg_tx_data, 0, flags);
}

static int tls_create_new_record(struct tls_offload_context_tx *offload_ctx,
				 struct page_frag *pfrag,
				 size_t prepend_size)
{
	struct tls_record_info *record;
	skb_frag_t *frag;

	record = kmalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return -ENOMEM;

	frag = &record->frags[0];
	__skb_frag_set_page(frag, pfrag->page);
	frag->page_offset = pfrag->offset;
	skb_frag_size_set(frag, prepend_size);

	get_page(pfrag->page);
	pfrag->offset += prepend_size;

	record->num_frags = 1;
	record->len = prepend_size;
	offload_ctx->open_record = record;
	return 0;
}

static int tls_do_allocation(struct sock *sk,
			     struct tls_offload_context_tx *offload_ctx,
			     struct page_frag *pfrag,
			     size_t prepend_size)
{
	int ret;

	if (!offload_ctx->open_record) {
		if (unlikely(!skb_page_frag_refill(prepend_size, pfrag,
						   sk->sk_allocation))) {
			sk->sk_prot->enter_memory_pressure(sk);
			sk_stream_moderate_sndbuf(sk);
			return -ENOMEM;
		}

		ret = tls_create_new_record(offload_ctx, pfrag, prepend_size);
		if (ret)
			return ret;

		if (pfrag->size > pfrag->offset)
			return 0;
	}

	if (!sk_page_frag_refill(sk, pfrag))
		return -ENOMEM;

	return 0;
}

int klpp_tls_push_data(struct sock *sk,
			 struct iov_iter *msg_iter,
			 size_t size, int flags,
			 unsigned char record_type)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context_tx *ctx = tls_offload_ctx_tx(tls_ctx);
	int tls_push_record_flags = flags | MSG_SENDPAGE_NOTLAST;
	int more = flags & (MSG_SENDPAGE_NOTLAST | MSG_MORE);
	struct tls_record_info *record = ctx->open_record;
	struct page_frag *pfrag;
	size_t orig_size = size;
	u32 max_open_record_len;
	int copy, rc = 0;
	bool done = false;
	long timeo;

	if (flags &
	    ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL | MSG_SENDPAGE_NOTLAST))
		return -ENOTSUPP;

	if (sk->sk_err)
		return -sk->sk_err;

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	if (tls_is_partially_sent_record(tls_ctx)) {
		rc = (*klpe_tls_push_partial_record)(sk, tls_ctx, flags);
		if (rc < 0)
			return rc;
	}

	pfrag = sk_page_frag(sk);

	/* TLS_HEADER_SIZE is not counted as part of the TLS record, and
	 * we need to leave room for an authentication tag.
	 */
	max_open_record_len = TLS_MAX_PAYLOAD_SIZE +
			      tls_ctx->tx.prepend_size;
	do {
		rc = tls_do_allocation(sk, ctx, pfrag,
				       tls_ctx->tx.prepend_size);
		if (rc) {
			rc = sk_stream_wait_memory(sk, &timeo);
			if (!rc)
				continue;

			record = ctx->open_record;
			if (!record)
				break;
handle_error:
			if (record_type != TLS_RECORD_TYPE_DATA) {
				/* avoid sending partial
				 * record with type !=
				 * application_data
				 */
				size = orig_size;
				(*klpe_destroy_record)(record);
				ctx->open_record = NULL;
			} else if (record->len > tls_ctx->tx.prepend_size) {
				goto last_record;
			}

			break;
		}

		record = ctx->open_record;
		copy = min_t(size_t, size, (pfrag->size - pfrag->offset));
		copy = min_t(size_t, copy, (max_open_record_len - record->len));

		if (copy_from_iter_nocache(page_address(pfrag->page) +
					       pfrag->offset,
					   copy, msg_iter) != copy) {
			rc = -EFAULT;
			goto handle_error;
		}
		(*klpe_tls_append_frag)(record, pfrag, copy);

		size -= copy;
		if (!size) {
last_record:
			tls_push_record_flags = flags;
			if (more) {
				tls_ctx->pending_open_record_frags =
						!!record->num_frags;
				break;
			}

			done = true;
		}

		if (done || record->len >= max_open_record_len ||
		    (record->num_frags >= MAX_SKB_FRAGS - 1)) {
			rc = klpr_tls_push_record(sk,
					     tls_ctx,
					     ctx,
					     record,
					     pfrag,
					     tls_push_record_flags,
					     record_type);
			if (rc < 0)
				break;
		}
	} while (!done);

	if (orig_size - size > 0)
		rc = orig_size - size;

	return rc;
}


#include "livepatch_bsc1227656.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "tls"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "destroy_record", (void *)&klpe_destroy_record, "tls" },
	{ "tls_append_frag", (void *)&klpe_tls_append_frag, "tls" },
	{ "tls_push_partial_record", (void *)&klpe_tls_push_partial_record,
	  "tls" },
	{ "tls_push_sg", (void *)&klpe_tls_push_sg, "tls" },
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

int bsc1227656_net_tls_tls_device_init(void)
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

void bsc1227656_net_tls_tls_device_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
