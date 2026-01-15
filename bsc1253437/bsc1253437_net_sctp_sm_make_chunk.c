/*
 * bsc1253437_net_sctp_sm_make_chunk
 *
 * Fix for CVE-2025-40204, bsc#1253437
 *
 *  Copyright (c) 2026 SUSE
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



#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/sctp/sm_make_chunk.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/random.h>	/* for get_random_bytes */
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/sctp/structs.h */
static void  *(*klpe_sctp_addto_chunk)(struct sctp_chunk *, int len, const void *data);

static const union sctp_addr *(*klpe_sctp_source)(const struct sctp_chunk *chunk);

static int (*klpe_sctp_add_bind_addr)(struct sctp_bind_addr *, union sctp_addr *,
		       int new_size, __u8 addr_state, gfp_t gfp);

static sctp_scope_t (*klpe_sctp_scope)(const union sctp_addr *);

static struct sctp_association *
(*klpe_sctp_association_new)(const struct sctp_endpoint *, const struct sock *,
		     sctp_scope_t scope, gfp_t gfp);
static void (*klpe_sctp_association_free)(struct sctp_association *);

static int (*klpe_sctp_assoc_set_bind_addr_from_cookie)(struct sctp_association *,
					 struct sctp_cookie*,
					 gfp_t gfp);

/* klp-ccp: from net/sctp/sm_make_chunk.c */
#include <net/sctp/sm.h>

/* klp-ccp: not from file */
#undef __sctp_sm_h__
/* klp-ccp: from include/net/sctp/sm.h */
#ifndef __sctp_sm_h__

static void (*klpe_sctp_init_cause)(struct sctp_chunk *, __be16 cause, size_t);

struct sctp_association *klpp_sctp_unpack_cookie(const struct sctp_endpoint *,
				       const struct sctp_association *,
				       struct sctp_chunk *,
				       gfp_t gfp, int *err,
				       struct sctp_chunk **err_chk_p);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __sctp_sm_h__ */

/* klp-ccp: from net/sctp/sm_make_chunk.c */
static struct sctp_chunk *(*klpe_sctp_make_op_error_space)(
	const struct sctp_association *asoc,
	const struct sctp_chunk *chunk,
	size_t size);
struct sctp_association *klpp_sctp_unpack_cookie(
	const struct sctp_endpoint *ep,
	const struct sctp_association *asoc,
	struct sctp_chunk *chunk, gfp_t gfp,
	int *error, struct sctp_chunk **errp)
{
	struct sctp_association *retval = NULL;
	struct sctp_signed_cookie *cookie;
	struct sctp_cookie *bear_cookie;
	int headersize, bodysize, fixed_size;
	__u8 *digest = ep->digest;
	unsigned int len;
	sctp_scope_t scope;
	struct sk_buff *skb = chunk->skb;
	ktime_t kt;

	/* Header size is static data prior to the actual cookie, including
	 * any padding.
	 */
	headersize = sizeof(sctp_chunkhdr_t) +
		     (sizeof(struct sctp_signed_cookie) -
		      sizeof(struct sctp_cookie));
	bodysize = ntohs(chunk->chunk_hdr->length) - headersize;
	fixed_size = headersize + sizeof(struct sctp_cookie);

	/* Verify that the chunk looks like it even has a cookie.
	 * There must be enough room for our cookie and our peer's
	 * INIT chunk.
	 */
	len = ntohs(chunk->chunk_hdr->length);
	if (len < fixed_size + sizeof(struct sctp_chunkhdr))
		goto malformed;

	/* Verify that the cookie has been padded out. */
	if (bodysize % SCTP_COOKIE_MULTIPLE)
		goto malformed;

	/* Process the cookie.  */
	cookie = chunk->subh.cookie_hdr;
	bear_cookie = &cookie->c;

	if (!sctp_sk(ep->base.sk)->hmac)
		goto no_hmac;

	/* Check the signature.  */
	{
		SHASH_DESC_ON_STACK(desc, sctp_sk(ep->base.sk)->hmac);
		int err;

		desc->tfm = sctp_sk(ep->base.sk)->hmac;
		desc->flags = 0;

		err = crypto_shash_setkey(desc->tfm, ep->secret_key,
					  sizeof(ep->secret_key)) ?:
		      crypto_shash_digest(desc, (u8 *)bear_cookie, bodysize,
					  digest);
		shash_desc_zero(desc);

		if (err) {
			*error = -SCTP_IERROR_NOMEM;
			goto fail;
		}
	}

	if (crypto_memneq(digest, cookie->signature, SCTP_SIGNATURE_SIZE)) {
		*error = -SCTP_IERROR_BAD_SIG;
		goto fail;
	}

no_hmac:
	/* IG Section 2.35.2:
	 *  3) Compare the port numbers and the verification tag contained
	 *     within the COOKIE ECHO chunk to the actual port numbers and the
	 *     verification tag within the SCTP common header of the received
	 *     packet. If these values do not match the packet MUST be silently
	 *     discarded,
	 */
	if (ntohl(chunk->sctp_hdr->vtag) != bear_cookie->my_vtag) {
		*error = -SCTP_IERROR_BAD_TAG;
		goto fail;
	}

	if (chunk->sctp_hdr->source != bear_cookie->peer_addr.v4.sin_port ||
	    ntohs(chunk->sctp_hdr->dest) != bear_cookie->my_port) {
		*error = -SCTP_IERROR_BAD_PORTS;
		goto fail;
	}

	/* Check to see if the cookie is stale.  If there is already
	 * an association, there is no need to check cookie's expiration
	 * for init collision case of lost COOKIE ACK.
	 * If skb has been timestamped, then use the stamp, otherwise
	 * use current time.  This introduces a small possibility that
	 * that a cookie may be considered expired, but his would only slow
	 * down the new association establishment instead of every packet.
	 */
	if (sock_flag(ep->base.sk, SOCK_TIMESTAMP))
		kt = skb_get_ktime(skb);
	else
		kt = ktime_get_real();

	if (!asoc && ktime_before(bear_cookie->expiration, kt)) {
		/*
		 * Section 3.3.10.3 Stale Cookie Error (3)
		 *
		 * Cause of error
		 * ---------------
		 * Stale Cookie Error:  Indicates the receipt of a valid State
		 * Cookie that has expired.
		 */
		len = ntohs(chunk->chunk_hdr->length);
		*errp = (*klpe_sctp_make_op_error_space)(asoc, chunk, len);
		if (*errp) {
			suseconds_t usecs = ktime_to_us(ktime_sub(kt, bear_cookie->expiration));
			__be32 n = htonl(usecs);

			(*klpe_sctp_init_cause)(*errp, SCTP_ERROR_STALE_COOKIE,
					sizeof(n));
			(*klpe_sctp_addto_chunk)(*errp, sizeof(n), &n);
			*error = -SCTP_IERROR_STALE_COOKIE;
		} else
			*error = -SCTP_IERROR_NOMEM;

		goto fail;
	}

	/* Make a new base association.  */
	scope = (*klpe_sctp_scope)((*klpe_sctp_source)(chunk));
	retval = (*klpe_sctp_association_new)(ep, ep->base.sk, scope, gfp);
	if (!retval) {
		*error = -SCTP_IERROR_NOMEM;
		goto fail;
	}

	/* Set up our peer's port number.  */
	retval->peer.port = ntohs(chunk->sctp_hdr->source);

	/* Populate the association from the cookie.  */
	memcpy(&retval->c, bear_cookie, sizeof(*bear_cookie));

	if ((*klpe_sctp_assoc_set_bind_addr_from_cookie)(retval, bear_cookie,
						 GFP_ATOMIC) < 0) {
		*error = -SCTP_IERROR_NOMEM;
		goto fail;
	}

	/* Also, add the destination address. */
	if (list_empty(&retval->base.bind_addr.address_list)) {
		(*klpe_sctp_add_bind_addr)(&retval->base.bind_addr, &chunk->dest,
				   sizeof(chunk->dest), SCTP_ADDR_SRC,
				   GFP_ATOMIC);
	}

	retval->next_tsn = retval->c.initial_tsn;
	retval->ctsn_ack_point = retval->next_tsn - 1;
	retval->addip_serial = retval->c.initial_tsn;
	retval->strreset_outseq = retval->c.initial_tsn;
	retval->adv_peer_ack_point = retval->ctsn_ack_point;
	retval->peer.prsctp_capable = retval->c.prsctp_capable;
	retval->peer.adaptation_ind = retval->c.adaptation_ind;

	/* The INIT stuff will be done by the side effects.  */
	return retval;

fail:
	if (retval)
		(*klpe_sctp_association_free)(retval);

	return NULL;

malformed:
	/* Yikes!  The packet is either corrupt or deliberately
	 * malformed.
	 */
	*error = -SCTP_IERROR_MALFORMED;
	goto fail;
}


#include "livepatch_bsc1253437.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_add_bind_addr", (void *)&klpe_sctp_add_bind_addr, "sctp" },
	{ "sctp_addto_chunk", (void *)&klpe_sctp_addto_chunk, "sctp" },
	{ "sctp_assoc_set_bind_addr_from_cookie",
	  (void *)&klpe_sctp_assoc_set_bind_addr_from_cookie, "sctp" },
	{ "sctp_association_free", (void *)&klpe_sctp_association_free,
	  "sctp" },
	{ "sctp_association_new", (void *)&klpe_sctp_association_new, "sctp" },
	{ "sctp_init_cause", (void *)&klpe_sctp_init_cause, "sctp" },
	{ "sctp_make_op_error_space", (void *)&klpe_sctp_make_op_error_space,
	  "sctp" },
	{ "sctp_scope", (void *)&klpe_sctp_scope, "sctp" },
	{ "sctp_source", (void *)&klpe_sctp_source, "sctp" },
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

int bsc1253437_net_sctp_sm_make_chunk_init(void)
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

void bsc1253437_net_sctp_sm_make_chunk_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
