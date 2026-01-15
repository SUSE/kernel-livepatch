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



/* klp-ccp: from net/sctp/sm_make_chunk.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <crypto/utils.h>
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
#include <net/sctp/sm.h>

/* klp-ccp: not from file */
#undef __sctp_sm_h__
/* klp-ccp: from include/net/sctp/sm.h */
#ifndef __sctp_sm_h__

struct sctp_association *klpp_sctp_unpack_cookie(
					const struct sctp_endpoint *ep,
					const struct sctp_association *asoc,
					struct sctp_chunk *chunk,
					gfp_t gfp, int *err,
					struct sctp_chunk **err_chk_p);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __sctp_sm_h__ */

/* klp-ccp: from net/sctp/sm_make_chunk.c */
struct sctp_chunk *sctp_make_op_error(const struct sctp_association *asoc,
				      const struct sctp_chunk *chunk,
				      __be16 cause_code, const void *payload,
				      size_t paylen, size_t reserve_tail);

const union sctp_addr *sctp_source(const struct sctp_chunk *chunk);

struct sctp_association *klpp_sctp_unpack_cookie(
					const struct sctp_endpoint *ep,
					const struct sctp_association *asoc,
					struct sctp_chunk *chunk, gfp_t gfp,
					int *error, struct sctp_chunk **errp)
{
	struct sctp_association *retval = NULL;
	int headersize, bodysize, fixed_size;
	struct sctp_signed_cookie *cookie;
	struct sk_buff *skb = chunk->skb;
	struct sctp_cookie *bear_cookie;
	__u8 *digest = ep->digest;
	enum sctp_scope scope;
	unsigned int len;
	ktime_t kt;

	/* Header size is static data prior to the actual cookie, including
	 * any padding.
	 */
	headersize = sizeof(struct sctp_chunkhdr) +
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
		struct crypto_shash *tfm = sctp_sk(ep->base.sk)->hmac;
		int err;

		err = crypto_shash_setkey(tfm, ep->secret_key,
					  sizeof(ep->secret_key)) ?:
		      crypto_shash_tfm_digest(tfm, (u8 *)bear_cookie, bodysize,
					      digest);
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
	 * a cookie may be considered expired, but this would only slow
	 * down the new association establishment instead of every packet.
	 */
	if (sock_flag(ep->base.sk, SOCK_TIMESTAMP))
		kt = skb_get_ktime(skb);
	else
		kt = ktime_get_real();

	if (!asoc && ktime_before(bear_cookie->expiration, kt)) {
		suseconds_t usecs = ktime_to_us(ktime_sub(kt, bear_cookie->expiration));
		__be32 n = htonl(usecs);

		/*
		 * Section 3.3.10.3 Stale Cookie Error (3)
		 *
		 * Cause of error
		 * ---------------
		 * Stale Cookie Error:  Indicates the receipt of a valid State
		 * Cookie that has expired.
		 */
		*errp = sctp_make_op_error(asoc, chunk,
					   SCTP_ERROR_STALE_COOKIE, &n,
					   sizeof(n), 0);
		if (*errp)
			*error = -SCTP_IERROR_STALE_COOKIE;
		else
			*error = -SCTP_IERROR_NOMEM;

		goto fail;
	}

	/* Make a new base association.  */
	scope = sctp_scope(sctp_source(chunk));
	retval = sctp_association_new(ep, ep->base.sk, scope, gfp);
	if (!retval) {
		*error = -SCTP_IERROR_NOMEM;
		goto fail;
	}

	/* Set up our peer's port number.  */
	retval->peer.port = ntohs(chunk->sctp_hdr->source);

	/* Populate the association from the cookie.  */
	memcpy(&retval->c, bear_cookie, sizeof(*bear_cookie));

	if (sctp_assoc_set_bind_addr_from_cookie(retval, bear_cookie,
						 GFP_ATOMIC) < 0) {
		*error = -SCTP_IERROR_NOMEM;
		goto fail;
	}

	/* Also, add the destination address. */
	if (list_empty(&retval->base.bind_addr.address_list)) {
		sctp_add_bind_addr(&retval->base.bind_addr, &chunk->dest,
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
		sctp_association_free(retval);

	return NULL;

malformed:
	/* Yikes!  The packet is either corrupt or deliberately
	 * malformed.
	 */
	*error = -SCTP_IERROR_MALFORMED;
	goto fail;
}


#include "livepatch_bsc1253437.h"

#include <linux/livepatch.h>

extern typeof(sctp_add_bind_addr) sctp_add_bind_addr
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_add_bind_addr);
extern typeof(sctp_assoc_set_bind_addr_from_cookie)
	 sctp_assoc_set_bind_addr_from_cookie
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_set_bind_addr_from_cookie);
extern typeof(sctp_association_free) sctp_association_free
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_association_free);
extern typeof(sctp_association_new) sctp_association_new
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_association_new);
extern typeof(sctp_make_op_error) sctp_make_op_error
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_make_op_error);
extern typeof(sctp_scope) sctp_scope KLP_RELOC_SYMBOL(sctp, sctp, sctp_scope);
extern typeof(sctp_source) sctp_source KLP_RELOC_SYMBOL(sctp, sctp, sctp_source);
