/*
 * bsc1253437_net_sctp_sm_statefuns
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

#include <crypto/utils.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/inet_ecn.h>
#include <linux/skbuff.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/structs.h>

enum sctp_ierror klpp_sctp_sf_authenticate(
					const struct sctp_association *asoc,
					struct sctp_chunk *chunk)
{
	struct sctp_shared_key *sh_key = NULL;
	struct sctp_authhdr *auth_hdr;
	__u8 *save_digest, *digest;
	struct sctp_hmac *hmac;
	unsigned int sig_len;
	__u16 key_id;

	/* Pull in the auth header, so we can do some more verification */
	auth_hdr = (struct sctp_authhdr *)chunk->skb->data;
	chunk->subh.auth_hdr = auth_hdr;
	skb_pull(chunk->skb, sizeof(*auth_hdr));

	/* Make sure that we support the HMAC algorithm from the auth
	 * chunk.
	 */
	if (!sctp_auth_asoc_verify_hmac_id(asoc, auth_hdr->hmac_id))
		return SCTP_IERROR_AUTH_BAD_HMAC;

	/* Make sure that the provided shared key identifier has been
	 * configured
	 */
	key_id = ntohs(auth_hdr->shkey_id);
	if (key_id != asoc->active_key_id) {
		sh_key = sctp_auth_get_shkey(asoc, key_id);
		if (!sh_key)
			return SCTP_IERROR_AUTH_BAD_KEYID;
	}

	/* Make sure that the length of the signature matches what
	 * we expect.
	 */
	sig_len = ntohs(chunk->chunk_hdr->length) -
		  sizeof(struct sctp_auth_chunk);
	hmac = sctp_auth_get_hmac(ntohs(auth_hdr->hmac_id));
	if (sig_len != hmac->hmac_len)
		return SCTP_IERROR_PROTO_VIOLATION;

	/* Now that we've done validation checks, we can compute and
	 * verify the hmac.  The steps involved are:
	 *  1. Save the digest from the chunk.
	 *  2. Zero out the digest in the chunk.
	 *  3. Compute the new digest
	 *  4. Compare saved and new digests.
	 */
	digest = (u8 *)(auth_hdr + 1);
	skb_pull(chunk->skb, sig_len);

	save_digest = kmemdup(digest, sig_len, GFP_ATOMIC);
	if (!save_digest)
		goto nomem;

	memset(digest, 0, sig_len);

	sctp_auth_calculate_hmac(asoc, chunk->skb,
				 (struct sctp_auth_chunk *)chunk->chunk_hdr,
				 sh_key, GFP_ATOMIC);

	/* Discard the packet if the digests do not match */
	if (crypto_memneq(save_digest, digest, sig_len)) {
		kfree(save_digest);
		return SCTP_IERROR_BAD_SIG;
	}

	kfree(save_digest);
	chunk->auth = 1;

	return SCTP_IERROR_NO_ERROR;
nomem:
	return SCTP_IERROR_NOMEM;
}


#include "livepatch_bsc1253437.h"

#include <linux/livepatch.h>

extern typeof(sctp_auth_asoc_verify_hmac_id) sctp_auth_asoc_verify_hmac_id
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_auth_asoc_verify_hmac_id);
extern typeof(sctp_auth_calculate_hmac) sctp_auth_calculate_hmac
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_auth_calculate_hmac);
extern typeof(sctp_auth_get_hmac) sctp_auth_get_hmac
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_auth_get_hmac);
extern typeof(sctp_auth_get_shkey) sctp_auth_get_shkey
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_auth_get_shkey);
