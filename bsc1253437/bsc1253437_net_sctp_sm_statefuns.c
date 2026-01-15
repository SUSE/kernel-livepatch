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



#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/sctp/sm_statefuns.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/algapi.h>
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

/* klp-ccp: from include/net/sctp/auth.h */
static struct sctp_shared_key *(*klpe_sctp_auth_get_shkey)(
				const struct sctp_association *asoc,
				__u16 key_id);

static struct sctp_hmac *(*klpe_sctp_auth_get_hmac)(__u16 hmac_id);

static int (*klpe_sctp_auth_asoc_verify_hmac_id)(const struct sctp_association *asoc,
				    __be16 hmac_id);

static void (*klpe_sctp_auth_calculate_hmac)(const struct sctp_association *asoc,
			    struct sk_buff *skb,
			    struct sctp_auth_chunk *auth, gfp_t gfp);

/* klp-ccp: from net/sctp/sm_statefuns.c */
#include <net/sctp/sm.h>
#include <net/sctp/structs.h>

sctp_ierror_t klpp_sctp_sf_authenticate(
				    const struct sctp_association *asoc,
				    struct sctp_chunk *chunk);

sctp_ierror_t klpp_sctp_sf_authenticate(
				    const struct sctp_association *asoc,
				    struct sctp_chunk *chunk)
{
	struct sctp_authhdr *auth_hdr;
	struct sctp_hmac *hmac;
	unsigned int sig_len;
	__u16 key_id;
	__u8 *save_digest;
	__u8 *digest;

	/* Pull in the auth header, so we can do some more verification */
	auth_hdr = (struct sctp_authhdr *)chunk->skb->data;
	chunk->subh.auth_hdr = auth_hdr;
	skb_pull(chunk->skb, sizeof(struct sctp_authhdr));

	/* Make sure that we support the HMAC algorithm from the auth
	 * chunk.
	 */
	if (!(*klpe_sctp_auth_asoc_verify_hmac_id)(asoc, auth_hdr->hmac_id))
		return SCTP_IERROR_AUTH_BAD_HMAC;

	/* Make sure that the provided shared key identifier has been
	 * configured
	 */
	key_id = ntohs(auth_hdr->shkey_id);
	if (key_id != asoc->active_key_id && !(*klpe_sctp_auth_get_shkey)(asoc, key_id))
		return SCTP_IERROR_AUTH_BAD_KEYID;
	/* Make sure that the length of the signature matches what
	 * we expect.
	 */
	sig_len = ntohs(chunk->chunk_hdr->length) - sizeof(sctp_auth_chunk_t);
	hmac = (*klpe_sctp_auth_get_hmac)(ntohs(auth_hdr->hmac_id));
	if (sig_len != hmac->hmac_len)
		return SCTP_IERROR_PROTO_VIOLATION;

	/* Now that we've done validation checks, we can compute and
	 * verify the hmac.  The steps involved are:
	 *  1. Save the digest from the chunk.
	 *  2. Zero out the digest in the chunk.
	 *  3. Compute the new digest
	 *  4. Compare saved and new digests.
	 */
	digest = auth_hdr->hmac;
	skb_pull(chunk->skb, sig_len);

	save_digest = kmemdup(digest, sig_len, GFP_ATOMIC);
	if (!save_digest)
		goto nomem;

	memset(digest, 0, sig_len);

	(*klpe_sctp_auth_calculate_hmac)(asoc, chunk->skb,
				(struct sctp_auth_chunk *)chunk->chunk_hdr,
				GFP_ATOMIC);

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

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_auth_asoc_verify_hmac_id",
	  (void *)&klpe_sctp_auth_asoc_verify_hmac_id, "sctp" },
	{ "sctp_auth_calculate_hmac", (void *)&klpe_sctp_auth_calculate_hmac,
	  "sctp" },
	{ "sctp_auth_get_hmac", (void *)&klpe_sctp_auth_get_hmac, "sctp" },
	{ "sctp_auth_get_shkey", (void *)&klpe_sctp_auth_get_shkey, "sctp" },
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

int bsc1253437_net_sctp_sm_statefuns_init(void)
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

void bsc1253437_net_sctp_sm_statefuns_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
