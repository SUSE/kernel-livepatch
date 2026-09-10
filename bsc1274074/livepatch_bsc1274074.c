/*
 * livepatch_bsc1274074
 *
 * Fix for CVE-2026-64564, bsc#1274074
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


#include "livepatch_bsc1274074.h"


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
static struct sctp_af *(*klpe_sctp_get_af_specific)(sa_family_t);

static void (*klpe_sctp_chunk_hold)(struct sctp_chunk *);

static void  *(*klpe_sctp_addto_chunk)(struct sctp_chunk *, int len, const void *data);

static const union sctp_addr *(*klpe_sctp_source)(const struct sctp_chunk *chunk);

static void (*klpe_sctp_transport_reset_hb_timer)(struct sctp_transport *);

static struct sctp_transport *(*klpe_sctp_assoc_lookup_paddr)(const struct sctp_association *,
					  const union sctp_addr *);

static struct sctp_transport *(*klpe_sctp_assoc_add_peer)(struct sctp_association *,
				     const union sctp_addr *address,
				     const gfp_t gfp,
				     const int peer_state);

static void (*klpe_sctp_assoc_rm_peer)(struct sctp_association *asoc,
			 struct sctp_transport *peer);

static void (*klpe_sctp_assoc_set_primary)(struct sctp_association *,
			    struct sctp_transport *);
static void (*klpe_sctp_assoc_del_nonprimary_peers)(struct sctp_association *,
				    struct sctp_transport *);

static int (*klpe_sctp_cmp_addr_exact)(const union sctp_addr *ss1,
			const union sctp_addr *ss2);

/* klp-ccp: from net/sctp/sm_make_chunk.c */
#include <net/sctp/sm.h>

/* klp-ccp: from net/sctp/sm_make_chunk.c */
static struct sctp_chunk *(*klpe_sctp_make_control)(const struct sctp_association *asoc,
					    __u8 type, __u8 flags, int paylen,
					    gfp_t gfp);
static struct sctp_chunk *(*klpe_sctp_make_control)(const struct sctp_association *asoc,
					    __u8 type, __u8 flags, int paylen,
					    gfp_t gfp);
static struct sctp_chunk *klpr_sctp_make_asconf_ack(const struct sctp_association *asoc,
					       __u32 serial, int vparam_len)
{
	sctp_addiphdr_t		asconf;
	struct sctp_chunk	*retval;
	int			length = sizeof(asconf) + vparam_len;

	/* Create the chunk.  */
	retval = (*klpe_sctp_make_control)(asoc, SCTP_CID_ASCONF_ACK, 0, length,
				   GFP_ATOMIC);
	if (!retval)
		return NULL;

	asconf.serial = htonl(serial);

	retval->subh.addip_hdr =
		(*klpe_sctp_addto_chunk)(retval, sizeof(asconf), &asconf);

	return retval;
}

static void klpr_sctp_add_asconf_response(struct sctp_chunk *chunk, __be32 crr_id,
			      __be16 err_code, sctp_addip_param_t *asconf_param)
{
	sctp_addip_param_t 	ack_param;
	sctp_errhdr_t		err_param;
	int			asconf_param_len = 0;
	int			err_param_len = 0;
	__be16			response_type;

	if (SCTP_ERROR_NO_ERROR == err_code) {
		response_type = SCTP_PARAM_SUCCESS_REPORT;
	} else {
		response_type = SCTP_PARAM_ERR_CAUSE;
		err_param_len = sizeof(err_param);
		if (asconf_param)
			asconf_param_len =
				 ntohs(asconf_param->param_hdr.length);
	}

	/* Add Success Indication or Error Cause Indication parameter. */
	ack_param.param_hdr.type = response_type;
	ack_param.param_hdr.length = htons(sizeof(ack_param) +
					   err_param_len +
					   asconf_param_len);
	ack_param.crr_id = crr_id;
	(*klpe_sctp_addto_chunk)(chunk, sizeof(ack_param), &ack_param);

	if (SCTP_ERROR_NO_ERROR == err_code)
		return;

	/* Add Error Cause parameter. */
	err_param.cause = err_code;
	err_param.length = htons(err_param_len + asconf_param_len);
	(*klpe_sctp_addto_chunk)(chunk, err_param_len, &err_param);

	/* Add the failed TLV copied from ASCONF chunk. */
	if (asconf_param)
		(*klpe_sctp_addto_chunk)(chunk, asconf_param_len, asconf_param);
}

static __be16 klpp_sctp_process_asconf_param(struct sctp_association *asoc,
				       struct sctp_chunk *asconf,
				       sctp_addip_param_t *asconf_param)
{
	struct sctp_transport *peer;
	struct sctp_af *af;
	union sctp_addr	addr;
	union sctp_addr_param *addr_param;

	addr_param = (void *)asconf_param + sizeof(sctp_addip_param_t);

	if (asconf_param->param_hdr.type != SCTP_PARAM_ADD_IP &&
	    asconf_param->param_hdr.type != SCTP_PARAM_DEL_IP &&
	    asconf_param->param_hdr.type != SCTP_PARAM_SET_PRIMARY)
		return SCTP_ERROR_UNKNOWN_PARAM;

	switch (addr_param->p.type) {
	case SCTP_PARAM_IPV6_ADDRESS:
		if (!asoc->peer.ipv6_address)
			return SCTP_ERROR_DNS_FAILED;
		break;
	case SCTP_PARAM_IPV4_ADDRESS:
		if (!asoc->peer.ipv4_address)
			return SCTP_ERROR_DNS_FAILED;
		break;
	default:
		return SCTP_ERROR_DNS_FAILED;
	}

	af = (*klpe_sctp_get_af_specific)(param_type2af(addr_param->p.type));
	if (unlikely(!af))
		return SCTP_ERROR_DNS_FAILED;

	if (!af->from_addr_param(&addr, addr_param, htons(asoc->peer.port), 0))
		return SCTP_ERROR_DNS_FAILED;

	/* ADDIP 4.2.1  This parameter MUST NOT contain a broadcast
	 * or multicast address.
	 * (note: wildcard is permitted and requires special handling so
	 *  make sure we check for that)
	 */
	if (!af->is_any(&addr) && !af->addr_valid(&addr, NULL, asconf->skb))
		return SCTP_ERROR_DNS_FAILED;

	switch (asconf_param->param_hdr.type) {
	case SCTP_PARAM_ADD_IP:
		/* Section 4.2.1:
		 * If the address 0.0.0.0 or ::0 is provided, the source
		 * address of the packet MUST be added.
		 */
		if (af->is_any(&addr))
			memcpy(&addr, &asconf->source, sizeof(addr));

		/* ADDIP 4.3 D9) If an endpoint receives an ADD IP address
		 * request and does not have the local resources to add this
		 * new address to the association, it MUST return an Error
		 * Cause TLV set to the new error code 'Operation Refused
		 * Due to Resource Shortage'.
		 */

		peer = (*klpe_sctp_assoc_add_peer)(asoc, &addr, GFP_ATOMIC, SCTP_UNCONFIRMED);
		if (!peer)
			return SCTP_ERROR_RSRC_LOW;

		/* Start the heartbeat timer. */
		(*klpe_sctp_transport_reset_hb_timer)(peer);
		asoc->new_transport = peer;
		break;
	case SCTP_PARAM_DEL_IP:
		/* ADDIP 4.3 D7) If a request is received to delete the
		 * last remaining IP address of a peer endpoint, the receiver
		 * MUST send an Error Cause TLV with the error cause set to the
		 * new error code 'Request to Delete Last Remaining IP Address'.
		 */
		if (asoc->peer.transport_count == 1)
			return SCTP_ERROR_DEL_LAST_IP;

		/* ADDIP 4.3 D8) If a request is received to delete an IP
		 * address which is also the source address of the IP packet
		 * which contained the ASCONF chunk, the receiver MUST reject
		 * this request. To reject the request the receiver MUST send
		 * an Error Cause TLV set to the new error code 'Request to
		 * Delete Source IP Address'
		 */
		if ((*klpe_sctp_cmp_addr_exact)(&asconf->source, &addr))
			return SCTP_ERROR_DEL_SRC_IP;

		/* Section 4.2.2
		 * If the address 0.0.0.0 or ::0 is provided, all
		 * addresses of the peer except	the source address of the
		 * packet MUST be deleted.
		 */
		if (af->is_any(&addr)) {
			(*klpe_sctp_assoc_set_primary)(asoc, asconf->transport);
			(*klpe_sctp_assoc_del_nonprimary_peers)(asoc,
							asconf->transport);
			return SCTP_ERROR_NO_ERROR;
		}

		/* If the address is not part of the association, the
		 * ASCONF-ACK with Error Cause Indication Parameter
		 * which including cause of Unresolvable Address should
		 * be sent.
		 */
		peer = (*klpe_sctp_assoc_lookup_paddr)(asoc, &addr);
		if (!peer)
			return SCTP_ERROR_DNS_FAILED;

		/* Don't free asconf->transport; a later wildcard DEL-IP
		 * parameter reuses it.
		 */
		if (peer == asconf->transport)
			return SCTP_ERROR_REQ_REFUSED;

		(*klpe_sctp_assoc_rm_peer)(asoc, peer);
		break;
	case SCTP_PARAM_SET_PRIMARY:
		/* ADDIP Section 4.2.4
		 * If the address 0.0.0.0 or ::0 is provided, the receiver
		 * MAY mark the source address of the packet as its
		 * primary.
		 */
		if (af->is_any(&addr))
			memcpy(&addr.v4, (*klpe_sctp_source)(asconf), sizeof(addr));

		peer = (*klpe_sctp_assoc_lookup_paddr)(asoc, &addr);
		if (!peer)
			return SCTP_ERROR_DNS_FAILED;

		(*klpe_sctp_assoc_set_primary)(asoc, peer);
		break;
	}

	return SCTP_ERROR_NO_ERROR;
}

struct sctp_chunk *klpp_sctp_process_asconf(struct sctp_association *asoc,
				       struct sctp_chunk *asconf)
{
	sctp_addip_chunk_t *addip = (sctp_addip_chunk_t *) asconf->chunk_hdr;
	bool all_param_pass = true;
	union sctp_params param;
	sctp_addiphdr_t		*hdr;
	union sctp_addr_param	*addr_param;
	struct sctp_chunk	*asconf_ack;
	__be16	err_code;
	int	length = 0;
	int	chunk_len;
	__u32	serial;

	chunk_len = ntohs(asconf->chunk_hdr->length) - sizeof(sctp_chunkhdr_t);
	hdr = (sctp_addiphdr_t *)asconf->skb->data;
	serial = ntohl(hdr->serial);

	/* Skip the addiphdr and store a pointer to address parameter.  */
	length = sizeof(sctp_addiphdr_t);
	addr_param = (union sctp_addr_param *)(asconf->skb->data + length);
	chunk_len -= length;

	/* Skip the address parameter and store a pointer to the first
	 * asconf parameter.
	 */
	length = ntohs(addr_param->p.length);
	chunk_len -= length;

	/* create an ASCONF_ACK chunk.
	 * Based on the definitions of parameters, we know that the size of
	 * ASCONF_ACK parameters are less than or equal to the fourfold of ASCONF
	 * parameters.
	 */
	asconf_ack = klpr_sctp_make_asconf_ack(asoc, serial, chunk_len * 4);
	if (!asconf_ack)
		goto done;

	/* Process the TLVs contained within the ASCONF chunk. */
	sctp_walk_params(param, addip, addip_hdr.params) {
		/* Skip preceeding address parameters. */
		if (param.p->type == SCTP_PARAM_IPV4_ADDRESS ||
		    param.p->type == SCTP_PARAM_IPV6_ADDRESS)
			continue;

		err_code = klpp_sctp_process_asconf_param(asoc, asconf,
						     param.addip);
		/* ADDIP 4.1 A7)
		 * If an error response is received for a TLV parameter,
		 * all TLVs with no response before the failed TLV are
		 * considered successful if not reported.  All TLVs after
		 * the failed response are considered unsuccessful unless
		 * a specific success indication is present for the parameter.
		 */
		if (err_code != SCTP_ERROR_NO_ERROR)
			all_param_pass = false;
		if (!all_param_pass)
			klpr_sctp_add_asconf_response(asconf_ack, param.addip->crr_id,
						 err_code, param.addip);

		/* ADDIP 4.3 D11) When an endpoint receiving an ASCONF to add
		 * an IP address sends an 'Out of Resource' in its response, it
		 * MUST also fail any subsequent add or delete requests bundled
		 * in the ASCONF.
		 */
		if (err_code == SCTP_ERROR_RSRC_LOW)
			goto done;
	}
done:
	asoc->peer.addip_serial++;

	/* If we are sending a new ASCONF_ACK hold a reference to it in assoc
	 * after freeing the reference to old asconf ack if any.
	 */
	if (asconf_ack) {
		(*klpe_sctp_chunk_hold)(asconf_ack);
		list_add_tail(&asconf_ack->transmitted_list,
			      &asoc->asconf_ack_list);
	}

	return asconf_ack;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_addto_chunk", (void *)&klpe_sctp_addto_chunk, "sctp" },
	{ "sctp_assoc_add_peer", (void *)&klpe_sctp_assoc_add_peer, "sctp" },
	{ "sctp_assoc_del_nonprimary_peers",
	  (void *)&klpe_sctp_assoc_del_nonprimary_peers, "sctp" },
	{ "sctp_assoc_lookup_paddr", (void *)&klpe_sctp_assoc_lookup_paddr,
	  "sctp" },
	{ "sctp_assoc_rm_peer", (void *)&klpe_sctp_assoc_rm_peer, "sctp" },
	{ "sctp_assoc_set_primary", (void *)&klpe_sctp_assoc_set_primary,
	  "sctp" },
	{ "sctp_chunk_hold", (void *)&klpe_sctp_chunk_hold, "sctp" },
	{ "sctp_cmp_addr_exact", (void *)&klpe_sctp_cmp_addr_exact, "sctp" },
	{ "sctp_get_af_specific", (void *)&klpe_sctp_get_af_specific, "sctp" },
	{ "sctp_make_control", (void *)&klpe_sctp_make_control, "sctp" },
	{ "sctp_source", (void *)&klpe_sctp_source, "sctp" },
	{ "sctp_transport_reset_hb_timer",
	  (void *)&klpe_sctp_transport_reset_hb_timer, "sctp" },
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

int livepatch_bsc1274074_init(void)
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

void livepatch_bsc1274074_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
