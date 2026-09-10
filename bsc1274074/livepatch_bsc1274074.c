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

/* klp-ccp: from net/sctp/sm_make_chunk.c */
static struct sctp_chunk *sctp_make_control(const struct sctp_association *asoc,
					    __u8 type, __u8 flags, int paylen,
					    gfp_t gfp);

extern struct sctp_chunk *_sctp_make_chunk(const struct sctp_association *asoc,
					   __u8 type, __u8 flags, int paylen,
					   gfp_t gfp);

extern void sctp_control_set_owner_w(struct sctp_chunk *chunk);

const union sctp_addr *sctp_source(const struct sctp_chunk *chunk);

struct sctp_chunk *_sctp_make_chunk(const struct sctp_association *asoc,
					   __u8 type, __u8 flags, int paylen,
					   gfp_t gfp);

static struct sctp_chunk *sctp_make_control(const struct sctp_association *asoc,
					    __u8 type, __u8 flags, int paylen,
					    gfp_t gfp)
{
	struct sctp_chunk *chunk;

	chunk = _sctp_make_chunk(asoc, type, flags, paylen, gfp);
	if (chunk)
		sctp_control_set_owner_w(chunk);

	return chunk;
}

void sctp_chunk_hold(struct sctp_chunk *ch);

void *sctp_addto_chunk(struct sctp_chunk *chunk, int len, const void *data);

static struct sctp_chunk *sctp_make_asconf_ack(const struct sctp_association *asoc,
					       __u32 serial, int vparam_len)
{
	struct sctp_addiphdr asconf;
	struct sctp_chunk *retval;
	int length = sizeof(asconf) + vparam_len;

	/* Create the chunk.  */
	retval = sctp_make_control(asoc, SCTP_CID_ASCONF_ACK, 0, length,
				   GFP_ATOMIC);
	if (!retval)
		return NULL;

	asconf.serial = htonl(serial);

	retval->subh.addip_hdr =
		sctp_addto_chunk(retval, sizeof(asconf), &asconf);

	return retval;
}

static void sctp_add_asconf_response(struct sctp_chunk *chunk, __be32 crr_id,
				     __be16 err_code,
				     struct sctp_addip_param *asconf_param)
{
	struct sctp_addip_param ack_param;
	struct sctp_errhdr err_param;
	int asconf_param_len = 0;
	int err_param_len = 0;
	__be16 response_type;

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
	sctp_addto_chunk(chunk, sizeof(ack_param), &ack_param);

	if (SCTP_ERROR_NO_ERROR == err_code)
		return;

	/* Add Error Cause parameter. */
	err_param.cause = err_code;
	err_param.length = htons(err_param_len + asconf_param_len);
	sctp_addto_chunk(chunk, err_param_len, &err_param);

	/* Add the failed TLV copied from ASCONF chunk. */
	if (asconf_param)
		sctp_addto_chunk(chunk, asconf_param_len, asconf_param);
}

static __be16 klpp_sctp_process_asconf_param(struct sctp_association *asoc,
					struct sctp_chunk *asconf,
					struct sctp_addip_param *asconf_param)
{
	union sctp_addr_param *addr_param;
	struct sctp_transport *peer;
	union sctp_addr	addr;
	struct sctp_af *af;

	if (asconf_param->param_hdr.type != SCTP_PARAM_ADD_IP &&
	    asconf_param->param_hdr.type != SCTP_PARAM_DEL_IP &&
	    asconf_param->param_hdr.type != SCTP_PARAM_SET_PRIMARY)
		return SCTP_ERROR_UNKNOWN_PARAM;

	addr_param = (void *)asconf_param + sizeof(*asconf_param);
	if (ntohs(addr_param->p.length) >
	    ntohs(asconf_param->param_hdr.length) - sizeof(*asconf_param))
		return SCTP_ERROR_PROTO_VIOLATION;

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

	af = sctp_get_af_specific(param_type2af(addr_param->p.type));
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

		if (security_sctp_bind_connect(asoc->ep->base.sk,
					       SCTP_PARAM_ADD_IP,
					       (struct sockaddr *)&addr,
					       af->sockaddr_len))
			return SCTP_ERROR_REQ_REFUSED;

		/* ADDIP 4.3 D9) If an endpoint receives an ADD IP address
		 * request and does not have the local resources to add this
		 * new address to the association, it MUST return an Error
		 * Cause TLV set to the new error code 'Operation Refused
		 * Due to Resource Shortage'.
		 */

		peer = sctp_assoc_add_peer(asoc, &addr, GFP_ATOMIC, SCTP_UNCONFIRMED);
		if (!peer)
			return SCTP_ERROR_RSRC_LOW;

		/* Start the heartbeat timer. */
		sctp_transport_reset_hb_timer(peer);
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
		if (sctp_cmp_addr_exact(&asconf->source, &addr))
			return SCTP_ERROR_DEL_SRC_IP;

		/* Section 4.2.2
		 * If the address 0.0.0.0 or ::0 is provided, all
		 * addresses of the peer except	the source address of the
		 * packet MUST be deleted.
		 */
		if (af->is_any(&addr)) {
			sctp_assoc_set_primary(asoc, asconf->transport);
			sctp_assoc_del_nonprimary_peers(asoc,
							asconf->transport);
			return SCTP_ERROR_NO_ERROR;
		}

		/* If the address is not part of the association, the
		 * ASCONF-ACK with Error Cause Indication Parameter
		 * which including cause of Unresolvable Address should
		 * be sent.
		 */
		peer = sctp_assoc_lookup_paddr(asoc, &addr);
		if (!peer)
			return SCTP_ERROR_DNS_FAILED;

		/* Don't free asconf->transport; a later wildcard DEL-IP
		 * parameter reuses it.
		 */
		if (peer == asconf->transport)
			return SCTP_ERROR_REQ_REFUSED;

		sctp_assoc_rm_peer(asoc, peer);
		break;
	case SCTP_PARAM_SET_PRIMARY:
		/* ADDIP Section 4.2.4
		 * If the address 0.0.0.0 or ::0 is provided, the receiver
		 * MAY mark the source address of the packet as its
		 * primary.
		 */
		if (af->is_any(&addr))
			memcpy(&addr, sctp_source(asconf), sizeof(addr));

		if (security_sctp_bind_connect(asoc->ep->base.sk,
					       SCTP_PARAM_SET_PRIMARY,
					       (struct sockaddr *)&addr,
					       af->sockaddr_len))
			return SCTP_ERROR_REQ_REFUSED;

		peer = sctp_assoc_lookup_paddr(asoc, &addr);
		if (!peer)
			return SCTP_ERROR_DNS_FAILED;

		sctp_assoc_set_primary(asoc, peer);
		break;
	}

	return SCTP_ERROR_NO_ERROR;
}

struct sctp_chunk *klpp_sctp_process_asconf(struct sctp_association *asoc,
				       struct sctp_chunk *asconf)
{
	union sctp_addr_param *addr_param;
	struct sctp_addip_chunk *addip;
	struct sctp_chunk *asconf_ack;
	bool all_param_pass = true;
	struct sctp_addiphdr *hdr;
	int length = 0, chunk_len;
	union sctp_params param;
	__be16 err_code;
	__u32 serial;

	addip = (struct sctp_addip_chunk *)asconf->chunk_hdr;
	chunk_len = ntohs(asconf->chunk_hdr->length) -
		    sizeof(struct sctp_chunkhdr);
	hdr = (struct sctp_addiphdr *)asconf->skb->data;
	serial = ntohl(hdr->serial);

	/* Skip the addiphdr and store a pointer to address parameter.  */
	length = sizeof(*hdr);
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
	asconf_ack = sctp_make_asconf_ack(asoc, serial, chunk_len * 4);
	if (!asconf_ack)
		goto done;

	/* Process the TLVs contained within the ASCONF chunk. */
	sctp_walk_params(param, addip) {
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
			sctp_add_asconf_response(asconf_ack, param.addip->crr_id,
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
		sctp_chunk_hold(asconf_ack);
		list_add_tail(&asconf_ack->transmitted_list,
			      &asoc->asconf_ack_list);
	}

	return asconf_ack;
}


#include <linux/livepatch.h>

extern typeof(_sctp_make_chunk) _sctp_make_chunk
	 KLP_RELOC_SYMBOL(sctp, sctp, _sctp_make_chunk);
extern typeof(sctp_addto_chunk) sctp_addto_chunk
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_addto_chunk);
extern typeof(sctp_assoc_add_peer) sctp_assoc_add_peer
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_add_peer);
extern typeof(sctp_assoc_del_nonprimary_peers) sctp_assoc_del_nonprimary_peers
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_del_nonprimary_peers);
extern typeof(sctp_assoc_lookup_paddr) sctp_assoc_lookup_paddr
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_lookup_paddr);
extern typeof(sctp_assoc_rm_peer) sctp_assoc_rm_peer
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_rm_peer);
extern typeof(sctp_assoc_set_primary) sctp_assoc_set_primary
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_assoc_set_primary);
extern typeof(sctp_chunk_hold) sctp_chunk_hold
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_chunk_hold);
extern typeof(sctp_cmp_addr_exact) sctp_cmp_addr_exact
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_cmp_addr_exact);
extern typeof(sctp_control_set_owner_w) sctp_control_set_owner_w
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_control_set_owner_w);
extern typeof(sctp_get_af_specific) sctp_get_af_specific
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_get_af_specific);
extern typeof(sctp_source) sctp_source KLP_RELOC_SYMBOL(sctp, sctp, sctp_source);
extern typeof(sctp_transport_reset_hb_timer) sctp_transport_reset_hb_timer
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_transport_reset_hb_timer);
