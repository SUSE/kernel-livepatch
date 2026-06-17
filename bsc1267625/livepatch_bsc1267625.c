/*
 * livepatch_bsc1267625
 *
 * Fix for bsc#1267625
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


#include "livepatch_bsc1267625.h"


/* klp-ccp: from net/sched/act_pedit.c */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <linux/tc_act/tc_pedit.h>
#include <net/tc_act/tc_pedit.h>
#include <uapi/linux/tc_act/tc_pedit.h>
#include <net/pkt_cls.h>
#include <net/tc_wrapper.h>

/* klp-ccp: from net/sched/act_pedit.c */
static bool offset_valid(struct sk_buff *skb, int offset)
{
	if (offset > 0 && offset > skb->len)
		return false;

	if  (offset < 0 && -offset > skb_headroom(skb))
		return false;

	return true;
}

extern int pedit_l4_skb_offset(struct sk_buff *skb, int *hoffset, const int header_type);

static int pedit_skb_hdr_offset(struct sk_buff *skb,
				 enum pedit_header_type htype, int *hoffset)
{
	int ret = -EINVAL;
	/* 'htype' is validated in the netlink parsing */
	switch (htype) {
	case TCA_PEDIT_KEY_EX_HDR_TYPE_ETH:
		if (skb_mac_header_was_set(skb)) {
			*hoffset = skb_mac_offset(skb);
			ret = 0;
		}
		break;
	case TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK:
	case TCA_PEDIT_KEY_EX_HDR_TYPE_IP4:
	case TCA_PEDIT_KEY_EX_HDR_TYPE_IP6:
		*hoffset = skb_network_offset(skb);
		ret = 0;
		break;
	case TCA_PEDIT_KEY_EX_HDR_TYPE_TCP:
		ret = pedit_l4_skb_offset(skb, hoffset, IPPROTO_TCP);
		break;
	case TCA_PEDIT_KEY_EX_HDR_TYPE_UDP:
		ret = pedit_l4_skb_offset(skb, hoffset, IPPROTO_UDP);
		break;
	default:
		break;
	}
	return ret;
}

int klpp_tcf_pedit_act(struct sk_buff *skb,
				    const struct tc_action *a,
				    struct tcf_result *res)
{
	enum pedit_header_type htype = TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
	enum pedit_cmd cmd = TCA_PEDIT_KEY_EX_CMD_SET;
	struct tcf_pedit *p = to_pedit(a);
	struct tcf_pedit_key_ex *tkey_ex;
	struct tcf_pedit_parms *parms;
	struct tc_pedit_key *tkey;
	u32 max_offset;
	int i;

	parms = rcu_dereference_bh(p->parms);

	/* Linearize so we are sure pedit is operating on a private copy */
	if (skb_has_shared_frag(skb)) {
		if (__skb_linearize(skb))
			goto bad;
	}

	max_offset = (skb_transport_header_was_set(skb) ?
		      skb_transport_offset(skb) :
		      skb_network_offset(skb)) +
		     parms->tcfp_off_max_hint;
	if (skb_ensure_writable(skb, min(skb->len, max_offset)))
		goto done;

	tcf_lastuse_update(&p->tcf_tm);
	tcf_action_update_bstats(&p->common, skb);

	tkey = parms->tcfp_keys;
	tkey_ex = parms->tcfp_keys_ex;

	for (i = parms->tcfp_nkeys; i > 0; i--, tkey++) {
		int offset = tkey->off;
		int hoffset = 0;
		u32 *ptr, hdata;
		u32 val;
		int rc;

		if (tkey_ex) {
			htype = tkey_ex->htype;
			cmd = tkey_ex->cmd;

			tkey_ex++;
		}

		rc = pedit_skb_hdr_offset(skb, htype, &hoffset);
		if (rc) {
			pr_info_ratelimited("tc action pedit unable to extract header offset for header type (0x%x)\n", htype);
			goto bad;
		}

		if (tkey->offmask) {
			u8 *d, _d;

			if (!offset_valid(skb, hoffset + tkey->at)) {
				pr_info_ratelimited("tc action pedit 'at' offset %d out of bounds\n",
						    hoffset + tkey->at);
				goto bad;
			}
			d = skb_header_pointer(skb, hoffset + tkey->at,
					       sizeof(_d), &_d);
			if (!d)
				goto bad;

			offset += (*d & tkey->offmask) >> tkey->shift;
			if (offset % 4) {
				pr_info_ratelimited("tc action pedit offset must be on 32 bit boundaries\n");
				goto bad;
			}
		}

		if (!offset_valid(skb, hoffset + offset)) {
			pr_info_ratelimited("tc action pedit offset %d out of bounds\n", hoffset + offset);
			goto bad;
		}

		ptr = skb_header_pointer(skb, hoffset + offset,
					 sizeof(hdata), &hdata);
		if (!ptr)
			goto bad;
		/* just do it, baby */
		switch (cmd) {
		case TCA_PEDIT_KEY_EX_CMD_SET:
			val = tkey->val;
			break;
		case TCA_PEDIT_KEY_EX_CMD_ADD:
			val = (*ptr + tkey->val) & ~tkey->mask;
			break;
		default:
			pr_info_ratelimited("tc action pedit bad command (%d)\n", cmd);
			goto bad;
		}

		*ptr = ((*ptr & tkey->mask) ^ val);
		if (ptr == &hdata)
			skb_store_bits(skb, hoffset + offset, ptr, 4);
	}

	goto done;

bad:
	tcf_action_inc_overlimit_qstats(&p->common);
done:
	return p->tcf_action;
}


#include <linux/livepatch.h>

extern typeof(pedit_l4_skb_offset) pedit_l4_skb_offset
	 KLP_RELOC_SYMBOL(act_pedit, act_pedit, pedit_l4_skb_offset);
