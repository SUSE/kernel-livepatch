/*
 * livepatch_bsc1267625
 *
 * Fix for CVE-2026-46331, bsc#1267625
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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/sched/act_pedit.c */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <linux/tc_act/tc_pedit.h>
#include <net/tc_act/tc_pedit.h>
#include <uapi/linux/tc_act/tc_pedit.h>

static bool (*klpe_offset_valid)(struct sk_buff *skb, int offset);

static int pedit_skb_hdr_offset(struct sk_buff *skb,
				enum pedit_header_type htype, int *hoffset)
{
	int ret = -EINVAL;

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
	case TCA_PEDIT_KEY_EX_HDR_TYPE_UDP:
		if (skb_transport_header_was_set(skb)) {
			*hoffset = skb_transport_offset(skb);
			ret = 0;
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int klpp_tcf_pedit_act(struct sk_buff *skb, const struct tc_action *a,
			 struct tcf_result *res)
{
	struct tcf_pedit *p = to_pedit(a);
	int i;

	if (skb_unclone(skb, GFP_ATOMIC))
		return p->tcf_action;

	spin_lock(&p->tcf_lock);

	tcf_lastuse_update(&p->tcf_tm);

	if (p->tcfp_nkeys > 0) {
		struct tc_pedit_key *tkey = p->tcfp_keys;
		struct tcf_pedit_key_ex *tkey_ex = p->tcfp_keys_ex;
		enum pedit_header_type htype =
			TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
		enum pedit_cmd cmd = TCA_PEDIT_KEY_EX_CMD_SET;

		/* Linearize so we are sure pedit is operating on a private copy */
		if (skb_has_shared_frag(skb)) {
			if (__skb_linearize(skb))
				goto bad;
		}

		for (i = p->tcfp_nkeys; i > 0; i--, tkey++) {
			u32 *ptr, hdata;
			int offset = tkey->off;
			int hoffset;
			u32 val;
			int rc;

			if (tkey_ex) {
				htype = tkey_ex->htype;
				cmd = tkey_ex->cmd;

				tkey_ex++;
			}

			rc = pedit_skb_hdr_offset(skb, htype, &hoffset);
			if (rc) {
				pr_info("tc action pedit bad header type specified (0x%x)\n",
					htype);
				goto bad;
			}

			if (tkey->offmask) {
				u8 *d, _d;

				if (!(*klpe_offset_valid)(skb, hoffset + tkey->at)) {
					pr_info("tc action pedit 'at' offset %d out of bounds\n",
						hoffset + tkey->at);
					goto bad;
				}
				d = skb_header_pointer(skb, hoffset + tkey->at,
						       sizeof(_d), &_d);
				if (!d)
					goto bad;
				offset += (*d & tkey->offmask) >> tkey->shift;
			}

			if (offset % 4) {
				pr_info("tc action pedit offset must be on 32 bit boundaries\n");
				goto bad;
			}

			if (!(*klpe_offset_valid)(skb, hoffset + offset)) {
				pr_info("tc action pedit offset %d out of bounds\n",
					hoffset + offset);
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
				pr_info("tc action pedit bad command (%d)\n",
					cmd);
				goto bad;
			}

			*ptr = ((*ptr & tkey->mask) ^ val);
			if (ptr == &hdata)
				skb_store_bits(skb, hoffset + offset, ptr, 4);
		}

		goto done;
	} else {
		WARN(1, "pedit BUG: index %d\n", p->tcf_index);
	}

bad:
	p->tcf_qstats.overlimits++;
done:
	bstats_update(&p->tcf_bstats, skb);
	spin_unlock(&p->tcf_lock);
	return p->tcf_action;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "act_pedit"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "offset_valid", (void *)&klpe_offset_valid, "act_pedit" },
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

int livepatch_bsc1267625_init(void)
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

void livepatch_bsc1267625_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
