/*
 * livepatch_bsc1212509
 *
 * Fix for CVE-2023-35788, bsc#1212509
 *
 *  Upstream commit:
 *  4d56304e5827 ("net/sched: flower: fix possible OOB write in fl_set_geneve_opt()")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  865936b7661d0b1ec69e9ec5b1721c639c459caf
 *
 *  SLE15-SP4 and -SP5 commit:
 *  3ad73db1c751c01b9df62c6315c0a056ad0eef4b
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#if !IS_MODULE(CONFIG_NET_CLS_FLOWER)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/sched/cls_flower.c */
#include <linux/module.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/ip.h>
#include <net/flow_dissector.h>
#include <net/geneve.h>

/* klp-ccp: from include/net/dst_metadata.h */
#define __NET_DST_METADATA_H 1

/* klp-ccp: from net/sched/cls_flower.c */
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <uapi/linux/netfilter/nf_conntrack_common.h>

struct fl_flow_key {
	struct flow_dissector_key_meta meta;
	struct flow_dissector_key_control control;
	struct flow_dissector_key_control enc_control;
	struct flow_dissector_key_basic basic;
	struct flow_dissector_key_eth_addrs eth;
	struct flow_dissector_key_vlan vlan;
	struct flow_dissector_key_vlan cvlan;
	union {
		struct flow_dissector_key_ipv4_addrs ipv4;
		struct flow_dissector_key_ipv6_addrs ipv6;
	};
	struct flow_dissector_key_ports tp;
	struct flow_dissector_key_icmp icmp;
	struct flow_dissector_key_arp arp;
	struct flow_dissector_key_keyid enc_key_id;
	union {
		struct flow_dissector_key_ipv4_addrs enc_ipv4;
		struct flow_dissector_key_ipv6_addrs enc_ipv6;
	};
	struct flow_dissector_key_ports enc_tp;
	struct flow_dissector_key_mpls mpls;
	struct flow_dissector_key_tcp tcp;
	struct flow_dissector_key_ip ip;
	struct flow_dissector_key_ip enc_ip;
	struct flow_dissector_key_enc_opts enc_opts;
	struct flow_dissector_key_ports_range tp_range;
	struct flow_dissector_key_ct ct;
	struct flow_dissector_key_hash hash;
} __aligned(BITS_PER_LONG / 8);

static const struct nla_policy
(*klpe_geneve_opt_policy)[TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX + 1];

int klpp_fl_set_geneve_opt(const struct nlattr *nla, struct fl_flow_key *key,
			     int depth, int option_len,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX + 1];
	struct nlattr *class = NULL, *type = NULL, *data = NULL;
	struct geneve_opt *opt;
	int err, data_len = 0;

	if (option_len > sizeof(struct geneve_opt))
		data_len = option_len - sizeof(struct geneve_opt);

	if (key->enc_opts.len > FLOW_DIS_TUN_OPTS_MAX - 4)
		return -ERANGE;

	opt = (struct geneve_opt *)&key->enc_opts.data[key->enc_opts.len];
	memset(opt, 0xff, option_len);
	opt->length = data_len / 4;
	opt->r1 = 0;
	opt->r2 = 0;
	opt->r3 = 0;

	/* If no mask has been prodived we assume an exact match. */
	if (!depth)
		return sizeof(struct geneve_opt) + data_len;

	if (nla_type(nla) != TCA_FLOWER_KEY_ENC_OPTS_GENEVE) {
		NL_SET_ERR_MSG(extack, "Non-geneve option type for mask");
		return -EINVAL;
	}

	err = nla_parse_nested_deprecated(tb,
					  TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX,
					  nla, (*klpe_geneve_opt_policy), extack);
	if (err < 0)
		return err;

	/* We are not allowed to omit any of CLASS, TYPE or DATA
	 * fields from the key.
	 */
	if (!option_len &&
	    (!tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS] ||
	     !tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE] ||
	     !tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA])) {
		NL_SET_ERR_MSG(extack, "Missing tunnel key geneve option class, type or data");
		return -EINVAL;
	}

	/* Omitting any of CLASS, TYPE or DATA fields is allowed
	 * for the mask.
	 */
	if (tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA]) {
		int new_len = key->enc_opts.len;

		data = tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA];
		data_len = nla_len(data);
		if (data_len < 4) {
			NL_SET_ERR_MSG(extack, "Tunnel key geneve option data is less than 4 bytes long");
			return -ERANGE;
		}
		if (data_len % 4) {
			NL_SET_ERR_MSG(extack, "Tunnel key geneve option data is not a multiple of 4 bytes long");
			return -ERANGE;
		}

		new_len += sizeof(struct geneve_opt) + data_len;
		BUILD_BUG_ON(FLOW_DIS_TUN_OPTS_MAX != IP_TUNNEL_OPTS_MAX);
		if (new_len > FLOW_DIS_TUN_OPTS_MAX) {
			NL_SET_ERR_MSG(extack, "Tunnel options exceeds max size");
			return -ERANGE;
		}
		opt->length = data_len / 4;
		memcpy(opt->opt_data, nla_data(data), data_len);
	}

	if (tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS]) {
		class = tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS];
		opt->opt_class = nla_get_be16(class);
	}

	if (tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE]) {
		type = tb[TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE];
		opt->type = nla_get_u8(type);
	}

	return sizeof(struct geneve_opt) + data_len;
}


#include "livepatch_bsc1212509.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cls_flower"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "geneve_opt_policy", (void *)&klpe_geneve_opt_policy, "cls_flower" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1212509_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1212509_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
