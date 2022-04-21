/*
 * livepatch_bsc1197335
 *
 * Fix for CVE-2022-1016, bsc#1197335
 *
 *  Upstream commit:
 *  4c905f6740a3 ("netfilter: nf_tables: initialize registers
 *                 in nft_do_chain()")
 *
 *  SLE12-SP3 commit:
 *  cda245e1c5c14e0588d50f4b2beedf8a30d027e5
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  4726ea9ddbe3e02d180c1e3f17eaa25b7a1fb4c2
 *
 *  SLE15-SP2 and -SP3 commit:
 *  7111961c9eecad2a954d1a7f7062b9653d800cd7
 *
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_NF_TABLES)
#error "Live patch supports only CONFIG_NF_TABLES=m"
#endif

/* klp-ccp: from net/netfilter/nf_tables_core.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>

/* klp-ccp: from include/linux/security.h */
struct xfrm_state;

/* klp-ccp: from include/uapi/linux/netlink.h */
struct nlmsghdr;

struct nlattr;

/* klp-ccp: from include/linux/netlink.h */
struct netlink_callback;

/* klp-ccp: from net/netfilter/nf_tables_core.c */
#include <linux/netfilter.h>
#include <linux/static_key.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>

/* klp-ccp: from include/net/netfilter/nf_tables_core.h */
static const struct nft_expr_ops (*klpe_nft_cmp_fast_ops);

static const struct nft_expr_ops (*klpe_nft_payload_fast_ops);
static struct static_key_false (*klpe_nft_trace_enabled);

/* klp-ccp: from net/netfilter/nf_tables_core.c */
#include <net/netfilter/nf_tables.h>

/* klp-ccp: from include/net/netfilter/nf_tables.h */
unsigned int klpp_nft_do_chain(struct nft_pktinfo *pkt, void *priv);

static void (*klpe_nft_trace_init)(struct nft_traceinfo *info, const struct nft_pktinfo *pkt,
		    const struct nft_verdict *verdict,
		    const struct nft_chain *basechain);

/* klp-ccp: from net/netfilter/nf_tables_core.c */
static void (*klpe___nft_trace_packet)(struct nft_traceinfo *info,
					const struct nft_chain *chain,
					int rulenum, enum nft_trace_types type);

static inline void klpr_nft_trace_packet(struct nft_traceinfo *info,
				    const struct nft_chain *chain,
				    const struct nft_rule *rule,
				    int rulenum,
				    enum nft_trace_types type,
				    bool nft_trace_enabled)
{
	if (nft_trace_enabled) {
		info->rule = rule;
		(*klpe___nft_trace_packet)(info, chain, rulenum, type);
	}
}

static void nft_cmp_fast_eval(const struct nft_expr *expr,
			      struct nft_regs *regs)
{
	const struct nft_cmp_fast_expr *priv = nft_expr_priv(expr);
	u32 mask = nft_cmp_fast_mask(priv->len);

	if ((regs->data[priv->sreg] & mask) == priv->data)
		return;
	regs->verdict.code = NFT_BREAK;
}

static bool nft_payload_fast_eval(const struct nft_expr *expr,
				  struct nft_regs *regs,
				  const struct nft_pktinfo *pkt)
{
	const struct nft_payload *priv = nft_expr_priv(expr);
	const struct sk_buff *skb = pkt->skb;
	u32 *dest = &regs->data[priv->dreg];
	unsigned char *ptr;

	if (priv->base == NFT_PAYLOAD_NETWORK_HEADER)
		ptr = skb_network_header(skb);
	else {
		if (!pkt->tprot_set)
			return false;
		ptr = skb_network_header(skb) + pkt->xt.thoff;
	}

	ptr += priv->offset;

	if (unlikely(ptr + priv->len > skb_tail_pointer(skb)))
		return false;

	*dest = 0;
	if (priv->len == 2)
		*(u16 *)dest = *(u16 *)ptr;
	else if (priv->len == 4)
		*(u32 *)dest = *(u32 *)ptr;
	else
		*(u8 *)dest = *(u8 *)ptr;
	return true;
}

struct nft_jumpstack {
	const struct nft_chain	*chain;
	const struct nft_rule	*rule;
	int			rulenum;
};

unsigned int
klpp_nft_do_chain(struct nft_pktinfo *pkt, void *priv)
{
	const struct nft_chain *chain = priv, *basechain = chain;
	struct nft_base_chain *base_chain;
	const struct net *net = nft_net(pkt);
	struct nft_stats __percpu *pstats;
	const struct nft_rule *rule;
	const struct nft_expr *expr, *last;
	/*
	 * Fix CVE-2022-1016
	 *  -1 line, +1 line
	 */
	struct nft_regs regs = {};
	unsigned int stackptr = 0;
	struct nft_jumpstack jumpstack[NFT_JUMP_STACK_SIZE];
	struct nft_stats *stats;
	int rulenum;
	unsigned int gencursor = nft_genmask_cur(net);
	struct nft_traceinfo info;
	bool nft_trace_enabled;

	info.trace = false;
	nft_trace_enabled = static_key_enabled(&(*klpe_nft_trace_enabled));
	if (nft_trace_enabled)
		(*klpe_nft_trace_init)(&info, pkt, &regs.verdict, basechain);
do_chain:
	rulenum = 0;
	rule = list_entry(&chain->rules, struct nft_rule, list);
next_rule:
	regs.verdict.code = NFT_CONTINUE;
	list_for_each_entry_continue_rcu(rule, &chain->rules, list) {

		/* This rule is not active, skip. */
		if (unlikely(rule->genmask & gencursor))
			continue;

		rulenum++;

		nft_rule_for_each_expr(expr, last, rule) {
			if (expr->ops == &(*klpe_nft_cmp_fast_ops))
				nft_cmp_fast_eval(expr, &regs);
			else if (expr->ops != &(*klpe_nft_payload_fast_ops) ||
				 !nft_payload_fast_eval(expr, &regs, pkt))
				expr->ops->eval(expr, &regs, pkt);

			if (regs.verdict.code != NFT_CONTINUE)
				break;
		}

		switch (regs.verdict.code) {
		case NFT_BREAK:
			regs.verdict.code = NFT_CONTINUE;
			continue;
		case NFT_CONTINUE:
			klpr_nft_trace_packet(&info, chain, rule,
					 rulenum, NFT_TRACETYPE_RULE,
					 nft_trace_enabled);
			continue;
		}
		break;
	}

	switch (regs.verdict.code & NF_VERDICT_MASK) {
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
	case NF_STOLEN:
		klpr_nft_trace_packet(&info, chain, rule,
				 rulenum, NFT_TRACETYPE_RULE,
				 nft_trace_enabled);
		return regs.verdict.code;
	}

	switch (regs.verdict.code) {
	case NFT_JUMP:
		if (WARN_ON_ONCE(stackptr >= NFT_JUMP_STACK_SIZE))
			return NF_DROP;
		jumpstack[stackptr].chain = chain;
		jumpstack[stackptr].rule  = rule;
		jumpstack[stackptr].rulenum = rulenum;
		stackptr++;
		/* fall through */
	case NFT_GOTO:
		klpr_nft_trace_packet(&info, chain, rule,
				 rulenum, NFT_TRACETYPE_RULE,
				 nft_trace_enabled);

		chain = regs.verdict.chain;
		goto do_chain;
	case NFT_CONTINUE:
		rulenum++;
		/* fall through */
	case NFT_RETURN:
		klpr_nft_trace_packet(&info, chain, rule,
				 rulenum, NFT_TRACETYPE_RETURN,
				 nft_trace_enabled);
		break;
	default:
		WARN_ON(1);
	}

	if (stackptr > 0) {
		stackptr--;
		chain = jumpstack[stackptr].chain;
		rule  = jumpstack[stackptr].rule;
		rulenum = jumpstack[stackptr].rulenum;
		goto next_rule;
	}

	klpr_nft_trace_packet(&info, basechain, NULL, -1,
			 NFT_TRACETYPE_POLICY, nft_trace_enabled);

	base_chain = nft_base_chain(basechain);

	rcu_read_lock_bh();
	pstats = READ_ONCE(base_chain->stats);
	if (pstats) {
		stats = this_cpu_ptr(pstats);
		u64_stats_update_begin(&stats->syncp);
		stats->pkts++;
		stats->bytes += pkt->skb->len;
		u64_stats_update_end(&stats->syncp);
	}
	rcu_read_unlock_bh();

	return nft_base_chain(basechain)->policy;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1197335.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__nft_trace_packet", (void *)&klpe___nft_trace_packet, "nf_tables" },
	{ "nft_cmp_fast_ops", (void *)&klpe_nft_cmp_fast_ops, "nf_tables" },
	{ "nft_payload_fast_ops", (void *)&klpe_nft_payload_fast_ops,
	  "nf_tables" },
	{ "nft_trace_enabled", (void *)&klpe_nft_trace_enabled, "nf_tables" },
	{ "nft_trace_init", (void *)&klpe_nft_trace_init, "nf_tables" },
};

static int livepatch_bsc1197335_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1197335_module_nb = {
	.notifier_call = livepatch_bsc1197335_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1197335_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1197335_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1197335_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1197335_module_nb);
}
