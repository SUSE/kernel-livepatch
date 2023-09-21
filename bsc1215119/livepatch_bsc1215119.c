/*
 * livepatch_bsc1215119
 *
 * Fix for CVE-2023-3776, bsc#1215119
 *
 *  Upstream commit:
 *  0323bce598ee ("net/sched: cls_fw: Fix improper refcount update leads to use-after-free")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  0349f73994e50b58ce7d1064c37614f1a659a40d
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b7fc513a90f5f2426b70790de82ac0fa0dae78f8
 *
 *  SLE15-SP4 and -SP5 commit:
 *  057a69b70d8f310efb2fd0068d987393fb834277
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

#if !IS_MODULE(CONFIG_NET_CLS_FW)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/sched/cls_fw.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/act_api.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>

#define HTSIZE 256

struct fw_head {
	u32			mask;
	struct fw_filter __rcu	*ht[HTSIZE];
	struct rcu_head		rcu;
};

struct fw_filter {
	struct fw_filter __rcu	*next;
	u32			id;
	struct tcf_result	res;
#ifdef CONFIG_NET_CLS_IND
	int			ifindex;
#endif /* CONFIG_NET_CLS_IND */
	struct tcf_exts		exts;
	struct tcf_proto	*tp;
	struct rcu_work		rwork;
};

int klpp_fw_set_parms(struct net *net, struct tcf_proto *tp,
			struct fw_filter *f, struct nlattr **tb,
			struct nlattr **tca, unsigned long base, bool ovr,
			struct netlink_ext_ack *extack)
{
	struct fw_head *head = rtnl_dereference(tp->root);
	u32 mask;
	int err;

	err = tcf_exts_validate(net, tp, tb, tca[TCA_RATE], &f->exts, ovr,
				extack);
	if (err < 0)
		return err;

#ifdef CONFIG_NET_CLS_IND
	if (tb[TCA_FW_INDEV]) {
		int ret;
		ret = tcf_change_indev(net, tb[TCA_FW_INDEV], extack);
		if (ret < 0)
			return ret;
		f->ifindex = ret;
	}
#endif /* CONFIG_NET_CLS_IND */
	err = -EINVAL;
	if (tb[TCA_FW_MASK]) {
		mask = nla_get_u32(tb[TCA_FW_MASK]);
		if (mask != head->mask)
			return err;
	} else if (head->mask != 0xFFFFFFFF)
		return err;

	if (tb[TCA_FW_CLASSID]) {
		f->res.classid = nla_get_u32(tb[TCA_FW_CLASSID]);
		tcf_bind_filter(tp, &f->res, base);
	}

	return 0;
}
