/*
 * livepatch_bsc1236207
 *
 * Fix for CVE-2025-21659, bsc#1236207
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/core/netdev-genl.c */
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>
#include <net/sock.h>

/* klp-ccp: from include/net/busy_poll.h */
#define MIN_NAPI_ID ((unsigned int)(NR_CPUS + 1))

/* klp-ccp: from net/core/netdev-genl-gen.h */
#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/netdev.h>

/* klp-ccp: from net/core/dev.h */
#include <linux/types.h>

extern struct napi_struct *napi_by_id(unsigned int napi_id);

struct napi_struct *netdev_napi_by_id(struct net *net, unsigned int napi_id){
	struct napi_struct *napi;

	napi = napi_by_id(napi_id);
	if (!napi)
		return NULL;

	if (WARN_ON_ONCE(!napi->dev))
		return NULL;
	if (!net_eq(net, dev_net(napi->dev)))
		return NULL;

	return napi;
}

/* klp-ccp: from net/core/netdev-genl.c */
int
klpp_netdev_nl_napi_fill_one(struct sk_buff *rsp, struct napi_struct *napi,
			const struct genl_info *info)
{
	void *hdr;
	pid_t pid;

	if (!(napi->dev->flags & IFF_UP))
		return 0;

	hdr = genlmsg_iput(rsp, info);
	if (!hdr)
		return -EMSGSIZE;

	if (napi->napi_id >= MIN_NAPI_ID &&
	    nla_put_u32(rsp, NETDEV_A_NAPI_ID, napi->napi_id))
		goto nla_put_failure;

	if (nla_put_u32(rsp, NETDEV_A_NAPI_IFINDEX, napi->dev->ifindex))
		goto nla_put_failure;

	if (napi->irq >= 0 && nla_put_u32(rsp, NETDEV_A_NAPI_IRQ, napi->irq))
		goto nla_put_failure;

	if (napi->thread) {
		pid = task_pid_nr(napi->thread);
		if (nla_put_u32(rsp, NETDEV_A_NAPI_PID, pid))
			goto nla_put_failure;
	}

	genlmsg_end(rsp, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(rsp, hdr);
	return -EMSGSIZE;
}

int klpp_netdev_nl_napi_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct napi_struct *napi;
	struct sk_buff *rsp;
	u32 napi_id;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, NETDEV_A_NAPI_ID))
		return -EINVAL;

	napi_id = nla_get_u32(info->attrs[NETDEV_A_NAPI_ID]);

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rtnl_lock();

	napi = netdev_napi_by_id(genl_info_net(info), napi_id);
	if (napi)
		err = klpp_netdev_nl_napi_fill_one(rsp, napi, info);
	else
		err = -EINVAL;

	rtnl_unlock();

	if (err)
		goto err_free_msg;

	return genlmsg_reply(rsp, info);

err_free_msg:
	nlmsg_free(rsp);
	return err;
}


#include "livepatch_bsc1236207.h"
#include <linux/livepatch.h>

extern typeof(napi_by_id) napi_by_id
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, napi_by_id);
