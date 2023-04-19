/*
 * bsc1207822_net_core_rtnetlink
 *
 * Fix for CVE-2023-0590, bsc#1207822
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

/* klp-ccp: from net/core/rtnetlink.c */
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/capability.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/mutex.h>
#include <linux/if_addr.h>
#include <linux/if_bridge.h>

/* klp-ccp: from include/net/net_namespace.h */
static int (*klpe_peernet2id_alloc)(struct net *net, struct net *peer, gfp_t gfp);

/* klp-ccp: from net/core/rtnetlink.c */
#include <linux/if_vlan.h>
#include <linux/etherdevice.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <net/switchdev.h>

/* klp-ccp: from net/core/rtnetlink.c */
#include <net/route.h>
#include <net/sock.h>
#include <net/fib_rules.h>
#include <net/rtnetlink.h>
#include <net/net_namespace.h>

int rtnl_is_locked(void);

static struct list_head (*klpe_rtnl_af_ops);

static bool rtnl_have_link_slave_info(const struct net_device *dev)
{
	struct net_device *master_dev;

	master_dev = netdev_master_upper_dev_get((struct net_device *) dev);
	if (master_dev && master_dev->rtnl_link_ops)
		return true;
	return false;
}

static int rtnl_link_slave_info_fill(struct sk_buff *skb,
				     const struct net_device *dev)
{
	struct net_device *master_dev;
	const struct rtnl_link_ops *ops;
	struct nlattr *slave_data;
	int err;

	master_dev = netdev_master_upper_dev_get((struct net_device *) dev);
	if (!master_dev)
		return 0;
	ops = master_dev->rtnl_link_ops;
	if (!ops)
		return 0;
	if (nla_put_string(skb, IFLA_INFO_SLAVE_KIND, ops->kind) < 0)
		return -EMSGSIZE;
	if (ops->fill_slave_info) {
		slave_data = nla_nest_start(skb, IFLA_INFO_SLAVE_DATA);
		if (!slave_data)
			return -EMSGSIZE;
		err = ops->fill_slave_info(skb, master_dev, dev);
		if (err < 0)
			goto err_cancel_slave_data;
		nla_nest_end(skb, slave_data);
	}
	return 0;

err_cancel_slave_data:
	nla_nest_cancel(skb, slave_data);
	return err;
}

static int rtnl_link_info_fill(struct sk_buff *skb,
			       const struct net_device *dev)
{
	const struct rtnl_link_ops *ops = dev->rtnl_link_ops;
	struct nlattr *data;
	int err;

	if (!ops)
		return 0;
	if (nla_put_string(skb, IFLA_INFO_KIND, ops->kind) < 0)
		return -EMSGSIZE;
	if (ops->fill_xstats) {
		err = ops->fill_xstats(skb, dev);
		if (err < 0)
			return err;
	}
	if (ops->fill_info) {
		data = nla_nest_start(skb, IFLA_INFO_DATA);
		if (data == NULL)
			return -EMSGSIZE;
		err = ops->fill_info(skb, dev);
		if (err < 0)
			goto err_cancel_data;
		nla_nest_end(skb, data);
	}
	return 0;

err_cancel_data:
	nla_nest_cancel(skb, data);
	return err;
}

static int rtnl_link_fill(struct sk_buff *skb, const struct net_device *dev)
{
	struct nlattr *linkinfo;
	int err = -EMSGSIZE;

	linkinfo = nla_nest_start(skb, IFLA_LINKINFO);
	if (linkinfo == NULL)
		goto out;

	err = rtnl_link_info_fill(skb, dev);
	if (err < 0)
		goto err_cancel_link;

	err = rtnl_link_slave_info_fill(skb, dev);
	if (err < 0)
		goto err_cancel_link;

	nla_nest_end(skb, linkinfo);
	return 0;

err_cancel_link:
	nla_nest_cancel(skb, linkinfo);
out:
	return err;
}

static int rtnl_vf_ports_fill(struct sk_buff *skb, struct net_device *dev)
{
	struct nlattr *vf_ports;
	struct nlattr *vf_port;
	int vf;
	int err;

	vf_ports = nla_nest_start(skb, IFLA_VF_PORTS);
	if (!vf_ports)
		return -EMSGSIZE;

	for (vf = 0; vf < dev_num_vf(dev->dev.parent); vf++) {
		vf_port = nla_nest_start(skb, IFLA_VF_PORT);
		if (!vf_port)
			goto nla_put_failure;
		if (nla_put_u32(skb, IFLA_PORT_VF, vf))
			goto nla_put_failure;
		err = dev->netdev_ops->ndo_get_vf_port(dev, vf, skb);
		if (err == -EMSGSIZE)
			goto nla_put_failure;
		if (err) {
			nla_nest_cancel(skb, vf_port);
			continue;
		}
		nla_nest_end(skb, vf_port);
	}

	nla_nest_end(skb, vf_ports);

	return 0;

nla_put_failure:
	nla_nest_cancel(skb, vf_ports);
	return -EMSGSIZE;
}

static int rtnl_port_self_fill(struct sk_buff *skb, struct net_device *dev)
{
	struct nlattr *port_self;
	int err;

	port_self = nla_nest_start(skb, IFLA_PORT_SELF);
	if (!port_self)
		return -EMSGSIZE;

	err = dev->netdev_ops->ndo_get_vf_port(dev, PORT_SELF_VF, skb);
	if (err) {
		nla_nest_cancel(skb, port_self);
		return (err == -EMSGSIZE) ? err : 0;
	}

	nla_nest_end(skb, port_self);

	return 0;
}

static int rtnl_port_fill(struct sk_buff *skb, struct net_device *dev,
			  u32 ext_filter_mask)
{
	int err;

	if (!dev->netdev_ops->ndo_get_vf_port || !dev->dev.parent ||
	    !(ext_filter_mask & RTEXT_FILTER_VF))
		return 0;

	err = rtnl_port_self_fill(skb, dev);
	if (err)
		return err;

	if (dev_num_vf(dev->dev.parent)) {
		err = rtnl_vf_ports_fill(skb, dev);
		if (err)
			return err;
	}

	return 0;
}

static int rtnl_phys_port_id_fill(struct sk_buff *skb, struct net_device *dev)
{
	int err;
	struct netdev_phys_item_id ppid;

	err = dev_get_phys_port_id(dev, &ppid);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	if (nla_put(skb, IFLA_PHYS_PORT_ID, ppid.id_len, ppid.id))
		return -EMSGSIZE;

	return 0;
}

static int rtnl_phys_port_name_fill(struct sk_buff *skb, struct net_device *dev)
{
	char name[IFNAMSIZ];
	int err;

	err = dev_get_phys_port_name(dev, name, sizeof(name));
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	if (nla_put_string(skb, IFLA_PHYS_PORT_NAME, name))
		return -EMSGSIZE;

	return 0;
}

static int (*klpe_rtnl_phys_switch_id_fill)(struct sk_buff *skb, struct net_device *dev);

static noinline_for_stack int (*klpe_rtnl_fill_stats)(struct sk_buff *skb,
					      struct net_device *dev);

static noinline_for_stack int (*klpe_rtnl_fill_vfinfo)(struct sk_buff *skb,
					       struct net_device *dev,
					       int vfs_num,
					       struct nlattr *vfinfo);

static int rtnl_fill_link_ifmap(struct sk_buff *skb, struct net_device *dev)
{
	struct rtnl_link_ifmap map;

	memset(&map, 0, sizeof(map));
	map.mem_start   = dev->mem_start;
	map.mem_end     = dev->mem_end;
	map.base_addr   = dev->base_addr;
	map.irq         = dev->irq;
	map.dma         = dev->dma;
	map.port        = dev->if_port;

	if (nla_put_64bit(skb, IFLA_MAP, sizeof(map), &map, IFLA_PAD))
		return -EMSGSIZE;

	return 0;
}

static u32 (*klpe_rtnl_xdp_prog_skb)(struct net_device *dev);

static u32 (*klpe_rtnl_xdp_prog_drv)(struct net_device *dev);

static u32 (*klpe_rtnl_xdp_prog_hw)(struct net_device *dev);

static int (*klpe_rtnl_xdp_report_one)(struct sk_buff *skb, struct net_device *dev,
			       u32 *prog_id, u8 *mode, u8 tgt_mode, u32 attr,
			       u32 (*get_prog_id)(struct net_device *dev));

static int klpr_rtnl_xdp_fill(struct sk_buff *skb, struct net_device *dev)
{
	struct nlattr *xdp;
	u32 prog_id;
	int err;
	u8 mode;

	xdp = nla_nest_start(skb, IFLA_XDP);
	if (!xdp)
		return -EMSGSIZE;

	prog_id = 0;
	mode = XDP_ATTACHED_NONE;
	err = (*klpe_rtnl_xdp_report_one)(skb, dev, &prog_id, &mode, XDP_ATTACHED_SKB,
				  IFLA_XDP_SKB_PROG_ID, (*klpe_rtnl_xdp_prog_skb));
	if (err)
		goto err_cancel;
	err = (*klpe_rtnl_xdp_report_one)(skb, dev, &prog_id, &mode, XDP_ATTACHED_DRV,
				  IFLA_XDP_DRV_PROG_ID, (*klpe_rtnl_xdp_prog_drv));
	if (err)
		goto err_cancel;
	err = (*klpe_rtnl_xdp_report_one)(skb, dev, &prog_id, &mode, XDP_ATTACHED_HW,
				  IFLA_XDP_HW_PROG_ID, (*klpe_rtnl_xdp_prog_hw));
	if (err)
		goto err_cancel;

	err = nla_put_u8(skb, IFLA_XDP_ATTACHED, mode);
	if (err)
		goto err_cancel;

	if (prog_id && mode != XDP_ATTACHED_MULTI) {
		err = nla_put_u32(skb, IFLA_XDP_PROG_ID, prog_id);
		if (err)
			goto err_cancel;
	}

	nla_nest_end(skb, xdp);
	return 0;

err_cancel:
	nla_nest_cancel(skb, xdp);
	return err;
}

int klpp_rtnl_fill_ifinfo(struct sk_buff *skb, struct net_device *dev,
			    int type, u32 pid, u32 seq, u32 change,
			    unsigned int flags, u32 ext_filter_mask,
			    u32 event, gfp_t gfp)
{
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;
	struct nlattr *af_spec;
	struct rtnl_af_ops *af_ops;
	struct net_device *upper_dev = netdev_master_upper_dev_get(dev);
	bool put_iflink = false;
	struct Qdisc *qdisc;

	ASSERT_RTNL();
	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ifm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ifm = nlmsg_data(nlh);
	ifm->ifi_family = AF_UNSPEC;
	ifm->__ifi_pad = 0;
	ifm->ifi_type = dev->type;
	ifm->ifi_index = dev->ifindex;
	ifm->ifi_flags = dev_get_flags(dev);
	ifm->ifi_change = change;

	qdisc = rtnl_dereference(dev->qdisc);
	if (nla_put_string(skb, IFLA_IFNAME, dev->name) ||
	    nla_put_u32(skb, IFLA_TXQLEN, dev->tx_queue_len) ||
	    nla_put_u8(skb, IFLA_OPERSTATE,
		       netif_running(dev) ? dev->operstate : IF_OPER_DOWN) ||
	    nla_put_u8(skb, IFLA_LINKMODE, dev->link_mode) ||
	    nla_put_u32(skb, IFLA_MTU, dev->mtu) ||
	    nla_put_u32(skb, IFLA_GROUP, dev->group) ||
	    nla_put_u32(skb, IFLA_PROMISCUITY, dev->promiscuity) ||
	    nla_put_u32(skb, IFLA_NUM_TX_QUEUES, dev->num_tx_queues) ||
	    nla_put_u32(skb, IFLA_GSO_MAX_SEGS, dev->gso_max_segs) ||
	    nla_put_u32(skb, IFLA_GSO_MAX_SIZE, dev->gso_max_size) ||
#ifdef CONFIG_RPS
	    nla_put_u32(skb, IFLA_NUM_RX_QUEUES, dev->num_rx_queues) ||
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	    (upper_dev &&
	     nla_put_u32(skb, IFLA_MASTER, upper_dev->ifindex)) ||
	    nla_put_u8(skb, IFLA_CARRIER, netif_carrier_ok(dev)) ||
	    (qdisc &&
	     nla_put_string(skb, IFLA_QDISC, qdisc->ops->id)) ||
	    (dev->ifalias &&
	     nla_put_string(skb, IFLA_IFALIAS, dev->ifalias)) ||
	    nla_put_u32(skb, IFLA_CARRIER_CHANGES,
			atomic_read(&dev->carrier_changes)) ||
	    nla_put_u8(skb, IFLA_PROTO_DOWN, dev->proto_down))
		goto nla_put_failure;

	if (event != IFLA_EVENT_NONE) {
		if (nla_put_u32(skb, IFLA_EVENT, event))
			goto nla_put_failure;
	}

	if (rtnl_fill_link_ifmap(skb, dev))
		goto nla_put_failure;

	if (dev->addr_len) {
		if (nla_put(skb, IFLA_ADDRESS, dev->addr_len, dev->dev_addr) ||
		    nla_put(skb, IFLA_BROADCAST, dev->addr_len, dev->broadcast))
			goto nla_put_failure;
	}

	if (rtnl_phys_port_id_fill(skb, dev))
		goto nla_put_failure;

	if (rtnl_phys_port_name_fill(skb, dev))
		goto nla_put_failure;

	if ((*klpe_rtnl_phys_switch_id_fill)(skb, dev))
		goto nla_put_failure;

	if ((*klpe_rtnl_fill_stats)(skb, dev))
		goto nla_put_failure;

	if (dev->dev.parent && (ext_filter_mask & RTEXT_FILTER_VF) &&
	    nla_put_u32(skb, IFLA_NUM_VF, dev_num_vf(dev->dev.parent)))
		goto nla_put_failure;

	if (dev->netdev_ops->ndo_get_vf_config && dev->dev.parent &&
	    ext_filter_mask & RTEXT_FILTER_VF) {
		int i;
		struct nlattr *vfinfo;
		int num_vfs = dev_num_vf(dev->dev.parent);

		vfinfo = nla_nest_start(skb, IFLA_VFINFO_LIST);
		if (!vfinfo)
			goto nla_put_failure;
		for (i = 0; i < num_vfs; i++) {
			if ((*klpe_rtnl_fill_vfinfo)(skb, dev, i, vfinfo))
				goto nla_put_failure;
		}

		nla_nest_end(skb, vfinfo);
	}

	if (rtnl_port_fill(skb, dev, ext_filter_mask))
		goto nla_put_failure;

	if (klpr_rtnl_xdp_fill(skb, dev))
		goto nla_put_failure;

	if (dev->rtnl_link_ops || rtnl_have_link_slave_info(dev)) {
		if (rtnl_link_fill(skb, dev) < 0)
			goto nla_put_failure;
	}

	if (dev->rtnl_link_ops &&
	    dev->rtnl_link_ops->get_link_net) {
		struct net *link_net = dev->rtnl_link_ops->get_link_net(dev);

		if (!net_eq(dev_net(dev), link_net)) {
			int id = (*klpe_peernet2id_alloc)(dev_net(dev), link_net, gfp);

			if (nla_put_s32(skb, IFLA_LINK_NETNSID, id))
				goto nla_put_failure;

			put_iflink = true;
		}
	}

	if ((put_iflink || dev->ifindex != dev_get_iflink(dev)) &&
	     nla_put_u32(skb, IFLA_LINK, dev_get_iflink(dev)))
		goto nla_put_failure;

	if (!(af_spec = nla_nest_start(skb, IFLA_AF_SPEC)))
		goto nla_put_failure;

	list_for_each_entry(af_ops, &(*klpe_rtnl_af_ops), list) {
		if (af_ops->fill_link_af) {
			struct nlattr *af;
			int err;

			if (!(af = nla_nest_start(skb, af_ops->family)))
				goto nla_put_failure;

			err = af_ops->fill_link_af(skb, dev, ext_filter_mask);

			/*
			 * Caller may return ENODATA to indicate that there
			 * was no data to be dumped. This is not an error, it
			 * means we should trim the attribute header and
			 * continue.
			 */
			if (err == -ENODATA)
				nla_nest_cancel(skb, af);
			else if (err < 0)
				goto nla_put_failure;

			nla_nest_end(skb, af);
		}
	}

	nla_nest_end(skb, af_spec);

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}



#include <linux/kernel.h>
#include "livepatch_bsc1207822.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "peernet2id_alloc", (void *)&klpe_peernet2id_alloc },
	{ "rtnl_af_ops", (void *)&klpe_rtnl_af_ops },
	{ "rtnl_fill_stats", (void *)&klpe_rtnl_fill_stats },
	{ "rtnl_fill_vfinfo", (void *)&klpe_rtnl_fill_vfinfo },
	{ "rtnl_phys_switch_id_fill", (void *)&klpe_rtnl_phys_switch_id_fill },
	{ "rtnl_xdp_prog_drv", (void *)&klpe_rtnl_xdp_prog_drv },
	{ "rtnl_xdp_prog_hw", (void *)&klpe_rtnl_xdp_prog_hw },
	{ "rtnl_xdp_prog_skb", (void *)&klpe_rtnl_xdp_prog_skb },
	{ "rtnl_xdp_report_one", (void *)&klpe_rtnl_xdp_report_one },
};

int bsc1207822_net_core_rtnetlink_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

