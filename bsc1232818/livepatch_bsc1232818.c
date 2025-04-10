/*
 * livepatch_bsc1232818
 *
 * Fix for CVE-2022-49014, bsc#1232818
 *
 *  Upstream commit:
 *  5daadc86f27e ("net: tun: Fix use-after-free in tun_detach()")
 *
 *  SLE12-SP5 commit:
 *  addf3df681f8bc2c5a05437e876220355fdaa9c5
 *
 *  SLE15-SP3 commit:
 *  fd350c7a3aa68716fb658bc84abddf20bd0ac827
 *
 *  SLE15-SP4 and -SP5 commit:
 *  ab6e024f092f7edc1b47d36ddc949e2fd33b2bc2
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

/* klp-ccp: from drivers/net/tun.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/if.h>

#include <linux/if_ether.h>
#include <linux/if_tun.h>

/* klp-ccp: from include/linux/if_tun.h */
#if defined(CONFIG_TUN) || defined(CONFIG_TUN_MODULE)

static void (*klpe_tun_ptr_free)(void *ptr);
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_TUN */

/* klp-ccp: from drivers/net/tun.c */
#include <linux/if_vlan.h>

#include <linux/nsproxy.h>

#include <linux/rcupdate.h>
#include <net/net_namespace.h>

#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/xdp.h>
#include <linux/seq_file.h>
#include <linux/uio.h>
#include <linux/skb_array.h>

#include <linux/mutex.h>

#include <linux/uaccess.h>

#define tun_debug(level, tun, fmt, args...)			\
do {								\
	if (0)							\
		netdev_printk(level, tun->dev, fmt, ##args);	\
} while (0)

#define FLT_EXACT_COUNT 8
struct tap_filter {
	unsigned int    count;    /* Number of addrs. Zero means disabled */
	u32             mask[2];  /* Mask of the hashed addrs */
	unsigned char	addr[FLT_EXACT_COUNT][ETH_ALEN];
};

#define MAX_TAP_QUEUES 256

struct tun_file {
	struct sock sk;
	struct socket socket;
	struct socket_wq wq;
	struct tun_struct __rcu *tun;
	struct fasync_struct *fasync;
	/* only used for fasnyc */
	unsigned int flags;
	union {
		u16 queue_index;
		unsigned int ifindex;
	};
	struct napi_struct napi;
	bool napi_enabled;
	bool napi_frags_enabled;
	struct mutex napi_mutex;	/* Protects access to the above napi */
	struct list_head next;
	struct tun_struct *detached;
	struct ptr_ring tx_ring;
	struct xdp_rxq_info xdp_rxq;
};

struct tun_flow_entry {
	struct hlist_node hash_link;
	struct rcu_head rcu;
	struct tun_struct *tun;

	u32 rxhash;
	u32 rps_rxhash;
	int queue_index;
	unsigned long updated;
};

#define TUN_NUM_FLOW_ENTRIES 1024

struct tun_struct {
	struct tun_file __rcu	*tfiles[MAX_TAP_QUEUES];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;

	struct net_device	*dev;
	netdev_features_t	set_features;

	int			align;
	int			vnet_hdr_sz;
	int			sndbuf;
	struct tap_filter	txflt;
	struct sock_fprog	fprog;
	/* protected by rtnl lock */
	bool			filter_attached;
#ifdef TUN_DEBUG
#error "klp-ccp: non-taken branch"
#endif
	spinlock_t lock;
	struct hlist_head flows[TUN_NUM_FLOW_ENTRIES];
	struct timer_list flow_gc_timer;
	unsigned long ageing_time;
	unsigned int numdisabled;
	struct list_head disabled;
	void *security;
	u32 flow_count;
	u32 rx_batched;
	struct tun_pcpu_stats __percpu *pcpu_stats;
	struct bpf_prog __rcu *xdp_prog;
	struct tun_prog __rcu *steering_prog;
	struct tun_prog __rcu *filter_prog;
	struct ethtool_link_ksettings link_ksettings;
};

static void tun_napi_disable(struct tun_file *tfile)
{
	if (tfile->napi_enabled)
		napi_disable(&tfile->napi);
}

static void tun_napi_del(struct tun_file *tfile)
{
	if (tfile->napi_enabled)
		netif_napi_del(&tfile->napi);
}

static void tun_flow_delete(struct tun_struct *tun, struct tun_flow_entry *e)
{
	tun_debug(KERN_INFO, tun, "delete flow: hash %u index %u\n",
		  e->rxhash, e->queue_index);
	hlist_del_rcu(&e->hash_link);
	kfree_rcu(e, rcu);
	--tun->flow_count;
}

static void tun_flow_delete_by_queue(struct tun_struct *tun, u16 queue_index)
{
	int i;

	spin_lock_bh(&tun->lock);
	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++) {
		struct tun_flow_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &tun->flows[i], hash_link) {
			if (e->queue_index == queue_index)
				tun_flow_delete(tun, e);
		}
	}
	spin_unlock_bh(&tun->lock);
}

static void tun_set_real_num_queues(struct tun_struct *tun)
{
	netif_set_real_num_tx_queues(tun->dev, tun->numqueues);
	netif_set_real_num_rx_queues(tun->dev, tun->numqueues);
}

static void tun_disable_queue(struct tun_struct *tun, struct tun_file *tfile)
{
	tfile->detached = tun;
	list_add_tail(&tfile->next, &tun->disabled);
	++tun->numdisabled;
}

static struct tun_struct *tun_enable_queue(struct tun_file *tfile)
{
	struct tun_struct *tun = tfile->detached;

	tfile->detached = NULL;
	list_del_init(&tfile->next);
	--tun->numdisabled;
	return tun;
}

static void (*klpe_tun_queue_purge)(struct tun_file *tfile);

void klpp___tun_detach(struct tun_file *tfile, bool clean)
{
	struct tun_file *ntfile;
	struct tun_struct *tun;

	tun = rtnl_dereference(tfile->tun);

	if (tun && clean) {
		tun_napi_disable(tfile);
		tun_napi_del(tfile);
	}

	if (tun && !tfile->detached) {
		u16 index = tfile->queue_index;
		BUG_ON(index >= tun->numqueues);

		rcu_assign_pointer(tun->tfiles[index],
				   tun->tfiles[tun->numqueues - 1]);
		ntfile = rtnl_dereference(tun->tfiles[index]);
		ntfile->queue_index = index;
		rcu_assign_pointer(tun->tfiles[tun->numqueues - 1],
				   NULL);

		--tun->numqueues;
		if (clean) {
			RCU_INIT_POINTER(tfile->tun, NULL);
			sock_put(&tfile->sk);
		} else
			tun_disable_queue(tun, tfile);

		synchronize_net();
		tun_flow_delete_by_queue(tun, tun->numqueues + 1);
		/* Drop read queue */
		(*klpe_tun_queue_purge)(tfile);
		tun_set_real_num_queues(tun);
	} else if (tfile->detached && clean) {
		tun = tun_enable_queue(tfile);
		sock_put(&tfile->sk);
	}

	if (clean) {
		if (tun && tun->numqueues == 0 && tun->numdisabled == 0) {
			netif_carrier_off(tun->dev);

			if (!(tun->flags & IFF_PERSIST) &&
			    tun->dev->reg_state == NETREG_REGISTERED)
				unregister_netdevice(tun->dev);
		}
		if (tun)
			xdp_rxq_info_unreg(&tfile->xdp_rxq);
		ptr_ring_cleanup(&tfile->tx_ring, (*klpe_tun_ptr_free));
	}
}

static void klpp_tun_detach(struct tun_file *tfile, bool clean)
{
	struct tun_struct *tun;
	struct net_device *dev;

	rtnl_lock();
	tun = rtnl_dereference(tfile->tun);
	dev = tun ? tun->dev : NULL;
	klpp___tun_detach(tfile, clean);
	if (dev)
		netdev_state_change(dev);
	rtnl_unlock();

	if (clean)
		sock_put(&tfile->sk);
}

int klpp_tun_chr_close(struct inode *inode, struct file *file)
{
	struct tun_file *tfile = file->private_data;

	klpp_tun_detach(tfile, true);

	return 0;
}


#include "livepatch_bsc1232818.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "tun"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tun_ptr_free", (void *)&klpe_tun_ptr_free, "tun" },
	{ "tun_queue_purge", (void *)&klpe_tun_queue_purge, "tun" },
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

int livepatch_bsc1232818_init(void)
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

void livepatch_bsc1232818_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
