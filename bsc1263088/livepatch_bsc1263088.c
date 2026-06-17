/*
 * livepatch_bsc1263088
 *
 * Fix for CVE-2026-31504, bsc#1263088
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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


/* klp-ccp: from net/packet/af_packet.c */
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>

#include <linux/kernel.h>

/* klp-ccp: from net/packet/af_packet.c */
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/ip.h>

#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/io.h>

#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/if_vlan.h>

#include <linux/net_tstamp.h>
#include <linux/percpu.h>

/* klp-ccp: from net/packet/internal.h */
struct packet_mclist {
	struct packet_mclist	*next;
	int			ifindex;
	int			count;
	unsigned short		type;
	unsigned short		alen;
	unsigned char		addr[MAX_ADDR_LEN];
};

struct tpacket_kbdq_core {
	struct pgv	*pkbdq;
	unsigned int	feature_req_word;
	unsigned int	hdrlen;
	unsigned char	reset_pending_on_curr_blk;
	unsigned char   delete_blk_timer;
	unsigned short	kactive_blk_num;
	unsigned short	blk_sizeof_priv;

	/* last_kactive_blk_num:
	 * trick to see if user-space has caught up
	 * in order to avoid refreshing timer when every single pkt arrives.
	 */
	unsigned short	last_kactive_blk_num;

	char		*pkblk_start;
	char		*pkblk_end;
	int		kblk_size;
	unsigned int	max_frame_len;
	unsigned int	knum_blocks;
	uint64_t	knxt_seq_num;
	char		*prev;
	char		*nxt_offset;
	struct sk_buff	*skb;

	atomic_t	blk_fill_in_prog;

	/* Default is set to 8ms */

	unsigned short  retire_blk_tov;
	unsigned short  version;
	unsigned long	tov_in_jiffies;

	/* timer to retire an outstanding block */
	struct timer_list retire_blk_timer;
};

struct packet_ring_buffer {
	struct pgv		*pg_vec;

	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	unsigned int		frame_max;

	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	unsigned int __percpu	*pending_refcnt;

	struct tpacket_kbdq_core	prb_bdqc;
};

static struct mutex (*klpe_fanout_mutex);
#define PACKET_FANOUT_MAX	256

struct packet_fanout {
	possible_net_t		net;
	unsigned int		num_members;
	u16			id;
	u8			type;
	u8			flags;
	union {
		atomic_t		rr_cur;
		struct bpf_prog __rcu	*bpf_prog;
	};
	struct list_head	list;
	struct sock		*arr[PACKET_FANOUT_MAX];
	spinlock_t		lock;
	atomic_t		sk_ref;
	struct packet_type	prot_hook ____cacheline_aligned_in_smp;
};

struct packet_sock {
	/* struct sock has to be the first member of packet_sock */
	struct sock		sk;
	struct packet_fanout	*fanout;
	union  tpacket_stats_u	stats;
	struct packet_ring_buffer	rx_ring;
	struct packet_ring_buffer	tx_ring;
	int			copy_thresh;
	spinlock_t		bind_lock;
	struct mutex		pg_vec_lock;
	unsigned int		running;	/* bind_lock must be held */
	unsigned int		auxdata:1,	/* writer must hold sock lock */
				origdev:1,
				has_vnet_hdr:1,
				tp_loss:1,
				tp_tx_has_off:1;
	int			pressure;
	int			ifindex;	/* bound device		*/
	__be16			num;
	struct packet_rollover	*rollover;
	struct packet_mclist	*mclist;
	atomic_t		mapped;
	enum tpacket_versions	tp_version;
	unsigned int		tp_hdrlen;
	unsigned int		tp_reserve;
	unsigned int		tp_tstamp;
	struct completion	skb_completion;
	struct net_device __rcu	*cached_dev;
	int			(*xmit)(struct sk_buff *skb);
	struct packet_type	prot_hook ____cacheline_aligned_in_smp;
};

static struct packet_sock *pkt_sk(struct sock *sk)
{
	return (struct packet_sock *)sk;
}

/* klp-ccp: from net/packet/af_packet.c */
static int (*klpe_packet_set_ring)(struct sock *sk, union tpacket_req_u *req_u,
		int closing, int tx_ring);

static void klpr_packet_flush_mclist(struct sock *sk);

static void packet_cached_dev_reset(struct packet_sock *po)
{
	RCU_INIT_POINTER(po->cached_dev, NULL);
}

static void (*klpe___unregister_prot_hook)(struct sock *sk, bool sync);

static void klpr_unregister_prot_hook(struct sock *sk, bool sync)
{
	struct packet_sock *po = pkt_sk(sk);

	if (po->running)
		(*klpe___unregister_prot_hook)(sk, sync);
}

static void packet_free_pending(struct packet_sock *po)
{
	free_percpu(po->tx_ring.pending_refcnt);
}

extern typeof((*klpe_fanout_mutex)) (*klpe_fanout_mutex);

static void (*klpe___fanout_set_data_bpf)(struct packet_fanout *f, struct bpf_prog *new);

static void klpr_fanout_release_data(struct packet_fanout *f)
{
	switch (f->type) {
	case PACKET_FANOUT_CBPF:
	case PACKET_FANOUT_EBPF:
		(*klpe___fanout_set_data_bpf)(f, NULL);
	}
}

static struct packet_fanout *klpr_fanout_release(struct sock *sk)
{
	struct packet_sock *po = pkt_sk(sk);
	struct packet_fanout *f;

	mutex_lock(&(*klpe_fanout_mutex));
	f = po->fanout;
	if (f) {
		po->fanout = NULL;

		if (atomic_dec_and_test(&f->sk_ref))
			list_del(&f->list);
		else
			f = NULL;
	}
	mutex_unlock(&(*klpe_fanout_mutex));

	return f;
}

int klpp_packet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct packet_sock *po;
	struct packet_fanout *f;
	struct net *net;
	union tpacket_req_u req_u;

	if (!sk)
		return 0;

	net = sock_net(sk);
	po = pkt_sk(sk);

	mutex_lock(&net->packet.sklist_lock);
	sk_del_node_init_rcu(sk);
	mutex_unlock(&net->packet.sklist_lock);

	preempt_disable();
	sock_prot_inuse_add(net, sk->sk_prot, -1);
	preempt_enable();

	spin_lock(&po->bind_lock);
	klpr_unregister_prot_hook(sk, false);
	WRITE_ONCE(po->num, 0);
	packet_cached_dev_reset(po);

	if (po->prot_hook.dev) {
		dev_put(po->prot_hook.dev);
		po->prot_hook.dev = NULL;
	}
	spin_unlock(&po->bind_lock);

	klpr_packet_flush_mclist(sk);

	lock_sock(sk);
	if (po->rx_ring.pg_vec) {
		memset(&req_u, 0, sizeof(req_u));
		(*klpe_packet_set_ring)(sk, &req_u, 1, 0);
	}

	if (po->tx_ring.pg_vec) {
		memset(&req_u, 0, sizeof(req_u));
		(*klpe_packet_set_ring)(sk, &req_u, 1, 1);
	}
	release_sock(sk);

	f = klpr_fanout_release(sk);

	synchronize_net();

	kfree(po->rollover);
	if (f) {
		klpr_fanout_release_data(f);
		kfree(f);
	}
	/*
	 *	Now the socket is dead. No more input will appear.
	 */
	sock_orphan(sk);
	sock->sk = NULL;

	/* Purge queues */

	skb_queue_purge(&sk->sk_receive_queue);
	packet_free_pending(po);
	sk_refcnt_debug_release(sk);

	sock_put(sk);
	return 0;
}

static int (*klpe_packet_dev_mc)(struct net_device *dev, struct packet_mclist *i,
			 int what);

static void klpr_packet_flush_mclist(struct sock *sk)
{
	struct packet_sock *po = pkt_sk(sk);
	struct packet_mclist *ml;

	if (!po->mclist)
		return;

	rtnl_lock();
	while ((ml = po->mclist) != NULL) {
		struct net_device *dev;

		po->mclist = ml->next;
		dev = __dev_get_by_index(sock_net(sk), ml->ifindex);
		if (dev != NULL)
			(*klpe_packet_dev_mc)(dev, ml, -1);
		kfree(ml);
	}
	rtnl_unlock();
}

static int (*klpe_packet_set_ring)(struct sock *sk, union tpacket_req_u *req_u,
		int closing, int tx_ring);


#include "livepatch_bsc1263088.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "af_packet"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__fanout_set_data_bpf", (void *)&klpe___fanout_set_data_bpf,
	  "af_packet" },
	{ "__unregister_prot_hook", (void *)&klpe___unregister_prot_hook,
	  "af_packet" },
	{ "fanout_mutex", (void *)&klpe_fanout_mutex, "af_packet" },
	{ "packet_dev_mc", (void *)&klpe_packet_dev_mc, "af_packet" },
	{ "packet_set_ring", (void *)&klpe_packet_set_ring, "af_packet" },
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

int livepatch_bsc1263088_init(void)
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

void livepatch_bsc1263088_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
