/*
 * livepatch_bsc1249208
 *
 * Fix for CVE-2025-38617, bsc#1249208
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


#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/if_vlan.h>
#include <linux/virtio_net.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/percpu.h>
#ifdef CONFIG_INET
#include <net/inet_common.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <linux/bpf.h>
#include <net/compat.h>
#include <linux/netfilter_netdev.h>
/* klp-ccp: from net/packet/internal.h */
#include <linux/refcount.h>

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

	rwlock_t	blk_fill_in_prog_lock;

	/* Default is set to 8ms */

	unsigned short  retire_blk_tov;
	unsigned short  version;
	unsigned long	tov_in_jiffies;

	/* timer to retire an outstanding block */
	struct timer_list retire_blk_timer;
};

struct pgv {
	char *buffer;
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

	union {
		unsigned long			*rx_owner_map;
		struct tpacket_kbdq_core	prb_bdqc;
	};
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
	unsigned long		flags;
	int			ifindex;	/* bound device		*/
	u8			vnet_hdr_sz;
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
	struct packet_type	prot_hook ____cacheline_aligned_in_smp;
	atomic_t		tp_drops ____cacheline_aligned_in_smp;
};

#define pkt_sk(ptr) container_of_const(ptr, struct packet_sock, sk)

enum packet_sock_flags {
	PACKET_SOCK_ORIGDEV,
	PACKET_SOCK_AUXDATA,
	PACKET_SOCK_TX_HAS_OFF,
	PACKET_SOCK_TP_LOSS,
	PACKET_SOCK_RUNNING,
	PACKET_SOCK_PRESSURE,
	PACKET_SOCK_QDISC_BYPASS,
};

static inline bool packet_sock_flag(const struct packet_sock *po,
				    enum packet_sock_flags flag)
{
	return test_bit(flag, &po->flags);
}

/* klp-ccp: from net/packet/af_packet.c */
int klpp_packet_set_ring(struct sock *sk, union tpacket_req_u *req_u,
		int closing, int tx_ring);

#define V3_ALIGNMENT	(8)

#define BLK_HDR_LEN	(ALIGN(sizeof(struct tpacket_block_desc), V3_ALIGNMENT))

#define BLK_PLUS_PRIV(sz_of_priv) \
	(BLK_HDR_LEN + ALIGN((sz_of_priv), V3_ALIGNMENT))

extern int tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev);

extern void prb_open_block(struct tpacket_kbdq_core *,
		struct tpacket_block_desc *);
extern void prb_retire_rx_blk_timer_expired(struct timer_list *);

#define GET_PBDQC_FROM_RB(x)	((struct tpacket_kbdq_core *)(&(x)->prb_bdqc))

extern void __register_prot_hook(struct sock *sk);

static void register_prot_hook(struct sock *sk)
{
	lockdep_assert_held_once(&pkt_sk(sk)->bind_lock);
	__register_prot_hook(sk);
}

extern void __unregister_prot_hook(struct sock *sk, bool sync);

static void prb_del_retire_blk_timer(struct tpacket_kbdq_core *pkc)
{
	del_timer_sync(&pkc->retire_blk_timer);
}

static void prb_shutdown_retire_blk_timer(struct packet_sock *po,
		struct sk_buff_head *rb_queue)
{
	struct tpacket_kbdq_core *pkc;

	pkc = GET_PBDQC_FROM_RB(&po->rx_ring);

	spin_lock_bh(&rb_queue->lock);
	pkc->delete_blk_timer = 1;
	spin_unlock_bh(&rb_queue->lock);

	prb_del_retire_blk_timer(pkc);
}

static void prb_setup_retire_blk_timer(struct packet_sock *po)
{
	struct tpacket_kbdq_core *pkc;

	pkc = GET_PBDQC_FROM_RB(&po->rx_ring);
	timer_setup(&pkc->retire_blk_timer, prb_retire_rx_blk_timer_expired,
		    0);
	pkc->retire_blk_timer.expires = jiffies;
}

extern int prb_calc_retire_blk_tmo(struct packet_sock *po,
				int blk_size_in_bytes);

static void prb_init_ft_ops(struct tpacket_kbdq_core *p1,
			union tpacket_req_u *req_u)
{
	p1->feature_req_word = req_u->req3.tp_feature_req_word;
}

static void init_prb_bdqc(struct packet_sock *po,
			struct packet_ring_buffer *rb,
			struct pgv *pg_vec,
			union tpacket_req_u *req_u)
{
	struct tpacket_kbdq_core *p1 = GET_PBDQC_FROM_RB(rb);
	struct tpacket_block_desc *pbd;

	memset(p1, 0x0, sizeof(*p1));

	p1->knxt_seq_num = 1;
	p1->pkbdq = pg_vec;
	pbd = (struct tpacket_block_desc *)pg_vec[0].buffer;
	p1->pkblk_start	= pg_vec[0].buffer;
	p1->kblk_size = req_u->req3.tp_block_size;
	p1->knum_blocks	= req_u->req3.tp_block_nr;
	p1->hdrlen = po->tp_hdrlen;
	p1->version = po->tp_version;
	p1->last_kactive_blk_num = 0;
	po->stats.stats3.tp_freeze_q_cnt = 0;
	if (req_u->req3.tp_retire_blk_tov)
		p1->retire_blk_tov = req_u->req3.tp_retire_blk_tov;
	else
		p1->retire_blk_tov = prb_calc_retire_blk_tmo(po,
						req_u->req3.tp_block_size);
	p1->tov_in_jiffies = msecs_to_jiffies(p1->retire_blk_tov);
	p1->blk_sizeof_priv = req_u->req3.tp_sizeof_priv;
	rwlock_init(&p1->blk_fill_in_prog_lock);

	p1->max_frame_len = p1->kblk_size - BLK_PLUS_PRIV(p1->blk_sizeof_priv);
	prb_init_ft_ops(p1, req_u);
	prb_setup_retire_blk_timer(po);
	prb_open_block(p1, pbd);
}

void prb_retire_rx_blk_timer_expired(struct timer_list *t);

void prb_open_block(struct tpacket_kbdq_core *pkc1,
	struct tpacket_block_desc *pbd1);

static unsigned int packet_read_pending(const struct packet_ring_buffer *rb)
{
	unsigned int refcnt = 0;
	int cpu;

	/* We don't use pending refcount in rx_ring. */
	if (rb->pending_refcnt == NULL)
		return 0;

	for_each_possible_cpu(cpu)
		refcnt += *per_cpu_ptr(rb->pending_refcnt, cpu);

	return refcnt;
}

extern int packet_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev);

int tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev);

extern void free_pg_vec(struct pgv *pg_vec, unsigned int order,
			unsigned int len);

static char *alloc_one_pg_vec_page(unsigned long order)
{
	char *buffer;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP |
			  __GFP_ZERO | __GFP_NOWARN | __GFP_NORETRY;

	buffer = (char *) __get_free_pages(gfp_flags, order);
	if (buffer)
		return buffer;

	/* __get_free_pages failed, fall back to vmalloc */
	buffer = vzalloc(array_size((1 << order), PAGE_SIZE));
	if (buffer)
		return buffer;

	/* vmalloc failed, lets dig into swap here */
	gfp_flags &= ~__GFP_NORETRY;
	buffer = (char *) __get_free_pages(gfp_flags, order);
	if (buffer)
		return buffer;

	/* complete and utter failure */
	return NULL;
}

static struct pgv *alloc_pg_vec(struct tpacket_req *req, int order)
{
	unsigned int block_nr = req->tp_block_nr;
	struct pgv *pg_vec;
	int i;

	pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);
	if (unlikely(!pg_vec))
		goto out;

	for (i = 0; i < block_nr; i++) {
		pg_vec[i].buffer = alloc_one_pg_vec_page(order);
		if (unlikely(!pg_vec[i].buffer))
			goto out_free_pgvec;
	}

out:
	return pg_vec;

out_free_pgvec:
	free_pg_vec(pg_vec, order, block_nr);
	pg_vec = NULL;
	goto out;
}

int klpp_packet_set_ring(struct sock *sk, union tpacket_req_u *req_u,
		int closing, int tx_ring)
{
	struct pgv *pg_vec = NULL;
	struct packet_sock *po = pkt_sk(sk);
	unsigned long *rx_owner_map = NULL;
	int was_running, order = 0;
	struct packet_ring_buffer *rb;
	struct sk_buff_head *rb_queue;
	__be16 num;
	int err;
	/* Added to avoid minimal code churn */
	struct tpacket_req *req = &req_u->req;

	rb = tx_ring ? &po->tx_ring : &po->rx_ring;
	rb_queue = tx_ring ? &sk->sk_write_queue : &sk->sk_receive_queue;

	err = -EBUSY;
	if (!closing) {
		if (atomic_read(&po->mapped))
			goto out;
		if (packet_read_pending(rb))
			goto out;
	}

	if (req->tp_block_nr) {
		unsigned int min_frame_size;

		/* Sanity tests and some calculations */
		err = -EBUSY;
		if (unlikely(rb->pg_vec))
			goto out;

		switch (po->tp_version) {
		case TPACKET_V1:
			po->tp_hdrlen = TPACKET_HDRLEN;
			break;
		case TPACKET_V2:
			po->tp_hdrlen = TPACKET2_HDRLEN;
			break;
		case TPACKET_V3:
			po->tp_hdrlen = TPACKET3_HDRLEN;
			break;
		}

		err = -EINVAL;
		if (unlikely((int)req->tp_block_size <= 0))
			goto out;
		if (unlikely(!PAGE_ALIGNED(req->tp_block_size)))
			goto out;
		min_frame_size = po->tp_hdrlen + po->tp_reserve;
		if (po->tp_version >= TPACKET_V3 &&
		    req->tp_block_size <
		    BLK_PLUS_PRIV((u64)req_u->req3.tp_sizeof_priv) + min_frame_size)
			goto out;
		if (unlikely(req->tp_frame_size < min_frame_size))
			goto out;
		if (unlikely(req->tp_frame_size & (TPACKET_ALIGNMENT - 1)))
			goto out;

		rb->frames_per_block = req->tp_block_size / req->tp_frame_size;
		if (unlikely(rb->frames_per_block == 0))
			goto out;
		if (unlikely(rb->frames_per_block > UINT_MAX / req->tp_block_nr))
			goto out;
		if (unlikely((rb->frames_per_block * req->tp_block_nr) !=
					req->tp_frame_nr))
			goto out;

		err = -ENOMEM;
		order = get_order(req->tp_block_size);
		pg_vec = alloc_pg_vec(req, order);
		if (unlikely(!pg_vec))
			goto out;
		switch (po->tp_version) {
		case TPACKET_V3:
			/* Block transmit is not supported yet */
			if (!tx_ring) {
				init_prb_bdqc(po, rb, pg_vec, req_u);
			} else {
				struct tpacket_req3 *req3 = &req_u->req3;

				if (req3->tp_retire_blk_tov ||
				    req3->tp_sizeof_priv ||
				    req3->tp_feature_req_word) {
					err = -EINVAL;
					goto out_free_pg_vec;
				}
			}
			break;
		default:
			if (!tx_ring) {
				rx_owner_map = bitmap_alloc(req->tp_frame_nr,
					GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
				if (!rx_owner_map)
					goto out_free_pg_vec;
			}
			break;
		}
	}
	/* Done */
	else {
		err = -EINVAL;
		if (unlikely(req->tp_frame_nr))
			goto out;
	}
	/* Detach socket from network */
	spin_lock(&po->bind_lock);
	was_running = packet_sock_flag(po, PACKET_SOCK_RUNNING);
	num = po->num;
	WRITE_ONCE(po->num, 0);
	if (was_running)
		__unregister_prot_hook(sk, false);

	spin_unlock(&po->bind_lock);

	synchronize_net();

	err = -EBUSY;
	mutex_lock(&po->pg_vec_lock);
	if (closing || atomic_read(&po->mapped) == 0) {
		err = 0;
		spin_lock_bh(&rb_queue->lock);
		swap(rb->pg_vec, pg_vec);
		if (po->tp_version <= TPACKET_V2)
			swap(rb->rx_owner_map, rx_owner_map);
		rb->frame_max = (req->tp_frame_nr - 1);
		rb->head = 0;
		rb->frame_size = req->tp_frame_size;
		spin_unlock_bh(&rb_queue->lock);

		swap(rb->pg_vec_order, order);
		swap(rb->pg_vec_len, req->tp_block_nr);

		rb->pg_vec_pages = req->tp_block_size/PAGE_SIZE;
		po->prot_hook.func = (po->rx_ring.pg_vec) ?
						tpacket_rcv : packet_rcv;
		skb_queue_purge(rb_queue);
		if (atomic_read(&po->mapped))
			pr_err("packet_mmap: vma is busy: %d\n",
			       atomic_read(&po->mapped));
	}
	mutex_unlock(&po->pg_vec_lock);

	spin_lock(&po->bind_lock);
	WRITE_ONCE(po->num, num);
	if (was_running)
		register_prot_hook(sk);

	spin_unlock(&po->bind_lock);
	if (pg_vec && (po->tp_version > TPACKET_V2)) {
		/* Because we don't support block-based V3 on tx-ring */
		if (!tx_ring)
			prb_shutdown_retire_blk_timer(po, rb_queue);
	}

out_free_pg_vec:
	if (pg_vec) {
		bitmap_free(rx_owner_map);
		free_pg_vec(pg_vec, order, req->tp_block_nr);
	}
out:
	return err;
}


#include "livepatch_bsc1249208.h"

#include <linux/livepatch.h>

extern typeof(__register_prot_hook) __register_prot_hook
	 KLP_RELOC_SYMBOL(af_packet, af_packet, __register_prot_hook);
extern typeof(__unregister_prot_hook) __unregister_prot_hook
	 KLP_RELOC_SYMBOL(af_packet, af_packet, __unregister_prot_hook);
extern typeof(free_pg_vec) free_pg_vec
	 KLP_RELOC_SYMBOL(af_packet, af_packet, free_pg_vec);
extern typeof(packet_rcv) packet_rcv
	 KLP_RELOC_SYMBOL(af_packet, af_packet, packet_rcv);
extern typeof(prb_calc_retire_blk_tmo) prb_calc_retire_blk_tmo
	 KLP_RELOC_SYMBOL(af_packet, af_packet, prb_calc_retire_blk_tmo);
extern typeof(prb_open_block) prb_open_block
	 KLP_RELOC_SYMBOL(af_packet, af_packet, prb_open_block);
extern typeof(prb_retire_rx_blk_timer_expired) prb_retire_rx_blk_timer_expired
	 KLP_RELOC_SYMBOL(af_packet, af_packet, prb_retire_rx_blk_timer_expired);
extern typeof(tpacket_rcv) tpacket_rcv
	 KLP_RELOC_SYMBOL(af_packet, af_packet, tpacket_rcv);
