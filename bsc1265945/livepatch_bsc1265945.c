/*
 * livepatch_bsc1265945
 *
 * Fix for CVE-2026-43494, bsc#1265945
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


#include "livepatch_bsc1265945.h"


/* klp-ccp: from net/rds/message.c */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/errqueue.h>
/* klp-ccp: from net/rds/rds.h */
#include <net/sock.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <rdma/rdma_cm.h>
#include <linux/mutex.h>
#include <linux/rds.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <linux/in6.h>

#define RDS_HEADER_EXT_SPACE	16

struct rds_header {
	__be64	h_sequence;
	__be64	h_ack;
	__be32	h_len;
	__be16	h_sport;
	__be16	h_dport;
	u8	h_flags;
	u8	h_credit;
	u8	h_padding[4];
	__sum16	h_csum;

	u8	h_exthdr[RDS_HEADER_EXT_SPACE];
};

#define RDS_RX_MAX_TRACES	(RDS_MSG_RX_DGRAM_TRACE_MAX + 1)

struct rds_inc_usercopy {
	rds_rdma_cookie_t	rdma_cookie;
	ktime_t			rx_tstamp;
};

struct rds_incoming {
	refcount_t		i_refcount;
	struct list_head	i_item;
	struct rds_connection	*i_conn;
	struct rds_conn_path	*i_conn_path;
	struct rds_header	i_hdr;
	unsigned long		i_rx_jiffies;
	struct in6_addr		i_saddr;

	struct rds_inc_usercopy i_usercopy;
	u64			i_rx_lat_trace[RDS_RX_MAX_TRACES];
};

struct rds_znotifier {
	struct mmpin		z_mmp;
	u32			z_cookie;
};

struct rds_msg_zcopy_info {
	struct list_head rs_zcookie_next;
	union {
		struct rds_znotifier znotif;
		struct rds_zcopy_cookies zcookies;
	};
};

struct rds_message {
	refcount_t		m_refcount;
	struct list_head	m_sock_item;
	struct list_head	m_conn_item;
	struct rds_incoming	m_inc;
	u64			m_ack_seq;
	struct in6_addr		m_daddr;
	unsigned long		m_flags;

	/* Never access m_rs without holding m_rs_lock.
	 * Lock nesting is
	 *  rm->m_rs_lock
	 *   -> rs->rs_lock
	 */
	spinlock_t		m_rs_lock;
	wait_queue_head_t	m_flush_wait;

	struct rds_sock		*m_rs;

	/* cookie to send to remote, in rds header */
	rds_rdma_cookie_t	m_rdma_cookie;

	unsigned int		m_used_sgs;
	unsigned int		m_total_sgs;

	void			*m_final_op;

	struct {
		struct rm_atomic_op {
			int			op_type;
			union {
				struct {
					uint64_t	compare;
					uint64_t	swap;
					uint64_t	compare_mask;
					uint64_t	swap_mask;
				} op_m_cswp;
				struct {
					uint64_t	add;
					uint64_t	nocarry_mask;
				} op_m_fadd;
			};

			u32			op_rkey;
			u64			op_remote_addr;
			unsigned int		op_notify:1;
			unsigned int		op_recverr:1;
			unsigned int		op_mapped:1;
			unsigned int		op_silent:1;
			unsigned int		op_active:1;
			struct scatterlist	*op_sg;
			struct rds_notifier	*op_notifier;

			struct rds_mr		*op_rdma_mr;
		} atomic;
		struct rm_rdma_op {
			u32			op_rkey;
			u64			op_remote_addr;
			unsigned int		op_write:1;
			unsigned int		op_fence:1;
			unsigned int		op_notify:1;
			unsigned int		op_recverr:1;
			unsigned int		op_mapped:1;
			unsigned int		op_silent:1;
			unsigned int		op_active:1;
			unsigned int		op_bytes;
			unsigned int		op_nents;
			unsigned int		op_count;
			struct scatterlist	*op_sg;
			struct rds_notifier	*op_notifier;

			struct rds_mr		*op_rdma_mr;

			u64			op_odp_addr;
			struct rds_mr		*op_odp_mr;
		} rdma;
		struct rm_data_op {
			unsigned int		op_active:1;
			unsigned int		op_nents;
			unsigned int		op_count;
			unsigned int		op_dmasg;
			unsigned int		op_dmaoff;
			struct rds_znotifier	*op_mmp_znotifier;
			struct scatterlist	*op_sg;
		} data;
	};

	struct rds_conn_path *m_conn_path;
};

struct rds_statistics {
	uint64_t	s_conn_reset;
	uint64_t	s_recv_drop_bad_checksum;
	uint64_t	s_recv_drop_old_seq;
	uint64_t	s_recv_drop_no_sock;
	uint64_t	s_recv_drop_dead_sock;
	uint64_t	s_recv_deliver_raced;
	uint64_t	s_recv_delivered;
	uint64_t	s_recv_queued;
	uint64_t	s_recv_immediate_retry;
	uint64_t	s_recv_delayed_retry;
	uint64_t	s_recv_ack_required;
	uint64_t	s_recv_rdma_bytes;
	uint64_t	s_recv_ping;
	uint64_t	s_send_queue_empty;
	uint64_t	s_send_queue_full;
	uint64_t	s_send_lock_contention;
	uint64_t	s_send_lock_queue_raced;
	uint64_t	s_send_immediate_retry;
	uint64_t	s_send_delayed_retry;
	uint64_t	s_send_drop_acked;
	uint64_t	s_send_ack_required;
	uint64_t	s_send_queued;
	uint64_t	s_send_rdma;
	uint64_t	s_send_rdma_bytes;
	uint64_t	s_send_pong;
	uint64_t	s_page_remainder_hit;
	uint64_t	s_page_remainder_miss;
	uint64_t	s_copy_to_user;
	uint64_t	s_copy_from_user;
	uint64_t	s_cong_update_queued;
	uint64_t	s_cong_update_received;
	uint64_t	s_cong_send_error;
	uint64_t	s_cong_send_blocked;
	uint64_t	s_recv_bytes_added_to_socket;
	uint64_t	s_recv_bytes_removed_from_socket;
	uint64_t	s_send_stuck_rm;
};

int klpp_rds_message_copy_from_user(struct rds_message *rm, struct iov_iter *from,
			       bool zcopy);

int rds_page_remainder_alloc(struct scatterlist *scat, unsigned long bytes,
			     gfp_t gfp);

extern __attribute__((section(".data..percpu" ""))) __typeof__(struct rds_statistics) rds_stats __attribute__((__aligned__((1 << (6)))));

#define rds_stats_add_which(which, member, count) do {		\
	per_cpu(which, get_cpu()).member += count;	\
	put_cpu();					\
} while (0)
#define rds_stats_add(member, count) rds_stats_add_which(rds_stats, member, count)

/* klp-ccp: from net/rds/message.c */
static int klpp_rds_message_zcopy_from_user(struct rds_message *rm, struct iov_iter *from)
{
	struct scatterlist *sg;
	int ret = 0;
	int length = iov_iter_count(from);
	struct rds_msg_zcopy_info *info;

	rm->m_inc.i_hdr.h_len = cpu_to_be32(iov_iter_count(from));

	/*
	 * now allocate and copy in the data payload.
	 */
	sg = rm->data.op_sg;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	INIT_LIST_HEAD(&info->rs_zcookie_next);
	rm->data.op_mmp_znotifier = &info->znotif;
	if (mm_account_pinned_pages(&rm->data.op_mmp_znotifier->z_mmp,
				    length)) {
		ret = -ENOMEM;
		goto err;
	}
	while (iov_iter_count(from)) {
		struct page *pages;
		size_t start;
		ssize_t copied;

		copied = iov_iter_get_pages2(from, &pages, PAGE_SIZE,
					    1, &start);
		if (copied < 0) {
			struct mmpin *mmp;
			int i;

			for (i = 0; i < rm->data.op_nents; i++)
				put_page(sg_page(&rm->data.op_sg[i]));
			rm->data.op_nents = 0;
			mmp = &rm->data.op_mmp_znotifier->z_mmp;
			mm_unaccount_pinned_pages(mmp);
			ret = -EFAULT;
			goto err;
		}
		length -= copied;
		sg_set_page(sg, pages, copied, start);
		rm->data.op_nents++;
		sg++;
	}
	WARN_ON_ONCE(length != 0);
	return ret;
err:
	kfree(info);
	rm->data.op_mmp_znotifier = NULL;
	return ret;
}

int klpp_rds_message_copy_from_user(struct rds_message *rm, struct iov_iter *from,
			       bool zcopy)
{
	unsigned long to_copy, nbytes;
	unsigned long sg_off;
	struct scatterlist *sg;
	int ret = 0;

	rm->m_inc.i_hdr.h_len = cpu_to_be32(iov_iter_count(from));

	/* now allocate and copy in the data payload.  */
	sg = rm->data.op_sg;
	sg_off = 0; /* Dear gcc, sg->page will be null from kzalloc. */

	if (zcopy)
		return klpp_rds_message_zcopy_from_user(rm, from);

	while (iov_iter_count(from)) {
		if (!sg_page(sg)) {
			ret = rds_page_remainder_alloc(sg, iov_iter_count(from),
						       GFP_HIGHUSER);
			if (ret)
				return ret;
			rm->data.op_nents++;
			sg_off = 0;
		}

		to_copy = min_t(unsigned long, iov_iter_count(from),
				sg->length - sg_off);

		rds_stats_add(s_copy_from_user, to_copy);
		nbytes = copy_page_from_iter(sg_page(sg), sg->offset + sg_off,
					     to_copy, from);
		if (nbytes != to_copy)
			return -EFAULT;

		sg_off += to_copy;

		if (sg_off == sg->length)
			sg++;
	}

	return ret;
}


#include <linux/livepatch.h>

extern typeof(rds_page_remainder_alloc) rds_page_remainder_alloc
	 KLP_RELOC_SYMBOL(rds, rds, rds_page_remainder_alloc);
extern typeof(rds_stats) rds_stats KLP_RELOC_SYMBOL(rds, rds, rds_stats);
