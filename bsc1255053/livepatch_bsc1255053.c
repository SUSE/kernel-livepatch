/*
 * livepatch_bsc1255053
 *
 * Fix for CVE-2025-40258, bsc#1255053
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1255053.h"


#define CC_USING_FENTRY 1
/* klp-ccp: from net/mptcp/protocol.c */
#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched/signal.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
#include <net/transp_v6.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <net/mptcp.h>
#include <net/xfrm.h>
#include <asm/ioctls.h>
/* klp-ccp: from net/mptcp/protocol.h */
#include <linux/random.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/mptcp.h>
#include <net/genetlink.h>

#define MPTCP_PM_MAX_ADDR_ID		U8_MAX

struct mptcp_pm_data {
	struct mptcp_addr_info local;
	struct mptcp_addr_info remote;
	struct list_head anno_list;
	struct list_head userspace_pm_local_addr_list;

	spinlock_t	lock;		/*protects the whole PM data */

	u8		addr_signal;
	bool		server_side;
	bool		work_pending;
	bool		accept_addr;
	bool		accept_subflow;
	bool		remote_deny_join_id0;
	u8		add_addr_signaled;
	u8		add_addr_accepted;
	u8		local_addr_used;
	u8		pm_type;
	u8		subflows;
	u8		status;
	DECLARE_BITMAP(id_avail_bitmap, MPTCP_PM_MAX_ADDR_ID + 1);
	struct mptcp_rm_list rm_list_tx;
	struct mptcp_rm_list rm_list_rx;
};

struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct inet_connection_sock sk;
	u64		local_key;
	u64		remote_key;
	u64		write_seq;
	u64		snd_nxt;
	u64		ack_seq;
	atomic64_t	rcv_wnd_sent;
	u64		rcv_data_fin_seq;
	int		rmem_fwd_alloc;
#ifndef __GENKSYMS__
	spinlock_t	fallback_lock;	/* protects fallback,
					 * allow_infinite_fallback and
					 * allow_join
					 */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct sock	*last_snd;
	int		snd_burst;
	int		old_wspace;
	u64		recovery_snd_nxt;	/* in recovery mode accept up to this seq;
						 * recovery related fields are under data_lock
						 * protection
						 */
	u64		snd_una;
	u64		wnd_end;
	unsigned long	timer_ival;
	u32		token;
	int		rmem_released;
	unsigned long	flags;
	unsigned long	cb_flags;
	unsigned long	push_pending;
	bool		recovery;		/* closing subflow write queue reinjected */
	bool		can_ack;
	bool		fully_established;
	bool		rcv_data_fin;
	bool		snd_data_fin_enable;
	bool		rcv_fastclose;
	bool		use_64bit_ack; /* Set when we received a 64-bit DSN */
	bool		csum_enabled;
	bool		allow_infinite_fallback;
	u8		mpc_endpoint_id;
	u8		recvmsg_inq:1,
			cork:1,
			nodelay:1,
			fastopening:1,
			in_accept_queue:1;
#ifndef __GENKSYMS__
	u8		pending_state; /* A subflow asked to set this sk_state,
					* protected by the msk data lock
					*/
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct work_struct work;
	struct sk_buff  *ooo_last_skb;
	struct rb_root  out_of_order_queue;
	struct sk_buff_head receive_queue;
	struct list_head conn_list;
	struct list_head rtx_queue;
	struct mptcp_data_frag *first_pending;
	struct list_head join_list;
	struct socket	*subflow; /* outgoing connect/listener/!mp_capable
				   * The mptcp ops can safely dereference, using suitable
				   * ONCE annotation, the subflow outside the socket
				   * lock as such sock is freed after close().
				   */
	struct sock	*first;
	struct mptcp_pm_data	pm;
	struct {
		u32	space;	/* bytes copied in last measurement window */
		u32	copied; /* bytes copied in this measurement window */
		u64	time;	/* start time of measurement window */
		u64	rtt_us; /* last maximum rtt of subflows */
	} rcvq_space;
	u8		scaling_ratio;
#ifndef __GENKSYMS__
	bool		allow_subflows;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u32 setsockopt_seq;
	char		ca_name[TCP_CA_NAME_MAX];
};

#define mptcp_sk(ptr) container_of_const(ptr, struct mptcp_sock, sk.icsk_inet.sk)


/* klp-ccp: from net/mptcp/protocol.c */
bool klpp_mptcp_schedule_work(struct sock *sk)
{
	if (inet_sk_state_load(sk) == TCP_CLOSE)
		return false;

	/* Get a reference on this socket, mptcp_worker() will release it.
	 * As mptcp_worker() might complete before us, we can not avoid
	 * a sock_hold()/sock_put() if schedule_work() returns false.
	 */
	sock_hold(sk);

	if (schedule_work(&mptcp_sk(sk)->work))
		return true;

	sock_put(sk);
	return false;
}


