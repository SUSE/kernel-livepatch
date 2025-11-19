/*
 * livepatch_bsc1242882
 *
 * Fix for CVE-2025-23145, bsc#1242882
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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



/* klp-ccp: from net/mptcp/subflow.c */
#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <crypto/algapi.h>

/* klp-ccp: from include/crypto/sha2.h */
#define SHA256_DIGEST_SIZE      32

/* klp-ccp: from net/mptcp/subflow.c */
#include <net/sock.h>

#include <net/inet_hashtables.h>

#include <net/tcp.h>

#include <net/mptcp.h>

/* klp-ccp: from include/uapi/linux/mptcp.h */
#define _UAPI_MPTCP_H

#define MPTCP_RST_EMPTCP	1

#define MPTCP_RST_EPROHIBIT	3

/* klp-ccp: from net/mptcp/protocol.h */
#include <linux/random.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/mptcp.h>

#define OPTION_MPTCP_MPC_SYN	BIT(0)
#define OPTION_MPTCP_MPC_SYNACK	BIT(1)
#define OPTION_MPTCP_MPC_ACK	BIT(2)
#define OPTION_MPTCP_MPJ_SYN	BIT(3)
#define OPTION_MPTCP_MPJ_SYNACK	BIT(4)
#define OPTION_MPTCP_MPJ_ACK	BIT(5)

#define OPTIONS_MPTCP_MPC	(OPTION_MPTCP_MPC_SYN | OPTION_MPTCP_MPC_SYNACK | \
				 OPTION_MPTCP_MPC_ACK)
#define OPTIONS_MPTCP_MPJ	(OPTION_MPTCP_MPJ_SYN | OPTION_MPTCP_MPJ_SYNACK | \
				 OPTION_MPTCP_MPJ_ACK)

struct mptcp_options_received {
	u64	sndr_key;
	u64	rcvr_key;
	u64	data_ack;
	u64	data_seq;
	u32	subflow_seq;
	u16	data_len;
	__sum16	csum;
	u16	suboptions;
	u32	token;
	u32	nonce;
	u16	use_map:1,
		dsn64:1,
		data_fin:1,
		use_ack:1,
		ack64:1,
		mpc_map:1,
		reset_reason:4,
		reset_transient:1,
		echo:1,
		backup:1,
		deny_join_id0:1,
		__unused:2;
	u8	join_id;
	u64	thmac;
	u8	hmac[MPTCPOPT_HMAC_LEN];
	struct mptcp_addr_info addr;
	struct mptcp_rm_list rm_list;
	u64	ahmac;
	u64	fail_seq;
};

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

	u32 setsockopt_seq;
	char		ca_name[TCP_CA_NAME_MAX];
};

#define mptcp_sk(ptr) container_of_const(ptr, struct mptcp_sock, sk.icsk_inet.sk)

struct mptcp_subflow_request_sock {
	struct	tcp_request_sock sk;
	u16	mp_capable : 1,
		mp_join : 1,
		backup : 1,
		csum_reqd : 1,
		allow_join_id0 : 1;
	u8	local_id;
	u8	remote_id;
	u64	local_key;
	u64	idsn;
	u32	token;
	u32	ssn_offset;
	u64	thmac;
	u32	local_nonce;
	u32	remote_nonce;
	struct mptcp_sock	*msk;
	struct hlist_nulls_node token_node;
};

static inline struct mptcp_subflow_request_sock *
mptcp_subflow_rsk(const struct request_sock *rsk)
{
	return (struct mptcp_subflow_request_sock *)rsk;
}

enum mptcp_data_avail {
	MPTCP_SUBFLOW_NODATA,
	MPTCP_SUBFLOW_DATA_AVAIL,
};

struct mptcp_subflow_context {
	struct	list_head node;/* conn_list of subflows */

	struct_group(reset,

	unsigned long avg_pacing_rate; /* protected by msk socket lock */
	u64	local_key;
	u64	remote_key;
	u64	idsn;
	u64	map_seq;
	u32	snd_isn;
	u32	token;
	u32	rel_write_seq;
	u32	map_subflow_seq;
	u32	ssn_offset;
	u32	map_data_len;
	__wsum	map_data_csum;
	u32	map_csum_len;
	u32	request_mptcp : 1,  /* send MP_CAPABLE */
		request_join : 1,   /* send MP_JOIN */
		request_bkup : 1,
		mp_capable : 1,	    /* remote is MPTCP capable */
		mp_join : 1,	    /* remote is JOINing */
		fully_established : 1,	    /* path validated */
		pm_notified : 1,    /* PM hook called for established status */
		conn_finished : 1,
		map_valid : 1,
		map_csum_reqd : 1,
		map_data_fin : 1,
		mpc_map : 1,
		backup : 1,
		send_mp_prio : 1,
		send_mp_fail : 1,
		send_fastclose : 1,
		send_infinite_map : 1,
		remote_key_valid : 1,        /* received the peer key from */
		disposable : 1,	    /* ctx can be free at ulp release time */
		stale : 1,	    /* unable to snd/rcv data, do not use for xmit */
		valid_csum_seen : 1,        /* at least one csum validated */
		is_mptfo : 1,	    /* subflow is doing TFO */
		__unused : 10;
	enum mptcp_data_avail data_avail;
	u32	remote_nonce;
	u64	thmac;
	u32	local_nonce;
	u32	remote_token;
	union {
		u8	hmac[MPTCPOPT_HMAC_LEN]; /* MPJ subflow only */
		u64	iasn;	    /* initial ack sequence number, MPC subflows only */
	};
	s16	local_id;	    /* if negative not initialized yet */
	u8	remote_id;
	u8	reset_seen:1;
	u8	reset_transient:1;
	u8	reset_reason:4;
	u8	stale_count;

	long	delegated_status;
	unsigned long	fail_tout;

	);

	struct	list_head delegated_node;   /* link into delegated_action, protected by local BH */

	u32	setsockopt_seq;
	u32	stale_rcv_tstamp;

	struct	sock *tcp_sock;	    /* tcp sk backpointer */
	struct	sock *conn;	    /* parent mptcp_sock */
	const	struct inet_connection_sock_af_ops *icsk_af_ops;
	void	(*tcp_state_change)(struct sock *sk);
	void	(*tcp_error_report)(struct sock *sk);

	struct	rcu_head rcu;
};

static inline struct mptcp_subflow_context *
mptcp_subflow_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* Use RCU on icsk_ulp_data only for sock diag code */
	return (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
}

void mptcp_subflow_fully_established(struct mptcp_subflow_context *subflow,
				     const struct mptcp_options_received *mp_opt);

void mptcp_subflow_drop_ctx(struct sock *ssk);

struct sock *mptcp_sk_clone_init(const struct sock *sk,
				 const struct mptcp_options_received *mp_opt,
				 struct sock *ssk,
				 struct request_sock *req);
void mptcp_get_options(const struct sk_buff *skb,
		       struct mptcp_options_received *mp_opt);

bool mptcp_finish_join(struct sock *sk);

void mptcp_crypto_hmac_sha(u64 key1, u64 key2, u8 *msg, int len, void *hmac);

void mptcp_pm_new_connection(struct mptcp_sock *msk, const struct sock *ssk, int server_side);
void mptcp_pm_fully_established(struct mptcp_sock *msk, const struct sock *ssk);

bool mptcp_pm_sport_in_anno_list(struct mptcp_sock *msk, const struct sock *sk);

/* klp-ccp: from net/mptcp/mib.h */
enum linux_mptcp_mib_field {
	MPTCP_MIB_NUM = 0,
	MPTCP_MIB_MPCAPABLEPASSIVE,	/* Received SYN with MP_CAPABLE */
	MPTCP_MIB_MPCAPABLEACTIVE,	/* Sent SYN with MP_CAPABLE */
	MPTCP_MIB_MPCAPABLEACTIVEACK,	/* Received SYN/ACK with MP_CAPABLE */
	MPTCP_MIB_MPCAPABLEPASSIVEACK,	/* Received third ACK with MP_CAPABLE */
	MPTCP_MIB_MPCAPABLEPASSIVEFALLBACK,/* Server-side fallback during 3-way handshake */
	MPTCP_MIB_MPCAPABLEACTIVEFALLBACK, /* Client-side fallback during 3-way handshake */
	MPTCP_MIB_TOKENFALLBACKINIT,	/* Could not init/allocate token */
	MPTCP_MIB_RETRANSSEGS,		/* Segments retransmitted at the MPTCP-level */
	MPTCP_MIB_JOINNOTOKEN,		/* Received MP_JOIN but the token was not found */
	MPTCP_MIB_JOINSYNRX,		/* Received a SYN + MP_JOIN */
	MPTCP_MIB_JOINSYNACKRX,		/* Received a SYN/ACK + MP_JOIN */
	MPTCP_MIB_JOINSYNACKMAC,	/* HMAC was wrong on SYN/ACK + MP_JOIN */
	MPTCP_MIB_JOINACKRX,		/* Received an ACK + MP_JOIN */
	MPTCP_MIB_JOINACKMAC,		/* HMAC was wrong on ACK + MP_JOIN */
	MPTCP_MIB_DSSNOMATCH,		/* Received a new mapping that did not match the previous one */
#ifndef __GENKSYMS__
	MPTCP_MIB_DSSCORRUPTIONFALLBACK,/* DSS corruption detected, fallback */
	MPTCP_MIB_DSSCORRUPTIONRESET,	/* DSS corruption detected, MPJ subflow reset */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	MPTCP_MIB_INFINITEMAPTX,	/* Sent an infinite mapping */
	MPTCP_MIB_INFINITEMAPRX,	/* Received an infinite mapping */
	MPTCP_MIB_DSSTCPMISMATCH,	/* DSS-mapping did not map with TCP's sequence numbers */
	MPTCP_MIB_DATACSUMERR,		/* The data checksum fail */
	MPTCP_MIB_OFOQUEUETAIL,	/* Segments inserted into OoO queue tail */
	MPTCP_MIB_OFOQUEUE,		/* Segments inserted into OoO queue */
	MPTCP_MIB_OFOMERGE,		/* Segments merged in OoO queue */
	MPTCP_MIB_NODSSWINDOW,		/* Segments not in MPTCP windows */
	MPTCP_MIB_DUPDATA,		/* Segments discarded due to duplicate DSS */
	MPTCP_MIB_ADDADDR,		/* Received ADD_ADDR with echo-flag=0 */
	MPTCP_MIB_ECHOADD,		/* Received ADD_ADDR with echo-flag=1 */
	MPTCP_MIB_PORTADD,		/* Received ADD_ADDR with a port-number */
	MPTCP_MIB_ADDADDRDROP,		/* Dropped incoming ADD_ADDR */
	MPTCP_MIB_JOINPORTSYNRX,	/* Received a SYN MP_JOIN with a different port-number */
	MPTCP_MIB_JOINPORTSYNACKRX,	/* Received a SYNACK MP_JOIN with a different port-number */
	MPTCP_MIB_JOINPORTACKRX,	/* Received an ACK MP_JOIN with a different port-number */
	MPTCP_MIB_MISMATCHPORTSYNRX,	/* Received a SYN MP_JOIN with a mismatched port-number */
	MPTCP_MIB_MISMATCHPORTACKRX,	/* Received an ACK MP_JOIN with a mismatched port-number */
	MPTCP_MIB_RMADDR,		/* Received RM_ADDR */
	MPTCP_MIB_RMADDRDROP,		/* Dropped incoming RM_ADDR */
	MPTCP_MIB_RMSUBFLOW,		/* Remove a subflow */
	MPTCP_MIB_MPPRIOTX,		/* Transmit a MP_PRIO */
	MPTCP_MIB_MPPRIORX,		/* Received a MP_PRIO */
	MPTCP_MIB_MPFAILTX,		/* Transmit a MP_FAIL */
	MPTCP_MIB_MPFAILRX,		/* Received a MP_FAIL */
	MPTCP_MIB_MPFASTCLOSETX,	/* Transmit a MP_FASTCLOSE */
	MPTCP_MIB_MPFASTCLOSERX,	/* Received a MP_FASTCLOSE */
	MPTCP_MIB_MPRSTTX,		/* Transmit a MP_RST */
	MPTCP_MIB_MPRSTRX,		/* Received a MP_RST */
	MPTCP_MIB_RCVPRUNED,		/* Incoming packet dropped due to memory limit */
	MPTCP_MIB_SUBFLOWSTALE,		/* Subflows entered 'stale' status */
	MPTCP_MIB_SUBFLOWRECOVER,	/* Subflows returned to active status after being stale */
	MPTCP_MIB_SNDWNDSHARED,		/* Subflow snd wnd is overridden by msk's one */
	MPTCP_MIB_RCVWNDSHARED,		/* Subflow rcv wnd is overridden by msk's one */
	MPTCP_MIB_RCVWNDCONFLICTUPDATE,	/* subflow rcv wnd is overridden by msk's one due to
					 * conflict with another subflow while updating msk rcv wnd
					 */
	MPTCP_MIB_RCVWNDCONFLICT,	/* Conflict with while updating msk rcv wnd */
	__MPTCP_MIB_MAX
};

#define LINUX_MIB_MPTCP_MAX	__MPTCP_MIB_MAX
struct mptcp_mib {
	unsigned long mibs[LINUX_MIB_MPTCP_MAX];
};

static inline void MPTCP_INC_STATS(struct net *net,
				   enum linux_mptcp_mib_field field)
{
	if (likely(net->mib.mptcp_statistics))
		SNMP_INC_STATS(net->mib.mptcp_statistics, field);
}

/* klp-ccp: from net/mptcp/subflow.c */
static void SUBFLOW_REQ_INC_STATS(struct request_sock *req,
				  enum linux_mptcp_mib_field field)
{
	MPTCP_INC_STATS(sock_net(req_to_sk(req)), field);
}

static void subflow_generate_hmac(u64 key1, u64 key2, u32 nonce1, u32 nonce2,
				  void *hmac)
{
	u8 msg[8];

	put_unaligned_be32(nonce1, &msg[0]);
	put_unaligned_be32(nonce2, &msg[4]);

	mptcp_crypto_hmac_sha(key1, key2, msg, 8, hmac);
}

extern bool mptcp_can_accept_new_subflow(const struct mptcp_sock *msk);

static bool subflow_use_different_sport(struct mptcp_sock *msk, const struct sock *sk)
{
	return inet_sk(sk)->inet_sport != inet_sk((struct sock *)msk)->inet_sport;
}

extern void subflow_add_reset_reason(struct sk_buff *skb, u8 reason);

static bool klpp_subflow_hmac_valid(const struct request_sock *req,
			       const struct mptcp_options_received *mp_opt)
{
	const struct mptcp_subflow_request_sock *subflow_req;
	u8 hmac[SHA256_DIGEST_SIZE];
	struct mptcp_sock *msk;

	subflow_req = mptcp_subflow_rsk(req);
	msk = subflow_req->msk;

	subflow_generate_hmac(msk->remote_key, msk->local_key,
			      subflow_req->remote_nonce,
			      subflow_req->local_nonce, hmac);

	return !crypto_memneq(hmac, mp_opt->hmac, MPTCPOPT_HMAC_LEN);
}


struct sock *klpp_subflow_syn_recv_sock(const struct sock *sk,
					  struct sk_buff *skb,
					  struct request_sock *req,
					  struct dst_entry *dst,
					  struct request_sock *req_unhash,
					  bool *own_req)
{
	struct mptcp_subflow_context *listener = mptcp_subflow_ctx(sk);
	struct mptcp_subflow_request_sock *subflow_req;
	struct mptcp_options_received mp_opt;
	bool fallback, fallback_is_fatal;
	struct mptcp_sock *owner;
	struct sock *child;

	pr_debug("listener=%p, req=%p, conn=%p", listener, req, listener->conn);

	/* After child creation we must look for MPC even when options
	 * are not parsed
	 */
	mp_opt.suboptions = 0;

	/* hopefully temporary handling for MP_JOIN+syncookie */
	subflow_req = mptcp_subflow_rsk(req);
	fallback_is_fatal = tcp_rsk(req)->is_mptcp && subflow_req->mp_join;
	fallback = !tcp_rsk(req)->is_mptcp;
	if (fallback)
		goto create_child;

	/* if the sk is MP_CAPABLE, we try to fetch the client key */
	if (subflow_req->mp_capable) {
		/* we can receive and accept an in-window, out-of-order pkt,
		 * which may not carry the MP_CAPABLE opt even on mptcp enabled
		 * paths: always try to extract the peer key, and fallback
		 * for packets missing it.
		 * Even OoO DSS packets coming legitly after dropped or
		 * reordered MPC will cause fallback, but we don't have other
		 * options.
		 */
		mptcp_get_options(skb, &mp_opt);
		if (!(mp_opt.suboptions & OPTIONS_MPTCP_MPC))
			fallback = true;

	} else if (subflow_req->mp_join) {
		mptcp_get_options(skb, &mp_opt);
		if (!(mp_opt.suboptions & OPTIONS_MPTCP_MPJ))
			fallback = true;
	}

create_child:
	child = listener->icsk_af_ops->syn_recv_sock(sk, skb, req, dst,
						     req_unhash, own_req);

	if (child && *own_req) {
		struct mptcp_subflow_context *ctx = mptcp_subflow_ctx(child);

		tcp_rsk(req)->drop_req = false;

		/* we need to fallback on ctx allocation failure and on pre-reqs
		 * checking above. In the latter scenario we additionally need
		 * to reset the context to non MPTCP status.
		 */
		if (!ctx || fallback) {
			if (fallback_is_fatal) {
				subflow_add_reset_reason(skb, MPTCP_RST_EMPTCP);
				goto dispose_child;
			}
			goto fallback;
		}

		/* ssk inherits options of listener sk */
		ctx->setsockopt_seq = listener->setsockopt_seq;

		if (ctx->mp_capable) {
			ctx->conn = mptcp_sk_clone_init(listener->conn, &mp_opt, child, req);
			if (!ctx->conn)
				goto fallback;

			owner = mptcp_sk(ctx->conn);
			mptcp_pm_new_connection(owner, child, 1);

			/* with OoO packets we can reach here without ingress
			 * mpc option
			 */
			if (mp_opt.suboptions & OPTION_MPTCP_MPC_ACK) {
				mptcp_subflow_fully_established(ctx, &mp_opt);
				mptcp_pm_fully_established(owner, child);
				ctx->pm_notified = 1;
			}
		} else if (ctx->mp_join) {
			owner = subflow_req->msk;
			if (!owner) {
				subflow_add_reset_reason(skb, MPTCP_RST_EPROHIBIT);
				goto dispose_child;
			}

			if (!klpp_subflow_hmac_valid(req, &mp_opt) ||
			    !mptcp_can_accept_new_subflow(subflow_req->msk)) {
				SUBFLOW_REQ_INC_STATS(req, MPTCP_MIB_JOINACKMAC);
				subflow_add_reset_reason(skb, MPTCP_RST_EPROHIBIT);
				goto dispose_child;
			}

			/* move the msk reference ownership to the subflow */
			subflow_req->msk = NULL;
			ctx->conn = (struct sock *)owner;

			if (subflow_use_different_sport(owner, sk)) {
				pr_debug("ack inet_sport=%d %d",
					 ntohs(inet_sk(sk)->inet_sport),
					 ntohs(inet_sk((struct sock *)owner)->inet_sport));
				if (!mptcp_pm_sport_in_anno_list(owner, sk)) {
					SUBFLOW_REQ_INC_STATS(req, MPTCP_MIB_MISMATCHPORTACKRX);
					goto dispose_child;
				}
				SUBFLOW_REQ_INC_STATS(req, MPTCP_MIB_JOINPORTACKRX);
			}

			if (!mptcp_finish_join(child))
				goto dispose_child;

			SUBFLOW_REQ_INC_STATS(req, MPTCP_MIB_JOINACKRX);
			tcp_rsk(req)->drop_req = true;
		}
	}

	/* check for expected invariant - should never trigger, just help
	 * catching eariler subtle bugs
	 */
	WARN_ON_ONCE(child && *own_req && tcp_sk(child)->is_mptcp &&
		     (!mptcp_subflow_ctx(child) ||
		      !mptcp_subflow_ctx(child)->conn));
	return child;

dispose_child:
	mptcp_subflow_drop_ctx(child);
	tcp_rsk(req)->drop_req = true;
	inet_csk_prepare_for_destroy_sock(child);
	tcp_done(child);
	req->rsk_ops->send_reset(sk, skb);

	/* The last child reference will be released by the caller */
	return child;

fallback:
	mptcp_subflow_drop_ctx(child);
	return child;
}


#include "livepatch_bsc1242882.h"

#include <linux/livepatch.h>

extern typeof(mptcp_can_accept_new_subflow) mptcp_can_accept_new_subflow
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_can_accept_new_subflow);
extern typeof(mptcp_crypto_hmac_sha) mptcp_crypto_hmac_sha
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_crypto_hmac_sha);
extern typeof(mptcp_finish_join) mptcp_finish_join
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_finish_join);
extern typeof(mptcp_get_options) mptcp_get_options
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_get_options);
extern typeof(mptcp_pm_fully_established) mptcp_pm_fully_established
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_pm_fully_established);
extern typeof(mptcp_pm_new_connection) mptcp_pm_new_connection
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_pm_new_connection);
extern typeof(mptcp_pm_sport_in_anno_list) mptcp_pm_sport_in_anno_list
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_pm_sport_in_anno_list);
extern typeof(mptcp_sk_clone_init) mptcp_sk_clone_init
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_sk_clone_init);
extern typeof(mptcp_subflow_drop_ctx) mptcp_subflow_drop_ctx
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_subflow_drop_ctx);
extern typeof(mptcp_subflow_fully_established) mptcp_subflow_fully_established
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_subflow_fully_established);
extern typeof(subflow_add_reset_reason) subflow_add_reset_reason
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, subflow_add_reset_reason);
