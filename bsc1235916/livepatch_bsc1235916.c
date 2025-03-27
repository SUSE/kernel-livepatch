/*
 * livepatch_bsc1235916
 *
 * Fix for CVE-2024-57882, bsc#1235916
 *
 *  Upstream commit:
 *  cbb26f7d8451 ("mptcp: fix TCP options overflow.")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  bfacfe0fd0d1aae8bc11df861b30890e72bfc92b
 *
 *  SLE MICRO-6-0 commit:
 *  bfacfe0fd0d1aae8bc11df861b30890e72bfc92b
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/mptcp/options.c */
#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>

#include <net/tcp.h>

/* klp-ccp: from net/mptcp/options.c */
#include <net/mptcp.h>

/* klp-ccp: from net/mptcp/protocol.h */
#include <linux/random.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

#define OPTION_MPTCP_MPC_SYN	BIT(0)
#define OPTION_MPTCP_MPC_SYNACK	BIT(1)
#define OPTION_MPTCP_MPC_ACK	BIT(2)

#define OPTION_MPTCP_MPJ_ACK	BIT(5)
#define OPTION_MPTCP_ADD_ADDR	BIT(6)
#define OPTION_MPTCP_RM_ADDR	BIT(7)
#define OPTION_MPTCP_FASTCLOSE	BIT(8)
#define OPTION_MPTCP_PRIO	BIT(9)
#define OPTION_MPTCP_RST	BIT(10)
#define OPTION_MPTCP_DSS	BIT(11)
#define OPTION_MPTCP_FAIL	BIT(12)

#define OPTIONS_MPTCP_MPC	(OPTION_MPTCP_MPC_SYN | OPTION_MPTCP_MPC_SYNACK | \
				 OPTION_MPTCP_MPC_ACK)

#define TCPOLEN_MPTCP_MPC_ACK		20
#define TCPOLEN_MPTCP_MPC_ACK_DATA	22

#define TCPOLEN_MPTCP_MPJ_ACK		24
#define TCPOLEN_MPTCP_DSS_BASE		4
#define TCPOLEN_MPTCP_DSS_ACK32		4
#define TCPOLEN_MPTCP_DSS_ACK64		8

#define TCPOLEN_MPTCP_DSS_MAP64		14
#define TCPOLEN_MPTCP_DSS_CHECKSUM	2

#define TCPOLEN_MPTCP_ADD_ADDR_BASE	8

#define TCPOLEN_MPTCP_ADD_ADDR6_BASE	20

#define TCPOLEN_MPTCP_PORT_LEN		2
#define TCPOLEN_MPTCP_PORT_ALIGN	2
#define TCPOLEN_MPTCP_RM_ADDR_BASE	3

#define TCPOLEN_MPTCP_PRIO_ALIGN	4
#define TCPOLEN_MPTCP_FASTCLOSE		12
#define TCPOLEN_MPTCP_RST		4
#define TCPOLEN_MPTCP_FAIL		12

#define MPTCPOPT_THMAC_LEN	8

#define MPTCP_FALLBACK_DONE	4

enum mptcp_addr_signal_status {
	MPTCP_ADD_ADDR_SIGNAL,
	MPTCP_ADD_ADDR_ECHO,
	MPTCP_RM_ADDR_SIGNAL,
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

static inline int __mptcp_rmem(const struct sock *sk)
{
	return atomic_read(&sk->sk_rmem_alloc) - READ_ONCE(mptcp_sk(sk)->rmem_released);
}

static inline int __mptcp_space(const struct sock *sk)
{
	return tcp_win_from_space(sk, READ_ONCE(sk->sk_rcvbuf) - __mptcp_rmem(sk));
}

enum mptcp_data_avail {
	MPTCP_SUBFLOW_NODATA,
	MPTCP_SUBFLOW_DATA_AVAIL,
};

struct mptcp_delegated_action {
	struct napi_struct napi;
	struct list_head head;
};

extern struct mptcp_delegated_action __percpu mptcp_delegated_actions;

#define MPTCP_DELEGATE_ACK		1

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
		local_id_valid : 1, /* local_id is correctly initialized */
		valid_csum_seen : 1,        /* at least one csum validated */
		is_mptfo : 1,	    /* subflow is doing TFO */
		__unused : 9;
	enum mptcp_data_avail data_avail;
	u32	remote_nonce;
	u64	thmac;
	u32	local_nonce;
	u32	remote_token;
	union {
		u8	hmac[MPTCPOPT_HMAC_LEN]; /* MPJ subflow only */
		u64	iasn;	    /* initial ack sequence number, MPC subflows only */
	};
	u8	local_id;
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

static inline struct sock *
mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

static inline void mptcp_subflow_delegate(struct mptcp_subflow_context *subflow, int action)
{
	struct mptcp_delegated_action *delegated;
	bool schedule;

	/* the caller held the subflow bh socket lock */
	lockdep_assert_in_softirq();

	/* The implied barrier pairs with mptcp_subflow_delegated_done(), and
	 * ensures the below list check sees list updates done prior to status
	 * bit changes
	 */
	if (!test_and_set_bit(action, &subflow->delegated_status)) {
		/* still on delegated list from previous scheduling */
		if (!list_empty(&subflow->delegated_node))
			return;

		delegated = this_cpu_ptr(&mptcp_delegated_actions);
		schedule = list_empty(&delegated->head);
		list_add_tail(&subflow->delegated_node, &delegated->head);
		sock_hold(mptcp_subflow_tcp_sock(subflow));
		if (schedule)
			napi_schedule(&delegated->napi);
	}
}

int mptcp_allow_join_id0(const struct net *net);

static inline bool mptcp_data_fin_enabled(const struct mptcp_sock *msk)
{
	return READ_ONCE(msk->snd_data_fin_enable) &&
	       READ_ONCE(msk->write_seq) == READ_ONCE(msk->snd_nxt);
}

static inline bool mptcp_pm_should_add_signal(struct mptcp_sock *msk)
{
	return READ_ONCE(msk->pm.addr_signal) &
		(BIT(MPTCP_ADD_ADDR_SIGNAL) | BIT(MPTCP_ADD_ADDR_ECHO));
}

static inline bool mptcp_pm_should_rm_signal(struct mptcp_sock *msk)
{
	return READ_ONCE(msk->pm.addr_signal) & BIT(MPTCP_RM_ADDR_SIGNAL);
}

static inline unsigned int mptcp_add_addr_len(int family, bool echo, bool port)
{
	u8 len = TCPOLEN_MPTCP_ADD_ADDR_BASE;

	if (family == AF_INET6)
		len = TCPOLEN_MPTCP_ADD_ADDR6_BASE;
	if (!echo)
		len += MPTCPOPT_THMAC_LEN;
	/* account for 2 trailing 'nop' options */
	if (port)
		len += TCPOLEN_MPTCP_PORT_LEN + TCPOLEN_MPTCP_PORT_ALIGN;

	return len;
}

static inline int mptcp_rm_addr_len(const struct mptcp_rm_list *rm_list)
{
	if (rm_list->nr == 0 || rm_list->nr > MPTCP_RM_IDS_MAX)
		return -EINVAL;

	return TCPOLEN_MPTCP_RM_ADDR_BASE + roundup(rm_list->nr - 1, 4) + 1;
}

bool mptcp_pm_add_addr_signal(struct mptcp_sock *msk, const struct sk_buff *skb,
			      unsigned int opt_size, unsigned int remaining,
			      struct mptcp_addr_info *addr, bool *echo,
			      bool *drop_other_suboptions);
bool mptcp_pm_rm_addr_signal(struct mptcp_sock *msk, unsigned int remaining,
			     struct mptcp_rm_list *rm_list);

static inline struct mptcp_ext *mptcp_get_ext(const struct sk_buff *skb)
{
	return (struct mptcp_ext *)skb_ext_find(skb, SKB_EXT_MPTCP);
}

static inline bool __mptcp_check_fallback(const struct mptcp_sock *msk)
{
	return test_bit(MPTCP_FALLBACK_DONE, &msk->flags);
}

static inline bool mptcp_check_infinite_map(struct sk_buff *skb)
{
	struct mptcp_ext *mpext;

	mpext = skb ? mptcp_get_ext(skb) : NULL;
	if (mpext && mpext->infinite_map)
		return true;

	return false;
}

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

/* klp-ccp: from net/mptcp/options.c */
static bool mptcp_established_options_mp(struct sock *sk, struct sk_buff *skb,
					 bool snd_data_fin_enable,
					 unsigned int *size,
					 struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);
	struct mptcp_ext *mpext;
	unsigned int data_len;
	u8 len;

	/* When skb is not available, we better over-estimate the emitted
	 * options len. A full DSS option (28 bytes) is longer than
	 * TCPOLEN_MPTCP_MPC_ACK_DATA(22) or TCPOLEN_MPTCP_MPJ_ACK(24), so
	 * tell the caller to defer the estimate to
	 * mptcp_established_options_dss(), which will reserve enough space.
	 */
	if (!skb)
		return false;

	/* MPC/MPJ needed only on 3rd ack packet, DATA_FIN and TCP shutdown take precedence */
	if (subflow->fully_established || snd_data_fin_enable ||
	    subflow->snd_isn != TCP_SKB_CB(skb)->seq ||
	    sk->sk_state != TCP_ESTABLISHED)
		return false;

	if (subflow->mp_capable) {
		mpext = mptcp_get_ext(skb);
		data_len = mpext ? mpext->data_len : 0;

		/* we will check ops->data_len in mptcp_write_options() to
		 * discriminate between TCPOLEN_MPTCP_MPC_ACK_DATA and
		 * TCPOLEN_MPTCP_MPC_ACK
		 */
		opts->data_len = data_len;
		opts->suboptions = OPTION_MPTCP_MPC_ACK;
		opts->sndr_key = subflow->local_key;
		opts->rcvr_key = subflow->remote_key;
		opts->csum_reqd = READ_ONCE(msk->csum_enabled);
		opts->allow_join_id0 = mptcp_allow_join_id0(sock_net(sk));

		/* Section 3.1.
		 * The MP_CAPABLE option is carried on the SYN, SYN/ACK, and ACK
		 * packets that start the first subflow of an MPTCP connection,
		 * as well as the first packet that carries data
		 */
		if (data_len > 0) {
			len = TCPOLEN_MPTCP_MPC_ACK_DATA;
			if (opts->csum_reqd) {
				/* we need to propagate more info to csum the pseudo hdr */
				opts->data_seq = mpext->data_seq;
				opts->subflow_seq = mpext->subflow_seq;
				opts->csum = mpext->csum;
				len += TCPOLEN_MPTCP_DSS_CHECKSUM;
			}
			*size = ALIGN(len, 4);
		} else {
			*size = TCPOLEN_MPTCP_MPC_ACK;
		}

		pr_debug("subflow=%p, local_key=%llu, remote_key=%llu map_len=%d",
			 subflow, subflow->local_key, subflow->remote_key,
			 data_len);

		return true;
	} else if (subflow->mp_join) {
		opts->suboptions = OPTION_MPTCP_MPJ_ACK;
		memcpy(opts->hmac, subflow->hmac, MPTCPOPT_HMAC_LEN);
		*size = TCPOLEN_MPTCP_MPJ_ACK;
		pr_debug("subflow=%p", subflow);

		/* we can use the full delegate action helper only from BH context
		 * If we are in process context - sk is flushing the backlog at
		 * socket lock release time - just set the appropriate flag, will
		 * be handled by the release callback
		 */
		if (sock_owned_by_user(sk))
			set_bit(MPTCP_DELEGATE_ACK, &subflow->delegated_status);
		else
			mptcp_subflow_delegate(subflow, MPTCP_DELEGATE_ACK);
		return true;
	}
	return false;
}

static void mptcp_write_data_fin(struct mptcp_subflow_context *subflow,
				 struct sk_buff *skb, struct mptcp_ext *ext)
{
	/* The write_seq value has already been incremented, so the actual
	 * sequence number for the DATA_FIN is one less.
	 */
	u64 data_fin_tx_seq = READ_ONCE(mptcp_sk(subflow->conn)->write_seq) - 1;

	if (!ext->use_map || !skb->len) {
		/* RFC6824 requires a DSS mapping with specific values
		 * if DATA_FIN is set but no data payload is mapped
		 */
		ext->data_fin = 1;
		ext->use_map = 1;
		ext->dsn64 = 1;
		ext->data_seq = data_fin_tx_seq;
		ext->subflow_seq = 0;
		ext->data_len = 1;
	} else if (ext->data_seq + ext->data_len == data_fin_tx_seq) {
		/* If there's an existing DSS mapping and it is the
		 * final mapping, DATA_FIN consumes 1 additional byte of
		 * mapping space.
		 */
		ext->data_fin = 1;
		ext->data_len++;
	}
}

static bool mptcp_established_options_dss(struct sock *sk, struct sk_buff *skb,
					  bool snd_data_fin_enable,
					  unsigned int *size,
					  struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);
	unsigned int dss_size = 0;
	struct mptcp_ext *mpext;
	unsigned int ack_size;
	bool ret = false;
	u64 ack_seq;

	opts->csum_reqd = READ_ONCE(msk->csum_enabled);
	mpext = skb ? mptcp_get_ext(skb) : NULL;

	if (!skb || (mpext && mpext->use_map) || snd_data_fin_enable) {
		unsigned int map_size = TCPOLEN_MPTCP_DSS_BASE + TCPOLEN_MPTCP_DSS_MAP64;

		if (mpext) {
			if (opts->csum_reqd)
				map_size += TCPOLEN_MPTCP_DSS_CHECKSUM;

			opts->ext_copy = *mpext;
		}

		dss_size = map_size;
		if (skb && snd_data_fin_enable)
			mptcp_write_data_fin(subflow, skb, &opts->ext_copy);
		opts->suboptions = OPTION_MPTCP_DSS;
		ret = true;
	}

	/* passive sockets msk will set the 'can_ack' after accept(), even
	 * if the first subflow may have the already the remote key handy
	 */
	opts->ext_copy.use_ack = 0;
	if (!READ_ONCE(msk->can_ack)) {
		*size = ALIGN(dss_size, 4);
		return ret;
	}

	ack_seq = READ_ONCE(msk->ack_seq);
	if (READ_ONCE(msk->use_64bit_ack)) {
		ack_size = TCPOLEN_MPTCP_DSS_ACK64;
		opts->ext_copy.data_ack = ack_seq;
		opts->ext_copy.ack64 = 1;
	} else {
		ack_size = TCPOLEN_MPTCP_DSS_ACK32;
		opts->ext_copy.data_ack32 = (uint32_t)ack_seq;
		opts->ext_copy.ack64 = 0;
	}
	opts->ext_copy.use_ack = 1;
	opts->suboptions = OPTION_MPTCP_DSS;
	WRITE_ONCE(msk->old_wspace, __mptcp_space((struct sock *)msk));

	/* Add kind/length/subtype/flag overhead if mapping is not populated */
	if (dss_size == 0)
		ack_size += TCPOLEN_MPTCP_DSS_BASE;

	dss_size += ack_size;

	*size = ALIGN(dss_size, 4);
	return true;
}

extern u64 add_addr_generate_hmac(u64 key1, u64 key2,
				  struct mptcp_addr_info *addr);

static bool klpp_mptcp_established_options_add_addr(struct sock *sk, struct sk_buff *skb,
					       unsigned int *size,
					       unsigned int remaining,
					       struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);
	bool drop_other_suboptions = false;
	unsigned int opt_size = *size;
	bool echo;
	int len;

	/* add addr will strip the existing options, be sure to avoid breaking
	 * MPC/MPJ handshakes
	 */
	if (!mptcp_pm_should_add_signal(msk) ||
	    (opts->suboptions & (OPTION_MPTCP_MPJ_ACK | OPTION_MPTCP_MPC_ACK)) ||
	    !mptcp_pm_add_addr_signal(msk, skb, opt_size, remaining, &opts->addr,
		    &echo, &drop_other_suboptions))
		return false;

	/*
	 * Later on, mptcp_write_options() will enforce mutually exclusion with
	 * DSS, bail out if such option is set and we can't drop it.
	 */
	if (drop_other_suboptions)
		remaining += opt_size;
	else if (opts->suboptions & OPTION_MPTCP_DSS)
		return false;

	len = mptcp_add_addr_len(opts->addr.family, echo, !!opts->addr.port);
	if (remaining < len)
		return false;

	*size = len;
	if (drop_other_suboptions) {
		pr_debug("drop other suboptions");
		opts->suboptions = 0;

		/* note that e.g. DSS could have written into the memory
		 * aliased by ahmac, we must reset the field here
		 * to avoid appending the hmac even for ADD_ADDR echo
		 * options
		 */
		opts->ahmac = 0;
		*size -= opt_size;
	}
	opts->suboptions |= OPTION_MPTCP_ADD_ADDR;
	if (!echo) {
		opts->ahmac = add_addr_generate_hmac(msk->local_key,
						     msk->remote_key,
						     &opts->addr);
	}
	pr_debug("addr_id=%d, ahmac=%llu, echo=%d, port=%d",
		 opts->addr.id, opts->ahmac, echo, ntohs(opts->addr.port));

	return true;
}

static bool mptcp_established_options_rm_addr(struct sock *sk,
					      unsigned int *size,
					      unsigned int remaining,
					      struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);
	struct mptcp_rm_list rm_list;
	int i, len;

	if (!mptcp_pm_should_rm_signal(msk) ||
	    !(mptcp_pm_rm_addr_signal(msk, remaining, &rm_list)))
		return false;

	len = mptcp_rm_addr_len(&rm_list);
	if (len < 0)
		return false;
	if (remaining < len)
		return false;

	*size = len;
	opts->suboptions |= OPTION_MPTCP_RM_ADDR;
	opts->rm_list = rm_list;

	for (i = 0; i < opts->rm_list.nr; i++)
		pr_debug("rm_list_ids[%d]=%d", i, opts->rm_list.ids[i]);

	return true;
}

static bool mptcp_established_options_mp_prio(struct sock *sk,
					      unsigned int *size,
					      unsigned int remaining,
					      struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

	/* can't send MP_PRIO with MPC, as they share the same option space:
	 * 'backup'. Also it makes no sense at all
	 */
	if (!subflow->send_mp_prio || (opts->suboptions & OPTIONS_MPTCP_MPC))
		return false;

	/* account for the trailing 'nop' option */
	if (remaining < TCPOLEN_MPTCP_PRIO_ALIGN)
		return false;

	*size = TCPOLEN_MPTCP_PRIO_ALIGN;
	opts->suboptions |= OPTION_MPTCP_PRIO;
	opts->backup = subflow->request_bkup;

	pr_debug("prio=%d", opts->backup);

	return true;
}

static noinline bool mptcp_established_options_rst(struct sock *sk, struct sk_buff *skb,
						   unsigned int *size,
						   unsigned int remaining,
						   struct mptcp_out_options *opts)
{
	const struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

	if (remaining < TCPOLEN_MPTCP_RST)
		return false;

	*size = TCPOLEN_MPTCP_RST;
	opts->suboptions |= OPTION_MPTCP_RST;
	opts->reset_transient = subflow->reset_transient;
	opts->reset_reason = subflow->reset_reason;
	MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPRSTTX);

	return true;
}

static bool mptcp_established_options_fastclose(struct sock *sk,
						unsigned int *size,
						unsigned int remaining,
						struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);

	if (likely(!subflow->send_fastclose))
		return false;

	if (remaining < TCPOLEN_MPTCP_FASTCLOSE)
		return false;

	*size = TCPOLEN_MPTCP_FASTCLOSE;
	opts->suboptions |= OPTION_MPTCP_FASTCLOSE;
	opts->rcvr_key = msk->remote_key;

	pr_debug("FASTCLOSE key=%llu", opts->rcvr_key);
	MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPFASTCLOSETX);
	return true;
}

static bool mptcp_established_options_mp_fail(struct sock *sk,
					      unsigned int *size,
					      unsigned int remaining,
					      struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

	if (likely(!subflow->send_mp_fail))
		return false;

	if (remaining < TCPOLEN_MPTCP_FAIL)
		return false;

	*size = TCPOLEN_MPTCP_FAIL;
	opts->suboptions |= OPTION_MPTCP_FAIL;
	opts->fail_seq = subflow->map_seq;

	pr_debug("MP_FAIL fail_seq=%llu", opts->fail_seq);
	MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPFAILTX);

	return true;
}

bool klpp_mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);
	unsigned int opt_size = 0;
	bool snd_data_fin;
	bool ret = false;

	opts->suboptions = 0;

	if (unlikely(__mptcp_check_fallback(msk) && !mptcp_check_infinite_map(skb)))
		return false;

	if (unlikely(skb && TCP_SKB_CB(skb)->tcp_flags & TCPHDR_RST)) {
		if (mptcp_established_options_fastclose(sk, &opt_size, remaining, opts) ||
		    mptcp_established_options_mp_fail(sk, &opt_size, remaining, opts)) {
			*size += opt_size;
			remaining -= opt_size;
		}
		/* MP_RST can be used with MP_FASTCLOSE and MP_FAIL if there is room */
		if (mptcp_established_options_rst(sk, skb, &opt_size, remaining, opts)) {
			*size += opt_size;
			remaining -= opt_size;
		}
		return true;
	}

	snd_data_fin = mptcp_data_fin_enabled(msk);
	if (mptcp_established_options_mp(sk, skb, snd_data_fin, &opt_size, opts))
		ret = true;
	else if (mptcp_established_options_dss(sk, skb, snd_data_fin, &opt_size, opts)) {
		unsigned int mp_fail_size;

		ret = true;
		if (mptcp_established_options_mp_fail(sk, &mp_fail_size,
						      remaining - opt_size, opts)) {
			*size += opt_size + mp_fail_size;
			remaining -= opt_size - mp_fail_size;
			return true;
		}
	}

	/* we reserved enough space for the above options, and exceeding the
	 * TCP option space would be fatal
	 */
	if (WARN_ON_ONCE(opt_size > remaining))
		return false;

	*size += opt_size;
	remaining -= opt_size;
	if (klpp_mptcp_established_options_add_addr(sk, skb, &opt_size, remaining, opts)) {
		*size += opt_size;
		remaining -= opt_size;
		ret = true;
	} else if (mptcp_established_options_rm_addr(sk, &opt_size, remaining, opts)) {
		*size += opt_size;
		remaining -= opt_size;
		ret = true;
	}

	if (mptcp_established_options_mp_prio(sk, &opt_size, remaining, opts)) {
		*size += opt_size;
		remaining -= opt_size;
		ret = true;
	}

	return ret;
}


#include "livepatch_bsc1235916.h"

#include <linux/livepatch.h>

extern typeof(add_addr_generate_hmac) add_addr_generate_hmac
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, add_addr_generate_hmac);
extern typeof(mptcp_allow_join_id0) mptcp_allow_join_id0
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_allow_join_id0);
extern typeof(mptcp_delegated_actions) mptcp_delegated_actions
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_delegated_actions);
extern typeof(mptcp_pm_add_addr_signal) mptcp_pm_add_addr_signal
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_pm_add_addr_signal);
extern typeof(mptcp_pm_rm_addr_signal) mptcp_pm_rm_addr_signal
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mptcp_pm_rm_addr_signal);
