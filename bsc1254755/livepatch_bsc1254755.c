/*
 * livepatch_bsc1254755
 *
 * Fix for CVE-2023-53781, bsc#1254755
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

#if IS_ENABLED(CONFIG_SMC)

#if !IS_MODULE(CONFIG_SMC)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1254755.h"


/* klp-ccp: from net/smc/af_smc.c */
#define KMSG_COMPONENT "smc"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/socket.h>
#include <linux/workqueue.h>
#include <linux/in.h>
#include <linux/sched/signal.h>
#include <linux/if_vlan.h>
#include <linux/rcupdate_wait.h>
#include <linux/ctype.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/smc.h>
#include <asm/ioctls.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
/* klp-ccp: from net/smc/smc_pnet.h */
#include <net/smc.h>
/* klp-ccp: from net/smc/smc.h */
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/compiler.h> /* __aligned */
#include <net/sock.h>
/* klp-ccp: from net/smc/smc_ib.h */
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <rdma/ib_verbs.h>
#include <net/smc.h>

/* klp-ccp: from net/smc/smc.h */
#define SMCPROTO_SMC		0	/* SMC protocol, IPv4 */
#define SMCPROTO_SMC6		1	/* SMC protocol, IPv6 */

#ifdef ATOMIC64_INIT
#define KERNEL_HAS_ATOMIC64
#endif

struct smc_wr_rx_hdr {	/* common prefix part of LLC and CDC to demultiplex */
	u8			type;
} __aligned(1);

struct smc_cdc_conn_state_flags {
#if defined(__BIG_ENDIAN_BITFIELD)
	u8	peer_done_writing : 1;	/* Sending done indicator */
	u8	peer_conn_closed : 1;	/* Peer connection closed indicator */
	u8	peer_conn_abort : 1;	/* Abnormal close indicator */
	u8	reserved : 5;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8	reserved : 5;
	u8	peer_conn_abort : 1;
	u8	peer_conn_closed : 1;
	u8	peer_done_writing : 1;
#endif
};

struct smc_cdc_producer_flags {
#if defined(__BIG_ENDIAN_BITFIELD)
	u8	write_blocked : 1;	/* Writing Blocked, no rx buf space */
	u8	urg_data_pending : 1;	/* Urgent Data Pending */
	u8	urg_data_present : 1;	/* Urgent Data Present */
	u8	cons_curs_upd_req : 1;	/* cursor update requested */
	u8	failover_validation : 1;/* message replay due to failover */
	u8	reserved : 3;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8	reserved : 3;
	u8	failover_validation : 1;
	u8	cons_curs_upd_req : 1;
	u8	urg_data_present : 1;
	u8	urg_data_pending : 1;
	u8	write_blocked : 1;
#endif
};

/* in host byte order */
union smc_host_cursor {	/* SMC cursor - an offset in an RMBE */
	struct {
		u16	reserved;
		u16	wrap;		/* window wrap sequence number */
		u32	count;		/* cursor (= offset) part */
	};
#ifdef KERNEL_HAS_ATOMIC64
	atomic64_t		acurs;	/* for atomic processing */
#else
	u64			acurs;	/* for atomic processing */
#endif
} __aligned(8);

/* in host byte order, except for flag bitfields in network byte order */
struct smc_host_cdc_msg {		/* Connection Data Control message */
	struct smc_wr_rx_hdr		common; /* .type = 0xFE */
	u8				len;	/* length = 44 */
	u16				seqno;	/* connection seq # */
	u32				token;	/* alert_token */
	union smc_host_cursor		prod;		/* producer cursor */
	union smc_host_cursor		cons;		/* consumer cursor,
							 * piggy backed "ack"
							 */
	struct smc_cdc_producer_flags	prod_flags;	/* conn. tx/rx status */
	struct smc_cdc_conn_state_flags	conn_state_flags; /* peer conn. status*/
	u8				reserved[18];
} __aligned(8);

enum smc_urg_state {
	SMC_URG_VALID,			/* data present */
	SMC_URG_NOTYET,			/* data pending */
	SMC_URG_READ			/* data was already read */
};

struct smc_connection {
	struct rb_node		alert_node;
	struct smc_link_group	*lgr;		/* link group of connection */
	u32			alert_token_local; /* unique conn. id */
	u8			peer_rmbe_idx;	/* from tcp handshake */
	int			peer_rmbe_size;	/* size of peer rx buffer */
	atomic_t		peer_rmbe_space;/* remaining free bytes in peer
						 * rmbe
						 */
	int			rtoken_idx;	/* idx to peer RMB rkey/addr */

	struct smc_buf_desc	*sndbuf_desc;	/* send buffer descriptor */
	struct smc_buf_desc	*rmb_desc;	/* RMBE descriptor */
	int			rmbe_size_short;/* compressed notation */
	int			rmbe_update_limit;
						/* lower limit for consumer
						 * cursor update
						 */

	struct smc_host_cdc_msg	local_tx_ctrl;	/* host byte order staging
						 * buffer for CDC msg send
						 * .prod cf. TCP snd_nxt
						 * .cons cf. TCP sends ack
						 */
	union smc_host_cursor	tx_curs_prep;	/* tx - prepared data
						 * snd_max..wmem_alloc
						 */
	union smc_host_cursor	tx_curs_sent;	/* tx - sent data
						 * snd_nxt ?
						 */
	union smc_host_cursor	tx_curs_fin;	/* tx - confirmed by peer
						 * snd-wnd-begin ?
						 */
	atomic_t		sndbuf_space;	/* remaining space in sndbuf */
	u16			tx_cdc_seq;	/* sequence # for CDC send */
	spinlock_t		send_lock;	/* protect wr_sends */
	struct delayed_work	tx_work;	/* retry of smc_cdc_msg_send */
	u32			tx_off;		/* base offset in peer rmb */

	struct smc_host_cdc_msg	local_rx_ctrl;	/* filled during event_handl.
						 * .prod cf. TCP rcv_nxt
						 * .cons cf. TCP snd_una
						 */
	union smc_host_cursor	rx_curs_confirmed; /* confirmed to peer
						    * source of snd_una ?
						    */
	union smc_host_cursor	urg_curs;	/* points at urgent byte */
	enum smc_urg_state	urg_state;
	bool			urg_tx_pend;	/* urgent data staged */
	bool			urg_rx_skip_pend;
						/* indicate urgent oob data
						 * read, but previous regular
						 * data still pending
						 */
	char			urg_rx_byte;	/* urgent byte */
	atomic_t		bytes_to_rcv;	/* arrived data,
						 * not yet received
						 */
	atomic_t		splice_pending;	/* number of spliced bytes
						 * pending processing
						 */
#ifndef KERNEL_HAS_ATOMIC64
	spinlock_t		acurs_lock;	/* protect cursors */
#endif
	struct work_struct	close_work;	/* peer sent some closing */
	struct tasklet_struct	rx_tsklet;	/* Receiver tasklet for SMC-D */
	u8			rx_off;		/* receive offset:
						 * 0 for SMC-R, 32 for SMC-D
						 */
	u64			peer_token;	/* SMC-D token of peer */
};

struct smc_sock {				/* smc sock container */
	struct sock		sk;
	struct socket		*clcsock;	/* internal tcp socket */
	struct smc_connection	conn;		/* smc connection */
	struct smc_sock		*listen_smc;	/* listen parent */
	struct work_struct	connect_work;	/* handle non-blocking connect*/
	struct work_struct	tcp_listen_work;/* handle tcp socket accepts */
	struct work_struct	smc_listen_work;/* prepare new accept socket */
	struct list_head	accept_q;	/* sockets to be accepted */
	spinlock_t		accept_q_lock;	/* protects accept_q */
	bool			use_fallback;	/* fallback to tcp */
	int			fallback_rsn;	/* reason for fallback */
	u32			peer_diagnosis; /* decline reason from peer */
	int			sockopt_defer_accept;
						/* sockopt TCP_DEFER_ACCEPT
						 * value
						 */
	u8			wait_close_tx_prepared : 1;
						/* shutdown wr or close
						 * started, waiting for unsent
						 * data to be sent
						 */
	u8			connect_nonblock : 1;
						/* non-blocking connect in
						 * flight
						 */
	struct mutex            clcsock_release_lock;
						/* protects clcsock of a listen
						 * socket
						 * */
};

static inline struct smc_sock *smc_sk(const struct sock *sk)
{
	return (struct smc_sock *)sk;
}

/* klp-ccp: from net/smc/smc_clc.h */
#include <rdma/ib_verbs.h>
#include <linux/smc.h>
/* klp-ccp: from net/smc/smc_netlink.h */
#include <net/netlink.h>
#include <net/genetlink.h>
/* klp-ccp: from net/smc/smc_wr.h */
#include <linux/atomic.h>
#include <rdma/ib_verbs.h>
#include <asm/div64.h>
/* klp-ccp: from net/smc/smc_core.h */
#include <linux/atomic.h>
#include <linux/smc.h>
#include <linux/pci.h>
#include <rdma/ib_verbs.h>
#include <net/genetlink.h>

#define SMC_BUF_MIN_SIZE	16384	/* minimum size of an RMB */

/* klp-ccp: from net/smc/smc_cdc.h */
#include <linux/kernel.h> /* max_t */
#include <linux/atomic.h>
#include <linux/in.h>
#include <linux/compiler.h>
/* klp-ccp: from net/smc/smc_ism.h */
#include <linux/uio.h>
#include <linux/types.h>
#include <linux/mutex.h>
/* klp-ccp: from net/smc/smc_tx.h */
#include <linux/socket.h>
#include <linux/types.h>
/* klp-ccp: from net/smc/smc_rx.h */
#include <linux/socket.h>
#include <linux/types.h>
/* klp-ccp: from net/smc/smc_close.h */
#include <linux/workqueue.h>
/* klp-ccp: from net/smc/smc_stats.h */
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/ctype.h>
#include <linux/smc.h>

/* klp-ccp: from net/smc/af_smc.c */
static struct sock *(*klpe_smc_sock_alloc)(struct net *net, struct socket *sock,
				   int protocol);
static void (*klpe_smc_close_init)(struct smc_sock *smc);
static const struct proto_ops (*klpe_smc_sock_ops);

int klpp_smc_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	int family = (protocol == SMCPROTO_SMC6) ? PF_INET6 : PF_INET;
	struct smc_sock *smc;
	struct sock *sk;
	int rc;

	rc = -ESOCKTNOSUPPORT;
	if (sock->type != SOCK_STREAM)
		goto out;

	rc = -EPROTONOSUPPORT;
	if (protocol != SMCPROTO_SMC && protocol != SMCPROTO_SMC6)
		goto out;

	rc = -ENOBUFS;
	sock->ops = &(*klpe_smc_sock_ops);
	sk = (*klpe_smc_sock_alloc)(net, sock, protocol);
	if (!sk)
		goto out;

	/* create internal TCP socket for CLC handshake and fallback */
	smc = smc_sk(sk);
	smc->use_fallback = false; /* assume rdma capability first */
	smc->fallback_rsn = 0;
	(*klpe_smc_close_init)(smc);
	rc = sock_create_kern(net, family, SOCK_STREAM, IPPROTO_TCP,
			      &smc->clcsock);
	if (rc) {
		sk_common_release(sk);
		goto out;
	}
	/* smc_clcsock_release() does not wait smc->clcsock->sk's
	 * destruction;  its sk_state might not be TCP_CLOSE after
	 * smc->sk is close()d, and TCP timers can be fired later,
	 * which need net ref.
	 */
	sk = smc->clcsock->sk;
	sk->sk_net_refcnt = 1;
	get_net(net);

	smc->sk.sk_sndbuf = max(smc->clcsock->sk->sk_sndbuf, SMC_BUF_MIN_SIZE);
	smc->sk.sk_rcvbuf = max(smc->clcsock->sk->sk_rcvbuf, SMC_BUF_MIN_SIZE);

out:
	return rc;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "smc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "smc_sock_alloc", (void *)&klpe_smc_sock_alloc, "smc" },
	{ "smc_sock_ops", (void *)&klpe_smc_sock_ops, "smc" },
	{ "smc_close_init", (void *)&klpe_smc_close_init, "smc" },
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

int livepatch_bsc1254755_init(void)
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

void livepatch_bsc1254755_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SMC) */
