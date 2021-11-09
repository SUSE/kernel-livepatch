/*
 * livepatch_bsc1192042
 *
 * Fix for CVE-2021-0935, bsc#1192042
 *
 *  Upstream commits:
 *  2f987a76a977 ("net: ipv6: keep sk status consistent after datagram connect
 *                 failure")
 *  b954f94023dc ("l2tp: fix races with ipv4-mapped ipv6 addresses")
 *
 *  SLE12-SP3 commit:
 *  none yet
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  c09bc5afeb3b450393e4b0da5c390c6b9676d3f0
 *
 *  SLE15-SP2 and -SP3 commit:
 *  not affected
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_L2TP)
#error "Live patch supports only CONFIG_L2TP=m"
#endif

/* klp-ccp: from net/l2tp/l2tp_core.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/l2tp.h>
#include <linux/hash.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/udp.h>

#include <net/inet6_connection_sock.h>
#include <net/inet_ecn.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#include <asm/byteorder.h>
#include <linux/atomic.h>

/* klp-ccp: from net/l2tp/l2tp_core.h */
#define L2TP_HASH_BITS	4
#define L2TP_HASH_SIZE	(1 << L2TP_HASH_BITS)

struct l2tp_stats {
	atomic_long_t		tx_packets;
	atomic_long_t		tx_bytes;
	atomic_long_t		tx_errors;
	atomic_long_t		rx_packets;
	atomic_long_t		rx_bytes;
	atomic_long_t		rx_seq_discards;
	atomic_long_t		rx_oos_packets;
	atomic_long_t		rx_errors;
	atomic_long_t		rx_cookie_discards;
};

struct l2tp_session {
	int			magic;		/* should be
						 * L2TP_SESSION_MAGIC */
	long			dead;

	struct l2tp_tunnel	*tunnel;	/* back pointer to tunnel
						 * context */
	u32			session_id;
	u32			peer_session_id;
	u8			cookie[8];
	int			cookie_len;
	u8			peer_cookie[8];
	int			peer_cookie_len;
	u16			offset;		/* offset from end of L2TP header
						   to beginning of data */
	u16			l2specific_len;
	u16			l2specific_type;
	u16			hdr_len;
	u32			nr;		/* session NR state (receive) */
	u32			ns;		/* session NR state (send) */
	struct sk_buff_head	reorder_q;	/* receive reorder queue */
	u32			nr_max;		/* max NR. Depends on tunnel */
	u32			nr_window_size;	/* NR window size */
	u32			nr_oos;		/* NR of last OOS packet */
	int			nr_oos_count;	/* For OOS recovery */
	int			nr_oos_count_max;
	struct hlist_node	hlist;		/* Hash list node */
	atomic_t		ref_count;

	char			name[32];	/* for logging */
	char			ifname[IFNAMSIZ];
	unsigned int		data_seq:2;	/* data sequencing level
						 * 0 => none, 1 => IP only,
						 * 2 => all
						 */
	unsigned int		recv_seq:1;	/* expect receive packets with
						 * sequence numbers? */
	unsigned int		send_seq:1;	/* send packets with sequence
						 * numbers? */
	unsigned int		lns_mode:1;	/* behave as LNS? LAC enables
						 * sequence numbers under
						 * control of LNS. */
	int			debug;		/* bitmask of debug message
						 * categories */
	int			reorder_timeout; /* configured reorder timeout
						  * (in jiffies) */
	int			reorder_skip;	/* set if skip to next nr */
	int			mtu;
	int			mru;
	enum l2tp_pwtype	pwtype;
	struct l2tp_stats	stats;
	struct hlist_node	global_hlist;	/* Global hash list node */

	int (*build_header)(struct l2tp_session *session, void *buf);
	void (*recv_skb)(struct l2tp_session *session, struct sk_buff *skb, int data_len);
	void (*session_close)(struct l2tp_session *session);
#if IS_ENABLED(CONFIG_L2TP_DEBUGFS)
	void (*show)(struct seq_file *m, void *priv);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	uint8_t			priv[0];	/* private data */
};

struct l2tp_tunnel {
	int			magic;		/* Should be L2TP_TUNNEL_MAGIC */

	unsigned long		dead;

	struct rcu_head rcu;
	rwlock_t		hlist_lock;	/* protect session_hlist */
	bool			acpt_newsess;	/* Indicates whether this
						 * tunnel accepts new sessions.
						 * Protected by hlist_lock.
						 */
	struct hlist_head	session_hlist[L2TP_HASH_SIZE];
						/* hashed list of sessions,
						 * hashed by id */
	u32			tunnel_id;
	u32			peer_tunnel_id;
	int			version;	/* 2=>L2TPv2, 3=>L2TPv3 */

	char			name[20];	/* for logging */
	int			debug;		/* bitmask of debug message
						 * categories */
	enum l2tp_encap_type	encap;
	struct l2tp_stats	stats;

	struct list_head	list;		/* Keep a list of all tunnels */
	struct net		*l2tp_net;	/* the net we belong to */

	atomic_t		ref_count;
#ifdef CONFIG_DEBUG_FS
	void (*show)(struct seq_file *m, void *arg);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	int (*recv_payload_hook)(struct sk_buff *skb);
	void (*old_sk_destruct)(struct sock *);
	struct sock		*sock;		/* Parent socket */
	int			fd;		/* Parent fd, if tunnel socket
						 * was created by userspace */
#if IS_ENABLED(CONFIG_IPV6)
	bool			v4mapped;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct work_struct	del_work;

	uint8_t			priv[0];	/* private data */
};

int klpp_l2tp_xmit_skb(struct l2tp_session *session, struct sk_buff *skb,
		  int hdr_len);

#define l2tp_printk(ptr, type, func, fmt, ...)				\
do {									\
	if (((ptr)->debug) & (type))					\
		func(fmt, ##__VA_ARGS__);				\
} while (0)

#define l2tp_dbg(ptr, type, fmt, ...)					\
	l2tp_printk(ptr, type, pr_debug, fmt, ##__VA_ARGS__)

/* klp-ccp: from net/l2tp/l2tp_core.c */
static bool klpp_l2tp_sk_is_v6(struct sock *sk)
{
	return sk->sk_family == PF_INET6 &&
	       !ipv6_addr_v4mapped(&sk->sk_v6_daddr);
}

static int klpp_l2tp_xmit_core(struct l2tp_session *session, struct sk_buff *skb,
			  struct flowi *fl, size_t data_len)
{
	struct l2tp_tunnel *tunnel = session->tunnel;
	unsigned int len = skb->len;
	int error;

	/* Debug */
	if (session->send_seq)
		l2tp_dbg(session, L2TP_MSG_DATA, "%s: send %zd bytes, ns=%u\n",
			 session->name, data_len, session->ns - 1);
	else
		l2tp_dbg(session, L2TP_MSG_DATA, "%s: send %zd bytes\n",
			 session->name, data_len);

	if (session->debug & L2TP_MSG_DATA) {
		int uhlen = (tunnel->encap == L2TP_ENCAPTYPE_UDP) ? sizeof(struct udphdr) : 0;
		unsigned char *datap = skb->data + uhlen;

		pr_debug("%s: xmit\n", session->name);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     datap, min_t(size_t, 32, len - uhlen));
	}

	/* Queue the packet to IP for output */
	skb->ignore_df = 1;
	skb_dst_drop(skb);
#if IS_ENABLED(CONFIG_IPV6)
	/*
	 * Fix CVE-2021-0935
	 *  -1 line, +1 line
	 */
	if (klpp_l2tp_sk_is_v6(tunnel->sock))
		error = inet6_csk_xmit(tunnel->sock, skb, NULL);
	else
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		error = ip_queue_xmit(tunnel->sock, skb, fl);

	/* Update stats */
	if (error >= 0) {
		atomic_long_inc(&tunnel->stats.tx_packets);
		atomic_long_add(len, &tunnel->stats.tx_bytes);
		atomic_long_inc(&session->stats.tx_packets);
		atomic_long_add(len, &session->stats.tx_bytes);
	} else {
		atomic_long_inc(&tunnel->stats.tx_errors);
		atomic_long_inc(&session->stats.tx_errors);
	}

	return 0;
}

int klpp_l2tp_xmit_skb(struct l2tp_session *session, struct sk_buff *skb, int hdr_len)
{
	int data_len = skb->len;
	struct l2tp_tunnel *tunnel = session->tunnel;
	struct sock *sk = tunnel->sock;
	struct flowi *fl;
	struct udphdr *uh;
	struct inet_sock *inet;
	int headroom;
	int uhlen = (tunnel->encap == L2TP_ENCAPTYPE_UDP) ? sizeof(struct udphdr) : 0;
	int udp_len;
	int ret = NET_XMIT_SUCCESS;

	/* Check that there's enough headroom in the skb to insert IP,
	 * UDP and L2TP headers. If not enough, expand it to
	 * make room. Adjust truesize.
	 */
	headroom = NET_SKB_PAD + sizeof(struct iphdr) +
		uhlen + hdr_len;
	if (skb_cow_head(skb, headroom)) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	/* Setup L2TP header */
	session->build_header(session, __skb_push(skb, hdr_len));

	/* Reset skb netfilter state */
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
	nf_reset(skb);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		kfree_skb(skb);
		ret = NET_XMIT_DROP;
		goto out_unlock;
	}

	/*
	 * Fix CVE-2021-0935
	 *  +8 lines
	 */
	/* The user-space may change the connection status for the user-space
	* provided socket at run time: we must check it under the socket lock
	*/
	if (tunnel->fd >= 0 && sk->sk_state != TCP_ESTABLISHED) {
		kfree_skb(skb);
		ret = NET_XMIT_DROP;
		goto out_unlock;
	}

	inet = inet_sk(sk);
	fl = &inet->cork.fl;
	switch (tunnel->encap) {
	case L2TP_ENCAPTYPE_UDP:
		/* Setup UDP header */
		__skb_push(skb, sizeof(*uh));
		skb_reset_transport_header(skb);
		uh = udp_hdr(skb);
		uh->source = inet->inet_sport;
		uh->dest = inet->inet_dport;
		udp_len = uhlen + hdr_len + data_len;
		uh->len = htons(udp_len);

#if IS_ENABLED(CONFIG_IPV6)
		/*
		 * Fix CVE-2021-0935
		 *  -1 line, +1 line
		 */
		if (klpp_l2tp_sk_is_v6(sk))
			udp6_set_csum(udp_get_no_check6_tx(sk),
				      skb, &inet6_sk(sk)->saddr,
				      &sk->sk_v6_daddr, udp_len);
		else
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		udp_set_csum(sk->sk_no_check_tx, skb, inet->inet_saddr,
			     inet->inet_daddr, udp_len);
		break;

	case L2TP_ENCAPTYPE_IP:
		break;
	}

	klpp_l2tp_xmit_core(session, skb, fl, data_len);
out_unlock:
	bh_unlock_sock(sk);

	return ret;
}
