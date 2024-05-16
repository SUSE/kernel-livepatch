/*
 * livepatch_bsc1220832
 *
 * Fix for CVE-2023-52502, bsc#1220832
 *
 *  Upstream commit:
 *  31c07dffafce ("net: nfc: fix races in nfc_llcp_sock_get() and nfc_llcp_sock_get_sn()")
 *
 *  SLE12-SP5 commit:
 *  d0dd97d6291b674bcf9a6b8cd7a1450b81feb8cd
 *
 *  SLE15-SP2 and -SP3 commit:
 *  3983469d675502edcde0403eedcbbd73419e7cbc
 *
 *  SLE15-SP4 and -SP5 commit:
 *  8c33586f92e7f73bf2e30b9d1b1d2d75faa31ae6
 *
 *  Copyright (c) 2024 SUSE
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

#if IS_ENABLED(CONFIG_NFC)

#if !IS_MODULE(CONFIG_NFC)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/nfc/llcp_core.c */
#define pr_fmt(fmt) "llcp: %s: " fmt, __func__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/nfc.h>
/* klp-ccp: from net/nfc/nfc.h */
#include <net/nfc/nfc.h>

/* klp-ccp: from include/net/nfc/nfc.h */
static struct sk_buff *(*klpe_nfc_alloc_recv_skb)(unsigned int size, gfp_t gfp);

/* klp-ccp: from net/nfc/nfc.h */
#include <net/sock.h>

static int (*klpe_nfc_genl_llc_send_sdres)(struct nfc_dev *dev, struct hlist_head *sdres_list);

static struct nfc_dev *(*klpe_nfc_get_device)(unsigned int idx);

static inline void nfc_put_device(struct nfc_dev *dev)
{
	put_device(&dev->dev);
}

static int (*klpe_nfc_dep_link_down)(struct nfc_dev *dev);

/* klp-ccp: from net/nfc/llcp.h */
enum llcp_state {
	LLCP_CONNECTED = 1, /* wait_for_packet() wants that */
	LLCP_CONNECTING,
	LLCP_DISCONNECTING,
	LLCP_CLOSED,
	LLCP_BOUND,
	LLCP_LISTEN,
};

#define LLCP_WKS_NUM_SAP   16
#define LLCP_SDP_NUM_SAP   16
#define LLCP_LOCAL_NUM_SAP 32

#define LLCP_MAX_SAP (LLCP_WKS_NUM_SAP + LLCP_SDP_NUM_SAP + LLCP_LOCAL_NUM_SAP)
#define LLCP_SDP_UNBOUND   (LLCP_MAX_SAP + 1)

struct llcp_sock_list {
	struct hlist_head head;
	rwlock_t          lock;
};

struct nfc_llcp_sdp_tlv {
	u8 *tlv;
	u8 tlv_len;

	char *uri;
	u8 tid;
	u8 sap;

	unsigned long time;

	struct hlist_node node;
};

struct nfc_llcp_local {
	struct list_head list;
	struct nfc_dev *dev;

	struct kref ref;

	struct mutex sdp_lock;

	struct timer_list link_timer;
	struct sk_buff_head tx_queue;
	struct work_struct	 tx_work;
	struct work_struct	 rx_work;
	struct sk_buff *rx_pending;
	struct work_struct	 timeout_work;

	u32 target_idx;
	u8 rf_mode;
	u8 comm_mode;
	u8 lto;
	u8 rw;
	__be16 miux;
	unsigned long local_wks;      /* Well known services */
	unsigned long local_sdp;      /* Local services  */
	unsigned long local_sap; /* Local SAPs, not available for discovery */
	atomic_t local_sdp_cnt[LLCP_SDP_NUM_SAP];

	/* local */
	u8 gb[NFC_MAX_GT_LEN];
	u8 gb_len;

	/* remote */
	u8 remote_gb[NFC_MAX_GT_LEN];
	u8 remote_gb_len;

	u8  remote_version;
	u16 remote_miu;
	u16 remote_lto;
	u8  remote_opt;
	u16 remote_wks;

	struct mutex sdreq_lock;
	struct hlist_head pending_sdreqs;
	struct timer_list sdreq_timer;
	struct work_struct sdreq_timeout_work;
	u8 sdreq_next_tid;

	/* sockets array */
	struct llcp_sock_list sockets;
	struct llcp_sock_list connecting_sockets;
	struct llcp_sock_list raw_sockets;
};

struct nfc_llcp_sock {
	struct sock sk;
	struct nfc_dev *dev;
	struct nfc_llcp_local *local;
	u32 target_idx;
	u32 nfc_protocol;

	/* Link parameters */
	u8 ssap;
	u8 dsap;
	char *service_name;
	size_t service_name_len;
	u8 rw;
	__be16 miux;


	/* Remote link parameters */
	u8 remote_rw;
	u16 remote_miu;

	/* Link variables */
	u8 send_n;
	u8 send_ack_n;
	u8 recv_n;
	u8 recv_ack_n;

	/* Is the remote peer ready to receive */
	u8 remote_ready;

	/* Reserved source SAP */
	u8 reserved_ssap;

	struct sk_buff_head tx_queue;
	struct sk_buff_head tx_pending_queue;

	struct list_head accept_queue;
	struct sock *parent;
};

struct nfc_llcp_ui_cb {
	__u8 dsap;
	__u8 ssap;
};

#define nfc_llcp_ui_skb_cb(__skb) ((struct nfc_llcp_ui_cb *)&((__skb)->cb[0]))

#define LLCP_HEADER_SIZE   2
#define LLCP_SEQUENCE_SIZE 1
#define LLCP_AGF_PDU_HEADER_SIZE 2

#define LLCP_PDU_SYMM     0x0

#define LLCP_PDU_AGF      0x2
#define LLCP_PDU_UI       0x3
#define LLCP_PDU_CONNECT  0x4
#define LLCP_PDU_DISC     0x5
#define LLCP_PDU_CC       0x6
#define LLCP_PDU_DM       0x7

#define LLCP_PDU_SNL      0x9
#define LLCP_PDU_I        0xc
#define LLCP_PDU_RR       0xd
#define LLCP_PDU_RNR      0xe

#define LLCP_TLV_SN      0x6

#define LLCP_TLV_SDREQ   0x8
#define LLCP_TLV_SDRES   0x9

#define LLCP_SAP_SDP   0x1

#define LLCP_SAP_MAX   0xff

#define LLCP_DM_DISC    0x00
#define LLCP_DM_NOCONN  0x01
#define LLCP_DM_NOBOUND 0x02
#define LLCP_DM_REJ     0x03

static void (*klpe_nfc_llcp_sock_link)(struct llcp_sock_list *l, struct sock *s);
static void (*klpe_nfc_llcp_sock_unlink)(struct llcp_sock_list *l, struct sock *s);

static int (*klpe_nfc_llcp_queue_i_frames)(struct nfc_llcp_sock *sock);

static struct sock *(*klpe_nfc_llcp_sock_alloc)(struct socket *sock, int type, gfp_t gfp, int kern);

static void (*klpe_nfc_llcp_accept_enqueue)(struct sock *parent, struct sock *sk);

static int (*klpe_nfc_llcp_parse_connection_tlv)(struct nfc_llcp_sock *sock,
				  u8 *tlv_array, u16 tlv_array_len);

static struct nfc_llcp_sdp_tlv *(*klpe_nfc_llcp_build_sdres_tlv)(u8 tid, u8 sap);

static int (*klpe_nfc_llcp_send_cc)(struct nfc_llcp_sock *sock);
static int (*klpe_nfc_llcp_send_snl_sdres)(struct nfc_llcp_local *local,
			    struct hlist_head *tlv_list, size_t tlvs_len);

static int (*klpe_nfc_llcp_send_dm)(struct nfc_llcp_local *local, u8 ssap, u8 dsap, u8 reason);

static int (*klpe_nfc_llcp_send_rr)(struct nfc_llcp_sock *sock);

static void (*klpe_nfc_llcp_socket_purge)(struct nfc_llcp_sock *sock);

static struct nfc_llcp_local *nfc_llcp_local_get(struct nfc_llcp_local *local)
{
	kref_get(&local->ref);

	return local;
}

/* klp-ccp: from net/nfc/llcp.h */
#define klpr_nfc_llcp_sock(sk) ((struct nfc_llcp_sock *) (sk))

struct nfc_llcp_sock *klpp_nfc_llcp_sock_get(struct nfc_llcp_local *local,
					       u8 ssap, u8 dsap)
{
	struct sock *sk;
	struct nfc_llcp_sock *llcp_sock, *tmp_sock;

	pr_debug("ssap dsap %d %d\n", ssap, dsap);

	if (ssap == 0 && dsap == 0)
		return NULL;

	read_lock(&local->sockets.lock);

	llcp_sock = NULL;

	sk_for_each(sk, &local->sockets.head) {
		tmp_sock = klpr_nfc_llcp_sock(sk);

		if (tmp_sock->ssap == ssap && tmp_sock->dsap == dsap) {
			llcp_sock = tmp_sock;
			sock_hold(&llcp_sock->sk);
			break;
		}
	}

	read_unlock(&local->sockets.lock);

	return llcp_sock;
}

static void nfc_llcp_sock_put(struct nfc_llcp_sock *sock)
{
	sock_put(&sock->sk);
}

static char *(*klpe_wks)[5];

static int klpr_nfc_llcp_wks_sap(char *service_name, size_t service_name_len)
{
	int sap, num_wks;

	pr_debug("%s\n", service_name);

	if (service_name == NULL)
		return -EINVAL;

	num_wks = ARRAY_SIZE((*klpe_wks));

	for (sap = 0; sap < num_wks; sap++) {
		if ((*klpe_wks)[sap] == NULL)
			continue;

		if (strncmp((*klpe_wks)[sap], service_name, service_name_len) == 0)
			return sap;
	}

	return -EINVAL;
}

static struct nfc_llcp_sock *klpp_nfc_llcp_sock_from_sn(struct nfc_llcp_local *local,
					    u8 *sn, size_t sn_len,
					    bool needref)
{
	struct sock *sk;
	struct nfc_llcp_sock *llcp_sock, *tmp_sock;

	pr_debug("sn %zd %p\n", sn_len, sn);

	if (sn == NULL || sn_len == 0)
		return NULL;

	read_lock(&local->sockets.lock);

	llcp_sock = NULL;

	sk_for_each(sk, &local->sockets.head) {
		tmp_sock = klpr_nfc_llcp_sock(sk);

		pr_debug("llcp sock %p\n", tmp_sock);

		if (tmp_sock->sk.sk_type == SOCK_STREAM &&
		    tmp_sock->sk.sk_state != LLCP_LISTEN)
			continue;

		if (tmp_sock->sk.sk_type == SOCK_DGRAM &&
		    tmp_sock->sk.sk_state != LLCP_BOUND)
			continue;

		if (tmp_sock->service_name == NULL ||
		    tmp_sock->service_name_len == 0)
			continue;

		if (tmp_sock->service_name_len != sn_len)
			continue;

		if (memcmp(sn, tmp_sock->service_name, sn_len) == 0) {
			llcp_sock = tmp_sock;
			if (needref)
				sock_hold(&llcp_sock->sk);
			break;
		}
	}

	read_unlock(&local->sockets.lock);

	pr_debug("Found llcp sock %p\n", llcp_sock);

	return llcp_sock;
}

u8 klpp_nfc_llcp_get_sdp_ssap(struct nfc_llcp_local *local,
			 struct nfc_llcp_sock *sock)
{
	mutex_lock(&local->sdp_lock);

	if (sock->service_name != NULL && sock->service_name_len > 0) {
		int ssap = klpr_nfc_llcp_wks_sap(sock->service_name,
					    sock->service_name_len);

		if (ssap > 0) {
			pr_debug("WKS %d\n", ssap);

			/* This is a WKS, let's check if it's free */
			if (local->local_wks & BIT(ssap)) {
				mutex_unlock(&local->sdp_lock);

				return LLCP_SAP_MAX;
			}

			set_bit(ssap, &local->local_wks);
			mutex_unlock(&local->sdp_lock);

			return ssap;
		}

		/*
		 * Check if there already is a non WKS socket bound
		 * to this service name.
		 */
		if (klpp_nfc_llcp_sock_from_sn(local, sock->service_name,
					  sock->service_name_len,
					  false) != NULL) {
			mutex_unlock(&local->sdp_lock);

			return LLCP_SAP_MAX;
		}

		mutex_unlock(&local->sdp_lock);

		return LLCP_SDP_UNBOUND;

	} else if (sock->ssap != 0 && sock->ssap < LLCP_WKS_NUM_SAP) {
		if (!test_bit(sock->ssap, &local->local_wks)) {
			set_bit(sock->ssap, &local->local_wks);
			mutex_unlock(&local->sdp_lock);

			return sock->ssap;
		}
	}

	mutex_unlock(&local->sdp_lock);

	return LLCP_SAP_MAX;
}

static u8 (*klpe_nfc_llcp_reserve_sdp_ssap)(struct nfc_llcp_local *local);

static u8 nfc_llcp_dsap(struct sk_buff *pdu)
{
	return (pdu->data[0] & 0xfc) >> 2;
}

static u8 nfc_llcp_ptype(struct sk_buff *pdu)
{
	return ((pdu->data[0] & 0x03) << 2) | ((pdu->data[1] & 0xc0) >> 6);
}

static u8 nfc_llcp_ssap(struct sk_buff *pdu)
{
	return pdu->data[1] & 0x3f;
}

static u8 nfc_llcp_ns(struct sk_buff *pdu)
{
	return pdu->data[2] >> 4;
}

static u8 nfc_llcp_nr(struct sk_buff *pdu)
{
	return pdu->data[2] & 0xf;
}

static struct nfc_llcp_sock *(*klpe_nfc_llcp_connecting_sock_get)(struct nfc_llcp_local *local,
							  u8 ssap);

static struct nfc_llcp_sock *klpr_nfc_llcp_sock_get_sn(struct nfc_llcp_local *local,
						  u8 *sn, size_t sn_len)
{
	return klpp_nfc_llcp_sock_from_sn(local, sn, sn_len, true);
}

static u8 *nfc_llcp_connect_sn(struct sk_buff *skb, size_t *sn_len)
{
	u8 *tlv = &skb->data[2], type, length;
	size_t tlv_array_len = skb->len - LLCP_HEADER_SIZE, offset = 0;

	while (offset < tlv_array_len) {
		type = tlv[0];
		length = tlv[1];

		pr_debug("type 0x%x length %d\n", type, length);

		if (type == LLCP_TLV_SN) {
			*sn_len = length;
			return &tlv[2];
		}

		offset += length + 2;
		tlv += length + 2;
	}

	return NULL;
}

static void klpr_nfc_llcp_recv_ui(struct nfc_llcp_local *local,
			     struct sk_buff *skb)
{
	struct nfc_llcp_sock *llcp_sock;
	struct nfc_llcp_ui_cb *ui_cb;
	u8 dsap, ssap;

	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);

	ui_cb = nfc_llcp_ui_skb_cb(skb);
	ui_cb->dsap = dsap;
	ui_cb->ssap = ssap;

	pr_debug("%d %d\n", dsap, ssap);

	/* We're looking for a bound socket, not a client one */
	llcp_sock = klpp_nfc_llcp_sock_get(local, dsap, LLCP_SAP_SDP);
	if (llcp_sock == NULL || llcp_sock->sk.sk_type != SOCK_DGRAM)
		return;

	/* There is no sequence with UI frames */
	skb_pull(skb, LLCP_HEADER_SIZE);
	if (!sock_queue_rcv_skb(&llcp_sock->sk, skb)) {
		/*
		 * UI frames will be freed from the socket layer, so we
		 * need to keep them alive until someone receives them.
		 */
		skb_get(skb);
	} else {
		pr_err("Receive queue is full\n");
	}

	nfc_llcp_sock_put(llcp_sock);
}

static void klpr_nfc_llcp_recv_connect(struct nfc_llcp_local *local,
				  struct sk_buff *skb)
{
	struct sock *new_sk, *parent;
	struct nfc_llcp_sock *sock, *new_sock;
	u8 dsap, ssap, reason;

	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);

	pr_debug("%d %d\n", dsap, ssap);

	if (dsap != LLCP_SAP_SDP) {
		sock = klpp_nfc_llcp_sock_get(local, dsap, LLCP_SAP_SDP);
		if (sock == NULL || sock->sk.sk_state != LLCP_LISTEN) {
			reason = LLCP_DM_NOBOUND;
			goto fail;
		}
	} else {
		u8 *sn;
		size_t sn_len;

		sn = nfc_llcp_connect_sn(skb, &sn_len);
		if (sn == NULL) {
			reason = LLCP_DM_NOBOUND;
			goto fail;
		}

		pr_debug("Service name length %zu\n", sn_len);

		sock = klpr_nfc_llcp_sock_get_sn(local, sn, sn_len);
		if (sock == NULL) {
			reason = LLCP_DM_NOBOUND;
			goto fail;
		}
	}

	lock_sock(&sock->sk);

	parent = &sock->sk;

	if (sk_acceptq_is_full(parent)) {
		reason = LLCP_DM_REJ;
		release_sock(&sock->sk);
		sock_put(&sock->sk);
		goto fail;
	}

	if (sock->ssap == LLCP_SDP_UNBOUND) {
		u8 ssap = (*klpe_nfc_llcp_reserve_sdp_ssap)(local);

		pr_debug("First client, reserving %d\n", ssap);

		if (ssap == LLCP_SAP_MAX) {
			reason = LLCP_DM_REJ;
			release_sock(&sock->sk);
			sock_put(&sock->sk);
			goto fail;
		}

		sock->ssap = ssap;
	}

	new_sk = (*klpe_nfc_llcp_sock_alloc)(NULL, parent->sk_type, GFP_ATOMIC, 0);
	if (new_sk == NULL) {
		reason = LLCP_DM_REJ;
		release_sock(&sock->sk);
		sock_put(&sock->sk);
		goto fail;
	}

	new_sock = klpr_nfc_llcp_sock(new_sk);
	new_sock->dev = local->dev;
	new_sock->local = nfc_llcp_local_get(local);
	new_sock->rw = sock->rw;
	new_sock->miux = sock->miux;
	new_sock->nfc_protocol = sock->nfc_protocol;
	new_sock->dsap = ssap;
	new_sock->target_idx = local->target_idx;
	new_sock->parent = parent;
	new_sock->ssap = sock->ssap;
	if (sock->ssap < LLCP_LOCAL_NUM_SAP && sock->ssap >= LLCP_WKS_NUM_SAP) {
		atomic_t *client_count;

		pr_debug("reserved_ssap %d for %p\n", sock->ssap, new_sock);

		client_count =
			&local->local_sdp_cnt[sock->ssap - LLCP_WKS_NUM_SAP];

		atomic_inc(client_count);
		new_sock->reserved_ssap = sock->ssap;
	}

	(*klpe_nfc_llcp_parse_connection_tlv)(new_sock, &skb->data[LLCP_HEADER_SIZE],
				      skb->len - LLCP_HEADER_SIZE);

	pr_debug("new sock %p sk %p\n", new_sock, &new_sock->sk);

	(*klpe_nfc_llcp_sock_link)(&local->sockets, new_sk);

	(*klpe_nfc_llcp_accept_enqueue)(&sock->sk, new_sk);

	(*klpe_nfc_get_device)(local->dev->idx);

	new_sk->sk_state = LLCP_CONNECTED;

	/* Wake the listening processes */
	parent->sk_data_ready(parent);

	/* Send CC */
	(*klpe_nfc_llcp_send_cc)(new_sock);

	release_sock(&sock->sk);
	sock_put(&sock->sk);

	return;

fail:
	/* Send DM */
	(*klpe_nfc_llcp_send_dm)(local, dsap, ssap, reason);
}

static void klpr_nfc_llcp_recv_hdlc(struct nfc_llcp_local *local,
			       struct sk_buff *skb)
{
	struct nfc_llcp_sock *llcp_sock;
	struct sock *sk;
	u8 dsap, ssap, ptype, ns, nr;

	ptype = nfc_llcp_ptype(skb);
	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);
	ns = nfc_llcp_ns(skb);
	nr = nfc_llcp_nr(skb);

	pr_debug("%d %d R %d S %d\n", dsap, ssap, nr, ns);

	llcp_sock = klpp_nfc_llcp_sock_get(local, dsap, ssap);
	if (llcp_sock == NULL) {
		(*klpe_nfc_llcp_send_dm)(local, dsap, ssap, LLCP_DM_NOCONN);
		return;
	}

	sk = &llcp_sock->sk;
	lock_sock(sk);
	if (sk->sk_state == LLCP_CLOSED) {
		release_sock(sk);
		nfc_llcp_sock_put(llcp_sock);
	}

	/* Pass the payload upstream */
	if (ptype == LLCP_PDU_I) {
		pr_debug("I frame, queueing on %p\n", &llcp_sock->sk);

		if (ns == llcp_sock->recv_n)
			llcp_sock->recv_n = (llcp_sock->recv_n + 1) % 16;
		else
			pr_err("Received out of sequence I PDU\n");

		skb_pull(skb, LLCP_HEADER_SIZE + LLCP_SEQUENCE_SIZE);
		if (!sock_queue_rcv_skb(&llcp_sock->sk, skb)) {
			/*
			 * I frames will be freed from the socket layer, so we
			 * need to keep them alive until someone receives them.
			 */
			skb_get(skb);
		} else {
			pr_err("Receive queue is full\n");
		}
	}

	/* Remove skbs from the pending queue */
	if (llcp_sock->send_ack_n != nr) {
		struct sk_buff *s, *tmp;
		u8 n;

		llcp_sock->send_ack_n = nr;

		/* Remove and free all skbs until ns == nr */
		skb_queue_walk_safe(&llcp_sock->tx_pending_queue, s, tmp) {
			n = nfc_llcp_ns(s);

			skb_unlink(s, &llcp_sock->tx_pending_queue);
			kfree_skb(s);

			if (n == nr)
				break;
		}

		/* Re-queue the remaining skbs for transmission */
		skb_queue_reverse_walk_safe(&llcp_sock->tx_pending_queue,
					    s, tmp) {
			skb_unlink(s, &llcp_sock->tx_pending_queue);
			skb_queue_head(&local->tx_queue, s);
		}
	}

	if (ptype == LLCP_PDU_RR)
		llcp_sock->remote_ready = true;
	else if (ptype == LLCP_PDU_RNR)
		llcp_sock->remote_ready = false;

	if ((*klpe_nfc_llcp_queue_i_frames)(llcp_sock) == 0 && ptype == LLCP_PDU_I)
		(*klpe_nfc_llcp_send_rr)(llcp_sock);

	release_sock(sk);
	nfc_llcp_sock_put(llcp_sock);
}

static void klpr_nfc_llcp_recv_disc(struct nfc_llcp_local *local,
			       struct sk_buff *skb)
{
	struct nfc_llcp_sock *llcp_sock;
	struct sock *sk;
	u8 dsap, ssap;

	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);

	if ((dsap == 0) && (ssap == 0)) {
		pr_debug("Connection termination");
		(*klpe_nfc_dep_link_down)(local->dev);
		return;
	}

	llcp_sock = klpp_nfc_llcp_sock_get(local, dsap, ssap);
	if (llcp_sock == NULL) {
		(*klpe_nfc_llcp_send_dm)(local, dsap, ssap, LLCP_DM_NOCONN);
		return;
	}

	sk = &llcp_sock->sk;
	lock_sock(sk);

	(*klpe_nfc_llcp_socket_purge)(llcp_sock);

	if (sk->sk_state == LLCP_CLOSED) {
		release_sock(sk);
		nfc_llcp_sock_put(llcp_sock);
	}

	if (sk->sk_state == LLCP_CONNECTED) {
		nfc_put_device(local->dev);
		sk->sk_state = LLCP_CLOSED;
		sk->sk_state_change(sk);
	}

	(*klpe_nfc_llcp_send_dm)(local, dsap, ssap, LLCP_DM_DISC);

	release_sock(sk);
	nfc_llcp_sock_put(llcp_sock);
}

static void klpr_nfc_llcp_recv_cc(struct nfc_llcp_local *local, struct sk_buff *skb)
{
	struct nfc_llcp_sock *llcp_sock;
	struct sock *sk;
	u8 dsap, ssap;

	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);

	llcp_sock = (*klpe_nfc_llcp_connecting_sock_get)(local, dsap);
	if (llcp_sock == NULL) {
		pr_err("Invalid CC\n");
		(*klpe_nfc_llcp_send_dm)(local, dsap, ssap, LLCP_DM_NOCONN);

		return;
	}

	sk = &llcp_sock->sk;

	/* Unlink from connecting and link to the client array */
	(*klpe_nfc_llcp_sock_unlink)(&local->connecting_sockets, sk);
	(*klpe_nfc_llcp_sock_link)(&local->sockets, sk);
	llcp_sock->dsap = ssap;

	(*klpe_nfc_llcp_parse_connection_tlv)(llcp_sock, &skb->data[LLCP_HEADER_SIZE],
				      skb->len - LLCP_HEADER_SIZE);

	sk->sk_state = LLCP_CONNECTED;
	sk->sk_state_change(sk);

	nfc_llcp_sock_put(llcp_sock);
}

static void klpr_nfc_llcp_recv_dm(struct nfc_llcp_local *local, struct sk_buff *skb)
{
	struct nfc_llcp_sock *llcp_sock;
	struct sock *sk;
	u8 dsap, ssap, reason;

	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);
	reason = skb->data[2];

	pr_debug("%d %d reason %d\n", ssap, dsap, reason);

	switch (reason) {
	case LLCP_DM_NOBOUND:
	case LLCP_DM_REJ:
		llcp_sock = (*klpe_nfc_llcp_connecting_sock_get)(local, dsap);
		break;

	default:
		llcp_sock = klpp_nfc_llcp_sock_get(local, dsap, ssap);
		break;
	}

	if (llcp_sock == NULL) {
		pr_debug("Already closed\n");
		return;
	}

	sk = &llcp_sock->sk;

	sk->sk_err = ENXIO;
	sk->sk_state = LLCP_CLOSED;
	sk->sk_state_change(sk);

	nfc_llcp_sock_put(llcp_sock);
}

static void klpr_nfc_llcp_recv_snl(struct nfc_llcp_local *local,
			      struct sk_buff *skb)
{
	struct nfc_llcp_sock *llcp_sock;
	u8 dsap, ssap, *tlv, type, length, tid, sap;
	u16 tlv_len, offset;
	char *service_name;
	size_t service_name_len;
	struct nfc_llcp_sdp_tlv *sdp;
	HLIST_HEAD(llc_sdres_list);
	size_t sdres_tlvs_len;
	HLIST_HEAD(nl_sdres_list);

	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);

	pr_debug("%d %d\n", dsap, ssap);

	if (dsap != LLCP_SAP_SDP || ssap != LLCP_SAP_SDP) {
		pr_err("Wrong SNL SAP\n");
		return;
	}

	tlv = &skb->data[LLCP_HEADER_SIZE];
	tlv_len = skb->len - LLCP_HEADER_SIZE;
	offset = 0;
	sdres_tlvs_len = 0;

	while (offset < tlv_len) {
		type = tlv[0];
		length = tlv[1];

		switch (type) {
		case LLCP_TLV_SDREQ:
			tid = tlv[2];
			service_name = (char *) &tlv[3];
			service_name_len = length - 1;

			pr_debug("Looking for %.16s\n", service_name);

			if (service_name_len == strlen("urn:nfc:sn:sdp") &&
			    !strncmp(service_name, "urn:nfc:sn:sdp",
				     service_name_len)) {
				sap = 1;
				goto add_snl;
			}

			llcp_sock = klpp_nfc_llcp_sock_from_sn(local, service_name,
							  service_name_len,
							  true);
			if (!llcp_sock) {
				sap = 0;
				goto add_snl;
			}

			/*
			 * We found a socket but its ssap has not been reserved
			 * yet. We need to assign it for good and send a reply.
			 * The ssap will be freed when the socket is closed.
			 */
			if (llcp_sock->ssap == LLCP_SDP_UNBOUND) {
				atomic_t *client_count;

				sap = (*klpe_nfc_llcp_reserve_sdp_ssap)(local);

				pr_debug("Reserving %d\n", sap);

				if (sap == LLCP_SAP_MAX) {
					sap = 0;
					nfc_llcp_sock_put(llcp_sock);
					goto add_snl;
				}

				client_count =
					&local->local_sdp_cnt[sap -
							      LLCP_WKS_NUM_SAP];

				atomic_inc(client_count);

				llcp_sock->ssap = sap;
				llcp_sock->reserved_ssap = sap;
			} else {
				sap = llcp_sock->ssap;
			}

			pr_debug("%p %d\n", llcp_sock, sap);

			nfc_llcp_sock_put(llcp_sock);
add_snl:
			sdp = (*klpe_nfc_llcp_build_sdres_tlv)(tid, sap);
			if (sdp == NULL)
				goto exit;

			sdres_tlvs_len += sdp->tlv_len;
			hlist_add_head(&sdp->node, &llc_sdres_list);
			break;

		case LLCP_TLV_SDRES:
			mutex_lock(&local->sdreq_lock);

			pr_debug("LLCP_TLV_SDRES: searching tid %d\n", tlv[2]);

			hlist_for_each_entry(sdp, &local->pending_sdreqs, node) {
				if (sdp->tid != tlv[2])
					continue;

				sdp->sap = tlv[3];

				pr_debug("Found: uri=%s, sap=%d\n",
					 sdp->uri, sdp->sap);

				hlist_del(&sdp->node);

				hlist_add_head(&sdp->node, &nl_sdres_list);

				break;
			}

			mutex_unlock(&local->sdreq_lock);
			break;

		default:
			pr_err("Invalid SNL tlv value 0x%x\n", type);
			break;
		}

		offset += length + 2;
		tlv += length + 2;
	}

exit:
	if (!hlist_empty(&nl_sdres_list))
		(*klpe_nfc_genl_llc_send_sdres)(local->dev, &nl_sdres_list);

	if (!hlist_empty(&llc_sdres_list))
		(*klpe_nfc_llcp_send_snl_sdres)(local, &llc_sdres_list, sdres_tlvs_len);
}

void klpp_nfc_llcp_rx_skb(struct nfc_llcp_local *local, struct sk_buff *skb);

static void klpr_nfc_llcp_recv_agf(struct nfc_llcp_local *local, struct sk_buff *skb)
{
	u8 ptype;
	u16 pdu_len;
	struct sk_buff *new_skb;

	if (skb->len <= LLCP_HEADER_SIZE) {
		pr_err("Malformed AGF PDU\n");
		return;
	}

	skb_pull(skb, LLCP_HEADER_SIZE);

	while (skb->len > LLCP_AGF_PDU_HEADER_SIZE) {
		pdu_len = skb->data[0] << 8 | skb->data[1];

		skb_pull(skb, LLCP_AGF_PDU_HEADER_SIZE);

		if (pdu_len < LLCP_HEADER_SIZE || pdu_len > skb->len) {
			pr_err("Malformed AGF PDU\n");
			return;
		}

		ptype = nfc_llcp_ptype(skb);

		if (ptype == LLCP_PDU_SYMM || ptype == LLCP_PDU_AGF)
			goto next;

		new_skb = (*klpe_nfc_alloc_recv_skb)(pdu_len, GFP_KERNEL);
		if (new_skb == NULL) {
			pr_err("Could not allocate PDU\n");
			return;
		}

		skb_put_data(new_skb, skb->data, pdu_len);

		klpp_nfc_llcp_rx_skb(local, new_skb);

		kfree_skb(new_skb);
next:
		skb_pull(skb, pdu_len);
	}
}

void klpp_nfc_llcp_rx_skb(struct nfc_llcp_local *local, struct sk_buff *skb)
{
	u8 dsap, ssap, ptype;

	ptype = nfc_llcp_ptype(skb);
	dsap = nfc_llcp_dsap(skb);
	ssap = nfc_llcp_ssap(skb);

	pr_debug("ptype 0x%x dsap 0x%x ssap 0x%x\n", ptype, dsap, ssap);

	if (ptype != LLCP_PDU_SYMM)
		print_hex_dump_debug("LLCP Rx: ", DUMP_PREFIX_OFFSET, 16, 1,
				     skb->data, skb->len, true);

	switch (ptype) {
	case LLCP_PDU_SYMM:
		pr_debug("SYMM\n");
		break;

	case LLCP_PDU_UI:
		pr_debug("UI\n");
		klpr_nfc_llcp_recv_ui(local, skb);
		break;

	case LLCP_PDU_CONNECT:
		pr_debug("CONNECT\n");
		klpr_nfc_llcp_recv_connect(local, skb);
		break;

	case LLCP_PDU_DISC:
		pr_debug("DISC\n");
		klpr_nfc_llcp_recv_disc(local, skb);
		break;

	case LLCP_PDU_CC:
		pr_debug("CC\n");
		klpr_nfc_llcp_recv_cc(local, skb);
		break;

	case LLCP_PDU_DM:
		pr_debug("DM\n");
		klpr_nfc_llcp_recv_dm(local, skb);
		break;

	case LLCP_PDU_SNL:
		pr_debug("SNL\n");
		klpr_nfc_llcp_recv_snl(local, skb);
		break;

	case LLCP_PDU_I:
	case LLCP_PDU_RR:
	case LLCP_PDU_RNR:
		pr_debug("I frame\n");
		klpr_nfc_llcp_recv_hdlc(local, skb);
		break;

	case LLCP_PDU_AGF:
		pr_debug("AGF frame\n");
		klpr_nfc_llcp_recv_agf(local, skb);
		break;
	}
}


#include "livepatch_bsc1220832.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nfc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfc_alloc_recv_skb", (void *)&klpe_nfc_alloc_recv_skb, "nfc" },
	{ "nfc_dep_link_down", (void *)&klpe_nfc_dep_link_down, "nfc" },
	{ "nfc_genl_llc_send_sdres", (void *)&klpe_nfc_genl_llc_send_sdres,
	  "nfc" },
	{ "nfc_get_device", (void *)&klpe_nfc_get_device, "nfc" },
	{ "nfc_llcp_accept_enqueue", (void *)&klpe_nfc_llcp_accept_enqueue,
	  "nfc" },
	{ "nfc_llcp_build_sdres_tlv", (void *)&klpe_nfc_llcp_build_sdres_tlv,
	  "nfc" },
	{ "nfc_llcp_connecting_sock_get",
	  (void *)&klpe_nfc_llcp_connecting_sock_get, "nfc" },
	{ "nfc_llcp_parse_connection_tlv",
	  (void *)&klpe_nfc_llcp_parse_connection_tlv, "nfc" },
	{ "nfc_llcp_queue_i_frames", (void *)&klpe_nfc_llcp_queue_i_frames,
	  "nfc" },
	{ "nfc_llcp_reserve_sdp_ssap", (void *)&klpe_nfc_llcp_reserve_sdp_ssap,
	  "nfc" },
	{ "nfc_llcp_send_cc", (void *)&klpe_nfc_llcp_send_cc, "nfc" },
	{ "nfc_llcp_send_dm", (void *)&klpe_nfc_llcp_send_dm, "nfc" },
	{ "nfc_llcp_send_rr", (void *)&klpe_nfc_llcp_send_rr, "nfc" },
	{ "nfc_llcp_send_snl_sdres", (void *)&klpe_nfc_llcp_send_snl_sdres,
	  "nfc" },
	{ "nfc_llcp_sock_alloc", (void *)&klpe_nfc_llcp_sock_alloc, "nfc" },
	{ "nfc_llcp_sock_link", (void *)&klpe_nfc_llcp_sock_link, "nfc" },
	{ "nfc_llcp_sock_unlink", (void *)&klpe_nfc_llcp_sock_unlink, "nfc" },
	{ "nfc_llcp_socket_purge", (void *)&klpe_nfc_llcp_socket_purge,
	  "nfc" },
	{ "wks", (void *)&klpe_wks, "nfc" },
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

int livepatch_bsc1220832_init(void)
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

void livepatch_bsc1220832_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC) */
