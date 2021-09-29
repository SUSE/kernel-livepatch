/*
 * livepatch_bsc1188613
 *
 * Fix for CVE-2021-3640, bsc#1188613
 *
 *  Upstream commits:
 *  ba316be1b6a0 ("Bluetooth: schedule SCO timeouts with delayed_work")
 *  734bc5ff7831 ("Bluetooth: avoid circular locks in sco_sock_connect")
 *  27c24fda62b6 ("Bluetooth: switch to lock_sock in SCO")
 *  99c23da0eed4 ("Bluetooth: sco: Fix lock_sock() blockage by
 *                 memcpy_from_msg()")
 *
 *  SLE12-SP3 commits:
 *  1527ca1f0ed64a763454a9530a967d8ef33f58c4
 *  a41b79231bd7050b42b222f7ee7b92cc287cc2b9
 *  a63cffe9c631fba46db09cf5b205dd9f4e30bdbc
 *  7f7f3085a8360be3cf1ead45a873f97f008b5b19
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  adfd842742638968c4d730be1ef589523fd4bc51
 *  cc905cc5639f7faf325a5cd4aaf2a3d7eb90f69e
 *  73d3a49043a5c1a847fc3580d78c86a59303dd87
 *  d78ba893886204ef3281755b562afcf13b68b457
 *
 *  SLE15-SP2 and -SP3 commits:
 *  a21f4da99f523376ca8b15f18a46ba348dd1c4b3
 *  cae7d5badc6621b391da6451d060847dcf6328e1
 *  f2d375d76da6f83d429ebb002bf98ffeee1bb793
 *  a21f4da99f523376ca8b15f18a46ba348dd1c4b3
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG_BT=m"
#endif

#include "../shadow.h"
#include <linux/mutex.h>

#define KLP_BSC1188613_SHARED_STATE_ID KLP_SHADOW_ID(1188613, 0)

/* Protected by module_mutex. */
struct klp_bsc1188613_shared_state
{
	unsigned long refcount;
	struct mutex mtx;
};

static struct klp_bsc1188613_shared_state *klp_bsc1188613_shared_state;


/* klp-ccp: from net/bluetooth/sco.c */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static int  (*klpe_bt_sock_recvmsg)(struct socket *sock, struct msghdr *msg, size_t len,
		     int flags);

static struct sock *(*klpe_bt_accept_dequeue)(struct sock *parent, struct socket *newsock);

/* klp-ccp: from net/bluetooth/sco.c */
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
static int (*klpe_hci_send_cmd)(struct hci_dev *hdev, __u16 opcode, __u32 plen,
		 const void *param);

static void (*klpe_hci_send_sco)(struct hci_conn *conn, struct sk_buff *skb);

/* klp-ccp: from net/bluetooth/sco.c */
#include <net/bluetooth/sco.h>

struct sco_conn {
	struct hci_conn	*hcon;

	spinlock_t	lock;
	struct sock	*sk;

	unsigned int    mtu;
};

#define sco_conn_lock(c)	spin_lock(&c->lock);
#define sco_conn_unlock(c)	spin_unlock(&c->lock);

static void (*klpe_sco_sock_close)(struct sock *sk);
static void (*klpe_sco_sock_kill)(struct sock *sk);

#define sco_pi(sk) ((struct sco_pinfo *) sk)

struct sco_pinfo {
	struct bt_sock	bt;
	bdaddr_t	src;
	bdaddr_t	dst;
	__u32		flags;
	__u16		setting;
	struct sco_conn	*conn;
};

#define SCO_DISCONN_TIMEOUT	(HZ * 2)

static void (*klpe_sco_sock_set_timer)(struct sock *sk, long timeout);

static void (*klpe_sco_sock_clear_timer)(struct sock *sk);

static void (*klpe_sco_chan_del)(struct sock *sk, int err);

void klpp_sco_conn_del(struct hci_conn *hcon, int err)
{
	struct sco_conn *conn = hcon->sco_data;
	struct sock *sk;

	if (!conn)
		return;

	BT_DBG("hcon %p conn %p, err %d", hcon, conn, err);

	/* Kill socket */
	sco_conn_lock(conn);
	sk = conn->sk;
	sco_conn_unlock(conn);

	if (sk) {
		sock_hold(sk);
		/*
		 * Fix CVE-2021-3640
		 *  +1 line
		 */
		mutex_lock(&klp_bsc1188613_shared_state->mtx);
		bh_lock_sock(sk);
		(*klpe_sco_sock_clear_timer)(sk);
		(*klpe_sco_chan_del)(sk, err);
		bh_unlock_sock(sk);
		(*klpe_sco_sock_kill)(sk);
		/*
		 * Fix CVE-2021-3640
		 *  +1 line
		 */
		mutex_unlock(&klp_bsc1188613_shared_state->mtx);
		sock_put(sk);
	}

	hcon->sco_data = NULL;
	kfree(conn);
}

/*
 * Fix CVE-2021-3640
 *  -1 line, +2 lines
 */
static int klpp_sco_send_frame(struct sock *sk, void *buf,
			       int len, unsigned int msg_flags)
{
	struct sco_conn *conn = sco_pi(sk)->conn;
	struct sk_buff *skb;
	int err;

	/* Check outgoing MTU */
	if (len > conn->mtu)
		return -EINVAL;

	BT_DBG("sk %p len %d", sk, len);

	/*
	 * Fix CVE-2021-3640
	 *  -1 line, +1 line
	 */
	skb = bt_skb_send_alloc(sk, len, msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	/*
	 * Fix CVE-2021-3640
	 *  -5 lines, +1 line
	 */
	memcpy(skb_put(skb, len), buf, len);
	(*klpe_hci_send_sco)(conn->hcon, skb);

	return len;
}

static void klpr_sco_sock_cleanup_listen(struct sock *parent)
{
	struct sock *sk;

	BT_DBG("parent %p", parent);

	/* Close not yet accepted channels */
	while ((sk = (*klpe_bt_accept_dequeue)(parent, NULL))) {
		(*klpe_sco_sock_close)(sk);
		(*klpe_sco_sock_kill)(sk);
	}

	parent->sk_state  = BT_CLOSED;
	sock_set_flag(parent, SOCK_ZAPPED);
}

static void (*klpe_sco_sock_kill)(struct sock *sk);

void klpp___sco_sock_close(struct sock *sk)
{
	BT_DBG("sk %p state %d socket %p", sk, sk->sk_state, sk->sk_socket);

	/*
	 * Fix CVE-2021-3640
	 *  +4 lines
	 */
	if (sk->sk_state == BT_LISTEN) {
		klpr_sco_sock_cleanup_listen(sk);
		return;
	}

	/*
	 * Fix CVE-2021-3640
	 *  +2 lines
	 */
	local_bh_disable();
	bh_lock_sock(sk);
	switch (sk->sk_state) {
	/*
	 * Fix CVE-2021-3640
	 *  -4 lines
	 */
	case BT_CONNECTED:
	case BT_CONFIG:
		if (sco_pi(sk)->conn->hcon) {
			sk->sk_state = BT_DISCONN;
			(*klpe_sco_sock_set_timer)(sk, SCO_DISCONN_TIMEOUT);
			sco_conn_lock(sco_pi(sk)->conn);
			hci_conn_drop(sco_pi(sk)->conn->hcon);
			sco_pi(sk)->conn->hcon = NULL;
			sco_conn_unlock(sco_pi(sk)->conn);
		} else
			(*klpe_sco_chan_del)(sk, ECONNRESET);
		break;

	case BT_CONNECT2:
	case BT_CONNECT:
	case BT_DISCONN:
		(*klpe_sco_chan_del)(sk, ECONNRESET);
		break;

	default:
		sock_set_flag(sk, SOCK_ZAPPED);
		break;
	}
	/*
	 * Fix CVE-2021-3640
	 *  +2 lines
	 */
	bh_unlock_sock(sk);
	local_bh_enable();
}

static void (*klpe_sco_sock_close)(struct sock *sk);

int klpp_sco_sock_sendmsg(struct socket *sock, struct msghdr *msg,
			    size_t len)
{
	struct sock *sk = sock->sk;
	/*
	 * Fix CVE-2021-3640
	 *  +1 line
	 */
	void *buf;
	int err;

	BT_DBG("sock %p, sk %p", sock, sk);

	err = sock_error(sk);
	if (err)
		return err;

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	/*
	 * Fix CVE-2021-3640
	 *  +9 lines
	 */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (memcpy_from_msg(buf, msg, len)) {
		kfree(buf);
		return -EFAULT;
	}

	lock_sock(sk);
	/*
	 * Fix CVE-2021-3640
	 *  +1 line
	 */
	mutex_lock(&klp_bsc1188613_shared_state->mtx);

	if (sk->sk_state == BT_CONNECTED)
		/*
		 * Fix CVE-2021-3640
		 *  -1 line, +1 line
		 */
		err = klpp_sco_send_frame(sk, buf, len, msg->msg_flags);
	else
		err = -ENOTCONN;

	/*
	 * Fix CVE-2021-3640
	 *  +1 line
	 */
	mutex_unlock(&klp_bsc1188613_shared_state->mtx);
	release_sock(sk);
	/*
	 * Fix CVE-2021-3640
	 *  +1 line
	 */
	kfree(buf);
	return err;
}

static void klpr_sco_conn_defer_accept(struct hci_conn *conn, u16 setting)
{
	struct hci_dev *hdev = conn->hdev;

	BT_DBG("conn %p", conn);

	conn->state = BT_CONFIG;

	if (!lmp_esco_capable(hdev)) {
		struct hci_cp_accept_conn_req cp;

		bacpy(&cp.bdaddr, &conn->dst);
		cp.role = 0x00; /* Ignored */

		(*klpe_hci_send_cmd)(hdev, HCI_OP_ACCEPT_CONN_REQ, sizeof(cp), &cp);
	} else {
		struct hci_cp_accept_sync_conn_req cp;

		bacpy(&cp.bdaddr, &conn->dst);
		cp.pkt_type = cpu_to_le16(conn->pkt_type);

		cp.tx_bandwidth   = cpu_to_le32(0x00001f40);
		cp.rx_bandwidth   = cpu_to_le32(0x00001f40);
		cp.content_format = cpu_to_le16(setting);

		switch (setting & SCO_AIRMODE_MASK) {
		case SCO_AIRMODE_TRANSP:
			if (conn->pkt_type & ESCO_2EV3)
				cp.max_latency = cpu_to_le16(0x0008);
			else
				cp.max_latency = cpu_to_le16(0x000D);
			cp.retrans_effort = 0x02;
			break;
		case SCO_AIRMODE_CVSD:
			cp.max_latency = cpu_to_le16(0xffff);
			cp.retrans_effort = 0xff;
			break;
		}

		(*klpe_hci_send_cmd)(hdev, HCI_OP_ACCEPT_SYNC_CONN_REQ,
			     sizeof(cp), &cp);
	}
}

int klpp_sco_sock_recvmsg(struct socket *sock, struct msghdr *msg,
			    size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct sco_pinfo *pi = sco_pi(sk);

	lock_sock(sk);
	/*
	 * Fix CVE-2021-3640
	 *  +1 line
	 */
	mutex_lock(&klp_bsc1188613_shared_state->mtx);
	if (sk->sk_state == BT_CONNECT2 &&
	    test_bit(BT_SK_DEFER_SETUP, &bt_sk(sk)->flags)) {
		klpr_sco_conn_defer_accept(pi->conn->hcon, pi->setting);
		sk->sk_state = BT_CONFIG;

		/*
		 * Fix CVE-2021-3640
		 *  +1 line
		 */
		mutex_unlock(&klp_bsc1188613_shared_state->mtx);
		release_sock(sk);
		return 0;
	}

	/*
	 * Fix CVE-2021-3640
	 *  +1 line
	 */
	mutex_unlock(&klp_bsc1188613_shared_state->mtx);
	release_sock(sk);

	return (*klpe_bt_sock_recvmsg)(sock, msg, len, flags);
}

static int klpp_sco_sock_getsockopt_old(struct socket *sock, int optname,
				   char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct sco_options opts;
	struct sco_conninfo cinfo;
	int len, err = 0;

	BT_DBG("sk %p", sk);

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case SCO_OPTIONS:
		/*
		 * Fix CVE-2021-3640
		 *  +2 lines
		 */
		local_bh_disable();
		bh_lock_sock(sk);
		if (sk->sk_state != BT_CONNECTED &&
		    !(sk->sk_state == BT_CONNECT2 &&
		      test_bit(BT_SK_DEFER_SETUP, &bt_sk(sk)->flags))) {
			err = -ENOTCONN;
			/*
			 * Fix CVE-2021-3640
			 *  +2 lines
			 */
			bh_unlock_sock(sk);
			local_bh_enable();
			break;
		}

		opts.mtu = sco_pi(sk)->conn->mtu;
		/*
		 * Fix CVE-2021-3640
		 *  +2 lines
		 */
		bh_unlock_sock(sk);
		local_bh_enable();

		BT_DBG("mtu %d", opts.mtu);

		len = min_t(unsigned int, len, sizeof(opts));
		if (copy_to_user(optval, (char *)&opts, len))
			err = -EFAULT;

		break;

	case SCO_CONNINFO:
		/*
		 * Fix CVE-2021-3640
		 *  +2 lines
		 */
		local_bh_disable();
		bh_lock_sock(sk);
		if (sk->sk_state != BT_CONNECTED &&
		    !(sk->sk_state == BT_CONNECT2 &&
		      test_bit(BT_SK_DEFER_SETUP, &bt_sk(sk)->flags))) {
			err = -ENOTCONN;
			/*
			 * Fix CVE-2021-3640
			 *  +2 lines
			 */
			bh_unlock_sock(sk);
			local_bh_enable();
			break;
		}

		memset(&cinfo, 0, sizeof(cinfo));
		cinfo.hci_handle = sco_pi(sk)->conn->hcon->handle;
		memcpy(cinfo.dev_class, sco_pi(sk)->conn->hcon->dev_class, 3);
		/*
		 * Fix CVE-2021-3640
		 *  +2 lines
		 */
		bh_unlock_sock(sk);
		local_bh_enable();

		len = min_t(unsigned int, len, sizeof(cinfo));
		if (copy_to_user(optval, (char *)&cinfo, len))
			err = -EFAULT;

		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

int klpp_sco_sock_getsockopt(struct socket *sock, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	int len, err = 0;
	struct bt_voice voice;

	BT_DBG("sk %p", sk);

	if (level == SOL_SCO)
		return klpp_sco_sock_getsockopt_old(sock, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {

	case BT_DEFER_SETUP:
		if (sk->sk_state != BT_BOUND && sk->sk_state != BT_LISTEN) {
			err = -EINVAL;
			break;
		}

		if (put_user(test_bit(BT_SK_DEFER_SETUP, &bt_sk(sk)->flags),
			     (u32 __user *)optval))
			err = -EFAULT;

		break;

	case BT_VOICE:
		voice.setting = sco_pi(sk)->setting;

		len = min_t(unsigned int, len, sizeof(voice));
		if (copy_to_user(optval, (char *)&voice, len))
			err = -EFAULT;

		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/livepatch.h>
#include "livepatch_bsc1188613.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "bluetooth"

static int klp_bsc1188613_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	struct klp_bsc1188613_shared_state *s = shadow_data;

	memset(s, 0, sizeof(*s));
	mutex_init(&s->mtx);

	return 0;
}

static void klp_bsc1188613_destroy_shared_state(void *obj,
					       void *shadow_data)
{
	struct klp_bsc1188613_shared_state *s = shadow_data;

	mutex_destroy(&s->mtx);
}

/* Must be called with module_mutex held. */
static int __klp_bsc1188613_get_shared_state(void)
{
	klp_bsc1188613_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1188613_SHARED_STATE_ID,
					sizeof(*klp_bsc1188613_shared_state),
					GFP_KERNEL,
					klp_bsc1188613_init_shared_state, NULL);
	if (!klp_bsc1188613_shared_state)
		return -ENOMEM;

	++klp_bsc1188613_shared_state->refcount;

	return 0;
}

/* Must be called with module_mutex held. */
static void __klp_bsc1188613_put_shared_state(void)
{
	--klp_bsc1188613_shared_state->refcount;
	if (!klp_bsc1188613_shared_state->refcount) {
		klp_shadow_free(NULL, KLP_BSC1188613_SHARED_STATE_ID,
				klp_bsc1188613_destroy_shared_state);
	}

	klp_bsc1188613_shared_state = NULL;
}


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bt_sock_recvmsg", (void *)&klpe_bt_sock_recvmsg, "bluetooth" },
	{ "bt_accept_dequeue", (void *)&klpe_bt_accept_dequeue, "bluetooth" },
	{ "sco_sock_clear_timer", (void *)&klpe_sco_sock_clear_timer,
	  "bluetooth" },
	{ "hci_send_sco", (void *)&klpe_hci_send_sco, "bluetooth" },
	{ "hci_send_cmd", (void *)&klpe_hci_send_cmd, "bluetooth" },
	{ "sco_sock_close", (void *)&klpe_sco_sock_close, "bluetooth" },
	{ "sco_sock_kill", (void *)&klpe_sco_sock_kill, "bluetooth" },
	{ "sco_sock_set_timer", (void *)&klpe_sco_sock_set_timer, "bluetooth" },
	{ "sco_chan_del", (void *)&klpe_sco_chan_del, "bluetooth" },
};

static int livepatch_bsc1188613_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1188613_module_nb = {
	.notifier_call = livepatch_bsc1188613_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1188613_init(void)
{
	int ret;

	mutex_lock(&module_mutex);

	ret = __klp_bsc1188613_get_shared_state();
	if (ret)
		goto out;

	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret) {
			__klp_bsc1188613_put_shared_state();
			goto out;
		}
	}

	ret = register_module_notifier(&livepatch_bsc1188613_module_nb);
	if (ret)
		__klp_bsc1188613_put_shared_state();
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1188613_cleanup(void)
{
	mutex_lock(&module_mutex);
	__klp_bsc1188613_put_shared_state();
	mutex_unlock(&module_mutex);

	unregister_module_notifier(&livepatch_bsc1188613_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
