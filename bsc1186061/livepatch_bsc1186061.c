/*
 * livepatch_bsc1186061
 *
 * Fix for CVE-2021-23134, bsc#1186061
 *
 *  Upstream commit:
 *  c61760e6940d ("net/nfc: fix use-after-free llcp_sock_bind/connect")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  8490bfcab96e4864915b21b7e3895d5ef4d0b877
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  577df82f61d5932af0db56b44dc49858b350c7fc
 *
 *  SLE15-SP2 commit:
 *  ffbe2a6027a50a5c23d27948d49f1d926a66148d
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

#if IS_ENABLED(CONFIG_NFC)

#if !IS_MODULE(CONFIG_NFC)
#error "Live patch supports only CONFIG_NFC=m"
#endif

/* klp-ccp: from net/nfc/llcp_sock.c */
#define pr_fmt(fmt) "llcp: %s: " fmt, __func__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/nfc.h>
#include <linux/sched/signal.h>
/* klp-ccp: from net/nfc/nfc.h */
#include <net/nfc/nfc.h>
#include <net/sock.h>

static struct nfc_llcp_local *(*klpe_nfc_llcp_find_local)(struct nfc_dev *dev);

static struct nfc_dev *(*klpe_nfc_get_device)(unsigned int idx);

static inline void nfc_put_device(struct nfc_dev *dev)
{
	put_device(&dev->dev);
}

/* klp-ccp: from net/nfc/llcp.h */
enum llcp_state {
	LLCP_CONNECTED = 1, /* wait_for_packet() wants that */
	LLCP_CONNECTING,
	LLCP_DISCONNECTING,
	LLCP_CLOSED,
	LLCP_BOUND,
	LLCP_LISTEN,
};

#define LLCP_SDP_NUM_SAP   16

struct llcp_sock_list {
	struct hlist_head head;
	rwlock_t          lock;
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

#define nfc_llcp_sock(sk) ((struct nfc_llcp_sock *) (sk))

#define LLCP_SAP_SDP   0x1

#define LLCP_SAP_MAX   0xff

static void (*klpe_nfc_llcp_sock_link)(struct llcp_sock_list *l, struct sock *s);
static void (*klpe_nfc_llcp_sock_unlink)(struct llcp_sock_list *l, struct sock *s);

static struct nfc_llcp_local *(*klpe_nfc_llcp_local_get)(struct nfc_llcp_local *local);
static int (*klpe_nfc_llcp_local_put)(struct nfc_llcp_local *local);
static u8 (*klpe_nfc_llcp_get_sdp_ssap)(struct nfc_llcp_local *local,
			 struct nfc_llcp_sock *sock);
static u8 (*klpe_nfc_llcp_get_local_ssap)(struct nfc_llcp_local *local);
static void (*klpe_nfc_llcp_put_ssap)(struct nfc_llcp_local *local, u8 ssap);

static int (*klpe_nfc_llcp_send_connect)(struct nfc_llcp_sock *sock);

/* klp-ccp: from net/nfc/llcp_sock.c */
static int sock_wait_state(struct sock *sk, int state, unsigned long timeo)
{
	DECLARE_WAITQUEUE(wait, current);
	int err = 0;

	pr_debug("sk %p", sk);

	add_wait_queue(sk_sleep(sk), &wait);
	set_current_state(TASK_INTERRUPTIBLE);

	while (sk->sk_state != state) {
		if (!timeo) {
			err = -EINPROGRESS;
			break;
		}

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		set_current_state(TASK_INTERRUPTIBLE);

		err = sock_error(sk);
		if (err)
			break;
	}

	__set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);
	return err;
}

int klpp_llcp_sock_bind(struct socket *sock, struct sockaddr *addr, int alen)
{
	struct sock *sk = sock->sk;
	struct nfc_llcp_sock *llcp_sock = nfc_llcp_sock(sk);
	struct nfc_llcp_local *local;
	struct nfc_dev *dev;
	struct sockaddr_nfc_llcp llcp_addr;
	int len, ret = 0;

	if (!addr || alen < offsetofend(struct sockaddr, sa_family) ||
	    addr->sa_family != AF_NFC)
		return -EINVAL;

	pr_debug("sk %p addr %p family %d\n", sk, addr, addr->sa_family);

	memset(&llcp_addr, 0, sizeof(llcp_addr));
	len = min_t(unsigned int, sizeof(llcp_addr), alen);
	memcpy(&llcp_addr, addr, len);

	/* This is going to be a listening socket, dsap must be 0 */
	if (llcp_addr.dsap != 0)
		return -EINVAL;

	lock_sock(sk);

	if (sk->sk_state != LLCP_CLOSED) {
		ret = -EBADFD;
		goto error;
	}

	dev = (*klpe_nfc_get_device)(llcp_addr.dev_idx);
	if (dev == NULL) {
		ret = -ENODEV;
		goto error;
	}

	local = (*klpe_nfc_llcp_find_local)(dev);
	if (local == NULL) {
		ret = -ENODEV;
		goto put_dev;
	}

	llcp_sock->dev = dev;
	llcp_sock->local = (*klpe_nfc_llcp_local_get)(local);
	llcp_sock->nfc_protocol = llcp_addr.nfc_protocol;
	llcp_sock->service_name_len = min_t(unsigned int,
					    llcp_addr.service_name_len,
					    NFC_LLCP_MAX_SERVICE_NAME);
	llcp_sock->service_name = kmemdup(llcp_addr.service_name,
					  llcp_sock->service_name_len,
					  GFP_KERNEL);
	if (!llcp_sock->service_name) {
		(*klpe_nfc_llcp_local_put)(llcp_sock->local);
		/*
		 * Fix CVE-2021-23134
		 *  +1 line
		 */
		llcp_sock->local = NULL;
		ret = -ENOMEM;
		goto put_dev;
	}
	llcp_sock->ssap = (*klpe_nfc_llcp_get_sdp_ssap)(local, llcp_sock);
	if (llcp_sock->ssap == LLCP_SAP_MAX) {
		(*klpe_nfc_llcp_local_put)(llcp_sock->local);
		/*
		 * Fix CVE-2021-23134
		 *  +1 line
		 */
		llcp_sock->local = NULL;
		kfree(llcp_sock->service_name);
		llcp_sock->service_name = NULL;
		ret = -EADDRINUSE;
		goto put_dev;
	}

	llcp_sock->reserved_ssap = llcp_sock->ssap;

	(*klpe_nfc_llcp_sock_link)(&local->sockets, sk);

	pr_debug("Socket bound to SAP %d\n", llcp_sock->ssap);

	sk->sk_state = LLCP_BOUND;

put_dev:
	nfc_put_device(dev);

error:
	release_sock(sk);
	return ret;
}

int klpp_llcp_sock_connect(struct socket *sock, struct sockaddr *_addr,
			     int len, int flags)
{
	struct sock *sk = sock->sk;
	struct nfc_llcp_sock *llcp_sock = nfc_llcp_sock(sk);
	struct sockaddr_nfc_llcp *addr = (struct sockaddr_nfc_llcp *)_addr;
	struct nfc_dev *dev;
	struct nfc_llcp_local *local;
	int ret = 0;

	pr_debug("sock %p sk %p flags 0x%x\n", sock, sk, flags);

	if (!addr || len < sizeof(*addr) || addr->sa_family != AF_NFC)
		return -EINVAL;

	if (addr->service_name_len == 0 && addr->dsap == 0)
		return -EINVAL;

	pr_debug("addr dev_idx=%u target_idx=%u protocol=%u\n", addr->dev_idx,
		 addr->target_idx, addr->nfc_protocol);

	lock_sock(sk);

	if (sk->sk_state == LLCP_CONNECTED) {
		ret = -EISCONN;
		goto error;
	}
	if (sk->sk_state == LLCP_CONNECTING) {
		ret = -EINPROGRESS;
		goto error;
	}

	dev = (*klpe_nfc_get_device)(addr->dev_idx);
	if (dev == NULL) {
		ret = -ENODEV;
		goto error;
	}

	local = (*klpe_nfc_llcp_find_local)(dev);
	if (local == NULL) {
		ret = -ENODEV;
		goto put_dev;
	}

	device_lock(&dev->dev);
	if (dev->dep_link_up == false) {
		ret = -ENOLINK;
		device_unlock(&dev->dev);
		goto put_dev;
	}
	device_unlock(&dev->dev);

	if (local->rf_mode == NFC_RF_INITIATOR &&
	    addr->target_idx != local->target_idx) {
		ret = -ENOLINK;
		goto put_dev;
	}

	llcp_sock->dev = dev;
	llcp_sock->local = (*klpe_nfc_llcp_local_get)(local);
	llcp_sock->ssap = (*klpe_nfc_llcp_get_local_ssap)(local);
	if (llcp_sock->ssap == LLCP_SAP_MAX) {
		(*klpe_nfc_llcp_local_put)(llcp_sock->local);
		/*
		 * Fix CVE-2021-23134
		 *  +1 line
		 */
		llcp_sock->local = NULL;
		ret = -ENOMEM;
		goto put_dev;
	}

	llcp_sock->reserved_ssap = llcp_sock->ssap;

	if (addr->service_name_len == 0)
		llcp_sock->dsap = addr->dsap;
	else
		llcp_sock->dsap = LLCP_SAP_SDP;
	llcp_sock->nfc_protocol = addr->nfc_protocol;
	llcp_sock->service_name_len = min_t(unsigned int,
					    addr->service_name_len,
					    NFC_LLCP_MAX_SERVICE_NAME);
	llcp_sock->service_name = kmemdup(addr->service_name,
					  llcp_sock->service_name_len,
					  GFP_KERNEL);

	(*klpe_nfc_llcp_sock_link)(&local->connecting_sockets, sk);

	ret = (*klpe_nfc_llcp_send_connect)(llcp_sock);
	if (ret)
		goto sock_unlink;

	sk->sk_state = LLCP_CONNECTING;

	ret = sock_wait_state(sk, LLCP_CONNECTED,
			      sock_sndtimeo(sk, flags & O_NONBLOCK));
	if (ret && ret != -EINPROGRESS)
		goto sock_unlink;

	release_sock(sk);

	return ret;

sock_unlink:
	(*klpe_nfc_llcp_put_ssap)(local, llcp_sock->ssap);

	(*klpe_nfc_llcp_sock_unlink)(&local->connecting_sockets, sk);
	kfree(llcp_sock->service_name);
	llcp_sock->service_name = NULL;

	(*klpe_nfc_llcp_local_put)(llcp_sock->local);
	/*
	 * Fix CVE-2021-23134
	 *  +1 line
	 */
	llcp_sock->local = NULL;

put_dev:
	nfc_put_device(dev);

error:
	release_sock(sk);
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1186061.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfc_llcp_find_local", (void *)&klpe_nfc_llcp_find_local, "nfc" },
	{ "nfc_get_device", (void *)&klpe_nfc_get_device, "nfc" },
	{ "nfc_llcp_sock_link", (void *)&klpe_nfc_llcp_sock_link, "nfc" },
	{ "nfc_llcp_sock_unlink", (void *)&klpe_nfc_llcp_sock_unlink, "nfc" },
	{ "nfc_llcp_local_get", (void *)&klpe_nfc_llcp_local_get, "nfc" },
	{ "nfc_llcp_local_put", (void *)&klpe_nfc_llcp_local_put, "nfc" },
	{ "nfc_llcp_get_sdp_ssap", (void *)&klpe_nfc_llcp_get_sdp_ssap, "nfc" },
	{ "nfc_llcp_get_local_ssap", (void *)&klpe_nfc_llcp_get_local_ssap,
	  "nfc" },
	{ "nfc_llcp_put_ssap", (void *)&klpe_nfc_llcp_put_ssap, "nfc" },
	{ "nfc_llcp_send_connect", (void *)&klpe_nfc_llcp_send_connect, "nfc" },
};

static int livepatch_bsc1186061_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1186061_module_nb = {
	.notifier_call = livepatch_bsc1186061_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1186061_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1186061_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1186061_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1186061_module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC) */
