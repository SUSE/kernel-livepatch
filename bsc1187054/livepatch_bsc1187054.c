/*
 * livepatch_bsc1187054
 *
 * Fix for CVE-2021-3573, bsc#1187054
 *
 *  Upstream commits:
 *  e305509e678b (Bluetooth: use correct lock to prevent UAF of hdev object")
 *  e04480920d1e ("Bluetooth: defer cleanup of resources in
 *                 hci_unregister_dev()")
 *
 *  SLE12-SP3 commit:
 *  e08729f111e76adf19d9360a6a4445f46ad41f87
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  c8012e0bd7c58a35d6d5b8d3de91ce8a585b6480
 *
 *  SLE12-SP5 commits:
 *  1793fcdbac417c8c821b15a37b6a57e4de160b39
 *  c8012e0bd7c58a35d6d5b8d3de91ce8a585b6480
 *
 *  SLE15-SP2 and -SP3 commit:
 *  6781ea8a7e050563efc951a5ac219e1600d41262
 *  38ad73f7d26b2ba662856a79d998c29dfc554b04
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

/* klp-ccp: from net/bluetooth/hci_sock.c */
#include <linux/export.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static void (*klpe_hci_sock_set_flag)(struct sock *sk, int nr);

/* klp-ccp: from net/bluetooth/hci_sock.c */
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
static int (*klpe_hci_dev_open)(__u16 dev);
static int (*klpe_hci_dev_close)(__u16 dev);

static int (*klpe_hci_dev_reset)(__u16 dev);
static int (*klpe_hci_dev_reset_stat)(__u16 dev);
static int (*klpe_hci_dev_cmd)(unsigned int cmd, void __user *arg);
static int (*klpe_hci_get_dev_list)(void __user *arg);
static int (*klpe_hci_get_dev_info)(void __user *arg);
static int (*klpe_hci_get_conn_list)(void __user *arg);
static int (*klpe_hci_get_conn_info)(struct hci_dev *hdev, void __user *arg);
static int (*klpe_hci_get_auth_info)(struct hci_dev *hdev, void __user *arg);
static int (*klpe_hci_inquiry)(void __user *arg);

static int (*klpe_hci_bdaddr_list_add)(struct list_head *list, bdaddr_t *bdaddr, u8 type);
static int (*klpe_hci_bdaddr_list_del)(struct list_head *list, bdaddr_t *bdaddr, u8 type);

static void (*klpe_hci_send_to_sock)(struct hci_dev *hdev, struct sk_buff *skb);
static void (*klpe_hci_send_to_channel)(unsigned short channel, struct sk_buff *skb,
			 int flag, struct sock *skip_sk);

void klpp_hci_sock_dev_event(struct hci_dev *hdev, int event);

/* klp-ccp: from net/bluetooth/hci_sock.c */
static struct ida (*klpe_sock_cookie_ida);

static atomic_t (*klpe_monitor_promisc);

#define hci_pi(sk) ((struct hci_pinfo *) sk)

struct hci_pinfo {
	struct bt_sock    bt;
	struct hci_dev    *hdev;
	struct hci_filter filter;
	__u32             cmsg_mask;
	unsigned short    channel;
	unsigned long     flags;
	__u32             cookie;
	char              comm[TASK_COMM_LEN];
};

static bool klpr_hci_sock_gen_cookie(struct sock *sk)
{
	int id = hci_pi(sk)->cookie;

	if (!id) {
		id = ida_simple_get(&(*klpe_sock_cookie_ida), 1, 0, GFP_KERNEL);
		if (id < 0)
			id = 0xffffffff;

		hci_pi(sk)->cookie = id;
		get_task_comm(hci_pi(sk)->comm, current);
		return true;
	}

	return false;
}

static struct bt_sock_list (*klpe_hci_sk_list);

static struct sk_buff *(*klpe_create_monitor_event)(struct hci_dev *hdev, int event);

static struct sk_buff *(*klpe_create_monitor_ctrl_open)(struct sock *sk);

static void klpr_hci_si_event(struct hci_dev *hdev, int type, int dlen, void *data)
{
	struct hci_event_hdr *hdr;
	struct hci_ev_stack_internal *ev;
	struct sk_buff *skb;

	skb = bt_skb_alloc(HCI_EVENT_HDR_SIZE + sizeof(*ev) + dlen, GFP_ATOMIC);
	if (!skb)
		return;

	hdr = skb_put(skb, HCI_EVENT_HDR_SIZE);
	hdr->evt  = HCI_EV_STACK_INTERNAL;
	hdr->plen = sizeof(*ev) + dlen;

	ev = skb_put(skb, sizeof(*ev) + dlen);
	ev->type = type;
	memcpy(ev->data, data, dlen);

	bt_cb(skb)->incoming = 1;
	__net_timestamp(skb);

	hci_skb_pkt_type(skb) = HCI_EVENT_PKT;
	(*klpe_hci_send_to_sock)(hdev, skb);
	kfree_skb(skb);
}

void klpp_hci_sock_dev_event(struct hci_dev *hdev, int event)
{
	BT_DBG("hdev %s event %d", hdev->name, event);

	if (atomic_read(&(*klpe_monitor_promisc))) {
		struct sk_buff *skb;

		/* Send event to monitor */
		skb = (*klpe_create_monitor_event)(hdev, event);
		if (skb) {
			(*klpe_hci_send_to_channel)(HCI_CHANNEL_MONITOR, skb,
					    HCI_SOCK_TRUSTED, NULL);
			kfree_skb(skb);
		}
	}

	if (event <= HCI_DEV_DOWN) {
		struct hci_ev_si_device ev;

		/* Send event to sockets */
		ev.event  = event;
		ev.dev_id = hdev->id;
		klpr_hci_si_event(NULL, HCI_EV_SI_DEVICE, sizeof(ev), &ev);
	}

	if (event == HCI_DEV_UNREG) {
		struct sock *sk;

		/* Detach sockets from device */
		read_lock(&(*klpe_hci_sk_list).lock);
		sk_for_each(sk, &(*klpe_hci_sk_list).head) {
			/*
			 * Fix CVE-2021-3573
			 *  -1 line, +1 line
			 */
			bh_lock_sock_nested(sk);
			if (hci_pi(sk)->hdev == hdev) {
				hci_pi(sk)->hdev = NULL;
				sk->sk_err = EPIPE;
				sk->sk_state = BT_OPEN;
				sk->sk_state_change(sk);

				hci_dev_put(hdev);
			}
			/*
			 * Fix CVE-2021-3573
			 *  -1 line, +1 line
			 */
			bh_unlock_sock(sk);
		}
		read_unlock(&(*klpe_hci_sk_list).lock);
	}
}

static int klpr_hci_sock_blacklist_add(struct hci_dev *hdev, void __user *arg)
{
	bdaddr_t bdaddr;
	int err;

	if (copy_from_user(&bdaddr, arg, sizeof(bdaddr)))
		return -EFAULT;

	hci_dev_lock(hdev);

	err = (*klpe_hci_bdaddr_list_add)(&hdev->blacklist, &bdaddr, BDADDR_BREDR);

	hci_dev_unlock(hdev);

	return err;
}

static int klpr_hci_sock_blacklist_del(struct hci_dev *hdev, void __user *arg)
{
	bdaddr_t bdaddr;
	int err;

	if (copy_from_user(&bdaddr, arg, sizeof(bdaddr)))
		return -EFAULT;

	hci_dev_lock(hdev);

	err = (*klpe_hci_bdaddr_list_del)(&hdev->blacklist, &bdaddr, BDADDR_BREDR);

	hci_dev_unlock(hdev);

	return err;
}

/*
 * Fix CVE-2021-3573
 *  -1 line, +1 line
 */
static int __klpp_hci_sock_bound_ioctl(struct hci_dev *hdev, unsigned int cmd,
				unsigned long arg)
{
	/*
	 * Fix CVE-2021-3573
	 *  -4 lines
	 */

	if (hci_dev_test_flag(hdev, HCI_USER_CHANNEL))
		return -EBUSY;

	if (hci_dev_test_flag(hdev, HCI_UNCONFIGURED))
		return -EOPNOTSUPP;

	if (hdev->dev_type != HCI_PRIMARY)
		return -EOPNOTSUPP;

	switch (cmd) {
	case HCISETRAW:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return -EOPNOTSUPP;

	case HCIGETCONNINFO:
		return (*klpe_hci_get_conn_info)(hdev, (void __user *)arg);

	case HCIGETAUTHINFO:
		return (*klpe_hci_get_auth_info)(hdev, (void __user *)arg);

	case HCIBLOCKADDR:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return klpr_hci_sock_blacklist_add(hdev, (void __user *)arg);

	case HCIUNBLOCKADDR:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return klpr_hci_sock_blacklist_del(hdev, (void __user *)arg);
	}

	return -ENOIOCTLCMD;
}

/*
 * Fix CVE-2021-3573
 *  +24 lines
 */
static int klpp_hci_sock_bound_ioctl(struct sock *sk, unsigned int cmd,
				unsigned long arg)
{
	int r;
	struct hci_dev *hdev;

	local_bh_disable();
	bh_lock_sock(sk);
	hdev =  hci_pi(sk)->hdev;
	if (!hdev) {
		bh_unlock_sock(sk);
		local_bh_enable();
		return -EBADFD;
	}
	hci_dev_hold(hdev);
	bh_unlock_sock(sk);
	local_bh_enable();

	r = __klpp_hci_sock_bound_ioctl(hdev, cmd, arg);

	hci_dev_put(hdev);

	return r;
}


int klpp_hci_sock_ioctl(struct socket *sock, unsigned int cmd,
			  unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct sock *sk = sock->sk;
	int err;

	BT_DBG("cmd %x arg %lx", cmd, arg);

	lock_sock(sk);

	if (hci_pi(sk)->channel != HCI_CHANNEL_RAW) {
		err = -EBADFD;
		goto done;
	}

	/* When calling an ioctl on an unbound raw socket, then ensure
	 * that the monitor gets informed. Ensure that the resulting event
	 * is only send once by checking if the cookie exists or not. The
	 * socket cookie will be only ever generated once for the lifetime
	 * of a given socket.
	 */
	if (klpr_hci_sock_gen_cookie(sk)) {
		struct sk_buff *skb;

		if (capable(CAP_NET_ADMIN))
			(*klpe_hci_sock_set_flag)(sk, HCI_SOCK_TRUSTED);

		/* Send event to monitor */
		skb = (*klpe_create_monitor_ctrl_open)(sk);
		if (skb) {
			(*klpe_hci_send_to_channel)(HCI_CHANNEL_MONITOR, skb,
					    HCI_SOCK_TRUSTED, NULL);
			kfree_skb(skb);
		}
	}

	release_sock(sk);

	switch (cmd) {
	case HCIGETDEVLIST:
		return (*klpe_hci_get_dev_list)(argp);

	case HCIGETDEVINFO:
		return (*klpe_hci_get_dev_info)(argp);

	case HCIGETCONNLIST:
		return (*klpe_hci_get_conn_list)(argp);

	case HCIDEVUP:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return (*klpe_hci_dev_open)(arg);

	case HCIDEVDOWN:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return (*klpe_hci_dev_close)(arg);

	case HCIDEVRESET:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return (*klpe_hci_dev_reset)(arg);

	case HCIDEVRESTAT:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return (*klpe_hci_dev_reset_stat)(arg);

	case HCISETSCAN:
	case HCISETAUTH:
	case HCISETENCRYPT:
	case HCISETPTYPE:
	case HCISETLINKPOL:
	case HCISETLINKMODE:
	case HCISETACLMTU:
	case HCISETSCOMTU:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return (*klpe_hci_dev_cmd)(cmd, argp);

	case HCIINQUIRY:
		return (*klpe_hci_inquiry)(argp);
	}

	lock_sock(sk);

	err = klpp_hci_sock_bound_ioctl(sk, cmd, arg);

done:
	release_sock(sk);
	return err;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1187054.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "bluetooth"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "monitor_promisc", (void *)&klpe_monitor_promisc, "bluetooth" },
	{ "sock_cookie_ida", (void *)&klpe_sock_cookie_ida, "bluetooth" },
	{ "hci_sk_list", (void *)&klpe_hci_sk_list, "bluetooth" },
	{ "hci_sock_set_flag", (void *)&klpe_hci_sock_set_flag, "bluetooth" },
	{ "hci_dev_open", (void *)&klpe_hci_dev_open, "bluetooth" },
	{ "hci_dev_close", (void *)&klpe_hci_dev_close, "bluetooth" },
	{ "hci_dev_reset", (void *)&klpe_hci_dev_reset, "bluetooth" },
	{ "hci_dev_reset_stat", (void *)&klpe_hci_dev_reset_stat, "bluetooth" },
	{ "hci_dev_cmd", (void *)&klpe_hci_dev_cmd, "bluetooth" },
	{ "hci_get_dev_list", (void *)&klpe_hci_get_dev_list, "bluetooth" },
	{ "hci_get_dev_info", (void *)&klpe_hci_get_dev_info, "bluetooth" },
	{ "hci_get_conn_list", (void *)&klpe_hci_get_conn_list, "bluetooth" },
	{ "hci_get_conn_info", (void *)&klpe_hci_get_conn_info, "bluetooth" },
	{ "hci_get_auth_info", (void *)&klpe_hci_get_auth_info, "bluetooth" },
	{ "hci_inquiry", (void *)&klpe_hci_inquiry, "bluetooth" },
	{ "hci_bdaddr_list_add", (void *)&klpe_hci_bdaddr_list_add,
	  "bluetooth" },
	{ "hci_bdaddr_list_del", (void *)&klpe_hci_bdaddr_list_del,
	  "bluetooth" },
	{ "hci_send_to_sock", (void *)&klpe_hci_send_to_sock, "bluetooth" },
	{ "hci_send_to_channel", (void *)&klpe_hci_send_to_channel,
	  "bluetooth" },
	{ "create_monitor_event", (void *)&klpe_create_monitor_event,
	  "bluetooth" },
	{ "create_monitor_ctrl_open", (void *)&klpe_create_monitor_ctrl_open,
	  "bluetooth" },
};

static int livepatch_bsc1187054_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1187054_module_nb = {
	.notifier_call = livepatch_bsc1187054_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1187054_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1187054_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1187054_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1187054_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
