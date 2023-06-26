/*
 * livepatch_bsc1210566
 *
 * Fix for CVE-2023-2002, bsc#1210566
 *
 *  Upstream commit:
 *  25c150ac103a ("bluetooth: Perform careful capability checks in hci_sock_ioctl()")
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
 *  cb9bcb29cd0fe0213c1584d2107191143825422e
 *
 *  SLE15-SP2 and -SP3 commit:
 *  cb86eb05a16ba2cd835398728bbc1a562899179b
 *
 *  SLE15-SP4 and -SP5 commit:
 *  ce41906048051bc155e9f6ba50d58b147fff47aa
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG=m"
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

static void (*klpe_hci_send_to_channel)(unsigned short channel, struct sk_buff *skb,
			 int flag, struct sock *skip_sk);

/* klp-ccp: from net/bluetooth/hci_sock.c */
static struct ida (*klpe_sock_cookie_ida);

#define hci_pi(sk) ((struct hci_pinfo *) sk)

struct hci_pinfo {
	struct bt_sock    bt;
	struct hci_dev    *hdev;
	struct hci_filter filter;
	__u8              cmsg_mask;
	unsigned short    channel;
	unsigned long     flags;
	__u32             cookie;
	char              comm[TASK_COMM_LEN];
	__u16             mtu;
};

static struct hci_dev *hci_hdev_from_sock(struct sock *sk)
{
	struct hci_dev *hdev = hci_pi(sk)->hdev;

	if (!hdev)
		return ERR_PTR(-EBADFD);
	if (hci_dev_test_flag(hdev, HCI_UNREGISTER))
		return ERR_PTR(-EPIPE);
	return hdev;
}

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

static struct sk_buff *(*klpe_create_monitor_ctrl_open)(struct sock *sk);

static int klpr_hci_sock_reject_list_add(struct hci_dev *hdev, void __user *arg)
{
	bdaddr_t bdaddr;
	int err;

	if (copy_from_user(&bdaddr, arg, sizeof(bdaddr)))
		return -EFAULT;

	hci_dev_lock(hdev);

	err = (*klpe_hci_bdaddr_list_add)(&hdev->reject_list, &bdaddr, BDADDR_BREDR);

	hci_dev_unlock(hdev);

	return err;
}

static int klpr_hci_sock_reject_list_del(struct hci_dev *hdev, void __user *arg)
{
	bdaddr_t bdaddr;
	int err;

	if (copy_from_user(&bdaddr, arg, sizeof(bdaddr)))
		return -EFAULT;

	hci_dev_lock(hdev);

	err = (*klpe_hci_bdaddr_list_del)(&hdev->reject_list, &bdaddr, BDADDR_BREDR);

	hci_dev_unlock(hdev);

	return err;
}

static int klpr_hci_sock_bound_ioctl(struct sock *sk, unsigned int cmd,
				unsigned long arg)
{
	struct hci_dev *hdev = hci_hdev_from_sock(sk);

	if (IS_ERR(hdev))
		return PTR_ERR(hdev);

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
		return klpr_hci_sock_reject_list_add(hdev, (void __user *)arg);

	case HCIUNBLOCKADDR:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return klpr_hci_sock_reject_list_del(hdev, (void __user *)arg);
	}

	return -ENOIOCTLCMD;
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


		/* Perform careful checks before setting the HCI_SOCK_TRUSTED
		 * flag. Make sure that not only the current task but also
		 * the socket opener has the required capability, since
		 * privileged programs can be tricked into making ioctl calls
		 * on HCI sockets, and the socket should not be marked as
		 * trusted simply because the ioctl caller is privileged.
		 */
		if (sk_capable(sk, CAP_NET_ADMIN))
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

	err = klpr_hci_sock_bound_ioctl(sk, cmd, arg);

done:
	release_sock(sk);
	return err;
}



#define LP_MODULE "bluetooth"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1210566.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "create_monitor_ctrl_open", (void *)&klpe_create_monitor_ctrl_open,
	  "bluetooth" },
	{ "hci_bdaddr_list_add", (void *)&klpe_hci_bdaddr_list_add,
	  "bluetooth" },
	{ "hci_bdaddr_list_del", (void *)&klpe_hci_bdaddr_list_del,
	  "bluetooth" },
	{ "hci_dev_close", (void *)&klpe_hci_dev_close, "bluetooth" },
	{ "hci_dev_cmd", (void *)&klpe_hci_dev_cmd, "bluetooth" },
	{ "hci_dev_open", (void *)&klpe_hci_dev_open, "bluetooth" },
	{ "hci_dev_reset", (void *)&klpe_hci_dev_reset, "bluetooth" },
	{ "hci_dev_reset_stat", (void *)&klpe_hci_dev_reset_stat,
	  "bluetooth" },
	{ "hci_get_auth_info", (void *)&klpe_hci_get_auth_info, "bluetooth" },
	{ "hci_get_conn_info", (void *)&klpe_hci_get_conn_info, "bluetooth" },
	{ "hci_get_conn_list", (void *)&klpe_hci_get_conn_list, "bluetooth" },
	{ "hci_get_dev_info", (void *)&klpe_hci_get_dev_info, "bluetooth" },
	{ "hci_get_dev_list", (void *)&klpe_hci_get_dev_list, "bluetooth" },
	{ "hci_inquiry", (void *)&klpe_hci_inquiry, "bluetooth" },
	{ "hci_send_to_channel", (void *)&klpe_hci_send_to_channel,
	  "bluetooth" },
	{ "hci_sock_set_flag", (void *)&klpe_hci_sock_set_flag, "bluetooth" },
	{ "sock_cookie_ida", (void *)&klpe_sock_cookie_ida, "bluetooth" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1210566_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1210566_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
