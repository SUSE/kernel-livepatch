/*
 * livepatch_bsc1276493
 *
 * Fix for CVE-2026-64011, bsc#1276493
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_NFC)

#if !IS_MODULE(CONFIG_NFC)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1276493.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
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

#define LLCP_SAP_MAX   0xff

static void (*klpe_nfc_llcp_sock_unlink)(struct llcp_sock_list *l, struct sock *s);

static void (*klpe_nfc_llcp_put_ssap)(struct nfc_llcp_local *local, u8 ssap);

static void (*klpe_nfc_llcp_accept_unlink)(struct sock *sk);

static int (*klpe_nfc_llcp_send_disconnect)(struct nfc_llcp_sock *sock);

/* klp-ccp: from net/nfc/llcp_sock.c */
int klpp_llcp_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct nfc_llcp_local *local;
	struct nfc_llcp_sock *llcp_sock = 

/* klp-ccp: from net/nfc/llcp.h */
#define nfc_llcp_sock(sk) ((struct nfc_llcp_sock *) (sk))
/* klp-ccp: from net/nfc/llcp_sock.c */
nfc_llcp_sock(sk);
	int err = 0;

	if (!sk)
		return 0;

	pr_debug("%p\n", sk);

	local = llcp_sock->local;
	if (local == NULL) {
		err = -ENODEV;
		goto out;
	}

	lock_sock(sk);

	/* Send a DISC */
	if (sk->sk_state == LLCP_CONNECTED)
		(*klpe_nfc_llcp_send_disconnect)(llcp_sock);

	if (sk->sk_state == LLCP_LISTEN) {
		struct nfc_llcp_sock *lsk, *n;
		struct sock *accept_sk;

		list_for_each_entry_safe(lsk, n, &llcp_sock->accept_queue,
					 accept_queue) {
			accept_sk = &lsk->sk;
			lock_sock(accept_sk);

			(*klpe_nfc_llcp_send_disconnect)(lsk);
			(*klpe_nfc_llcp_accept_unlink)(accept_sk);

			release_sock(accept_sk);
		}
	}

	if (llcp_sock->reserved_ssap < LLCP_SAP_MAX)
		(*klpe_nfc_llcp_put_ssap)(llcp_sock->local, llcp_sock->ssap);

	release_sock(sk);

	/* Keep this sock alive and therefore do not remove it from the sockets
	 * list until the DISC PDU has been actually sent. Otherwise we would
	 * reply with DM PDUs before sending the DISC one.
	 */
	if (sk->sk_state == LLCP_DISCONNECTING)
		return err;

	if (sock->type == SOCK_RAW)
		(*klpe_nfc_llcp_sock_unlink)(&local->raw_sockets, sk);
	else if (sk->sk_state == LLCP_CONNECTING)
		(*klpe_nfc_llcp_sock_unlink)(&local->connecting_sockets, sk);
	else
		(*klpe_nfc_llcp_sock_unlink)(&local->sockets, sk);

out:
	sock_orphan(sk);
	sock_put(sk);

	return err;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nfc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfc_llcp_accept_unlink", (void *)&klpe_nfc_llcp_accept_unlink,
	  "nfc" },
	{ "nfc_llcp_put_ssap", (void *)&klpe_nfc_llcp_put_ssap, "nfc" },
	{ "nfc_llcp_send_disconnect", (void *)&klpe_nfc_llcp_send_disconnect,
	  "nfc" },
	{ "nfc_llcp_sock_unlink", (void *)&klpe_nfc_llcp_sock_unlink, "nfc" },
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

int livepatch_bsc1276493_init(void)
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

void livepatch_bsc1276493_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC) */
