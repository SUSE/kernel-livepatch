/*
 * livepatch_bsc1190432
 *
 * Fix for CVE-2021-3752, bsc#1190432
 *
 *  Upstream commit:
 *  3af70b39fa2d ("Bluetooth: check for zapped sk before connecting")
 *
 *  SLE12-SP3 commit:
 *  1e8e3c37cc88d8e7169b4371ee888ea1dd291ca4
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  7504476e7d7e6c6b7bd0beb235dd3bcb8b9e5fdd
 *
 *  SLE15-SP2 and SLE15-SP3 commit:
 *  0ff2558ac0be701cc27fdd24f7bcf1d16ecdb30e
 *
 *
 *  Copyright (c) 2021 SUSE
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
#error "Live patch supports only CONFIG_BT=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1190432.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "bluetooth"

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
#include <linux/module.h>
#include <linux/export.h>
#include <linux/sched/signal.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static int  (*klpe_bt_sock_wait_state)(struct sock *sk, int state, unsigned long timeo);

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from include/net/bluetooth/l2cap.h */
static int (*klpe_l2cap_chan_connect)(struct l2cap_chan *chan, __le16 psm, u16 cid,
		       bdaddr_t *dst, u8 dst_type);

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
int klpp_l2cap_sock_connect(struct socket *sock, struct sockaddr *addr,
			      int alen, int flags)
{
	struct sock *sk = sock->sk;
	struct l2cap_chan *chan = l2cap_pi(sk)->chan;
	struct sockaddr_l2 la;
	int len, err = 0;
	/*
	 * Fix CVE-2021-3752
	 *  +1 line
	 */
	bool zapped;

	BT_DBG("sk %p", sk);

	/*
	 * Fix CVE-2021-3752
	 *  +7 lines
	 */
	lock_sock(sk);
	zapped = sock_flag(sk, SOCK_ZAPPED);
	release_sock(sk);

	if (zapped)
		return -EINVAL;

	if (!addr || alen < sizeof(addr->sa_family) ||
	    addr->sa_family != AF_BLUETOOTH)
		return -EINVAL;

	memset(&la, 0, sizeof(la));
	len = min_t(unsigned int, sizeof(la), alen);
	memcpy(&la, addr, len);

	if (la.l2_cid && la.l2_psm)
		return -EINVAL;

	if (!bdaddr_type_is_valid(la.l2_bdaddr_type))
		return -EINVAL;

	/* Check that the socket wasn't bound to something that
	 * conflicts with the address given to connect(). If chan->src
	 * is BDADDR_ANY it means bind() was never used, in which case
	 * chan->src_type and la.l2_bdaddr_type do not need to match.
	 */
	if (chan->src_type == BDADDR_BREDR && bacmp(&chan->src, BDADDR_ANY) &&
	    bdaddr_type_is_le(la.l2_bdaddr_type)) {
		/* Old user space versions will try to incorrectly bind
		 * the ATT socket using BDADDR_BREDR. We need to accept
		 * this and fix up the source address type only when
		 * both the source CID and destination CID indicate
		 * ATT. Anything else is an invalid combination.
		 */
		if (chan->scid != L2CAP_CID_ATT ||
		    la.l2_cid != cpu_to_le16(L2CAP_CID_ATT))
			return -EINVAL;

		/* We don't have the hdev available here to make a
		 * better decision on random vs public, but since all
		 * user space versions that exhibit this issue anyway do
		 * not support random local addresses assuming public
		 * here is good enough.
		 */
		chan->src_type = BDADDR_LE_PUBLIC;
	}

	if (chan->src_type != BDADDR_BREDR && la.l2_bdaddr_type == BDADDR_BREDR)
		return -EINVAL;

	if (bdaddr_type_is_le(la.l2_bdaddr_type)) {
		/* We only allow ATT user space socket */
		if (la.l2_cid &&
		    la.l2_cid != cpu_to_le16(L2CAP_CID_ATT))
			return -EINVAL;
	}

	if (chan->psm && bdaddr_type_is_le(chan->src_type))
		chan->mode = L2CAP_MODE_LE_FLOWCTL;

	err = (*klpe_l2cap_chan_connect)(chan, la.l2_psm, __le16_to_cpu(la.l2_cid),
				 &la.l2_bdaddr, la.l2_bdaddr_type);
	if (err)
		return err;

	lock_sock(sk);

	err = (*klpe_bt_sock_wait_state)(sk, BT_CONNECTED,
				 sock_sndtimeo(sk, flags & O_NONBLOCK));

	release_sock(sk);

	return err;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bt_sock_wait_state", (void *)&klpe_bt_sock_wait_state, "bluetooth" },
	{ "l2cap_chan_connect", (void *)&klpe_l2cap_chan_connect, "bluetooth" },
};

static int livepatch_bsc1190432_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1190432_module_nb = {
	.notifier_call = livepatch_bsc1190432_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1190432_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1190432_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1190432_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1190432_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
