/*
 * livepatch_bsc1275228
 *
 * Fix for CVE-2026-68121, bsc#1275228
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

#if IS_ENABLED(CONFIG_PPPOE)

#if !IS_MODULE(CONFIG_PPPOE)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1275228.h"


/* klp-ccp: from drivers/net/ppp/pppoe.c */
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>
#include <linux/ppp_channel.h>
#include <linux/ppp_defs.h>
#include <linux/ppp-ioctl.h>
#include <linux/notifier.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <linux/uaccess.h>

int klpp_pppoe_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	struct sk_buff *skb;
	struct sock *sk = sock->sk;
	struct pppox_sock *po = pppox_sk(sk);
	int error;
	struct pppoe_hdr hdr;
	struct pppoe_hdr *ph;
	struct net_device *dev;
	char *start;
	int hlen;

	lock_sock(sk);
	if (sock_flag(sk, SOCK_DEAD) || !(sk->sk_state & PPPOX_CONNECTED)) {
		error = -ENOTCONN;
		goto end;
	}

	hdr.ver = 1;
	hdr.type = 1;
	hdr.code = 0;
	hdr.sid = po->num;

	dev = po->pppoe_dev;

	error = -EMSGSIZE;
	if (total_len > (dev->mtu + dev->hard_header_len))
		goto end;

	hlen = LL_RESERVED_SPACE(dev);
	skb = sock_wmalloc(sk, hlen + sizeof(*ph) + total_len +
			   dev->needed_tailroom, 0, GFP_KERNEL);
	if (!skb) {
		error = -ENOMEM;
		goto end;
	}

	/* Reserve space for headers. */
	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);

	skb->dev = dev;

	skb->priority = READ_ONCE(sk->sk_priority);
	skb->protocol = cpu_to_be16(ETH_P_PPP_SES);

	ph = skb_put(skb, total_len + sizeof(struct pppoe_hdr));
	start = (char *)&ph->tag[0];

	error = memcpy_from_msg(start, m, total_len);
	if (error < 0) {
		kfree_skb(skb);
		goto end;
	}

	error = total_len;
	dev_hard_header(skb, dev, ETH_P_PPP_SES,
			po->pppoe_pa.remote, NULL, total_len);

	ph = pppoe_hdr(skb);
	memcpy(ph, &hdr, sizeof(struct pppoe_hdr));

	ph->length = htons(total_len);

	dev_queue_xmit(skb);

end:
	release_sock(sk);
	return error;
}



#endif /* IS_ENABLED(CONFIG_PPPOE) */
