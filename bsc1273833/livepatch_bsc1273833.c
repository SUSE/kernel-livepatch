/*
 * livepatch_bsc1273833
 *
 * Fix for CVE-2026-64114, bsc#1273833
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


#include "livepatch_bsc1273833.h"


/* klp-ccp: from net/ipv4/raw.c */
#include <linux/types.h>
#include <linux/atomic.h>
#include <asm/byteorder.h>
#include <asm/current.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/sockios.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/mroute.h>
#include <linux/netdevice.h>
#include <linux/in_route.h>
#include <linux/route.h>
#include <linux/skbuff.h>
#include <linux/igmp.h>
#include <net/net_namespace.h>
#include <net/dst.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/raw.h>
#include <net/snmp.h>
#include <net/tcp_states.h>
#include <net/inet_common.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/compat.h>
#include <linux/uio.h>

struct raw_frag_vec {
	struct msghdr *msg;
	union {
		struct icmphdr icmph;
		char c[1];
	} hdr;
	int hlen;
};

static int klpp_raw_send_hdrinc(struct sock *sk, struct flowi4 *fl4,
			   struct msghdr *msg, size_t length,
			   struct rtable **rtp, unsigned int flags,
			   const struct sockcm_cookie *sockc)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct iphdr *iph;
	struct sk_buff *skb;
	unsigned int iphlen;
	int err;
	struct rtable *rt = *rtp;
	int hlen, tlen;

	if (length > rt->dst.dev->mtu) {
		ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
			       rt->dst.dev->mtu);
		return -EMSGSIZE;
	}
	if (length < sizeof(struct iphdr))
		return -EINVAL;

	if (flags&MSG_PROBE)
		goto out;

	hlen = LL_RESERVED_SPACE(rt->dst.dev);
	tlen = rt->dst.dev->needed_tailroom;
	skb = sock_alloc_send_skb(sk,
				  length + hlen + tlen + 15,
				  flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto error;
	skb_reserve(skb, hlen);

	skb->protocol = htons(ETH_P_IP);
	skb->priority = READ_ONCE(sk->sk_priority);
	skb->mark = sockc->mark;
	skb->tstamp = sockc->transmit_time;
	skb_dst_set(skb, &rt->dst);
	*rtp = NULL;

	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	skb_put(skb, length);

	skb->ip_summed = CHECKSUM_NONE;

	skb_setup_tx_timestamp(skb, sockc->tsflags);

	if (flags & MSG_CONFIRM)
		skb_set_dst_pending_confirm(skb, 1);

	skb->transport_header = skb->network_header;
	err = -EFAULT;
	if (memcpy_from_msg(iph, msg, length))
		goto error_free;

	iphlen = iph->ihl * 4;

	/*
	 * We don't want to modify the ip header, but we do need to
	 * be sure that it won't cause problems later along the network
	 * stack.  Specifically we want to make sure that iph->ihl is a
	 * sane value.  If ihl points beyond the length of the buffer passed
	 * in, reject the frame as invalid
	 */
	err = -EINVAL;
	if (iphlen > length || iphlen < sizeof(*iph))
		goto error_free;

	if (iphlen >= sizeof(*iph)) {
		if (!iph->saddr)
			iph->saddr = fl4->saddr;
		iph->check   = 0;
		iph->tot_len = htons(length);
		if (!iph->id)
			ip_select_ident(net, skb, NULL);

		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
		skb->transport_header += iphlen;
		if (iph->protocol == IPPROTO_ICMP &&
		    length >= iphlen + sizeof(struct icmphdr))
			icmp_out_count(net, ((struct icmphdr *)
				skb_transport_header(skb))->type);
	}

	err = NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
		      net, sk, skb, NULL, rt->dst.dev,
		      dst_output);
	if (err > 0)
		err = net_xmit_errno(err);
	if (err)
		goto error;
out:
	return 0;

error_free:
	kfree_skb(skb);
error:
	IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	if (err == -ENOBUFS && !inet->recverr)
		err = 0;
	return err;
}

static int raw_probe_proto_opt(struct raw_frag_vec *rfv, struct flowi4 *fl4)
{
	int err;

	if (fl4->flowi4_proto != IPPROTO_ICMP)
		return 0;

	/* We only need the first two bytes. */
	rfv->hlen = 2;

	err = memcpy_from_msg(rfv->hdr.c, rfv->msg, rfv->hlen);
	if (err)
		return err;

	fl4->fl4_icmp_type = rfv->hdr.icmph.type;
	fl4->fl4_icmp_code = rfv->hdr.icmph.code;

	return 0;
}

extern int raw_getfrag(void *from, char *to, int offset, int len, int odd,
		       struct sk_buff *skb);

int klpp_raw_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	int free = 0;
	__be32 daddr;
	__be32 saddr;
	u8  tos;
	int err;
	struct ip_options_data opt_copy;
	struct raw_frag_vec rfv;
	int hdrincl;

	err = -EMSGSIZE;
	if (len > 0xFFFF)
		goto out;

	/* hdrincl should be READ_ONCE(inet->hdrincl)
	 * but READ_ONCE() doesn't work with bit fields.
	 * Doing this indirectly yields the same result.
	 */
	hdrincl = inet->hdrincl;
	hdrincl = READ_ONCE(hdrincl);
	/*
	 *	Check the flags.
	 */

	err = -EOPNOTSUPP;
	if (msg->msg_flags & MSG_OOB)	/* Mirror BSD error message */
		goto out;               /* compatibility */

	/*
	 *	Get and verify the address.
	 */

	if (msg->msg_namelen) {
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(*usin))
			goto out;
		if (usin->sin_family != AF_INET) {
			pr_info_once("%s: %s forgot to set AF_INET. Fix it!\n",
				     __func__, current->comm);
			err = -EAFNOSUPPORT;
			if (usin->sin_family)
				goto out;
		}
		daddr = usin->sin_addr.s_addr;
		/* ANK: I did not forget to get protocol from port field.
		 * I just do not know, who uses this weirdness.
		 * IP_HDRINCL is much more convenient.
		 */
	} else {
		err = -EDESTADDRREQ;
		if (sk->sk_state != TCP_ESTABLISHED)
			goto out;
		daddr = inet->inet_daddr;
	}

	ipcm_init_sk(&ipc, inet);
	/* Keep backward compat */
	if (hdrincl)
		ipc.protocol = IPPROTO_RAW;

	if (msg->msg_controllen) {
		err = ip_cmsg_send(sk, msg, &ipc, false);
		if (unlikely(err)) {
			kfree(ipc.opt);
			goto out;
		}
		if (ipc.opt)
			free = 1;
	}

	saddr = ipc.addr;
	ipc.addr = daddr;

	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	if (ipc.opt) {
		err = -EINVAL;
		/* Linux does not mangle headers on raw sockets,
		 * so that IP options + IP_HDRINCL is non-sense.
		 */
		if (hdrincl)
			goto done;
		if (ipc.opt->opt.srr) {
			if (!daddr)
				goto done;
			daddr = ipc.opt->opt.faddr;
		}
	}
	tos = get_rtconn_flags(&ipc, sk);
	if (msg->msg_flags & MSG_DONTROUTE)
		tos |= RTO_ONLINK;

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	} else if (!ipc.oif) {
		ipc.oif = inet->uc_index;
	} else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
		/* oif is set, packet is to local broadcast
		 * and uc_index is set. oif is most likely set
		 * by sk_bound_dev_if. If uc_index != oif check if the
		 * oif is an L3 master and uc_index is an L3 slave.
		 * If so, we want to allow the send using the uc_index.
		 */
		if (ipc.oif != inet->uc_index &&
		    ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
							      inet->uc_index)) {
			ipc.oif = inet->uc_index;
		}
	}

	flowi4_init_output(&fl4, ipc.oif, ipc.sockc.mark, tos,
			   RT_SCOPE_UNIVERSE,
			   hdrincl ? ipc.protocol : sk->sk_protocol,
			   inet_sk_flowi_flags(sk) |
			    (hdrincl ? FLOWI_FLAG_KNOWN_NH : 0),
			   daddr, saddr, 0, 0, sk->sk_uid);

	fl4.fl4_icmp_type = 0;
	fl4.fl4_icmp_code = 0;

	if (!hdrincl) {
		rfv.msg = msg;
		rfv.hlen = 0;

		err = raw_probe_proto_opt(&rfv, &fl4);
		if (err)
			goto done;
	}

	security_sk_classify_flow(sk, flowi4_to_flowi_common(&fl4));
	rt = ip_route_output_flow(net, &fl4, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		rt = NULL;
		goto done;
	}

	err = -EACCES;
	if (rt->rt_flags & RTCF_BROADCAST && !sock_flag(sk, SOCK_BROADCAST))
		goto done;

	if (msg->msg_flags & MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	if (hdrincl)
		err = klpp_raw_send_hdrinc(sk, &fl4, msg, len,
				      &rt, msg->msg_flags, &ipc.sockc);

	 else {
		if (!ipc.addr)
			ipc.addr = fl4.daddr;
		lock_sock(sk);
		err = ip_append_data(sk, &fl4, raw_getfrag,
				     &rfv, len, 0,
				     &ipc, &rt, msg->msg_flags);
		if (err)
			ip_flush_pending_frames(sk);
		else if (!(msg->msg_flags & MSG_MORE)) {
			err = ip_push_pending_frames(sk, &fl4);
			if (err == -ENOBUFS && !inet->recverr)
				err = 0;
		}
		release_sock(sk);
	}
done:
	if (free)
		kfree(ipc.opt);
	ip_rt_put(rt);

out:
	if (err < 0)
		return err;
	return len;

do_confirm:
	if (msg->msg_flags & MSG_PROBE)
		dst_confirm_neigh(&rt->dst, &fl4.daddr);
	if (!(msg->msg_flags & MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto done;
}


#include <linux/livepatch.h>

extern typeof(icmp_out_count) icmp_out_count
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, icmp_out_count);
extern typeof(ip_append_data) ip_append_data
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip_append_data);
extern typeof(ip_cmsg_send) ip_cmsg_send
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip_cmsg_send);
extern typeof(ip_flush_pending_frames) ip_flush_pending_frames
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip_flush_pending_frames);
extern typeof(ip_local_error) ip_local_error
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip_local_error);
extern typeof(ip_push_pending_frames) ip_push_pending_frames
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip_push_pending_frames);
extern typeof(raw_getfrag) raw_getfrag
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, raw_getfrag);
