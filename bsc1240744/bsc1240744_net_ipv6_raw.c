/*
 * bsc1240744_net_ipv6_raw
 *
 * Fix for CVE-2025-21791, bsc#1240744
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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


#define __KERNEL__ 1
#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1

/* klp-ccp: from net/ipv6/raw.c */
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>

/* klp-ccp: from include/linux/if_arp.h */
#define _LINUX_IF_ARP_H

/* klp-ccp: from include/uapi/linux/if_arp.h */
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from net/ipv6/raw.c */
#include <linux/icmpv6.h>
#include <linux/netfilter.h>

#include <linux/skbuff.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>

#include <net/net_namespace.h>
#include <net/ip.h>

/* klp-ccp: from include/net/l3mdev.h */
#ifdef CONFIG_NET_L3_MASTER_DEV

static inline
struct sk_buff *klpp_l3mdev_l3_out(struct sock *sk, struct sk_buff *skb, u16 proto)
{
	struct net_device *dev = skb_dst(skb)->dev;

	if (netif_is_l3_slave(dev)) {
		struct net_device *master;

		rcu_read_lock();
		master = netdev_master_upper_dev_get_rcu(dev);
		if (master && master->l3mdev_ops->l3mdev_l3_out)
			skb = master->l3mdev_ops->l3mdev_l3_out(master, sk,
								skb, proto);
		rcu_read_unlock();
	}

	return skb;
}

static inline
struct sk_buff *klpr_l3mdev_ip6_out(struct sock *sk, struct sk_buff *skb)
{
	return klpp_l3mdev_l3_out(sk, skb, AF_INET6);
}
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from include/net/ipv6.h */
static void (*klpe_ipv6_local_error)(struct sock *sk, int err, struct flowi6 *fl6, u32 info);

/* klp-ccp: from net/ipv6/raw.c */
#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/ndisc.h>

#include <net/ip6_route.h>

#include <net/addrconf.h>
#include <net/transp_v6.h>

#include <net/tcp_states.h>

#include <linux/seq_file.h>
#include <linux/export.h>
#include <net/ip6_checksum.h>

static int rawv6_push_pending_frames(struct sock *sk, struct flowi6 *fl6,
				     struct raw6_sock *rp)
{
	struct ipv6_txoptions *opt;
	struct sk_buff *skb;
	int err = 0;
	int offset;
	int len;
	int total_len;
	__wsum tmp_csum;
	__sum16 csum;

	if (!rp->checksum)
		goto send;

	skb = skb_peek(&sk->sk_write_queue);
	if (!skb)
		goto out;

	offset = rp->offset;
	total_len = inet_sk(sk)->cork.base.length;
	opt = inet6_sk(sk)->cork.opt;
	total_len -= opt ? opt->opt_flen : 0;

	if (offset >= total_len - 1) {
		err = -EINVAL;
		ip6_flush_pending_frames(sk);
		goto out;
	}

	/* should be check HW csum miyazawa */
	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		/*
		 * Only one fragment on the socket.
		 */
		tmp_csum = skb->csum;
	} else {
		struct sk_buff *csum_skb = NULL;
		tmp_csum = 0;

		skb_queue_walk(&sk->sk_write_queue, skb) {
			tmp_csum = csum_add(tmp_csum, skb->csum);

			if (csum_skb)
				continue;

			len = skb->len - skb_transport_offset(skb);
			if (offset >= len) {
				offset -= len;
				continue;
			}

			csum_skb = skb;
		}

		skb = csum_skb;
	}

	offset += skb_transport_offset(skb);
	err = skb_copy_bits(skb, offset, &csum, 2);
	if (err < 0) {
		ip6_flush_pending_frames(sk);
		goto out;
	}

	/* in case cksum was not initialized */
	if (unlikely(csum))
		tmp_csum = csum_sub(tmp_csum, csum_unfold(csum));

	csum = csum_ipv6_magic(&fl6->saddr, &fl6->daddr,
			       total_len, fl6->flowi6_proto, tmp_csum);

	if (csum == 0 && fl6->flowi6_proto == IPPROTO_UDP)
		csum = CSUM_MANGLED_0;

	BUG_ON(skb_store_bits(skb, offset, &csum, 2));

send:
	err = ip6_push_pending_frames(sk);
out:
	return err;
}

static int klpp_rawv6_send_hdrinc(struct sock *sk, struct msghdr *msg, int length,
			struct flowi6 *fl6, struct dst_entry **dstp,
			unsigned int flags)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct net *net = sock_net(sk);
	struct ipv6hdr *iph;
	struct sk_buff *skb;
	int err;
	struct rt6_info *rt = (struct rt6_info *)*dstp;
	int hlen = LL_RESERVED_SPACE(rt->dst.dev);
	int tlen = rt->dst.dev->needed_tailroom;

	if (length > rt->dst.dev->mtu) {
		(*klpe_ipv6_local_error)(sk, EMSGSIZE, fl6, rt->dst.dev->mtu);
		return -EMSGSIZE;
	}
	if (length < sizeof(struct ipv6hdr))
		return -EINVAL;
	if (flags&MSG_PROBE)
		goto out;

	skb = sock_alloc_send_skb(sk,
				  length + hlen + tlen + 15,
				  flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto error;
	skb_reserve(skb, hlen);

	skb->protocol = htons(ETH_P_IPV6);
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	skb_put(skb, length);
	skb_reset_network_header(skb);
	iph = ipv6_hdr(skb);

	skb->ip_summed = CHECKSUM_NONE;

	if (flags & MSG_CONFIRM)
		skb_set_dst_pending_confirm(skb, 1);

	skb->transport_header = skb->network_header;
	err = memcpy_from_msg(iph, msg, length);
	if (err) {
		err = -EFAULT;
		kfree_skb(skb);
		goto error;
	}

	skb_dst_set(skb, &rt->dst);
	*dstp = NULL;

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = klpr_l3mdev_ip6_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	/* Acquire rcu_read_lock() in case we need to use rt->rt6i_idev
	 * in the error path. Since skb has been freed, the dst could
	 * have been queued for deletion.
	 */
	rcu_read_lock();
	IP6_UPD_PO_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUT, skb->len);
	err = NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_OUT, net, sk, skb,
		      NULL, rt->dst.dev, dst_output);
	if (err > 0)
		err = net_xmit_errno(err);
	if (err) {
		IP6_INC_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
		rcu_read_unlock();
		goto error_check;
	}
	rcu_read_unlock();
out:
	return 0;

error:
	IP6_INC_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
error_check:
	if (err == -ENOBUFS && !np->recverr)
		err = 0;
	return err;
}

struct raw6_frag_vec {
	struct msghdr *msg;
	int hlen;
	char c[4];
};

static int rawv6_probe_proto_opt(struct raw6_frag_vec *rfv, struct flowi6 *fl6)
{
	int err = 0;
	switch (fl6->flowi6_proto) {
	case IPPROTO_ICMPV6:
		rfv->hlen = 2;
		err = memcpy_from_msg(rfv->c, rfv->msg, rfv->hlen);
		if (!err) {
			fl6->fl6_icmp_type = rfv->c[0];
			fl6->fl6_icmp_code = rfv->c[1];
		}
		break;
	case IPPROTO_MH:
		rfv->hlen = 4;
		err = memcpy_from_msg(rfv->c, rfv->msg, rfv->hlen);
		if (!err)
			fl6->fl6_mh_type = rfv->c[2];
	}
	return err;
}

static int (*klpe_raw6_getfrag)(void *from, char *to, int offset, int len, int odd,
		       struct sk_buff *skb);

int klpp_rawv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct ipv6_txoptions *opt_to_free = NULL;
	struct ipv6_txoptions opt_space;
	DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, msg->msg_name);
	struct in6_addr *daddr, *final_p, final;
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct raw6_sock *rp = raw6_sk(sk);
	struct ipv6_txoptions *opt = NULL;
	struct ip6_flowlabel *flowlabel = NULL;
	struct dst_entry *dst = NULL;
	struct raw6_frag_vec rfv;
	struct flowi6 fl6;
	struct sockcm_cookie sockc;
	struct ipcm6_cookie ipc6;
	int addr_len = msg->msg_namelen;
	int hdrincl;
	u16 proto;
	int err;

	/* Rough check on arithmetic overflow,
	   better check is made in ip6_append_data().
	 */
	if (len > INT_MAX)
		return -EMSGSIZE;

	/* Mirror BSD error message compatibility */
	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	/* hdrincl should be READ_ONCE(inet->hdrincl)
	 * but READ_ONCE() doesn't work with bit fields.
	 * Doing this indirectly yields the same result.
	 */
	hdrincl = inet->hdrincl;
	hdrincl = READ_ONCE(hdrincl);

	/*
	 *	Get and verify the address.
	 */
	memset(&fl6, 0, sizeof(fl6));

	fl6.flowi6_mark = sk->sk_mark;
	fl6.flowi6_uid = sk->sk_uid;

	ipc6.hlimit = -1;
	ipc6.tclass = -1;
	ipc6.dontfrag = -1;
	ipc6.opt = NULL;

	if (sin6) {
		if (addr_len < SIN6_LEN_RFC2133)
			return -EINVAL;

		if (sin6->sin6_family && sin6->sin6_family != AF_INET6)
			return -EAFNOSUPPORT;

		/* port is the proto value [0..255] carried in nexthdr */
		proto = ntohs(sin6->sin6_port);

		if (!proto)
			proto = inet->inet_num;
		else if (proto != inet->inet_num)
			return -EINVAL;

		if (proto > 255)
			return -EINVAL;

		daddr = &sin6->sin6_addr;
		if (np->sndflow) {
			fl6.flowlabel = sin6->sin6_flowinfo&IPV6_FLOWINFO_MASK;
			if (fl6.flowlabel&IPV6_FLOWLABEL_MASK) {
				flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
				if (!flowlabel)
					return -EINVAL;
			}
		}

		/*
		 * Otherwise it will be difficult to maintain
		 * sk->sk_dst_cache.
		 */
		if (sk->sk_state == TCP_ESTABLISHED &&
		    ipv6_addr_equal(daddr, &sk->sk_v6_daddr))
			daddr = &sk->sk_v6_daddr;

		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    sin6->sin6_scope_id &&
		    __ipv6_addr_needs_scope_id(__ipv6_addr_type(daddr)))
			fl6.flowi6_oif = sin6->sin6_scope_id;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;

		proto = inet->inet_num;
		daddr = &sk->sk_v6_daddr;
		fl6.flowlabel = np->flow_label;
	}

	if (fl6.flowi6_oif == 0)
		fl6.flowi6_oif = sk->sk_bound_dev_if;

	sockc.tsflags = sk->sk_tsflags;
	if (msg->msg_controllen) {
		opt = &opt_space;
		memset(opt, 0, sizeof(struct ipv6_txoptions));
		opt->tot_len = sizeof(struct ipv6_txoptions);
		ipc6.opt = opt;

		err = ip6_datagram_send_ctl(sock_net(sk), sk, msg, &fl6, &ipc6, &sockc);
		if (err < 0) {
			fl6_sock_release(flowlabel);
			return err;
		}
		if ((fl6.flowlabel&IPV6_FLOWLABEL_MASK) && !flowlabel) {
			flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
			if (!flowlabel)
				return -EINVAL;
		}
		if (!(opt->opt_nflen|opt->opt_flen))
			opt = NULL;
	}
	if (!opt) {
		opt = txopt_get(np);
		opt_to_free = opt;
	}
	if (flowlabel)
		opt = fl6_merge_options(&opt_space, flowlabel, opt);
	opt = ipv6_fixup_options(&opt_space, opt);

	fl6.flowi6_proto = proto;

	if (!hdrincl) {
		rfv.msg = msg;
		rfv.hlen = 0;
		err = rawv6_probe_proto_opt(&rfv, &fl6);
		if (err)
			goto out;
	}

	if (!ipv6_addr_any(daddr))
		fl6.daddr = *daddr;
	else
		fl6.daddr.s6_addr[15] = 0x1; /* :: means loopback (BSD'ism) */
	if (ipv6_addr_any(&fl6.saddr) && !ipv6_addr_any(&np->saddr))
		fl6.saddr = np->saddr;

	final_p = fl6_update_dst(&fl6, opt, &final);

	if (!fl6.flowi6_oif && ipv6_addr_is_multicast(&fl6.daddr))
		fl6.flowi6_oif = np->mcast_oif;
	else if (!fl6.flowi6_oif)
		fl6.flowi6_oif = np->ucast_oif;
	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	if (hdrincl)
		fl6.flowi6_flags |= FLOWI_FLAG_KNOWN_NH;

	if (ipc6.tclass < 0)
		ipc6.tclass = np->tclass;

	fl6.flowlabel = ip6_make_flowinfo(ipc6.tclass, fl6.flowlabel);

	dst = ip6_dst_lookup_flow__net(sock_net(sk), sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto out;
	}
	if (ipc6.hlimit < 0)
		ipc6.hlimit = ip6_sk_dst_hoplimit(np, &fl6, dst);

	if (ipc6.dontfrag < 0)
		ipc6.dontfrag = np->dontfrag;

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;

back_from_confirm:
	if (hdrincl)
		err = klpp_rawv6_send_hdrinc(sk, msg, len, &fl6, &dst, msg->msg_flags);
	else {
		ipc6.opt = opt;
		lock_sock(sk);
		err = ip6_append_data(sk, (*klpe_raw6_getfrag), &rfv,
			len, 0, &ipc6, &fl6, (struct rt6_info *)dst,
			msg->msg_flags, &sockc);

		if (err)
			ip6_flush_pending_frames(sk);
		else if (!(msg->msg_flags & MSG_MORE))
			err = rawv6_push_pending_frames(sk, &fl6, rp);
		release_sock(sk);
	}
done:
	dst_release(dst);
out:
	fl6_sock_release(flowlabel);
	txopt_put(opt_to_free);
	return err < 0 ? err : len;
do_confirm:
	if (msg->msg_flags & MSG_PROBE)
		dst_confirm_neigh(dst, &fl6.daddr);
	if (!(msg->msg_flags & MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto done;
}


#include "livepatch_bsc1240744.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ipv6_local_error", (void *)&klpe_ipv6_local_error },
	{ "raw6_getfrag", (void *)&klpe_raw6_getfrag },
};

int bsc1240744_net_ipv6_raw_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

