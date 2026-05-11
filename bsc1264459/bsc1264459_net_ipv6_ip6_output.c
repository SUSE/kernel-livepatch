/*
 * bsc1264459_net_ipv6_ip6_output
 *
 * Fix for CVE-2026-43284, bsc#1264459
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


#include "livepatch_bsc1264459.h"


/* klp-ccp: from net/ipv6/ip6_output.c */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/route.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/bpf-cgroup.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

/* klp-ccp: from include/net/ipv6.h */
int klpp_ip6_append_data(struct sock *sk,
		    int getfrag(void *from, char *to, int offset, int len,
				int odd, struct sk_buff *skb),
		    void *from, size_t length, int transhdrlen,
		    struct ipcm6_cookie *ipc6, struct flowi6 *fl6,
		    struct rt6_info *rt, unsigned int flags);

struct sk_buff *klpp_ip6_make_skb(struct sock *sk,
			     int getfrag(void *from, char *to, int offset,
					 int len, int odd, struct sk_buff *skb),
			     void *from, size_t length, int transhdrlen,
			     struct ipcm6_cookie *ipc6,
			     struct rt6_info *rt, unsigned int flags,
			     struct inet_cork_full *cork);

/* klp-ccp: from net/ipv6/ip6_output.c */
#include <net/sock.h>
#include <net/snmp.h>
#include <net/gso.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/rawv6.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/checksum.h>
#include <linux/mroute6.h>
#include <net/l3mdev.h>
#include <net/lwtunnel.h>
#include <net/ip_tunnels.h>

static void ip6_append_data_mtu(unsigned int *mtu,
				int *maxfraglen,
				unsigned int fragheaderlen,
				struct sk_buff *skb,
				struct rt6_info *rt,
				unsigned int orig_mtu)
{
	if (!(rt->dst.flags & DST_XFRM_TUNNEL)) {
		if (!skb) {
			/* first fragment, reserve header_len */
			*mtu = orig_mtu - rt->dst.header_len;

		} else {
			/*
			 * this fragment is not first, the headers
			 * space is regarded as data space.
			 */
			*mtu = orig_mtu;
		}
		*maxfraglen = ((*mtu - fragheaderlen) & ~7)
			      + fragheaderlen - sizeof(struct frag_hdr);
	}
}

extern int ip6_setup_cork(struct sock *sk, struct inet_cork_full *cork,
			  struct inet6_cork *v6_cork, struct ipcm6_cookie *ipc6,
			  struct rt6_info *rt);

static int klpp___ip6_append_data(struct sock *sk,
			     struct sk_buff_head *queue,
			     struct inet_cork_full *cork_full,
			     struct inet6_cork *v6_cork,
			     struct page_frag *pfrag,
			     int getfrag(void *from, char *to, int offset,
					 int len, int odd, struct sk_buff *skb),
			     void *from, size_t length, int transhdrlen,
			     unsigned int flags, struct ipcm6_cookie *ipc6)
{
	struct sk_buff *skb, *skb_prev = NULL;
	struct inet_cork *cork = &cork_full->base;
	struct flowi6 *fl6 = &cork_full->fl.u.ip6;
	unsigned int maxfraglen, fragheaderlen, mtu, orig_mtu, pmtu;
	struct ubuf_info *uarg = NULL;
	int exthdrlen = 0;
	int dst_exthdrlen = 0;
	int hh_len;
	int copy;
	int err;
	int offset = 0;
	bool zc = false;
	u32 tskey = 0;
	struct rt6_info *rt = (struct rt6_info *)cork->dst;
	struct ipv6_txoptions *opt = v6_cork->opt;
	int csummode = CHECKSUM_NONE;
	unsigned int maxnonfragsize, headersize;
	unsigned int wmem_alloc_delta = 0;
	bool paged, extra_uref = false;

	skb = skb_peek_tail(queue);
	if (!skb) {
		exthdrlen = opt ? opt->opt_flen : 0;
		dst_exthdrlen = rt->dst.header_len - rt->rt6i_nfheader_len;
	}

	paged = !!cork->gso_size;
	mtu = cork->gso_size ? IP6_MAX_MTU : cork->fragsize;
	orig_mtu = mtu;

	if (cork->tx_flags & SKBTX_ANY_TSTAMP &&
	    READ_ONCE(sk->sk_tsflags) & SOF_TIMESTAMPING_OPT_ID)
		tskey = atomic_inc_return(&sk->sk_tskey) - 1;

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	fragheaderlen = sizeof(struct ipv6hdr) + rt->rt6i_nfheader_len +
			(opt ? opt->opt_nflen : 0);

	headersize = sizeof(struct ipv6hdr) +
		     (opt ? opt->opt_flen + opt->opt_nflen : 0) +
		     (dst_allfrag(&rt->dst) ?
		      sizeof(struct frag_hdr) : 0) +
		     rt->rt6i_nfheader_len;

	if (mtu <= fragheaderlen ||
	    ((mtu - fragheaderlen) & ~7) + fragheaderlen <= sizeof(struct frag_hdr))
		goto emsgsize;

	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen -
		     sizeof(struct frag_hdr);

	/* as per RFC 7112 section 5, the entire IPv6 Header Chain must fit
	 * the first fragment
	 */
	if (headersize + transhdrlen > mtu)
		goto emsgsize;

	if (cork->length + length > mtu - headersize && ipc6->dontfrag &&
	    (sk->sk_protocol == IPPROTO_UDP ||
	     sk->sk_protocol == IPPROTO_ICMPV6 ||
	     sk->sk_protocol == IPPROTO_RAW)) {
		ipv6_local_rxpmtu(sk, fl6, mtu - headersize +
				sizeof(struct ipv6hdr));
		goto emsgsize;
	}

	if (ip6_sk_ignore_df(sk))
		maxnonfragsize = sizeof(struct ipv6hdr) + IPV6_MAXPLEN;
	else
		maxnonfragsize = mtu;

	if (cork->length + length > maxnonfragsize - headersize) {
emsgsize:
		pmtu = max_t(int, mtu - headersize + sizeof(struct ipv6hdr), 0);
		ipv6_local_error(sk, EMSGSIZE, fl6, pmtu);
		return -EMSGSIZE;
	}

	/* CHECKSUM_PARTIAL only with no extension headers and when
	 * we are not going to fragment
	 */
	if (transhdrlen && sk->sk_protocol == IPPROTO_UDP &&
	    headersize == sizeof(struct ipv6hdr) &&
	    length <= mtu - headersize &&
	    (!(flags & MSG_MORE) || cork->gso_size) &&
	    rt->dst.dev->features & (NETIF_F_IPV6_CSUM | NETIF_F_HW_CSUM))
		csummode = CHECKSUM_PARTIAL;

	if ((flags & MSG_ZEROCOPY) && length) {
		struct msghdr *msg = from;

		if (getfrag == ip_generic_getfrag && msg->msg_ubuf) {
			if (skb_zcopy(skb) && msg->msg_ubuf != skb_zcopy(skb))
				return -EINVAL;

			/* Leave uarg NULL if can't zerocopy, callers should
			 * be able to handle it.
			 */
			if ((rt->dst.dev->features & NETIF_F_SG) &&
			    csummode == CHECKSUM_PARTIAL) {
				paged = true;
				zc = true;
				uarg = msg->msg_ubuf;
			}
		} else if (sock_flag(sk, SOCK_ZEROCOPY)) {
			uarg = msg_zerocopy_realloc(sk, length, skb_zcopy(skb));
			if (!uarg)
				return -ENOBUFS;
			extra_uref = !skb_zcopy(skb);	/* only ref on new uarg */
			if (rt->dst.dev->features & NETIF_F_SG &&
			    csummode == CHECKSUM_PARTIAL) {
				paged = true;
				zc = true;
			} else {
				uarg_to_msgzc(uarg)->zerocopy = 0;
				skb_zcopy_set(skb, uarg, &extra_uref);
			}
		}
	} else if ((flags & MSG_SPLICE_PAGES) && length) {
		if (inet_sk(sk)->hdrincl)
			return -EPERM;
		if (rt->dst.dev->features & NETIF_F_SG &&
		    getfrag == ip_generic_getfrag)
			/* We need an empty buffer to attach stuff to */
			paged = true;
		else
			flags &= ~MSG_SPLICE_PAGES;
	}

	/*
	 * Let's try using as much space as possible.
	 * Use MTU if total length of the message fits into the MTU.
	 * Otherwise, we need to reserve fragment header and
	 * fragment alignment (= 8-15 octects, in total).
	 *
	 * Note that we may need to "move" the data from the tail
	 * of the buffer to the new fragment when we split
	 * the message.
	 *
	 * FIXME: It may be fragmented into multiple chunks
	 *        at once if non-fragmentable extension headers
	 *        are too large.
	 * --yoshfuji
	 */

	cork->length += length;
	if (!skb)
		goto alloc_new_skb;

	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
		copy = (cork->length <= mtu && !(cork->flags & IPCORK_ALLFRAG) ? mtu : maxfraglen) - skb->len;
		if (copy < length)
			copy = maxfraglen - skb->len;

		if (copy <= 0) {
			char *data;
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen, alloc_extra;
			unsigned int pagedlen;
alloc_new_skb:
			/* There's no room in the current skb */
			if (skb)
				fraggap = skb->len - maxfraglen;
			else
				fraggap = 0;
			/* update mtu and maxfraglen if necessary */
			if (!skb || !skb_prev)
				ip6_append_data_mtu(&mtu, &maxfraglen,
						    fragheaderlen, skb, rt,
						    orig_mtu);

			skb_prev = skb;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			datalen = length + fraggap;

			if (datalen > (cork->length <= mtu && !(cork->flags & IPCORK_ALLFRAG) ? mtu : maxfraglen) - fragheaderlen)
				datalen = maxfraglen - fragheaderlen - rt->dst.trailer_len;
			fraglen = datalen + fragheaderlen;
			pagedlen = 0;

			alloc_extra = hh_len;
			alloc_extra += dst_exthdrlen;
			alloc_extra += rt->dst.trailer_len;

			/* We just reserve space for fragment header.
			 * Note: this may be overallocation if the message
			 * (without MSG_MORE) fits into the MTU.
			 */
			alloc_extra += sizeof(struct frag_hdr);

			if ((flags & MSG_MORE) &&
			    !(rt->dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else if (!paged &&
				 (fraglen + alloc_extra < SKB_MAX_ALLOC ||
				  !(rt->dst.dev->features & NETIF_F_SG)))
				alloclen = fraglen;
			else {
				alloclen = fragheaderlen + transhdrlen;
				pagedlen = datalen - transhdrlen;
			}
			alloclen += alloc_extra;

			if (datalen != length + fraggap) {
				/*
				 * this is not the last fragment, the trailer
				 * space is regarded as data space.
				 */
				datalen += rt->dst.trailer_len;
			}

			fraglen = datalen + fragheaderlen;

			copy = datalen - transhdrlen - fraggap - pagedlen;
			/* [!] NOTE: copy may be negative if pagedlen>0
			 * because then the equation may reduces to -fraggap.
			 */
			if (copy < 0 && !(flags & MSG_SPLICE_PAGES)) {
				err = -EINVAL;
				goto error;
			}
			if (transhdrlen) {
				skb = sock_alloc_send_skb(sk, alloclen,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				if (refcount_read(&sk->sk_wmem_alloc) + wmem_alloc_delta <=
				    2 * sk->sk_sndbuf)
					skb = alloc_skb(alloclen,
							sk->sk_allocation);
				if (unlikely(!skb))
					err = -ENOBUFS;
			}
			if (!skb)
				goto error;
			/*
			 *	Fill in the control structures
			 */
			skb->protocol = htons(ETH_P_IPV6);
			skb->ip_summed = csummode;
			skb->csum = 0;
			/* reserve for fragmentation and ipsec header */
			skb_reserve(skb, hh_len + sizeof(struct frag_hdr) +
				    dst_exthdrlen);

			/*
			 *	Find where to start putting bytes
			 */
			data = skb_put(skb, fraglen - pagedlen);
			skb_set_network_header(skb, exthdrlen);
			data += fragheaderlen;
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}
			if (copy > 0 &&
			    getfrag(from, data + transhdrlen, offset,
				    copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			} else if (flags & MSG_SPLICE_PAGES) {
				copy = 0;
			}

			offset += copy;
			length -= copy + transhdrlen;
			transhdrlen = 0;
			exthdrlen = 0;
			dst_exthdrlen = 0;

			/* Only the initial fragment is time stamped */
			skb_shinfo(skb)->tx_flags = cork->tx_flags;
			cork->tx_flags = 0;
			skb_shinfo(skb)->tskey = tskey;
			tskey = 0;
			skb_zcopy_set(skb, uarg, &extra_uref);

			if ((flags & MSG_CONFIRM) && !skb_prev)
				skb_set_dst_pending_confirm(skb, 1);

			/*
			 * Put the packet on the pending queue
			 */
			if (!skb->destructor) {
				skb->destructor = sock_wfree;
				skb->sk = sk;
				wmem_alloc_delta += skb->truesize;
			}
			__skb_queue_tail(queue, skb);
			continue;
		}

		if (copy > length)
			copy = length;

		if (!(rt->dst.dev->features&NETIF_F_SG) &&
		    skb_tailroom(skb) >= copy) {
			unsigned int off;

			off = skb->len;
			if (getfrag(from, skb_put(skb, copy),
						offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else if (flags & MSG_SPLICE_PAGES) {
			struct msghdr *msg = from;

			err = -EIO;
			if (WARN_ON_ONCE(copy > msg->msg_iter.count))
				goto error;

			err = skb_splice_from_iter(skb, &msg->msg_iter, copy,
						   sk->sk_allocation);
			if (err < 0)
				goto error;
			copy = err;
			if (!(flags & MSG_NO_SHARED_FRAGS))
				skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;
			wmem_alloc_delta += copy;
		} else if (!zc) {
			int i = skb_shinfo(skb)->nr_frags;

			err = -ENOMEM;
			if (!sk_page_frag_refill(sk, pfrag))
				goto error;

			skb_zcopy_downgrade_managed(skb);
			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				err = -EMSGSIZE;
				if (i == MAX_SKB_FRAGS)
					goto error;

				__skb_fill_page_desc(skb, i, pfrag->page,
						     pfrag->offset, 0);
				skb_shinfo(skb)->nr_frags = ++i;
				get_page(pfrag->page);
			}
			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			if (getfrag(from,
				    page_address(pfrag->page) + pfrag->offset,
				    offset, copy, skb->len, skb) < 0)
				goto error_efault;

			pfrag->offset += copy;
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			wmem_alloc_delta += copy;
		} else {
			err = skb_zerocopy_iter_dgram(skb, from, copy);
			if (err < 0)
				goto error;
		}
		offset += copy;
		length -= copy;
	}

	if (wmem_alloc_delta)
		refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return 0;

error_efault:
	err = -EFAULT;
error:
	net_zcopy_put_abort(uarg, extra_uref);
	cork->length -= length;
	IP6_INC_STATS(sock_net(sk), rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
	refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return err;
}

int klpp_ip6_append_data(struct sock *sk,
		    int getfrag(void *from, char *to, int offset, int len,
				int odd, struct sk_buff *skb),
		    void *from, size_t length, int transhdrlen,
		    struct ipcm6_cookie *ipc6, struct flowi6 *fl6,
		    struct rt6_info *rt, unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	int exthdrlen;
	int err;

	if (flags&MSG_PROBE)
		return 0;
	if (skb_queue_empty(&sk->sk_write_queue)) {
		/*
		 * setup for corking
		 */
		dst_hold(&rt->dst);
		err = ip6_setup_cork(sk, &inet->cork, &np->cork,
				     ipc6, rt);
		if (err)
			return err;

		inet->cork.fl.u.ip6 = *fl6;
		exthdrlen = (ipc6->opt ? ipc6->opt->opt_flen : 0);
		length += exthdrlen;
		transhdrlen += exthdrlen;
	} else {
		transhdrlen = 0;
	}

	return klpp___ip6_append_data(sk, &sk->sk_write_queue, &inet->cork,
				 &np->cork, sk_page_frag(sk), getfrag,
				 from, length, transhdrlen, flags, ipc6);
}

typeof(klpp_ip6_append_data) klpp_ip6_append_data;

static void ip6_cork_release(struct inet_cork_full *cork,
			     struct inet6_cork *v6_cork)
{
	if (v6_cork->opt) {
		struct ipv6_txoptions *opt = v6_cork->opt;

		kfree(opt->dst0opt);
		kfree(opt->dst1opt);
		kfree(opt->hopopt);
		kfree(opt->srcrt);
		kfree(opt);
		v6_cork->opt = NULL;
	}

	if (cork->base.dst) {
		dst_release(cork->base.dst);
		cork->base.dst = NULL;
		cork->base.flags &= ~IPCORK_ALLFRAG;
	}
}

struct sk_buff *__ip6_make_skb(struct sock *sk,
			       struct sk_buff_head *queue,
			       struct inet_cork_full *cork,
			       struct inet6_cork *v6_cork);

extern void __ip6_flush_pending_frames(struct sock *sk,
				       struct sk_buff_head *queue,
				       struct inet_cork_full *cork,
				       struct inet6_cork *v6_cork);

struct sk_buff *klpp_ip6_make_skb(struct sock *sk,
			     int getfrag(void *from, char *to, int offset,
					 int len, int odd, struct sk_buff *skb),
			     void *from, size_t length, int transhdrlen,
			     struct ipcm6_cookie *ipc6, struct rt6_info *rt,
			     unsigned int flags, struct inet_cork_full *cork)
{
	struct inet6_cork v6_cork;
	struct sk_buff_head queue;
	int exthdrlen = (ipc6->opt ? ipc6->opt->opt_flen : 0);
	int err;

	if (flags & MSG_PROBE) {
		dst_release(&rt->dst);
		return NULL;
	}

	__skb_queue_head_init(&queue);

	cork->base.flags = 0;
	cork->base.addr = 0;
	cork->base.opt = NULL;
	v6_cork.opt = NULL;
	err = ip6_setup_cork(sk, cork, &v6_cork, ipc6, rt);
	if (err) {
		ip6_cork_release(cork, &v6_cork);
		return ERR_PTR(err);
	}
	if (ipc6->dontfrag < 0)
		ipc6->dontfrag = inet6_sk(sk)->dontfrag;

	err = klpp___ip6_append_data(sk, &queue, cork, &v6_cork,
				&current->task_frag, getfrag, from,
				length + exthdrlen, transhdrlen + exthdrlen,
				flags, ipc6);
	if (err) {
		__ip6_flush_pending_frames(sk, &queue, cork, &v6_cork);
		return ERR_PTR(err);
	}

	return __ip6_make_skb(sk, &queue, cork, &v6_cork);
}


#include <linux/livepatch.h>

extern typeof(__ip6_flush_pending_frames) __ip6_flush_pending_frames
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __ip6_flush_pending_frames);
extern typeof(__ip6_make_skb) __ip6_make_skb
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __ip6_make_skb);
extern typeof(ip6_setup_cork) ip6_setup_cork
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip6_setup_cork);
extern typeof(ipv6_local_error) ipv6_local_error
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipv6_local_error);
extern typeof(ipv6_local_rxpmtu) ipv6_local_rxpmtu
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipv6_local_rxpmtu);
