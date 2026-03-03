/*
 * livepatch_bsc1256644
 *
 * Fix for CVE-2025-68813, bsc#1256644
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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



#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/netfilter/ipvs/ip_vs_xmit.c */
#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/tcp.h>                  /* for tcphdr */
#include <net/ip.h>
#include <net/tcp.h>                    /* for csum_tcpudp_magic */
#include <net/udp.h>
#include <net/icmp.h>                   /* for icmp_send */
#include <net/route.h>                  /* for ip_route_output */
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>
#include <linux/icmpv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip_vs.h>

/* klp-ccp: from include/net/ip_vs.h */
static void (*klpe_ip_vs_conn_fill_cport)(struct ip_vs_conn *cp, __be16 cport);

int klpp_ip_vs_bypass_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		      struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);
int klpp_ip_vs_nat_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		   struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);
int klpp_ip_vs_tunnel_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		      struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);
int klpp_ip_vs_dr_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		  struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);
int klpp_ip_vs_icmp_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		    struct ip_vs_protocol *pp, int offset,
		    unsigned int hooknum, struct ip_vs_iphdr *iph);
static void (*klpe_ip_vs_dest_dst_rcu_free)(struct rcu_head *head);

static void (*klpe_ip_vs_nat_icmp)(struct sk_buff *skb, struct ip_vs_protocol *pp,
		    struct ip_vs_conn *cp, int dir);

#ifdef CONFIG_IP_VS_NFCT

static void (*klpe_ip_vs_update_conntrack)(struct sk_buff *skb, struct ip_vs_conn *cp,
			    int outin);
static int (*klpe_ip_vs_confirm_conntrack)(struct sk_buff *skb);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_IP_VS_NFCT */

/* klp-ccp: from net/netfilter/ipvs/ip_vs_xmit.c */
enum {
	IP_VS_RT_MODE_LOCAL	= 1, /* Allow local dest */
	IP_VS_RT_MODE_NON_LOCAL	= 2, /* Allow non-local dest */
	IP_VS_RT_MODE_RDR	= 4, /* Allow redirect from remote daddr to
				      * local
				      */
	IP_VS_RT_MODE_CONNECT	= 8, /* Always bind route to saddr */
	IP_VS_RT_MODE_KNOWN_NH	= 16,/* Route via remote addr */
	IP_VS_RT_MODE_TUNNEL	= 32,/* Tunnel mode */
};

static inline struct ip_vs_dest_dst *ip_vs_dest_dst_alloc(void)
{
	return kmalloc(sizeof(struct ip_vs_dest_dst), GFP_ATOMIC);
}

static inline void ip_vs_dest_dst_free(struct ip_vs_dest_dst *dest_dst)
{
	kfree(dest_dst);
}

static inline void
klpr___ip_vs_dst_set(struct ip_vs_dest *dest, struct ip_vs_dest_dst *dest_dst,
		struct dst_entry *dst, u32 dst_cookie)
{
	struct ip_vs_dest_dst *old;

	old = rcu_dereference_protected(dest->dest_dst,
					lockdep_is_held(&dest->dst_lock));

	if (dest_dst) {
		dest_dst->dst_cache = dst;
		dest_dst->dst_cookie = dst_cookie;
	}
	rcu_assign_pointer(dest->dest_dst, dest_dst);

	if (old)
		call_rcu(&old->rcu_head, (*klpe_ip_vs_dest_dst_rcu_free));
}

static inline struct ip_vs_dest_dst *
__ip_vs_dst_check(struct ip_vs_dest *dest)
{
	struct ip_vs_dest_dst *dest_dst = rcu_dereference(dest->dest_dst);
	struct dst_entry *dst;

	if (!dest_dst)
		return NULL;
	dst = dest_dst->dst_cache;
	if (READ_ONCE(dst->obsolete) &&
	    dst->ops->check(dst, dest_dst->dst_cookie) == NULL)
		return NULL;
	return dest_dst;
}

static inline bool
__mtu_check_toobig_v6(const struct sk_buff *skb, u32 mtu)
{
	if (IP6CB(skb)->frag_max_size) {
		/* frag_max_size tell us that, this packet have been
		 * defragmented by netfilter IPv6 conntrack module.
		 */
		if (IP6CB(skb)->frag_max_size > mtu)
			return true; /* largest fragment violate MTU */
	}
	else if (skb->len > mtu && !skb_is_gso(skb)) {
		return true; /* Packet size violate MTU size */
	}
	return false;
}

static struct rtable *(*klpe_do_output_route4)(struct net *net, __be32 daddr,
				       int rt_mode, __be32 *ret_saddr);

#ifdef CONFIG_IP_VS_IPV6
static inline int __ip_vs_is_local_route6(struct rt6_info *rt)
{
	return rt->dst.dev && rt->dst.dev->flags & IFF_LOOPBACK;
}
#endif

static inline bool crosses_local_route_boundary(int skb_af, struct sk_buff *skb,
						int rt_mode,
						bool new_rt_is_local)
{
	bool rt_mode_allow_local = !!(rt_mode & IP_VS_RT_MODE_LOCAL);
	bool rt_mode_allow_non_local = !!(rt_mode & IP_VS_RT_MODE_NON_LOCAL);
	bool rt_mode_allow_redirect = !!(rt_mode & IP_VS_RT_MODE_RDR);
	bool source_is_loopback;
	bool old_rt_is_local;

#ifdef CONFIG_IP_VS_IPV6
	if (skb_af == AF_INET6) {
		int addr_type = ipv6_addr_type(&ipv6_hdr(skb)->saddr);

		source_is_loopback =
			(!skb->dev || skb->dev->flags & IFF_LOOPBACK) &&
			(addr_type & IPV6_ADDR_LOOPBACK);
		old_rt_is_local = __ip_vs_is_local_route6(
			(struct rt6_info *)skb_dst(skb));
	} else
#endif
	{
		source_is_loopback = ipv4_is_loopback(ip_hdr(skb)->saddr);
		old_rt_is_local = skb_rtable(skb)->rt_flags & RTCF_LOCAL;
	}

	if (unlikely(new_rt_is_local)) {
		if (!rt_mode_allow_local)
			return true;
		if (!rt_mode_allow_redirect && !old_rt_is_local)
			return true;
	} else {
		if (!rt_mode_allow_non_local)
			return true;
		if (source_is_loopback)
			return true;
	}
	return false;
}

static inline void maybe_update_pmtu(int skb_af, struct sk_buff *skb, int mtu)
{
	struct sock *sk = skb->sk;
	struct rtable *ort = skb_rtable(skb);

	if (!skb->dev && sk && sk_fullsock(sk))
		ort->dst.ops->update_pmtu(&ort->dst, sk, NULL, mtu);
}

static inline bool ensure_mtu_is_adequate(struct netns_ipvs *ipvs, int skb_af,
					  int rt_mode,
					  struct ip_vs_iphdr *ipvsh,
					  struct sk_buff *skb, int mtu)
{
#ifdef CONFIG_IP_VS_IPV6
	if (skb_af == AF_INET6) {
		struct net *net = ipvs->net;

		if (unlikely(__mtu_check_toobig_v6(skb, mtu))) {
			if (!skb->dev)
				skb->dev = net->loopback_dev;
			/* only send ICMP too big on first fragment */
			if (!ipvsh->fragoffs && !ip_vs_iph_icmp(ipvsh))
				icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
			IP_VS_DBG(1, "frag needed for %pI6c\n",
				  &ipv6_hdr(skb)->saddr);
			return false;
		}
	} else
#endif
	{
		/* If we're going to tunnel the packet and pmtu discovery
		 * is disabled, we'll just fragment it anyway
		 */
		if ((rt_mode & IP_VS_RT_MODE_TUNNEL) && !sysctl_pmtu_disc(ipvs))
			return true;

		if (unlikely(ip_hdr(skb)->frag_off & htons(IP_DF) &&
			     skb->len > mtu && !skb_is_gso(skb) &&
			     !ip_vs_iph_icmp(ipvsh))) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				  htonl(mtu));
			IP_VS_DBG(1, "frag needed for %pI4\n",
				  &ip_hdr(skb)->saddr);
			return false;
		}
	}

	return true;
}

static inline bool decrement_ttl(struct netns_ipvs *ipvs,
				 int skb_af,
				 struct sk_buff *skb)
{
	struct net *net = ipvs->net;

#ifdef CONFIG_IP_VS_IPV6
	if (skb_af == AF_INET6) {
		struct dst_entry *dst = skb_dst(skb);

		/* check and decrement ttl */
		if (ipv6_hdr(skb)->hop_limit <= 1) {
			struct inet6_dev *idev = __in6_dev_get_safely(skb->dev);

			/* Force OUTPUT device used as source address */
			skb->dev = dst->dev;
			icmpv6_send(skb, ICMPV6_TIME_EXCEED,
				    ICMPV6_EXC_HOPLIMIT, 0);
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);

			return false;
		}

		/* don't propagate ttl change to cloned packets */
		if (!skb_make_writable(skb, sizeof(struct ipv6hdr)))
			return false;

		ipv6_hdr(skb)->hop_limit--;
	} else
#endif
	{
		if (ip_hdr(skb)->ttl <= 1) {
			/* Tell the sender its packet died... */
			__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
			icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
			return false;
		}

		/* don't propagate ttl change to cloned packets */
		if (!skb_make_writable(skb, sizeof(struct iphdr)))
			return false;

		/* Decrease ttl */
		ip_decrease_ttl(ip_hdr(skb));
	}

	return true;
}

int
klpp___ip_vs_get_out_rt(struct netns_ipvs *ipvs, int skb_af, struct sk_buff *skb,
		   struct ip_vs_dest *dest,
		   __be32 daddr, int rt_mode, __be32 *ret_saddr,
		   struct ip_vs_iphdr *ipvsh)
{
	struct net *net = ipvs->net;
	struct ip_vs_dest_dst *dest_dst;
	struct rtable *rt;			/* Route to the other host */
	int mtu;
	int local, noref = 1;

	if (dest) {
		dest_dst = __ip_vs_dst_check(dest);
		if (likely(dest_dst))
			rt = (struct rtable *) dest_dst->dst_cache;
		else {
			dest_dst = ip_vs_dest_dst_alloc();
			spin_lock_bh(&dest->dst_lock);
			if (!dest_dst) {
				klpr___ip_vs_dst_set(dest, NULL, NULL, 0);
				spin_unlock_bh(&dest->dst_lock);
				goto err_unreach;
			}
			rt = (*klpe_do_output_route4)(net, dest->addr.ip, rt_mode,
					      &dest_dst->dst_saddr.ip);
			if (!rt) {
				klpr___ip_vs_dst_set(dest, NULL, NULL, 0);
				spin_unlock_bh(&dest->dst_lock);
				ip_vs_dest_dst_free(dest_dst);
				goto err_unreach;
			}
			klpr___ip_vs_dst_set(dest, dest_dst, &rt->dst, 0);
			spin_unlock_bh(&dest->dst_lock);
			IP_VS_DBG(10, "new dst %pI4, src %pI4, refcnt=%d\n",
				  &dest->addr.ip, &dest_dst->dst_saddr.ip,
				  atomic_read(&rt->dst.__refcnt));
		}
		if (ret_saddr)
			*ret_saddr = dest_dst->dst_saddr.ip;
	} else {
		noref = 0;

		/* For such unconfigured boxes avoid many route lookups
		 * for performance reasons because we do not remember saddr
		 */
		rt_mode &= ~IP_VS_RT_MODE_CONNECT;
		rt = (*klpe_do_output_route4)(net, daddr, rt_mode, ret_saddr);
		if (!rt)
			goto err_unreach;
	}

	local = (rt->rt_flags & RTCF_LOCAL) ? 1 : 0;
	if (unlikely(crosses_local_route_boundary(skb_af, skb, rt_mode,
						  local))) {
		IP_VS_DBG_RL("We are crossing local and non-local addresses"
			     " daddr=%pI4\n", &daddr);
		goto err_put;
	}

	if (unlikely(local)) {
		/* skb to local stack, preserve old route */
		if (!noref)
			ip_rt_put(rt);
		return local;
	}

	if (!decrement_ttl(ipvs, skb_af, skb))
		goto err_put;

	if (likely(!(rt_mode & IP_VS_RT_MODE_TUNNEL))) {
		mtu = dst_mtu(&rt->dst);
	} else {
		mtu = dst_mtu(&rt->dst) - sizeof(struct iphdr);
		if (mtu < 68) {
			IP_VS_DBG_RL("%s(): mtu less than 68\n", __func__);
			goto err_put;
		}
		maybe_update_pmtu(skb_af, skb, mtu);
	}

	if (!ensure_mtu_is_adequate(ipvs, skb_af, rt_mode, ipvsh, skb, mtu))
		goto err_put;

	skb_dst_drop(skb);
	if (noref) {
		if (!local)
			skb_dst_set_noref(skb, &rt->dst);
		else
			skb_dst_set(skb, dst_clone(&rt->dst));
	} else
		skb_dst_set(skb, &rt->dst);

	return local;

err_put:
	if (!noref)
		ip_rt_put(rt);
	return -1;

err_unreach:
	if (!skb->dev)
		skb->dev = skb_dst(skb)->dev;

	dst_link_failure(skb);
	return -1;
}

static inline int klpr_ip_vs_tunnel_xmit_prepare(struct sk_buff *skb,
					    struct ip_vs_conn *cp)
{
	int ret = NF_ACCEPT;

	skb->ipvs_property = 1;
	if (unlikely(cp->flags & IP_VS_CONN_F_NFCT))
		ret = (*klpe_ip_vs_confirm_conntrack)(skb);
	if (ret == NF_ACCEPT) {
		nf_reset(skb);
		skb_forward_csum(skb);
	}
	return ret;
}

static inline void ip_vs_drop_early_demux_sk(struct sk_buff *skb)
{
	/* If dev is set, the packet came from the LOCAL_IN callback and
	 * not from a local TCP socket.
	 */
	if (skb->dev)
		skb_orphan(skb);
}

static inline int klpr_ip_vs_nat_send_or_cont(int pf, struct sk_buff *skb,
					 struct ip_vs_conn *cp, int local)
{
	int ret = NF_STOLEN;

	skb->ipvs_property = 1;
	if (likely(!(cp->flags & IP_VS_CONN_F_NFCT)))
		ip_vs_notrack(skb);
	else
		(*klpe_ip_vs_update_conntrack)(skb, cp, 1);

	/* Remove the early_demux association unless it's bound for the
	 * exact same port and address on this host after translation.
	 */
	if (!local || cp->vport != cp->dport ||
	    !ip_vs_addr_equal(cp->af, &cp->vaddr, &cp->daddr))
		ip_vs_drop_early_demux_sk(skb);

	if (!local) {
		skb_forward_csum(skb);
		NF_HOOK(pf, NF_INET_LOCAL_OUT, cp->ipvs->net, NULL, skb,
			NULL, skb_dst(skb)->dev, dst_output);
	} else
		ret = NF_ACCEPT;

	return ret;
}

static inline int ip_vs_send_or_cont(int pf, struct sk_buff *skb,
				     struct ip_vs_conn *cp, int local)
{
	int ret = NF_STOLEN;

	skb->ipvs_property = 1;
	if (likely(!(cp->flags & IP_VS_CONN_F_NFCT)))
		ip_vs_notrack(skb);
	if (!local) {
		ip_vs_drop_early_demux_sk(skb);
		skb_forward_csum(skb);
		NF_HOOK(pf, NF_INET_LOCAL_OUT, cp->ipvs->net, NULL, skb,
			NULL, skb_dst(skb)->dev, dst_output);
	} else
		ret = NF_ACCEPT;
	return ret;
}

int
klpp_ip_vs_bypass_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		  struct ip_vs_protocol *pp, struct ip_vs_iphdr *ipvsh)
{
	struct iphdr  *iph = ip_hdr(skb);

	EnterFunction(10);

	rcu_read_lock();
	if (klpp___ip_vs_get_out_rt(cp->ipvs, cp->af, skb, NULL, iph->daddr,
			       IP_VS_RT_MODE_NON_LOCAL, NULL, ipvsh) < 0)
		goto tx_error;

	ip_send_check(iph);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->ignore_df = 1;

	ip_vs_send_or_cont(NFPROTO_IPV4, skb, cp, 0);
	rcu_read_unlock();

	LeaveFunction(10);
	return NF_STOLEN;

 tx_error:
	kfree_skb(skb);
	rcu_read_unlock();
	LeaveFunction(10);
	return NF_STOLEN;
}

int
klpp_ip_vs_nat_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
	       struct ip_vs_protocol *pp, struct ip_vs_iphdr *ipvsh)
{
	struct rtable *rt;		/* Route to the other host */
	int local, rc, was_input;

	EnterFunction(10);

	rcu_read_lock();
	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 _pt, *p;

		p = skb_header_pointer(skb, ipvsh->len, sizeof(_pt), &_pt);
		if (p == NULL)
			goto tx_error;
		(*klpe_ip_vs_conn_fill_cport)(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	was_input = rt_is_input_route(skb_rtable(skb));
	local = klpp___ip_vs_get_out_rt(cp->ipvs, cp->af, skb, cp->dest, cp->daddr.ip,
				   IP_VS_RT_MODE_LOCAL |
				   IP_VS_RT_MODE_NON_LOCAL |
				   IP_VS_RT_MODE_RDR, NULL, ipvsh);
	if (local < 0)
		goto tx_error;
	rt = skb_rtable(skb);

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	if (cp->flags & IP_VS_CONN_F_SYNC && local) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

		if (ct) {
			IP_VS_DBG_RL_PKT(10, AF_INET, pp, skb, ipvsh->off,
					 "ip_vs_nat_xmit(): "
					 "stopping DNAT to local address");
			goto tx_error;
		}
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (local && ipv4_is_loopback(cp->daddr.ip) && was_input) {
		IP_VS_DBG_RL_PKT(1, AF_INET, pp, skb, ipvsh->off,
				 "ip_vs_nat_xmit(): stopping DNAT to loopback "
				 "address");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, sizeof(struct iphdr)))
		goto tx_error;

	if (skb_cow(skb, rt->dst.dev->hard_header_len))
		goto tx_error;

	/* mangle the packet */
	if (pp->dnat_handler && !pp->dnat_handler(skb, pp, cp, ipvsh))
		goto tx_error;
	ip_hdr(skb)->daddr = cp->daddr.ip;
	ip_send_check(ip_hdr(skb));

	IP_VS_DBG_PKT(10, AF_INET, pp, skb, ipvsh->off, "After DNAT");

	/* FIXME: when application helper enlarges the packet and the length
	   is larger than the MTU of outgoing device, there will be still
	   MTU problem. */

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->ignore_df = 1;

	rc = klpr_ip_vs_nat_send_or_cont(NFPROTO_IPV4, skb, cp, local);
	rcu_read_unlock();

	LeaveFunction(10);
	return rc;

  tx_error:
	kfree_skb(skb);
	rcu_read_unlock();
	LeaveFunction(10);
	return NF_STOLEN;
}

static struct sk_buff *
ip_vs_prepare_tunneled_skb(struct sk_buff *skb, int skb_af,
			   unsigned int max_headroom, __u8 *next_protocol,
			   __u32 *payload_len, __u8 *dsfield, __u8 *ttl,
			   __be16 *df)
{
	struct sk_buff *new_skb = NULL;
	struct iphdr *old_iph = NULL;
#ifdef CONFIG_IP_VS_IPV6
	struct ipv6hdr *old_ipv6h = NULL;
#endif
	ip_vs_drop_early_demux_sk(skb);

	if (skb_headroom(skb) < max_headroom || skb_cloned(skb)) {
		new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb)
			goto error;
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		consume_skb(skb);
		skb = new_skb;
	}

#ifdef CONFIG_IP_VS_IPV6
	if (skb_af == AF_INET6) {
		old_ipv6h = ipv6_hdr(skb);
		*next_protocol = IPPROTO_IPV6;
		if (payload_len)
			*payload_len =
				ntohs(old_ipv6h->payload_len) +
				sizeof(*old_ipv6h);
		*dsfield = ipv6_get_dsfield(old_ipv6h);
		*ttl = old_ipv6h->hop_limit;
		if (df)
			*df = 0;
	} else
#endif
	{
		old_iph = ip_hdr(skb);
		/* Copy DF, reset fragment offset and MF */
		if (df)
			*df = (old_iph->frag_off & htons(IP_DF));
		*next_protocol = IPPROTO_IPIP;

		/* fix old IP header checksum */
		ip_send_check(old_iph);
		*dsfield = ipv4_get_dsfield(old_iph);
		*ttl = old_iph->ttl;
		if (payload_len)
			*payload_len = ntohs(old_iph->tot_len);
	}

	return skb;
error:
	kfree_skb(skb);
	return ERR_PTR(-ENOMEM);
}

static inline int __tun_gso_type_mask(int encaps_af, int orig_af)
{
	switch (encaps_af) {
	case AF_INET:
		return SKB_GSO_IPXIP4;
	case AF_INET6:
		return SKB_GSO_IPXIP6;
	default:
		return 0;
	}
}

int
klpp_ip_vs_tunnel_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		  struct ip_vs_protocol *pp, struct ip_vs_iphdr *ipvsh)
{
	struct netns_ipvs *ipvs = cp->ipvs;
	struct net *net = ipvs->net;
	struct rtable *rt;			/* Route to the other host */
	__be32 saddr;				/* Source for tunnel */
	struct net_device *tdev;		/* Device to other host */
	__u8 next_protocol = 0;
	__u8 dsfield = 0;
	__u8 ttl = 0;
	__be16 df = 0;
	__be16 *dfp = NULL;
	struct iphdr  *iph;			/* Our new IP header */
	unsigned int max_headroom;		/* The extra header space needed */
	int ret, local;

	EnterFunction(10);

	rcu_read_lock();
	local = klpp___ip_vs_get_out_rt(ipvs, cp->af, skb, cp->dest, cp->daddr.ip,
				   IP_VS_RT_MODE_LOCAL |
				   IP_VS_RT_MODE_NON_LOCAL |
				   IP_VS_RT_MODE_CONNECT |
				   IP_VS_RT_MODE_TUNNEL, &saddr, ipvsh);
	if (local < 0)
		goto tx_error;
	if (local) {
		rcu_read_unlock();
		return ip_vs_send_or_cont(NFPROTO_IPV4, skb, cp, 1);
	}

	rt = skb_rtable(skb);
	tdev = rt->dst.dev;

	/*
	 * Okay, now see if we can stuff it in the buffer as-is.
	 */
	max_headroom = LL_RESERVED_SPACE(tdev) + sizeof(struct iphdr);

	/* We only care about the df field if sysctl_pmtu_disc(ipvs) is set */
	dfp = sysctl_pmtu_disc(ipvs) ? &df : NULL;
	skb = ip_vs_prepare_tunneled_skb(skb, cp->af, max_headroom,
					 &next_protocol, NULL, &dsfield,
					 &ttl, dfp);
	if (IS_ERR(skb))
		goto tx_error;

	if (iptunnel_handle_offloads(skb, __tun_gso_type_mask(AF_INET, cp->af)))
		goto tx_error;

	skb->transport_header = skb->network_header;

	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	/*
	 *	Push down and install the IPIP header.
	 */
	iph			=	ip_hdr(skb);
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr)>>2;
	iph->frag_off		=	df;
	iph->protocol		=	next_protocol;
	iph->tos		=	dsfield;
	iph->daddr		=	cp->daddr.ip;
	iph->saddr		=	saddr;
	iph->ttl		=	ttl;
	ip_select_ident(net, skb, NULL);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->ignore_df = 1;

	ret = klpr_ip_vs_tunnel_xmit_prepare(skb, cp);
	if (ret == NF_ACCEPT)
		ip_local_out(net, skb->sk, skb);
	else if (ret == NF_DROP)
		kfree_skb(skb);
	rcu_read_unlock();

	LeaveFunction(10);

	return NF_STOLEN;

  tx_error:
	if (!IS_ERR(skb))
		kfree_skb(skb);
	rcu_read_unlock();
	LeaveFunction(10);
	return NF_STOLEN;
}

int
klpp_ip_vs_dr_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
	      struct ip_vs_protocol *pp, struct ip_vs_iphdr *ipvsh)
{
	int local;

	EnterFunction(10);

	rcu_read_lock();
	local = klpp___ip_vs_get_out_rt(cp->ipvs, cp->af, skb, cp->dest, cp->daddr.ip,
				   IP_VS_RT_MODE_LOCAL |
				   IP_VS_RT_MODE_NON_LOCAL |
				   IP_VS_RT_MODE_KNOWN_NH, NULL, ipvsh);
	if (local < 0)
		goto tx_error;
	if (local) {
		rcu_read_unlock();
		return ip_vs_send_or_cont(NFPROTO_IPV4, skb, cp, 1);
	}

	ip_send_check(ip_hdr(skb));

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->ignore_df = 1;

	ip_vs_send_or_cont(NFPROTO_IPV4, skb, cp, 0);
	rcu_read_unlock();

	LeaveFunction(10);
	return NF_STOLEN;

  tx_error:
	kfree_skb(skb);
	rcu_read_unlock();
	LeaveFunction(10);
	return NF_STOLEN;
}

int
klpp_ip_vs_icmp_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		struct ip_vs_protocol *pp, int offset, unsigned int hooknum,
		struct ip_vs_iphdr *iph)
{
	struct rtable	*rt;	/* Route to the other host */
	int rc;
	int local;
	int rt_mode, was_input;

	EnterFunction(10);

	/* The ICMP packet for VS/TUN, VS/DR and LOCALNODE will be
	   forwarded directly here, because there is no need to
	   translate address/port back */
	if (IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_MASQ) {
		if (cp->packet_xmit)
			rc = cp->packet_xmit(skb, cp, pp, iph);
		else
			rc = NF_ACCEPT;
		/* do not touch skb anymore */
		atomic_inc(&cp->in_pkts);
		goto out;
	}

	/*
	 * mangle and send the packet here (only for VS/NAT)
	 */
	was_input = rt_is_input_route(skb_rtable(skb));

	/* LOCALNODE from FORWARD hook is not supported */
	rt_mode = (hooknum != NF_INET_FORWARD) ?
		  IP_VS_RT_MODE_LOCAL | IP_VS_RT_MODE_NON_LOCAL |
		  IP_VS_RT_MODE_RDR : IP_VS_RT_MODE_NON_LOCAL;
	rcu_read_lock();
	local = klpp___ip_vs_get_out_rt(cp->ipvs, cp->af, skb, cp->dest, cp->daddr.ip, rt_mode,
				   NULL, iph);
	if (local < 0)
		goto tx_error;
	rt = skb_rtable(skb);

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	if (cp->flags & IP_VS_CONN_F_SYNC && local) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

		if (ct) {
			IP_VS_DBG(10, "%s(): "
				  "stopping DNAT to local address %pI4\n",
				  __func__, &cp->daddr.ip);
			goto tx_error;
		}
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (local && ipv4_is_loopback(cp->daddr.ip) && was_input) {
		IP_VS_DBG(1, "%s(): "
			  "stopping DNAT to loopback %pI4\n",
			  __func__, &cp->daddr.ip);
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, offset))
		goto tx_error;

	if (skb_cow(skb, rt->dst.dev->hard_header_len))
		goto tx_error;

	(*klpe_ip_vs_nat_icmp)(skb, pp, cp, 0);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->ignore_df = 1;

	rc = klpr_ip_vs_nat_send_or_cont(NFPROTO_IPV4, skb, cp, local);
	rcu_read_unlock();
	goto out;

  tx_error:
	kfree_skb(skb);
	rcu_read_unlock();
	rc = NF_STOLEN;
  out:
	LeaveFunction(10);
	return rc;
}


#include "livepatch_bsc1256644.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ip_vs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "do_output_route4", (void *)&klpe_do_output_route4, "ip_vs" },
	{ "ip_vs_confirm_conntrack", (void *)&klpe_ip_vs_confirm_conntrack,
	  "ip_vs" },
	{ "ip_vs_conn_fill_cport", (void *)&klpe_ip_vs_conn_fill_cport,
	  "ip_vs" },
	{ "ip_vs_dest_dst_rcu_free", (void *)&klpe_ip_vs_dest_dst_rcu_free,
	  "ip_vs" },
	{ "ip_vs_nat_icmp", (void *)&klpe_ip_vs_nat_icmp, "ip_vs" },
	{ "ip_vs_update_conntrack", (void *)&klpe_ip_vs_update_conntrack,
	  "ip_vs" },
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

int livepatch_bsc1256644_init(void)
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

void livepatch_bsc1256644_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
