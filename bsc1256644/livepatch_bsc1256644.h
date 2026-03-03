#ifndef _LIVEPATCH_BSC1256644_H
#define _LIVEPATCH_BSC1256644_H

#include <linux/types.h>

static inline int livepatch_bsc1256644_init(void) { return 0; }
static inline void livepatch_bsc1256644_cleanup(void) {}

struct ip_vs_conn;
struct ip_vs_dest;
struct ip_vs_iphdr;
struct ip_vs_protocol;
struct netns_ipvs;
struct sk_buff;

int klpp___ip_vs_get_out_rt(struct netns_ipvs *ipvs, int skb_af, struct sk_buff *skb, struct ip_vs_dest *dest, __be32 daddr, int rt_mode, __be32 *ret_saddr, struct ip_vs_iphdr *ipvsh);
int klpp_ip_vs_bypass_xmit(struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);
int klpp_ip_vs_dr_xmit(struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);
int klpp_ip_vs_icmp_xmit(struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp, int offset, unsigned int hooknum, struct ip_vs_iphdr *iph);
int klpp_ip_vs_nat_xmit(struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);
int klpp_ip_vs_tunnel_xmit(struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp, struct ip_vs_iphdr *iph);

#endif /* _LIVEPATCH_BSC1256644_H */
