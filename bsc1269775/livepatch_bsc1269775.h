#ifndef _LIVEPATCH_BSC1269775_H
#define _LIVEPATCH_BSC1269775_H

#include <linux/types.h>

static inline int livepatch_bsc1269775_init(void) { return 0; }
static inline void livepatch_bsc1269775_cleanup(void) {}

struct ip_set;
struct ip_set_adt_opt;
struct net;
struct net_device;
struct nf_log_buf;
struct nf_loginfo;
struct sk_buff;
struct xt_action_param;

enum ipset_adt;

bool klpp_mac_mt(const struct sk_buff *skb, struct xt_action_param *par);
int klpp_bitmap_ipmac_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
int klpp_hash_ipmac4_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
int klpp_hash_ipmac6_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
int klpp_hash_mac4_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
void klpp_nf_log_ip6_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix);
void klpp_nf_log_ip_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix);
void klpp_nf_log_netdev_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix);
void noinline_for_stack klpp_dump_arp_packet(struct nf_log_buf *m, const struct nf_loginfo *info, const struct sk_buff *skb, unsigned int nhoff);

#endif /* _LIVEPATCH_BSC1269775_H */
