#ifndef _LIVEPATCH_BSC1269775_H
#define _LIVEPATCH_BSC1269775_H

#include <linux/types.h>

int livepatch_bsc1269775_init(void);
void livepatch_bsc1269775_cleanup(void);

int bsc1269775_net_ipv4_netfilter_nf_log_ipv4_init(void);
void bsc1269775_net_ipv4_netfilter_nf_log_ipv4_cleanup(void);

int bsc1269775_net_netfilter_ipset_ip_set_hash_ipmac_init(void);
void bsc1269775_net_netfilter_ipset_ip_set_hash_ipmac_cleanup(void);

int bsc1269775_net_netfilter_ipset_ip_set_hash_mac_init(void);
void bsc1269775_net_netfilter_ipset_ip_set_hash_mac_cleanup(void);


struct ip_set;
struct ip_set_adt_opt;
struct net;
struct net_device;
struct nf_loginfo;
struct sk_buff;
struct xt_action_param;

enum ipset_adt;

bool klpp_eui64_mt6(const struct sk_buff *skb, struct xt_action_param *par);
bool klpp_mac_mt(const struct sk_buff *skb, struct xt_action_param *par);
int klpp_bitmap_ipmac_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
int klpp_hash_ipmac4_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
int klpp_hash_ipmac6_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
int klpp_hash_mac4_kadt(struct ip_set *set, const struct sk_buff *skb, const struct xt_action_param *par, enum ipset_adt adt, struct ip_set_adt_opt *opt);
void klpp_nf_log_ip_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix);
#endif /* _LIVEPATCH_BSC1269775_H */
