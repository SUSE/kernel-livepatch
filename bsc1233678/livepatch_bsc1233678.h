#ifndef _LIVEPATCH_BSC1233678_H
#define _LIVEPATCH_BSC1233678_H

#include <linux/types.h>

int livepatch_bsc1233678_init(void);
void livepatch_bsc1233678_cleanup(void);

struct sk_buff;
struct iphdr;

struct net_device *
klpp_mlxsw_sp_span_gretap4_route(const struct net_device *to_dev,
                                 __be32 *saddrp, __be32 *daddrp);

int klpp_gre_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

void klpp_ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
                         const struct iphdr *tnl_params, const u8 protocol);
void klpp_ip_md_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
                            const u8 proto, int tunnel_hlen);
int klpp_ip_tunnel_bind_dev(struct net_device *dev);

#endif /* _LIVEPATCH_BSC1233678_H */
