#ifndef _LIVEPATCH_BSC1264253_H
#define _LIVEPATCH_BSC1264253_H

#include <linux/types.h>

int livepatch_bsc1264253_init(void);
void livepatch_bsc1264253_cleanup(void);


struct net;
struct nf_conn;
struct nf_conntrack_zone;
struct nlatt;
struct nlattr;

int klpp_ctnetlink_create_expect(struct net *net, const struct nf_conntrack_zone *zone, const struct nlattr * const cda[], u_int8_t u3, u32 portid, int report);
int klpp_ctnetlink_glue_attach_expect(const struct nlattr *attr, struct nf_conn *ct, u32 portid, u32 report);
#endif /* _LIVEPATCH_BSC1264253_H */
