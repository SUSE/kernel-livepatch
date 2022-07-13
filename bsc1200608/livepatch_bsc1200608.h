#ifndef _LIVEPATCH_BSC1200608_H
#define _LIVEPATCH_BSC1200608_H

int livepatch_bsc1200608_init(void);
void livepatch_bsc1200608_cleanup(void);


struct sk_buff;
struct netlink_callback;
struct inet_diag_req_v2;
struct nlattr;
struct sctp_endpoint;

void klpp_sctp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			   const struct inet_diag_req_v2 *r, struct nlattr *bc);

void klpp_sctp_endpoint_put(struct sctp_endpoint *ep);

#endif /* _LIVEPATCH_BSC1200608_H */
