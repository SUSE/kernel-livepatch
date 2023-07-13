#ifndef _LIVEPATCH_BSC1212509_H
#define _LIVEPATCH_BSC1212509_H

int livepatch_bsc1212509_init(void);
void livepatch_bsc1212509_cleanup(void);

struct nlattr;
struct fl_flow_key;
struct netlink_ext_ack;

int klpp_fl_set_geneve_opt(const struct nlattr *nla, struct fl_flow_key *key,
			     int depth, int option_len,
			     struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1212509_H */
