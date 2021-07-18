#ifndef _BSC1188117_COMMON_H
#define _BSC1188117_COMMON_H

int livepatch_bsc1188117_x_tables_init(void);
void livepatch_bsc1188117_x_tables_cleanup(void);

int livepatch_bsc1188117_arp_tables_init(void);
void livepatch_bsc1188117_arp_tables_cleanup(void);

int livepatch_bsc1188117_ip_tables_init(void);
void livepatch_bsc1188117_ip_tables_cleanup(void);

int livepatch_bsc1188117_ip6_tables_init(void);
void livepatch_bsc1188117_ip6_tables_cleanup(void);


struct xt_entry_match;
struct xt_entry_target;

void klpp_xt_compat_match_from_user(struct xt_entry_match *m, void **dstptr,
			       unsigned int *size);
void klpp_xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size);

#endif /* _BSC1188117_COMMON_H */
