#ifndef _LIVEPATCH_BSC1188117_H
#define _LIVEPATCH_BSC1188117_H

int livepatch_bsc1188117_init(void);
void livepatch_bsc1188117_cleanup(void);


struct net;
struct xt_table_info;
struct compat_arpt_replace;
struct compat_ipt_replace;
struct compat_ip6t_replace;

int klpp_arp_tables_translate_compat_table(struct xt_table_info **pinfo,
				  void **pentry0,
				  const struct compat_arpt_replace *compatr);
int
klpp_ip_tables_translate_compat_table(struct net *net,
		       struct xt_table_info **pinfo,
		       void **pentry0,
		       const struct compat_ipt_replace *compatr);

int
klpp_ip6_tables_translate_compat_table(struct net *net,
		       struct xt_table_info **pinfo,
		       void **pentry0,
		       const struct compat_ip6t_replace *compatr);

#endif /* _LIVEPATCH_BSC1188117_H */
