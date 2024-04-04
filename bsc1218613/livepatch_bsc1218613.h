#ifndef _LIVEPATCH_BSC1218613_H
#define _LIVEPATCH_BSC1218613_H

struct hash_netportnet4;
struct hash_netportnet6;
struct ip_set;
struct ip_set_ext;

void
klpp_hash_netportnet4_del_cidr(struct ip_set *set, struct hash_netportnet4 *h, u8 cidr, u8 n);
int
klpp_hash_netportnet4_add(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags);
int
klpp_hash_netportnet4_test(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	   struct ip_set_ext *mext, u32 flags);
void
klpp_hash_netportnet6_del_cidr(struct ip_set *set, struct hash_netportnet6 *h, u8 cidr, u8 n);
int
klpp_hash_netportnet6_add(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags);
int
klpp_hash_netportnet6_test(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	   struct ip_set_ext *mext, u32 flags);

int livepatch_bsc1218613_init(void);
void livepatch_bsc1218613_cleanup(void);


#endif /* _LIVEPATCH_BSC1218613_H */
