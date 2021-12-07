#ifndef _LIVEPATCH_BSC1191813_H
#define _LIVEPATCH_BSC1191813_H

int livepatch_bsc1191813_init(void);
void livepatch_bsc1191813_cleanup(void);


struct fib_nh;

void klpp_update_or_create_fnhe(struct fib_nh *nh, __be32 daddr, __be32 gw,
				  u32 pmtu, bool lock, unsigned long expires);

#endif /* _LIVEPATCH_BSC1191813_H */
