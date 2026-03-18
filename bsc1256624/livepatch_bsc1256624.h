#ifndef _LIVEPATCH_BSC1256624_H
#define _LIVEPATCH_BSC1256624_H

#include <linux/types.h>

int livepatch_bsc1256624_init(void);
static inline void livepatch_bsc1256624_cleanup(void) {}


struct calipso_doi;
struct netlbl_lsm_secattr;
struct sk_buff;

int klpp_calipso_skbuff_setattr(struct sk_buff *skb, const struct calipso_doi *doi_def, const struct netlbl_lsm_secattr *secattr);
#endif /* _LIVEPATCH_BSC1256624_H */
