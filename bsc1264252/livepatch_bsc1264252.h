#ifndef _LIVEPATCH_BSC1264252_H
#define _LIVEPATCH_BSC1264252_H

#include <linux/types.h>

static inline int livepatch_bsc1264252_init(void) { return 0; }
static inline void livepatch_bsc1264252_cleanup(void) {}

struct nf_conntrack_helper;

void klpp_nf_conntrack_helper_unregister(struct nf_conntrack_helper *);

#endif /* _LIVEPATCH_BSC1264252_H */
