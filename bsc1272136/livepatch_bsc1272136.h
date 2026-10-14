#ifndef _LIVEPATCH_BSC1272136_H
#define _LIVEPATCH_BSC1272136_H

#include <linux/types.h>

static inline int livepatch_bsc1272136_init(void) { return 0; }
static inline void livepatch_bsc1272136_cleanup(void) {}

struct p9_fid;

struct p9_fid *klpp_p9_client_walk(struct p9_fid *oldfid, uint16_t nwname, const unsigned char * const *wnames, int clone);

#endif /* _LIVEPATCH_BSC1272136_H */
