#ifndef _LIVEPATCH_BSC1223683_H
#define _LIVEPATCH_BSC1223683_H

static inline int livepatch_bsc1223683_init(void) { return 0; }
static inline void livepatch_bsc1223683_cleanup(void) {}

void klpp_unix_gc(void);

#endif /* _LIVEPATCH_BSC1223683_H */
