#ifndef _LIVEPATCH_BSC1260908_H
#define _LIVEPATCH_BSC1260908_H

struct xt_tgchk_param;

static inline int livepatch_bsc1260908_init(void) { return 0; }
static inline void livepatch_bsc1260908_cleanup(void) {}

int klpp_idletimer_tg_checkentry(const struct xt_tgchk_param *par);

#endif /* _LIVEPATCH_BSC1260908_H */
