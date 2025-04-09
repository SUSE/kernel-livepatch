#ifndef _LIVEPATCH_BSC1235431_H
#define _LIVEPATCH_BSC1235431_H

static inline int livepatch_bsc1235431_init(void) { return 0; }
static inline void livepatch_bsc1235431_cleanup(void) {}

int klpp_led_tg_check(const struct xt_tgchk_param *par);

#endif /* _LIVEPATCH_BSC1235431_H */
