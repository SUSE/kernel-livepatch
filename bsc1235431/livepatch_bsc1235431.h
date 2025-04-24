#ifndef _LIVEPATCH_BSC1235431_H
#define _LIVEPATCH_BSC1235431_H

#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_LED)

int livepatch_bsc1235431_init(void);
void livepatch_bsc1235431_cleanup(void);

int klpp_led_tg_check(const struct xt_tgchk_param *par);

#else /* !IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_LED) */

static inline int livepatch_bsc1235431_init(void) { return 0; }
static inline void livepatch_bsc1235431_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_LED) */

#endif /* _LIVEPATCH_BSC1235431_H */
