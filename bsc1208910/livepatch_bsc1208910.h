#ifndef _LIVEPATCH_BSC1208910_H
#define _LIVEPATCH_BSC1208910_H

#if IS_ENABLED(CONFIG_IR_ENE)

int livepatch_bsc1208910_init(void);
void livepatch_bsc1208910_cleanup(void);

struct pnp_dev;

void klpp_ene_remove(struct pnp_dev *pnp_dev);

#else /* !IS_ENABLED(CONFIG_IR_ENE) */

static inline int livepatch_bsc1208910_init(void) { return 0; }
static inline void livepatch_bsc1208910_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_IR_ENE) */

#endif /* _LIVEPATCH_BSC1208910_H */
