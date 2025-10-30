#ifndef _LIVEPATCH_BSC1249847_H
#define _LIVEPATCH_BSC1249847_H

#if IS_ENABLED(CONFIG_IGB)

struct igb_adapter;

int livepatch_bsc1249847_init(void);
void livepatch_bsc1249847_cleanup(void);
int klpp_igb_init_interrupt_scheme(struct igb_adapter *adapter, bool msix);

#else /* !IS_ENABLED(CONFIG_IGB) */

static inline int livepatch_bsc1249847_init(void) { return 0; }
static inline void livepatch_bsc1249847_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_IGB) */

#endif /* _LIVEPATCH_BSC1249847_H */
