#ifndef _LIVEPATCH_BSC1210500_H
#define _LIVEPATCH_BSC1210500_H

#if IS_ENABLED(CONFIG_BT_HCIBTSDIO)

int livepatch_bsc1210500_init(void);
void livepatch_bsc1210500_cleanup(void);

struct sdio_func;

void klpp_btsdio_remove(struct sdio_func *func);

#else /* !IS_ENABLED(CONFIG_BT_HCIBTSDIO) */

static inline int livepatch_bsc1210500_init(void) { return 0; }
static inline void livepatch_bsc1210500_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT_HCIBTSDIO) */

#endif /* _LIVEPATCH_BSC1210500_H */
