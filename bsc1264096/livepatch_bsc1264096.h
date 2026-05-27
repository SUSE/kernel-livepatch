#ifndef _LIVEPATCH_BSC1264096_H
#define _LIVEPATCH_BSC1264096_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_X86)

int livepatch_bsc1264096_init(void);
void livepatch_bsc1264096_cleanup(void);

#else /* !IS_ENABLED(CONFIG_X86) */

static inline int livepatch_bsc1264096_init(void) { return 0; }
static inline void livepatch_bsc1264096_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_X86) */


#endif /* _LIVEPATCH_BSC1264096_H */
