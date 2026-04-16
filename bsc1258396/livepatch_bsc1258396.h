#ifndef _LIVEPATCH_BSC1258396_H
#define _LIVEPATCH_BSC1258396_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_SND_ALOOP)

int livepatch_bsc1258396_init(void);
void livepatch_bsc1258396_cleanup(void);

struct snd_pcm_substream;

int klpp_loopback_trigger(struct snd_pcm_substream *substream, int cmd);
#else /* !IS_ENABLED(CONFIG_SND_ALOOP) */

static inline int livepatch_bsc1258396_init(void) { return 0; }
static inline void livepatch_bsc1258396_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_SND_ALOOP) */

#endif /* _LIVEPATCH_BSC1258396_H */
