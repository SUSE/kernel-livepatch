#ifndef _LIVEPATCH_BSC1275162_H
#define _LIVEPATCH_BSC1275162_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_SND_SEQUENCER)

int livepatch_bsc1275162_init(void);
void livepatch_bsc1275162_cleanup(void);

struct snd_seq_timer;

void klpp_snd_seq_timer_delete(struct snd_seq_timer **tmr);
#else /* !IS_ENABLED(CONFIG_SND_SEQUENCER) */

static inline int livepatch_bsc1275162_init(void) { return 0; }
static inline void livepatch_bsc1275162_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_SND_SEQUENCER) */

#endif /* _LIVEPATCH_BSC1275162_H */
