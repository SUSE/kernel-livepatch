#ifndef _LIVEPATCH_BSC1265127_H
#define _LIVEPATCH_BSC1265127_H

#include <linux/types.h>

static inline int livepatch_bsc1265127_init(void) { return 0; }
static inline void livepatch_bsc1265127_cleanup(void) {}

struct file;
struct snd_pcm_substream;

int klpp_snd_pcm_drain(struct snd_pcm_substream *substream, struct file *file);

#endif /* _LIVEPATCH_BSC1265127_H */
