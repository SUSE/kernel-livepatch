#ifndef _LIVEPATCH_BSC1227700_H
#define _LIVEPATCH_BSC1227700_H

#if IS_ENABLED(CONFIG_SND_PCM_OSS)

int livepatch_bsc1227700_init(void);
void livepatch_bsc1227700_cleanup(void);


struct snd_pcm_substream;
struct snd_pcm_hw_params;

int klpp_snd_pcm_oss_period_size(struct snd_pcm_substream *substream, 
				   struct snd_pcm_hw_params *oss_params,
				   struct snd_pcm_hw_params *slave_params);

#else /* !IS_ENABLED(CONFIG_SND_PCM_OSS) */

static inline int livepatch_bsc1227700_init(void) { return 0; }
static inline void livepatch_bsc1227700_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SND_PCM_OSS) */

#endif /* _LIVEPATCH_BSC1227700_H */
