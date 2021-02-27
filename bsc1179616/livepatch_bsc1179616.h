#ifndef _LIVEPATCH_BSC1179616_H
#define _LIVEPATCH_BSC1179616_H

#if IS_ENABLED(CONFIG_SND_RAWMIDI)

int livepatch_bsc1179616_init(void);
void livepatch_bsc1179616_cleanup(void);


struct snd_rawmidi_substream;
struct snd_rawmidi_params;

int klpp_snd_rawmidi_output_params(struct snd_rawmidi_substream *substream,
			      struct snd_rawmidi_params *params);

int klpp_snd_rawmidi_input_params(struct snd_rawmidi_substream *substream,
			     struct snd_rawmidi_params *params);

#else /* !IS_ENABLED(CONFIG_SND_RAWMIDI) */

static inline int livepatch_bsc1179616_init(void) { return 0; }

static inline void livepatch_bsc1179616_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SND_RAWMIDI) */
#endif /* _LIVEPATCH_BSC1179616_H */
