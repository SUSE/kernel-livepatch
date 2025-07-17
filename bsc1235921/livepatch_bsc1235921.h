#ifndef _LIVEPATCH_BSC1235921_H
#define _LIVEPATCH_BSC1235921_H

#if IS_ENABLED(CONFIG_SND_SEQUENCER_OSS)

int livepatch_bsc1235921_init(void);
void livepatch_bsc1235921_cleanup(void);

int klpp_snd_seq_oss_synth_sysex(struct seq_oss_devinfo *dp, int dev, unsigned char *buf,
                struct snd_seq_event *ev);

#else /* !IS_ENABLED(CONFIG_SND_SEQUENCER_OSS) */

static inline int livepatch_bsc1235921_init(void) { return 0; }
static inline void livepatch_bsc1235921_cleanup(void) {}

int klpp_snd_seq_oss_synth_sysex(struct seq_oss_devinfo *dp, int dev, unsigned char *buf,
                struct snd_seq_event *ev);

#endif /* IS_ENABLED(CONFIG_SND_SEQUENCER_OSS) */

#endif /* _LIVEPATCH_BSC1235921_H */
