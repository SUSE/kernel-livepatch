#ifndef _LIVEPATCH_BSC1238730_H
#define _LIVEPATCH_BSC1238730_H

#if IS_ENABLED(CONFIG_SND_USB_AUDIO)

struct snd_rawmidi_substream;

int livepatch_bsc1238730_init(void);
void livepatch_bsc1238730_cleanup(void);
int klpp_snd_usbmidi_output_close(struct snd_rawmidi_substream *substream);

#else /* !IS_ENABLED(CONFIG_SND_USB_AUDIO) */

static inline int livepatch_bsc1238730_init(void) { return 0; }
static inline void livepatch_bsc1238730_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SND_USB_AUDIO) */

#endif /* _LIVEPATCH_BSC1238730_H */
