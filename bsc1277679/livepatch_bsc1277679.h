#ifndef _LIVEPATCH_BSC1277679_H
#define _LIVEPATCH_BSC1277679_H

#include <linux/types.h>

static inline int livepatch_bsc1277679_init(void) { return 0; }
static inline void livepatch_bsc1277679_cleanup(void) {}

struct snd_sof_control;

int klpp__sof_ipc3_bytes_ext_get(struct snd_sof_control *scontrol, const unsigned int __user *binary_data, unsigned int size, bool from_dsp);
int klpp_sof_ipc3_bytes_ext_put(struct snd_sof_control *scontrol, const unsigned int __user *binary_data, unsigned int size);

#endif /* _LIVEPATCH_BSC1277679_H */
