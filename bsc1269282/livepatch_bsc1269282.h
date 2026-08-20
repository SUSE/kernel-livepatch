#ifndef _LIVEPATCH_BSC1269282_H
#define _LIVEPATCH_BSC1269282_H

#include <linux/types.h>

static inline int livepatch_bsc1269282_init(void) { return 0; }
static inline void livepatch_bsc1269282_cleanup(void) {}

int klpp_restore_signal_shadow_stack(void);

#endif /* _LIVEPATCH_BSC1269282_H */
