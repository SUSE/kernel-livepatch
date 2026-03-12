#ifndef _LIVEPATCH_BSC1257118_H
#define _LIVEPATCH_BSC1257118_H

#include <linux/types.h>

static inline int livepatch_bsc1257118_init(void) { return 0; }
static inline void livepatch_bsc1257118_cleanup(void) {}

struct ata_queued_cmd;

void klpp_ata_pio_sector(struct ata_queued_cmd *qc);

#endif /* _LIVEPATCH_BSC1257118_H */
