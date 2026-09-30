#ifndef _LIVEPATCH_BSC1273003_H
#define _LIVEPATCH_BSC1273003_H

#include <linux/types.h>

static inline int livepatch_bsc1273003_init(void) { return 0; }
static inline void livepatch_bsc1273003_cleanup(void) {}

struct hci_dev;

int klpp_hci_le_create_cis_sync(struct hci_dev *hdev);

#endif /* _LIVEPATCH_BSC1273003_H */
