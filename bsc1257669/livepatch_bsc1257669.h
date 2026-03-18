#ifndef _LIVEPATCH_BSC1257669_H
#define _LIVEPATCH_BSC1257669_H

#include <linux/types.h>

static inline int livepatch_bsc1257669_init(void) { return 0; }
static inline void livepatch_bsc1257669_cleanup(void) {}

struct hci_dev;

void klpp_mgmt_index_removed(struct hci_dev *hdev);

#endif /* _LIVEPATCH_BSC1257669_H */
