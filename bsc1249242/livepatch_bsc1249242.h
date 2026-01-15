#ifndef _LIVEPATCH_BSC1249242_H
#define _LIVEPATCH_BSC1249242_H

#include <linux/types.h>

static inline int livepatch_bsc1249242_init(void) { return 0; }
static inline void livepatch_bsc1249242_cleanup(void) {}

struct hci_dev;

u16 klpp_append_eir_data_to_buf(struct hci_dev *hdev, u8 *eir);

#endif /* _LIVEPATCH_BSC1249242_H */
