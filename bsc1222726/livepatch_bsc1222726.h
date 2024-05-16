#ifndef _LIVEPATCH_BSC1222726_H
#define _LIVEPATCH_BSC1222726_H

#if IS_ENABLED(CONFIG_INFINIBAND_HFI1)

int livepatch_bsc1222726_init(void);
void livepatch_bsc1222726_cleanup(void);

struct hfi1_devdata;
struct sdma_txreq;

int klpp__pad_sdma_tx_descs(struct hfi1_devdata *, struct sdma_txreq *);

#else /* !IS_ENABLED(CONFIG_INFINIBAND_HFI1) */

static inline int livepatch_bsc1222726_init(void) { return 0; }
static inline void livepatch_bsc1222726_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_INFINIBAND_HFI1) */

#endif /* _LIVEPATCH_BSC1222726_H */
