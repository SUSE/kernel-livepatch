#ifndef _LIVEPATCH_BSC1199606_H
#define _LIVEPATCH_BSC1199606_H

#if IS_ENABLED(CONFIG_NFC_MRVL)

struct nfcmrvl_private;

void klpp_nfcmrvl_nci_unregister_dev(struct nfcmrvl_private *priv);

int livepatch_bsc1199606_init(void);
void livepatch_bsc1199606_cleanup(void);

#else /* !IS_ENABLED(CONFIG_NFC_MRVL) */

static inline int livepatch_bsc1199606_init(void) { return 0; }
static inline void livepatch_bsc1199606_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NFC_MRVL) */

#endif /* _LIVEPATCH_BSC1199606_H */
