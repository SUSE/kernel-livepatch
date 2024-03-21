#ifndef _LIVEPATCH_BSC1219157_H
#define _LIVEPATCH_BSC1219157_H

#if IS_ENABLED(CONFIG_SCSI_MPT3SAS)

u32
klpp__base_readl_ext_retry(const volatile void __iomem *addr);

static inline int livepatch_bsc1219157_init(void) { return 0; }
static inline void livepatch_bsc1219157_cleanup(void) {}

#else /* !IS_ENABLED(CONFIG_SCSI_MPT3SAS) */

static inline int livepatch_bsc1219157_init(void) { return 0; }
static inline void livepatch_bsc1219157_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SCSI_MPT3SAS) */

#endif /* _LIVEPATCH_BSC1219157_H */
