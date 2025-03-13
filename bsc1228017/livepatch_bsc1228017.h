#ifndef _LIVEPATCH_BSC1228017_H
#define _LIVEPATCH_BSC1228017_H

#if IS_ENABLED(CONFIG_SCSI_PM8001)

int livepatch_bsc1228017_init(void);
void livepatch_bsc1228017_cleanup(void);

void klpp_mpi_ssp_completion(struct pm8001_hba_info *pm8001_ha, void *piomb);
void klpp_mpi_sata_completion(struct pm8001_hba_info *pm8001_ha, void *piomb);

#else

static inline int livepatch_bsc1228017_init(void) { return 0; }
static inline void livepatch_bsc1228017_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SCSI_PM8001) */

#endif /* _LIVEPATCH_BSC1228017_H */
