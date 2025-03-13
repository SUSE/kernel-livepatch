#ifndef _LIVEPATCH_BSC1228755_H
#define _LIVEPATCH_BSC1228755_H

static inline int livepatch_bsc1228755_init(void) { return 0; }
static inline void livepatch_bsc1228755_cleanup(void) {}

struct mpi3mr_sas_port *klpp_mpi3mr_sas_port_add(struct mpi3mr_ioc *mrioc,
	u16 handle, u64 sas_address_parent, struct mpi3mr_hba_port *hba_port);

#endif /* _LIVEPATCH_BSC1228755_H */
