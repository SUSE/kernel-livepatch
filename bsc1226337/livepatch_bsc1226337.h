#ifndef _LIVEPATCH_BSC1226337_H
#define _LIVEPATCH_BSC1226337_H

#if IS_ENABLED(CONFIG_NVME_TCP)

int livepatch_bsc1226337_init(void);
void livepatch_bsc1226337_cleanup(void);

void klpp_nvme_tcp_io_work(struct work_struct *w);

#endif /* IS_ENABLED() */

#endif /* _LIVEPATCH_BSC1226337_H */
