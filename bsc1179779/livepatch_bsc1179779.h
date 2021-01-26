#ifndef _LIVEPATCH_BSC1179779_H
#define _LIVEPATCH_BSC1179779_H

int livepatch_bsc1179779_init(void);
static inline void livepatch_bsc1179779_cleanup(void) {}


struct work_struct;

void klpp_io_sq_wq_submit_work(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1179779_H */
