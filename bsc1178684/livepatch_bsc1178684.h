#ifndef _LIVEPATCH_BSC1178684_H
#define _LIVEPATCH_BSC1178684_H

int livepatch_bsc1178684_init(void);
void livepatch_bsc1178684_cleanup(void);


struct work_struct;

void klpp_target_xcopy_do_work(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1178684_H */
