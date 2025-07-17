#ifndef _LIVEPATCH_BSC1229458_H
#define _LIVEPATCH_BSC1229458_H

int livepatch_bsc1229458_init(void);
void livepatch_bsc1229458_cleanup(void);

void klpp_delayed_work(struct work_struct *work);
void klpp_ceph_monc_stop(struct ceph_mon_client *monc);

#endif /* _LIVEPATCH_BSC1229458_H */
