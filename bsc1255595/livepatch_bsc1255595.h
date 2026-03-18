#ifndef _LIVEPATCH_BSC1255595_H
#define _LIVEPATCH_BSC1255595_H

struct net_device;
struct mrp_application;

int livepatch_bsc1255595_init(void);
void livepatch_bsc1255595_cleanup(void);

void klpp_mrp_uninit_applicant (struct net_device *dev,
                                struct mrp_application *appl);

#endif /* _LIVEPATCH_BSC1255595_H */
