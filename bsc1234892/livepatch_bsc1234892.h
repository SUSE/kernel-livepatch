#ifndef _LIVEPATCH_BSC1234892_H
#define _LIVEPATCH_BSC1234892_H

int livepatch_bsc1234892_init(void);
void livepatch_bsc1234892_cleanup(void);

void klpp_nfs4_open_release(void *calldata);

#endif /* _LIVEPATCH_BSC1234892_H */
