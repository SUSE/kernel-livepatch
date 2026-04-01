#ifndef _LIVEPATCH_BSC1252689_H
#define _LIVEPATCH_BSC1252689_H

struct net;

int livepatch_bsc1252689_init(void);
void livepatch_bsc1252689_cleanup(void);
void klpp___ip_vs_ftp_exit(struct net *net);

#endif /* _LIVEPATCH_BSC1252689_H */
