#ifndef _LIVEPATCH_BSC1232818_H
#define _LIVEPATCH_BSC1232818_H

int livepatch_bsc1232818_init(void);
void livepatch_bsc1232818_cleanup(void);

void klpp___tun_detach(struct tun_file *tfile, bool clean);
int klpp_tun_chr_close(struct inode *inode, struct file *file);

#endif /* _LIVEPATCH_BSC1232818_H */
