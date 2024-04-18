#ifndef _LIVEPATCH_BSC1219079_H
#define _LIVEPATCH_BSC1219079_H

int livepatch_bsc1219079_init(void);
void livepatch_bsc1219079_cleanup(void);

struct super_block;

int klpp_ext4_remount(struct super_block *sb, int *flags, char *data);

#endif /* _LIVEPATCH_BSC1219079_H */
