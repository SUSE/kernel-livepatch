#ifndef _LIVEPATCH_BSC1246075_H
#define _LIVEPATCH_BSC1246075_H

struct exfat_sb_info;

static inline int livepatch_bsc1246075_init(void) { return 0; }
static inline void livepatch_bsc1246075_cleanup(void) {}
void klpp_exfat_free_upcase_table(struct exfat_sb_info *sbi);


#endif /* _LIVEPATCH_BSC1246075_H */
