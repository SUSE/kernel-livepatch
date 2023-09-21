#ifndef _LIVEPATCH_BSC1214123_H
#define _LIVEPATCH_BSC1214123_H

#if IS_ENABLED(CONFIG_EXFAT_FS)


struct exfat_chain;
struct exfat_dir_entry;
struct exfat_inode_info;
struct exfat_hint;
struct exfat_uni_name;
struct inode;
struct super_block;

int klpp_exfat_find_dir_entry(struct super_block *sb, struct exfat_inode_info *ei,
		struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname,
		int num_entries, unsigned int type, struct exfat_hint *hint_opt);
int klpp_exfat_readdir(struct inode *inode, loff_t *cpos, struct exfat_dir_entry *dir_entry);

int livepatch_bsc1214123_init(void);
void livepatch_bsc1214123_cleanup(void);

#else /* !IS_ENABLED(CONFIG_EXFAT_FS) */

static inline int livepatch_bsc1214123_init(void) { return 0; }
static inline void livepatch_bsc1214123_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_EXFAT_FS) */

#endif /* _LIVEPATCH_BSC1214123_H */
