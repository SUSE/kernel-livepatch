#ifndef _LIVEPATCH_BSC1226325_H
#define _LIVEPATCH_BSC1226325_H

static inline int livepatch_bsc1226325_init(void) { return 0; }
static inline void livepatch_bsc1226325_cleanup(void) {}

struct v9fs_session_info;
struct p9_wstat;

umode_t klpp_p9mode2unixmode(struct v9fs_session_info *v9ses,
			       struct p9_wstat *stat, dev_t *rdev);

struct inode;
struct super_block;

void
klpp_v9fs_stat2inode(struct p9_wstat *stat, struct inode *inode,
		 struct super_block *sb, unsigned int flags);

#endif /* _LIVEPATCH_BSC1226325_H */
