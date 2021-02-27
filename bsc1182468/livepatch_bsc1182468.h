#ifndef _LIVEPATCH_BSC1182468_H
#define _LIVEPATCH_BSC1182468_H

int livepatch_bsc1182468_init(void);
void livepatch_bsc1182468_cleanup(void);


struct inode;
struct dentry;

int
klpp_nfs_do_lookup_revalidate(struct inode *dir, struct dentry *dentry,
			 unsigned int flags);

#endif /* _LIVEPATCH_BSC1182468_H */
