#ifndef _LIVEPATCH_BSC1228573_H
#define _LIVEPATCH_BSC1228573_H

int livepatch_bsc1228573_init(void);
void livepatch_bsc1228573_cleanup(void);

struct dentry;

ssize_t klpp_hfsplus_listxattr(struct dentry *dentry, char *buffer, size_t size);

#endif /* _LIVEPATCH_BSC1228573_H */
