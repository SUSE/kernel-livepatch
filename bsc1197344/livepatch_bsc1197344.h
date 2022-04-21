#ifndef _LIVEPATCH_BSC1197344_H
#define _LIVEPATCH_BSC1197344_H

int livepatch_bsc1197344_init(void);
void livepatch_bsc1197344_cleanup(void);


struct fuse_copy_state;
struct fuse_arg;
struct fuse_io_priv;
struct iov_iter;

int klpp_fuse_copy_args(struct fuse_copy_state *cs, unsigned numargs,
			  unsigned argpages, struct fuse_arg *args,
			  int zeroing);

ssize_t klpp_fuse_direct_io(struct fuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags);


#endif /* _LIVEPATCH_BSC1197344_H */
