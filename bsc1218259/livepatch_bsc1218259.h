#ifndef _LIVEPATCH_BSC1218259_H
#define _LIVEPATCH_BSC1218259_H

#include <linux/types.h>

struct file;
struct iov_iter;
struct io_kiocb;

extern const struct file_operations *klpe_perf_fops;

ssize_t
klpp_perf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
ssize_t klpp_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos);
ssize_t klpp_do_iter_read(struct file *file, struct iov_iter *iter,
		loff_t *pos, int __bitwise flags);
ssize_t klpp_loop_rw_iter(int rw, struct io_kiocb *req, struct iov_iter *iter);

int bsc1218259_kernel_events_core_init(void);
int bsc1218259_fs_read_write_init(void);

int livepatch_bsc1218259_init(void);
static inline void livepatch_bsc1218259_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1218259_H */
