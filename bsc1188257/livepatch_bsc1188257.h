#ifndef _LIVEPATCH_BSC1188257_H
#define _LIVEPATCH_BSC1188257_H

static inline int livepatch_bsc1188257_init(void) { return 0; }
static inline void livepatch_bsc1188257_cleanup(void) {}


#include <linux/types.h>

struct  seq_file;
struct file;

int klpp_traverse(struct seq_file *m, loff_t offset);

ssize_t klpp_seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);

int klpp_single_open_size(struct file *file, int (*show)(struct seq_file *, void *),
		void *data, size_t size);

#endif /* _LIVEPATCH_BSC1188257_H */
