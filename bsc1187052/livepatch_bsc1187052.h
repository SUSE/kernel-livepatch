#ifndef _LIVEPATCH_BSC1187052_H
#define _LIVEPATCH_BSC1187052_H

int livepatch_bsc1187052_init(void);
void livepatch_bsc1187052_cleanup(void);


#include <linux/types.h>

struct ucma_file;

ssize_t klpp_ucma_migrate_id(struct ucma_file *new_file,
			       const char __user *inbuf,
			       int in_len, int out_len);

#endif /* _LIVEPATCH_BSC1187052_H */
