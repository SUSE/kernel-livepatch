#ifndef _LIVEPATCH_BSC1242579_H
#define _LIVEPATCH_BSC1242579_H

#include <linux/types.h>

struct super_block;
struct proc_dir_entry;
struct seq_operations;
struct seq_file;

int livepatch_bsc1242579_init(void);
void livepatch_bsc1242579_cleanup(void);

struct proc_dir_entry *klpp_proc_create_seq_private(const char *name, umode_t mode,
        struct proc_dir_entry *parent, const struct seq_operations *ops,
        unsigned int state_size, void *data);
struct proc_dir_entry *klpp_proc_create_single_data(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *), void *data);
struct inode *klpp_proc_get_inode(struct super_block *sb, struct proc_dir_entry *de);

#endif /* _LIVEPATCH_BSC1242579_H */
