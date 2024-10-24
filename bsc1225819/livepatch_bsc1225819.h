#ifndef _LIVEPATCH_BSC1225819_H
#define _LIVEPATCH_BSC1225819_H


struct seq_file;

int klpp_cifs_debug_data_proc_show(struct seq_file *m, void *v);

static inline int livepatch_bsc1225819_init(void) { return 0; }
static inline void livepatch_bsc1225819_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1225819_H */
