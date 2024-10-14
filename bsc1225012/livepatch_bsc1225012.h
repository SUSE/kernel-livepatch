#ifndef _LIVEPATCH_BSC1225012_H
#define _LIVEPATCH_BSC1225012_H


struct seq_file;

static inline int livepatch_bsc1225012_init(void) { return 0; }
static inline void livepatch_bsc1225012_cleanup(void) {}
int klpp_cifs_stats_proc_show(struct seq_file *m, void *v);


#endif /* _LIVEPATCH_BSC1225012_H */
