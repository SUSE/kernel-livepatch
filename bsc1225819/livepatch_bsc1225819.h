#ifndef _LIVEPATCH_BSC1225819_H
#define _LIVEPATCH_BSC1225819_H


struct seq_file;

int livepatch_bsc1225819_init(void);
void livepatch_bsc1225819_cleanup(void);
int klpp_cifs_debug_data_proc_show(struct seq_file *m, void *v);


#endif /* _LIVEPATCH_BSC1225819_H */
