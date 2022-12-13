#ifndef _LIVEPATCH_BSC1206228_H
#define _LIVEPATCH_BSC1206228_H

int livepatch_bsc1206228_init(void);
static inline void livepatch_bsc1206228_cleanup(void) {}



int klpp___do_proc_dointvec(void *tbl_data, struct ctl_table *table,
		  int write, void __user *buffer,
		  size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data);

int klpp___do_proc_douintvec(void *tbl_data, struct ctl_table *table,
			       int write, void __user *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data);

int klpp___do_proc_doulongvec_minmax(void *data, struct ctl_table *table, int write,
				     void __user *buffer,
				     size_t *lenp, loff_t *ppos,
				     unsigned long convmul,
				     unsigned long convdiv);

int klpp_proc_do_large_bitmap(struct ctl_table *, int,
				void __user *, size_t *, loff_t *);

#endif /* _LIVEPATCH_BSC1206228_H */
