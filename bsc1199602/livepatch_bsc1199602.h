#ifndef _LIVEPATCH_BSC1199602_H
#define _LIVEPATCH_BSC1199602_H

int livepatch_bsc1199602_init(void);
static inline void livepatch_bsc1199602_cleanup(void) {}


struct task_struct;

int klpp_ptrace_attach(struct task_struct *task, long request,
			 unsigned long addr,
			 unsigned long flags);

#endif /* _LIVEPATCH_BSC1199602_H */
