#ifndef _LIVEPATCH_BSC1210987_H
#define _LIVEPATCH_BSC1210987_H

int livepatch_bsc1210987_init(void);
static inline void livepatch_bsc1210987_cleanup(void) {}

int bsc1210987_fs_exec_init(void);
int bsc1210987_kernel_events_core_init(void);

struct linux_binprm;

int klpp_begin_new_exec(struct linux_binprm * bprm);

void klpp_perf_event_exec(void);

#endif /* _LIVEPATCH_BSC1210987_H */
