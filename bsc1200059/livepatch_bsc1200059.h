#ifndef _LIVEPATCH_BSC1200059_H
#define _LIVEPATCH_BSC1200059_H

#if IS_ENABLED(CONFIG_KGDB)

int livepatch_bsc1200059_init(void);
static inline void livepatch_bsc1200059_cleanup(void) {}

struct kgdb_state;
struct pt_regs;

int klpp_kgdb_cpu_enter(struct kgdb_state *ks, struct pt_regs *regs,
		int exception_state);


#else /* !IS_ENABLED(CONFIG_KGDB) */

static inline int livepatch_bsc1200059_init(void) { return 0; }
static inline void livepatch_bsc1200059_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_KGDB) */
#endif /* _LIVEPATCH_BSC1200059_H */
