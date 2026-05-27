#ifndef _LIVEPATCH_BSC1265384_H
#define _LIVEPATCH_BSC1265384_H

#include <linux/types.h>

static inline int livepatch_bsc1265384_init(void) { return 0; }
static inline void livepatch_bsc1265384_cleanup(void) {}

struct task_struct;

/*
 *
 * Bit layout inside task_struct->suse_kabi_padding:
 *
 *   bit 0 : KLP_USER_DUMPABLE       cached (get_dumpable(mm) == SUID_DUMP_USER)
 *                                   snapshot taken in the patched exit_mm()
 *                                   right before current->mm is cleared.
 *
 *   bit 1 : KLP_USER_DUMPABLE_VALID set by the patched exit_mm() to indicate
 *                                   bit 0 was populated by this livepatch.
 */

#define KLP_USER_DUMPABLE_MASK		(1UL << 0)
#define KLP_USER_DUMPABLE_VALID_MASK	(1UL << 1)

#define KLP_USER_DUMPABLE(t) \
	((unsigned long)(t)->suse_kabi_padding & KLP_USER_DUMPABLE_MASK)

#define KLP_USER_DUMPABLE_VALID(t) \
	(!!((unsigned long)(t)->suse_kabi_padding & KLP_USER_DUMPABLE_VALID_MASK))

#define KLP_SET_USER_DUMPABLE(t, v) \
	((t)->suse_kabi_padding = (void *)( \
		((unsigned long)(t)->suse_kabi_padding & ~KLP_USER_DUMPABLE_MASK) | \
		((v) ? KLP_USER_DUMPABLE_MASK : 0UL)))

#define KLP_SET_USER_DUMPABLE_VALID(t, v) \
	((t)->suse_kabi_padding = (void *)( \
		((unsigned long)(t)->suse_kabi_padding & ~KLP_USER_DUMPABLE_VALID_MASK) | \
		((v) ? KLP_USER_DUMPABLE_VALID_MASK : 0UL)))

int klpp___ptrace_may_access(struct task_struct *task, unsigned int mode);
void klpp_do_exit(long error_code);

#endif /* _LIVEPATCH_BSC1265384_H */
