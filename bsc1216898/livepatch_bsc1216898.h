#ifndef _LIVEPATCH_BSC1216898_H
#define _LIVEPATCH_BSC1216898_H

#if IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)

#include <asm/insn.h>

int livepatch_bsc1216898_init(void);
static inline void livepatch_bsc1216898_cleanup(void) {}

struct pt_regs;

int klpp_insn_fetch_from_user_inatomic(struct pt_regs *regs, unsigned char buf[MAX_INSN_SIZE],
					unsigned long caller_rdx);

#else /* !IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT) */

static inline int livepatch_bsc1216898_init(void) { return 0; }
static inline void livepatch_bsc1216898_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT) */

#endif /* _LIVEPATCH_BSC1216898_H */
