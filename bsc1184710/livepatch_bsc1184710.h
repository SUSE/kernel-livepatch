#ifndef _LIVEPATCH_BSC1184710_H
#define _LIVEPATCH_BSC1184710_H

#if IS_ENABLED(CONFIG_X86_64)

int livepatch_bsc1184710_init(void);
static inline void livepatch_bsc1184710_cleanup(void) {}


struct bpf_prog;
struct jit_context;

int klpp_do_jit(struct bpf_prog *bpf_prog, int *addrs, u8 *image,
		  int oldproglen, struct jit_context *ctx);

#else /* !IS_ENABLED(CONFIG_X86_64) */

static inline int livepatch_bsc1184710_init(void) { return 0; }

static inline void livepatch_bsc1184710_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_X86_64) */
#endif /* _LIVEPATCH_BSC1184710_H */
