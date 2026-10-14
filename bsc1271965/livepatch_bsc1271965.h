#ifndef _LIVEPATCH_BSC1271965_H
#define _LIVEPATCH_BSC1271965_H

#include <linux/types.h>

static inline int livepatch_bsc1271965_init(void) { return 0; }
static inline void livepatch_bsc1271965_cleanup(void) {}

struct kvm;
struct kvm_sev_cmd;

int klpp_sev_dbg_crypt(struct kvm *kvm, struct kvm_sev_cmd *argp, bool dec);

#endif /* _LIVEPATCH_BSC1271965_H */
