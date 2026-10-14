#ifndef _LIVEPATCH_BSC1271965_H
#define _LIVEPATCH_BSC1271965_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_KVM_AMD)

int livepatch_bsc1271965_init(void);
void livepatch_bsc1271965_cleanup(void);

struct kvm;
struct kvm_sev_cmd;

int klpp_sev_dbg_crypt(struct kvm *kvm, struct kvm_sev_cmd *argp, bool dec);
#else /* !IS_ENABLED(CONFIG_KVM_AMD) */

static inline int livepatch_bsc1271965_init(void) { return 0; }
static inline void livepatch_bsc1271965_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_KVM_AMD) */

#endif /* _LIVEPATCH_BSC1271965_H */
