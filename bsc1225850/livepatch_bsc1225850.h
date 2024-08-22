#ifndef _LIVEPATCH_BSC1225850_H
#define _LIVEPATCH_BSC1225850_H

#include <linux/types.h>

struct iwl_mvm;

int klpp_iwl_mvm_mld_rm_sta_id(struct iwl_mvm *mvm, u8 sta_id);

static inline int livepatch_bsc1225850_init(void) { return 0; }
static inline void livepatch_bsc1225850_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1225850_H */
