#ifndef _LIVEPATCH_BSC1252036_H
#define _LIVEPATCH_BSC1252036_H

#include <linux/types.h>

static inline int livepatch_bsc1252036_init(void) { return 0; }
static inline void livepatch_bsc1252036_cleanup(void) {}

struct i40e_pf;

int klpp_i40e_vc_process_vf_msg(struct i40e_pf *pf, s16 vf_id, u32 v_opcode, u32 v_retval, u8 *msg, u16 msglen);

#endif /* _LIVEPATCH_BSC1252036_H */
