#ifndef _LIVEPATCH_BSC1259896_H
#define _LIVEPATCH_BSC1259896_H

static inline int livepatch_bsc1259896_init(void) { return 0; }
static inline void livepatch_bsc1259896_cleanup(void) {}

void klpp_smb2_query_server_interfaces(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1259896_H */
