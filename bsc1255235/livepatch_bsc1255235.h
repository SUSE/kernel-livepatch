#ifndef _LIVEPATCH_BSC1255235_H
#define _LIVEPATCH_BSC1255235_H

struct work_struct;

int livepatch_bsc1255235_init(void);
void livepatch_bsc1255235_cleanup(void);

void klpp_smb2_reconnect_server(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1255235_H */
