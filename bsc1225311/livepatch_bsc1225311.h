#ifndef _LIVEPATCH_BSC1225311_H
#define _LIVEPATCH_BSC1225311_H


#include <linux/types.h>
struct TCP_Server_Info;

int livepatch_bsc1225311_init(void);
void livepatch_bsc1225311_cleanup(void);
void klpp_smb2_is_network_name_deleted(char *buf, struct TCP_Server_Info *server);


#endif /* _LIVEPATCH_BSC1225311_H */
