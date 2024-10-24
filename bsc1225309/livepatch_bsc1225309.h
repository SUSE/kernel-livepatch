#ifndef _LIVEPATCH_BSC1225309_H
#define _LIVEPATCH_BSC1225309_H

struct TCP_Server_Info;

int livepatch_bsc1225309_init(void);
void livepatch_bsc1225309_cleanup(void);
bool klpp_smb2_is_valid_oplock_break(char *buffer, struct TCP_Server_Info *server);


#endif /* _LIVEPATCH_BSC1225309_H */
