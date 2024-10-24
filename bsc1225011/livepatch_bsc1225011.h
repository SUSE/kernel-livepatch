#ifndef _LIVEPATCH_BSC1225011_H
#define _LIVEPATCH_BSC1225011_H

struct TCP_Server_Info;

bool klpp_is_valid_oplock_break(char *buffer, struct TCP_Server_Info *srv);

int livepatch_bsc1225011_init(void);
void livepatch_bsc1225011_cleanup(void);

#endif /* _LIVEPATCH_BSC1225011_H */
