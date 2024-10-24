#ifndef _LIVEPATCH_BSC1225011_H
#define _LIVEPATCH_BSC1225011_H

struct TCP_Server_Info;

static inline int livepatch_bsc1225011_init(void) { return 0; }
static inline void livepatch_bsc1225011_cleanup(void) {}

bool klpp_is_valid_oplock_break(char *buffer, struct TCP_Server_Info *srv);


#endif /* _LIVEPATCH_BSC1225011_H */
