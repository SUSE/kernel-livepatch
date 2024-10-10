#ifndef _LIVEPATCH_BSC1225312_H
#define _LIVEPATCH_BSC1225312_H

#include <linux/types.h>
struct TCP_Server_Info;

static inline int livepatch_bsc1225312_init(void) { return 0; }
static inline void livepatch_bsc1225312_cleanup(void) { }
void klpp_cifs_signal_cifsd_for_reconnect(struct TCP_Server_Info *server,
				bool all_channels);


#endif /* _LIVEPATCH_BSC1225312_H */
