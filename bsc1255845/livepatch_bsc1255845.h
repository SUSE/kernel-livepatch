#ifndef _LIVEPATCH_BSC1255845_H
#define _LIVEPATCH_BSC1255845_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_NVME_TARGET_TCP)

int livepatch_bsc1255845_init(void);
void livepatch_bsc1255845_cleanup(void);

struct nvmet_tcp_queue;

int klpp_nvmet_tcp_try_recv_pdu(struct nvmet_tcp_queue *queue);
#else /* !IS_ENABLED(CONFIG_NVME_TARGET_TCP) */

static inline int livepatch_bsc1255845_init(void) { return 0; }
static inline void livepatch_bsc1255845_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_NVME_TARGET_TCP) */

#endif /* _LIVEPATCH_BSC1255845_H */
