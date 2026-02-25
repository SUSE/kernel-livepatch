#ifndef _LIVEPATCH_BSC1258139_H
#define _LIVEPATCH_BSC1258139_H

#include <linux/types.h>
#include <net/netmem.h>

static inline int livepatch_bsc1258139_init(void) { return 0; }
static inline void livepatch_bsc1258139_cleanup(void) {}

struct page_pool;

int klpp_page_pool_release(struct page_pool *pool);
void klpp_page_pool_put_unrefed_netmem(struct page_pool *pool, netmem_ref netmem, unsigned int dma_sync_size, bool allow_direct);

#endif /* _LIVEPATCH_BSC1258139_H */
