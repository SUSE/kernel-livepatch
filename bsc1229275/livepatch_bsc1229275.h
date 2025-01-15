#ifndef _LIVEPATCH_BSC1229275_H
#define _LIVEPATCH_BSC1229275_H

int livepatch_bsc1229275_init(void);
void livepatch_bsc1229275_cleanup(void);

struct cachefiles_cache;

void klpp_cachefiles_withdraw_cache(struct cachefiles_cache *cache);

struct cachefiles_volume;

void klpp_cachefiles_withdraw_volume(struct cachefiles_volume *volume);

struct fscache_volume;

void klpp_fscache_put_volume(struct fscache_volume *volume);

#endif /* _LIVEPATCH_BSC1229275_H */
