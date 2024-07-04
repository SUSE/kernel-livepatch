#ifndef _LIVEPATCH_BSC1220145_H
#define _LIVEPATCH_BSC1220145_H

int livepatch_bsc1220145_init(void);
void livepatch_bsc1220145_cleanup(void);

struct r5conf;

int klpp_grow_one_stripe(struct r5conf *conf, gfp_t gfp);

int klpp_drop_one_stripe(struct r5conf *conf);

struct mddev;

int klpp_raid5_set_cache_size(struct mddev *mddev, int size);

struct shrinker;
struct shrink_control;

unsigned long klpp_raid5_cache_count(struct shrinker *shrink,
				       struct shrink_control *sc);

#endif /* _LIVEPATCH_BSC1220145_H */
